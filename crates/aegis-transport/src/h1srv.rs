//! HTTP/1.1 connection driver: hyper's h1 server behind the strict framing filter ([`crate::h1::H1Validator`]),
//! with a TBI-8 watchdog (head / body / response stall deadline, idle deadline) and the TBI-6/7 ledger on the
//! response path. One request at a time per connection, so TBI-4 holds by construction (≤ 1 live handler).

use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use aegis_canon::Proto;
use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::{Instant, sleep, timeout, timeout_at};

use crate::counters;
use crate::h1::{H1Reject, H1Validator, HeadLimits};
use crate::ledger::{ConnLedger, RecvHold, Side};
use crate::limits::usize_sat;
use crate::pipeline::{App, ConnInfo, RawHead, Reply, ReplyBody, admit, body_cap, finish, response_head, stall_ms};
use crate::server::{CountingIo, Gauge, Progress, Server};

/// State shared by the I/O filter, the service and the watchdog.
#[derive(Debug, Default)]
struct H1State {
    progress: Arc<Progress>,
    head_partial: AtomicBool,
    mid_message: AtomicBool,
    in_flight: AtomicU64,
    reject: Mutex<Option<H1Reject>>,
}

impl H1State {
    fn reject(&self) -> Option<H1Reject> {
        *self.reject.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// hyper I/O adapter: reads pass through the strict framing filter; writes go to the counting transport.
struct H1Guard<IO> {
    io: CountingIo<IO>,
    validator: Option<H1Validator>,
    inbuf: Vec<u8>,
    out: Vec<u8>,
    pos: usize,
    eof: bool,
    st: Arc<H1State>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> hyper::rt::Read for H1Guard<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if let Some(avail) = this.out.get(this.pos..)
                && !avail.is_empty()
            {
                let n = avail.len().min(buf.remaining());
                buf.put_slice(avail.get(..n).unwrap_or(&[]));
                this.pos = this.pos.saturating_add(n);
                if this.pos >= this.out.len() {
                    this.out.clear();
                    this.pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.eof || this.validator.as_ref().is_some_and(|v| v.rejected().is_some()) {
                return Poll::Ready(Ok(()));
            }
            let mut tmp = ReadBuf::new(&mut this.inbuf);
            match Pin::new(&mut this.io).poll_read(cx, &mut tmp) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
            let got = tmp.filled();
            if got.is_empty() {
                this.eof = true;
                return Poll::Ready(Ok(()));
            }
            match this.validator.as_mut() {
                Some(v) => {
                    if let Err(r) = v.feed(got, &mut this.out) {
                        *this.st.reject.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(r);
                    }
                    this.st.head_partial.store(v.head_partial(), Ordering::Relaxed);
                    this.st.mid_message.store(v.mid_message(), Ordering::Relaxed);
                }
                None => this.out.extend_from_slice(got),
            }
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> hyper::rt::Write for H1Guard<IO> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

struct Shared<A: App> {
    srv: Arc<Server<A>>,
    info: ConnInfo,
    ledger: Arc<ConnLedger>,
    st: Arc<H1State>,
}

struct Svc<A: App>(Arc<Shared<A>>);

impl<A: App> hyper::service::Service<http::Request<Incoming>> for Svc<A> {
    type Response = http::Response<OutBody>;
    type Error = std::convert::Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: http::Request<Incoming>) -> Self::Future {
        let sh = self.0.clone();
        Box::pin(async move { Ok(handle(sh, req).await) })
    }
}

/// Counts a request as in flight until its response body is dropped.
struct InFlight(Arc<H1State>);

impl InFlight {
    fn new(st: Arc<H1State>) -> Self {
        counters::bump(&st.in_flight);
        Self(st)
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        counters::dec(&self.0.in_flight);
    }
}

type Reserve = Pin<Box<dyn Future<Output = bool> + Send>>;

/// Response body: generated chunk by chunk, each chunk admitted by the ledger first.
struct OutBody {
    body: ReplyBody,
    off: u64,
    len: u64,
    chunk: u64,
    stall: Duration,
    ledger: Option<Arc<ConnLedger>>,
    pending: Option<Reserve>,
    _in_flight: InFlight,
}

impl Body for OutBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        let this = self.get_mut();
        if this.off >= this.len {
            return Poll::Ready(None);
        }
        let want = this.chunk.min(this.len.saturating_sub(this.off));
        if let Some(ledger) = &this.ledger {
            if this.pending.is_none() && !ledger.try_reserve(Side::Send, want) {
                let l = ledger.clone();
                let deadline = Instant::now() + this.stall;
                this.pending = Some(Box::pin(async move { l.reserve(Side::Send, want, deadline).await }));
            }
            if let Some(p) = this.pending.as_mut() {
                match p.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(false) => {
                        this.pending = None;
                        return Poll::Ready(Some(Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "response stalled on the connection ledger",
                        ))));
                    }
                    Poll::Ready(true) => this.pending = None,
                }
            }
        }
        let data = this.body.chunk(this.off, want);
        this.off = this.off.saturating_add(want);
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(data)))))
    }

    fn is_end_stream(&self) -> bool {
        self.off >= self.len
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.len.saturating_sub(self.off))
    }
}

fn out<A: App>(sh: &Shared<A>, reply: Reply, head_req: bool, close: bool, stall: Duration) -> http::Response<OutBody> {
    counters::bump(&sh.srv.counters.responses);
    let (mut parts, ()) = response_head(&reply, head_req).into_parts();
    if close {
        parts.headers.insert(http::header::CONNECTION, http::HeaderValue::from_static("close"));
    }
    let len = if head_req { 0 } else { reply.body.len() };
    let body = OutBody {
        body: reply.body,
        off: 0,
        len,
        chunk: sh.srv.limits.chunk_bytes,
        stall,
        ledger: if sh.srv.wrapper { Some(sh.ledger.clone()) } else { None },
        pending: None,
        _in_flight: InFlight::new(sh.st.clone()),
    };
    http::Response::from_parts(parts, body)
}

enum BodyErr {
    TooLarge,
    Stalled,
    Other,
}

async fn handle<A: App>(sh: Arc<Shared<A>>, req: http::Request<Incoming>) -> http::Response<OutBody> {
    let _f = InFlight::new(sh.st.clone());
    let srv = sh.srv.clone();
    let l = srv.limits;
    let stall = srv.stall();
    counters::bump(&srv.counters.streams_accepted);
    let _live = Gauge::up(&srv.counters.streams_live);
    let (parts, mut body) = req.into_parts();
    let head_req = parts.method == http::Method::HEAD;
    let hosts: Vec<&[u8]> = parts.headers.get_all(http::header::HOST).iter().map(|v| v.as_bytes()).collect();
    let raw = RawHead {
        proto: Proto::H1,
        method: &parts.method,
        scheme: None,
        authority: parts.uri.authority().map(|a| a.as_str().as_bytes()),
        hosts,
        origin: parts.headers.get(http::header::ORIGIN).map(http::HeaderValue::as_bytes),
        path_and_query: parts.uri.path_and_query().map_or(b"" as &[u8], |p| p.as_str().as_bytes()),
    };
    let adm = match admit(&srv.app, &srv.vhosts, &sh.info, &raw) {
        Ok(a) => a,
        Err(r) => {
            if r.authority {
                counters::bump(&srv.counters.authority_rejects);
            }
            // The unread body (if any) would desynchronize keep-alive: close after a reject.
            return out(&sh, r.reply, head_req, true, stall);
        }
    };
    let cap = body_cap(&adm.budget, l.max_body_bytes);
    let stall = Duration::from_millis(stall_ms(&adm.budget, l.stall_timeout_ms));
    let mut hold = RecvHold::empty(sh.ledger.clone());
    let message = match read_body(&sh, &mut body, cap, stall, &mut hold).await {
        Ok(m) => m,
        Err(BodyErr::TooLarge) => {
            counters::bump(&srv.counters.body_too_large);
            return out(&sh, Reply::status(413), head_req, true, stall);
        }
        Err(BodyErr::Stalled) => {
            counters::bump(&srv.counters.streams_stall_reaped);
            return out(&sh, Reply::status(408), head_req, true, stall);
        }
        Err(BodyErr::Other) => return out(&sh, Reply::status(400), head_req, true, stall),
    };
    let reply = finish(&srv.app, &adm, &message);
    drop(message);
    drop(hold);
    out(&sh, reply, head_req, false, stall)
}

async fn read_body<A: App>(
    sh: &Shared<A>,
    body: &mut Incoming,
    cap: u64,
    stall: Duration,
    hold: &mut RecvHold,
) -> Result<Vec<u8>, BodyErr> {
    let mut buf = Vec::new();
    let on = sh.srv.wrapper;
    loop {
        if body.is_end_stream() {
            return Ok(buf);
        }
        let deadline = Instant::now() + stall;
        let mut b = Pin::new(&mut *body);
        let next = if on {
            match timeout_at(deadline, poll_fn(|cx| b.as_mut().poll_frame(cx))).await {
                Ok(n) => n,
                Err(_) => return Err(BodyErr::Stalled),
            }
        } else {
            poll_fn(|cx| b.as_mut().poll_frame(cx)).await
        };
        let frame = match next {
            None => return Ok(buf),
            Some(Err(_)) => return Err(BodyErr::Other),
            Some(Ok(f)) => f,
        };
        let Ok(data) = frame.into_data() else { continue };
        let n = u64::try_from(data.len()).unwrap_or(u64::MAX);
        if u64::try_from(buf.len()).unwrap_or(u64::MAX).saturating_add(n) > cap {
            return Err(BodyErr::TooLarge);
        }
        if on {
            if !sh.ledger.reserve(Side::Recv, n, deadline).await {
                return Err(BodyErr::Stalled);
            }
            hold.grow(n);
        }
        buf.extend_from_slice(&data);
    }
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        408 => "Request Timeout",
        417 => "Expectation Failed",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    }
}

/// Drive one HTTP/1.1 connection to completion.
pub(crate) async fn serve<A, IO>(srv: Arc<Server<A>>, io: IO, info: ConnInfo)
where
    A: App,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let l = srv.limits;
    let on = srv.wrapper;
    let ledger = Arc::new(ConnLedger::new(if on { l.ledger_bytes } else { u64::MAX }));
    let st = Arc::new(H1State::default());
    let epoch = srv.instant_at(0);
    st.progress.touch(srv.now_ms());
    let validator = on.then(|| {
        H1Validator::new(HeadLimits {
            max_head_bytes: l.h1_max_head_bytes,
            max_field_bytes: l.max_header_list_size,
            max_fields: l.max_header_fields,
        })
    });
    let guard = H1Guard {
        io: CountingIo::new(io, ledger.clone(), Some((st.progress.clone(), epoch))),
        validator,
        inbuf: vec![0u8; 16_384],
        out: Vec::new(),
        pos: 0,
        eof: false,
        st: st.clone(),
    };
    let sh = Arc::new(Shared { srv: srv.clone(), info, ledger, st: st.clone() });
    let mut b = hyper::server::conn::http1::Builder::new();
    b.half_close(true)
        .keep_alive(true)
        .max_headers(usize_sat(l.max_header_fields).saturating_add(1))
        .max_buf_size(65_536)
        .header_read_timeout(None)
        .writev(false);
    let conn = b.serve_connection(guard, Svc(sh));
    let mut fut = pin!(conn.without_shutdown());
    let mut timer = pin!(sleep(Duration::from_millis(l.idle_timeout_ms)));
    let res = poll_fn(|cx| {
        if let Poll::Ready(r) = fut.as_mut().poll(cx) {
            return Poll::Ready(Some(r));
        }
        if !on {
            return Poll::Pending;
        }
        loop {
            // TBI-8: inside a message (head, body, or a response being written) the stall deadline applies;
            // between messages the idle deadline does.
            let busy = st.mid_message.load(Ordering::Relaxed) || st.in_flight.load(Ordering::Relaxed) > 0;
            let window = if busy { l.stall_timeout_ms } else { l.idle_timeout_ms };
            let deadline_ms = st.progress.get().saturating_add(window);
            if srv.now_ms() >= deadline_ms {
                if busy {
                    counters::bump(&srv.counters.streams_stall_reaped);
                } else {
                    counters::bump(&srv.counters.conns_idle_closed);
                }
                return Poll::Ready(None);
            }
            timer.as_mut().reset(srv.instant_at(deadline_ms));
            if timer.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
        }
    })
    .await;
    let Some(Ok(parts)) = res else { return };
    if let Some(rej) = st.reject() {
        counters::bump(&srv.counters.h1_rejects);
        if rej.status == 431 {
            counters::bump(&srv.counters.field_block_rejects);
        }
        let msg = format!(
            "HTTP/1.1 {} {}\r\nconnection: close\r\ncontent-length: 0\r\n\r\n",
            rej.status,
            reason_phrase(rej.status)
        );
        let mut io = parts.io.io.io;
        let _ = timeout(srv.stall(), async {
            io.write_all(msg.as_bytes()).await?;
            io.shutdown().await
        })
        .await;
    }
}
