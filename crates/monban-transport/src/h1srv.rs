//! HTTP/1.1 connection driver: hyper's h1 server behind the strict framing filter ([`crate::h1::H1Validator`]),
//! with a TBI-8 watchdog (head / body / response stall deadline, idle deadline) and the TBI-6/7 ledger on the
//! response path. One request at a time per connection, so TBI-4 holds by construction (≤ 1 live handler). While
//! the handler runs the watchdog is suspended (the handler is bounded by the exchange's stall deadline itself) and
//! the transport is probed instead: a client FIN or TCP RST ends the connection, which drops the handler future
//! (INV-NOMUT-C NC1: an h1 close before the commit point cancels the request, so a half-closed client gets no
//! reply from a handler that has not answered yet).
//! Draining (`Server::drain`) closes an idle connection and ends a busy one after its current response.

use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use monban_canon::Proto;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::{Instant, sleep, timeout, timeout_at};

use crate::counters;
use crate::h1::{H1Reject, H1Validator, HeadLimits};
use crate::ledger::{ConnLedger, RecvHold, Side};
use crate::limits::WrapperLimits;
use crate::limits::usize_sat;
use crate::pipeline::{
    App, ConnFlags, ConnInfo, RawHead, Reply, ReplyBody, admit, arrive, body_cap, finish, response_head, stall_ms,
};
use crate::server::{CountingIo, Gauge, Progress, Server};

/// State shared by the I/O filter, the service and the watchdog.
#[derive(Debug, Default)]
struct H1State {
    progress: Arc<Progress>,
    head_partial: AtomicBool,
    mid_message: AtomicBool,
    in_flight: AtomicU64,
    /// Handlers running (watchdog suspended while > 0).
    handling: AtomicU64,
    reject: Mutex<Option<H1Reject>>,
    /// The reject hit a message body: hyper already has that request's head and answers it (R6).
    reject_in_body: AtomicBool,
    /// Request heads the filter forwarded to hyper.
    heads: AtomicU64,
    /// Responses the service handed to hyper (one per dispatched request).
    answered: AtomicU64,
}

impl H1State {
    fn reject(&self) -> Option<H1Reject> {
        *self.reject.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The connection's transport and read filter, shared by hyper (through [`H1Guard`]) and the serve loop's
/// peer-gone probe (both on the connection task, so the lock is never contended).
struct GuardIo<IO> {
    io: CountingIo<IO>,
    validator: Option<H1Validator>,
    inbuf: Vec<u8>,
    out: Vec<u8>,
    pos: usize,
    eof: bool,
    st: Arc<H1State>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> GuardIo<IO> {
    fn filtered(&self) -> &[u8] {
        self.out.get(self.pos..).unwrap_or(&[])
    }

    fn closed(&self) -> bool {
        self.eof || self.validator.as_ref().is_some_and(|v| v.rejected().is_some())
    }

    /// One read from the transport (into the fixed `inbuf`) through the strict framing filter into `out`.
    fn fill(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut tmp = ReadBuf::new(&mut self.inbuf);
        match Pin::new(&mut self.io).poll_read(cx, &mut tmp) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        let got = tmp.filled();
        if got.is_empty() {
            self.eof = true;
            return Poll::Ready(Ok(()));
        }
        match self.validator.as_mut() {
            Some(v) => {
                if let Err(r) = v.feed(got, &mut self.out) {
                    *self.st.reject.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(r);
                    self.st.reject_in_body.store(v.rejected_in_body(), Ordering::Relaxed);
                }
                self.st.heads.store(v.heads_forwarded(), Ordering::Relaxed);
                self.st.head_partial.store(v.head_partial(), Ordering::Relaxed);
                self.st.mid_message.store(v.mid_message(), Ordering::Relaxed);
            }
            None => self.out.extend_from_slice(got),
        }
        Poll::Ready(Ok(()))
    }

    /// While a handler runs hyper does not read (`half_close`), so a client FIN or TCP RST would go unseen until
    /// the reply. `true` once the peer is gone: EOF or a read error. Reads at most one `inbuf` worth ahead: bytes
    /// that arrive meanwhile (a pipelined request) are filtered into `out` and replayed to hyper later, and probing
    /// pauses until hyper has consumed them (the handler stays bounded by the exchange stall deadline either way).
    fn peer_gone(&mut self, cx: &mut Context<'_>) -> bool {
        if self.eof {
            return true;
        }
        if self.closed() || !self.filtered().is_empty() {
            return false;
        }
        match self.fill(cx) {
            Poll::Pending => false,
            Poll::Ready(Err(_)) => true,
            Poll::Ready(Ok(())) => self.eof,
        }
    }
}

fn lock<IO>(m: &Mutex<GuardIo<IO>>) -> std::sync::MutexGuard<'_, GuardIo<IO>> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// hyper I/O adapter: reads pass through the strict framing filter; writes go to the counting transport.
struct H1Guard<IO>(Arc<Mutex<GuardIo<IO>>>);

impl<IO: AsyncRead + AsyncWrite + Unpin> hyper::rt::Read for H1Guard<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = lock(&self.0);
        loop {
            let avail = this.filtered();
            if !avail.is_empty() {
                let n = avail.len().min(buf.remaining());
                buf.put_slice(avail.get(..n).unwrap_or(&[]));
                this.pos = this.pos.saturating_add(n);
                if this.pos >= this.out.len() {
                    this.out.clear();
                    this.pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.closed() {
                return Poll::Ready(Ok(()));
            }
            match this.fill(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> hyper::rt::Write for H1Guard<IO> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut lock(&self.0).io).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut lock(&self.0).io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut lock(&self.0).io).poll_shutdown(cx)
    }
}

struct Shared<A: App> {
    srv: Arc<Server<A>>,
    info: ConnInfo,
    flags: Arc<ConnFlags>,
    l: WrapperLimits,
    ledger: Arc<ConnLedger>,
    st: Arc<H1State>,
}

/// Marks a handler as running; the I/O progress clock restarts when it returns.
struct Handling<'a, A: App>(&'a Shared<A>);

impl<'a, A: App> Handling<'a, A> {
    fn new(sh: &'a Shared<A>) -> Self {
        counters::bump(&sh.st.handling);
        Self(sh)
    }
}

impl<A: App> Drop for Handling<'_, A> {
    fn drop(&mut self) {
        self.0.st.progress.touch(self.0.srv.now_ms());
        counters::dec(&self.0.st.handling);
    }
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
    counters::bump(&sh.st.answered);
    let (mut parts, ()) = response_head(&reply, head_req).into_parts();
    if close || sh.srv.is_draining() {
        parts.headers.insert(http::header::CONNECTION, http::HeaderValue::from_static("close"));
    }
    let len = reply.sent_len(head_req);
    let body = OutBody {
        body: reply.body,
        off: 0,
        len,
        chunk: sh.l.chunk_bytes,
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
    let l = sh.l;
    let stall = Duration::from_millis(l.stall_timeout_ms);
    counters::bump(&srv.counters.streams_accepted);
    let _live = Gauge::up(&srv.counters.streams_live);
    let (parts, mut body) = req.into_parts();
    let head_req = parts.method == http::Method::HEAD;
    // A reply sent before the body was read would desynchronize keep-alive: close after it.
    let unread = !body.is_end_stream();
    let mut arrival = match arrive(&srv.app, &sh.info, &sh.flags) {
        Ok(a) => a,
        Err(reply) => return out(&sh, reply, head_req, unread, stall),
    };
    let hosts: Vec<&[u8]> = parts.headers.get_all(http::header::HOST).iter().map(|v| v.as_bytes()).collect();
    let raw = RawHead {
        proto: Proto::H1,
        method: &parts.method,
        scheme: None,
        authority: parts.uri.authority().map(|a| a.as_str().as_bytes()),
        hosts,
        origin: parts.headers.get(http::header::ORIGIN).map(http::HeaderValue::as_bytes),
        path_and_query: parts.uri.path_and_query().map_or(b"" as &[u8], |p| p.as_str().as_bytes()),
        fields: parts.headers.iter().map(|(n, v)| (n.as_str().as_bytes(), v.as_bytes())).collect(),
    };
    let adm = match admit(&srv.app, &srv.vhosts(), &sh.info, &raw) {
        Ok(a) => a,
        Err(r) => {
            if r.authority {
                counters::bump(&srv.counters.authority_rejects);
            }
            arrival.complete();
            return out(&sh, r.reply, head_req, unread, stall);
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
        // R6: a strict-filter reject inside this body ended the stream hyper reads; this is the one response to the
        // request, with the reject's status, and `serve` adds none.
        Err(BodyErr::Other) => {
            let status = sh.st.reject().map_or(400, |r| r.status);
            return out(&sh, Reply::status(status), head_req, true, stall);
        }
    };
    let reply = {
        let _h = Handling::new(&sh);
        finish(&srv.app, adm, &sh.info, message, stall).await
    };
    arrival.complete();
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
pub(crate) async fn serve<A, IO>(srv: Arc<Server<A>>, io: IO, info: ConnInfo, flags: Arc<ConnFlags>)
where
    A: App,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let l = srv.limits();
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
    let shared_io = Arc::new(Mutex::new(GuardIo {
        io: CountingIo::new(io, ledger.clone(), Some((st.progress.clone(), epoch))),
        validator,
        inbuf: vec![0u8; 16_384],
        out: Vec::new(),
        pos: 0,
        eof: false,
        st: st.clone(),
    }));
    let guard = H1Guard(shared_io.clone());
    let sh = Arc::new(Shared { srv: srv.clone(), info, flags, l, ledger, st: st.clone() });
    let mut b = hyper::server::conn::http1::Builder::new();
    b.half_close(true)
        .keep_alive(true)
        .max_headers(usize_sat(l.max_header_fields).saturating_add(1))
        .max_buf_size(65_536)
        .header_read_timeout(None)
        .writev(false);
    let mut conn = b.serve_connection(guard, Svc(sh));
    let mut timer = pin!(sleep(Duration::from_millis(l.idle_timeout_ms)));
    let mut drain = pin!(srv.drain_notify.notified());
    drain.as_mut().enable();
    let mut drained = false;
    let res = poll_fn(|cx| {
        if !drained && (srv.is_draining() || drain.as_mut().poll(cx).is_ready()) {
            drained = true;
            Pin::new(&mut conn).graceful_shutdown();
        }
        if let Poll::Ready(r) = conn.poll_without_shutdown(cx) {
            return Poll::Ready(Some(r));
        }
        if st.handling.load(Ordering::Relaxed) > 0 {
            // NC1: the client closed (FIN) or reset the connection while the handler runs: end the connection,
            // which drops the service future and with it the handler, before its commit point.
            if lock(&shared_io).peer_gone(cx) {
                counters::bump(&srv.counters.handlers_aborted);
                return Poll::Ready(None);
            }
            return Poll::Pending;
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
    let Some(Ok(())) = res else { return };
    if let Some(rej) = st.reject() {
        counters::bump(&srv.counters.h1_rejects);
        if rej.status == 431 {
            counters::bump(&srv.counters.field_block_rejects);
        }
        // R6 (RFC 9110: one final response per request). The client sent `heads` requests hyper saw, plus the
        // rejected one when the reject hit its head. A reject inside a body belongs to a request hyper dispatched
        // and (normally) answered with `connection: close`; the filter answers only a request nobody answered.
        let sent =
            st.heads.load(Ordering::Relaxed).saturating_add(u64::from(!st.reject_in_body.load(Ordering::Relaxed)));
        let msg = (st.answered.load(Ordering::Relaxed) < sent).then(|| {
            format!(
                "HTTP/1.1 {} {}\r\nconnection: close\r\ncontent-length: 0\r\n\r\n",
                rej.status,
                reason_phrase(rej.status)
            )
        });
        let H1Guard(guard) = conn.into_parts().io;
        drop(shared_io);
        let Ok(gio) = Arc::try_unwrap(guard) else { return };
        let mut io = gio.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner).io.io;
        let _ = timeout(srv.stall(), async {
            if let Some(m) = &msg {
                io.write_all(m.as_bytes()).await?;
            }
            io.shutdown().await
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    //! R6 (P7-oracle-uring-001 finding 2): one malformed chunked request gets exactly one response, then a close.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use std::sync::atomic::AtomicUsize;

    use monban_canon::Canon;
    use monban_canon::kind::{Authority, RoutePath};
    use monban_types::RouteId;
    use tokio::io::{AsyncReadExt, DuplexStream};

    use super::*;
    use crate::exchange::{ExchangeBudget, FrontEnd, Head, HeadVerdict, MessageVerdict, Method, Mode};
    use crate::{ReplyBody, VhostTable};

    /// Counts handler calls: a rejected body must never reach the handler.
    #[derive(Default)]
    struct T {
        handled: AtomicUsize,
    }

    const BUDGET: ExchangeBudget = ExchangeBudget {
        max_message_bytes: 65_536,
        max_frame_bytes: 16_384,
        max_messages: 1,
        max_total_bytes: 65_536,
        stall_ms: 120_000,
    };

    impl FrontEnd for T {
        fn on_head(&self, _h: &Head<'_>) -> HeadVerdict {
            HeadVerdict::Accept(Mode::Unary, BUDGET)
        }
        fn on_message(&self, _h: &Head<'_>, _m: &[u8]) -> MessageVerdict {
            MessageVerdict::Continue
        }
    }

    impl App for T {
        fn route(&self, _a: &Canon<Authority>, _p: &Canon<RoutePath>, _m: Method) -> Option<RouteId> {
            RouteId::new(1).ok()
        }
        fn respond(&self, _h: &Head<'_>, _m: &[u8]) -> Reply {
            self.handled.fetch_add(1, Ordering::SeqCst);
            Reply::new(200, "text/plain", ReplyBody::Static(b"ok"))
        }
    }

    fn server() -> Arc<Server<T>> {
        let mut l = WrapperLimits::GOLDEN;
        l.set_f8("stall_timeout_ms", 300).unwrap();
        l.set_f8("idle_timeout_ms", 1000).unwrap();
        let mut v = VhostTable::new();
        v.add(b"monban.test", &[]);
        Server::new(T::default(), v, l).unwrap()
    }

    /// Sends `parts` (with a short pause between them, so each is a separate read), keeps the write side open
    /// (the server must close on its own), and returns everything received until the server closes (5 s cap).
    async fn exchange(srv: &Arc<Server<T>>, parts: &[&[u8]]) -> (String, bool) {
        let (mut io, server_io): (DuplexStream, DuplexStream) = tokio::io::duplex(1 << 20);
        let h = tokio::spawn(srv.clone().serve_plain(server_io));
        for (i, p) in parts.iter().enumerate() {
            if i > 0 {
                sleep(Duration::from_millis(30)).await;
            }
            io.write_all(p).await.unwrap();
        }
        let mut out = Vec::new();
        let closed = timeout(Duration::from_secs(5), io.read_to_end(&mut out)).await.is_ok();
        let _ = timeout(Duration::from_secs(5), h).await;
        (String::from_utf8_lossy(&out).into_owned(), closed)
    }

    fn statuses(resp: &str) -> Vec<&str> {
        resp.match_indices("HTTP/1.1 ").map(|(i, _)| resp.get(i + 9..i + 12).unwrap_or("")).collect()
    }

    const HEAD: &[u8] = b"POST /x HTTP/1.1\r\nHost: monban.test\r\nTransfer-Encoding: chunked\r\n\r\n";

    #[test]
    fn r6_one_response_per_malformed_chunked_request() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let srv = server();
            let ext = format!("1;{}\r\nz\r\n0\r\n\r\n", "e".repeat(20_000));
            let cases: Vec<(&str, Vec<Vec<u8>>, &str)> = vec![
                ("bad-size", vec![[HEAD, b"zz\r\nhello\r\n0\r\n\r\n"].concat()], "400"),
                ("bare-lf", vec![[HEAD, b"5\nhello\r\n0\r\n\r\n"].concat()], "400"),
                ("bad-size split", vec![HEAD.to_vec(), b"zz\r\nhello\r\n0\r\n\r\n".to_vec()], "400"),
                ("bare-lf split", vec![HEAD.to_vec(), b"5\nhello\r\n0\r\n\r\n".to_vec()], "400"),
                ("data not CRLF", vec![[HEAD, b"3\r\nabcX0\r\n\r\n"].concat()], "400"),
                ("ext over TBI-1", vec![[HEAD, ext.as_bytes()].concat()], "431"),
            ];
            for (name, parts, want) in &cases {
                let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
                let (resp, closed) = exchange(&srv, &parts).await;
                assert_eq!(statuses(&resp), vec![*want], "{name}: exactly one response: {resp:?}");
                assert!(closed, "{name}: the server closes after the reject: {resp:?}");
            }
            assert_eq!(srv.app.handled.load(Ordering::SeqCst), 0, "a rejected body never reaches the handler");
            let rejects = srv.counters().snapshot().into_iter().find(|(k, _)| *k == "h1_rejects").map(|(_, v)| v);
            assert_eq!(rejects, Some(u64::try_from(cases.len()).unwrap()), "each reject counted once");

            // Head-level reject: nothing reached hyper, so the filter answers (once).
            let (resp, closed) = exchange(&srv, &[b"GET / HTTP/1.1\nHost: monban.test\r\n\r\n"]).await;
            assert_eq!(statuses(&resp), vec!["400"], "{resp:?}");
            assert!(closed);
            // Pipelined: a valid request then a bad head is two requests, two responses (200, then the filter's 400).
            let two: &[u8] = b"GET / HTTP/1.1\r\nHost: monban.test\r\n\r\nGET / HTTP/1.1\nHost: monban.test\r\n\r\n";
            let (resp, closed) = exchange(&srv, &[two]).await;
            assert_eq!(statuses(&resp), vec!["200", "400"], "{resp:?}");
            assert!(closed);
            // A valid request then a bad chunk line in the next request's body: 200, then one 400.
            let (resp, closed) =
                exchange(&srv, &[&[b"GET / HTTP/1.1\r\nHost: monban.test\r\n\r\n", HEAD, b"zz\r\n"].concat()]).await;
            assert_eq!(statuses(&resp), vec!["200", "400"], "{resp:?}");
            assert!(closed);
            // Positive control: a well-formed chunked POST is answered once with 200.
            let (resp, _) = exchange(
                &srv,
                &[b"POST /x HTTP/1.1\r\nHost: monban.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n"],
            )
            .await;
            assert_eq!(statuses(&resp), vec!["200"], "{resp:?}");
        });
    }
}
