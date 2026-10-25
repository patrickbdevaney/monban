//! HTTP/2 connection driver over h2 with the AEGIS wrapper (ARCHITECTURE §3.1).
//!
//! h2 carries the golden SETTINGS (max_concurrent_streams, max_header_list_size, header_table_size = TBI-3,
//! windows, max_frame, send buffer, pending-accept-reset and local-error-reset caps). The wrapper adds what h2
//! lacks: the TBI-1 field-count cap with cookie crumbs, the TBI-4 handler gate (live + queue, then GOAWAY
//! ENHANCE_YOUR_CALM), the TBI-5 peer-reset bucket, server-reset cap and total-streams cap, the TBI-6/7
//! per-connection ledger (request bytes are only released back to the peer as window when the ledger admits them;
//! response bytes are only handed to h2 when it admits them), and TBI-8 per-stream stall and connection idle
//! deadlines. Spikes/q2-009 is the prototype of the ledger + stall part. The request handler runs inside the stream
//! task, under its TBI-4 permit; its reply goes out through the same ledger-gated send path. Draining
//! (`Server::drain`) sends a graceful GOAWAY.

use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use aegis_canon::Proto;
use h2::server::SendResponse;
use h2::{Reason, RecvStream};
use hyper::body::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep, timeout_at};

use crate::counters;
use crate::fields::request_block;
use crate::ledger::{Admit, ConnLedger, HandlerGate, RecvHold, ResetBudget, Side};
use crate::limits::{WrapperLimits, u32_sat, usize_sat};
use crate::pipeline::{
    App, ConnFlags, ConnInfo, RawHead, Reply, admit, arrive, body_cap, finish, response_head, stall_ms,
};
use crate::server::{CountingIo, Gauge, Progress, Server};

/// Grace given to a GOAWAY to reach the peer before the transport is dropped.
const GOAWAY_GRACE: Duration = Duration::from_millis(1000);

struct Conn<A: App> {
    srv: Arc<Server<A>>,
    info: ConnInfo,
    flags: Arc<ConnFlags>,
    l: WrapperLimits,
    ledger: Arc<ConnLedger>,
    gate: HandlerGate,
    resets: ResetBudget,
    /// Last stream-level progress or new stream (TBI-8 idle clock).
    activity: Progress,
    calm: AtomicBool,
}

impl<A: App> Conn<A> {
    fn on(&self) -> bool {
        self.srv.wrapper
    }
    fn touch(&self) {
        self.activity.touch(self.srv.now_ms());
    }
    fn calm(&self) {
        self.calm.store(true, Ordering::Relaxed);
    }
    fn peer_reset(&self) {
        counters::bump(&self.srv.counters.peer_resets);
        if self.on() && !self.resets.peer_reset(self.srv.now_ns()) {
            self.calm();
        }
    }
    fn server_reset<B: hyper::body::Buf>(&self, send: &mut h2::SendStream<B>, reason: Reason) {
        send.send_reset(reason);
        self.count_server_reset();
    }
    fn count_server_reset(&self) {
        counters::bump(&self.srv.counters.server_resets);
        if self.on() && !self.resets.server_reset() {
            self.calm();
        }
    }
    fn reset_respond(&self, respond: &mut SendResponse<Bytes>, reason: Reason) {
        respond.send_reset(reason);
        self.count_server_reset();
    }
}

enum Ev<T> {
    Accept(Option<Result<T, h2::Error>>),
    Done,
    Timer,
    Drain,
}

/// Drive one HTTP/2 connection to completion.
pub(crate) async fn serve<A, IO>(srv: Arc<Server<A>>, io: IO, info: ConnInfo, flags: Arc<ConnFlags>)
where
    A: App,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let l = srv.limits();
    let on = srv.wrapper;
    let ledger = Arc::new(ConnLedger::new(if on { l.ledger_bytes } else { u64::MAX }));
    let io = CountingIo::new(io, ledger.clone(), None);
    let mut b = h2::server::Builder::new();
    b.initial_window_size(u32_sat(l.stream_window))
        .initial_connection_window_size(u32_sat(l.conn_window))
        .max_frame_size(u32_sat(l.max_frame_size))
        .max_header_list_size(u32_sat(l.max_header_list_size))
        .header_table_size(u32_sat(l.header_table_size))
        .max_concurrent_streams(u32_sat(l.max_concurrent_streams))
        .max_send_buffer_size(usize_sat(l.send_buffer))
        .max_pending_accept_reset_streams(usize_sat(l.max_pending_accept_resets))
        .max_local_error_reset_streams(if on { Some(usize_sat(l.max_local_error_resets)) } else { None });
    let deadline = Instant::now() + srv.stall();
    let mut conn = match timeout_at(deadline, b.handshake::<_, Bytes>(io)).await {
        Ok(Ok(c)) => c,
        _ => return,
    };
    let c = Arc::new(Conn {
        info,
        flags,
        l,
        ledger,
        gate: HandlerGate::new(usize_sat(l.max_concurrent_streams), l.handler_queue),
        resets: ResetBudget::new(l.rst_burst, l.rst_refill_per_s, l.max_local_error_resets, srv.now_ns()),
        activity: Progress::default(),
        calm: AtomicBool::new(false),
        srv,
    });
    c.touch();
    let srv = c.srv.clone();
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut accepted: u64 = 0;
    let mut closing_at: Option<Instant> = None;
    let mut timer = Box::pin(sleep(Duration::from_millis(l.idle_timeout_ms)));
    let mut drain = Box::pin(srv.drain_notify.notified());
    drain.as_mut().enable();
    let mut drained = false;
    loop {
        let idle_at = srv.instant_at(c.activity.get().saturating_add(l.idle_timeout_ms));
        let wake = match closing_at {
            Some(t) => t,
            None => idle_at,
        };
        timer.as_mut().reset(wake);
        let timer_live = on || closing_at.is_some();
        let ev = poll_fn(|cx| {
            if let Poll::Ready(r) = conn.poll_accept(cx) {
                return Poll::Ready(Ev::Accept(r));
            }
            if let Poll::Ready(Some(_)) = tasks.poll_join_next(cx) {
                return Poll::Ready(Ev::Done);
            }
            if timer_live && timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ev::Timer);
            }
            if !drained && (srv.is_draining() || drain.as_mut().poll(cx).is_ready()) {
                return Poll::Ready(Ev::Drain);
            }
            Poll::Pending
        })
        .await;
        match ev {
            Ev::Accept(None) | Ev::Accept(Some(Err(_))) => break,
            Ev::Accept(Some(Ok((req, mut respond)))) => {
                accepted = accepted.saturating_add(1);
                counters::bump(&srv.counters.streams_accepted);
                c.touch();
                if on && accepted > l.max_streams_per_conn {
                    c.reset_respond(&mut respond, Reason::REFUSED_STREAM);
                    continue;
                }
                if on && accepted == l.max_streams_per_conn {
                    counters::bump(&srv.counters.goaway_stream_cap);
                    conn.graceful_shutdown();
                }
                tasks.spawn(stream_task(c.clone(), req, respond));
            }
            Ev::Done => {}
            Ev::Drain => {
                drained = true;
                conn.graceful_shutdown();
            }
            Ev::Timer => {
                if closing_at.is_some_and(|t| Instant::now() >= t) {
                    break;
                }
                if on && closing_at.is_none() && srv.now_ms() >= c.activity.get().saturating_add(l.idle_timeout_ms) {
                    counters::bump(&srv.counters.conns_idle_closed);
                    conn.abrupt_shutdown(Reason::NO_ERROR);
                    closing_at = Some(Instant::now() + GOAWAY_GRACE);
                }
            }
        }
        if c.calm.load(Ordering::Relaxed) && closing_at.is_none() {
            counters::bump(&srv.counters.goaway_calm);
            conn.abrupt_shutdown(Reason::ENHANCE_YOUR_CALM);
            closing_at = Some(Instant::now() + GOAWAY_GRACE);
        }
        if on {
            c.ledger.reconcile_if_idle(tasks.len());
            counters::max(&srv.counters.ledger_peak_bytes, c.ledger.snapshot().peak());
        }
    }
    tasks.abort_all();
}

/// `true` if the peer already reset this stream (non-blocking).
fn reset_by_peer(respond: &mut SendResponse<Bytes>) -> bool {
    let mut cx = Context::from_waker(Waker::noop());
    matches!(respond.poll_reset(&mut cx), Poll::Ready(Ok(_)))
}

fn is_peer_reset(e: &h2::Error) -> bool {
    e.is_reset() && e.is_remote()
}

enum BodyErr {
    TooLarge,
    Stalled,
    PeerReset,
    Other,
}

async fn stream_task<A: App>(c: Arc<Conn<A>>, req: http::Request<RecvStream>, mut respond: SendResponse<Bytes>) {
    let srv = c.srv.clone();
    let l = c.l;
    let on = c.on();
    let _live = Gauge::up(&srv.counters.streams_live);
    let stall = srv.stall();

    // TBI-1: field block bytes and count (cookie crumbs individually); h2 already bounded the bytes while
    // decoding (SETTINGS_MAX_HEADER_LIST_SIZE), the count is ours.
    let fb = request_block(&req, true);
    let mut hold = RecvHold::empty(c.ledger.clone());
    if on {
        if !fb.within(l.max_header_list_size, l.max_header_fields) {
            counters::bump(&srv.counters.field_block_rejects);
            send_reply(&c, &mut respond, Reply::status(431), false, stall).await;
            return;
        }
        // TBI-7: the decoded block lives as long as the task; account it.
        if !c.ledger.try_reserve(Side::Recv, fb.bytes()) {
            counters::bump(&srv.counters.ledger_waits);
            c.reset_respond(&mut respond, Reason::REFUSED_STREAM);
            return;
        }
        hold.grow(fb.bytes());
    }

    // TBI-4: one permit per live handler, held until this task ends.
    let _permit = if on {
        match c.gate.admit(Instant::now() + stall).await {
            Admit::Permit(p) => Some(p),
            Admit::QueueFull => {
                counters::bump(&srv.counters.streams_queue_overflow);
                c.calm();
                return;
            }
            Admit::Timeout => {
                c.reset_respond(&mut respond, Reason::REFUSED_STREAM);
                return;
            }
        }
    } else {
        None
    };
    if reset_by_peer(&mut respond) {
        c.peer_reset();
        return;
    }

    let (parts, mut body) = req.into_parts();
    let head_req = parts.method == http::Method::HEAD;
    let mut arrival = match arrive(&srv.app, &c.info, &c.flags) {
        Ok(a) => a,
        Err(reply) => {
            send_reply(&c, &mut respond, reply, head_req, stall).await;
            return;
        }
    };
    let hosts: Vec<&[u8]> = parts.headers.get_all(http::header::HOST).iter().map(|v| v.as_bytes()).collect();
    // RFC 9113 §8.2.3: cookie crumbs are concatenated with "; " before anything else sees them.
    let cookie: Vec<u8> =
        parts.headers.get_all(http::header::COOKIE).iter().map(|v| v.as_bytes()).collect::<Vec<_>>().join(&b"; "[..]);
    let mut fields: Vec<(&[u8], &[u8])> = parts
        .headers
        .iter()
        .filter(|(n, _)| *n != http::header::COOKIE)
        .map(|(n, v)| (n.as_str().as_bytes(), v.as_bytes()))
        .collect();
    if !cookie.is_empty() {
        fields.push((b"cookie", &cookie));
    }
    let raw = RawHead {
        proto: Proto::H2,
        method: &parts.method,
        scheme: parts.uri.scheme_str(),
        authority: parts.uri.authority().map(|a| a.as_str().as_bytes()),
        hosts,
        origin: parts.headers.get(http::header::ORIGIN).map(http::HeaderValue::as_bytes),
        path_and_query: parts.uri.path_and_query().map_or(b"" as &[u8], |p| p.as_str().as_bytes()),
        fields,
    };
    let adm = match admit(&srv.app, &srv.vhosts(), &c.info, &raw) {
        Ok(a) => a,
        Err(r) => {
            if r.authority {
                counters::bump(&srv.counters.authority_rejects);
            }
            arrival.complete();
            send_reply(&c, &mut respond, r.reply, head_req, stall).await;
            return;
        }
    };
    let cap = body_cap(&adm.budget, l.max_body_bytes);
    let stall = Duration::from_millis(stall_ms(&adm.budget, l.stall_timeout_ms));
    let message = match read_body(&c, &mut body, cap, stall, &mut hold).await {
        Ok(m) => m,
        Err(BodyErr::TooLarge) => {
            counters::bump(&srv.counters.body_too_large);
            send_reply(&c, &mut respond, Reply::status(413), head_req, stall).await;
            return;
        }
        Err(BodyErr::Stalled) => {
            counters::bump(&srv.counters.streams_stall_reaped);
            c.reset_respond(&mut respond, Reason::CANCEL);
            return;
        }
        Err(BodyErr::PeerReset) => {
            c.peer_reset();
            return;
        }
        Err(BodyErr::Other) => return,
    };
    drop(body);
    let reply = finish(&srv.app, adm, &c.info, message, stall).await;
    arrival.complete();
    drop(hold);
    c.touch();
    if reset_by_peer(&mut respond) {
        c.peer_reset();
        return;
    }
    send_reply(&c, &mut respond, reply, head_req, stall).await;
}

async fn read_body<A: App>(
    c: &Conn<A>,
    body: &mut RecvStream,
    cap: u64,
    stall: Duration,
    hold: &mut RecvHold,
) -> Result<Vec<u8>, BodyErr> {
    let mut buf = Vec::new();
    if body.is_end_stream() {
        return Ok(buf);
    }
    let on = c.on();
    loop {
        let deadline = Instant::now() + stall;
        let next = if on {
            match timeout_at(deadline, poll_fn(|cx| body.poll_data(cx))).await {
                Ok(n) => n,
                Err(_) => return Err(BodyErr::Stalled),
            }
        } else {
            poll_fn(|cx| body.poll_data(cx)).await
        };
        let chunk = match next {
            None => return Ok(buf),
            Some(Err(e)) if is_peer_reset(&e) => return Err(BodyErr::PeerReset),
            Some(Err(_)) => return Err(BodyErr::Other),
            Some(Ok(chunk)) => chunk,
        };
        let n = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        if u64::try_from(buf.len()).unwrap_or(u64::MAX).saturating_add(n) > cap {
            return Err(BodyErr::TooLarge);
        }
        // TBI-6: the bytes move from h2's window into our buffer; window is given back to the peer only once the
        // ledger has admitted them, so buffered bytes never exceed what we advertised.
        if on {
            if !c.ledger.try_reserve(Side::Recv, n) {
                counters::bump(&c.srv.counters.ledger_waits);
                if !c.ledger.reserve(Side::Recv, n, deadline).await {
                    return Err(BodyErr::Stalled);
                }
            }
            hold.grow(n);
        }
        buf.extend_from_slice(&chunk);
        drop(chunk);
        let _ = body.flow_control().release_capacity(usize::try_from(n).unwrap_or(usize::MAX));
        c.touch();
    }
}

/// Send a reply under the ledger and the stall deadline (TBI-6/7/8).
async fn send_reply<A: App>(
    c: &Conn<A>,
    respond: &mut SendResponse<Bytes>,
    reply: Reply,
    head_req: bool,
    stall: Duration,
) {
    let srv = &c.srv;
    let l = c.l;
    let on = c.on();
    let body_len = reply.sent_len(head_req);
    let mut send = match respond.send_response(response_head(&reply, head_req), body_len == 0) {
        Ok(s) => s,
        Err(_) => {
            if reset_by_peer(respond) {
                c.peer_reset();
            }
            return;
        }
    };
    counters::bump(&srv.counters.responses);
    c.touch();
    let mut off: u64 = 0;
    let mut last_progress = Instant::now();
    while off < body_len {
        let deadline = last_progress + stall;
        let want = l.chunk_bytes.min(body_len.saturating_sub(off));
        if on && !c.ledger.try_reserve(Side::Send, want) {
            counters::bump(&srv.counters.ledger_waits);
            if !c.ledger.reserve(Side::Send, want, deadline).await {
                counters::bump(&srv.counters.streams_stall_reaped);
                c.server_reset(&mut send, Reason::CANCEL);
                return;
            }
        }
        // Without the wrapper: the stock pattern (reserve up to the send buffer, as hyper does for a body chunk).
        let reserve = if on { want } else { body_len.saturating_sub(off).min(l.send_buffer) };
        send.reserve_capacity(usize_sat(reserve));
        let cap = loop {
            let cap = u64::try_from(send.capacity()).unwrap_or(0);
            if cap > 0 {
                break cap;
            }
            let polled = if on {
                match timeout_at(deadline, poll_fn(|cx| send.poll_capacity(cx))).await {
                    Ok(p) => p,
                    Err(_) => {
                        unreserve(c, want);
                        counters::bump(&srv.counters.streams_stall_reaped);
                        c.server_reset(&mut send, Reason::CANCEL);
                        return;
                    }
                }
            } else {
                poll_fn(|cx| send.poll_capacity(cx)).await
            };
            match polled {
                Some(Ok(_)) => {}
                Some(Err(e)) => {
                    unreserve(c, want);
                    if is_peer_reset(&e) {
                        c.peer_reset();
                    }
                    return;
                }
                None => {
                    unreserve(c, want);
                    return;
                }
            }
        };
        let n = cap.min(want);
        if on && n < want {
            unreserve(c, want.saturating_sub(n));
        }
        let end = off.saturating_add(n) >= body_len;
        if send.send_data(Bytes::from(reply.body.chunk(off, n)), end).is_err() {
            unreserve(c, n);
            return;
        }
        off = off.saturating_add(n);
        last_progress = Instant::now();
        c.touch();
    }
}

/// Give back a send reservation that was never handed to h2.
fn unreserve<A: App>(c: &Conn<A>, n: u64) {
    if c.on() {
        c.ledger.written(n);
    }
}
