//! Inbound HTTP/2 driver over the `h2` crate, with the golden settings from the transport's `WrapperLimits`
//! (max_concurrent_streams, header list / table size, windows, frame size, send buffer, pending-accept and
//! local-error reset caps) and, on top: TBI-1 field-block bound per request (transport `FieldBlock`, cookie crumbs
//! counted), `max_streams_per_conn` then GOAWAY, a stall deadline on every body read / capacity wait, and the idle
//! deadline. The full AEGIS h2 wrapper (TBI-4 handler queue, TBI-5 RST bucket, TBI-6/7 ledger) lives inside
//! `aegis_transport::Server`, whose front-end API cannot forward yet (see the unit report); until it can, this
//! driver is the proxy's h2 path.

use std::future::poll_fn;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use aegis_canon::Proto;
use aegis_transport::FieldBlock;
use h2::server::SendResponse;
use h2::{Reason, RecvStream};
use hyper::body::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{sleep, timeout};

use crate::h1in::ConnMeta;
use crate::proxy::{self, Inbound, Reply};
use crate::shared::{Shared, bump};
use crate::util::{Either, race};

fn u32_sat(v: u64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}
fn usize_sat(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

struct Active(Arc<AtomicUsize>);
impl Active {
    fn new(a: &Arc<AtomicUsize>) -> Self {
        a.fetch_add(1, Ordering::AcqRel);
        Self(a.clone())
    }
}
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Drive one HTTP/2 connection.
pub async fn serve<IO: AsyncRead + AsyncWrite + Unpin + Send + 'static>(shared: Arc<Shared>, io: IO, meta: ConnMeta) {
    let wl = shared.snapshot().plan.wl;
    let stall = Duration::from_millis(wl.stall_timeout_ms);
    let idle = Duration::from_millis(wl.idle_timeout_ms);
    let mut b = h2::server::Builder::new();
    b.initial_window_size(u32_sat(wl.stream_window))
        .initial_connection_window_size(u32_sat(wl.conn_window))
        .max_frame_size(u32_sat(wl.max_frame_size))
        .max_header_list_size(u32_sat(wl.max_header_list_size))
        .header_table_size(u32_sat(wl.header_table_size))
        .max_concurrent_streams(u32_sat(wl.max_concurrent_streams))
        .max_send_buffer_size(usize_sat(wl.send_buffer))
        .max_pending_accept_reset_streams(usize_sat(wl.max_pending_accept_resets))
        .max_local_error_reset_streams(Some(usize_sat(wl.max_local_error_resets)));
    let mut conn = match timeout(stall, b.handshake::<_, Bytes>(io)).await {
        Ok(Ok(c)) => c,
        _ => return,
    };
    let active = Arc::new(AtomicUsize::new(0));
    let mut accepted: u64 = 0;
    let mut shutting = false;
    loop {
        let notified = shared.drain_notify.notified();
        let mut notified = pin!(notified);
        notified.as_mut().enable();
        if shared.is_draining() && !shutting {
            conn.graceful_shutdown();
            shutting = true;
        }
        let ev = race(conn.accept(), race(sleep(idle), notified)).await;
        match ev {
            Either::Left(Some(Ok((req, mut respond)))) => {
                accepted = accepted.saturating_add(1);
                if accepted > wl.max_streams_per_conn {
                    respond.send_reset(Reason::REFUSED_STREAM);
                    if !shutting {
                        conn.graceful_shutdown();
                        shutting = true;
                    }
                    continue;
                }
                let guard = Active::new(&active);
                tokio::spawn(stream_task(shared.clone(), req, respond, meta.clone(), accepted == 1, wl, guard));
            }
            Either::Left(Some(Err(_)) | None) => break,
            Either::Right(Either::Left(())) => {
                if active.load(Ordering::Acquire) == 0 {
                    if shutting {
                        break;
                    }
                    conn.graceful_shutdown();
                    shutting = true;
                }
            }
            Either::Right(Either::Right(())) => {}
        }
    }
    if accepted > 0 {
        shared.conn_closed(&meta.peer);
    }
}

async fn stream_task(
    shared: Arc<Shared>,
    req: http::Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    meta: ConnMeta,
    newconn: bool,
    wl: aegis_transport::WrapperLimits,
    _active: Active,
) {
    let stall = Duration::from_millis(wl.stall_timeout_ms);
    let (parts, mut recv) = req.into_parts();
    let head_req = parts.method == http::Method::HEAD;
    // TBI-1: decoded field block (pseudo-fields included) and field count (cookie crumbs counted).
    let mut fb = FieldBlock::new();
    fb.add(b":method", parts.method.as_str().as_bytes());
    if let Some(s) = parts.uri.scheme_str() {
        fb.add(b":scheme", s.as_bytes());
    }
    if let Some(a) = parts.uri.authority() {
        fb.add(b":authority", a.as_str().as_bytes());
    }
    let target = parts.uri.path_and_query().map(|p| p.as_str().as_bytes()).unwrap_or(b"");
    fb.add(b":path", target);
    for (n, v) in &parts.headers {
        fb.add(n.as_str().as_bytes(), v.as_bytes());
    }
    let id = shared.next_id();
    bump(&shared.stats.requests);
    if !fb.within(wl.max_header_list_size, wl.max_header_fields) {
        send_reply(&mut respond, &Reply::status(431), head_req, stall).await;
        return;
    }
    let scheme_ok = parts.uri.scheme_str().map(str::as_bytes) == Some(meta.scheme.as_str().as_bytes());
    if !scheme_ok || target.is_empty() {
        send_reply(&mut respond, &Reply::status(400), head_req, stall).await;
        return;
    }
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
    if let Err(status) = shared.admit(id, &meta.peer, newconn) {
        send_reply(&mut respond, &Reply::status(status), head_req, stall).await;
        return;
    }
    let inb = Inbound {
        proto: Proto::H2,
        scheme: meta.scheme,
        sni: meta.sni.as_deref(),
        method: parts.method.as_str().as_bytes(),
        authority: parts.uri.authority().map(|a| a.as_str().as_bytes()),
        target,
        fields,
    };
    let adm = match proxy::head(&shared, &inb) {
        Ok(a) => a,
        Err(reply) => {
            shared.done(id, false);
            send_reply(&mut respond, &reply, head_req, stall).await;
            return;
        }
    };
    let mut body = Vec::new();
    loop {
        match timeout(stall, recv.data()).await {
            Err(_) | Ok(Some(Err(_))) => {
                shared.done(id, true);
                respond.send_reset(Reason::CANCEL);
                return;
            }
            Ok(None) => break,
            Ok(Some(Ok(chunk))) => {
                let _ = recv.flow_control().release_capacity(chunk.len());
                if u64::try_from(body.len().saturating_add(chunk.len())).unwrap_or(u64::MAX) > adm.body_cap {
                    shared.done(id, true);
                    send_reply(&mut respond, &Reply::status(413), head_req, stall).await;
                    return;
                }
                body.extend_from_slice(&chunk);
            }
        }
    }
    let reply = proxy::forward(&shared, &adm, &body).await;
    shared.done(id, false);
    send_reply(&mut respond, &reply, head_req, stall).await;
}

async fn send_reply(respond: &mut SendResponse<Bytes>, reply: &Reply, head_req: bool, stall: Duration) {
    let mut b = http::Response::builder().status(reply.status);
    for (n, v) in &reply.headers {
        if n == b"content-length" {
            continue;
        }
        if let (Ok(n), Ok(v)) = (http::HeaderName::from_bytes(n), http::HeaderValue::from_bytes(v)) {
            b = b.header(n, v);
        }
    }
    match reply.explicit_length() {
        Some(l) => {
            if let Ok(v) = http::HeaderValue::from_bytes(l) {
                b = b.header(http::header::CONTENT_LENGTH, v);
            }
        }
        None if reply.status == 204 || reply.status == 304 => {}
        None => b = b.header(http::header::CONTENT_LENGTH, reply.body.len()),
    }
    let Ok(resp) = b.body(()) else {
        respond.send_reset(Reason::INTERNAL_ERROR);
        return;
    };
    let body: &[u8] = if head_req { &[] } else { &reply.body };
    let Ok(mut stream) = respond.send_response(resp, body.is_empty()) else { return };
    let mut off = 0usize;
    while off < body.len() {
        stream.reserve_capacity(body.len().saturating_sub(off).min(64 * 1024));
        let n = match timeout(stall, poll_fn(|cx| stream.poll_capacity(cx))).await {
            Ok(Some(Ok(n))) if n > 0 => n,
            Ok(Some(Ok(_))) => continue,
            _ => {
                stream.send_reset(Reason::CANCEL);
                return;
            }
        };
        let end = off.saturating_add(n).min(body.len());
        let chunk = Bytes::copy_from_slice(body.get(off..end).unwrap_or(&[]));
        if stream.send_data(chunk, end == body.len()).is_err() {
            return;
        }
        off = end;
    }
}
