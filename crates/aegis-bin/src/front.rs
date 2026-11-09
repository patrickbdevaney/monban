//! Connection front matter before TLS (Phase 7; features `proxy-protocol`, `l4`, `mtc`): the PROXY v2 header
//! (PROXY-1..3), L4 SNI passthrough (L4-1, L4-2) and the per-ClientHello credential selector (SEL-1..3). The wire
//! parsing is aegis-wire's (D-P7.2: own parsers, no allocation); this module owns the reads, the deadlines, the
//! policy and the audit events. The receiver rules are `oracles/proxy-l4/README.md` (the oracle is the contract).
//!
//! One connection, in order:
//! 1. **PROXY** (listener with `proxy_protocol`). Trust is decided on the TCP peer only ([`ProxyProtocol::admits`],
//!    an IPv4-mapped peer matches as IPv4). From a trusted source the v2 header is required (never auto-detected);
//!    v1, a malformed header, a declared length over 536, a DGRAM family on this stream listener, EOF or the
//!    deadline close the connection with no byte sent. From an untrusted source, first bytes that could begin a PROXY
//!    header (a prefix of the v2 signature or of `PROXY`) close the connection; anything else is served with the TCP
//!    peer. An admitted header is audited (`proxy.accept`, detail `peer` = the admission/audit address, `via` = the
//!    TCP peer) before anything else happens; that address is what admission (S0..S6) and the app see (PROXY-2).
//!    Bytes after the header are never re-parsed as a header: they are TLS (or L4) bytes.
//! 2. **L4** (listener with `l4`). The first record must be one complete ClientHello (aegis-wire peek); its SNI is
//!    matched exactly, case-insensitively, against the routes; no SNI, an unknown SNI or anything that is not a
//!    ClientHello (an HTTP request line included, L4-2) closes the connection: there is no default upstream (L4-1).
//!    The routed connection is audited (`l4.route`), then the client's bytes from the ClientHello record on are
//!    forwarded byte-exact (a PROXY header in front is never forwarded) and the two directions are spliced until
//!    both ended, the idle deadline (`limits.idle_timeout_ms`, no byte either way) or the drain.
//! 3. **MTC selector** (feature `mtc`, listener with `tls.credentials` candidates): the first record is read, the
//!    selector's per-connection `ServerConfig` is built from exactly those bytes and rustls is fed the same bytes.
//!    When the selector picks nothing for a hello that passed F12 admission steps 1-2 (TLS 1.3 offered, sigalgs meet
//!    the profile), the connection gets a plaintext fatal handshake_failure (40) from here and is closed (F1 SEL-3;
//!    rustls itself would answer 49). Hellos that fail steps 1-2 still go to rustls (70 / 49, tls/verdicts.toml).
//!
//! Deadline: the PROXY header and the ClientHello record must both have arrived within `limits.stall_timeout_ms`
//! counted from accept (not per read), so a dribbling client is closed too.

#[cfg(any(feature = "proxy-protocol", feature = "l4"))]
use std::net::IpAddr;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
#[cfg(feature = "l4")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use aegis_transport::TlsAcceptor;
#[cfg(any(feature = "l4", all(feature = "mtc", not(feature = "cmvp"))))]
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::time::Instant;

use crate::audit::Auditor;
use crate::serve::Srv;
use crate::shared::Shared;

/// One listener's front matter, built at boot from its [`crate::plan::ListenerPlan`].
#[derive(Debug)]
pub struct Front {
    /// The listener name (audit object).
    #[cfg_attr(not(any(feature = "proxy-protocol", feature = "l4")), allow(dead_code))]
    pub name: String,
    #[cfg(feature = "proxy-protocol")]
    pub proxy: Option<aegis_config::ProxyProtocol>,
    #[cfg(feature = "l4")]
    pub l4: Option<Vec<aegis_config::L4Route>>,
    #[cfg(all(feature = "mtc", not(feature = "cmvp")))]
    pub selector: Option<Arc<aegis_tls::CredentialSelector>>,
    /// Where `proxy.accept` / `l4.route` go (fail closed: a failed append refuses the connection).
    #[cfg_attr(not(any(feature = "proxy-protocol", feature = "l4")), allow(dead_code))]
    pub auditor: Arc<Auditor>,
}

impl Front {
    /// Whether this listener needs any front matter (otherwise the plain path serves it unchanged).
    pub fn active(&self) -> bool {
        let mut a = false;
        #[cfg(feature = "proxy-protocol")]
        {
            a |= self.proxy.is_some();
        }
        #[cfg(feature = "l4")]
        {
            a |= self.l4.is_some();
        }
        #[cfg(all(feature = "mtc", not(feature = "cmvp")))]
        {
            a |= self.selector.is_some();
        }
        a
    }
}

/// Replays the bytes read while peeking, then reads from `io` (writes go straight to `io`).
#[derive(Debug)]
pub struct Prefixed<IO> {
    prefix: Vec<u8>,
    pos: usize,
    io: IO,
}

impl<IO> Prefixed<IO> {
    pub fn new(prefix: Vec<u8>, io: IO) -> Self {
        Self { prefix, pos: 0, io }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for Prefixed<IO> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Some(rest) = this.prefix.get(this.pos..)
            && !rest.is_empty()
        {
            let n = rest.len().min(buf.remaining());
            buf.put_slice(rest.get(..n).unwrap_or(&[]));
            this.pos = this.pos.saturating_add(n);
            if this.pos >= this.prefix.len() {
                this.prefix = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.io).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Prefixed<IO> {
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

/// Read once more into `buf` before `deadline`. `false`: EOF, error or the deadline (the caller closes).
async fn fill<IO: AsyncRead + Unpin>(io: &mut IO, buf: &mut Vec<u8>, deadline: Instant) -> bool {
    let mut chunk = [0u8; 4096];
    match tokio::time::timeout_at(deadline, io.read(&mut chunk)).await {
        Ok(Ok(n)) if n > 0 => {
            buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
            true
        }
        _ => false,
    }
}

#[cfg(any(feature = "proxy-protocol", feature = "l4"))]
/// The IP as audit writes it: exactly the address admission keys on (an IPv6 source in a TCP6 header stays IPv6,
/// IPv4-mapped included; PROXY-2 uses the header's address as sent).
fn ip_text(ip: IpAddr) -> String {
    ip.to_string()
}

#[cfg(any(feature = "proxy-protocol", feature = "l4"))]
/// Append one front event durably (off the async workers: the log fsyncs). `false` ⇒ refuse the connection.
async fn audit(front: &Front, shared: &Shared, action: &'static str, detail: Vec<(&'static str, String)>) -> bool {
    let auditor = Arc::clone(&front.auditor);
    let object = front.name.clone();
    let hash = shared.snapshot().hash;
    let r = tokio::task::spawn_blocking(move || {
        let d: Vec<(&str, aegis_audit::DetailValue)> =
            detail.iter().map(|(k, v)| (*k, crate::audit::text(v))).collect();
        auditor.admin(action, &object, aegis_audit::Outcome::Allow, hash, &d)
    })
    .await;
    match r {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            let pid = std::process::id();
            eprintln!("aegis[{pid}]: {action} on {:?}: {e}; connection refused (audit fails closed)", front.name);
            false
        }
        Err(_) => false,
    }
}

/// PROXY-1..3 on a `proxy_protocol` listener. `Some((peer, consumed))`: serve with `peer`, the first `consumed`
/// bytes of `buf` were the header. `None`: close, nothing sent.
#[cfg(feature = "proxy-protocol")]
async fn proxy_header<IO: AsyncRead + Unpin>(
    io: &mut IO,
    buf: &mut Vec<u8>,
    pp: &aegis_config::ProxyProtocol,
    tcp_peer: SocketAddr,
    deadline: Instant,
) -> Option<(SocketAddr, usize)> {
    use aegis_wire::proxy::{ProxyError, looks_like_proxy, parse_v2};
    if !pp.admits(tcp_peer.ip()) {
        // Untrusted: never parsed. Something that could begin a header is refused; anything else is served.
        if !fill(io, buf, deadline).await || looks_like_proxy(buf) {
            return None;
        }
        return Some((tcp_peer, 0));
    }
    loop {
        match parse_v2(buf) {
            Ok((h, consumed)) => {
                if !h.stream_accept() {
                    return None; // a datagram flow announced on a stream listener (policy)
                }
                return Some((h.source().unwrap_or(tcp_peer), consumed));
            }
            Err(ProxyError::Incomplete) => {
                if buf.len() > aegis_wire::proxy::MAX_HEADER_LEN || !fill(io, buf, deadline).await {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
}

/// Read until `buf[start..]` holds one complete ClientHello record (or the peek refuses it). `false`: close.
#[cfg(any(feature = "l4", all(feature = "mtc", not(feature = "cmvp"))))]
async fn read_hello<IO: AsyncRead + Unpin>(io: &mut IO, buf: &mut Vec<u8>, start: usize, deadline: Instant) -> bool {
    use aegis_wire::tls_peek::{MAX_RECORD, PeekError, RECORD_HEADER, client_hello};
    loop {
        match client_hello(buf.get(start..).unwrap_or(&[])) {
            Err(PeekError::Incomplete) => {
                let have = buf.len().saturating_sub(start);
                if have > RECORD_HEADER.saturating_add(MAX_RECORD) || !fill(io, buf, deadline).await {
                    return false;
                }
            }
            Ok(_) => return true,
            Err(_) => return false,
        }
    }
}

/// Serve one accepted connection of a listener with front matter.
pub async fn serve<IO>(
    shared: Arc<Shared>,
    srv: Arc<Srv>,
    front: Arc<Front>,
    #[allow(unused_mut)] mut io: IO,
    tcp_peer: SocketAddr,
    acc: TlsAcceptor,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let limits = shared.snapshot().plan.limits;
    let deadline = Instant::now() + Duration::from_millis(limits.stall_timeout_ms);
    #[allow(unused_mut)]
    let mut buf: Vec<u8> = Vec::new();
    #[allow(unused_mut)]
    let mut peer = tcp_peer;
    #[allow(unused_mut)]
    let mut start = 0usize;
    #[cfg(feature = "proxy-protocol")]
    if let Some(pp) = &front.proxy {
        let Some((p, consumed)) = proxy_header(&mut io, &mut buf, pp, tcp_peer, deadline).await else { return };
        if consumed > 0 {
            let detail = vec![("peer", ip_text(p.ip())), ("via", ip_text(tcp_peer.ip()))];
            if !audit(&front, &shared, "proxy.accept", detail).await {
                return;
            }
        }
        peer = p;
        start = consumed;
    }
    #[cfg(feature = "l4")]
    if let Some(routes) = &front.l4 {
        let idle = Duration::from_millis(limits.idle_timeout_ms);
        return l4(&shared, &front, routes, io, buf, start, peer, deadline, idle).await;
    }
    #[allow(unused_mut)]
    let mut acc = acc;
    #[cfg(all(feature = "mtc", not(feature = "cmvp")))]
    if let Some(sel) = &front.selector {
        if !read_hello(&mut io, &mut buf, start, deadline).await {
            return;
        }
        let raw = buf.get(start..).unwrap_or(&[]);
        if sel3_refuses(sel, raw) {
            // SEL-3: nothing among this listener's credentials matches -> handshake_failure (40), sent here because
            // rustls answers an unresolved certificate with access_denied (49).
            let _ = tokio::time::timeout_at(deadline, io.write_all(&ALERT_HANDSHAKE_FAILURE)).await;
            let _ = tokio::time::timeout_at(deadline, io.shutdown()).await;
            return;
        }
        acc = TlsAcceptor::from(sel.config_for(raw));
    }
    let rest = buf.get(start..).map(<[u8]>::to_vec).unwrap_or_default();
    srv.serve_tls_from(Prefixed::new(rest, io), acc, Some(peer)).await;
}

/// A plaintext fatal `handshake_failure` alert record (RFC 8446 section 6: level 2, description 40), legacy record
/// version 0x0303 as rustls writes its own pre-ServerHello alerts.
#[cfg(all(feature = "mtc", not(feature = "cmvp")))]
const ALERT_HANDSHAKE_FAILURE: [u8; 7] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 40];

/// SEL-3 on the peeked ClientHello `raw`: `true` iff the selector picks no credential **and** the hello passes the
/// F12 admission steps that come before selection (tls/verdicts.toml "Admission order"): it offers TLS 1.3
/// (step 1, else rustls answers protocol_version 70) and its signature_algorithms meet the profile's F12 list
/// (step 2, else rustls answers access_denied 49). Only then is the refusal a selection miss, which F1 SEL-3 answers
/// with handshake_failure (40).
#[cfg(all(feature = "mtc", not(feature = "cmvp")))]
fn sel3_refuses(sel: &aegis_tls::CredentialSelector, raw: &[u8]) -> bool {
    let Ok(peek) = aegis_wire::tls_peek::client_hello(raw) else { return false };
    let offers_13 = peek.version_list().any(|v| v == 0x0304);
    let profile: Vec<u16> = sel.profile().sigalgs().iter().map(|s| u16::from(*s)).collect();
    let offered: Vec<u16> = peek.sigalg_list().collect();
    selection_miss(sel.select_peek(&peek).is_some(), offers_13, &offered, &profile)
}

/// The decision of [`sel3_refuses`] over its inputs (pure, unit-tested).
#[cfg(any(test, all(feature = "mtc", not(feature = "cmvp"))))]
fn selection_miss(selected: bool, offers_13: bool, offered: &[u16], profile: &[u16]) -> bool {
    !selected && offers_13 && offered.iter().any(|s| profile.contains(s))
}

/// L4-1/L4-2: peek, route by SNI, audit, forward, splice.
#[cfg(feature = "l4")]
#[allow(clippy::too_many_arguments)]
async fn l4<IO>(
    shared: &Arc<Shared>,
    front: &Front,
    routes: &[aegis_config::L4Route],
    mut io: IO,
    mut buf: Vec<u8>,
    start: usize,
    peer: SocketAddr,
    deadline: Instant,
    idle: Duration,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if !read_hello(&mut io, &mut buf, start, deadline).await {
        return;
    }
    let sent = buf.get(start..).unwrap_or(&[]);
    let Ok(peek) = aegis_wire::tls_peek::client_hello(sent) else { return };
    let Some(sni) = peek.sni else { return }; // no SNI: never a default upstream
    let Some(route) = routes.iter().find(|r| r.sni.as_bytes().eq_ignore_ascii_case(sni)) else { return };
    let sni = String::from_utf8_lossy(sni).into_owned();
    let up = match tokio::time::timeout_at(
        deadline,
        tokio::net::TcpStream::connect((route.upstream_host.as_str(), route.upstream_port)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => return,
    };
    let _ = up.set_nodelay(true);
    let detail = vec![("sni", sni), ("upstream", route.upstream()), ("peer", ip_text(peer.ip()))];
    if !audit(front, shared, "l4.route", detail).await {
        return;
    }
    let first = buf.split_off(start);
    splice(shared, io, up, first, idle).await;
}

/// Copy both directions until both ended, `idle` passed with no byte either way, or the drain started.
#[cfg(feature = "l4")]
async fn splice<A, B>(shared: &Arc<Shared>, client: A, upstream: B, first: Vec<u8>, idle: Duration)
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (cr, cw) = tokio::io::split(client);
    let (ur, mut uw) = tokio::io::split(upstream);
    let t0 = std::time::Instant::now();
    let last = Arc::new(AtomicU64::new(0));
    if tokio::time::timeout(idle, uw.write_all(&first)).await.map_or(true, |r| r.is_err()) {
        return;
    }
    let up = tokio::spawn(pump(Arc::clone(shared), cr, uw, Arc::clone(&last), t0, idle));
    pump(Arc::clone(shared), ur, cw, last, t0, idle).await;
    let _ = up.await;
}

/// One direction of [`splice`]. On EOF the write side is shut down (half-close passes through).
#[cfg(feature = "l4")]
async fn pump<R, W>(
    shared: Arc<Shared>,
    mut r: R,
    mut w: W,
    last: Arc<AtomicU64>,
    t0: std::time::Instant,
    idle: Duration,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let idle_ms = u64::try_from(idle.as_millis()).unwrap_or(u64::MAX);
    let now = || u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        if shared.is_draining() {
            break;
        }
        match tokio::time::timeout(Duration::from_millis(250).min(idle), r.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {
                let _ = w.shutdown().await;
                return;
            }
            Ok(Ok(n)) => {
                let data = chunk.get(..n).unwrap_or(&[]);
                if tokio::time::timeout(idle, w.write_all(data)).await.map_or(true, |r| r.is_err()) {
                    break;
                }
                last.fetch_max(now(), Ordering::Relaxed);
            }
            Err(_) => {
                if now().saturating_sub(last.load(Ordering::Relaxed)) >= idle_ms {
                    break;
                }
            }
        }
    }
    let _ = w.shutdown().await;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[cfg(any(feature = "proxy-protocol", feature = "l4"))]
    #[test]
    fn peers_are_written_as_sent() {
        assert_eq!(ip_text("::ffff:198.51.100.77".parse().unwrap()), "::ffff:198.51.100.77");
        assert_eq!(ip_text("::1".parse().unwrap()), "::1");
    }

    /// SEL-3 vs the admission steps before selection: only a selection miss on an admitted hello is answered 40.
    #[test]
    fn selection_miss_is_handshake_failure_only_after_admission() {
        let profile = [0x0403u16];
        // pub2: nothing matches, the client offers an in-profile scheme and TLS 1.3 -> 40 (SEL-3).
        assert!(selection_miss(false, true, &[0x0904, 0x0403], &profile));
        assert!(selection_miss(false, true, &[0x0403], &profile));
        // A credential was selected: rustls proceeds.
        assert!(!selection_miss(true, true, &[0x0403], &profile));
        // Step 2: sigalgs disjoint from the profile (ML-DSA only on P-PUBLIC-WEB) -> rustls' 49.
        assert!(!selection_miss(false, true, &[0x0904, 0x0905, 0x0906], &profile));
        assert!(!selection_miss(false, true, &[], &profile));
        // Step 1: no TLS 1.3 -> rustls' 70.
        assert!(!selection_miss(false, false, &[0x0403], &profile));
    }

    #[test]
    fn prefixed_replays_then_reads() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let (a, mut b) = tokio::io::duplex(64);
            b.write_all(b"world").await.unwrap();
            drop(b);
            let mut p = Prefixed::new(b"hello ".to_vec(), a);
            let mut out = Vec::new();
            p.read_to_end(&mut out).await.unwrap();
            assert_eq!(out, b"hello world");
        });
    }
}
