//! Server shell: limits + front end + vhosts, TLS / cleartext entry points, and the I/O adapters the drivers share.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use monban_canon::Scheme;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use tokio::time::{Instant, timeout};
use tokio_rustls::TlsAcceptor;

use crate::counters::{self, Counters};
use crate::ledger::ConnLedger;
use crate::limits::{LimitsError, WrapperLimits};
use crate::pipeline::{App, ConnFlags, ConnInfo, VhostTable};

/// The HTTP/2 connection preface (RFC 9113 §3.4).
pub const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// One server: a front end, its vhosts and the wrapper limits. Cheap to share (`Arc`).
///
/// Vhosts and limits can be replaced at run time (config reload): new requests see the new vhost table, new
/// connections the new limits (a live connection keeps the limits it started with).
#[derive(Debug)]
pub struct Server<A: App> {
    pub(crate) app: A,
    vhosts: RwLock<Arc<VhostTable>>,
    limits: RwLock<WrapperLimits>,
    pub(crate) counters: Counters,
    /// `false` only through the `negative-control` feature (oracle self-test).
    pub(crate) wrapper: bool,
    epoch: Instant,
    conn_ids: AtomicU64,
    draining: AtomicBool,
    pub(crate) drain_notify: Notify,
}

impl<A: App> Server<A> {
    fn build(app: A, vhosts: VhostTable, limits: WrapperLimits, wrapper: bool) -> Result<Arc<Self>, LimitsError> {
        limits.validate()?;
        Ok(Arc::new(Self {
            app,
            vhosts: RwLock::new(Arc::new(vhosts)),
            limits: RwLock::new(limits),
            counters: Counters::default(),
            wrapper,
            epoch: Instant::now(),
            conn_ids: AtomicU64::new(1),
            draining: AtomicBool::new(false),
            drain_notify: Notify::new(),
        }))
    }

    /// Build a server; limits are validated here (fail closed before any connection is served).
    pub fn new(app: A, vhosts: VhostTable, limits: WrapperLimits) -> Result<Arc<Self>, LimitsError> {
        Self::build(app, vhosts, limits, true)
    }

    /// NEGATIVE CONTROL ONLY (oracles/transport-stall `--self-test`): the same server with the Monban wrapper
    /// layer switched off (no field-count cap, ledger, handler gate, RST bucket, stream cap, stall or idle
    /// deadlines, strict-H1 filter; h2's own settings stay). Never enabled in the shipped binary.
    #[cfg(feature = "negative-control")]
    pub fn new_without_wrapper(app: A, vhosts: VhostTable, limits: WrapperLimits) -> Result<Arc<Self>, LimitsError> {
        Self::build(app, vhosts, limits, false)
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    /// The current limits (a copy).
    pub fn limits(&self) -> WrapperLimits {
        *self.limits.read().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Replace the limits for connections accepted from now on; invalid limits are refused and change nothing.
    pub fn set_limits(&self, limits: WrapperLimits) -> Result<(), LimitsError> {
        limits.validate()?;
        *self.limits.write().unwrap_or_else(std::sync::PoisonError::into_inner) = limits;
        Ok(())
    }

    /// The current vhost table.
    pub fn vhosts(&self) -> Arc<VhostTable> {
        self.vhosts.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }

    /// Replace the vhost table for requests admitted from now on.
    pub fn set_vhosts(&self, vhosts: VhostTable) {
        *self.vhosts.write().unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(vhosts);
    }

    /// Start draining (upgrade / shutdown): HTTP/1.1 connections close after their current response (idle ones
    /// now), HTTP/2 connections get a graceful GOAWAY. Idempotent; connections accepted later drain at once.
    pub fn drain(&self) {
        self.draining.store(true, Ordering::Release);
        self.drain_notify.notify_waiters();
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    pub fn app(&self) -> &A {
        &self.app
    }

    /// Milliseconds since the server was built (monotonic, saturating).
    pub(crate) fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    pub(crate) fn now_ns(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    /// The `Instant` for a `now_ms` value.
    pub(crate) fn instant_at(&self, ms: u64) -> Instant {
        self.epoch
            .checked_add(Duration::from_millis(ms))
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400))
    }

    pub(crate) fn stall(&self) -> Duration {
        Duration::from_millis(self.limits().stall_timeout_ms)
    }

    fn conn_info(&self, scheme: Scheme, sni: Option<Vec<u8>>, peer: Option<SocketAddr>) -> ConnInfo {
        ConnInfo { scheme, sni, peer, id: self.conn_ids.fetch_add(1, Ordering::Relaxed) }
    }

    /// Run one driver, then tell the app the connection ended.
    async fn drive<IO>(self: Arc<Self>, io: IO, info: ConnInfo, h2: bool)
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let flags = Arc::new(ConnFlags::default());
        if h2 {
            crate::h2srv::serve(self.clone(), io, info.clone(), flags.clone()).await;
        } else {
            crate::h1srv::serve(self.clone(), io, info.clone(), flags.clone()).await;
        }
        self.app.conn_closed(&info, flags.admitted());
    }

    /// Serve one accepted TLS transport: handshake (bounded by the stall deadline), then h2 if ALPN chose `h2`,
    /// else HTTP/1.1. SNI is bound to the vhost through monban-canon (CANON-6).
    pub async fn serve_tls<IO>(self: Arc<Self>, io: IO, acceptor: TlsAcceptor)
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.serve_tls_from(io, acceptor, None).await;
    }

    /// [`Server::serve_tls`] with the peer address (handed to the app in [`ConnInfo`]).
    pub async fn serve_tls_from<IO>(self: Arc<Self>, io: IO, acceptor: TlsAcceptor, peer: Option<SocketAddr>)
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let _g = ConnGauge::up(&self.counters);
        let tls = match timeout(self.stall(), acceptor.accept(io)).await {
            Ok(Ok(s)) => s,
            _ => {
                counters::bump(&self.counters.tls_failures);
                return;
            }
        };
        let (_, sc) = tls.get_ref();
        let info = self.conn_info(Scheme::Https, sc.server_name().map(|s| s.as_bytes().to_vec()), peer);
        let h2 = sc.alpn_protocol() == Some(b"h2");
        self.clone().drive(tls, info, h2).await;
    }

    /// Serve one cleartext transport: h2 with prior knowledge if the client opens with the h2 preface, else
    /// HTTP/1.1 (no h2c Upgrade).
    pub async fn serve_plain<IO>(self: Arc<Self>, io: IO)
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.serve_plain_from(io, None).await;
    }

    /// [`Server::serve_plain`] with the peer address (handed to the app in [`ConnInfo`]).
    pub async fn serve_plain_from<IO>(self: Arc<Self>, mut io: IO, peer: Option<SocketAddr>)
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let _g = ConnGauge::up(&self.counters);
        let mut prefix = Vec::with_capacity(H2_PREFACE.len());
        let sniff = async {
            let mut b = [0u8; 24];
            while prefix.len() < H2_PREFACE.len() && H2_PREFACE.starts_with(&prefix) {
                let want = H2_PREFACE.len().saturating_sub(prefix.len());
                let n = io.read(b.get_mut(..want).unwrap_or(&mut [])).await?;
                if n == 0 {
                    break;
                }
                prefix.extend_from_slice(b.get(..n).unwrap_or(&[]));
            }
            Ok::<(), std::io::Error>(())
        };
        if !matches!(timeout(self.stall(), sniff).await, Ok(Ok(()))) {
            return;
        }
        let h2 = prefix.as_slice() == H2_PREFACE.as_slice();
        let io = Prefixed { prefix, pos: 0, io };
        let info = self.conn_info(Scheme::Http, None, peer);
        self.clone().drive(io, info, h2).await;
    }
}

/// Live-connection gauge.
struct ConnGauge<'a>(&'a Counters);

impl<'a> ConnGauge<'a> {
    fn up(c: &'a Counters) -> Self {
        counters::bump(&c.conns_accepted);
        counters::bump(&c.conns_live);
        Self(c)
    }
}

impl Drop for ConnGauge<'_> {
    fn drop(&mut self) {
        counters::dec(&self.0.conns_live);
    }
}

/// Generic RAII gauge.
pub(crate) struct Gauge<'a>(&'a AtomicU64);

impl<'a> Gauge<'a> {
    pub(crate) fn up(a: &'a AtomicU64) -> Self {
        counters::bump(a);
        Self(a)
    }
}

impl Drop for Gauge<'_> {
    fn drop(&mut self) {
        counters::dec(self.0);
    }
}

/// Replays bytes read while sniffing, then reads from `io`.
#[derive(Debug)]
pub(crate) struct Prefixed<IO> {
    prefix: Vec<u8>,
    pos: usize,
    io: IO,
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

/// Progress clock shared between an I/O adapter and a watchdog (ms since the server epoch).
#[derive(Debug, Default)]
pub(crate) struct Progress(pub(crate) AtomicU64);

impl Progress {
    pub(crate) fn touch(&self, now_ms: u64) {
        self.0.fetch_max(now_ms, Ordering::Relaxed);
    }
    pub(crate) fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Counts bytes written to the transport into the connection ledger (TBI-6/7) and optionally marks I/O progress.
#[derive(Debug)]
pub(crate) struct CountingIo<IO> {
    pub(crate) io: IO,
    ledger: Arc<ConnLedger>,
    progress: Option<(Arc<Progress>, Instant)>,
}

impl<IO> CountingIo<IO> {
    pub(crate) fn new(io: IO, ledger: Arc<ConnLedger>, progress: Option<(Arc<Progress>, Instant)>) -> Self {
        Self { io, ledger, progress }
    }

    pub(crate) fn mark(&self) {
        if let Some((p, epoch)) = &self.progress {
            p.touch(u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX));
        }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for CountingIo<IO> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let r = Pin::new(&mut this.io).poll_read(cx, buf);
        if buf.filled().len() > before {
            this.mark();
        }
        r
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for CountingIo<IO> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.ledger.note_flushed(false);
        let r = Pin::new(&mut this.io).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r
            && *n > 0
        {
            this.ledger.written(u64::try_from(*n).unwrap_or(u64::MAX));
            this.mark();
        }
        r
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let r = Pin::new(&mut this.io).poll_flush(cx);
        if let Poll::Ready(Ok(())) = &r {
            this.ledger.note_flushed(true);
        }
        r
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}
