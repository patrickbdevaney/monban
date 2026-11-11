//! The caller-facing types: [`UringListener`] and [`UringStream`].

use std::future::poll_fn;
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::driver::{self, Cmd, ConnState, EPIPE, Handle, ListenState, Sd, lock};
use crate::{UringConfig, UringError};

fn set_waker(slot: &mut Option<Waker>, cx: &Context<'_>) {
    match slot {
        Some(w) if w.will_wake(cx.waker()) => {}
        _ => *slot = Some(cx.waker().clone()),
    }
}

fn os_err(errno: i32) -> io::Error {
    io::Error::from_raw_os_error(errno)
}

/// A listening socket whose accepts run on io_uring. One driver thread and one ring per listener.
///
/// Dropping it cancels a pending accept and closes accepted-but-unclaimed connections; streams already handed out
/// keep working, and the driver thread exits once the listener and every stream are gone.
#[derive(Debug)]
pub struct UringListener {
    handle: Arc<Handle>,
    listen: Arc<Mutex<ListenState>>,
    local: SocketAddr,
    fd: RawFd,
    ring_fd: RawFd,
}

impl UringListener {
    /// Take ownership of a bound, listening socket and serve it through io_uring with [`UringConfig::default`].
    ///
    /// The socket's blocking flag is left as it is (a dup shared with an upgrade child keeps working); `EAGAIN`
    /// is handled with a ring poll. On `Err` the socket is closed and nothing was ever accepted from it.
    pub fn bind(listener: TcpListener) -> Result<Self, UringError> {
        Self::bind_with(listener, UringConfig::default())
    }

    /// As [`UringListener::bind`], with explicit bounds.
    pub fn bind_with(listener: TcpListener, cfg: UringConfig) -> Result<Self, UringError> {
        Self::bind_inner(listener, cfg, &driver::default_setup)
    }

    pub(crate) fn bind_inner(
        listener: TcpListener,
        cfg: UringConfig,
        setup: &driver::Setup,
    ) -> Result<Self, UringError> {
        let s = driver::start(listener, cfg, setup)?;
        Ok(UringListener { handle: s.handle, listen: s.listen, local: s.local, fd: s.fd, ring_fd: s.ring_fd })
    }

    /// The fd of this listener's ring (`anon_inode:[io_uring]`), for /proc evidence only; owned by the driver.
    pub fn ring_fd(&self) -> RawFd {
        self.ring_fd
    }

    /// The bound address (as reported by the socket at bind time).
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Poll for the next connection. One acceptor task per listener: a second concurrent poller replaces the first's
    /// waker. Cancel-safe: a connection accepted after the caller stopped polling is kept for the next poll.
    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(UringStream, SocketAddr)>> {
        let mut ls = lock(&self.listen);
        if let Some(r) = ls.ready.pop_front() {
            return Poll::Ready(r.map_err(os_err));
        }
        if let Some(e) = ls.dead {
            return Poll::Ready(Err(os_err(e)));
        }
        if !ls.busy {
            ls.busy = true;
            if let Err(e) = self.handle.send(Cmd::Accept) {
                ls.busy = false;
                return Poll::Ready(Err(e));
            }
        }
        set_waker(&mut ls.waker, cx);
        Poll::Pending
    }

    /// Accept the next connection (see [`UringListener::poll_accept`]). Errors such as `EMFILE` are returned as-is;
    /// the listener stays usable.
    pub async fn accept(&self) -> io::Result<(UringStream, SocketAddr)> {
        poll_fn(|cx| self.poll_accept(cx)).await
    }
}

impl AsRawFd for UringListener {
    /// The listening socket's fd (owned by the driver; for /proc checks, never for I/O).
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for UringListener {
    fn drop(&mut self) {
        let _ = self.handle.send(Cmd::StopAccept);
    }
}

/// One accepted TCP connection whose I/O runs on io_uring.
///
/// Semantics match `tokio::net::TcpStream` as `monban-transport` uses it, with one difference: `poll_write` copies up
/// to `max_io` bytes into a driver-owned buffer and returns `Ready(n)` at once; the send completes in the background
/// and a send error surfaces on the next `poll_write`/`poll_flush`/`poll_shutdown`. `poll_flush` waits until the
/// kernel has taken every accepted byte. `poll_shutdown` flushes, then `shutdown(SHUT_WR)`. Dropping the stream
/// cancels a pending read, lets an accepted write drain (bounded by [`UringConfig::linger`]) and closes the fd.
/// TCP_NODELAY is set on accept (best effort, IORING_OP_URING_CMD).
#[derive(Debug)]
pub struct UringStream {
    id: u64,
    fd: RawFd,
    st: Arc<Mutex<ConnState>>,
    handle: Arc<Handle>,
    peer: SocketAddr,
    max_io: usize,
}

impl UringStream {
    pub(crate) fn new(
        id: u64,
        fd: RawFd,
        st: Arc<Mutex<ConnState>>,
        handle: Arc<Handle>,
        peer: SocketAddr,
        max_io: usize,
    ) -> Self {
        UringStream { id, fd, st, handle, peer, max_io }
    }

    /// The remote address from accept.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
}

impl AsRawFd for UringStream {
    /// The connection's fd (owned by the driver; for /proc checks, never for I/O).
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for UringStream {
    fn drop(&mut self) {
        let _ = self.handle.send(Cmd::Close { conn: self.id });
    }
}

impl AsyncRead for UringStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let mut g = lock(&me.st);
        let st = &mut *g;
        if st.rd_pos < st.rd_len {
            let avail = st.rd.get(st.rd_pos..st.rd_len).unwrap_or(&[]);
            let n = avail.len().min(buf.remaining());
            buf.put_slice(avail.get(..n).unwrap_or(&[]));
            st.rd_pos = st.rd_pos.saturating_add(n);
            return Poll::Ready(Ok(()));
        }
        if let Some(e) = st.rd_err {
            return Poll::Ready(Err(os_err(e)));
        }
        if st.rd_eof || buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !st.rd_busy {
            let want = buf.remaining().clamp(1, me.max_io);
            let mut b = std::mem::take(&mut st.rd);
            b.resize(want, 0);
            st.rd_pos = 0;
            st.rd_len = 0;
            st.rd_busy = true;
            if let Err(e) = me.handle.send(Cmd::Recv { conn: me.id, buf: b }) {
                st.rd_busy = false;
                return Poll::Ready(Err(e));
            }
        }
        set_waker(&mut st.rd_waker, cx);
        Poll::Pending
    }
}

impl UringStream {
    fn flush_state(st: &mut ConnState, cx: &Context<'_>) -> Poll<io::Result<()>> {
        if st.wr_busy {
            set_waker(&mut st.wr_waker, cx);
            return Poll::Pending;
        }
        match st.wr_err {
            Some(e) => Poll::Ready(Err(os_err(e))),
            None => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncWrite for UringStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let mut g = lock(&me.st);
        let st = &mut *g;
        if let Some(e) = st.wr_err {
            return Poll::Ready(Err(os_err(e)));
        }
        if st.sd != Sd::Idle {
            return Poll::Ready(Err(os_err(EPIPE)));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if st.wr_busy {
            set_waker(&mut st.wr_waker, cx);
            return Poll::Pending;
        }
        let n = data.len().min(me.max_io);
        let mut b = std::mem::take(&mut st.wr_spare);
        b.clear();
        b.extend_from_slice(data.get(..n).unwrap_or(&[]));
        st.wr_busy = true;
        if let Err(e) = me.handle.send(Cmd::Send { conn: me.id, buf: b }) {
            st.wr_busy = false;
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let mut g = lock(&me.st);
        Self::flush_state(&mut g, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let mut g = lock(&me.st);
        let st = &mut *g;
        match st.sd {
            Sd::Done(None) => return Poll::Ready(Ok(())),
            Sd::Done(Some(e)) => return Poll::Ready(Err(os_err(e))),
            Sd::Busy => {}
            Sd::Idle => {
                match Self::flush_state(st, cx) {
                    Poll::Ready(Ok(())) => {}
                    other => return other,
                }
                st.sd = Sd::Busy;
                if let Err(e) = me.handle.send(Cmd::Shutdown { conn: me.id }) {
                    st.sd = Sd::Done(Some(e.raw_os_error().unwrap_or(EPIPE)));
                    return Poll::Ready(Err(e));
                }
            }
        }
        set_waker(&mut st.wr_waker, cx);
        Poll::Pending
    }
}
