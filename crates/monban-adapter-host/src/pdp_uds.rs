//! PDP-1 SOCK_SEQPACKET plumbing (safe rustix + std): server listen/accept, the client [`UdsTransport`] that
//! implements the pure `monban_authz::pdp::PdpTransport`, and one-packet send/recv that reports a packet's true
//! length.
//!
//! Moved here from monban-pdp (L5) so the host side (monban-bin, the MCP listener gate) can reach the out-of-process
//! Cedar PDP without linking Cedar (DEVIATIONS X-8). monban-pdp re-exports this module as `monban_pdp::uds` for its
//! server loop, the probe and oracles/pdp-dst.

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use monban_authz::pdp::{PdpTransport, TransportFault};
use rustix::net::{
    AddressFamily, RecvFlags, SendFlags, SocketAddrUnix, SocketFlags, SocketType, accept_with, bind, connect, listen,
    recv, send, socket_with,
};

fn seqpacket() -> io::Result<OwnedFd> {
    socket_with(AddressFamily::UNIX, SocketType::SEQPACKET, SocketFlags::CLOEXEC, None).map_err(io::Error::from)
}

/// Bind and listen on a filesystem path (must not exist yet).
pub fn listen_at(path: &Path) -> io::Result<OwnedFd> {
    let fd = seqpacket()?;
    bind(&fd, &SocketAddrUnix::new(path).map_err(io::Error::from)?).map_err(io::Error::from)?;
    listen(&fd, 64).map_err(io::Error::from)?;
    Ok(fd)
}

/// Accept one connection as a `UnixStream` (std gives us timeouts; reads/writes go through [`recv_packet`]).
pub fn accept_one(listener: &OwnedFd) -> io::Result<UnixStream> {
    Ok(UnixStream::from(accept_with(listener, SocketFlags::CLOEXEC).map_err(io::Error::from)?))
}

/// Connect to a PDP socket.
pub fn connect_to(path: &Path) -> io::Result<UnixStream> {
    let fd = seqpacket()?;
    connect(&fd, &SocketAddrUnix::new(path).map_err(io::Error::from)?).map_err(io::Error::from)?;
    Ok(UnixStream::from(fd))
}

/// True if `fd` is a SOCK_SEQPACKET socket (used to refuse a wrong inherited fd).
pub fn is_seqpacket<Fd: AsFd>(fd: Fd) -> bool {
    rustix::net::sockopt::socket_type(fd).is_ok_and(|t| t == SocketType::SEQPACKET)
}

/// One received packet: bytes copied (≤ buf.len()) and the packet's true length (`MSG_TRUNC`). 0/0 is EOF.
pub fn recv_packet<Fd: AsFd>(fd: Fd, buf: &mut [u8]) -> io::Result<(usize, usize)> {
    recv(fd, buf, RecvFlags::TRUNC).map_err(io::Error::from)
}

/// Send one packet; a short write is an error.
pub fn send_packet<Fd: AsFd>(fd: Fd, b: &[u8]) -> io::Result<()> {
    let n = send(fd, b, SendFlags::NOSIGNAL).map_err(io::Error::from)?;
    if n == b.len() { Ok(()) } else { Err(io::Error::from(io::ErrorKind::WriteZero)) }
}

/// Client transport over a SOCK_SEQPACKET path, with a per-exchange deadline. Connects lazily; `reset` drops the
/// connection so the next exchange reconnects.
#[derive(Debug)]
pub struct UdsTransport {
    path: PathBuf,
    deadline: Duration,
    conn: Option<UnixStream>,
}

impl UdsTransport {
    pub fn new(path: PathBuf, deadline: Duration) -> Self {
        Self { path, deadline: deadline.max(Duration::from_millis(1)), conn: None }
    }

    fn conn(&mut self) -> Result<&UnixStream, TransportFault> {
        if self.conn.is_none() {
            let s = connect_to(&self.path).map_err(|_| TransportFault::Closed)?;
            s.set_read_timeout(Some(self.deadline)).map_err(|_| TransportFault::Io)?;
            s.set_write_timeout(Some(self.deadline)).map_err(|_| TransportFault::Io)?;
            self.conn = Some(s);
        }
        self.conn.as_ref().ok_or(TransportFault::Closed)
    }
}

impl PdpTransport for UdsTransport {
    fn exchange(&mut self, request: &[u8], reply: &mut [u8]) -> Result<usize, TransportFault> {
        let s = self.conn()?;
        send_packet(s, request).map_err(|e| fault(&e))?;
        match recv_packet(s, reply) {
            Ok((_, 0)) => Err(TransportFault::Closed),
            Ok((_, n)) => Ok(n),
            Err(e) => Err(fault(&e)),
        }
    }

    fn reset(&mut self) {
        self.conn = None;
    }
}

fn fault(e: &io::Error) -> TransportFault {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => TransportFault::Timeout,
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::NotConnected => {
            TransportFault::Closed
        }
        _ => TransportFault::Io,
    }
}
