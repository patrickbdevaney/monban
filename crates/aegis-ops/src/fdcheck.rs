//! UP-2: validate every received fd (SO_TYPE, SO_ACCEPTCONN, getsockname) against its `listeners` entry, then claim
//! it or close it. An fd that fails any check is never used.

use crate::wire::{Family, ListenerDesc, Proto};
use nix::sys::socket::{SockType, SockaddrStorage, getsockname, getsockopt, sockopt};
use std::fmt;
use std::net::{SocketAddr, TcpListener};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

/// Why an fd was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FdReject {
    /// Not a socket (SO_TYPE failed with ENOTSOCK or similar).
    NotSocket,
    /// SO_TYPE does not match `proto`.
    WrongType,
    /// A TCP fd that is not listening (SO_ACCEPTCONN = 0).
    NotListening,
    /// getsockname family or address differs from the descriptor.
    AddrMismatch,
    /// getsockname failed.
    NoName,
}

impl fmt::Display for FdReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NotSocket => "not a socket",
            Self::WrongType => "socket type mismatch",
            Self::NotListening => "not listening",
            Self::AddrMismatch => "address mismatch",
            Self::NoName => "getsockname failed",
        };
        f.write_str(s)
    }
}

/// F11 address encoding of a std socket address.
pub fn encode_addr(sa: &SocketAddr) -> (Family, Vec<u8>) {
    match sa {
        SocketAddr::V4(a) => {
            let mut v = a.ip().octets().to_vec();
            v.extend_from_slice(&a.port().to_be_bytes());
            (Family::Inet, v)
        }
        SocketAddr::V6(a) => {
            let mut v = a.ip().octets().to_vec();
            v.extend_from_slice(&a.port().to_be_bytes());
            (Family::Inet6, v)
        }
    }
}

/// Describe a TCP listener for `listeners`.
pub fn describe_tcp(name: &str, l: &TcpListener) -> std::io::Result<ListenerDesc> {
    let (family, addr) = encode_addr(&l.local_addr()?);
    Ok(ListenerDesc { name: name.to_string(), family, addr, proto: Proto::Tcp })
}

fn sockname(fd: BorrowedFd<'_>) -> Result<(Family, Vec<u8>), FdReject> {
    let ss: SockaddrStorage = getsockname(fd.as_raw_fd()).map_err(|_| FdReject::NoName)?;
    if let Some(a) = ss.as_sockaddr_in() {
        let mut v = a.ip().octets().to_vec();
        v.extend_from_slice(&a.port().to_be_bytes());
        return Ok((Family::Inet, v));
    }
    if let Some(a) = ss.as_sockaddr_in6() {
        let mut v = a.ip().octets().to_vec();
        v.extend_from_slice(&a.port().to_be_bytes());
        return Ok((Family::Inet6, v));
    }
    if let Some(u) = ss.as_unix_addr() {
        let p = u.path().map(|p| p.as_os_str().as_bytes().to_vec()).unwrap_or_default();
        return Ok((Family::Unix, p));
    }
    Err(FdReject::AddrMismatch)
}

/// Validate `fd` against `desc` (UP-2). `Ok` means the fd is exactly the socket the parent described.
pub fn validate(fd: BorrowedFd<'_>, desc: &ListenerDesc) -> Result<(), FdReject> {
    let ty = getsockopt(&fd, sockopt::SockType).map_err(|_| FdReject::NotSocket)?;
    match (desc.proto, ty) {
        (Proto::Tcp, SockType::Stream) => {
            let listening = getsockopt(&fd, sockopt::AcceptConn).map_err(|_| FdReject::NotSocket)?;
            if !listening {
                return Err(FdReject::NotListening);
            }
        }
        (Proto::Udp, SockType::Datagram) => {}
        _ => return Err(FdReject::WrongType),
    }
    let (family, addr) = sockname(fd)?;
    if family != desc.family || addr != desc.addr {
        return Err(FdReject::AddrMismatch);
    }
    Ok(())
}

/// Validate then claim: on success returns an owned, CLOEXEC duplicate as a `TcpListener` (UP-6: the duplicate is
/// made with F_DUPFD_CLOEXEC). The caller closes the source slot either way.
pub fn claim_tcp(fd: BorrowedFd<'_>, desc: &ListenerDesc) -> Result<TcpListener, FdReject> {
    validate(fd, desc)?;
    if desc.proto != Proto::Tcp {
        return Err(FdReject::WrongType);
    }
    let owned = fd.as_fd().try_clone_to_owned().map_err(|_| FdReject::NotSocket)?;
    Ok(TcpListener::from(owned))
}

/// Validate then claim a received fd (SCM_RIGHTS, already CLOEXEC via `MSG_CMSG_CLOEXEC`): on success the fd itself
/// becomes the `TcpListener`; on any failure it is dropped, i.e. closed (claim-or-close, UP-2).
pub fn claim_owned_tcp(fd: OwnedFd, desc: &ListenerDesc) -> Result<TcpListener, FdReject> {
    validate(fd.as_fd(), desc)?;
    if desc.proto != Proto::Tcp {
        return Err(FdReject::WrongType);
    }
    Ok(TcpListener::from(fd))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpStream, UdpSocket};

    #[test]
    fn accepts_matching_listener() {
        let l = TcpListener::bind("127.0.0.1:0").ok();
        let Some(l) = l else { return };
        let d = describe_tcp("x", &l).ok();
        let Some(d) = d else { return };
        assert_eq!(validate(l.as_fd(), &d), Ok(()));
        let c = claim_tcp(l.as_fd(), &d);
        assert!(c.is_ok());
    }

    #[test]
    fn rejects_mismatches() {
        let (Ok(l), Ok(l2)) = (TcpListener::bind("127.0.0.1:0"), TcpListener::bind("127.0.0.1:0")) else { return };
        let Ok(d) = describe_tcp("x", &l) else { return };
        // A different listening socket: address mismatch.
        assert_eq!(validate(l2.as_fd(), &d), Err(FdReject::AddrMismatch));
        // A connected (non-listening) TCP socket.
        let Ok(s) = TcpStream::connect(l.local_addr().unwrap_or_else(|_| ([127, 0, 0, 1], 1).into())) else { return };
        assert_eq!(validate(s.as_fd(), &d), Err(FdReject::NotListening));
        // A UDP socket offered as TCP.
        let Ok(u) = UdpSocket::bind("127.0.0.1:0") else { return };
        assert_eq!(validate(u.as_fd(), &d), Err(FdReject::WrongType));
        // A pipe / file is not a socket.
        let Ok(f) = std::fs::File::open("/dev/null") else { return };
        assert_eq!(validate(f.as_fd(), &d), Err(FdReject::NotSocket));
        // Proto mismatch in the descriptor.
        let mut du = d.clone();
        du.proto = Proto::Udp;
        assert_eq!(validate(l.as_fd(), &du), Err(FdReject::WrongType));
        // UDP descriptor accepted for the matching bound UDP socket.
        let Ok(ua) = u.local_addr() else { return };
        let (family, addr) = encode_addr(&ua);
        let dudp = ListenerDesc { name: "u".into(), family, addr, proto: Proto::Udp };
        assert_eq!(validate(u.as_fd(), &dudp), Ok(()));
    }
}
