//! Opt-in io_uring front (PREFLIGHT D-P7.3, F1 FRONT-1).
//!
//! P7-spec-002 stub: [`UringFront::bind`] refuses with [`UringError::Unimplemented`], so `--front uring` fails closed
//! (never a silent fall back to epoll) until P7-uring-001 lands the front.
#![forbid(unsafe_code)]

use std::fmt;
use std::net::SocketAddr;

/// Why the io_uring front could not start. Every variant is a refusal to start (exit != 0), never an epoll fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UringError {
    /// Not built yet (P7-spec-002 stub): fail closed.
    Unimplemented,
    /// The kernel refuses io_uring (`kernel.io_uring_disabled`, seccomp, or an old kernel).
    Unavailable(String),
}

impl fmt::Display for UringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UringError::Unimplemented => f.write_str("io_uring front not built (fail closed)"),
            UringError::Unavailable(why) => write!(f, "io_uring unavailable: {why}"),
        }
    }
}

impl std::error::Error for UringError {}

/// An io_uring listening front.
#[derive(Debug)]
pub struct UringFront {
    _private: (),
}

impl UringFront {
    /// Bind a listener on `addr` with a bounded submission queue of `sq_entries`.
    ///
    /// Stub: always `Err(UringError::Unimplemented)`.
    pub fn bind(addr: SocketAddr, sq_entries: u32) -> Result<Self, UringError> {
        let _ = (addr, sq_entries);
        Err(UringError::Unimplemented)
    }
}
