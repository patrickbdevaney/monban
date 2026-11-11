//! Opt-in io_uring front (PREFLIGHT D-P7.3, F1 FRONT-1).
//!
//! [`UringListener::bind`] takes an already bound `std::net::TcpListener` and starts one driver thread that owns
//! one io_uring instance (io-uring 0.7.15). Accept, recv, send, shutdown and close of every connection are issued as
//! ring operations; neither the listening socket nor any connection socket is ever registered in an epoll instance
//! (the oracle checks `/proc/<pid>/fdinfo`). Accepted connections are [`UringStream`]s, which implement tokio's
//! `AsyncRead + AsyncWrite + Unpin + Send`, so `monban-transport`'s server consumes them like a `TcpStream`.
//!
//! **Fails closed.** If the kernel refuses io_uring (`kernel.io_uring_disabled`, a seccomp filter returning EPERM,
//! an old kernel without the needed opcodes), [`uring_available`] and [`UringListener::bind`] return
//! [`UringError::Unavailable`], whose message names `io_uring`. There is no epoll fallback anywhere in this crate.
//!
//! **Buffer ownership** (the argument behind the one `unsafe` site, DEVIATIONS X-19): every buffer the kernel reads
//! or writes is heap memory owned by the driver's operation table from the moment its SQE is queued until its CQE is
//! reaped. Streams hand buffers over by value and get them back by value; nothing borrowed crosses an `.await`.
//! Dropping a stream with operations in flight cancels its reads, lets accepted writes finish (bounded by
//! [`UringConfig::linger`], then cancelled), reaps every CQE, and only then closes the fd. A ring failure leaks the
//! in-flight buffers instead of freeing them.
//!
//! **Bounded.** The submission queue has [`UringConfig::sq_entries`] slots. Each connection has at most one recv,
//! one send, one shutdown, one setsockopt and one linger timer in flight, and the listener at most one accept, so the
//! driver's overflow backlog is bounded by the number of open connections. Accept is armed only on demand.
#![deny(unsafe_code)]

mod driver;
mod stream;
#[cfg(test)]
mod tests;

use std::fmt;
use std::time::Duration;

pub use stream::{UringListener, UringStream};

/// Why the io_uring front could not start. Every variant is a refusal to start (exit != 0), never an epoll fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UringError {
    /// The kernel refuses io_uring (`kernel.io_uring_disabled`, seccomp, or an old kernel).
    Unavailable(String),
    /// A bad [`UringConfig`] or a failure to start the driver thread.
    Start(String),
}

impl fmt::Display for UringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UringError::Unavailable(why) => {
                write!(f, "io_uring unavailable: {why}; refusing to start (no epoll fallback)")
            }
            UringError::Start(why) => write!(f, "io_uring front failed to start: {why}"),
        }
    }
}

impl std::error::Error for UringError {}

/// Tuning for one [`UringListener`]. All fields are bounded; [`UringListener::bind_with`] refuses values outside
/// the documented ranges with [`UringError::Start`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UringConfig {
    /// Submission queue slots, 1..=4096 (the kernel rounds up to a power of two). Default 256.
    pub sq_entries: u32,
    /// Largest single recv or send, 1..=1 MiB. Default 64 KiB.
    pub max_io: usize,
    /// How long a dropped stream's already-accepted write may keep draining before it is cancelled, 0..=300 s.
    /// Default 30 s.
    pub linger: Duration,
}

impl Default for UringConfig {
    fn default() -> Self {
        UringConfig { sq_entries: 256, max_io: 64 * 1024, linger: Duration::from_secs(30) }
    }
}

impl UringConfig {
    fn check(&self) -> Result<(), UringError> {
        if !(1..=4096).contains(&self.sq_entries) {
            return Err(UringError::Start(format!("sq_entries {} outside 1..=4096", self.sq_entries)));
        }
        if !(1..=1024 * 1024).contains(&self.max_io) {
            return Err(UringError::Start(format!("max_io {} outside 1..=1048576", self.max_io)));
        }
        if self.linger > Duration::from_secs(300) {
            return Err(UringError::Start(format!("linger {:?} above 300 s", self.linger)));
        }
        Ok(())
    }
}

/// Probe whether this process may use io_uring: sets up a ring, checks that every opcode the front uses is
/// supported, and runs one NOP through `io_uring_enter`. Call it before binding anything so `--front uring` fails
/// closed early; [`UringListener::bind`] repeats the same checks on its own ring.
pub fn uring_available() -> Result<(), UringError> {
    driver::open_ring(&driver::default_setup, 4).map(drop)
}
