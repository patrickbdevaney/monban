//! Signal handling without handlers: the signals are blocked in every thread (call [`Signals::block`] before
//! spawning threads) and a dedicated thread takes them synchronously with sigwait. No unsafe, no async-signal-safety
//! hazards.

use nix::sys::signal::{SigSet, Signal};

/// Signals relevant to the server lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sig {
    /// SIGHUP: upgrade (re-exec as child).
    Hup,
    /// SIGTERM / SIGINT: drain and exit.
    Term,
    /// SIGUSR2: also upgrade (HAProxy/nginx convention).
    Usr2,
}

/// A blocked signal set.
#[derive(Debug, Clone, Copy)]
pub struct Signals {
    set: SigSet,
}

impl Signals {
    /// Block SIGHUP, SIGTERM, SIGINT, SIGUSR2 in the calling thread (inherited by threads spawned later).
    pub fn block() -> nix::Result<Self> {
        let mut set = SigSet::empty();
        for s in [Signal::SIGHUP, Signal::SIGTERM, Signal::SIGINT, Signal::SIGUSR2] {
            set.add(s);
        }
        set.thread_block()?;
        Ok(Self { set })
    }
    /// Wait for the next signal.
    pub fn wait(&self) -> nix::Result<Sig> {
        loop {
            match self.set.wait()? {
                Signal::SIGHUP => return Ok(Sig::Hup),
                Signal::SIGUSR2 => return Ok(Sig::Usr2),
                Signal::SIGTERM | Signal::SIGINT => return Ok(Sig::Term),
                _ => continue,
            }
        }
    }
}
