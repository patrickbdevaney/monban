//! Lifecycle signal handling with no first-party `unsafe`.
//!
//! The handlers are tokio's (`tokio::signal::unix`, backed by signal-hook-registry): the async-signal-safe handler
//! only records the signal and writes a wake byte to a self-pipe; everything else runs on the thread that calls
//! [`Signals::wait`]. A private current-thread runtime drives the signal driver, so callers stay synchronous and do
//! not need to be inside a tokio runtime. Call [`Signals::block`] as early as possible (before any thread exists):
//! until it returns, SIGHUP / SIGTERM / SIGINT / SIGUSR2 still have their default action (terminate).
//!
//! (rustix exposes sigprocmask / sigwait only as `unsafe` and semver-exempt `runtime` APIs, so the previous
//! block-and-sigwait design cannot be kept without `unsafe` here; P2-ops-rustix-001.)

use std::future::poll_fn;
use std::io;
use std::sync::Mutex;
use std::task::Poll;
use tokio::runtime::{Builder, Runtime};
use tokio::signal::unix::{Signal, SignalKind, signal};

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

/// Registered lifecycle signal streams and the runtime that drives them.
#[derive(Debug)]
pub struct Signals {
    // Field order = drop order: the streams deregister before their driver goes away.
    streams: Mutex<[(Signal, Sig); 4]>,
    rt: Runtime,
}

impl Signals {
    /// Take over SIGHUP, SIGTERM, SIGINT and SIGUSR2 for the whole process (their default terminate action is
    /// replaced; from now on they are only reported through [`Signals::wait`]). The name is kept from the
    /// sigprocmask design: the effect for callers is the same.
    pub fn block() -> io::Result<Self> {
        let rt = Builder::new_current_thread().enable_io().build()?;
        let streams = rt.block_on(async {
            io::Result::Ok([
                (signal(SignalKind::hangup())?, Sig::Hup),
                (signal(SignalKind::interrupt())?, Sig::Term),
                (signal(SignalKind::user_defined2())?, Sig::Usr2),
                (signal(SignalKind::terminate())?, Sig::Term),
            ])
        })?;
        Ok(Self { streams: Mutex::new(streams), rt })
    }

    /// Wait for the next signal. Repeated deliveries of one signal while nobody waits coalesce (as with sigwait).
    pub fn wait(&self) -> io::Result<Sig> {
        let mut streams = match self.streams.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        self.rt.block_on(poll_fn(|cx| {
            for (s, kind) in streams.iter_mut() {
                match s.poll_recv(cx) {
                    Poll::Ready(Some(())) => return Poll::Ready(Ok(*kind)),
                    Poll::Ready(None) => return Poll::Ready(Err(io::Error::other("signal driver shut down"))),
                    Poll::Pending => {}
                }
            }
            Poll::Pending
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::process::{Signal as RSig, getpid, kill_process};

    #[test]
    fn reports_each_lifecycle_signal() {
        let Ok(s) = Signals::block() else { return };
        for (raw, want) in
            [(RSig::HUP, Sig::Hup), (RSig::USR2, Sig::Usr2), (RSig::TERM, Sig::Term), (RSig::INT, Sig::Term)]
        {
            assert!(kill_process(getpid(), raw).is_ok());
            assert_eq!(s.wait().ok(), Some(want));
        }
    }
}
