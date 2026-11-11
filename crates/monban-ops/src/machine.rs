//! Sans-IO parent and child handover state machines (UP-1, UP-2, UP-4, UP-7).
//!
//! The IO drivers in [`crate::handover`] feed events in and execute the returned actions in order. Keeping the
//! decisions here makes the invariants checkable by exhaustive random event sequences (see tests):
//!
//! * **UP-1 (parent):** the parent closes its listeners only on the transition AwaitReady → Draining, which requires
//!   a `ready` whose claimed set equals the offered listener set exactly. Every failure before that point leaves the
//!   listeners open and the parent serving.
//! * **UP-1 (child):** once the child has sent `ready` it never closes a claimed listener, whatever the parent does
//!   afterwards (the parent may already have closed its copies).
//! * **UP-7:** any timeout, child exit, undecodable frame, unexpected message, or credential mismatch before
//!   Draining is a child failure: kill the child, clean up, return to Idle with listeners open.

use crate::wire::{ListenerDesc, Msg, WireError};
use std::collections::BTreeSet;

/// Parent state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentState {
    /// Serving; no handover in progress.
    Idle,
    /// Child spawned; waiting for it to connect to the handover socket.
    AwaitPeer,
    /// Peer authenticated; waiting for `hello`.
    AwaitHello,
    /// `listeners` sent; waiting for `ready`.
    AwaitReady,
    /// Listeners closed; draining in-flight connections until the deadline.
    Draining,
    /// `done` sent; the process should exit.
    Finished,
}

/// Inputs to the parent machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParentEvent {
    /// The child process was spawned with this pid.
    Spawned {
        /// Child pid.
        pid: u32,
    },
    /// A peer connected to the handover socket; SO_PEERCRED values and whether /proc/<pid>/exe matched.
    PeerConnected {
        /// SO_PEERCRED pid.
        pid: u32,
        /// SO_PEERCRED uid.
        uid: u32,
        /// `/proc/<pid>/exe` resolves to the binary we spawned.
        exe_ok: bool,
    },
    /// A frame arrived (decoded or not).
    Frame(Result<Msg, WireError>),
    /// The per-step handover deadline passed.
    Timeout,
    /// The child exited or closed the handover socket.
    ChildGone,
    /// The drain finished; this many connections were force-closed at the deadline.
    DrainFinished {
        /// Forced closes (UP-4).
        forced: u64,
    },
}

/// Outputs of the parent machine, executed in order by the driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParentAction {
    /// sd-notify RELOADING=1 + MONOTONIC_USEC.
    NotifyReloading,
    /// Send `listeners` (and hand the fds over in the same order).
    SendListeners(Vec<ListenerDesc>),
    /// Stop accepting and close this process's listener fds (the child holds the same sockets).
    CloseListeners,
    /// Send `drain`.
    SendDrain {
        /// Deadline in ms.
        deadline_ms: u64,
    },
    /// sd-notify MAINPID=<child> + READY=1.
    NotifyMainPid {
        /// New main pid.
        pid: u32,
    },
    /// Run the two-phase drain (stop new work on existing connections, then force-close at the deadline).
    StartDrain {
        /// Deadline in ms.
        deadline_ms: u64,
    },
    /// Send `done`.
    SendDone {
        /// Forced closes.
        forced: u64,
    },
    /// Send `abort` (best effort), kill and reap the child, remove the handover directory, keep serving.
    AbortChild {
        /// Why.
        reason: String,
    },
    /// sd-notify READY=1 (end the RELOADING state after a failed upgrade; the old process is still main).
    NotifyReady,
    /// Exit the process successfully.
    Exit,
}

/// Parent handover machine.
#[derive(Debug, Clone)]
pub struct ParentMachine {
    state: ParentState,
    offered: Vec<ListenerDesc>,
    own_uid: u32,
    child_pid: Option<u32>,
    drain_deadline_ms: u64,
    listeners_open: bool,
    claimed_all: bool,
    failures: u64,
    last_failure: Option<String>,
}

impl ParentMachine {
    /// New machine for a process serving `offered` listeners as `own_uid`.
    pub fn new(offered: Vec<ListenerDesc>, own_uid: u32, drain_deadline_ms: u64) -> Self {
        Self {
            state: ParentState::Idle,
            offered,
            own_uid,
            child_pid: None,
            drain_deadline_ms,
            listeners_open: true,
            claimed_all: false,
            failures: 0,
            last_failure: None,
        }
    }

    /// Current state.
    pub fn state(&self) -> ParentState {
        self.state
    }
    /// Whether this process still holds its listeners.
    pub fn listeners_open(&self) -> bool {
        self.listeners_open
    }
    /// Number of failed handovers so far.
    pub fn failures(&self) -> u64 {
        self.failures
    }
    /// Reason of the last failed handover.
    pub fn last_failure(&self) -> Option<&str> {
        self.last_failure.as_deref()
    }
    /// The child pid of the handover in progress.
    pub fn child_pid(&self) -> Option<u32> {
        self.child_pid
    }

    /// UP-1 as a predicate over the machine: listeners are closed only after a full claim.
    pub fn up1_holds(&self) -> bool {
        self.listeners_open || (self.claimed_all && matches!(self.state, ParentState::Draining | ParentState::Finished))
    }

    fn fail(&mut self, reason: &str) -> Vec<ParentAction> {
        self.failures += 1;
        self.last_failure = Some(reason.to_string());
        self.state = ParentState::Idle;
        self.child_pid = None;
        vec![ParentAction::AbortChild { reason: reason.to_string() }, ParentAction::NotifyReady]
    }

    fn claim_matches(&self, claimed: &[String]) -> bool {
        let offered: BTreeSet<&str> = self.offered.iter().map(|l| l.name.as_str()).collect();
        let got: BTreeSet<&str> = claimed.iter().map(String::as_str).collect();
        got.len() == claimed.len() && offered.len() == self.offered.len() && got == offered
    }

    /// Feed one event; returns the actions to execute in order.
    pub fn step(&mut self, ev: ParentEvent) -> Vec<ParentAction> {
        use ParentEvent as E;
        use ParentState as S;
        match (self.state, ev) {
            (S::Idle, E::Spawned { pid }) => {
                self.child_pid = Some(pid);
                self.state = S::AwaitPeer;
                vec![ParentAction::NotifyReloading]
            }
            (S::AwaitPeer, E::PeerConnected { pid, uid, exe_ok }) => {
                if Some(pid) != self.child_pid {
                    self.fail("peer pid is not the spawned child")
                } else if uid != self.own_uid {
                    self.fail("peer uid differs")
                } else if !exe_ok {
                    self.fail("peer executable is not the spawned binary")
                } else {
                    self.state = S::AwaitHello;
                    vec![]
                }
            }
            (S::AwaitHello, E::Frame(Ok(Msg::Hello { child_pid, .. }))) => {
                if self.child_pid.map(u64::from) != Some(child_pid) {
                    self.fail("hello pid mismatch")
                } else {
                    self.state = S::AwaitReady;
                    vec![ParentAction::SendListeners(self.offered.clone())]
                }
            }
            (S::AwaitReady, E::Frame(Ok(Msg::Ready { claimed }))) => {
                if !self.claim_matches(&claimed) {
                    return self.fail("child did not claim exactly the offered listeners");
                }
                self.claimed_all = true;
                self.listeners_open = false;
                self.state = S::Draining;
                let pid = self.child_pid.unwrap_or_default();
                let d = self.drain_deadline_ms;
                vec![
                    ParentAction::CloseListeners,
                    ParentAction::SendDrain { deadline_ms: d },
                    ParentAction::NotifyMainPid { pid },
                    ParentAction::StartDrain { deadline_ms: d },
                ]
            }
            (S::AwaitPeer | S::AwaitHello | S::AwaitReady, E::Frame(Ok(Msg::Abort { reason }))) => {
                self.fail(&format!("child aborted: {}", crate::wire::clamp_reason(&reason)))
            }
            (S::AwaitPeer | S::AwaitHello | S::AwaitReady, E::Frame(Err(e))) => self.fail(&format!("bad frame: {e}")),
            (S::AwaitPeer | S::AwaitHello | S::AwaitReady, E::Frame(Ok(_))) => self.fail("unexpected message"),
            (S::AwaitPeer | S::AwaitHello | S::AwaitReady, E::Timeout) => self.fail("handover timeout"),
            (S::AwaitPeer | S::AwaitHello | S::AwaitReady, E::ChildGone) => self.fail("child exited"),
            (S::AwaitHello | S::AwaitReady, E::PeerConnected { .. }) => self.fail("second peer"),
            (S::Draining, E::DrainFinished { forced }) => {
                self.state = S::Finished;
                vec![ParentAction::SendDone { forced }, ParentAction::Exit]
            }
            // Draining: the child owns the sockets now; frames, timeouts and child exit do not reopen anything
            // (a dead child after takeover is a documented residual, see handover.rs). Idle/Finished: ignore.
            _ => vec![],
        }
    }
}

/// Child state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildState {
    /// Waiting for `listeners`.
    AwaitListeners,
    /// Validating and claiming fds.
    Claiming,
    /// `ready` sent; waiting for `drain`.
    AwaitDrain,
    /// Owns the listeners; serving.
    Serving,
    /// Handover failed; claimed fds closed, process should exit nonzero.
    Failed,
}

/// Inputs to the child machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildEvent {
    /// A frame from the parent.
    Frame(Result<Msg, WireError>),
    /// Result of validating the fds: names claimed, and how many fds were closed because they failed validation.
    Claimed {
        /// Listener names claimed.
        claimed: Vec<String>,
        /// Fds closed as invalid (UP-2).
        rejected: usize,
    },
    /// Read deadline passed.
    Timeout,
    /// Parent closed the socket.
    ParentGone,
}

/// Outputs of the child machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildAction {
    /// Validate each received fd against its descriptor; claim or close (UP-2).
    ValidateAndClaim(Vec<ListenerDesc>),
    /// Send `ready` with these names; start accepting first.
    SendReady(Vec<String>),
    /// Send `abort`, close every received/claimed fd, exit nonzero.
    Abort {
        /// Why.
        reason: String,
    },
    /// The handover is complete; this process is now the main process.
    BecomeMain,
}

/// Child handover machine (starts after `hello` was sent).
#[derive(Debug, Clone)]
pub struct ChildMachine {
    state: ChildState,
    expected: usize,
}

impl Default for ChildMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl ChildMachine {
    /// New machine, waiting for `listeners`.
    pub fn new() -> Self {
        Self { state: ChildState::AwaitListeners, expected: 0 }
    }
    /// Current state.
    pub fn state(&self) -> ChildState {
        self.state
    }
    /// Whether the child may close claimed listeners right now (only before `ready`).
    pub fn may_close_claimed(&self) -> bool {
        matches!(self.state, ChildState::AwaitListeners | ChildState::Claiming | ChildState::Failed)
    }

    fn fail(&mut self, reason: &str) -> Vec<ChildAction> {
        self.state = ChildState::Failed;
        vec![ChildAction::Abort { reason: reason.to_string() }]
    }

    /// Feed one event.
    pub fn step(&mut self, ev: ChildEvent) -> Vec<ChildAction> {
        use ChildEvent as E;
        use ChildState as S;
        match (self.state, ev) {
            (S::AwaitListeners, E::Frame(Ok(Msg::Listeners(ls)))) => {
                if ls.is_empty() {
                    return self.fail("no listeners offered");
                }
                self.expected = ls.len();
                self.state = S::Claiming;
                vec![ChildAction::ValidateAndClaim(ls)]
            }
            (S::Claiming, E::Claimed { claimed, rejected }) => {
                if rejected > 0 || claimed.len() != self.expected {
                    self.fail("fd validation failed")
                } else {
                    self.state = S::AwaitDrain;
                    vec![ChildAction::SendReady(claimed)]
                }
            }
            (S::AwaitDrain, E::Frame(Ok(Msg::Drain { .. }))) => {
                self.state = S::Serving;
                vec![ChildAction::BecomeMain]
            }
            // After `ready` the parent may already have closed its copies: never give the sockets up (UP-1).
            (S::AwaitDrain, E::Timeout | E::ParentGone | E::Frame(_)) => {
                self.state = S::Serving;
                vec![ChildAction::BecomeMain]
            }
            (S::AwaitListeners | S::Claiming, E::Frame(Ok(Msg::Abort { .. }))) => self.fail("parent aborted"),
            (S::AwaitListeners | S::Claiming, E::Frame(Err(e))) => self.fail(&format!("bad frame: {e}")),
            (S::AwaitListeners | S::Claiming, E::Frame(Ok(_))) => self.fail("unexpected message"),
            (S::AwaitListeners | S::Claiming, E::Timeout) => self.fail("handover timeout"),
            (S::AwaitListeners | S::Claiming, E::ParentGone) => self.fail("parent gone"),
            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Family, Proto};

    fn descs() -> Vec<ListenerDesc> {
        vec![
            ListenerDesc { name: "a".into(), family: Family::Inet, addr: vec![127, 0, 0, 1, 0, 80], proto: Proto::Tcp },
            ListenerDesc { name: "b".into(), family: Family::Inet, addr: vec![127, 0, 0, 1, 0, 81], proto: Proto::Tcp },
        ]
    }

    fn happy_prefix(m: &mut ParentMachine) {
        assert_eq!(m.step(ParentEvent::Spawned { pid: 10 }), vec![ParentAction::NotifyReloading]);
        assert!(m.step(ParentEvent::PeerConnected { pid: 10, uid: 1000, exe_ok: true }).is_empty());
        let a = m.step(ParentEvent::Frame(Ok(Msg::Hello { child_pid: 10, config_hash: [0; 32] })));
        assert_eq!(a, vec![ParentAction::SendListeners(descs())]);
    }

    #[test]
    fn parent_happy_path() {
        let mut m = ParentMachine::new(descs(), 1000, 500);
        happy_prefix(&mut m);
        assert!(m.listeners_open());
        let a = m.step(ParentEvent::Frame(Ok(Msg::Ready { claimed: vec!["b".into(), "a".into()] })));
        assert_eq!(a.first(), Some(&ParentAction::CloseListeners));
        assert!(!m.listeners_open());
        assert!(m.up1_holds());
        let a = m.step(ParentEvent::DrainFinished { forced: 3 });
        assert_eq!(a, vec![ParentAction::SendDone { forced: 3 }, ParentAction::Exit]);
        assert_eq!(m.state(), ParentState::Finished);
    }

    #[test]
    fn parent_rejects_partial_duplicate_or_unknown_claims() {
        for claimed in [vec!["a"], vec!["a", "a"], vec!["a", "b", "c"], vec!["a", "x"], vec![]] {
            let mut m = ParentMachine::new(descs(), 1000, 500);
            happy_prefix(&mut m);
            let a =
                m.step(ParentEvent::Frame(Ok(Msg::Ready { claimed: claimed.iter().map(|s| s.to_string()).collect() })));
            assert!(matches!(a.first(), Some(ParentAction::AbortChild { .. })), "{claimed:?}");
            assert!(m.listeners_open());
            assert_eq!(m.state(), ParentState::Idle);
        }
    }

    #[test]
    fn parent_rejects_wrong_credentials() {
        for (pid, uid, exe_ok) in [(11, 1000, true), (10, 0, true), (10, 1000, false)] {
            let mut m = ParentMachine::new(descs(), 1000, 500);
            m.step(ParentEvent::Spawned { pid: 10 });
            let a = m.step(ParentEvent::PeerConnected { pid, uid, exe_ok });
            assert!(matches!(a.first(), Some(ParentAction::AbortChild { .. })));
            assert!(m.listeners_open());
        }
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// Half the time the protocol-correct next event for the state, otherwise anything.
    fn random_parent_event(r: &mut Rng, st: ParentState) -> ParentEvent {
        if r.next().is_multiple_of(2) {
            match st {
                ParentState::Idle => return ParentEvent::Spawned { pid: 10 },
                ParentState::AwaitPeer => return ParentEvent::PeerConnected { pid: 10, uid: 1000, exe_ok: true },
                ParentState::AwaitHello => {
                    return ParentEvent::Frame(Ok(Msg::Hello { child_pid: 10, config_hash: [0; 32] }));
                }
                ParentState::AwaitReady => {
                    return ParentEvent::Frame(Ok(Msg::Ready { claimed: vec!["a".into(), "b".into()] }));
                }
                ParentState::Draining => return ParentEvent::DrainFinished { forced: r.next() % 3 },
                ParentState::Finished => {}
            }
        }
        let names = ["a", "b", "c"];
        let pick = |r: &mut Rng| names.get((r.next() % 3) as usize).copied().unwrap_or("a").to_string();
        match r.next() % 12 {
            0 => ParentEvent::Spawned { pid: 10 + (r.next() % 2) as u32 },
            1 => ParentEvent::PeerConnected {
                pid: 10 + (r.next() % 2) as u32,
                uid: if r.next().is_multiple_of(4) { 0 } else { 1000 },
                exe_ok: !r.next().is_multiple_of(5),
            },
            2 => ParentEvent::Frame(Ok(Msg::Hello { child_pid: 10 + r.next() % 2, config_hash: [0; 32] })),
            3 | 4 => {
                let n = r.next() % 4;
                ParentEvent::Frame(Ok(Msg::Ready { claimed: (0..n).map(|_| pick(r)).collect() }))
            }
            5 => ParentEvent::Frame(Err(WireError::Truncated)),
            6 => ParentEvent::Frame(Ok(Msg::Abort { reason: "x".into() })),
            7 => ParentEvent::Frame(Ok(Msg::Drain { deadline_ms: 1 })),
            8 => ParentEvent::Timeout,
            9 => ParentEvent::ChildGone,
            10 => ParentEvent::DrainFinished { forced: r.next() % 3 },
            _ => ParentEvent::Frame(Ok(Msg::Listeners(vec![]))),
        }
    }

    /// UP-1/UP-7 over 200k random event sequences: listeners are never closed without a full claim; every abort
    /// leaves them open; Exit only ever follows a full claim and a finished drain.
    #[test]
    fn parent_invariants_under_random_sequences() {
        let mut r = Rng(0x1234_5678_9abc_def1);
        let mut handovers = 0;
        for _ in 0..200_000 {
            let mut m = ParentMachine::new(descs(), 1000, 100);
            for _ in 0..12 {
                let before_open = m.listeners_open();
                let ev = random_parent_event(&mut r, m.state());
                let acts = m.step(ev);
                assert!(m.up1_holds());
                for a in &acts {
                    match a {
                        ParentAction::CloseListeners => assert!(before_open && m.state() == ParentState::Draining),
                        ParentAction::AbortChild { .. } => assert!(m.listeners_open()),
                        ParentAction::Exit => {
                            handovers += 1;
                            assert_eq!(m.state(), ParentState::Finished);
                        }
                        _ => {}
                    }
                }
            }
        }
        assert!(handovers > 0, "random sequences must reach a full handover sometimes");
    }

    #[test]
    fn child_paths() {
        let mut c = ChildMachine::new();
        assert_eq!(
            c.step(ChildEvent::Frame(Ok(Msg::Listeners(descs())))),
            vec![ChildAction::ValidateAndClaim(descs())]
        );
        assert!(c.may_close_claimed());
        let a = c.step(ChildEvent::Claimed { claimed: vec!["a".into(), "b".into()], rejected: 0 });
        assert_eq!(a, vec![ChildAction::SendReady(vec!["a".into(), "b".into()])]);
        assert!(!c.may_close_claimed());
        assert_eq!(c.step(ChildEvent::ParentGone), vec![ChildAction::BecomeMain]);
        assert_eq!(c.state(), ChildState::Serving);

        let mut c = ChildMachine::new();
        c.step(ChildEvent::Frame(Ok(Msg::Listeners(descs()))));
        let a = c.step(ChildEvent::Claimed { claimed: vec!["a".into()], rejected: 1 });
        assert!(matches!(a.first(), Some(ChildAction::Abort { .. })));
        assert_eq!(c.state(), ChildState::Failed);

        let mut c = ChildMachine::new();
        assert!(matches!(c.step(ChildEvent::Timeout).first(), Some(ChildAction::Abort { .. })));
    }

    /// Child UP-1: after `ready`, no event sequence leads to Failed (which would close claimed sockets).
    #[test]
    fn child_never_fails_after_ready() {
        let mut r = Rng(42);
        for _ in 0..50_000 {
            let mut c = ChildMachine::new();
            c.step(ChildEvent::Frame(Ok(Msg::Listeners(descs()))));
            c.step(ChildEvent::Claimed { claimed: vec!["a".into(), "b".into()], rejected: 0 });
            for _ in 0..6 {
                let ev = match r.next() % 5 {
                    0 => ChildEvent::Timeout,
                    1 => ChildEvent::ParentGone,
                    2 => ChildEvent::Frame(Err(WireError::BadShape)),
                    3 => ChildEvent::Frame(Ok(Msg::Abort { reason: String::new() })),
                    _ => ChildEvent::Claimed { claimed: vec![], rejected: 9 },
                };
                for a in c.step(ev) {
                    assert!(!matches!(a, ChildAction::Abort { .. }));
                }
                assert_ne!(c.state(), ChildState::Failed);
            }
        }
    }
}
