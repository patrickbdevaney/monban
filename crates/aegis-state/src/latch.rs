//! NC2: the commit point and the outcome latch.
//!
//! [`State::commit`] is the commit point CP(r). In one atomic, durable store transaction it writes the request's
//! user rows, its outcome record under `(principal, key)` and its outbox rows; only after that transaction is
//! durable does it return the [`Reply`]. From then on the outcome is latched: if the request timer fired after CP,
//! the reply is [`Reply::Accepted`] (202) and the outcome stays retrievable through [`State::begin`] (a replay of
//! the same key and digest) or [`State::outcome`]. If the transaction fails, the store is poisoned (fail-stop) and
//! nothing is acknowledged.
//!
//! [`State`] owns the [`Store`] (opened with [`Store::open`], the full INV-DURABLE bootstrap) and the in-memory
//! lease table. Spaces used: [`IDEM_SPACE`](crate::idem::IDEM_SPACE), [`USER_SPACE`](crate::idem::USER_SPACE),
//! [`OUTBOX_SPACE`](crate::outbox::OUTBOX_SPACE); the crash subject's spaces 0 and 1 are not touched.
use std::collections::HashMap;
use std::path::Path;

use crate::idem::{IDEM_SPACE, Lease, Outcome, Record, USER_SPACE};
use crate::outbox;
use crate::store::{Op, Rows, Store};
use crate::{StateError, StateMutations};

/// Status of a reply whose request timer fired after the commit point.
pub const ACCEPTED_STATUS: u16 = 202;

/// What the host sends once the commit point has passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// The committed outcome.
    Outcome(Outcome),
    /// The timer fired after CP: 202, the outcome is latched and retrievable by key.
    Accepted,
}

impl Reply {
    /// HTTP status of this reply.
    pub fn status(&self) -> u16 {
        match self {
            Reply::Outcome(o) => o.status,
            Reply::Accepted => ACCEPTED_STATUS,
        }
    }
}

/// Wall-clock seconds (Unix time) for the IDEMP-R timestamps. The default reads the system clock; a host or a
/// test subject may inject its own ([`State::set_clock`]).
pub struct Clock(Box<dyn Fn() -> u64 + Send + Sync>);

impl Clock {
    /// A clock from a function returning Unix seconds.
    pub fn new(f: impl Fn() -> u64 + Send + Sync + 'static) -> Clock {
        Clock(Box::new(f))
    }

    /// The system clock (0 if it reads before 1970, so such a host never expires a key).
    pub fn system() -> Clock {
        Clock::new(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()))
    }

    /// Read the clock.
    pub fn now(&self) -> u64 {
        (self.0)()
    }
}

impl core::fmt::Debug for Clock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Clock")
    }
}

/// Idempotency + outbox + latch on top of the durable store. Single writer (`&mut self`).
#[derive(Debug)]
pub struct State {
    pub(crate) store: Store,
    /// Held keys (encoded) -> digest of the holder. In memory only (NC1).
    pub(crate) held: HashMap<Vec<u8>, Vec<u8>>,
    pub(crate) next_seq: u64,
    pub(crate) muts: StateMutations,
    /// IDEMP-R retention in seconds; `None` = never expire (F8 `state.idempotency_retention_s` absent).
    pub(crate) retention: Option<u64>,
    pub(crate) clock: Clock,
}

impl State {
    /// Open or create the store under `root` ([`Store::open`]) and recover the outbox: undelivered committed
    /// effects stay pending and are delivered by the next relay pass. No lease survives a restart.
    pub fn open(root: &Path) -> Result<State, StateError> {
        State::open_with(root, StateMutations::NONE)
    }

    /// Self-test entry point. Production code uses [`State::open`].
    #[doc(hidden)]
    pub fn open_with(root: &Path, muts: StateMutations) -> Result<State, StateError> {
        let mut store = Store::open(root)?;
        let next_seq = outbox::recover(&mut store, muts.outbox_drop_on_restart)?;
        Ok(State { store, held: HashMap::new(), next_seq, muts, retention: None, clock: Clock::system() })
    }

    /// IDEMP-R: forget completed keys `secs` seconds after their commit point (F8
    /// `state.idempotency_retention_s`, validated there to 60..=2,592,000). `None` (the default) = never expire.
    /// Refuses 0 (a window that admits no replay at all).
    pub fn set_retention(&mut self, secs: Option<u64>) -> Result<(), StateError> {
        if secs == Some(0) {
            return Err(StateError::Invalid("idempotency retention of 0 s"));
        }
        self.retention = secs;
        Ok(())
    }

    /// The retention in force.
    pub fn retention(&self) -> Option<u64> {
        self.retention
    }

    /// Replace the wall clock used for commit timestamps and expiry.
    pub fn set_clock(&mut self, clock: Clock) {
        self.clock = clock;
    }

    pub(crate) fn now(&self) -> u64 {
        self.clock.now()
    }

    /// The commit point of `lease`'s request: user rows, outcome record and outbox rows, atomically and durably,
    /// then the latched reply. `timer_fired_after_cp`: the request timer fired after CP (the host decides this
    /// once CP has passed, never before), giving [`Reply::Accepted`]. The key is released from the lease table
    /// whatever the result; on `Err` nothing was acknowledged and the store is poisoned (fail-stop).
    pub fn commit(&mut self, lease: Lease, outcome: Outcome, timer_fired_after_cp: bool) -> Result<Reply, StateError> {
        let enc = lease.ik.encode();
        self.held.remove(&enc);
        if !(100..=599).contains(&outcome.status) {
            return Err(StateError::Invalid("status outside 100..=599"));
        }
        let rec = Record { digest: lease.digest, outcome, committed_at: Some(self.now()) };
        let mut ops: Vec<Op> = lease.writes;
        ops.push(Op::Put { space: IDEM_SPACE, key: enc, value: rec.encode() });
        let mut seq = self.next_seq;
        for e in lease.effects.iter().filter(|e| !e.inserted) {
            ops.push(self.outbox_put_at(seq, e.dedupe, &e.payload));
            seq = seq.checked_add(1).ok_or(StateError::Invalid("outbox sequence exhausted"))?;
        }
        self.store.commit(&ops)?;
        self.next_seq = seq;
        Ok(if timer_fired_after_cp { Reply::Accepted } else { Reply::Outcome(rec.outcome) })
    }

    /// One committed user row.
    pub fn user_row(&mut self, row: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.store.get(USER_SPACE, row)?)
    }

    /// Every committed user row, ordered by key.
    pub fn user_rows(&mut self) -> Result<Rows, StateError> {
        Ok(self.store.scan(USER_SPACE)?)
    }

    /// True once a commit has failed (fail-stop).
    pub fn is_poisoned(&self) -> bool {
        self.store.is_poisoned()
    }

    /// Number of keys currently held by open leases.
    pub fn held_count(&self) -> usize {
        self.held.len()
    }
}
