//! Idempotency, outbox, commit-point latch, durable store (INV-NOMUT-C, INV-IDEMP, INV-DURABLE).
//!
//! [`store`] is the INV-DURABLE store (P4-state-001): SQLite WAL, `synchronous=FULL`, single writer, q2-007
//! start-up checks, bootstrap fsync of files and directories, fail-stop on any commit error. It is gated by
//! `oracles/crash-harness` through `subjects/crash-subject`.
//!
//! On top of it (P4-state-002, gated by `oracles/state-props` through `subjects/state-subject`):
//! - [`idem`]: INV-IDEMP, key = (principal, idempotency-key); replay, conflict, in-flight; leases in memory only.
//! - [`latch`]: NC2, [`State::commit`] is the commit point (rows + outcome record + outbox rows in one durable
//!   transaction, then the reply; 202 when the timer fired after CP, outcome retrievable).
//! - [`outbox`]: NC6, effects only through the outbox; at-least-once relay with a stable dedupe key.
//! - IDEMP-R (Phase 8, R12): [`State::set_retention`] forgets completed keys after the F8 window; absent = never.
//!
//! Spec: `spec/SPEC_INVARIANTS.md`.
#![forbid(unsafe_code)]

pub mod idem;
pub mod latch;
pub mod outbox;
pub mod store;

#[cfg(test)]
mod retention_tests;

use std::fmt;
use std::path::Path;

pub use idem::{Begin, IdemKey, Lease, Outcome, Record};
pub use latch::{ACCEPTED_STATUS, Clock, Reply, State};
pub use outbox::{Dedupe, DeliverError, Effect};
pub use store::{Dump, Op, Rows, Space, Store, StoreError};

/// Failure of the idempotency / outbox / latch layer. Fail-closed: the caller must not serve or ack on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    /// Store failure (a commit failure poisons the store).
    Store(StoreError),
    /// Caller input outside the accepted domain (empty key, over-long digest, bad status, ...).
    Invalid(&'static str),
    /// A stored row does not decode (detect only; nothing is repaired).
    Corrupt(String),
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateError::Store(e) => write!(f, "{e}"),
            StateError::Invalid(m) => write!(f, "invalid: {m}"),
            StateError::Corrupt(m) => write!(f, "corrupt {m}"),
        }
    }
}

impl std::error::Error for StateError {}

impl From<StoreError> for StateError {
    fn from(e: StoreError) -> Self {
        StateError::Store(e)
    }
}

/// Self-test mutations for `oracles/state-props`. Each one breaks a required property, so production code must
/// use [`State::open`], which is [`StateMutations::NONE`].
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StateMutations {
    /// The idempotency key is the client key alone (principal dropped).
    pub idem_key_without_principal: bool,
    /// A completed key with the same digest runs again instead of replaying.
    pub replay_reexecutes: bool,
    /// EFFECT commits its outbox row at once, before the commit point.
    pub effect_before_commit: bool,
    /// Undelivered outbox rows are dropped on open.
    pub outbox_drop_on_restart: bool,
    /// IDEMP-R: the retention window is ignored (keys never expire).
    pub retention_ignored: bool,
    /// IDEMP-R: keys expire one second before the window ends.
    pub retention_early: bool,
}

impl StateMutations {
    /// No mutation.
    pub const NONE: StateMutations = StateMutations {
        idem_key_without_principal: false,
        replay_reexecutes: false,
        effect_before_commit: false,
        outbox_drop_on_restart: false,
        retention_ignored: false,
        retention_early: false,
    };
}

/// The crash-harness subject contract (`oracles/crash-harness/README.md`, "Subject protocol").
pub trait CrashSubject {
    /// Open or create the store in `dir`; `Ok` only after files and directories are fsynced.
    fn open_bootstrap(dir: &Path) -> Result<Self, StoreError>
    where
        Self: Sized;
    /// Commit `(table, key, value)` puts atomically. `Ok` only once durable; `Err` poisons the store.
    fn commit(&mut self, puts: &[(u8, Vec<u8>, Vec<u8>)]) -> Result<(), StoreError>;
    /// Every row as `(table, key) -> value`.
    fn dump(&mut self) -> Result<Dump, StoreError>;
    /// Detect-only integrity check.
    fn check(&mut self) -> Result<(), StoreError>;
}

impl CrashSubject for Store {
    fn open_bootstrap(dir: &Path) -> Result<Self, StoreError> {
        Store::open(dir)
    }
    fn commit(&mut self, puts: &[(u8, Vec<u8>, Vec<u8>)]) -> Result<(), StoreError> {
        let ops: Vec<Op> =
            puts.iter().map(|(t, k, v)| Op::Put { space: *t, key: k.clone(), value: v.clone() }).collect();
        Store::commit(self, &ops)
    }
    fn dump(&mut self) -> Result<Dump, StoreError> {
        Store::dump(self)
    }
    fn check(&mut self) -> Result<(), StoreError> {
        Store::check(self).map(|_| ())
    }
}
