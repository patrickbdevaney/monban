//! Idempotency, outbox, commit-point latch, durable store (INV-NOMUT-C, INV-IDEMP, INV-DURABLE).
//!
//! [`store`] is the INV-DURABLE store (P4-state-001): SQLite WAL, `synchronous=FULL`, single writer, q2-007
//! start-up checks, bootstrap fsync of files and directories, fail-stop on any commit error. It is gated by
//! `oracles/crash-harness` through `subjects/crash-subject`. Idempotency, outbox and latch (P4-state-002) build on
//! it. Spec: `spec/SPEC_INVARIANTS.md`.
#![forbid(unsafe_code)]

pub mod store;

use std::path::Path;

pub use store::{Dump, Op, Rows, Space, Store, StoreError};

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
