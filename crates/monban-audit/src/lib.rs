//! Tamper-evident audit log: C2SP tlog-tiles writer, single sequencer, signed checkpoints. Storage via the
//! [`AuditSink`] trait (implemented in L4).
//!
//! Specs: F9 `interfaces/F9-audit-event.schema.json`; `spec/SPEC_INVARIANTS.md` §G Audit I1–I7; RFC 6962 §2.1;
//! c2sp.org/tlog-tiles@v1, c2sp.org/tlog-checkpoint@v1.1.0, c2sp.org/signed-note@v1.1.0 (editor's copies read at
//! C2SP commit fea9004f, 2026-10-22). Independent verification (I5): `oracles/tlog-verify` (Go, x/mod sumdb).
#![forbid(unsafe_code)]

pub mod checkpoint;
pub mod encoding;
pub mod event;
pub mod log;
pub mod merkle;
pub mod note;
pub mod sink;
pub mod tile;

pub use checkpoint::{Checkpoint, SignedCheckpoint};
pub use event::{
    Action, Actor, ActorKind, AuditEvent, Detail, DetailKey, DetailValue, EventClass, EventError, FipsStatus, Outcome,
    Untrusted,
};
pub use log::{
    AdminError, AppendError, Appended, CommitError, ConfigError, FailurePolicy, Log, LogConfig, OnFailure, RejectReason,
};
pub use merkle::{Hash, MerkleStore, leaf_hash, node_hash, verify_consistency, verify_inclusion};
pub use note::{
    Ed25519NoteSigner, MLDSA87_COSIGN, MlDsa87NoteSigner, NoteError, NoteSigner, NoteVerifier, open_note, sign_note,
};
pub use sink::{AuditSink, SinkError};
pub use tile::{TileKind, TilePath};

#[cfg(test)]
mod tests;
