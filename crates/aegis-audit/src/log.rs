//! The single sequencer (Audit I1–I4, I7).
//!
//! - **I2 gapless seq:** `seq` is the leaf index, assigned only when the leaf is appended; rejected or dropped
//!   events never consume a number.
//! - **I1 append-only consistent checkpoints:** the tree only grows; every checkpoint is a prefix of the next
//!   (consistency proofs from [`Log::consistency_proof`]).
//! - **I3 full tiles immutable:** a full tile or bundle is written for exactly one tree-size range and never
//!   rewritten with other bytes (retries rewrite identical bytes); partial tiles live at distinct `.p/<W>` paths.
//! - **I4 checkpoint after fsync:** [`Log::checkpoint`] writes every new tile and bundle, calls
//!   [`AuditSink::sync`], and only after `Ok` signs and publishes.
//! - **I7 failure policy:** admin events fail closed (an `Err` the caller must treat as "do not apply");
//!   data-plane events are dropped with a counter (or fail closed if configured).

use crate::checkpoint::{Checkpoint, CheckpointError, SignedCheckpoint, check_origin};
use crate::event::{AuditEvent, EventClass, EventError};
use crate::merkle::{Hash, MerkleStore, leaf_hash};
use crate::note::{NoteError, NoteSigner, sign_note};
use crate::sink::{AuditSink, SinkError};
use crate::tile::{TILE_HEIGHT, TILE_WIDTH, TileKind, TilePath};

/// What happens to an event the log cannot take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnFailure {
    /// Return an error; the caller must not perform the audited action.
    FailClosed,
    /// Drop the event and increment [`Log::dropped`]; never block the data plane.
    DropAndCount,
}

/// Admin events are always [`OnFailure::FailClosed`]; only the data-plane behaviour is configurable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FailurePolicy {
    pub data_plane: OnFailure,
}

impl Default for FailurePolicy {
    fn default() -> Self {
        Self { data_plane: OnFailure::DropAndCount }
    }
}

impl FailurePolicy {
    pub fn for_class(&self, class: EventClass) -> OnFailure {
        match class {
            EventClass::Admin => OnFailure::FailClosed,
            EventClass::DataPlane => self.data_plane,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogConfig {
    /// Checkpoint origin line (c2sp.org/tlog-checkpoint); SHOULD equal the log key name.
    pub origin: String,
    /// Maximum sequenced-but-not-yet-durable events before new events hit the failure policy.
    pub max_pending: u64,
    /// Gov profiles: refuse to run without an ML-DSA-87 (or other) cosigner (ARCHITECTURE §3.10).
    pub require_cosigner: bool,
    pub policy: FailurePolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    BadOrigin,
    MissingCosigner,
    ZeroPending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    Invalid(EventError),
    /// `max_pending` reached.
    Backpressure,
    /// The last checkpoint attempt failed; the log takes no new fail-closed events until one succeeds.
    SinkUnavailable,
}

/// Returned only under [`OnFailure::FailClosed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppendError(pub RejectReason);

impl std::fmt::Display for AppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "audit append refused (fail closed): {:?}", self.0)
    }
}
impl std::error::Error for AppendError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Appended {
    Sequenced(u64),
    Dropped(RejectReason),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitError {
    Sink(SinkError),
    Sign(NoteError),
    Checkpoint(CheckpointError),
}

impl std::fmt::Display for CommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sink(e) => write!(f, "{e}"),
            Self::Sign(e) => write!(f, "checkpoint signing failed: {e}"),
            Self::Checkpoint(e) => write!(f, "checkpoint: {e}"),
        }
    }
}
impl std::error::Error for CommitError {}

/// Single-writer tlog-tiles log over an [`AuditSink`].
#[derive(Debug)]
pub struct Log<S: AuditSink> {
    cfg: LogConfig,
    signer: Box<dyn NoteSigner>,
    cosigners: Vec<Box<dyn NoteSigner>>,
    sink: S,
    store: MerkleStore,
    /// Leaves `[leaves_start, size)`, kept until their bundle is durable and full.
    leaves: Vec<Vec<u8>>,
    leaves_start: u64,
    durable_size: u64,
    last: Option<SignedCheckpoint>,
    sink_failed: bool,
    dropped: u64,
}

impl<S: AuditSink + std::fmt::Debug> Log<S> {
    pub fn new(
        cfg: LogConfig,
        signer: Box<dyn NoteSigner>,
        cosigners: Vec<Box<dyn NoteSigner>>,
        sink: S,
    ) -> Result<Self, ConfigError> {
        check_origin(&cfg.origin).map_err(|_| ConfigError::BadOrigin)?;
        if cfg.require_cosigner && cosigners.is_empty() {
            return Err(ConfigError::MissingCosigner);
        }
        if cfg.max_pending == 0 {
            return Err(ConfigError::ZeroPending);
        }
        Ok(Self {
            cfg,
            signer,
            cosigners,
            sink,
            store: MerkleStore::new(),
            leaves: Vec::new(),
            leaves_start: 0,
            durable_size: 0,
            last: None,
            sink_failed: false,
            dropped: 0,
        })
    }

    /// Sequenced entries (including those not yet checkpointed).
    pub fn size(&self) -> u64 {
        self.store.size()
    }
    /// Tree size of the last published checkpoint.
    pub fn published_size(&self) -> u64 {
        self.last.as_ref().map_or(0, |c| c.checkpoint.size())
    }
    pub fn last_checkpoint(&self) -> Option<&SignedCheckpoint> {
        self.last.as_ref()
    }
    /// Data-plane events dropped under [`OnFailure::DropAndCount`].
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
    pub fn sink(&self) -> &S {
        &self.sink
    }
    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }
    /// Verifier keys: log key first, then cosigners.
    pub fn vkeys(&self) -> Vec<String> {
        std::iter::once(self.signer.vkey()).chain(self.cosigners.iter().map(|c| c.vkey())).collect()
    }

    fn refuse(&mut self, class: EventClass, why: RejectReason) -> Result<Appended, AppendError> {
        match self.cfg.policy.for_class(class) {
            OnFailure::FailClosed => Err(AppendError(why)),
            OnFailure::DropAndCount => {
                self.dropped = self.dropped.saturating_add(1);
                Ok(Appended::Dropped(why))
            }
        }
    }

    /// Sequence one event at wall-clock `unix_ms`. Not durable until the next successful [`Log::checkpoint`].
    pub fn append(&mut self, ev: &AuditEvent, unix_ms: u64) -> Result<Appended, AppendError> {
        if self.sink_failed {
            return self.refuse(ev.class, RejectReason::SinkUnavailable);
        }
        let seq = self.store.size();
        if seq.saturating_sub(self.durable_size) >= self.cfg.max_pending {
            return self.refuse(ev.class, RejectReason::Backpressure);
        }
        let leaf = match ev.encode_leaf(seq, unix_ms) {
            Ok(l) => l,
            Err(e) => return self.refuse(ev.class, RejectReason::Invalid(e)),
        };
        self.store.push_leaf(leaf_hash(&leaf));
        self.leaves.push(leaf);
        Ok(Appended::Sequenced(seq))
    }

    /// Admin path: sequence and make durable before returning. On `Err` the caller must not apply the action.
    /// (If the error comes from the checkpoint step, the event stays sequenced and is published by the next
    /// successful checkpoint; the log then records an attempt that was not applied, never the reverse.)
    pub fn append_durable(&mut self, ev: &AuditEvent, unix_ms: u64) -> Result<(u64, SignedCheckpoint), AdminError> {
        let seq = match self.append(ev, unix_ms) {
            Ok(Appended::Sequenced(s)) => s,
            Ok(Appended::Dropped(r)) => return Err(AdminError::Refused(AppendError(r))),
            Err(e) => return Err(AdminError::Refused(e)),
        };
        let cp = self.checkpoint().map_err(AdminError::Commit)?;
        Ok((seq, cp))
    }

    fn hash_tile(&self, level: u8, index: u64, count: u64) -> Option<(TilePath, Vec<u8>)> {
        let start = index.checked_mul(TILE_WIDTH)?;
        let end = start.saturating_add(TILE_WIDTH).min(count);
        let hashes: &[Hash] = self.store.level_range(usize::from(level) * TILE_HEIGHT as usize, start, end)?;
        let width = u16::try_from(end - start).ok()?;
        Some((TilePath { kind: TileKind::Hash(level), index, width }, hashes.concat()))
    }

    fn bundle(&self, index: u64, count: u64) -> Option<(TilePath, Vec<u8>)> {
        let start = index.checked_mul(TILE_WIDTH)?;
        let end = start.saturating_add(TILE_WIDTH).min(count);
        let lo = usize::try_from(start.checked_sub(self.leaves_start)?).ok()?;
        let hi = usize::try_from(end.checked_sub(self.leaves_start)?).ok()?;
        let mut data = Vec::new();
        for leaf in self.leaves.get(lo..hi)? {
            let len = u16::try_from(leaf.len()).ok()?;
            data.extend_from_slice(&len.to_be_bytes());
            data.extend_from_slice(leaf);
        }
        let width = u16::try_from(end - start).ok()?;
        Some((TilePath { kind: TileKind::Entries, index, width }, data))
    }

    /// Every tile and bundle that tree size `to` adds over `from`.
    fn new_resources(&self, from: u64, to: u64) -> Option<Vec<(TilePath, Vec<u8>)>> {
        let mut out = Vec::new();
        if to > from {
            for n in from / TILE_WIDTH..=(to - 1) / TILE_WIDTH {
                out.push(self.bundle(n, to)?);
            }
        }
        for level in 0u8..8 {
            let shift = u32::from(level) * TILE_HEIGHT;
            let (cf, ct) = (from >> shift, to >> shift);
            if ct == 0 || ct == cf {
                break;
            }
            for n in cf / TILE_WIDTH..=(ct - 1) / TILE_WIDTH {
                out.push(self.hash_tile(level, n, ct)?);
            }
        }
        Some(out)
    }

    fn persist(&mut self, size: u64) -> Result<(), SinkError> {
        let resources = self
            .new_resources(self.durable_size, size)
            .ok_or_else(|| SinkError::Io("internal: tile range unavailable".into()))?;
        for (path, data) in &resources {
            match path.kind {
                TileKind::Entries => self.sink.write_entries(path, data)?,
                TileKind::Hash(_) => self.sink.write_tile(path, data)?,
            }
        }
        self.sink.sync()
    }

    /// Persist, fsync, then sign and publish a checkpoint for the current size (I4). Idempotent when nothing
    /// was appended since the last published checkpoint.
    pub fn checkpoint(&mut self) -> Result<SignedCheckpoint, CommitError> {
        let size = self.store.size();
        if let Some(last) = &self.last
            && last.checkpoint.size() == size
            && !self.sink_failed
        {
            return Ok(last.clone());
        }
        if self.durable_size < size {
            if let Err(e) = self.persist(size) {
                self.sink_failed = true;
                return Err(CommitError::Sink(e));
            }
            self.durable_size = size;
            let keep_from = size / TILE_WIDTH * TILE_WIDTH;
            let drop_n = usize::try_from(keep_from.saturating_sub(self.leaves_start)).unwrap_or(0);
            self.leaves.drain(..drop_n.min(self.leaves.len()));
            self.leaves_start = keep_from.max(self.leaves_start);
        }
        let root = self
            .store
            .root(size)
            .ok_or_else(|| CommitError::Sink(SinkError::Io("internal: root unavailable".into())))?;
        let cp = Checkpoint::new(&self.cfg.origin, size, root).map_err(CommitError::Checkpoint)?;
        let mut signers: Vec<&dyn NoteSigner> = vec![self.signer.as_ref()];
        signers.extend(self.cosigners.iter().map(|c| c.as_ref()));
        let note = match sign_note(&cp.text(), &signers) {
            Ok(n) => n,
            Err(e) => {
                self.sink_failed = true;
                return Err(CommitError::Sign(e));
            }
        };
        if let Err(e) = self.sink.publish_checkpoint(size, note.as_bytes()) {
            self.sink_failed = true;
            return Err(CommitError::Sink(e));
        }
        let signed = SignedCheckpoint { checkpoint: cp, note };
        self.last = Some(signed.clone());
        self.sink_failed = false;
        Ok(signed)
    }

    /// Root of the tree at a published or earlier size.
    pub fn root_at(&self, size: u64) -> Option<Hash> {
        if size > self.published_size() { None } else { self.store.root(size) }
    }
    /// Inclusion proof of `index` in the tree of `size` (`size <= published_size`).
    pub fn inclusion_proof(&self, index: u64, size: u64) -> Option<Vec<Hash>> {
        if size > self.published_size() { None } else { self.store.inclusion_proof(index, size) }
    }
    /// Consistency proof between tree sizes `old <= new <= published_size`.
    pub fn consistency_proof(&self, old: u64, new: u64) -> Option<Vec<Hash>> {
        if new > self.published_size() { None } else { self.store.consistency_proof(old, new) }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminError {
    Refused(AppendError),
    Commit(CommitError),
}

impl std::fmt::Display for AdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(e) => write!(f, "{e}"),
            Self::Commit(e) => write!(f, "audit commit failed (fail closed): {e}"),
        }
    }
}
impl std::error::Error for AdminError {}
