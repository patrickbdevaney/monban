//! INV-IDEMP: idempotency keyed by `(principal, idempotency-key)` (ARCHITECTURE §3.7 R-STATE-2/3,
//! draft-ietf-httpapi-idempotency-key-header-08 and Stripe semantics).
//!
//! [`State::begin`] answers one of four ways:
//! - [`Begin::Replay`]: the key completed with the same request digest; the stored outcome is returned byte for byte
//!   and nothing runs again.
//! - [`Begin::Conflict`]: the key completed (or is held) with a different digest (422-class).
//! - [`Begin::InFlight`]: an open request holds the key (409-class).
//! - [`Begin::New`]: the key is free; a [`Lease`] is taken. The lease lives **in memory only** (NC1): it buffers the
//!   request's user-row writes and outbox effects, nothing of it is durable before the commit point, and a crash
//!   frees the key. The outcome record is written only by [`State::commit`] (`latch.rs`), in the same transaction
//!   as the rows and the outbox rows.
//!
//! The principal is part of the key: the same client key under another principal is an independent key and never
//! sees that principal's outcome, conflict or lease. Exactly-once is not claimed: a request that dies before its
//! commit point leaves nothing behind and may run again.
//!
//! Every [`Lease`] must end in exactly one of [`State::commit`] or [`State::abort`]; a lease that is dropped keeps
//! its key held (fail-closed: `InFlight`) until the process restarts.
//!
//! Retention (F8 `state.idempotency_retention_s`, SPEC_INVARIANTS §F IDEMP-R; PREFLIGHT R12): each outcome record
//! carries the wall-clock second of its commit point ([`Record::committed_at`], written in the same transaction).
//! With a retention `R` set ([`State::set_retention`]), a record whose `now - committed_at >= R` is forgotten: the
//! key answers as if it had never completed (`New`, never `Replay` or `Conflict`), and [`State::purge_expired`]
//! deletes such records. Within the window (`now - committed_at < R`) INV-IDEMP holds unchanged. A record from the
//! future (the clock went back) is kept. Records written before Phase 8 have no timestamp and never expire, and with
//! no retention set (the default, F8 absent) nothing ever expires: the pre-Phase-8 meaning.
use crate::StateError;
use crate::latch::State;
use crate::outbox::{self, Dedupe};
use crate::store::{Op, Space};

/// Store space of the outcome records: key [`IdemKey::encode`], value [`Record`].
pub const IDEM_SPACE: Space = 16;
/// Store space of the user rows written through a [`Lease`].
pub const USER_SPACE: Space = 17;
/// Longest accepted client idempotency key, in bytes (Stripe's limit).
pub const MAX_KEY_LEN: usize = 255;
/// Longest accepted principal identifier, in bytes.
pub const MAX_PRINCIPAL_LEN: usize = 1024;
/// Longest accepted request digest, in bytes.
pub const MAX_DIGEST_LEN: usize = 64;

/// The idempotency key: `(principal, client key)`. Both parts are opaque, non-empty bytes; the host passes the
/// authenticated principal's stable identifier, never a client-supplied one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IdemKey {
    principal: Vec<u8>,
    key: Vec<u8>,
}

impl IdemKey {
    /// Build a key. Refuses an empty or over-long principal or client key.
    pub fn new(principal: &[u8], key: &[u8]) -> Result<IdemKey, StateError> {
        if principal.is_empty() || principal.len() > MAX_PRINCIPAL_LEN {
            return Err(StateError::Invalid("principal empty or longer than MAX_PRINCIPAL_LEN"));
        }
        if key.is_empty() || key.len() > MAX_KEY_LEN {
            return Err(StateError::Invalid("idempotency key empty or longer than MAX_KEY_LEN"));
        }
        Ok(IdemKey { principal: principal.to_vec(), key: key.to_vec() })
    }

    /// The principal part.
    pub fn principal(&self) -> &[u8] {
        &self.principal
    }

    /// The client key part.
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Unambiguous encoding: `u32be(len(principal)) || principal || key`.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(4 + self.principal.len() + self.key.len());
        b.extend_from_slice(&len_u32(self.principal.len()).to_be_bytes());
        b.extend_from_slice(&self.principal);
        b.extend_from_slice(&self.key);
        b
    }
}

/// A latched outcome: HTTP status and body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// HTTP status, 100..=599.
    pub status: u16,
    /// Response body.
    pub body: Vec<u8>,
}

/// The durable outcome record of a completed key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Digest of the request that completed the key.
    pub digest: Vec<u8>,
    /// Its outcome.
    pub outcome: Outcome,
    /// Wall-clock second (Unix time) of the commit point; `None` for a record written before Phase 8 (never
    /// expires).
    pub committed_at: Option<u64>,
}

/// Leading word of a timestamped (Phase 8) record. A pre-Phase-8 record starts with its digest length, which is at
/// most [`MAX_DIGEST_LEN`], so the two encodings cannot be confused.
const TIMESTAMPED: u32 = 0xFFFF_FFFE;

impl Record {
    /// Phase 8 form `u32be(0xFFFFFFFE) || u64be(committed_at) || v1`, else (no timestamp) the pre-Phase-8 form
    /// v1 = `u32be(len(digest)) || digest || u16be(status) || body`.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(18 + self.digest.len() + self.outcome.body.len());
        if let Some(t) = self.committed_at {
            b.extend_from_slice(&TIMESTAMPED.to_be_bytes());
            b.extend_from_slice(&t.to_be_bytes());
        }
        b.extend_from_slice(&len_u32(self.digest.len()).to_be_bytes());
        b.extend_from_slice(&self.digest);
        b.extend_from_slice(&self.outcome.status.to_be_bytes());
        b.extend_from_slice(&self.outcome.body);
        b
    }

    /// Inverse of [`Record::encode`]; any malformed record is [`StateError::Corrupt`].
    pub fn decode(b: &[u8]) -> Result<Record, StateError> {
        let bad = || StateError::Corrupt("idempotency record".to_string());
        let (committed_at, b) = match b.split_first_chunk::<4>() {
            Some((w, rest)) if u32::from_be_bytes(*w) == TIMESTAMPED => {
                let (t, rest) = rest.split_first_chunk::<8>().ok_or_else(bad)?;
                (Some(u64::from_be_bytes(*t)), rest)
            }
            _ => (None, b),
        };
        let (n, rest) = b.split_first_chunk::<4>().ok_or_else(bad)?;
        let n = usize::try_from(u32::from_be_bytes(*n)).map_err(|_| bad())?;
        let (digest, rest) = rest.split_at_checked(n).ok_or_else(bad)?;
        let (st, body) = rest.split_first_chunk::<2>().ok_or_else(bad)?;
        if digest.len() > MAX_DIGEST_LEN {
            return Err(bad());
        }
        Ok(Record {
            digest: digest.to_vec(),
            outcome: Outcome { status: u16::from_be_bytes(*st), body: body.to_vec() },
            committed_at,
        })
    }
}

/// Answer of [`State::begin`].
#[derive(Debug)]
pub enum Begin {
    /// Key free: the lease is held until [`State::commit`] or [`State::abort`].
    New(Lease),
    /// Completed with the same digest: the stored outcome, byte-identical.
    Replay(Outcome),
    /// Completed (or held) with a different digest: 422-class.
    Conflict,
    /// Held by an open request with the same digest: 409-class.
    InFlight,
}

/// One buffered outbox effect of a lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingEffect {
    pub(crate) dedupe: Dedupe,
    pub(crate) payload: Vec<u8>,
    /// Already in the outbox (only under the `effect_before_commit` self-test mutation).
    pub(crate) inserted: bool,
}

/// An open request's hold on its key, with its buffered (not yet durable) writes and effects. Not `Clone`: it is
/// consumed by exactly one [`State::commit`] or [`State::abort`].
#[derive(Debug)]
pub struct Lease {
    pub(crate) ik: IdemKey,
    pub(crate) digest: Vec<u8>,
    pub(crate) writes: Vec<Op>,
    pub(crate) effects: Vec<PendingEffect>,
}

impl Lease {
    /// The key this lease holds (as the store sees it).
    pub fn key(&self) -> &IdemKey {
        &self.ik
    }

    /// Buffer a user-row write; durable only at [`State::commit`].
    pub fn write(&mut self, row: &[u8], value: &[u8]) {
        self.writes.push(Op::Put { space: USER_SPACE, key: row.to_vec(), value: value.to_vec() });
    }

    /// Buffer a user-row delete; durable only at [`State::commit`].
    pub fn delete(&mut self, row: &[u8]) {
        self.writes.push(Op::Delete { space: USER_SPACE, key: row.to_vec() });
    }

    /// Number of effects buffered so far.
    pub fn effect_count(&self) -> usize {
        self.effects.len()
    }
}

impl State {
    /// INV-IDEMP lookup and lease. `digest` is the request digest (method, target, canonical body), 1..=64 bytes.
    pub fn begin(&mut self, key: &IdemKey, digest: &[u8]) -> Result<Begin, StateError> {
        if digest.is_empty() || digest.len() > MAX_DIGEST_LEN {
            return Err(StateError::Invalid("digest empty or longer than MAX_DIGEST_LEN"));
        }
        let ik = if self.muts.idem_key_without_principal {
            IdemKey { principal: b"*".to_vec(), key: key.key.clone() } // MUTATION (self-test only)
        } else {
            key.clone()
        };
        let enc = ik.encode();
        let now = self.now();
        let live = match self.store.get(IDEM_SPACE, &enc)? {
            Some(raw) => Some(Record::decode(&raw)?).filter(|rec| !self.expired(rec, now)),
            None => None,
        };
        if let Some(rec) = live {
            if rec.digest != digest {
                return Ok(Begin::Conflict);
            }
            if !self.muts.replay_reexecutes {
                return Ok(Begin::Replay(rec.outcome));
            }
        }
        if let Some(held) = self.held.get(&enc) {
            return Ok(if held.as_slice() == digest { Begin::InFlight } else { Begin::Conflict });
        }
        self.held.insert(enc, digest.to_vec());
        Ok(Begin::New(Lease { ik, digest: digest.to_vec(), writes: Vec::new(), effects: Vec::new() }))
    }

    /// Buffer an external effect of `lease` for the outbox (NC6). Nothing is visible or durable before
    /// [`State::commit`]. Returns the effect's dedupe key, derived from the idempotency key and the effect's
    /// position, so it is stable across redeliveries.
    pub fn effect(&mut self, lease: &mut Lease, payload: &[u8]) -> Result<Dedupe, StateError> {
        let index = u64::try_from(lease.effects.len()).map_err(|_| StateError::Invalid("too many effects"))?;
        let dedupe = outbox::dedupe_key(&lease.ik, index);
        let mut inserted = false;
        if self.muts.effect_before_commit {
            // MUTATION (self-test only): the outbox row is committed at once, before the commit point.
            let op = self.outbox_put(dedupe, payload);
            self.store.commit(&[op])?;
            self.next_seq = self.next_seq.saturating_add(1);
            inserted = true;
        }
        lease.effects.push(PendingEffect { dedupe, payload: payload.to_vec(), inserted });
        Ok(dedupe)
    }

    /// Terminate `lease` before its commit point (NC1): its buffered writes and effects are discarded, nothing
    /// becomes durable, and the key is free again.
    pub fn abort(&mut self, lease: Lease) {
        self.held.remove(&lease.ik.encode());
    }

    /// The durable outcome record of a key, if it completed and is not expired (retrieval after a 202, NC2).
    pub fn outcome(&mut self, key: &IdemKey) -> Result<Option<Record>, StateError> {
        let now = self.now();
        match self.store.get(IDEM_SPACE, &key.encode())? {
            Some(raw) => {
                let rec = Record::decode(&raw)?;
                Ok(if self.expired(&rec, now) { None } else { Some(rec) })
            }
            None => Ok(None),
        }
    }

    /// IDEMP-R: whether `rec` is past the retention window at `now` (never without a retention or a timestamp,
    /// never for a record from the future).
    pub(crate) fn expired(&self, rec: &Record, now: u64) -> bool {
        if self.muts.retention_ignored {
            return false; // MUTATION (self-test only): keys never expire
        }
        let (Some(r), Some(t)) = (self.retention, rec.committed_at) else { return false };
        let age = now.saturating_sub(t);
        if self.muts.retention_early {
            return now >= t && age.saturating_add(1) >= r; // MUTATION (self-test only): one second early
        }
        now >= t && age >= r
    }

    /// Delete every outcome record past the retention window (IDEMP-R), in one durable transaction. Keys held by an
    /// open lease are left alone (their commit overwrites the record). Returns the number deleted; 0 without a
    /// retention. Bounded by the size of the idempotency space (one scan).
    pub fn purge_expired(&mut self) -> Result<usize, StateError> {
        if self.retention.is_none() {
            return Ok(0);
        }
        let now = self.now();
        let mut ops = Vec::new();
        for (k, v) in self.store.scan(IDEM_SPACE)? {
            if self.held.contains_key(&k) {
                continue;
            }
            if self.expired(&Record::decode(&v)?, now) {
                ops.push(Op::Delete { space: IDEM_SPACE, key: k });
            }
        }
        if !ops.is_empty() {
            self.store.commit(&ops)?;
        }
        Ok(ops.len())
    }
}

fn len_u32(n: usize) -> u32 {
    // Lengths are bounded by MAX_PRINCIPAL_LEN / MAX_DIGEST_LEN at construction; saturate defensively.
    u32::try_from(n).unwrap_or(u32::MAX)
}
