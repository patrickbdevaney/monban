//! NC6: external effects only through the outbox.
//!
//! A request's effects are buffered in its [`Lease`](crate::Lease) and become outbox rows in the same store
//! transaction as its user rows and outcome record ([`State::commit`], `latch.rs`). Nothing of an aborted,
//! killed or rolled-back request ever reaches the outbox, so it can never be delivered.
//!
//! The relay ([`State::deliver`]) is at-least-once: it hands every committed, undelivered effect to the sink,
//! oldest first, and marks it delivered (removes the row, durably) only **after** the sink accepted it. A crash
//! between the two redelivers the effect with the same [`Dedupe`] key, which is derived from the idempotency key
//! and the effect's position in its request and stored in the row, so it never changes across redeliveries and
//! never names two different effects (a key completes once). Exactly-once is not claimed; the receiver dedupes.
//!
//! Row layout in [`OUTBOX_SPACE`]: key `u64be(seq)` (commit order), value `dedupe(16) || payload`.
use aws_lc_rs::digest::{SHA256, digest};

use crate::StateError;
use crate::idem::IdemKey;
use crate::latch::State;
use crate::store::{Op, Space, Store};

/// Store space of the undelivered outbox rows.
pub const OUTBOX_SPACE: Space = 18;
/// Length of a dedupe key in bytes.
pub const DEDUPE_LEN: usize = 16;
/// Dedupe key of one effect.
pub type Dedupe = [u8; DEDUPE_LEN];

const DEDUPE_DOMAIN: &[u8] = b"monban-state outbox dedupe v1\0";

/// `SHA-256(domain || IdemKey::encode() || u64be(index))[..16]`: stable for a given request's `index`-th effect.
pub fn dedupe_key(ik: &IdemKey, index: u64) -> Dedupe {
    let enc = ik.encode();
    let mut m = Vec::with_capacity(DEDUPE_DOMAIN.len() + 4 + enc.len() + 8);
    m.extend_from_slice(DEDUPE_DOMAIN);
    m.extend_from_slice(&u32::try_from(enc.len()).unwrap_or(u32::MAX).to_be_bytes());
    m.extend_from_slice(&enc);
    m.extend_from_slice(&index.to_be_bytes());
    let d = digest(&SHA256, &m);
    let mut out = [0u8; DEDUPE_LEN];
    for (o, b) in out.iter_mut().zip(d.as_ref().iter()) {
        *o = *b;
    }
    out
}

/// One committed, undelivered effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effect {
    /// Commit order (outbox sequence number).
    pub seq: u64,
    /// Stable dedupe key, to be sent with the effect.
    pub dedupe: Dedupe,
    /// Effect payload.
    pub payload: Vec<u8>,
}

/// Failure of a relay pass.
#[derive(Debug)]
pub enum DeliverError<E> {
    /// The sink refused an effect; it stays undelivered and the pass stops.
    Sink(E),
    /// Store failure (fail-closed; the store may be poisoned).
    State(StateError),
}

impl<E> From<StateError> for DeliverError<E> {
    fn from(e: StateError) -> Self {
        DeliverError::State(e)
    }
}

fn decode_row(k: &[u8], v: &[u8]) -> Result<Effect, StateError> {
    let bad = || StateError::Corrupt("outbox row".to_string());
    let seq = u64::from_be_bytes(<[u8; 8]>::try_from(k).map_err(|_| bad())?);
    let (dedupe, payload) = v.split_first_chunk::<DEDUPE_LEN>().ok_or_else(bad)?;
    Ok(Effect { seq, dedupe: *dedupe, payload: payload.to_vec() })
}

/// Outbox recovery at open: the next sequence number (one past the newest undelivered row). Under the
/// `outbox_drop_on_restart` self-test mutation, undelivered rows are dropped instead.
pub(crate) fn recover(store: &mut Store, drop_undelivered: bool) -> Result<u64, StateError> {
    let rows = store.scan(OUTBOX_SPACE)?;
    let mut next = 0u64;
    let mut drops = Vec::new();
    for (k, v) in &rows {
        let e = decode_row(k, v)?;
        next = next.max(e.seq.saturating_add(1));
        if drop_undelivered {
            drops.push(Op::Delete { space: OUTBOX_SPACE, key: k.clone() }); // MUTATION (self-test only)
        }
    }
    if !drops.is_empty() {
        store.commit(&drops)?;
    }
    Ok(next)
}

impl State {
    /// The outbox row for the next sequence number (the caller advances `next_seq` once it commits).
    pub(crate) fn outbox_put(&self, dedupe: Dedupe, payload: &[u8]) -> Op {
        self.outbox_put_at(self.next_seq, dedupe, payload)
    }

    pub(crate) fn outbox_put_at(&self, seq: u64, dedupe: Dedupe, payload: &[u8]) -> Op {
        let mut value = Vec::with_capacity(DEDUPE_LEN + payload.len());
        value.extend_from_slice(&dedupe);
        value.extend_from_slice(payload);
        Op::Put { space: OUTBOX_SPACE, key: seq.to_be_bytes().to_vec(), value }
    }

    /// Every committed, undelivered effect, oldest first.
    pub fn pending(&mut self) -> Result<Vec<Effect>, StateError> {
        let rows = self.store.scan(OUTBOX_SPACE)?;
        rows.iter().map(|(k, v)| decode_row(k, v)).collect()
    }

    /// Mark one effect delivered (durable). Call only after the sink accepted it.
    pub fn mark_delivered(&mut self, seq: u64) -> Result<(), StateError> {
        self.store.commit(&[Op::Delete { space: OUTBOX_SPACE, key: seq.to_be_bytes().to_vec() }])?;
        Ok(())
    }

    /// One relay pass: each pending effect goes to `send`, and is marked delivered only after `send` returned
    /// `Ok` (at-least-once). Returns the number of effects delivered.
    pub fn deliver<E, F>(&mut self, mut send: F) -> Result<usize, DeliverError<E>>
    where
        F: FnMut(&Effect) -> Result<(), E>,
    {
        let mut n = 0usize;
        for e in self.pending()? {
            send(&e).map_err(DeliverError::Sink)?;
            self.mark_delivered(e.seq)?;
            n = n.saturating_add(1);
        }
        Ok(n)
    }
}
