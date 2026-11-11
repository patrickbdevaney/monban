//! `do idem` / `do outbox` on monban-state: idempotency keyed by (principal, key); outbox entries scoped by
//! (principal, tenant).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use monban_adapter_pg::data_ir::tenant_text;
use monban_state::{Begin, IdemKey, Outcome, State, StateMutations};

use crate::{Mutants, Scope};

/// Request digest of a `do idem` (the oracle's request is the same request under each key; the value is its outcome).
const IDEM_DIGEST: &[u8] = b"crs-diff idem v1";
/// Request digest of an outbox-enqueueing request.
const OUTBOX_DIGEST: &[u8] = b"crs-diff outbox v1";

pub struct Scoped {
    dir: PathBuf,
    state: State,
    seq: u64,
}

/// `u32be(len(principal)) || principal || tenant_text(tenant)`: the scope an outbox payload is tagged with.
fn scope_tag(s: &Scope) -> Vec<u8> {
    let p = s.principal.as_bytes();
    let mut b = Vec::with_capacity(4 + p.len() + 16);
    b.extend_from_slice(&u32::try_from(p.len()).unwrap_or(u32::MAX).to_be_bytes());
    b.extend_from_slice(p);
    b.extend_from_slice(tenant_text(s.tenant).as_bytes());
    b
}

/// Split a payload into (scope tag, entry).
fn split_payload(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let (n, rest) = b.split_first_chunk::<4>()?;
    let n = usize::try_from(u32::from_be_bytes(*n)).ok()?.checked_add(16)?;
    let tag_len = n.checked_add(4)?;
    let tag = b.get(..tag_len)?;
    let entry = rest.get(n..)?;
    Some((tag, entry))
}

impl Scoped {
    pub fn open(m: Mutants) -> Result<Scoped, String> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("crs-subject-{}-{nanos}", std::process::id()));
        std::fs::create_dir(&dir).map_err(|e| format!("state dir {}: {e}", dir.display()))?;
        let muts = StateMutations { idem_key_without_principal: m.idem_no_principal, ..StateMutations::NONE };
        match State::open_with(&dir, muts) {
            Ok(state) => Ok(Scoped { dir, state, seq: 0 }),
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                Err(format!("open state: {e}"))
            }
        }
    }

    /// Store `value` as the outcome under (principal, key) unless an outcome exists; returns (prior, fresh).
    pub fn idem(&mut self, s: &Scope, key: &str, value: &str) -> Result<(Option<String>, bool), String> {
        let ik = IdemKey::new(s.principal.as_bytes(), key.as_bytes()).map_err(|e| e.to_string())?;
        match self.state.begin(&ik, IDEM_DIGEST).map_err(|e| e.to_string())? {
            Begin::Replay(o) => Ok((Some(String::from_utf8_lossy(&o.body).into_owned()), false)),
            Begin::New(lease) => {
                let outcome = Outcome { status: 200, body: value.as_bytes().to_vec() };
                self.state.commit(lease, outcome, false).map_err(|e| e.to_string())?;
                Ok((None, true))
            }
            Begin::Conflict => Err("idempotency conflict".into()),
            Begin::InFlight => Err("idempotency key in flight".into()),
        }
    }

    /// Enqueue `entry` as the effect of a committed request of scope `s`; list the pending entries of `s` (or of
    /// every scope under the `outbox-no-principal` mutant).
    pub fn outbox(&mut self, s: &Scope, entry: &str, unscoped: bool) -> Result<Vec<String>, String> {
        self.seq = self.seq.saturating_add(1);
        let rk = format!("crs-outbox-{}", self.seq);
        let ik = IdemKey::new(s.principal.as_bytes(), rk.as_bytes()).map_err(|e| e.to_string())?;
        let mut lease = match self.state.begin(&ik, OUTBOX_DIGEST).map_err(|e| e.to_string())? {
            Begin::New(l) => l,
            _ => return Err("outbox request key already used".into()),
        };
        let tag = scope_tag(s);
        let mut payload = tag.clone();
        payload.extend_from_slice(entry.as_bytes());
        self.state.effect(&mut lease, &payload).map_err(|e| e.to_string())?;
        self.state.commit(lease, Outcome { status: 200, body: Vec::new() }, false).map_err(|e| e.to_string())?;
        let mut vis = Vec::new();
        for e in self.state.pending().map_err(|e| e.to_string())? {
            let (t, body) = split_payload(&e.payload).ok_or("corrupt outbox payload")?;
            if unscoped || t == tag.as_slice() {
                vis.push(String::from_utf8_lossy(body).into_owned());
            }
        }
        Ok(vis)
    }

    pub fn close(self) {
        let Scoped { dir, state, .. } = self;
        drop(state);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
