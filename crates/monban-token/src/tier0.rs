//! Tier 0 (default): an opaque 32-byte handle resolved in a server-side table, with instant revocation.
//!
//! A handle is 8 public selector bytes followed by 24 secret bytes, all from the AWS-LC DRBG. The table is keyed by
//! the selector and stores only SHA-256(handle), so a table dump does not reveal live handles; the full digest is
//! compared in constant time. Lookups judge the stored caveats with the same `denote` as Tier L.

use std::collections::HashMap;

use aws_lc_rs::{constant_time, digest};

use monban_types::{Principal, TenantId, authn_path};

use crate::caveat::{Caveat, Req, denote};
use crate::{TokenError, VerifyError};

pub const HANDLE_LEN: usize = 32;
const SELECTOR_LEN: usize = 8;

/// An opaque handle. Debug redacts it.
#[derive(Clone, PartialEq, Eq)]
pub struct Handle([u8; HANDLE_LEN]);

impl core::fmt::Debug for Handle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Handle(<redacted>)")
    }
}

impl Handle {
    pub fn as_bytes(&self) -> &[u8; HANDLE_LEN] {
        &self.0
    }
}

#[derive(Debug)]
struct Entry {
    digest: [u8; 32],
    tenant: TenantId,
    subject: Vec<u8>,
    caveats: Vec<Caveat>,
}

/// The server-side handle table.
#[derive(Debug, Default)]
pub struct Tier0Table {
    map: HashMap<[u8; SELECTOR_LEN], Entry>,
}

fn selector(h: &[u8]) -> Option<[u8; SELECTOR_LEN]> {
    h.get(..SELECTOR_LEN)?.try_into().ok()
}

fn sha256(b: &[u8]) -> Result<[u8; 32], TokenError> {
    digest::digest(&digest::SHA256, b).as_ref().try_into().map_err(|_| TokenError::Crypto)
}

impl Tier0Table {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Registers a grant and returns its fresh handle. `subject` is 1..255 bytes; caveats must be well formed.
    pub fn insert(&mut self, tenant: TenantId, subject: &[u8], caveats: Vec<Caveat>) -> Result<Handle, TokenError> {
        if subject.is_empty() || subject.len() > authn_path::MAX_SUBJECT_BYTES || !crate::tier_l::caveats_ok(&caveats) {
            return Err(TokenError::Invalid);
        }
        for _ in 0..8 {
            let mut h = [0u8; HANDLE_LEN];
            aws_lc_rs::rand::fill(&mut h).map_err(|_| TokenError::Crypto)?;
            let sel = selector(&h).ok_or(TokenError::Crypto)?;
            if self.map.contains_key(&sel) {
                continue;
            }
            let entry = Entry { digest: sha256(&h)?, tenant, subject: subject.to_vec(), caveats };
            self.map.insert(sel, entry);
            return Ok(Handle(h));
        }
        Err(TokenError::Crypto)
    }

    fn find(&self, handle: &[u8]) -> Option<([u8; SELECTOR_LEN], &Entry)> {
        if handle.len() != HANDLE_LEN {
            return None;
        }
        let sel = selector(handle)?;
        let e = self.map.get(&sel)?;
        let d = sha256(handle).ok()?;
        constant_time::verify_slices_are_equal(&d, &e.digest).ok()?;
        Some((sel, e))
    }

    /// Instant revocation. Returns whether a live grant was removed.
    pub fn revoke(&mut self, handle: &[u8]) -> bool {
        let Some((sel, _)) = self.find(handle) else { return false };
        self.map.remove(&sel).is_some()
    }

    /// Resolves a presented handle and judges the request against every stored caveat.
    pub fn lookup(&self, handle: &[u8], r: &Req) -> Result<Principal, VerifyError> {
        let (_, e) = self.find(handle).ok_or(VerifyError::BadTag)?;
        if e.tenant.get() != r.tenant {
            return Err(VerifyError::Denied);
        }
        if !denote(&e.caveats, r) {
            return Err(VerifyError::Denied);
        }
        authn_path::mint(e.tenant, Some(&e.subject)).map_err(|_| VerifyError::BadPrincipal)
    }
}
