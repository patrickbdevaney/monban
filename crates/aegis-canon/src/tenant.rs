//! Principal / tenant id: an ASCII slug `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`, accepted only as itself (no
//! folding of any kind). There is no `Canon` kind for it in F2, so the sealed result is [`TenantSlug`].

use alloc::boxed::Box;
use core::fmt;

use crate::Reject;

/// A tenant slug that passed [`canon_tenant`]; constructible only by this crate.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TenantSlug(Box<[u8]>);

impl TenantSlug {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for TenantSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TenantSlug(<{} bytes>)", self.0.len())
    }
}

/// Validate a tenant slug.
pub fn canon_tenant(input: &[u8]) -> Result<TenantSlug, Reject> {
    let alnum = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let ok = (1..=63).contains(&input.len())
        && input.iter().all(|b| alnum(b) || *b == b'-')
        && input.first().is_some_and(alnum)
        && input.last().is_some_and(alnum);
    if ok {
        Ok(TenantSlug(Box::from(input)))
    } else {
        Err(Reject::new(400, "tenant", "not an ASCII slug (no folding)"))
    }
}
