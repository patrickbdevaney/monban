//! Principals for test sessions, minted through the production authentication path: an monban-token Tier-0 handle
//! with a `tenant` caveat, resolved by `Tier0Table::lookup` (which calls `monban_types::authn_path::mint`).

use monban_token::{Caveat, Req, Tier0Table};
use monban_types::{Principal, TenantId};

pub fn principal(tenant: TenantId) -> Result<Principal, String> {
    let mut table = Tier0Table::new();
    let h = table
        .insert(tenant, b"host-subject", vec![Caveat::Tenant(tenant.get())])
        .map_err(|e| format!("tier0 insert: {e:?}"))?;
    let req = Req {
        aud: String::new(),
        ops: 0,
        res: Vec::new(),
        tenant: tenant.get(),
        holder: Vec::new(),
        tool: String::new(),
        args: Vec::new(),
        now: 0,
    };
    table.lookup(h.as_bytes(), &req).map_err(|e| format!("tier0 lookup: {e:?}"))
}
