//! Test principals, minted through the production authentication path: an aegis-token Tier-0 handle with a
//! `tenant` caveat, resolved by `Tier0Table::lookup` (the aegis-token-owned authentication path).

use aegis_token::{Caveat, Req, Tier0Table};
use aegis_types::{Principal, TenantId};

pub fn principal(tenant: TenantId) -> Result<Principal, String> {
    let mut table = Tier0Table::new();
    let h = table
        .insert(tenant, b"aegis-bin-test", vec![Caveat::Tenant(tenant.get())])
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
