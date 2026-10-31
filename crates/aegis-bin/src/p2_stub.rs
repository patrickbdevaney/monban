//! Builds without feature `p2` (PLAN-5 D3): no P2 supervisor is linked. A `{"wasm": id}` route is refused by
//! `plan` and the boot fails closed (exit 78) before any socket; nothing here can serve a request. The types mirror
//! `p2/mod.rs` so the assembly compiles unchanged; [`Runtime`] is uninhabited.

use std::path::Path;
use std::sync::Arc;

use aegis_config::{Config, RouteTarget};

/// True iff the config routes at least one request to a P2 module.
pub fn has_wasm_routes(cfg: &Config) -> bool {
    cfg.vhosts().iter().flat_map(|v| v.routes.iter()).any(|r| matches!(r.to, RouteTarget::Wasm { .. }))
}

/// The P2 supervisor: uninhabited without feature `p2`.
#[derive(Debug)]
pub enum Runtime {}

/// Never produced.
#[derive(Debug)]
pub struct Prepared;

impl Runtime {
    pub fn prepare(&self, _cfg: &Config) -> Result<Prepared, String> {
        match *self {}
    }
    pub fn install(&self, _p: Prepared) -> Result<(), String> {
        match *self {}
    }
    pub fn shutdown(&self) {
        match *self {}
    }
    pub fn set_auditor(&self, _a: Arc<crate::audit::Auditor>) {
        match *self {}
    }
}

/// Mirrors `p2::Guard`.
#[derive(Debug)]
pub struct Guard(pub Option<Arc<Runtime>>);

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(rt) = &self.0 {
            rt.shutdown();
        }
    }
}

/// No P2 supervisor: `Ok(None)`, or a refusal when the config has a wasm route (unreachable after `plan`).
pub fn boot(
    cfg: &Config,
    _keyring: Option<&Path>,
    _runtime_dir: Option<&Path>,
) -> Result<Option<Arc<Runtime>>, String> {
    if has_wasm_routes(cfg) {
        return Err("wasm routes need the P2 supervisor: this build has no feature `p2`".into());
    }
    Ok(None)
}

pub mod http {
    use std::sync::Arc;

    use aegis_transport::{Reply, Request};

    use crate::shared::Shared;

    /// No route of a build without `p2` targets a module (plan refuses them).
    pub async fn handle(_s: &Arc<Shared>, _q: &Request) -> Option<Reply> {
        None
    }
}
