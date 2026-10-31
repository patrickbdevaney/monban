//! The core build (no feature `native`, PLAN D17): no data plane is linked. An `app:<name>` route names no linked
//! app, so `plan` refuses it and the boot fails closed (exit 78) before any socket; nothing here can serve a request.
//! The types mirror `native/mod.rs` so the assembly compiles unchanged; [`DataPlane`] is uninhabited.

use std::sync::Arc;

use aegis_config::{Config, RouteTarget};

/// The prefix of an app route target (F8 `upstream` is a free string; PLAN D16).
pub const APP_PREFIX: &str = "app:";
/// No app is linked into the core build.
pub const APPS: &[&str] = &[];

/// An app route as served (never produced in the core build: [`Bindings`] is always empty).
#[derive(Clone, Debug)]
pub struct AppRoute;

/// App routes of one config generation: always empty here.
#[derive(Debug, Default)]
pub struct Bindings;

impl Bindings {
    pub fn get(&self, _host: &str, _id: u64) -> Option<&AppRoute> {
        None
    }
}

/// The data plane: uninhabited in the core build.
#[derive(Debug)]
pub enum DataPlane {}

impl DataPlane {
    pub fn bind(&self, _cfg: &Config) -> Result<Bindings, String> {
        match *self {}
    }
    pub fn bump_epoch(&self, _epoch: u64) {
        match *self {}
    }
    pub fn active(&self) -> usize {
        match *self {}
    }
    pub fn start_dropping(&self) {
        match *self {}
    }
}

/// True iff the config binds at least one route to an app.
pub fn has_app_routes(cfg: &Config) -> bool {
    cfg.vhosts()
        .iter()
        .flat_map(|v| v.routes.iter())
        .any(|r| matches!(&r.to, RouteTarget::Upstream { upstream, .. } if upstream.starts_with(APP_PREFIX)))
}

/// True iff some `{"wasm": id}` route carries a data block (refused by `plan` in this build).
pub fn has_data_wasm_routes(cfg: &Config) -> bool {
    cfg.vhosts()
        .iter()
        .flat_map(|v| v.routes.iter())
        .any(|r| matches!(r.to, RouteTarget::Wasm { .. }) && r.data.is_some())
}

/// No data plane, so no P2 store: every data_run of a P2 route is refused (and audited as refused).
#[cfg(feature = "p2")]
pub fn p2_store(
    _dp: Option<&Arc<DataPlane>>,
    _bindings: &Bindings,
    _host: &str,
    _route_id: u64,
    _principal: aegis_types::Principal,
) -> Option<Box<dyn crate::p2::data::Store>> {
    None
}

/// No data plane: `Ok(None)`, or a refusal when the config binds a route to an app (unreachable after `plan`).
pub fn boot(
    cfg: &Config,
    _keyring: Option<&std::path::Path>,
    _mutants: crate::shared::Mutants,
) -> Result<Option<Arc<DataPlane>>, String> {
    if has_app_routes(cfg) || has_data_wasm_routes(cfg) {
        return Err(
            "app routes and data endowments need the native data plane: this build has no feature `native`".into()
        );
    }
    Ok(None)
}

pub mod http {
    use std::sync::Arc;

    use aegis_transport::{Reply, Request};

    use super::{AppRoute, DataPlane};
    use crate::shared::Shared;

    pub async fn handle(_s: &Arc<Shared>, dp: &Arc<DataPlane>, _r: &AppRoute, _id: u64, _q: &Request) -> Reply {
        match **dp {}
    }
}
