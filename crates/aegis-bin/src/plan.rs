//! From a validated F8 [`Config`] to what the assembly runs: listener plans, the admin bind, and the routing table.
//!
//! aegis-config already enforced F8 exactly; this adds the checks only the assembly can make (fail closed, exit 78
//! at boot, last-known-good on reload):
//! * listener `bind` is an IP socket address; the profile is buildable in this binary (not F12-pending);
//! * `admin.bind` is a loopback socket address or `unix:/absolute/path` (default `127.0.0.1:9464`);
//! * every route path is already canonical (`canon_path` is a fixed point on it), so routing compares canonical
//!   bytes with canonical bytes;
//! * `to.upstream` is `host:port` or `unix:/absolute/path`. F8 declares no upstream table, so the string *is* the
//!   upstream; plain HTTP to it (upstream TLS is a later unit). `framing` defaults to `h1-regenerate` (TCP) or `uds`
//!   (unix); `uds` = HTTP/1.1 with regenerated framing over a unix socket and requires a `unix:` target;
//! * `to.upstream = "app:<name>"` binds the route to a native app linked into this binary (modes A/D, PLAN D16);
//!   it and a `wasm` route are the only routes that may carry a `data` endowment (resolved at boot by
//!   [`crate::native`]);
//! * `to.static` is refused: static file serving is not in this build;
//! * `to.wasm = <module-id>` (Phase 5, F14) binds the route to a P2 module served by aegis-p2 workers; it needs
//!   feature `p2` (refused otherwise), a `data` block on it needs feature `native` too (resolved by the native data
//!   plane, served to the module's `data_run`s, P5-bin-002), and `p2.frame_max_bytes` must be the default 65,536:
//!   the aegis-p2 worker command line cannot carry another frame cap, so any other value is refused rather than
//!   half-applied.
//!
//! Routing (documented semantics; F8 says nothing finer): a route path matches a canonical request path exactly,
//! or as a prefix when the route path ends in `/` (`/api/` matches `/api/x`, not `/api`); the longest match wins.
//! A trailing slash is its own canonical form (q4-008), so `/a` and `/a/` are different routes.

use std::net::SocketAddr;
use std::path::PathBuf;

use aegis_config::{AuthzRequirement, Config, Framing, QueryMode, RouteTarget};

/// Default admin bind when the config has no `admin.bind` (F8: "metrics endpoint always on").
pub const DEFAULT_ADMIN: &str = "127.0.0.1:9464";

/// The only policy name this build evaluates. Cedar policy sets arrive in Phase 3 (aegis-authz); every other name
/// is denied (fail closed), as is a route without `authz` (INV-NONEMPTY).
pub const ALLOW_ALL: &str = "allow-all";

/// Upstream address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    Tcp { host: String, port: u16 },
    Unix(PathBuf),
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp { host, port } if host.contains(':') => write!(f, "[{host}]:{port}"),
            Self::Tcp { host, port } => write!(f, "{host}:{port}"),
            Self::Unix(p) => write!(f, "unix:{}", p.display()),
        }
    }
}

/// Upstream wire protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UpFraming {
    /// HTTP/1.1, framing regenerated from Canon (R-TLS-3).
    H1,
    /// HTTP/2 with prior knowledge (h2c).
    H2,
}

/// CRS C3: the upstream pool key is `derive(Hash, Eq)` over this whole struct. `scope` is σ for this phase (the
/// canonical vhost host): there are no principals before Phase 3, and a connection is never shared across vhosts
/// (C2/C8). The pool adds the config epoch (C5).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UpstreamConnConfig {
    pub target: Target,
    pub framing: UpFraming,
    pub scope: Vec<u8>,
}

/// Authorization outcome for a route, decided at plan time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authz {
    /// No `authz` (or empty): INV-NONEMPTY deny.
    Missing,
    /// `allow-all`.
    AllowAll,
    /// A policy name this build cannot evaluate: deny.
    Unknown(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteRt {
    pub id: u64,
    /// Canonical route path.
    pub path: Vec<u8>,
    pub prefix: bool,
    pub to: RouteTo,
    pub authz: Authz,
}

/// Where a route's requests go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteTo {
    /// Reverse proxy (mode R).
    Upstream(UpstreamConnConfig),
    /// A native application linked into this binary (modes A/D): `to.upstream = "app:<name>"` (PLAN D16).
    App(String),
    /// A P2 module (feature `p2`): `to.wasm = <module-id>`, a declared `p2.modules[]` entry.
    Wasm(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VhostRt {
    pub host: String,
    pub routes: Vec<RouteRt>,
}

impl VhostRt {
    /// Longest matching route for a canonical path.
    pub fn route(&self, path: &[u8]) -> Option<&RouteRt> {
        self.routes
            .iter()
            .filter(|r| r.path == path || (r.prefix && path.starts_with(&r.path)))
            .max_by_key(|r| r.path.len())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListenerPlan {
    pub name: String,
    pub addr: SocketAddr,
    pub profile: aegis_tls::Profile,
    pub alpn: Vec<Vec<u8>>,
    /// F8 `proxy_protocol` (PROXY-1..3; feature `proxy-protocol`, refused by [`plan`] otherwise).
    pub proxy: Option<aegis_config::ProxyProtocol>,
    /// F8 `l4` (L4-1/L4-2; feature `l4`, refused by [`plan`] otherwise): an SNI-passthrough listener, never HTTP.
    pub l4: Option<Vec<aegis_config::L4Route>>,
    /// F8 `front` (FRONT-1; `uring` needs feature `uring`). The `--front` flag overrides it at serve time.
    pub front: aegis_config::Front,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminBind {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl std::fmt::Display for AdminBind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(a) => write!(f, "{a}"),
            Self::Unix(p) => write!(f, "unix:{}", p.display()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Plan {
    pub listeners: Vec<ListenerPlan>,
    pub admin: AdminBind,
    pub vhosts: Vec<VhostRt>,
    pub query: aegis_canon::QueryMode,
    pub limits: aegis_config::Limits,
    /// The same limits mapped by name onto the transport's wrapper limits (plus its golden non-F8 settings).
    pub wl: aegis_transport::WrapperLimits,
    /// F8 `admission` with defaults applied (absent = the pre-Phase-7 constants); fixed for the process.
    pub admission: aegis_config::Admission,
    /// Non-fatal findings for `check-config`.
    pub warnings: Vec<String>,
}

impl Plan {
    /// Listeners and admin are bound once per process; a reload may change routes and limits only (a listener
    /// change goes through the zero-downtime upgrade, SIGUSR2).
    pub fn same_sockets(&self, other: &Plan) -> bool {
        self.listeners == other.listeners && self.admin == other.admin
    }
    /// The admission limiter is built once per process: a reload may not change F8 `admission`.
    pub fn same_admission(&self, other: &Plan) -> bool {
        self.admission == other.admission
    }
}

fn parse_target(s: &str) -> Result<Target, String> {
    if let Some(p) = s.strip_prefix("unix:") {
        let p = PathBuf::from(p);
        if !p.is_absolute() {
            return Err(format!("upstream {s:?}: unix path must be absolute"));
        }
        return Ok(Target::Unix(p));
    }
    let (host, port) = s.rsplit_once(':').ok_or_else(|| format!("upstream {s:?}: expected host:port or unix:/path"))?;
    let port: u16 = port.parse().ok().filter(|p| *p != 0).ok_or_else(|| format!("upstream {s:?}: bad port"))?;
    let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    let ok = !host.is_empty()
        && host.len() <= 253
        && (host.parse::<std::net::IpAddr>().is_ok()
            || host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.'));
    if !ok {
        return Err(format!("upstream {s:?}: bad host"));
    }
    Ok(Target::Tcp { host: host.to_ascii_lowercase(), port })
}

fn parse_admin(s: Option<&str>) -> Result<AdminBind, String> {
    let s = s.unwrap_or(DEFAULT_ADMIN);
    if let Some(p) = s.strip_prefix("unix:") {
        let p = PathBuf::from(p);
        if !p.is_absolute() {
            return Err(format!("admin.bind {s:?}: unix path must be absolute"));
        }
        return Ok(AdminBind::Unix(p));
    }
    let a: SocketAddr = s.parse().map_err(|_| format!("admin.bind {s:?}: not a socket address or unix:/path"))?;
    if !a.ip().is_loopback() {
        return Err(format!("admin.bind {s:?}: must be loopback (or a unix socket)"));
    }
    Ok(AdminBind::Tcp(a))
}

fn route_authz(at: &str, r: &aegis_config::Route, warnings: &mut Vec<String>) -> Authz {
    match r.authz_requirement() {
        AuthzRequirement::Deny => {
            warnings.push(format!("{at}: no authz policy; every request is denied (INV-NONEMPTY)"));
            Authz::Missing
        }
        AuthzRequirement::Policy(ALLOW_ALL) => Authz::AllowAll,
        AuthzRequirement::Policy(p) => {
            warnings
                .push(format!("{at}/authz {p:?}: only \"{ALLOW_ALL}\" is evaluated before Phase 3 (Cedar); denied"));
            Authz::Unknown(p.to_string())
        }
    }
}

/// The frame cap the aegis-p2 worker uses (F8 `p2.frame_max_bytes` default; the worker has no flag for another).
pub const P2_FRAME_MAX: u64 = 65_536;

/// Check a validated config against what this assembly can serve.
pub fn plan(cfg: &Config) -> Result<Plan, String> {
    let mut warnings = Vec::new();
    if let Some(p2) = cfg.p2() {
        let fm = p2.limits().frame_max_bytes;
        if fm != P2_FRAME_MAX {
            return Err(format!(
                "/p2/frame_max_bytes {fm}: the aegis-p2 worker uses {P2_FRAME_MAX} and its command line cannot carry \
                 another value (fail closed)"
            ));
        }
    }
    let mut listeners = Vec::new();
    for (i, l) in cfg.listeners().iter().enumerate() {
        let addr: SocketAddr =
            l.bind.parse().map_err(|_| format!("/listeners/{i}/bind {:?}: not an IP socket address", l.bind))?;
        let profile = aegis_tls::Profile::from_name(l.profile.as_str())
            .ok_or_else(|| format!("/listeners/{i}/profile {:?}: unknown to aegis-tls", l.profile.as_str()))?;
        if let Some(reason) = profile.pending_reason() {
            return Err(format!("/listeners/{i}/profile {}: not servable by this build: {reason}", l.profile.as_str()));
        }
        let alpn = match &l.alpn {
            Some(v) => v.iter().map(|a| a.as_str().as_bytes().to_vec()).collect(),
            None => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        };
        // A Phase-7 member whose feature is not built is refused (fail closed, exit 78): it is never ignored.
        if l.proxy_protocol.is_some() && !cfg!(feature = "proxy-protocol") {
            return Err(format!(
                "/listeners/{i}/proxy_protocol: this build has no feature `proxy-protocol` (fail closed)"
            ));
        }
        if l.l4.is_some() && !cfg!(feature = "l4") {
            return Err(format!("/listeners/{i}/l4: this build has no feature `l4` (fail closed)"));
        }
        if l.front == aegis_config::Front::Uring && !cfg!(feature = "uring") {
            return Err(format!("/listeners/{i}/front \"uring\": this build has no feature `uring` (fail closed)"));
        }
        listeners.push(ListenerPlan {
            name: l.name.clone(),
            addr,
            profile,
            alpn,
            proxy: l.proxy_protocol.clone(),
            l4: l.l4.clone(),
            front: l.front,
        });
    }
    if cfg.tls().is_some() && !cfg!(all(feature = "mtc", not(feature = "cmvp"))) {
        return Err("/tls: credential selection needs feature `mtc` (compiled out of the cmvp build); this build has \
                    none (fail closed)"
            .into());
    }
    for a in cfg.data().map(aegis_config::DataBlock::adapters).unwrap_or(&[]) {
        let built = match a.family {
            aegis_config::AdapterFamily::Mariadb => cfg!(feature = "adapter-mariadb"),
            aegis_config::AdapterFamily::Crdb => cfg!(feature = "adapter-crdb"),
        };
        if !built {
            return Err(format!(
                "/data/backends {:?}: engine {} needs feature `adapter-{}`; this build has none (fail closed)",
                a.id,
                a.family.as_str(),
                a.family.as_str()
            ));
        }
    }
    let admin = parse_admin(cfg.admin().and_then(|a| a.bind.as_deref()))?;
    let mut vhosts = Vec::new();
    for (vi, v) in cfg.vhosts().iter().enumerate() {
        let mut routes = Vec::new();
        for (ri, r) in v.routes.iter().enumerate() {
            let at = format!("/vhosts/{vi}/routes/{ri}");
            let canon = aegis_canon::canon_path(r.path.as_bytes())
                .map_err(|e| format!("{at}/path {:?}: not canonical ({e})", r.path))?;
            if canon.as_bytes() != r.path.as_bytes() {
                return Err(format!(
                    "{at}/path {:?}: not canonical (canonical form {:?})",
                    r.path,
                    String::from_utf8_lossy(canon.as_bytes())
                ));
            }
            let (upstream, framing) = match &r.to {
                RouteTarget::Upstream { upstream, framing } => (upstream, framing),
                RouteTarget::Static { .. } => {
                    return Err(format!("{at}/to: static targets are not served by this build (fail closed)"));
                }
                RouteTarget::Wasm { module } => {
                    if !cfg!(feature = "p2") {
                        return Err(format!(
                            "{at}/to: wasm targets need the P2 supervisor; this build has no feature `p2` (fail closed)"
                        ));
                    }
                    // A data block is resolved by the native data plane, which only a `native` build has.
                    if r.data.is_some() && !cfg!(feature = "native") {
                        return Err(format!(
                            "{at}/data: data endowments of wasm routes need the native data plane; this build has no \
                             feature `native` (fail closed)"
                        ));
                    }
                    let authz = route_authz(&at, r, &mut warnings);
                    routes.push(RouteRt {
                        id: r.id,
                        path: r.path.as_bytes().to_vec(),
                        prefix: r.path.ends_with('/'),
                        to: RouteTo::Wasm(module.clone()),
                        authz,
                    });
                    continue;
                }
            };
            let to = if let Some(app) = upstream.strip_prefix(crate::native::APP_PREFIX) {
                if !crate::native::APPS.contains(&app) {
                    let why = if cfg!(feature = "native") { "" } else { "; this build has no feature `native`" };
                    return Err(format!("{at}/to: unknown app {app:?} (linked: {:?}{why})", crate::native::APPS));
                }
                if framing.is_some() {
                    return Err(format!("{at}/to/framing: an app route has no upstream framing"));
                }
                RouteTo::App(app.to_string())
            } else {
                if r.data.is_some() {
                    return Err(format!("{at}/data: a data endowment needs an app route (to.upstream \"app:<name>\")"));
                }
                let target = parse_target(upstream).map_err(|e| format!("{at}/to: {e}"))?;
                let framing = match (framing, &target) {
                    (Some(Framing::H2), _) => UpFraming::H2,
                    (Some(Framing::H1Regenerate), _) | (None, _) => UpFraming::H1,
                    (Some(Framing::Uds), Target::Unix(_)) => UpFraming::H1,
                    (Some(Framing::Uds), Target::Tcp { .. }) => {
                        return Err(format!("{at}/to/framing: \"uds\" needs a unix:/path upstream"));
                    }
                };
                RouteTo::Upstream(UpstreamConnConfig { target, framing, scope: v.host.as_bytes().to_vec() })
            };
            let authz = route_authz(&at, r, &mut warnings);
            routes.push(RouteRt {
                id: r.id,
                path: r.path.as_bytes().to_vec(),
                prefix: r.path.ends_with('/'),
                to,
                authz,
            });
        }
        vhosts.push(VhostRt { host: v.host.clone(), routes });
    }
    let query = match cfg.canon().query {
        QueryMode::Opaque => aegis_canon::QueryMode::Opaque,
        QueryMode::Typed => aegis_canon::QueryMode::Typed,
    };
    let mut wl = aegis_transport::WrapperLimits::GOLDEN;
    for (&(name, ..), v) in aegis_config::Limits::BOUNDS.iter().zip(cfg.limits().values()) {
        wl.set_f8(name, v).map_err(|e| format!("/limits/{name}: {e}"))?;
    }
    wl.validate().map_err(|e| format!("/limits: {e}"))?;
    Ok(Plan { listeners, admin, vhosts, query, limits: *cfg.limits(), wl, admission: *cfg.admission(), warnings })
}

/// The routing table of one config generation, with the vhost authorities expanded for the listener ports.
#[derive(Debug)]
pub struct Snapshot {
    pub generation: u64,
    /// CRS C5 epoch: bumped on every applied config change; upstream connections never cross it.
    pub epoch: u64,
    pub hash: [u8; 32],
    pub plan: Plan,
    /// (canonical authority, allowed serialized origins, vhost index).
    authorities: Vec<(Vec<u8>, Vec<Vec<u8>>, usize)>,
    /// The app routes of this generation, resolved against the introspected schemas (empty without a data plane).
    pub native: std::sync::Arc<crate::native::Bindings>,
}

impl Snapshot {
    pub fn new(generation: u64, epoch: u64, hash: [u8; 32], plan: Plan) -> Self {
        let mut ports: Vec<u16> = plan.listeners.iter().map(|l| l.addr.port()).collect();
        ports.sort_unstable();
        ports.dedup();
        let mut authorities = Vec::new();
        for (i, v) in plan.vhosts.iter().enumerate() {
            let mut names = vec![v.host.clone()];
            names.extend(ports.iter().filter(|p| **p != 443).map(|p| format!("{}:{p}", v.host)));
            // Same-origin only: F8 has no origin list, so an Origin other than this vhost's own is a 421 (CANON-6).
            let origins: Vec<Vec<u8>> = names.iter().map(|n| format!("https://{n}").into_bytes()).collect();
            for n in names {
                authorities.push((n.into_bytes(), origins.clone(), i));
            }
        }
        Self { generation, epoch, hash, plan, authorities, native: Default::default() }
    }

    /// An empty table (no vhosts): every request is refused. Used only by the `skip-lkg` negative control.
    #[cfg(feature = "e2e-mutants")]
    pub fn empty(&self) -> Self {
        let mut plan = self.plan.clone();
        plan.vhosts.clear();
        Self {
            generation: self.generation,
            epoch: self.epoch.saturating_add(1),
            hash: [0; 32],
            plan,
            authorities: Vec::new(),
            native: Default::default(),
        }
    }

    /// The same table for the transport (CANON-6 binding happens there).
    pub fn vhost_table(&self) -> aegis_transport::VhostTable {
        let mut t = aegis_transport::VhostTable::new();
        for (a, o, _) in &self.authorities {
            let origins: Vec<&[u8]> = o.iter().map(Vec::as_slice).collect();
            t.add(a, &origins);
        }
        t
    }

    /// The vhost a canonical authority belongs to.
    pub fn vhost(&self, authority: &[u8]) -> Option<&VhostRt> {
        let (_, _, i) = self.authorities.iter().find(|(a, _, _)| a.as_slice() == authority)?;
        self.plan.vhosts.get(*i)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    fn cfg(routes: &str) -> Config {
        let doc = format!(
            r#"{{"v":1,"listeners":[{{"name":"pub","bind":"127.0.0.1:8443","profile":"P-PUBLIC-WEB"}}],
               "vhosts":[{{"host":"aegis.test","routes":{routes}}}]}}"#
        );
        aegis_config::parse_config(doc.as_bytes()).unwrap()
    }

    #[test]
    fn routes_and_targets() {
        let p = plan(&cfg(r#"[{"id":1,"path":"/api/","to":{"upstream":"127.0.0.1:9000"},"authz":"allow-all"},
                {"id":2,"path":"/x","to":{"upstream":"unix:/run/u.sock","framing":"uds"}},
                {"id":3,"path":"/","to":{"upstream":"[::1]:80","framing":"h2"},"authz":"cedar-set"}]"#))
        .unwrap();
        let v = &p.vhosts[0];
        assert_eq!(v.route(b"/api/x").unwrap().id, 1);
        assert_eq!(v.route(b"/api").unwrap().id, 3);
        assert_eq!(v.route(b"/x").unwrap().id, 2);
        assert_eq!(v.route(b"/x/").unwrap().id, 3);
        assert_eq!(v.routes[1].authz, Authz::Missing);
        assert_eq!(v.routes[2].authz, Authz::Unknown("cedar-set".into()));
        assert!(matches!(&v.routes[2].to, RouteTo::Upstream(u) if u.framing == UpFraming::H2));
        assert_eq!(p.admin, AdminBind::Tcp("127.0.0.1:9464".parse().unwrap()));
        let s = Snapshot::new(1, 1, [0; 32], p);
        assert!(s.vhost(b"aegis.test:8443").is_some() && s.vhost(b"aegis.test").is_some());
        assert!(s.vhost(b"other.test").is_none());
    }

    #[test]
    fn refusals() {
        assert!(plan(&cfg(r#"[{"id":1,"path":"/a","to":{"static":"/srv"}}]"#)).is_err());
        assert!(plan(&cfg(r#"[{"id":1,"path":"/a","to":{"upstream":"nohost"}}]"#)).is_err());
        assert!(plan(&cfg(r#"[{"id":1,"path":"/a","to":{"upstream":"h:1","framing":"uds"}}]"#)).is_err());
        assert!(plan(&cfg(r#"[{"id":1,"path":"/a//b","to":{"upstream":"h:1"}}]"#)).is_err());
        assert!(plan(&cfg(r#"[{"id":1,"path":"/a/./b","to":{"upstream":"h:1"}}]"#)).is_err());
        // App routes: only linked apps (none in the core build, PLAN D17), no framing.
        let notes = plan(&cfg(r#"[{"id":1,"path":"/n/","to":{"upstream":"app:notes"},"authz":"allow-all"}]"#));
        if cfg!(feature = "native") {
            assert_eq!(notes.unwrap().vhosts[0].routes[0].to, RouteTo::App("notes".into()));
        } else {
            assert!(notes.unwrap_err().contains("feature `native`"));
        }
        assert!(plan(&cfg(r#"[{"id":1,"path":"/n/","to":{"upstream":"app:nope"}}]"#)).is_err());
    }

    fn p2_cfg(extra: &str) -> Config {
        let doc = format!(
            r#"{{"v":1,"listeners":[{{"name":"pub","bind":"127.0.0.1:8443","profile":"P-PUBLIC-WEB"}}],
               "p2":{{"worker":"/opt/aegis-p2"{extra},"modules":[{{"id":"m","path":"/srv/m.wasm","sha256":"{}"}}]}},
               "vhosts":[{{"host":"aegis.test","routes":[{{"id":1,"path":"/m/","to":{{"wasm":"m"}},"authz":"allow-all"}}]}}]}}"#,
            "ab".repeat(32)
        );
        aegis_config::parse_config(doc.as_bytes()).unwrap()
    }

    #[test]
    fn wasm_routes() {
        let p = plan(&p2_cfg(""));
        if cfg!(feature = "p2") {
            let p = p.unwrap();
            assert_eq!(p.vhosts[0].routes[0].to, RouteTo::Wasm("m".into()));
            assert_eq!(p.vhosts[0].route(b"/m/x").unwrap().id, 1);
        } else {
            assert!(p.unwrap_err().contains("feature `p2`"));
        }
        // The worker cannot be told another frame cap: refused, never half-applied.
        assert!(plan(&p2_cfg(r#","frame_max_bytes":4096"#)).unwrap_err().contains("frame_max_bytes"));
        assert!(plan(&p2_cfg(r#","frame_max_bytes":65536"#)).is_ok() == cfg!(feature = "p2"));
        assert!(plan(&cfg(r#"[{"id":1,"path":"/n/","to":{"upstream":"app:notes","framing":"h2"}}]"#)).is_err());
    }

    fn p7(listener: &str, root: &str) -> Result<Plan, String> {
        let doc = format!(
            r#"{{"v":1,"listeners":[{{"name":"pub","bind":"127.0.0.1:8443","profile":"P-PUBLIC-WEB"{listener}}}]{root},
               "vhosts":[{{"host":"aegis.test","routes":[{{"id":1,"path":"/","to":{{"upstream":"127.0.0.1:9"}},"authz":"allow-all"}}]}}]}}"#
        );
        plan(&aegis_config::parse_config(doc.as_bytes()).unwrap())
    }

    /// A Phase-7 member whose feature is not built fails the boot (exit 78); with the feature it is planned.
    #[test]
    fn phase7_members_need_their_feature() {
        let cases: [(&str, &str, bool, &str); 6] = [
            (r#","proxy_protocol":{"trusted":["10.0.0.0/8"]}"#, "", cfg!(feature = "proxy-protocol"), "proxy-protocol"),
            (r#","l4":[{"sni":"a.test","upstream":"127.0.0.1:9"}]"#, "", cfg!(feature = "l4"), "`l4`"),
            (r#","front":"uring""#, "", cfg!(feature = "uring"), "`uring`"),
            (
                "",
                r#","tls":{"credentials":[{"id":"c","kind":"x509","chain":"path:/c.pem","key":"path:/k.pem"}]}"#,
                cfg!(all(feature = "mtc", not(feature = "cmvp"))),
                "`mtc`",
            ),
            (
                "",
                r#","data":{"backends":[{"id":"cr","engine":"crdb","dsn_ref":"env:X","pin":"crdb"}]}"#,
                cfg!(feature = "adapter-crdb"),
                "adapter-crdb",
            ),
            (
                "",
                r#","data":{"backends":[{"id":"my","engine":"mariadb","dsn_ref":"env:X","pin":"mariadb"}]}"#,
                cfg!(feature = "adapter-mariadb"),
                "adapter-mariadb",
            ),
        ];
        for (l, r, built, name) in cases {
            match p7(l, r) {
                Ok(_) => assert!(built, "{name}: planned without the feature"),
                Err(e) => assert!(!built && e.contains(name) && e.contains("fail closed"), "{name}: {e}"),
            }
        }
        let p = p7("", "").unwrap();
        assert_eq!(p.admission, aegis_config::Admission::default());
        assert_eq!(p.listeners[0].front, aegis_config::Front::Epoll);
    }

    #[test]
    fn wasm_route_data_needs_the_native_data_plane() {
        let doc = format!(
            r#"{{"v":1,"listeners":[{{"name":"pub","bind":"127.0.0.1:8443","profile":"P-PUBLIC-WEB"}}],
               "data":{{"backends":[{{"id":"sq","engine":"sqlite","dsn_ref":"path:/srv/notes.db","pin":"sqlite"}}]}},
               "p2":{{"worker":"/opt/aegis-p2","modules":[{{"id":"m","path":"/srv/m.wasm","sha256":"{}"}}]}},
               "vhosts":[{{"host":"aegis.test","routes":[{{"id":1,"path":"/m/","to":{{"wasm":"m"}},"authz":"allow-all",
               "data":[{{"backend":"sq","collection":"notes","ops":["select"],"columns":["id","body"]}}]}}]}}]}}"#,
            "ab".repeat(32)
        );
        let p = plan(&aegis_config::parse_config(doc.as_bytes()).unwrap());
        match (cfg!(feature = "p2"), cfg!(feature = "native")) {
            (true, true) => assert_eq!(p.unwrap().vhosts[0].routes[0].to, RouteTo::Wasm("m".into())),
            (true, false) => assert!(p.unwrap_err().contains("feature `native`")),
            (false, _) => assert!(p.unwrap_err().contains("feature `p2`")),
        }
    }
}
