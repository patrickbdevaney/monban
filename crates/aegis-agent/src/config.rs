//! Agent listener configuration (`aegis agent --config FILE`), parsed by the one JSON owner. F8 has no agent
//! section yet, so this is a separate, versioned document; every field is required unless stated, unknown fields
//! are refused, and every refusal stops the boot (fail closed).
//!
//! ```json
//! {"v": 1,
//!  "listen": "127.0.0.1:8443",
//!  "hosts": ["127.0.0.1:8443", "localhost:8443"],
//!  "origins": ["http://127.0.0.1:8443", "http://localhost:8443"],
//!  "auth": {"issuer": "https://issuer.example", "hs256_secret_file": "/run/credentials/aegis/jwt.key"},
//!  "pdp": {"socket": "/run/aegis/pdp.sock", "deadline_ms": 250},
//!  "upstream_credential_file": "/run/credentials/aegis/upstream.key",      (optional)
//!  "egress_readmit": ["127.0.0.1/32"],                                     (optional)
//!  "sessions": {"max": 10000, "per_principal": 256, "idle_ttl_s": 1800},  (optional)
//!  "routes": [{"path": "/mcp", "resource": "http://127.0.0.1:8443/mcp",
//!              "upstreams": [{"prefix": "", "url": "http://127.0.0.1:9000/"}]}]}
//! ```
//! `resource` is the RFC 8707 audience a token must carry for the route. A route with several upstreams multiplexes
//! them: each needs a distinct non-empty prefix (tool names are namespaced `prefix + name`).

use std::string::{String, ToString};
use std::vec::Vec;

use aegis_canon::{JsonValue, canon_authority, canon_origin, canon_path, parse_json};

/// One upstream of a route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamCfg {
    /// Tool-name namespace prefix ("" on a single-upstream route).
    pub prefix: String,
    /// Absolute upstream URL (validated again by the assembly with the egress URL parser).
    pub url: String,
}

/// One MCP route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteCfg {
    pub path: String,
    pub resource: String,
    pub upstreams: Vec<UpstreamCfg>,
}

/// Session table bounds (2025-11-25 era).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionCfg {
    pub max: usize,
    pub per_principal: usize,
    pub idle_ttl_s: u64,
}

impl Default for SessionCfg {
    fn default() -> Self {
        Self { max: 10_000, per_principal: 256, idle_ttl_s: 1800 }
    }
}

/// The whole agent configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentConfig {
    pub listen: String,
    /// Canonical authorities (`host:port`, lowercase).
    pub hosts: Vec<String>,
    /// Canonical serialized origins.
    pub origins: Vec<String>,
    pub issuer: String,
    pub hs256_secret_file: String,
    pub pdp_socket: String,
    pub pdp_deadline_ms: u64,
    pub upstream_credential_file: Option<String>,
    pub egress_readmit: Vec<String>,
    pub sessions: SessionCfg,
    pub routes: Vec<RouteCfg>,
}

fn obj<'a>(v: &'a JsonValue, what: &str, allowed: &[&str]) -> Result<&'a [(String, JsonValue)], String> {
    let JsonValue::Object(m) = v else { return Err(format!("{what}: expected an object")) };
    if let Some((k, _)) = m.iter().find(|(k, _)| !allowed.contains(&k.as_str())) {
        return Err(format!("{what}: unknown field {k:?}"));
    }
    Ok(m)
}

fn field<'a>(m: &'a [(String, JsonValue)], name: &str) -> Option<&'a JsonValue> {
    m.iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

fn req<'a>(m: &'a [(String, JsonValue)], what: &str, name: &str) -> Result<&'a JsonValue, String> {
    field(m, name).ok_or_else(|| format!("{what}: missing {name:?}"))
}

fn string(v: &JsonValue, what: &str) -> Result<String, String> {
    match v {
        JsonValue::String(s) if !s.is_empty() && !s.chars().any(char::is_control) => Ok(s.clone()),
        _ => Err(format!("{what}: expected a non-empty string")),
    }
}

fn strings(v: &JsonValue, what: &str) -> Result<Vec<String>, String> {
    let JsonValue::Array(a) = v else { return Err(format!("{what}: expected an array")) };
    a.iter().map(|x| string(x, what)).collect()
}

fn uint(v: &JsonValue, what: &str, lo: u64, hi: u64) -> Result<u64, String> {
    match v {
        JsonValue::Int(i) if *i >= 0 && (lo..=hi).contains(&i.unsigned_abs()) => Ok(i.unsigned_abs()),
        _ => Err(format!("{what}: expected an integer in {lo}..={hi}")),
    }
}

fn prefix_ok(p: &str) -> bool {
    p.len() <= 32 && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

impl AgentConfig {
    /// Parse and validate. Every error is a boot refusal.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let v = parse_json(bytes).map_err(|e| format!("agent config: {e}"))?;
        let top = obj(
            &v,
            "agent config",
            &[
                "v",
                "listen",
                "hosts",
                "origins",
                "auth",
                "pdp",
                "upstream_credential_file",
                "egress_readmit",
                "sessions",
                "routes",
            ],
        )?;
        if uint(req(top, "agent config", "v")?, "v", 1, 1)? != 1 {
            return Err("agent config: unsupported version".into());
        }
        let listen = string(req(top, "agent config", "listen")?, "listen")?;
        let mut hosts = Vec::new();
        for h in strings(req(top, "agent config", "hosts")?, "hosts")? {
            let c = canon_authority(h.as_bytes(), aegis_canon::Scheme::Http).map_err(|e| format!("hosts: {h}: {e}"))?;
            let c = String::from_utf8(c.as_bytes().to_vec()).map_err(|_| "hosts: not UTF-8".to_string())?;
            if c != h {
                return Err(format!("hosts: {h:?} is not canonical (want {c:?})"));
            }
            hosts.push(c);
        }
        if hosts.is_empty() {
            return Err("hosts: at least one allowed authority is required".into());
        }
        let mut origins = Vec::new();
        for o in strings(req(top, "agent config", "origins")?, "origins")? {
            let c = canon_origin(o.as_bytes()).map_err(|e| format!("origins: {o}: {e}"))?;
            let c = String::from_utf8(c.as_bytes().to_vec()).map_err(|_| "origins: not UTF-8".to_string())?;
            if c != o {
                return Err(format!("origins: {o:?} is not canonical (want {c:?})"));
            }
            origins.push(c);
        }
        let auth = obj(req(top, "agent config", "auth")?, "auth", &["issuer", "hs256_secret_file"])?;
        let issuer = string(req(auth, "auth", "issuer")?, "auth.issuer")?;
        let hs256_secret_file = string(req(auth, "auth", "hs256_secret_file")?, "auth.hs256_secret_file")?;
        let pdp = obj(req(top, "agent config", "pdp")?, "pdp", &["socket", "deadline_ms"])?;
        let pdp_socket = string(req(pdp, "pdp", "socket")?, "pdp.socket")?;
        let pdp_deadline_ms = uint(req(pdp, "pdp", "deadline_ms")?, "pdp.deadline_ms", 1, 10_000)?;
        let upstream_credential_file =
            field(top, "upstream_credential_file").map(|v| string(v, "upstream_credential_file")).transpose()?;
        let egress_readmit =
            field(top, "egress_readmit").map(|v| strings(v, "egress_readmit")).transpose()?.unwrap_or_default();
        let sessions = match field(top, "sessions") {
            None => SessionCfg::default(),
            Some(s) => {
                let s = obj(s, "sessions", &["max", "per_principal", "idle_ttl_s"])?;
                SessionCfg {
                    max: usize::try_from(uint(req(s, "sessions", "max")?, "sessions.max", 1, 1_000_000)?)
                        .map_err(|_| "sessions.max".to_string())?,
                    per_principal: usize::try_from(uint(
                        req(s, "sessions", "per_principal")?,
                        "sessions.per_principal",
                        1,
                        100_000,
                    )?)
                    .map_err(|_| "sessions.per_principal".to_string())?,
                    idle_ttl_s: uint(req(s, "sessions", "idle_ttl_s")?, "sessions.idle_ttl_s", 1, 86_400)?,
                }
            }
        };
        let JsonValue::Array(rs) = req(top, "agent config", "routes")? else {
            return Err("routes: expected an array".into());
        };
        let mut routes: Vec<RouteCfg> = Vec::new();
        for r in rs {
            let m = obj(r, "route", &["path", "resource", "upstreams"])?;
            let path = string(req(m, "route", "path")?, "route.path")?;
            // A route path must itself be canonical, or no request could ever match it.
            let cp = canon_path(path.as_bytes()).map_err(|e| format!("route {path}: {e}"))?;
            if cp.as_bytes() != path.as_bytes() || path.starts_with("/.well-known/") {
                return Err(format!("route {path}: path is not canonical or is reserved"));
            }
            let resource = string(req(m, "route", "resource")?, "route.resource")?;
            if !(resource.starts_with("https://") || resource.starts_with("http://"))
                || !resource.ends_with(path.as_str())
                || resource.contains(['?', '#', ' '])
            {
                return Err(format!("route {path}: resource must be an absolute http(s) URL ending in the path"));
            }
            let JsonValue::Array(us) = req(m, "route", "upstreams")? else {
                return Err(format!("route {path}: upstreams must be an array"));
            };
            let mut upstreams = Vec::new();
            for u in us {
                let um = obj(u, "upstream", &["prefix", "url"])?;
                let prefix = match req(um, "upstream", "prefix")? {
                    JsonValue::String(s) if prefix_ok(s) => s.clone(),
                    _ => return Err(format!("route {path}: bad upstream prefix")),
                };
                let url = string(req(um, "upstream", "url")?, "upstream.url")?;
                upstreams.push(UpstreamCfg { prefix, url });
            }
            match upstreams.as_slice() {
                [] => return Err(format!("route {path}: no upstream")),
                [one] if !one.prefix.is_empty() => {
                    return Err(format!("route {path}: a single upstream takes the empty prefix"));
                }
                [_] => {}
                many => {
                    for (i, a) in many.iter().enumerate() {
                        if a.prefix.is_empty() {
                            return Err(format!("route {path}: multiplexed upstreams need non-empty prefixes"));
                        }
                        for b in many.iter().skip(i.saturating_add(1)) {
                            let (x, y) = (a.prefix.to_ascii_lowercase(), b.prefix.to_ascii_lowercase());
                            if x.starts_with(&y) || y.starts_with(&x) {
                                return Err(format!("route {path}: prefixes overlap under case folding"));
                            }
                        }
                    }
                }
            }
            if routes.iter().any(|o| o.path == path) {
                return Err(format!("route {path}: duplicate path"));
            }
            if routes.iter().any(|o| o.resource == resource) {
                return Err(format!("route {path}: duplicate resource (audiences must be distinct)"));
            }
            routes.push(RouteCfg { path, resource, upstreams });
        }
        if routes.is_empty() {
            return Err("routes: at least one route is required (no implicit serve-everything mode)".into());
        }
        Ok(Self {
            listen,
            hosts,
            origins,
            issuer,
            hs256_secret_file,
            pdp_socket,
            pdp_deadline_ms,
            upstream_credential_file,
            egress_readmit,
            sessions,
            routes,
        })
    }
}
