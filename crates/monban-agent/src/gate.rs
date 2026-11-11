//! The MCP listener gate (ARCHITECTURE §3.9, R-AGENT-4/7). Sans-I/O: [`Gate::check`] turns one canonical HTTP
//! request into either a reply (every reject, and local answers such as OPTIONS or the RFC 9728 metadata document)
//! or a [`Forward`] plan; the assembly performs the plan's upstream calls through monban-egress and hands the
//! results to [`Gate::complete`]. A reject is produced before any upstream call exists, so it can never reach a
//! handler (INV-FAILCLOSED; the mcp-corpus counts upstream requests).
//!
//! Order of checks for a POST (each failure answers immediately):
//! 1. route (404); Host/`:authority` allowlist (421); Origin allowlist (403) or, with no Origin, the ambient-
//!    credential rule (`Sec-Fetch-Site: cross-site`, or a Cookie without a bearer: 403);
//! 2. `Content-Type` is `application/json` (415) (CORS-safelisted `text/plain` can never reach the parser);
//! 3. bearer JWT (401 with an RFC 9728 `resource_metadata` challenge), audience = the route's resource (RFC 8707);
//! 4. one strict parse by the JSON owner (400 / -32700; 413 above the owner's cap), exact JSON-RPC 2.0 request
//!    shape (400 / -32600: unknown or case-variant members, batches, responses);
//! 5. protocol version: an unsupported `MCP-Protocol-Version` or `_meta` version is 400 / -32022 listing the
//!    supported versions; header and `_meta` disagreeing is 400 / -32020;
//! 6. era rules. 2026-07-28: `Mcp-Method` must equal `method`, `Mcp-Name` must equal `params.name` for named
//!    methods, `_meta` must carry the version (400 / -32020); session machinery (initialize, ping, session ids) is
//!    gone (404 / -32601). 2025-11-25: initialize mints a session bound to (subject, route); every other call needs
//!    a live session with exactly that binding (400 when absent, 404 when unknown or bound elsewhere);
//! 7. method allowlist per era (404 / -32601), `tools/call` needs a string `name` (400 / -32602);
//! 8. the Cedar PDP (403), fail closed (F6).
//!
//! What is forwarded is the owner's canonical serialization of what was checked (CANON-4), with the gate's own
//! upstream credential: the client's Authorization, Cookie and API-key fields are never forwarded. Upstream
//! redirects are not followed (the egress policy allows none). Replies are parsed by the owner and must be a JSON-RPC
//! response to the same id. Multiplexed routes namespace tool names by prefix and refuse case-fold collisions.

use std::string::{String, ToString};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::vec::Vec;

use monban_canon::{JsonValue, canon_json, canon_media_type, canon_origin, parse_json};

use crate::authz::{Authorizer, allowed, pdp_request};
use crate::b64;
use crate::config::{AgentConfig, RouteCfg};
use crate::emit::{self, get, get_str};
use crate::jwt::{AuthError, JwtProfile, Subject};
use crate::session::{SessionError, SessionTable};

/// The 2025-11-25 era (sessions, initialize).
pub const V_LEGACY: &str = "2025-11-25";
/// The 2026-07-28 era (stateless, header/body consistency).
pub const V_MODERN: &str = "2026-07-28";
/// Every protocol version this gate serves.
pub const SUPPORTED: [&str; 2] = [V_LEGACY, V_MODERN];
/// `_meta` key carrying the protocol version (2026-07-28).
pub const META_PV: &str = "io.modelcontextprotocol/protocolVersion";
/// RFC 9728 well-known prefix.
pub const PRM_PREFIX: &str = "/.well-known/oauth-protected-resource";

/// JSON-RPC: parse error.
pub const PARSE_ERROR: i64 = -32700;
/// JSON-RPC: invalid request.
pub const INVALID_REQUEST: i64 = -32600;
/// JSON-RPC: method not found.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// JSON-RPC: invalid params.
pub const INVALID_PARAMS: i64 = -32602;
/// JSON-RPC: internal error (upstream failures).
pub const INTERNAL_ERROR: i64 = -32603;
/// MCP 2026-07-28: header/body mismatch.
pub const HEADER_MISMATCH: i64 = -32020;
/// MCP 2026-07-28: unsupported protocol version.
pub const UNSUPPORTED_VERSION: i64 = -32022;
/// Policy refusal (server-defined range).
pub const FORBIDDEN: i64 = -32001;

const LEGACY_METHODS: &[&str] = &[
    "initialize",
    "notifications/initialized",
    "ping",
    "tools/list",
    "tools/call",
    "resources/list",
    "prompts/list",
    "notifications/cancelled",
];
const MODERN_METHODS: &[&str] =
    &["tools/list", "tools/call", "resources/list", "prompts/list", "notifications/cancelled"];
/// Methods whose `params.name` must agree with `Mcp-Name` (2026-07-28).
const NAMED: &[&str] = &["tools/call"];

/// Request method as the gate distinguishes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Options,
    Other,
}

/// One canonical HTTP request (from the transport: canonical authority and path, CANON-1/2 checked header set with
/// lowercase names, the size-checked body).
#[derive(Debug)]
pub struct HttpRequest<'a> {
    pub method: Method,
    pub authority: &'a [u8],
    pub path: &'a [u8],
    pub headers: &'a [(&'a [u8], &'a [u8])],
    pub body: &'a [u8],
}

/// A reply. A non-empty body is `application/json`. Header names are lowercase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    fn empty(status: u16, headers: Vec<(String, String)>) -> Self {
        Self { status, headers, body: Vec::new() }
    }
}

/// What a path maps to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// The MCP endpoint of route `i`.
    Mcp(usize),
    /// The RFC 9728 protected-resource metadata of route `i`.
    Metadata(usize),
}

/// One upstream request the assembly must perform (POST, through monban-egress).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamCall {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// An upstream reply (`Err(())` from the assembly: the fetch failed, was refused by egress, or redirected).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamReply {
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Debug)]
enum Plan {
    /// One upstream; `initialize` mints a session on success.
    Single { initialize: bool },
    /// Multiplexed tools/list: merge with namespaced names (call i ↔ upstream i).
    MergeList { prefixes: Vec<String> },
}

/// An accepted request: the upstream calls to make, and what to do with their replies.
#[derive(Debug)]
pub struct Forward {
    route: usize,
    sub: Subject,
    rid: Option<JsonValue>,
    plan: Plan,
    extra: Vec<(String, String)>,
    calls: Vec<UpstreamCall>,
}

impl Forward {
    pub fn calls(&self) -> &[UpstreamCall] {
        &self.calls
    }
}

/// Result of [`Gate::check`].
#[derive(Debug)]
pub enum Verdict {
    Reply(Response),
    Forward(Box<Forward>),
}

#[derive(Debug)]
struct RejBody {
    status: u16,
    code: Option<i64>,
    msg: &'static str,
    data: Option<JsonValue>,
    headers: Vec<(String, String)>,
    id: Option<JsonValue>,
}

/// A reject (boxed: it travels through every `?` of the hot path).
#[derive(Debug)]
struct Rej(Box<RejBody>);

impl core::ops::Deref for Rej {
    type Target = RejBody;
    fn deref(&self) -> &RejBody {
        &self.0
    }
}

impl core::ops::DerefMut for Rej {
    fn deref_mut(&mut self) -> &mut RejBody {
        &mut self.0
    }
}

fn rej(status: u16) -> Rej {
    Rej(Box::new(RejBody { status, code: None, msg: "", data: None, headers: Vec::new(), id: None }))
}

fn rpc(status: u16, code: i64, msg: &'static str) -> Rej {
    Rej(Box::new(RejBody { status, code: Some(code), msg, data: None, headers: Vec::new(), id: None }))
}

impl Rej {
    fn id(mut self, id: &Option<JsonValue>) -> Self {
        self.0.id = id.clone();
        self
    }

    fn into_response(self, cors: &[(String, String)]) -> Response {
        let b = *self.0;
        let mut headers = b.headers;
        headers.extend(cors.iter().cloned());
        let body = match b.code {
            Some(code) => error_body(b.id.as_ref(), code, b.msg, b.data.as_ref()),
            None => Vec::new(),
        };
        Response { status: b.status, headers, body }
    }
}

fn error_body(id: Option<&JsonValue>, code: i64, msg: &str, data: Option<&JsonValue>) -> Vec<u8> {
    let mut err =
        Vec::from([("code".to_string(), JsonValue::Int(code)), ("message".into(), JsonValue::String(msg.into()))]);
    if let Some(d) = data {
        err.push(("data".into(), d.clone()));
    }
    let v = JsonValue::Object(Vec::from([
        ("jsonrpc".to_string(), JsonValue::String("2.0".into())),
        ("id".into(), id.cloned().unwrap_or(JsonValue::Null)),
        ("error".into(), JsonValue::Object(err)),
    ]));
    let mut s = String::new();
    emit::value(&v, &mut s);
    s.into_bytes()
}

fn hdr<'a>(h: &[(&'a [u8], &'a [u8])], name: &[u8]) -> Option<&'a [u8]> {
    h.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

fn hdr_str<'a>(h: &[(&'a [u8], &'a [u8])], name: &[u8]) -> Option<&'a str> {
    hdr(h, name).and_then(|v| core::str::from_utf8(v).ok())
}

/// A header value that may use the MCP base64 sentinel (`=?base64?<std base64>?=`, used for values with
/// characters a field cannot carry). `None` if the sentinel does not decode to UTF-8.
fn header_text(v: &[u8]) -> Option<String> {
    if let Some(inner) = v.strip_prefix(b"=?base64?").and_then(|r| r.strip_suffix(b"?=")) {
        return String::from_utf8(b64::decode_std(inner)?).ok();
    }
    String::from_utf8(v.to_vec()).ok()
}

/// A header value for an upstream request: visible ASCII as is, anything else in the base64 sentinel.
fn header_out(s: &str) -> String {
    if !s.is_empty() && s.bytes().all(|b| (0x21..0x7f).contains(&b)) && !s.starts_with("=?") {
        s.to_string()
    } else {
        format!("=?base64?{}?=", b64::encode_std(s.as_bytes()))
    }
}

#[derive(Debug)]
struct Route {
    cfg: RouteCfg,
    prm_path: String,
    prm_url: String,
}

/// Counters (monotonic).
#[derive(Debug, Default)]
pub struct GateStats {
    pub rejected: AtomicU64,
    pub forwarded: AtomicU64,
    pub upstream_failed: AtomicU64,
}

/// The listener gate.
pub struct Gate {
    routes: Vec<Route>,
    hosts: Vec<String>,
    origins: Vec<String>,
    jwt: JwtProfile,
    sessions: Mutex<SessionTable>,
    authz: Box<dyn Authorizer>,
    upstream_credential: Option<String>,
    stats: GateStats,
}

impl core::fmt::Debug for Gate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Gate").field("routes", &self.routes).field("hosts", &self.hosts).finish_non_exhaustive()
    }
}

fn is_era(v: &str) -> bool {
    SUPPORTED.contains(&v)
}

fn supported_data() -> JsonValue {
    JsonValue::Object(Vec::from([(
        "supported".to_string(),
        JsonValue::Array(SUPPORTED.iter().map(|v| JsonValue::String((*v).into())).collect()),
    )]))
}

impl Gate {
    /// Build the gate. `secret` is the HS256 key; `upstream_credential` the `Authorization` value the gate sends
    /// upstream (its own, never the client's).
    pub fn new(
        cfg: &AgentConfig,
        secret: &[u8],
        upstream_credential: Option<String>,
        authz: Box<dyn Authorizer>,
    ) -> Result<Self, String> {
        let jwt = JwtProfile::new(secret, &cfg.issuer)?;
        if let Some(c) = &upstream_credential
            && (c.is_empty() || !c.bytes().all(|b| (0x20..0x7f).contains(&b)))
        {
            return Err("upstream credential must be a non-empty visible-ASCII field value".into());
        }
        let routes = cfg
            .routes
            .iter()
            .map(|r| {
                let origin = r.resource.strip_suffix(r.path.as_str()).unwrap_or(&r.resource).to_string();
                let prm_path = format!("{PRM_PREFIX}{}", r.path);
                Route { cfg: r.clone(), prm_url: format!("{origin}{prm_path}"), prm_path }
            })
            .collect();
        Ok(Self {
            routes,
            hosts: cfg.hosts.clone(),
            origins: cfg.origins.clone(),
            jwt,
            sessions: Mutex::new(SessionTable::new(cfg.sessions)),
            authz,
            upstream_credential,
            stats: GateStats::default(),
        })
    }

    pub fn stats(&self) -> &GateStats {
        &self.stats
    }

    /// Allowed canonical authorities (for the transport's vhost table).
    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    /// Allowed canonical origins (for the transport's vhost table).
    pub fn origins(&self) -> &[String] {
        &self.origins
    }

    /// Map a canonical path to a target.
    pub fn target(&self, path: &[u8]) -> Option<Target> {
        self.routes.iter().enumerate().find_map(|(i, r)| {
            if r.cfg.path.as_bytes() == path {
                Some(Target::Mcp(i))
            } else if r.prm_path.as_bytes() == path {
                Some(Target::Metadata(i))
            } else {
                None
            }
        })
    }

    /// Decide one request. `now`: unix seconds.
    pub fn check(&self, r: &HttpRequest<'_>, now: u64) -> Verdict {
        let mut cors = Vec::new();
        match self.check_inner(r, now, &mut cors) {
            Ok(v) => v,
            Err(e) => {
                self.stats.rejected.fetch_add(1, Ordering::Relaxed);
                Verdict::Reply(e.into_response(&cors))
            }
        }
    }

    fn challenge(&self, route: &Route, presented: bool) -> Rej {
        let mut v = format!("Bearer resource_metadata=\"{}\"", route.prm_url);
        if presented {
            v.push_str(", error=\"invalid_token\"");
        }
        let mut e = rpc(401, INVALID_REQUEST, "unauthorized");
        e.headers.push(("www-authenticate".into(), v));
        e
    }

    fn authenticate(&self, route: &Route, h: &[(&[u8], &[u8])], now: u64) -> Result<Subject, Rej> {
        let a = hdr(h, b"authorization");
        self.jwt.verify(a, &route.cfg.resource, now).map_err(|e| self.challenge(route, e != AuthError::Missing))
    }

    fn sessions(&self) -> Result<std::sync::MutexGuard<'_, SessionTable>, Rej> {
        self.sessions.lock().map_err(|_| rpc(503, INTERNAL_ERROR, "session table unavailable"))
    }

    fn check_inner(&self, r: &HttpRequest<'_>, now: u64, cors: &mut Vec<(String, String)>) -> Result<Verdict, Rej> {
        let h = r.headers;
        let Some(target) = self.target(r.path) else { return Err(rej(404)) };
        // CANON-6 analogue on the listener: the transport already bound Host and Origin to the vhost; the gate
        // re-checks against its own allowlists (defence in depth; both answer 403 for a bad Origin, as MCP mandates).
        if !self.hosts.iter().any(|a| a.as_bytes() == r.authority) {
            return Err(rej(421));
        }
        match hdr(h, b"origin") {
            Some(o) => {
                let Ok(c) = canon_origin(o) else { return Err(rej(403)) };
                let Some(ok) = self.origins.iter().find(|x| x.as_bytes() == c.as_bytes()) else {
                    return Err(rej(403));
                };
                cors.push(("access-control-allow-origin".into(), ok.clone()));
                cors.push(("vary".into(), "origin".into()));
            }
            None => {
                if hdr(h, b"sec-fetch-site").is_some_and(|v| v.eq_ignore_ascii_case(b"cross-site")) {
                    return Err(rej(403));
                }
                if hdr(h, b"cookie").is_some() && hdr(h, b"authorization").is_none() {
                    return Err(rej(403));
                }
            }
        }
        let (ri, route) = match target {
            Target::Metadata(i) => {
                let route = self.routes.get(i).ok_or_else(|| rej(404))?;
                return match r.method {
                    Method::Get | Method::Head => Ok(Verdict::Reply(self.metadata(route, cors))),
                    _ => {
                        let mut e = rej(405);
                        e.headers.push(("allow".into(), "GET".into()));
                        Err(e)
                    }
                };
            }
            Target::Mcp(i) => (i, self.routes.get(i).ok_or_else(|| rej(404))?),
        };
        match r.method {
            Method::Post => {}
            Method::Options => {
                let mut hs = cors.clone();
                if !cors.is_empty() {
                    hs.push(("access-control-allow-methods".into(), "POST, DELETE".into()));
                    hs.push((
                        "access-control-allow-headers".into(),
                        "content-type, authorization, mcp-protocol-version, mcp-method, mcp-name, mcp-session-id"
                            .into(),
                    ));
                    hs.push(("access-control-expose-headers".into(), "mcp-session-id, www-authenticate".into()));
                }
                return Ok(Verdict::Reply(Response::empty(204, hs)));
            }
            Method::Delete => {
                let sub = self.authenticate(route, h, now)?;
                let sid = hdr_str(h, b"mcp-session-id").ok_or_else(|| rej(404))?;
                if self.sessions()?.delete(sid, sub.as_str(), ri, now) {
                    return Ok(Verdict::Reply(Response::empty(204, cors.clone())));
                }
                return Err(rej(404));
            }
            Method::Get | Method::Head | Method::Put | Method::Patch | Method::Other => {
                // No standalone server-to-client stream (removed in 2026-07-28; optional in 2025-11-25).
                let mut e = rej(405);
                e.headers.push(("allow".into(), "POST, DELETE".into()));
                return Err(e);
            }
        }
        // ---- POST
        let ct = hdr(h, b"content-type").ok_or_else(|| rej(415))?;
        let ct = canon_media_type(ct).map_err(|_| rej(415))?;
        if !matches!(ct.as_bytes(), b"application/json" | b"application/json; charset=utf-8") {
            return Err(rej(415));
        }
        let sub = self.authenticate(route, h, now)?;
        if r.body.is_empty() {
            return Err(rpc(400, PARSE_ERROR, "parse error"));
        }
        let msg = parse_json(r.body).map_err(|e| {
            if e.status() == 413 {
                rpc(413, PARSE_ERROR, "body too large")
            } else {
                rpc(400, PARSE_ERROR, "parse error")
            }
        })?;
        // Exact JSON-RPC 2.0 request shape.
        let JsonValue::Object(members) = &msg else { return Err(rpc(400, INVALID_REQUEST, "invalid request")) };
        if members.iter().any(|(k, _)| !matches!(k.as_str(), "jsonrpc" | "id" | "method" | "params")) {
            return Err(rpc(400, INVALID_REQUEST, "invalid request"));
        }
        let rid = match get(&msg, "id") {
            None => None,
            Some(v @ (JsonValue::Int(_) | JsonValue::String(_))) => Some(v.clone()),
            Some(_) => return Err(rpc(400, INVALID_REQUEST, "invalid request")),
        };
        if get_str(&msg, "jsonrpc") != Some("2.0") {
            return Err(rpc(400, INVALID_REQUEST, "invalid request").id(&rid));
        }
        let Some(meth) = get_str(&msg, "method") else {
            return Err(rpc(400, INVALID_REQUEST, "invalid request").id(&rid));
        };
        let empty = JsonValue::Object(Vec::new());
        let params = match get(&msg, "params") {
            None => &empty,
            Some(p @ JsonValue::Object(_)) => p,
            Some(_) => return Err(rpc(400, INVALID_REQUEST, "invalid request").id(&rid)),
        };
        let notification = rid.is_none();
        if notification != meth.starts_with("notifications/") {
            return Err(rpc(400, INVALID_REQUEST, "invalid request").id(&rid));
        }
        let body_pv = match get(params, "_meta") {
            None => None,
            Some(m @ JsonValue::Object(_)) => match get(m, META_PV) {
                None => None,
                Some(JsonValue::String(v)) => Some(v.as_str()),
                Some(_) => return Err(rpc(400, INVALID_REQUEST, "invalid _meta").id(&rid)),
            },
            Some(_) => return Err(rpc(400, INVALID_REQUEST, "invalid _meta").id(&rid)),
        };
        let pv_hdr = match hdr(h, b"mcp-protocol-version") {
            None => None,
            Some(v) => Some(core::str::from_utf8(v).map_err(|_| rpc(400, INVALID_REQUEST, "bad header"))?),
        };
        for v in [pv_hdr, body_pv].into_iter().flatten() {
            if !is_era(v) {
                let mut e = rpc(400, UNSUPPORTED_VERSION, "unsupported protocol version").id(&rid);
                e.data = Some(supported_data());
                return Err(e);
            }
        }
        if body_pv.is_some() && pv_hdr != body_pv {
            return Err(rpc(400, HEADER_MISMATCH, "header mismatch: MCP-Protocol-Version").id(&rid));
        }
        let modern = match pv_hdr {
            Some(V_MODERN) => true,
            Some(_) => false,
            // 2025-11-25: the header is required on every request after initialize.
            None if meth == "initialize" => false,
            None => return Err(rpc(400, INVALID_REQUEST, "missing MCP-Protocol-Version").id(&rid)),
        };
        let name = get(params, "name");
        let mcp_method = hdr(h, b"mcp-method").map(|v| header_text(v).ok_or_else(|| rej(400))).transpose()?;
        let mcp_name = hdr(h, b"mcp-name").map(|v| header_text(v).ok_or_else(|| rej(400))).transpose()?;
        let name_matches = |hv: &Option<String>| matches!((hv, name), (Some(a), Some(JsonValue::String(b))) if a == b);
        let mut session_needed = false;
        let mut initialize = false;
        if modern {
            if mcp_method.as_deref() != Some(meth) {
                return Err(rpc(400, HEADER_MISMATCH, "header mismatch: Mcp-Method").id(&rid));
            }
            if NAMED.contains(&meth) && !name_matches(&mcp_name) {
                return Err(rpc(400, HEADER_MISMATCH, "header mismatch: Mcp-Name").id(&rid));
            }
            if body_pv.is_none() {
                return Err(rpc(400, HEADER_MISMATCH, "header mismatch: _meta protocolVersion missing").id(&rid));
            }
            if !MODERN_METHODS.contains(&meth) {
                return Err(rpc(404, METHOD_NOT_FOUND, "method not found").id(&rid));
            }
            if hdr(h, b"mcp-session-id").is_some() {
                return Err(rpc(400, INVALID_REQUEST, "no sessions in 2026-07-28").id(&rid));
            }
        } else {
            // Optional in this era, but if a client sends them they must agree with the body.
            if mcp_method.as_ref().is_some_and(|m| m != meth) {
                return Err(rpc(400, HEADER_MISMATCH, "header mismatch: Mcp-Method").id(&rid));
            }
            if mcp_name.is_some() && !name_matches(&mcp_name) {
                return Err(rpc(400, HEADER_MISMATCH, "header mismatch: Mcp-Name").id(&rid));
            }
            if !LEGACY_METHODS.contains(&meth) {
                return Err(rpc(404, METHOD_NOT_FOUND, "method not found").id(&rid));
            }
            if meth == "initialize" {
                if hdr(h, b"mcp-session-id").is_some() {
                    return Err(rpc(400, INVALID_REQUEST, "initialize inside a session").id(&rid));
                }
                if !matches!(get_str(params, "protocolVersion"), Some(V_LEGACY)) {
                    let mut e = rpc(400, UNSUPPORTED_VERSION, "unsupported protocol version").id(&rid);
                    e.data = Some(supported_data());
                    return Err(e);
                }
                initialize = true;
            } else {
                session_needed = true;
            }
        }
        if meth == "tools/call" && !matches!(name, Some(JsonValue::String(_))) {
            return Err(rpc(400, INVALID_PARAMS, "invalid params").id(&rid));
        }
        if session_needed {
            let sid =
                hdr_str(h, b"mcp-session-id").ok_or_else(|| rpc(400, INVALID_REQUEST, "missing session").id(&rid))?;
            if !self.sessions()?.check(sid, sub.as_str(), ri, now) {
                return Err(rpc(404, INVALID_REQUEST, "unknown session").id(&rid));
            }
        }
        if initialize && !self.sessions()?.has_room(sub.as_str(), now) {
            return Err(rpc(503, INTERNAL_ERROR, "session table full").id(&rid));
        }
        let era = if modern { V_MODERN } else { V_LEGACY };
        let tool = match name {
            Some(JsonValue::String(s)) if meth == "tools/call" => s.as_str(),
            _ => "",
        };
        if !allowed(self.authz.as_ref(), &pdp_request(sub.as_str(), &route.cfg.path, era, meth, tool)) {
            return Err(rpc(403, FORBIDDEN, "forbidden by policy").id(&rid));
        }
        // ---- forward plan
        let ups = &route.cfg.upstreams;
        let base_headers = |name_out: Option<&str>| {
            let mut hs = Vec::from([
                ("content-type".to_string(), "application/json".to_string()),
                ("accept".into(), "application/json".into()),
                ("mcp-protocol-version".into(), era.into()),
            ]);
            if modern {
                hs.push(("mcp-method".into(), header_out(meth)));
                if let Some(n) = name_out {
                    hs.push(("mcp-name".into(), header_out(n)));
                }
            }
            if let Some(c) = &self.upstream_credential {
                hs.push(("authorization".into(), c.clone()));
            }
            hs
        };
        let canonical =
            || canon_json(r.body).map(|c| c.as_bytes().to_vec()).map_err(|_| rpc(400, PARSE_ERROR, "parse error"));
        let (plan, calls) = if ups.len() > 1 && meth == "tools/list" {
            let body = canonical()?;
            let calls = ups
                .iter()
                .map(|u| UpstreamCall { url: u.url.clone(), headers: base_headers(None), body: body.clone() })
                .collect();
            (Plan::MergeList { prefixes: ups.iter().map(|u| u.prefix.clone()).collect() }, calls)
        } else if ups.len() > 1 && meth == "tools/call" {
            let full = match name {
                Some(JsonValue::String(s)) => s.as_str(),
                _ => return Err(rpc(400, INVALID_PARAMS, "invalid params").id(&rid)),
            };
            let Some((u, local)) = ups.iter().find_map(|u| full.strip_prefix(u.prefix.as_str()).map(|l| (u, l))) else {
                return Err(rpc(404, INVALID_PARAMS, "unknown tool").id(&rid));
            };
            if local.is_empty() {
                return Err(rpc(404, INVALID_PARAMS, "unknown tool").id(&rid));
            }
            let body = emit::canonical(&rename(&msg, local)).ok_or_else(|| rpc(400, PARSE_ERROR, "parse error"))?;
            (
                Plan::Single { initialize },
                Vec::from([UpstreamCall { url: u.url.clone(), headers: base_headers(Some(local)), body }]),
            )
        } else {
            let u = ups.first().ok_or_else(|| rej(404))?;
            let n = match name {
                Some(JsonValue::String(s)) if NAMED.contains(&meth) => Some(s.as_str()),
                _ => None,
            };
            (
                Plan::Single { initialize },
                Vec::from([UpstreamCall { url: u.url.clone(), headers: base_headers(n), body: canonical()? }]),
            )
        };
        self.stats.forwarded.fetch_add(1, Ordering::Relaxed);
        Ok(Verdict::Forward(Box::new(Forward { route: ri, sub, rid, plan, extra: cors.clone(), calls })))
    }

    fn metadata(&self, route: &Route, cors: &[(String, String)]) -> Response {
        let v = JsonValue::Object(Vec::from([
            ("resource".to_string(), JsonValue::String(route.cfg.resource.clone())),
            (
                "authorization_servers".into(),
                JsonValue::Array(Vec::from([JsonValue::String(self.jwt.issuer().into())])),
            ),
            ("bearer_methods_supported".into(), JsonValue::Array(Vec::from([JsonValue::String("header".into())]))),
        ]));
        match emit::canonical(&v) {
            Some(body) => Response { status: 200, headers: cors.to_vec(), body },
            None => Response::empty(500, cors.to_vec()),
        }
    }

    /// Turn the upstream replies (one per [`Forward::calls`] entry, in order) into the client's reply.
    pub fn complete(&self, fwd: Forward, replies: Vec<Result<UpstreamReply, ()>>, now: u64) -> Response {
        let Forward { route, sub, rid, plan, extra, calls } = fwd;
        let fail = |status: u16, msg: &'static str| {
            self.stats.upstream_failed.fetch_add(1, Ordering::Relaxed);
            rpc(status, INTERNAL_ERROR, msg).id(&rid).into_response(&extra)
        };
        if replies.len() != calls.len() {
            return fail(502, "upstream reply count");
        }
        match plan {
            Plan::Single { initialize } => {
                let Some(Ok(rep)) = replies.into_iter().next() else { return fail(502, "upstream unavailable") };
                if rid.is_none() {
                    // A notification: nothing to relay.
                    return if (200..300).contains(&rep.status) {
                        Response::empty(202, extra.clone())
                    } else {
                        fail(502, "upstream refused notification")
                    };
                }
                let Some(v) = valid_reply(&rep, rid.as_ref()) else { return fail(502, "bad upstream reply") };
                let Ok(body) = canon_json(&rep.body) else { return fail(502, "bad upstream reply") };
                let mut headers = extra.clone();
                let status = if rep.status == 200 { 200 } else { 502 };
                if initialize && status == 200 && get(&v, "result").is_some() {
                    let created = match self.sessions.lock() {
                        Ok(mut t) => t.create(sub.as_str(), route, now),
                        Err(_) => Err(SessionError::Full),
                    };
                    match created {
                        Ok(sid) => headers.push(("mcp-session-id".into(), sid)),
                        Err(_) => return fail(503, "session table full"),
                    }
                }
                Response { status, headers, body: body.as_bytes().to_vec() }
            }
            Plan::MergeList { prefixes } => {
                let mut tools: Vec<JsonValue> = Vec::new();
                for (rep, prefix) in replies.into_iter().zip(prefixes.iter()) {
                    let Ok(rep) = rep else { return fail(502, "upstream unavailable") };
                    if rep.status != 200 {
                        return fail(502, "upstream error");
                    }
                    let Some(v) = valid_reply(&rep, rid.as_ref()) else { return fail(502, "bad upstream reply") };
                    let Some(JsonValue::Array(ts)) = get(&v, "result").and_then(|r| get(r, "tools")) else {
                        return fail(502, "bad upstream tool list");
                    };
                    for t in ts {
                        let (JsonValue::Object(m), Some(n)) = (t, get_str(t, "name")) else {
                            return fail(502, "bad upstream tool");
                        };
                        let full = format!("{prefix}{n}");
                        let m = m
                            .iter()
                            .map(|(k, x)| {
                                (k.clone(), if k == "name" { JsonValue::String(full.clone()) } else { x.clone() })
                            })
                            .collect();
                        tools.push(JsonValue::Object(m));
                    }
                }
                let mut folded: Vec<String> =
                    tools.iter().filter_map(|t| get_str(t, "name")).map(str::to_ascii_lowercase).collect();
                let n = folded.len();
                folded.sort();
                folded.dedup();
                if folded.len() != n {
                    return fail(502, "tool names collide under case folding");
                }
                let v = JsonValue::Object(Vec::from([
                    ("jsonrpc".to_string(), JsonValue::String("2.0".into())),
                    ("id".into(), rid.clone().unwrap_or(JsonValue::Null)),
                    ("result".into(), JsonValue::Object(Vec::from([("tools".to_string(), JsonValue::Array(tools))]))),
                ]));
                match emit::canonical(&v) {
                    Some(body) => Response { status: 200, headers: extra.clone(), body },
                    None => fail(502, "merged tool list"),
                }
            }
        }
    }
}

/// `msg` with `params.name` replaced.
fn rename(msg: &JsonValue, local: &str) -> JsonValue {
    let JsonValue::Object(m) = msg else { return msg.clone() };
    JsonValue::Object(
        m.iter()
            .map(|(k, v)| {
                let v = match (k.as_str(), v) {
                    ("params", JsonValue::Object(p)) => JsonValue::Object(
                        p.iter()
                            .map(|(pk, pv)| {
                                (pk.clone(), if pk == "name" { JsonValue::String(local.into()) } else { pv.clone() })
                            })
                            .collect(),
                    ),
                    _ => v.clone(),
                };
                (k.clone(), v)
            })
            .collect(),
    )
}

/// A JSON-RPC 2.0 response to `rid`, parsed by the owner: exactly `jsonrpc`, `id` and one of `result` / `error`.
fn valid_reply(rep: &UpstreamReply, rid: Option<&JsonValue>) -> Option<JsonValue> {
    let v = parse_json(&rep.body).ok()?;
    let JsonValue::Object(m) = &v else { return None };
    if m.iter().any(|(k, _)| !matches!(k.as_str(), "jsonrpc" | "id" | "result" | "error")) {
        return None;
    }
    if get_str(&v, "jsonrpc") != Some("2.0") || get(&v, "id") != rid {
        return None;
    }
    if get(&v, "result").is_some() == get(&v, "error").is_some() {
        return None;
    }
    Some(v)
}
