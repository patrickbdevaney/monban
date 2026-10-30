//! F8 validation over the strict I-JSON value tree. Order of checks within an object: unknown fields (document
//! order), then missing required fields (schema order), then each property (schema order). Arrays are checked
//! for length before their items. The first violation found is returned.

use std::collections::HashSet;

use aegis_canon::{JsonValue, parse_json};

use crate::ErrorKind as E;
use crate::data::{self, Backend, CapList, CapSpec, DataBlock, DataOp, DsnRef, Engine, RouteData};
use crate::{
    Admin, Alpn, Canon, Config, ConfigError, Framing, Limits, Listener, MAX_CONFIG_BYTES, MAX_ROUTE_ID, Profile,
    QueryMode, Route, RouteTarget, Vhost, emit, sha256,
};

type Members = [(String, JsonValue)];
type R<T> = Result<T, ConfigError>;

pub(crate) fn parse(input: &[u8]) -> R<Config> {
    // CFG-2: the byte cap comes first, before any parsing work.
    if input.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::new(E::TooLarge, "", "document exceeds 1 MiB"));
    }
    let v = parse_json(input).map_err(|r| {
        let kind = if r.status() == 413 { E::TooLarge } else { E::Syntax };
        ConfigError::new(kind, "", r.reason())
    })?;
    root(&v)
}

// ------------------------------------------------------------------------------------------------ helpers

/// RFC 6901 child pointer.
fn child(p: &str, key: &str) -> String {
    let mut s = String::with_capacity(p.len().saturating_add(key.len()).saturating_add(1));
    s.push_str(p);
    s.push('/');
    for c in key.chars() {
        match c {
            '~' => s.push_str("~0"),
            '/' => s.push_str("~1"),
            c => s.push(c),
        }
    }
    s
}

fn index(p: &str, i: usize) -> String {
    format!("{p}/{i}")
}

fn object<'a>(v: &'a JsonValue, p: &str) -> R<&'a Members> {
    match v {
        JsonValue::Object(m) => Ok(m),
        _ => Err(ConfigError::new(E::Type, p, "expected object")),
    }
}

fn fields(m: &Members, p: &str, allowed: &[&str], required: &[&str]) -> R<()> {
    for (k, _) in m {
        if !allowed.contains(&k.as_str()) {
            return Err(ConfigError::new(E::UnknownField, child(p, k), "unknown field"));
        }
    }
    for r in required {
        if get(m, r).is_none() {
            return Err(ConfigError::new(E::MissingField, child(p, r), "required field missing"));
        }
    }
    Ok(())
}

fn get<'a>(m: &'a Members, k: &str) -> Option<&'a JsonValue> {
    m.iter().find(|(n, _)| n == k).map(|(_, v)| v)
}

fn string<'a>(v: &'a JsonValue, p: &str) -> R<&'a str> {
    match v {
        JsonValue::String(s) => Ok(s),
        _ => Err(ConfigError::new(E::Type, p, "expected string")),
    }
}

/// JSON Schema `type: integer` (a number with zero fractional part, so `1.0` and `1e2` qualify) with inclusive
/// bounds. Integral values outside the I-JSON safe range are reported against the bound they exceed.
fn integer(v: &JsonValue, p: &str, min: u64, max: u64) -> R<u64> {
    const SAFE: f64 = 9_007_199_254_740_991.0;
    let n: i64 = match v {
        JsonValue::Int(n) => *n,
        JsonValue::Float(f) if f.is_finite() && f.fract() == 0.0 => {
            if *f > SAFE {
                return Err(ConfigError::new(E::Maximum, p, "above maximum"));
            }
            if *f < -SAFE {
                return Err(ConfigError::new(E::Minimum, p, "below minimum"));
            }
            // In range and integral: the conversion is exact.
            *f as i64
        }
        _ => return Err(ConfigError::new(E::Type, p, "expected integer")),
    };
    let Ok(u) = u64::try_from(n) else {
        return Err(ConfigError::new(E::Minimum, p, "below minimum"));
    };
    if u < min {
        return Err(ConfigError::new(E::Minimum, p, "below minimum"));
    }
    if u > max {
        return Err(ConfigError::new(E::Maximum, p, "above maximum"));
    }
    Ok(u)
}

fn array<'a>(v: &'a JsonValue, p: &str, min: usize, max: usize) -> R<&'a [JsonValue]> {
    let JsonValue::Array(a) = v else {
        return Err(ConfigError::new(E::Type, p, "expected array"));
    };
    if a.len() < min {
        return Err(ConfigError::new(E::MinItems, p, "too few items"));
    }
    if a.len() > max {
        return Err(ConfigError::new(E::MaxItems, p, "too many items"));
    }
    Ok(a)
}

fn enum_of<T: Copy>(v: &JsonValue, p: &str, table: &[(&str, T)]) -> R<T> {
    if let JsonValue::String(s) = v
        && let Some((_, t)) = table.iter().find(|(n, _)| n == s)
    {
        return Ok(*t);
    }
    Err(ConfigError::new(E::Enum, p, "not one of the allowed values"))
}

fn const_str(v: &JsonValue, p: &str, want: &str) -> R<()> {
    match v {
        JsonValue::String(s) if s == want => Ok(()),
        _ => Err(ConfigError::new(E::Const, p, "must equal the fixed value")),
    }
}

// ------------------------------------------------------------------------------------------------ patterns

/// `^[a-z][a-z0-9-]{0,31}$`
pub(crate) fn is_listener_name(s: &str) -> bool {
    let b = s.as_bytes();
    match b.split_first() {
        Some((first, rest)) => {
            first.is_ascii_lowercase()
                && rest.len() <= 31
                && rest.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        }
        None => false,
    }
}

/// `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`
pub(crate) fn is_host(s: &str) -> bool {
    let alnum = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    s.split('.').all(|label| {
        let b = label.as_bytes();
        match (b.first(), b.last()) {
            (Some(f), Some(l)) => b.len() <= 63 && alnum(f) && alnum(l) && b.iter().all(|c| alnum(c) || *c == b'-'),
            _ => false,
        }
    })
}

/// `^/[A-Za-z0-9._~!$&'()*+,;=:@/-]*$`
pub(crate) fn is_route_path(s: &str) -> bool {
    match s.as_bytes().split_first() {
        Some((b'/', rest)) => rest.iter().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    b'.' | b'_'
                        | b'~'
                        | b'!'
                        | b'$'
                        | b'&'
                        | b'\''
                        | b'('
                        | b')'
                        | b'*'
                        | b'+'
                        | b','
                        | b';'
                        | b'='
                        | b':'
                        | b'@'
                        | b'/'
                        | b'-'
                )
        }),
        _ => false,
    }
}

// ------------------------------------------------------------------------------------------------ schema

fn root(v: &JsonValue) -> R<Config> {
    let m = object(v, "")?;
    fields(m, "", &["v", "listeners", "vhosts", "admin", "limits", "canon", "data"], &["v", "listeners", "vhosts"])?;

    // `const: 1` (numeric equality, so 1.0 matches too).
    match get(m, "v") {
        Some(JsonValue::Int(1)) => {}
        Some(JsonValue::Float(f)) if *f == 1.0 => {}
        _ => return Err(ConfigError::new(E::Const, "/v", "must equal 1")),
    }

    let mut listeners = Vec::new();
    if let Some(lv) = get(m, "listeners") {
        let items = array(lv, "/listeners", 1, 64)?;
        let mut names = HashSet::new();
        for (i, item) in items.iter().enumerate() {
            let p = index("/listeners", i);
            let l = listener(item, &p)?;
            if !names.insert(l.name.clone()) {
                return Err(ConfigError::new(E::DuplicateListener, child(&p, "name"), "duplicate listener name"));
            }
            listeners.push(l);
        }
    }

    let mut vhosts = Vec::new();
    if let Some(vv) = get(m, "vhosts") {
        let items = array(vv, "/vhosts", 1, 4096)?;
        let mut hosts = HashSet::new();
        for (i, item) in items.iter().enumerate() {
            let p = index("/vhosts", i);
            let h = vhost(item, &p)?;
            if !hosts.insert(h.host.clone()) {
                return Err(ConfigError::new(E::DuplicateHost, child(&p, "host"), "duplicate vhost host"));
            }
            vhosts.push(h);
        }
    }

    let admin = match get(m, "admin") {
        Some(av) => {
            let am = object(av, "/admin")?;
            fields(am, "/admin", &["bind"], &[])?;
            let bind = match get(am, "bind") {
                Some(b) => Some(string(b, "/admin/bind")?.to_owned()),
                None => None,
            };
            Some(Admin { bind })
        }
        None => None,
    };

    let mut limits = Limits::default();
    if let Some(lv) = get(m, "limits") {
        let lm = object(lv, "/limits")?;
        let names: Vec<&str> = Limits::BOUNDS.iter().map(|(n, ..)| *n).collect();
        fields(lm, "/limits", &names, &[])?;
        for (name, min, max, _) in Limits::BOUNDS {
            if let Some(x) = get(lm, name) {
                limits.set(name, integer(x, &child("/limits", name), *min, *max)?);
            }
        }
    }

    let mut canon = Canon::default();
    if let Some(cv) = get(m, "canon") {
        let cm = object(cv, "/canon")?;
        let mut names: Vec<&str> = Canon::FIXED.iter().map(|(n, _)| *n).collect();
        names.push("query");
        fields(cm, "/canon", &names, &[])?;
        for (name, want) in Canon::FIXED {
            if let Some(x) = get(cm, name) {
                const_str(x, &child("/canon", name), want)?;
            }
        }
        if let Some(q) = get(cm, "query") {
            canon.query = enum_of(q, "/canon/query", &QueryMode::ALL)?;
        }
    }

    let data = match get(m, "data") {
        Some(dv) => Some(data_block(dv, "/data")?),
        None => None,
    };
    cap_backends(&vhosts, data.as_ref())?;

    let mut cfg = Config { listeners, vhosts, admin, limits, canon, data, canonical: Box::default(), hash: [0; 32] };
    let canonical = emit::canonical(&cfg)?;
    cfg.hash = sha256::sha256(&canonical);
    cfg.canonical = canonical;
    Ok(cfg)
}

fn listener(v: &JsonValue, p: &str) -> R<Listener> {
    let m = object(v, p)?;
    fields(m, p, &["name", "bind", "profile", "alpn"], &["name", "bind", "profile"])?;
    let (mut name, mut bind, mut profile, mut alpn) = (String::new(), String::new(), Profile::PublicWeb, None);
    if let Some(x) = get(m, "name") {
        let pp = child(p, "name");
        let s = string(x, &pp)?;
        if !is_listener_name(s) {
            return Err(ConfigError::new(E::Pattern, pp, "listener name must match ^[a-z][a-z0-9-]{0,31}$"));
        }
        name = s.to_owned();
    }
    if let Some(x) = get(m, "bind") {
        bind = string(x, &child(p, "bind"))?.to_owned();
    }
    if let Some(x) = get(m, "profile") {
        profile = enum_of(x, &child(p, "profile"), &Profile::ALL)?;
    }
    if let Some(x) = get(m, "alpn") {
        let pp = child(p, "alpn");
        // No maxItems in F8; uniqueness over a two-value enum bounds it, so the item loop stops at the first
        // repeat.
        let items = array(x, &pp, 1, usize::MAX)?;
        let mut out: Vec<Alpn> = Vec::new();
        for (i, it) in items.iter().enumerate() {
            let a = enum_of(it, &index(&pp, i), &Alpn::ALL)?;
            if out.contains(&a) {
                return Err(ConfigError::new(E::UniqueItems, pp, "alpn items must be unique"));
            }
            out.push(a);
        }
        alpn = Some(out);
    }
    Ok(Listener { name, bind, profile, alpn })
}

fn vhost(v: &JsonValue, p: &str) -> R<Vhost> {
    let m = object(v, p)?;
    fields(m, p, &["host", "routes"], &["host", "routes"])?;
    let mut host = String::new();
    if let Some(x) = get(m, "host") {
        let pp = child(p, "host");
        let s = string(x, &pp)?;
        if !is_host(s) {
            return Err(ConfigError::new(E::Pattern, pp, "host must be an ASCII-lowercase A-label"));
        }
        host = s.to_owned();
    }
    let mut routes = Vec::new();
    if let Some(x) = get(m, "routes") {
        let pp = child(p, "routes");
        let items = array(x, &pp, 1, 4096)?;
        let mut ids = HashSet::new();
        for (i, it) in items.iter().enumerate() {
            let rp = index(&pp, i);
            let r = route(it, &rp)?;
            if !ids.insert(r.id) {
                return Err(ConfigError::new(E::DuplicateRouteId, child(&rp, "id"), "duplicate route id in vhost"));
            }
            routes.push(r);
        }
    }
    Ok(Vhost { host, routes })
}

fn route(v: &JsonValue, p: &str) -> R<Route> {
    let m = object(v, p)?;
    fields(m, p, &["id", "path", "to", "authz", "data"], &["id", "path", "to"])?;
    let mut id = 0;
    if let Some(x) = get(m, "id") {
        id = integer(x, &child(p, "id"), 1, MAX_ROUTE_ID)?;
    }
    let mut path = String::new();
    if let Some(x) = get(m, "path") {
        let pp = child(p, "path");
        let s = string(x, &pp)?;
        if !is_route_path(s) {
            return Err(ConfigError::new(E::Pattern, pp, "route path must match ^/[A-Za-z0-9._~!$&'()*+,;=:@/-]*$"));
        }
        path = s.to_owned();
    }
    let mut to = RouteTarget::Static { root: String::new() };
    if let Some(x) = get(m, "to") {
        to = target(x, &child(p, "to"))?;
    }
    let mut authz = None;
    if let Some(x) = get(m, "authz") {
        authz = Some(string(x, &child(p, "authz"))?.to_owned());
    }
    let mut data = None;
    if let Some(x) = get(m, "data") {
        data = Some(route_data(x, &child(p, "data"))?);
    }
    Ok(Route { id, path, to, authz, data })
}

fn target_upstream(v: &JsonValue, p: &str) -> R<RouteTarget> {
    let m = object(v, p)?;
    fields(m, p, &["upstream", "framing"], &["upstream"])?;
    let mut upstream = String::new();
    if let Some(x) = get(m, "upstream") {
        upstream = string(x, &child(p, "upstream"))?.to_owned();
    }
    let mut framing = None;
    if let Some(x) = get(m, "framing") {
        framing = Some(enum_of(x, &child(p, "framing"), &Framing::ALL)?);
    }
    Ok(RouteTarget::Upstream { upstream, framing })
}

fn target_static(v: &JsonValue, p: &str) -> R<RouteTarget> {
    let m = object(v, p)?;
    fields(m, p, &["static"], &["static"])?;
    let mut root = String::new();
    if let Some(x) = get(m, "static") {
        root = string(x, &child(p, "static"))?.to_owned();
    }
    Ok(RouteTarget::Static { root })
}

/// `oneOf` [upstream, static]: exactly one branch must validate. When none does, the error of the branch the
/// object evidently aims at (it names `upstream` or `static`, but not both) is reported for precision.
fn target(v: &JsonValue, p: &str) -> R<RouteTarget> {
    let a = target_upstream(v, p);
    let b = target_static(v, p);
    match (a, b) {
        (Ok(t), Err(_)) | (Err(_), Ok(t)) => Ok(t),
        (Ok(_), Ok(_)) => Err(ConfigError::new(E::OneOf, p, "route target matches more than one branch")),
        (Err(ea), Err(eb)) => {
            let (has_u, has_s) = match v {
                JsonValue::Object(m) => (get(m, "upstream").is_some(), get(m, "static").is_some()),
                _ => (false, false),
            };
            match (has_u, has_s) {
                (true, false) => Err(ea),
                (false, true) => Err(eb),
                _ => Err(ConfigError::new(
                    E::OneOf,
                    p,
                    "route target must be exactly one of {\"upstream\": ...} or {\"static\": ...}",
                )),
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------ data (F8, Phase 4)

/// `^[a-z_][a-z0-9_]{0,62}$` (collection and column names).
pub(crate) fn is_ident(s: &str) -> bool {
    let b = s.as_bytes();
    match b.split_first() {
        Some((f, rest)) => {
            (f.is_ascii_lowercase() || *f == b'_')
                && rest.len() <= 62
                && rest.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
        }
        None => false,
    }
}

/// `^(env:[A-Z_][A-Z0-9_]{0,63}|cred:[A-Za-z0-9_.-]{1,64}|path:/[A-Za-z0-9._/-]{1,255})$`
pub(crate) fn dsn_ref(s: &str) -> Option<DsnRef> {
    if let Some(n) = s.strip_prefix("env:") {
        let b = n.as_bytes();
        let ok = match b.split_first() {
            Some((f, rest)) => {
                (f.is_ascii_uppercase() || *f == b'_')
                    && rest.len() <= 63
                    && rest.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
            }
            None => false,
        };
        return ok.then(|| DsnRef::Env(n.to_owned()));
    }
    if let Some(n) = s.strip_prefix("cred:") {
        let ok = (1..=64).contains(&n.len())
            && n.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'));
        return ok.then(|| DsnRef::Cred(n.to_owned()));
    }
    if let Some(n) = s.strip_prefix("path:") {
        let ok = match n.as_bytes().split_first() {
            Some((b'/', rest)) => {
                (1..=255).contains(&rest.len())
                    && rest.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'/' | b'-'))
            }
            _ => false,
        };
        return ok.then(|| DsnRef::Path(n.to_owned()));
    }
    None
}

fn data_block(v: &JsonValue, p: &str) -> R<DataBlock> {
    let m = object(v, p)?;
    fields(m, p, &["backends"], &["backends"])?;
    let mut backends: Vec<Backend> = Vec::new();
    if let Some(x) = get(m, "backends") {
        let pp = child(p, "backends");
        let items = array(x, &pp, 1, data::MAX_BACKENDS)?;
        for (i, it) in items.iter().enumerate() {
            let bp = index(&pp, i);
            let b = backend(it, &bp)?;
            if backends.iter().any(|o| o.id == b.id) {
                return Err(ConfigError::new(E::DuplicateBackend, child(&bp, "id"), "duplicate backend id"));
            }
            backends.push(b);
        }
    }
    Ok(DataBlock { backends })
}

fn backend(v: &JsonValue, p: &str) -> R<Backend> {
    let m = object(v, p)?;
    fields(
        m,
        p,
        &["id", "engine", "dsn_ref", "pin", "max_conns", "op_budget_ms"],
        &["id", "engine", "dsn_ref", "pin"],
    )?;
    let mut id = String::new();
    if let Some(x) = get(m, "id") {
        let pp = child(p, "id");
        let s = string(x, &pp)?;
        if !is_listener_name(s) {
            return Err(ConfigError::new(E::Pattern, pp, "backend id must match ^[a-z][a-z0-9-]{0,31}$"));
        }
        id = s.to_owned();
    }
    // Required, so present after `fields`; the fallback is never used for an accepted config.
    let mut engine = Engine::Sqlite;
    if let Some(x) = get(m, "engine") {
        engine = enum_of(x, &child(p, "engine"), &Engine::ALL)?;
    }
    let mut dsn = DsnRef::Path(String::new());
    if let Some(x) = get(m, "dsn_ref") {
        let pp = child(p, "dsn_ref");
        let s = string(x, &pp)?;
        let Some(d) = dsn_ref(s) else {
            return Err(ConfigError::new(E::Pattern, pp, "dsn_ref must be env:NAME, cred:NAME or path:/abs"));
        };
        // allOf if/then/else: sqlite takes path: only; network engines take env:/cred: only.
        let fits =
            matches!((engine.is_embedded(), &d), (true, DsnRef::Path(_)) | (false, DsnRef::Env(_) | DsnRef::Cred(_)));
        if !fits {
            let why = if engine.is_embedded() {
                "dsn_ref for sqlite must be path:/abs"
            } else {
                "dsn_ref for a network engine must be env:NAME or cred:NAME"
            };
            return Err(ConfigError::new(E::Pattern, pp, why));
        }
        dsn = d;
    }
    let mut pin = String::new();
    if let Some(x) = get(m, "pin") {
        let pp = child(p, "pin");
        let s = string(x, &pp)?;
        if !data::is_pin_name(s) {
            return Err(ConfigError::new(E::Pattern, pp, "pin must match ^[a-z][a-z0-9]{0,15}$"));
        }
        match data::engine_pin(s) {
            None => return Err(ConfigError::new(E::UnknownPin, pp, "pin not in supply-chain/engine-pins.toml")),
            Some(info) if info.engine != engine => {
                return Err(ConfigError::new(E::PinEngineMismatch, pp, "pin family differs from engine"));
            }
            Some(_) => {}
        }
        pin = s.to_owned();
    }
    let mut max_conns = Backend::DEFAULT_MAX_CONNS;
    if let Some(x) = get(m, "max_conns") {
        let (lo, hi) = Backend::MAX_CONNS_BOUNDS;
        max_conns = integer(x, &child(p, "max_conns"), lo, hi)?;
    }
    let mut op_budget_ms = Backend::DEFAULT_OP_BUDGET_MS;
    if let Some(x) = get(m, "op_budget_ms") {
        let (lo, hi) = Backend::OP_BUDGET_MS_BOUNDS;
        op_budget_ms = integer(x, &child(p, "op_budget_ms"), lo, hi)?;
    }
    Ok(Backend { id, engine, dsn_ref: dsn, pin, max_conns, op_budget_ms })
}

/// `oneOf` [array 1..256 of data_cap, const "unrestricted"]. The branches are disjoint by JSON type, so an array
/// reports the array branch's own error, and anything else but the exact literal is a `OneOf` failure.
fn route_data(v: &JsonValue, p: &str) -> R<RouteData> {
    match v {
        JsonValue::String(s) if s == data::UNRESTRICTED => Ok(RouteData::Unrestricted),
        JsonValue::Array(_) => {
            let items = array(v, p, 1, data::MAX_CAPS)?;
            let mut caps = Vec::with_capacity(items.len());
            for (k, it) in items.iter().enumerate() {
                caps.push(data_cap(it, &index(p, k))?);
            }
            Ok(RouteData::Caps(CapList(caps)))
        }
        _ => Err(ConfigError::new(
            E::OneOf,
            p,
            "route data must be a non-empty capability list or the literal \"unrestricted\"",
        )),
    }
}

fn data_cap(v: &JsonValue, p: &str) -> R<CapSpec> {
    let m = object(v, p)?;
    fields(m, p, &["backend", "collection", "ops", "columns"], &["backend", "collection", "ops", "columns"])?;
    let mut backend = String::new();
    if let Some(x) = get(m, "backend") {
        let pp = child(p, "backend");
        let s = string(x, &pp)?;
        if !is_listener_name(s) {
            return Err(ConfigError::new(E::Pattern, pp, "backend must match ^[a-z][a-z0-9-]{0,31}$"));
        }
        backend = s.to_owned();
    }
    let mut collection = String::new();
    if let Some(x) = get(m, "collection") {
        let pp = child(p, "collection");
        let s = string(x, &pp)?;
        if !is_ident(s) {
            return Err(ConfigError::new(E::Pattern, pp, "collection must match ^[a-z_][a-z0-9_]{0,62}$"));
        }
        collection = s.to_owned();
    }
    let mut ops = 0u8;
    if let Some(x) = get(m, "ops") {
        let pp = child(p, "ops");
        let items = array(x, &pp, 1, 5)?;
        for (i, it) in items.iter().enumerate() {
            let o = enum_of(it, &index(&pp, i), &DataOp::NAMES)?;
            if ops & o.bit() != 0 {
                return Err(ConfigError::new(E::UniqueItems, pp, "ops items must be unique"));
            }
            ops |= o.bit();
        }
    }
    let mut columns: Vec<String> = Vec::new();
    if let Some(x) = get(m, "columns") {
        let pp = child(p, "columns");
        let items = array(x, &pp, 1, data::MAX_CAP_COLUMNS)?;
        let mut seen = HashSet::new();
        for (i, it) in items.iter().enumerate() {
            let ip = index(&pp, i);
            let s = string(it, &ip)?;
            if !is_ident(s) {
                return Err(ConfigError::new(E::Pattern, ip, "column must match ^[a-z_][a-z0-9_]{0,62}$"));
            }
            if !seen.insert(s) {
                return Err(ConfigError::new(E::UniqueItems, pp, "columns items must be unique"));
            }
            columns.push(s.to_owned());
        }
    }
    if ops == 0 || columns.is_empty() {
        // Unreachable after the required/minItems checks; fail closed rather than build an empty grant.
        return Err(ConfigError::new(E::MinItems, p, "cap grants no op or no column"));
    }
    Ok(CapSpec { backend, collection, ops, columns })
}

/// Cross-field: every cap names a declared backend (checked at load; no `data` block means no backend exists).
fn cap_backends(vhosts: &[Vhost], data: Option<&DataBlock>) -> R<()> {
    for (i, vh) in vhosts.iter().enumerate() {
        for (j, r) in vh.routes.iter().enumerate() {
            if let Some(RouteData::Caps(list)) = &r.data {
                for (k, c) in list.as_slice().iter().enumerate() {
                    if data.and_then(|d| d.backend(&c.backend)).is_none() {
                        return Err(ConfigError::new(
                            E::UnknownBackend,
                            format!("/vhosts/{i}/routes/{j}/data/{k}/backend"),
                            "cap names an undeclared backend",
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}
