//! F8 validation over the strict I-JSON value tree. Order of checks within an object: unknown fields (document
//! order), then missing required fields (schema order), then each property (schema order). Arrays are checked
//! for length before their items. The first violation found is returned.

use std::collections::HashSet;

use monban_canon::{JsonValue, parse_json};

use crate::ErrorKind as E;
use crate::data::{
    self, AdapterBackend, AdapterFamily, Backend, CapList, CapSpec, DataBlock, DataOp, Decl, DsnRef, Engine, Pins,
    RouteData,
};
use crate::p2::{self, CrashBudget, IsolationSetting, P2Block, P2Limits, P2Module, Tenancy};
use crate::p7::{
    self, Admission, Cidr, Credential, CredentialKind, Front, L4Route, ProxyProtocol, RateLimit, SecretRef, TlsBlock,
    TrustAnchorId,
};
use crate::p8::{Runtime, StateBlock};
use crate::{
    Admin, Alpn, Canon, Config, ConfigError, Framing, Limits, Listener, MAX_CONFIG_BYTES, MAX_ROUTE_ID, Profile,
    QueryMode, Route, RouteTarget, Vhost, emit, sha256,
};

type Members = [(String, JsonValue)];
type R<T> = Result<T, ConfigError>;

pub(crate) fn parse(input: &[u8]) -> R<Config> {
    parse_with(input, data::pins())
}

/// [`parse`] against an explicit engine-pin catalogue (the embedded one in production; unit tests inject pins the
/// catalogue does not carry yet, such as the Phase-7 adapter families).
pub(crate) fn parse_with(input: &[u8], pins: &Pins) -> R<Config> {
    // CFG-2: the byte cap comes first, before any parsing work.
    if input.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::new(E::TooLarge, "", "document exceeds 1 MiB"));
    }
    let v = parse_json(input).map_err(|r| {
        let kind = if r.status() == 413 { E::TooLarge } else { E::Syntax };
        ConfigError::new(kind, "", r.reason())
    })?;
    root(&v, pins)
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

/// A route path that `monban_canon::canon_path` accepts and returns byte-for-byte unchanged (Phase 8, R13).
pub(crate) fn is_canonical_route_path(s: &str) -> bool {
    matches!(monban_canon::canon_path(s.as_bytes()), Ok(c) if c.as_bytes() == s.as_bytes())
}

// ------------------------------------------------------------------------------------------------ schema

fn root(v: &JsonValue, pins: &Pins) -> R<Config> {
    let m = object(v, "")?;
    fields(
        m,
        "",
        &["v", "listeners", "vhosts", "admin", "limits", "canon", "data", "p2", "tls", "admission", "runtime", "state"],
        &["v", "listeners", "vhosts"],
    )?;

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
        Some(dv) => Some(data_block(dv, "/data", pins)?),
        None => None,
    };
    cap_backends(&vhosts, data.as_ref())?;

    let p2 = match get(m, "p2") {
        Some(pv) => Some(p2_block(pv, "/p2")?),
        None => None,
    };
    wasm_modules(&vhosts, p2.as_ref())?;

    let tls = match get(m, "tls") {
        Some(tv) => Some(tls_block(tv, "/tls", &listeners)?),
        None => None,
    };

    let admission = match get(m, "admission") {
        Some(av) => admission_block(av, "/admission")?,
        None => Admission::default(),
    };

    let runtime = match get(m, "runtime") {
        Some(rv) => runtime_block(rv, "/runtime")?,
        None => Runtime::default(),
    };

    let state = match get(m, "state") {
        Some(sv) => state_block(sv, "/state")?,
        None => StateBlock::default(),
    };

    let mut cfg = Config {
        listeners,
        vhosts,
        admin,
        limits,
        canon,
        data,
        p2,
        tls,
        admission,
        runtime,
        state,
        canonical: Box::default(),
        hash: [0; 32],
    };
    let canonical = emit::canonical(&cfg)?;
    cfg.hash = sha256::sha256(&canonical);
    cfg.canonical = canonical;
    Ok(cfg)
}

fn listener(v: &JsonValue, p: &str) -> R<Listener> {
    let m = object(v, p)?;
    fields(m, p, &["name", "bind", "profile", "alpn", "proxy_protocol", "l4", "front"], &["name", "bind", "profile"])?;
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
    let mut proxy = None;
    if let Some(x) = get(m, "proxy_protocol") {
        proxy = Some(proxy_protocol(x, &child(p, "proxy_protocol"))?);
    }
    let mut l4 = None;
    if let Some(x) = get(m, "l4") {
        l4 = Some(l4_routes(x, &child(p, "l4"))?);
    }
    let mut front = Front::default();
    if let Some(x) = get(m, "front") {
        front = enum_of(x, &child(p, "front"), &Front::ALL)?;
    }
    // allOf: a listener is L4 or HTTP, never both (L4-2).
    if l4.is_some() && alpn.is_some() {
        return Err(ConfigError::new(E::Forbidden, child(p, "alpn"), "an L4 listener carries no alpn"));
    }
    Ok(Listener { name, bind, profile, alpn, proxy_protocol: proxy, l4, front })
}

// ------------------------------------------------------------------------------------------------ Phase 7 (F8)

fn proxy_protocol(v: &JsonValue, p: &str) -> R<ProxyProtocol> {
    let m = object(v, p)?;
    fields(m, p, &["trusted"], &["trusted"])?;
    let mut trusted: Vec<Cidr> = Vec::new();
    if let Some(x) = get(m, "trusted") {
        let pp = child(p, "trusted");
        let items = array(x, &pp, 1, p7::MAX_TRUSTED)?;
        for (i, it) in items.iter().enumerate() {
            let ip = index(&pp, i);
            let s = string(it, &ip)?;
            let Some(c) = Cidr::parse(s) else {
                return Err(ConfigError::new(
                    E::Pattern,
                    ip,
                    "trusted must be a canonical IPv4 /1..32 or IPv6 /1..128 prefix with zero host bits",
                ));
            };
            if trusted.contains(&c) {
                return Err(ConfigError::new(E::UniqueItems, pp, "trusted items must be unique"));
            }
            trusted.push(c);
        }
    }
    if trusted.is_empty() {
        // Unreachable after the required/minItems checks; fail closed rather than trust nobody silently.
        return Err(ConfigError::new(E::MinItems, child(p, "trusted"), "no trusted prefix"));
    }
    Ok(ProxyProtocol { trusted })
}

fn l4_routes(v: &JsonValue, p: &str) -> R<Vec<L4Route>> {
    let items = array(v, p, 1, p7::MAX_L4_ROUTES)?;
    let mut out: Vec<L4Route> = Vec::with_capacity(items.len());
    for (i, it) in items.iter().enumerate() {
        let rp = index(p, i);
        let m = object(it, &rp)?;
        fields(m, &rp, &["sni", "upstream"], &["sni", "upstream"])?;
        let mut sni = String::new();
        if let Some(x) = get(m, "sni") {
            let pp = child(&rp, "sni");
            let s = string(x, &pp)?;
            if !is_host(s) {
                return Err(ConfigError::new(E::Pattern, pp, "sni must be an ASCII-lowercase A-label (no wildcard)"));
            }
            sni = s.to_owned();
        }
        let (mut upstream_host, mut upstream_port) = (String::new(), 0u16);
        if let Some(x) = get(m, "upstream") {
            let pp = child(&rp, "upstream");
            let s = string(x, &pp)?;
            let Some((h, port)) = p7::upstream(s) else {
                return Err(ConfigError::new(
                    E::Pattern,
                    pp,
                    "upstream must be host:port or [ipv6]:port, port 1..65535",
                ));
            };
            (upstream_host, upstream_port) = (h, port);
        }
        if out.iter().any(|r| r.sni == sni) {
            return Err(ConfigError::new(E::DuplicateSni, child(&rp, "sni"), "duplicate sni in l4 listener"));
        }
        out.push(L4Route { sni, upstream_host, upstream_port });
    }
    Ok(out)
}

fn admission_block(v: &JsonValue, p: &str) -> R<Admission> {
    let m = object(v, p)?;
    let mut names: Vec<&str> = vec!["per_ip"];
    names.extend(Admission::BOUNDS.iter().map(|(n, ..)| *n));
    fields(m, p, &names, &[])?;
    let mut a = Admission::default();
    if let Some(x) = get(m, "per_ip") {
        let pp = child(p, "per_ip");
        let pm = object(x, &pp)?;
        fields(pm, &pp, &["rate_per_s", "burst"], &[])?;
        let mut r = Admission::DEFAULT_PER_IP;
        if let Some(y) = get(pm, "rate_per_s") {
            let (lo, hi) = RateLimit::RATE_BOUNDS;
            r.rate_per_s = integer(y, &child(&pp, "rate_per_s"), lo, hi)?;
        }
        if let Some(y) = get(pm, "burst") {
            let (lo, hi) = RateLimit::BURST_BOUNDS;
            r.burst = integer(y, &child(&pp, "burst"), lo, hi)?;
        }
        if r.burst < r.rate_per_s {
            return Err(ConfigError::new(E::BurstBelowRate, child(&pp, "burst"), "burst must be >= rate_per_s"));
        }
        a.per_ip = r;
    }
    for (name, min, max, _) in Admission::BOUNDS {
        if let Some(x) = get(m, name) {
            a.set(name, integer(x, &child(p, name), *min, *max)?);
        }
    }
    Ok(a)
}

fn runtime_block(v: &JsonValue, p: &str) -> R<Runtime> {
    let m = object(v, p)?;
    let names: Vec<&str> = Runtime::BOUNDS.iter().map(|(n, ..)| *n).collect();
    fields(m, p, &names, &[])?;
    let mut r = Runtime::default();
    for (name, min, max, _) in Runtime::BOUNDS {
        if let Some(x) = get(m, name) {
            r.set(name, integer(x, &child(p, name), *min, *max)?);
        }
    }
    Ok(r)
}

fn state_block(v: &JsonValue, p: &str) -> R<StateBlock> {
    let m = object(v, p)?;
    fields(m, p, StateBlock::MEMBERS, &[])?;
    let mut s = StateBlock::default();
    if let Some(x) = get(m, "idempotency_retention_s") {
        let (lo, hi) = StateBlock::RETENTION_BOUNDS;
        s.idempotency_retention_s = Some(integer(x, &child(p, "idempotency_retention_s"), lo, hi)?);
    }
    Ok(s)
}

fn secret_ref(v: &JsonValue, p: &str) -> R<SecretRef> {
    let s = string(v, p)?;
    SecretRef::parse(s).ok_or_else(|| ConfigError::new(E::Pattern, p, "must be cred:NAME or path:/abs"))
}

fn tls_block(v: &JsonValue, p: &str, listeners: &[Listener]) -> R<TlsBlock> {
    let m = object(v, p)?;
    fields(m, p, &["credentials"], &["credentials"])?;
    let mut creds: Vec<Credential> = Vec::new();
    if let Some(x) = get(m, "credentials") {
        let pp = child(p, "credentials");
        let items = array(x, &pp, 1, p7::MAX_CREDENTIALS)?;
        for (i, it) in items.iter().enumerate() {
            let cp = index(&pp, i);
            let c = credential(it, &cp, listeners)?;
            if creds.iter().any(|o| o.id == c.id) {
                return Err(ConfigError::new(E::DuplicateCredential, child(&cp, "id"), "duplicate credential id"));
            }
            if let Some(t) = &c.trust_anchor_id
                && creds.iter().any(|o| o.trust_anchor_id.as_ref() == Some(t))
            {
                return Err(ConfigError::new(
                    E::DuplicateTrustAnchor,
                    child(&cp, "trust_anchor_id"),
                    "two mtc credentials share a trust_anchor_id",
                ));
            }
            creds.push(c);
        }
    }
    if creds.is_empty() {
        // Unreachable after the required/minItems checks; fail closed.
        return Err(ConfigError::new(E::MinItems, child(p, "credentials"), "no credential"));
    }
    Ok(TlsBlock { credentials: creds })
}

fn credential(v: &JsonValue, p: &str, listeners: &[Listener]) -> R<Credential> {
    let m = object(v, p)?;
    fields(m, p, &["id", "kind", "trust_anchor_id", "chain", "key", "listeners"], &["id", "kind", "chain", "key"])?;
    let mut id = String::new();
    if let Some(x) = get(m, "id") {
        let pp = child(p, "id");
        let s = string(x, &pp)?;
        if !is_listener_name(s) {
            return Err(ConfigError::new(E::Pattern, pp, "credential id must match ^[a-z][a-z0-9-]{0,31}$"));
        }
        id = s.to_owned();
    }
    // Required, so present after `fields`; the fallback is never used for an accepted config.
    let mut kind = CredentialKind::X509;
    if let Some(x) = get(m, "kind") {
        kind = enum_of(x, &child(p, "kind"), &CredentialKind::ALL)?;
    }
    let mut trust_anchor_id = None;
    if let Some(x) = get(m, "trust_anchor_id") {
        let pp = child(p, "trust_anchor_id");
        let s = string(x, &pp)?;
        let Some(t) = TrustAnchorId::parse(s) else {
            return Err(ConfigError::new(
                E::Pattern,
                pp,
                "trust_anchor_id must be a dotted-decimal relative OID (1..32 components, each < 2^32)",
            ));
        };
        trust_anchor_id = Some(t);
    }
    let mut chain = SecretRef::Path(String::new());
    if let Some(x) = get(m, "chain") {
        chain = secret_ref(x, &child(p, "chain"))?;
    }
    let mut key = SecretRef::Path(String::new());
    if let Some(x) = get(m, "key") {
        key = secret_ref(x, &child(p, "key"))?;
    }
    let mut scope = None;
    if let Some(x) = get(m, "listeners") {
        let pp = child(p, "listeners");
        let items = array(x, &pp, 1, p7::MAX_CREDENTIALS)?;
        let mut names: Vec<String> = Vec::with_capacity(items.len());
        for (k, it) in items.iter().enumerate() {
            let ip = index(&pp, k);
            let s = string(it, &ip)?;
            if !is_listener_name(s) {
                return Err(ConfigError::new(E::Pattern, ip, "listener name must match ^[a-z][a-z0-9-]{0,31}$"));
            }
            if names.iter().any(|n| n == s) {
                return Err(ConfigError::new(E::UniqueItems, pp, "listeners items must be unique"));
            }
            names.push(s.to_owned());
        }
        scope = Some(names);
    }
    // allOf if/then/else: trust_anchor_id is required for mtc and not allowed otherwise (SEL-1).
    match (kind, &trust_anchor_id) {
        (CredentialKind::Mtc, None) => {
            return Err(ConfigError::new(
                E::MissingField,
                child(p, "trust_anchor_id"),
                "an mtc credential needs a trust_anchor_id",
            ));
        }
        (CredentialKind::X509 | CredentialKind::MlDsa, Some(_)) => {
            return Err(ConfigError::new(
                E::Forbidden,
                child(p, "trust_anchor_id"),
                "trust_anchor_id is only allowed on an mtc credential",
            ));
        }
        _ => {}
    }
    // Cross-field: the scope names declared HTTP listeners; never an mldsa credential on P-PUBLIC-WEB (SEL-2).
    if let Some(names) = &scope {
        for (k, n) in names.iter().enumerate() {
            let ip = format!("{p}/listeners/{k}");
            let Some(l) = listeners.iter().find(|l| &l.name == n) else {
                return Err(ConfigError::new(E::UnknownListener, ip, "credential names an undeclared listener"));
            };
            if l.l4.is_some() {
                return Err(ConfigError::new(E::CredentialScope, ip, "an L4 listener terminates no TLS"));
            }
            if kind == CredentialKind::MlDsa && l.profile == Profile::PublicWeb {
                return Err(ConfigError::new(
                    E::CredentialScope,
                    ip,
                    "an mldsa credential is never served on a P-PUBLIC-WEB listener (SEL-2)",
                ));
            }
        }
    }
    Ok(Credential { id, kind, trust_anchor_id, chain, key, listeners: scope })
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
        // R13 (Phase 8): routing compares canonical request paths, so a path canon_path changes (dot or empty
        // segment) or rejects (over-long) is a route no request can reach. Refuse it here instead of loading it dead.
        if !is_canonical_route_path(s) {
            return Err(ConfigError::new(
                E::NotCanonical,
                pp,
                "route path must be canonical (monban_canon::canon_path leaves it unchanged)",
            ));
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

fn target_wasm(v: &JsonValue, p: &str) -> R<RouteTarget> {
    let m = object(v, p)?;
    fields(m, p, &["wasm"], &["wasm"])?;
    let mut module = String::new();
    if let Some(x) = get(m, "wasm") {
        let pp = child(p, "wasm");
        let s = string(x, &pp)?;
        if !is_listener_name(s) {
            return Err(ConfigError::new(E::Pattern, pp, "wasm module id must match ^[a-z][a-z0-9-]{0,31}$"));
        }
        module = s.to_owned();
    }
    Ok(RouteTarget::Wasm { module })
}

/// `oneOf` [upstream, static, wasm]: exactly one branch must validate. When none does, the error of the branch
/// the object evidently aims at (it names exactly one of `upstream`, `static`, `wasm`) is reported for precision.
fn target(v: &JsonValue, p: &str) -> R<RouteTarget> {
    let results = [target_upstream(v, p), target_static(v, p), target_wasm(v, p)];
    let mut found: Option<&RouteTarget> = None;
    for t in results.iter().flatten() {
        if found.is_some() {
            return Err(ConfigError::new(E::OneOf, p, "route target matches more than one branch"));
        }
        found = Some(t);
    }
    if let Some(t) = found {
        return Ok(t.clone());
    }
    let named: [bool; 3] = match v {
        JsonValue::Object(m) => [get(m, "upstream").is_some(), get(m, "static").is_some(), get(m, "wasm").is_some()],
        _ => [false; 3],
    };
    if named.iter().filter(|b| **b).count() == 1 {
        for (r, n) in results.into_iter().zip(named) {
            if let (true, Err(e)) = (n, r) {
                return Err(e);
            }
        }
    }
    Err(ConfigError::new(
        E::OneOf,
        p,
        "route target must be exactly one of {\"upstream\": ...}, {\"static\": ...} or {\"wasm\": ...}",
    ))
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

fn data_block(v: &JsonValue, p: &str, pins: &Pins) -> R<DataBlock> {
    let m = object(v, p)?;
    fields(m, p, &["backends"], &["backends"])?;
    let mut backends: Vec<Backend> = Vec::new();
    let mut adapters: Vec<AdapterBackend> = Vec::new();
    let mut order: Vec<Decl> = Vec::new();
    if let Some(x) = get(m, "backends") {
        let pp = child(p, "backends");
        let items = array(x, &pp, 1, data::MAX_BACKENDS)?;
        for (i, it) in items.iter().enumerate() {
            let bp = index(&pp, i);
            let b = backend(it, &bp, pins)?;
            let id = match &b {
                Parsed::Golden(g) => &g.id,
                Parsed::Adapter(a) => &a.id,
            };
            if backends.iter().any(|o| &o.id == id) || adapters.iter().any(|o| &o.id == id) {
                return Err(ConfigError::new(E::DuplicateBackend, child(&bp, "id"), "duplicate backend id"));
            }
            match b {
                Parsed::Golden(g) => {
                    order.push(Decl::Golden(backends.len()));
                    backends.push(g);
                }
                Parsed::Adapter(a) => {
                    order.push(Decl::Adapter(adapters.len()));
                    adapters.push(a);
                }
            }
        }
    }
    Ok(DataBlock { backends, adapters, order })
}

/// F8 `backend.engine`: a golden family ([`Engine`]) or a Phase-7 adapter family ([`AdapterFamily`]).
#[derive(Clone, Copy)]
enum Family {
    Golden(Engine),
    Adapter(AdapterFamily),
}

impl Family {
    const ALL: [(&'static str, Family); 6] = [
        ("sqlite", Family::Golden(Engine::Sqlite)),
        ("postgres", Family::Golden(Engine::Postgres)),
        ("redis", Family::Golden(Engine::Redis)),
        ("valkey", Family::Golden(Engine::Valkey)),
        ("mariadb", Family::Adapter(AdapterFamily::Mariadb)),
        ("crdb", Family::Adapter(AdapterFamily::Crdb)),
    ];
    fn is_embedded(self) -> bool {
        matches!(self, Family::Golden(e) if e.is_embedded())
    }
}

enum Parsed {
    Golden(Backend),
    Adapter(AdapterBackend),
}

fn backend(v: &JsonValue, p: &str, pins: &Pins) -> R<Parsed> {
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
    let mut engine = Family::Golden(Engine::Sqlite);
    if let Some(x) = get(m, "engine") {
        engine = enum_of(x, &child(p, "engine"), &Family::ALL)?;
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
        let same = match (engine, pins.golden(s), pins.adapter(s)) {
            (_, None, None) => {
                return Err(ConfigError::new(E::UnknownPin, pp, "pin not in supply-chain/engine-pins.toml"));
            }
            (Family::Golden(e), Some(info), _) => info.engine == e,
            (Family::Adapter(f), _, Some(info)) => info.family == f,
            _ => false,
        };
        if !same {
            return Err(ConfigError::new(E::PinEngineMismatch, pp, "pin family differs from engine"));
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
    Ok(match engine {
        Family::Golden(engine) => Parsed::Golden(Backend { id, engine, dsn_ref: dsn, pin, max_conns, op_budget_ms }),
        Family::Adapter(family) => {
            Parsed::Adapter(AdapterBackend { id, family, dsn_ref: dsn, pin, max_conns, op_budget_ms })
        }
    })
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
                    if !data.is_some_and(|d| d.declares(&c.backend)) {
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

// ------------------------------------------------------------------------------------------------ p2 (F8, Phase 5)

/// `^/[A-Za-z0-9._/-]{1,max}$` (`p2.worker`, `p2.cache_dir`: max 255).
fn is_abs_path(s: &str, max: usize) -> bool {
    match s.as_bytes().split_first() {
        Some((b'/', rest)) => {
            (1..=max).contains(&rest.len())
                && rest.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'/' | b'-'))
        }
        _ => false,
    }
}

/// `^/[A-Za-z0-9._/-]{1,250}\.wasm$` (`p2_module.path`).
pub(crate) fn is_wasm_path(s: &str) -> bool {
    match s.strip_suffix(".wasm") {
        Some(stem) => is_abs_path(stem, 250),
        None => false,
    }
}

/// `^[0-9a-f]{64}$`, decoded.
fn hex32(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    let (pairs, rest) = b.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    for (o, [h, l]) in out.iter_mut().zip(pairs) {
        *o = (nib(*h)? << 4) | nib(*l)?;
    }
    Some(out)
}

fn boolean(v: &JsonValue, p: &str) -> R<bool> {
    match v {
        JsonValue::Bool(b) => Ok(*b),
        _ => Err(ConfigError::new(E::Type, p, "expected boolean")),
    }
}

fn p2_block(v: &JsonValue, p: &str) -> R<P2Block> {
    let m = object(v, p)?;
    fields(m, p, P2Block::MEMBERS, &["worker", "modules"])?;
    let mut worker = String::new();
    if let Some(x) = get(m, "worker") {
        let pp = child(p, "worker");
        let s = string(x, &pp)?;
        if !is_abs_path(s, 255) {
            return Err(ConfigError::new(E::Pattern, pp, "worker must match ^/[A-Za-z0-9._/-]{1,255}$"));
        }
        worker = s.to_owned();
    }
    let mut cache_dir = None;
    if let Some(x) = get(m, "cache_dir") {
        let pp = child(p, "cache_dir");
        let s = string(x, &pp)?;
        if !is_abs_path(s, 255) {
            return Err(ConfigError::new(E::Pattern, pp, "cache_dir must match ^/[A-Za-z0-9._/-]{1,255}$"));
        }
        cache_dir = Some(s.to_owned());
    }
    let mut isolation = IsolationSetting::default();
    if let Some(x) = get(m, "isolation") {
        isolation = enum_of(x, &child(p, "isolation"), &IsolationSetting::ALL)?;
    }
    let mut limits = P2Limits::default();
    for (name, min, max, _) in P2Limits::BOUNDS {
        if let Some(x) = get(m, name) {
            limits.set(name, integer(x, &child(p, name), *min, *max)?);
        }
    }
    let mut crash_budget = CrashBudget::default();
    if let Some(x) = get(m, "crash_budget") {
        let pp = child(p, "crash_budget");
        let cm = object(x, &pp)?;
        let names: Vec<&str> = CrashBudget::BOUNDS.iter().map(|(n, ..)| *n).collect();
        fields(cm, &pp, &names, &[])?;
        for (name, min, max, _) in CrashBudget::BOUNDS {
            if let Some(y) = get(cm, name) {
                crash_budget.set(name, integer(y, &child(&pp, name), *min, *max)?);
            }
        }
    }
    let mut mpk = false;
    if let Some(x) = get(m, "mpk") {
        mpk = boolean(x, &child(p, "mpk"))?;
    }
    let mut modules: Vec<P2Module> = Vec::new();
    if let Some(x) = get(m, "modules") {
        let pp = child(p, "modules");
        let items = array(x, &pp, 1, p2::MAX_P2_MODULES)?;
        for (i, it) in items.iter().enumerate() {
            let mp = index(&pp, i);
            let md = p2_module(it, &mp, &limits)?;
            if modules.iter().any(|o| o.id == md.id) {
                return Err(ConfigError::new(E::DuplicateModule, child(&mp, "id"), "duplicate p2 module id"));
            }
            modules.push(md);
        }
    }
    if modules.is_empty() {
        // Unreachable after the required/minItems checks; fail closed rather than build an empty table.
        return Err(ConfigError::new(E::MinItems, child(p, "modules"), "p2 block declares no module"));
    }
    Ok(P2Block { worker, cache_dir, isolation, limits, crash_budget, mpk, modules })
}

fn p2_module(v: &JsonValue, p: &str, block: &P2Limits) -> R<P2Module> {
    let m = object(v, p)?;
    fields(m, p, P2Module::MEMBERS, &["id", "path", "sha256"])?;
    let mut id = String::new();
    if let Some(x) = get(m, "id") {
        let pp = child(p, "id");
        let s = string(x, &pp)?;
        if !is_listener_name(s) {
            return Err(ConfigError::new(E::Pattern, pp, "module id must match ^[a-z][a-z0-9-]{0,31}$"));
        }
        id = s.to_owned();
    }
    let mut path = String::new();
    if let Some(x) = get(m, "path") {
        let pp = child(p, "path");
        let s = string(x, &pp)?;
        if !is_wasm_path(s) {
            return Err(ConfigError::new(E::Pattern, pp, "module path must match ^/[A-Za-z0-9._/-]{1,250}\\.wasm$"));
        }
        path = s.to_owned();
    }
    let mut sha256 = [0u8; 32];
    if let Some(x) = get(m, "sha256") {
        let pp = child(p, "sha256");
        let s = string(x, &pp)?;
        let Some(d) = hex32(s) else {
            return Err(ConfigError::new(E::Pattern, pp, "sha256 must match ^[0-9a-f]{64}$"));
        };
        sha256 = d;
    }
    let mut tenancy = Tenancy::default();
    if let Some(x) = get(m, "tenancy") {
        tenancy = enum_of(x, &child(p, "tenancy"), &Tenancy::ALL)?;
    }
    // Overrides carry the block's bounds; absent = the block's (already defaulted) value.
    let over = |name: &str, (lo, hi): (u64, u64), dflt: u64| -> R<u64> {
        match get(m, name) {
            Some(x) => integer(x, &child(p, name), lo, hi),
            None => Ok(dflt),
        }
    };
    let fuel = over("fuel", P2Limits::FUEL_BOUNDS, block.fuel)?;
    let wall_ms = over("wall_ms", P2Limits::WALL_MS_BOUNDS, block.wall_ms)?;
    let memory_mib = over("memory_mib", P2Limits::MEMORY_MIB_BOUNDS, block.memory_mib)?;
    Ok(P2Module { id, path, sha256, tenancy, fuel, wall_ms, memory_mib })
}

/// Cross-field: every `{"wasm": id}` route target names a declared module (no `p2` block means no module exists).
fn wasm_modules(vhosts: &[Vhost], p2: Option<&P2Block>) -> R<()> {
    for (i, vh) in vhosts.iter().enumerate() {
        for (j, r) in vh.routes.iter().enumerate() {
            if let RouteTarget::Wasm { module } = &r.to
                && p2.and_then(|b| b.module(module)).is_none()
            {
                let why = if p2.is_some() {
                    "wasm route names an undeclared p2 module"
                } else {
                    "wasm route without a p2 block"
                };
                return Err(ConfigError::new(E::UnknownModule, format!("/vhosts/{i}/routes/{j}/to/wasm"), why));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    //! Phase-7 adapter families against an injected pin catalogue (the embedded engine-pins.toml carries no
    //! mariadb/crdb entry until P7-oracle-adapters-001 adds them; until then the real parser refuses them with
    //! `UnknownPin`, see tests/p7.rs).
    use super::*;
    use crate::data::parse_all_pins;
    use crate::{FieldId, ResolvedData, SchemaProvider, Unresolved};

    const PINS: &str = r#"
[sqlite]
version = "3.54.1"
[engines.pg18]
kind = "postgres"
policy = "allow"
[engines.maria118]
kind = "mariadb"
policy = "allow"
[engines.crdb254]
kind = "crdb"
policy = "allow"
"#;

    fn doc(backends: &str, data: &str) -> String {
        format!(
            r#"{{"v":1,"listeners":[{{"name":"a","bind":"b","profile":"P-PUBLIC-WEB"}}],
 "vhosts":[{{"host":"a","routes":[{{"id":1,"path":"/n","to":{{"upstream":"u"}},"authz":"n","data":{data}}}]}}],
 "data":{{"backends":{backends}}}}}"#
        )
    }

    const MIXED: &str = r#"[{"id":"m","engine":"mariadb","dsn_ref":"env:MARIA_DSN","pin":"maria118"},
 {"id":"pg","engine":"postgres","dsn_ref":"env:PG_DSN","pin":"pg18"},
 {"id":"c","engine":"crdb","dsn_ref":"cred:crdb","pin":"crdb254","max_conns":4}]"#;
    const CAP_M: &str = r#"[{"backend":"m","collection":"notes","ops":["select"],"columns":["id"]}]"#;
    const CAP_PG: &str = r#"[{"backend":"pg","collection":"notes","ops":["select"],"columns":["id"]}]"#;

    fn parse_t(s: &str) -> R<Config> {
        parse_with(s.as_bytes(), &parse_all_pins(PINS))
    }

    #[test]
    fn adapter_families_parse_apart_from_golden_backends_in_document_order() {
        let c = parse_t(&doc(MIXED, CAP_M)).unwrap();
        let d = c.data().unwrap();
        assert_eq!(d.backends().iter().map(|b| b.id.as_str()).collect::<Vec<_>>(), vec!["pg"]);
        let a: Vec<(&str, AdapterFamily, u64)> =
            d.adapters().iter().map(|b| (b.id.as_str(), b.family, b.max_conns)).collect();
        assert_eq!(a, vec![("m", AdapterFamily::Mariadb, 16), ("c", AdapterFamily::Crdb, 4)]);
        assert!(d.declares("m") && d.declares("pg") && !d.declares("x"));
        // The effective form keeps document order and the family names, and round-trips to the same hash.
        let eff = std::str::from_utf8(c.effective_json()).unwrap();
        let im = eff.find("\"mariadb\"").unwrap();
        let ipg = eff.find("\"postgres\"").unwrap();
        let ic = eff.find("\"crdb\"").unwrap();
        assert!(im < ipg && ipg < ic, "{eff}");
        assert_eq!(parse_t(eff).unwrap().config_hash(), c.config_hash());
    }

    #[test]
    fn adapter_family_pin_rules() {
        let one = |e: &str, dsn: &str, pin: &str| {
            parse_t(&doc(&format!(r#"[{{"id":"m","engine":"{e}","dsn_ref":"{dsn}","pin":"{pin}"}}]"#), CAP_M))
        };
        assert!(one("mariadb", "env:X", "maria118").is_ok());
        assert!(one("crdb", "env:X", "crdb254").is_ok());
        let k = |r: R<Config>| r.err().map(|e| (e.kind(), e.pointer().to_owned()));
        let at = |s: &str| format!("/data/backends/0/{s}");
        assert_eq!(k(one("mariadb", "env:X", "crdb254")), Some((E::PinEngineMismatch, at("pin"))));
        assert_eq!(k(one("crdb", "env:X", "pg18")), Some((E::PinEngineMismatch, at("pin"))));
        assert_eq!(k(one("postgres", "env:X", "crdb254")), Some((E::PinEngineMismatch, at("pin"))));
        assert_eq!(k(one("mariadb", "env:X", "maria999")), Some((E::UnknownPin, at("pin"))));
        // Network engines: path: is refused.
        assert_eq!(k(one("mariadb", "path:/x.db", "maria118")), Some((E::Pattern, at("dsn_ref"))));
        assert_eq!(k(one("mysql", "env:X", "maria118")), Some((E::Enum, at("engine"))));
        // Ids are unique across golden and adapter backends.
        let dup = r#"[{"id":"m","engine":"postgres","dsn_ref":"env:A","pin":"pg18"},
          {"id":"m","engine":"mariadb","dsn_ref":"env:B","pin":"maria118"}]"#;
        assert_eq!(k(parse_t(&doc(dup, CAP_M))), Some((E::DuplicateBackend, "/data/backends/1/id".to_owned())));
    }

    /// A provider that knows golden backends only, like every assembly before Phase 7.
    struct GoldenOnly;
    impl SchemaProvider for GoldenOnly {
        fn field(&self, _: &Backend, _: &str, _: &str) -> Result<FieldId, Unresolved> {
            Ok(1)
        }
    }
    struct Both;
    impl SchemaProvider for Both {
        fn field(&self, _: &Backend, _: &str, _: &str) -> Result<FieldId, Unresolved> {
            Ok(1)
        }
        fn adapter_field(&self, b: &AdapterBackend, _: &str, _: &str) -> Result<FieldId, Unresolved> {
            if b.family == AdapterFamily::Mariadb { Ok(7) } else { Err(Unresolved::NoCollection) }
        }
    }

    #[test]
    fn an_endowment_on_an_adapter_backend_fails_closed_unless_the_assembly_wires_the_family() {
        let c = parse_t(&doc(MIXED, CAP_M)).unwrap();
        let e = c.resolve_data(&GoldenOnly).unwrap_err();
        assert_eq!((e.kind(), e.pointer()), (E::SchemaUnavailable, "/vhosts/0/routes/0/data/0/backend"));
        let r = c.resolve_data(&Both).unwrap();
        assert!(matches!(&r[0].data, ResolvedData::Caps(caps) if caps[0].fields == vec![7] && caps[0].backend == "m"));
        // Golden caps resolve exactly as before, whatever adapter backends are declared.
        let g = parse_t(&doc(MIXED, CAP_PG)).unwrap();
        assert!(g.resolve_data(&GoldenOnly).is_ok());
    }
}
