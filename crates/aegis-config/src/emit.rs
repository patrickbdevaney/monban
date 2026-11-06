//! Effective-config JSON: written here as plain JSON text, then canonicalized by aegis-canon's serializer
//! (`canon_json`), so the canonical form (member order, escapes, number layout) is the one CANON-1 owner's.

use std::fmt::Write as _;

use aegis_canon::canon_json;

use crate::data::Decl;
use crate::{
    Admission, Canon, Config, ConfigError, CrashBudget, DataBlock, DsnRef, ErrorKind, Front, Limits, Listener,
    MAX_CONFIG_BYTES, P2Block, P2Limits, RouteData, RouteTarget, TlsBlock,
};

fn string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn key(k: &str, out: &mut String) {
    string(k, out);
    out.push(':');
}

fn limits(l: &Limits, out: &mut String) {
    out.push('{');
    for (i, ((name, ..), v)) in Limits::BOUNDS.iter().zip(l.values()).enumerate() {
        if i > 0 {
            out.push(',');
        }
        key(name, out);
        let _ = write!(out, "{v}");
    }
    out.push('}');
}

fn canon(c: &Canon, out: &mut String) {
    out.push('{');
    for (name, val) in Canon::FIXED {
        key(name, out);
        string(val, out);
        out.push(',');
    }
    key("query", out);
    string(c.query.as_str(), out);
    out.push('}');
}

fn str_array<'a>(items: impl Iterator<Item = &'a str>, out: &mut String) {
    out.push('[');
    for (i, s) in items.enumerate() {
        if i > 0 {
            out.push(',');
        }
        string(s, out);
    }
    out.push(']');
}

/// `routes[].data`: the literal for `Unrestricted` (so the ledger sees every grant), else the cap list. Ops are
/// emitted in F4 order (they are a set); columns in document order.
fn route_data(d: &RouteData, out: &mut String) {
    match d {
        RouteData::Unrestricted => string(crate::UNRESTRICTED, out),
        RouteData::Caps(list) => {
            out.push('[');
            for (k, c) in list.as_slice().iter().enumerate() {
                if k > 0 {
                    out.push(',');
                }
                out.push('{');
                key("backend", out);
                string(c.backend(), out);
                out.push(',');
                key("collection", out);
                string(c.collection(), out);
                out.push(',');
                key("ops", out);
                let ops = c.ops();
                str_array(ops.iter().map(|o| o.as_str()), out);
                out.push(',');
                key("columns", out);
                str_array(c.columns().iter().map(String::as_str), out);
                out.push('}');
            }
            out.push(']');
        }
    }
}

/// One backend object (golden or adapter family), defaults applied.
fn backend(id: &str, engine: &str, dsn: &DsnRef, pin: &str, max_conns: u64, op_budget_ms: u64, out: &mut String) {
    out.push('{');
    key("id", out);
    string(id, out);
    out.push(',');
    key("engine", out);
    string(engine, out);
    out.push(',');
    key("dsn_ref", out);
    string(&dsn.to_f8(), out);
    out.push(',');
    key("pin", out);
    string(pin, out);
    out.push(',');
    key("max_conns", out);
    let _ = write!(out, "{max_conns},");
    key("op_budget_ms", out);
    let _ = write!(out, "{op_budget_ms}");
    out.push('}');
}

/// The `data` block with backend defaults (`max_conns`, `op_budget_ms`) applied, backends in document order.
fn data_block(d: &DataBlock, out: &mut String) {
    out.push('{');
    key("backends", out);
    out.push('[');
    // `order` indexes exist by construction (the parser pushes both together); a missing one is skipped, never a
    // panic.
    let mut items: Vec<String> = Vec::with_capacity(d.order.len());
    for decl in &d.order {
        let mut o = String::new();
        match *decl {
            Decl::Golden(i) => {
                if let Some(b) = d.backends.get(i) {
                    backend(&b.id, b.engine.as_str(), &b.dsn_ref, &b.pin, b.max_conns, b.op_budget_ms, &mut o);
                }
            }
            Decl::Adapter(i) => {
                if let Some(b) = d.adapters.get(i) {
                    backend(&b.id, b.family.as_str(), &b.dsn_ref, &b.pin, b.max_conns, b.op_budget_ms, &mut o);
                }
            }
        }
        if !o.is_empty() {
            items.push(o);
        }
    }
    out.push_str(&items.join(","));
    out.push_str("]}");
}

/// Phase-7 listener members. `front` is printed only when it is not the default or when `dump` is set, so a
/// pre-Phase-7 config keeps its hashed effective form (and an explicit `"front":"epoll"` hashes like an absent one).
fn listener_p7(l: &Listener, dump: bool, out: &mut String) {
    if let Some(pp) = &l.proxy_protocol {
        out.push(',');
        key("proxy_protocol", out);
        out.push('{');
        key("trusted", out);
        out.push('[');
        for (i, c) in pp.trusted().iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            string(&c.to_string(), out);
        }
        out.push_str("]}");
    }
    if let Some(routes) = &l.l4 {
        out.push(',');
        key("l4", out);
        out.push('[');
        for (i, r) in routes.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('{');
            key("sni", out);
            string(&r.sni, out);
            out.push(',');
            key("upstream", out);
            string(&r.upstream(), out);
            out.push('}');
        }
        out.push(']');
    }
    if dump || l.front != Front::Epoll {
        out.push(',');
        key("front", out);
        string(l.front.as_str(), out);
    }
}

/// The `admission` block with every default applied.
fn admission_block(a: &Admission, out: &mut String) {
    let _ = write!(out, "{{\"per_ip\":{{\"rate_per_s\":{},\"burst\":{}}},", a.per_ip.rate_per_s, a.per_ip.burst);
    bounded(Admission::BOUNDS, a.values(), out);
    out.push('}');
}

/// The `tls` block (no defaults to apply; `trust_anchor_id` and `listeners` printed only when present).
fn tls_block(t: &TlsBlock, out: &mut String) {
    out.push('{');
    key("credentials", out);
    out.push('[');
    for (i, c) in t.credentials().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        key("id", out);
        string(c.id(), out);
        out.push(',');
        key("kind", out);
        string(c.kind().as_str(), out);
        if let Some(tai) = c.trust_anchor_id() {
            out.push(',');
            key("trust_anchor_id", out);
            string(&tai.to_string(), out);
        }
        out.push(',');
        key("chain", out);
        string(&c.chain().to_f8(), out);
        out.push(',');
        key("key", out);
        string(&c.key().to_f8(), out);
        if let Some(ls) = c.listeners() {
            out.push(',');
            key("listeners", out);
            str_array(ls.iter().map(String::as_str), out);
        }
        out.push('}');
    }
    out.push_str("]}");
}

/// Integer members `name: value` from a bounds table, comma-separated (no leading or trailing comma).
fn bounded(bounds: &[(&str, u64, u64, u64)], values: Vec<u64>, out: &mut String) {
    for (i, ((name, ..), v)) in bounds.iter().zip(values).enumerate() {
        if i > 0 {
            out.push(',');
        }
        key(name, out);
        let _ = write!(out, "{v}");
    }
}

/// The `p2` block with every default applied: block limits, `isolation`, `crash_budget`, `mpk`, and per module
/// `tenancy` plus the resolved `fuel` / `wall_ms` / `memory_mib` (an absent override means the block's value, so
/// printing it keeps the meaning and makes "absent" and "explicit equal" hash the same). `cache_dir` has no
/// schema default and is printed only when present.
///
/// `resolved = Some(cpus)` (the dump only, never the hashed form) adds `isolation_effective` and `usable_cpus`.
fn p2_block(b: &P2Block, resolved: Option<usize>, out: &mut String) {
    out.push('{');
    key("worker", out);
    string(b.worker(), out);
    if let Some(d) = b.cache_dir() {
        out.push(',');
        key("cache_dir", out);
        string(d, out);
    }
    out.push(',');
    key("isolation", out);
    string(b.isolation().as_str(), out);
    if let Some(cpus) = resolved {
        out.push(',');
        key("isolation_effective", out);
        string(b.effective_isolation(cpus).as_str(), out);
        let _ = write!(out, ",\"usable_cpus\":{cpus}");
    }
    out.push(',');
    bounded(P2Limits::BOUNDS, b.limits().values(), out);
    out.push(',');
    key("crash_budget", out);
    out.push('{');
    bounded(CrashBudget::BOUNDS, b.crash_budget().values(), out);
    out.push('}');
    out.push(',');
    key("mpk", out);
    out.push_str(if b.mpk() { "true" } else { "false" });
    out.push(',');
    key("modules", out);
    out.push('[');
    for (i, m) in b.modules().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        key("id", out);
        string(m.id(), out);
        out.push(',');
        key("path", out);
        string(m.path(), out);
        out.push(',');
        key("sha256", out);
        string(&m.sha256_hex(), out);
        out.push(',');
        key("tenancy", out);
        string(m.tenancy().as_str(), out);
        let _ = write!(out, ",\"fuel\":{},\"wall_ms\":{},\"memory_mib\":{}", m.fuel(), m.wall_ms(), m.memory_mib());
        out.push('}');
    }
    out.push_str("]}");
}

fn text(c: &Config, resolved: Option<usize>) -> String {
    let mut o = String::with_capacity(4096);
    o.push('{');
    key("v", &mut o);
    o.push_str("1,");
    key("listeners", &mut o);
    o.push('[');
    for (i, l) in c.listeners.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push('{');
        key("name", &mut o);
        string(&l.name, &mut o);
        o.push(',');
        key("bind", &mut o);
        string(&l.bind, &mut o);
        o.push(',');
        key("profile", &mut o);
        string(l.profile.as_str(), &mut o);
        if let Some(alpn) = &l.alpn {
            o.push(',');
            key("alpn", &mut o);
            o.push('[');
            for (j, a) in alpn.iter().enumerate() {
                if j > 0 {
                    o.push(',');
                }
                string(a.as_str(), &mut o);
            }
            o.push(']');
        }
        listener_p7(l, resolved.is_some(), &mut o);
        o.push('}');
    }
    o.push_str("],");
    key("vhosts", &mut o);
    o.push('[');
    for (i, h) in c.vhosts.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push('{');
        key("host", &mut o);
        string(&h.host, &mut o);
        o.push(',');
        key("routes", &mut o);
        o.push('[');
        for (j, r) in h.routes.iter().enumerate() {
            if j > 0 {
                o.push(',');
            }
            o.push('{');
            key("id", &mut o);
            let _ = write!(o, "{},", r.id);
            key("path", &mut o);
            string(&r.path, &mut o);
            o.push(',');
            key("to", &mut o);
            o.push('{');
            match &r.to {
                RouteTarget::Upstream { upstream, framing } => {
                    key("upstream", &mut o);
                    string(upstream, &mut o);
                    if let Some(f) = framing {
                        o.push(',');
                        key("framing", &mut o);
                        string(f.as_str(), &mut o);
                    }
                }
                RouteTarget::Static { root } => {
                    key("static", &mut o);
                    string(root, &mut o);
                }
                RouteTarget::Wasm { module } => {
                    key("wasm", &mut o);
                    string(module, &mut o);
                }
            }
            o.push('}');
            if let Some(a) = &r.authz {
                o.push(',');
                key("authz", &mut o);
                string(a, &mut o);
            }
            // Absent data is omitted (never `null`): no capability.
            if let Some(d) = &r.data {
                o.push(',');
                key("data", &mut o);
                route_data(d, &mut o);
            }
            o.push('}');
        }
        o.push_str("]}");
    }
    o.push(']');
    if let Some(a) = &c.admin {
        o.push(',');
        key("admin", &mut o);
        o.push('{');
        if let Some(b) = &a.bind {
            key("bind", &mut o);
            string(b, &mut o);
        }
        o.push('}');
    }
    o.push(',');
    key("limits", &mut o);
    limits(&c.limits, &mut o);
    o.push(',');
    key("canon", &mut o);
    canon(&c.canon, &mut o);
    // Absent data block is omitted (never `null`).
    if let Some(d) = &c.data {
        o.push(',');
        key("data", &mut o);
        data_block(d, &mut o);
    }
    // Absent p2 block is omitted (never `null`).
    if let Some(b) = &c.p2 {
        o.push(',');
        key("p2", &mut o);
        p2_block(b, resolved, &mut o);
    }
    // The admission block is printed only when it differs from the pre-Phase-7 constants (its defaults), so absent
    // and explicit-default documents hash the same and a pre-Phase-7 config keeps its hash. The dump always shows it.
    if resolved.is_some() || c.admission != Admission::default() {
        o.push(',');
        key("admission", &mut o);
        admission_block(&c.admission, &mut o);
    }
    // Absent tls block is omitted (never `null`).
    if let Some(t) = &c.tls {
        o.push(',');
        key("tls", &mut o);
        tls_block(t, &mut o);
    }
    o.push('}');
    o
}

/// Canonical bytes of the effective config. CFG-2 holds the effective form to the same cap as the input
/// (defaults and integer re-layout such as `1e9` → `1000000000` can grow a document).
pub(crate) fn canonical(c: &Config) -> Result<Box<[u8]>, ConfigError> {
    let t = text(c, None);
    let too_large = || ConfigError::new(ErrorKind::TooLarge, "", "effective config exceeds 1 MiB");
    if t.len() > MAX_CONFIG_BYTES {
        return Err(too_large());
    }
    let canon = canon_json(t.as_bytes()).map_err(|_| too_large())?;
    let b = canon.as_bytes();
    if b.len() > MAX_CONFIG_BYTES {
        return Err(too_large());
    }
    Ok(b.into())
}

/// The `--print-effective` dump: the effective form plus the host-resolved P2 path (see `Config::effective_dump`).
/// Falls back to the hashed canonical form if canonicalization fails (it cannot for a parsed config; never panic).
pub(crate) fn dump(c: &Config, usable_cpus: usize) -> Vec<u8> {
    match canon_json(text(c, Some(usable_cpus)).as_bytes()) {
        Ok(d) => d.as_bytes().to_vec(),
        Err(_) => c.effective_json().to_vec(),
    }
}

/// `{"canon":{...},"limits":{...}}` with every schema default, canonical.
pub(crate) fn defaults_json() -> Vec<u8> {
    let mut o = String::from("{");
    key("canon", &mut o);
    canon(&Canon::default(), &mut o);
    o.push(',');
    key("limits", &mut o);
    limits(&Limits::default(), &mut o);
    o.push('}');
    match canon_json(o.as_bytes()) {
        Ok(c) => c.as_bytes().to_vec(),
        // Unreachable (a fixed, small, valid document); fall back to the uncanonicalized text, never panic.
        Err(_) => o.into_bytes(),
    }
}
