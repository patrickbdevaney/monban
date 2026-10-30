//! Effective-config JSON: written here as plain JSON text, then canonicalized by aegis-canon's serializer
//! (`canon_json`), so the canonical form (member order, escapes, number layout) is the one CANON-1 owner's.

use std::fmt::Write as _;

use aegis_canon::canon_json;

use crate::{Canon, Config, ConfigError, DataBlock, ErrorKind, Limits, MAX_CONFIG_BYTES, RouteData, RouteTarget};

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

/// The `data` block with backend defaults (`max_conns`, `op_budget_ms`) applied.
fn data_block(d: &DataBlock, out: &mut String) {
    out.push('{');
    key("backends", out);
    out.push('[');
    for (i, b) in d.backends().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        key("id", out);
        string(&b.id, out);
        out.push(',');
        key("engine", out);
        string(b.engine.as_str(), out);
        out.push(',');
        key("dsn_ref", out);
        string(&b.dsn_ref.to_f8(), out);
        out.push(',');
        key("pin", out);
        string(&b.pin, out);
        out.push(',');
        key("max_conns", out);
        let _ = write!(out, "{},", b.max_conns);
        key("op_budget_ms", out);
        let _ = write!(out, "{}", b.op_budget_ms);
        out.push('}');
    }
    out.push_str("]}");
}

fn text(c: &Config) -> String {
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
    o.push('}');
    o
}

/// Canonical bytes of the effective config. CFG-2 holds the effective form to the same cap as the input
/// (defaults and integer re-layout such as `1e9` → `1000000000` can grow a document).
pub(crate) fn canonical(c: &Config) -> Result<Box<[u8]>, ConfigError> {
    let t = text(c);
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
