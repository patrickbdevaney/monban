//! Query string (without the leading '?'). F8 `canon.query`: `opaque` (default) or `typed` per route.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use aegis_types::{Canon, kind::Query};

use crate::limits::MAX_PATH;
use crate::{Reject, cp_len, is_pchar_lit, is_unreserved, pct_at, push_pct, seal};

const K: &str = "query";

const fn rej(reason: &'static str) -> Reject {
    Reject::new(400, K, reason)
}

/// F8 `canon.query`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum QueryMode {
    /// RFC 3986 6.2.2.1/6.2.2.2 only, otherwise byte-exact; never split, reordered or de-duplicated.
    #[default]
    Opaque,
    /// Route-declared parameters: strict `name=value&...`, '&' the only separator, '+' and ambiguous escapes
    /// rejected, duplicate (decoded) names rejected.
    Typed,
}

/// Canonicalize a query. The empty query is accepted as itself; above [`MAX_PATH`] code points the answer is 414.
pub fn canon_query(input: &[u8], mode: QueryMode) -> Result<Canon<Query>, Reject> {
    if input.is_empty() {
        return Ok(seal(Vec::new()));
    }
    if cp_len(input) > MAX_PATH {
        return Err(Reject::new(414, K, "too long"));
    }
    match mode {
        QueryMode::Opaque => opaque(input).map(seal),
        QueryMode::Typed => typed(input).map(seal),
    }
}

/// RFC 3986 query = *( pchar / "/" / "?" ), pchar including ';'.
fn is_query_lit(b: u8) -> bool {
    is_pchar_lit(b) || matches!(b, b';' | b'/' | b'?')
}

fn opaque(q: &[u8]) -> Result<Vec<u8>, Reject> {
    let mut o = Vec::with_capacity(q.len());
    let mut i = 0usize;
    while let Some(&c) = q.get(i) {
        if c == b'%' {
            let v = pct_at(q, i).ok_or(rej("bad percent-escape"))?;
            if is_unreserved(v) {
                o.push(v);
            } else if v < 0x20 || v == 0x7F || v == b'+' {
                return Err(rej("rejected percent-escape"));
            } else {
                push_pct(&mut o, v); // %80-%FF stay opaque octets
            }
            i = i.saturating_add(3);
            continue;
        }
        if !is_query_lit(c) {
            return Err(rej("forbidden character"));
        }
        o.push(c);
        i = i.saturating_add(1);
    }
    // Lexical checks on the raw form only; the output is never split.
    for part in q.split(|&b| b == b'&') {
        if part.is_empty() {
            return Err(rej("empty pair"));
        }
        if part.first() == Some(&b'=') {
            return Err(rej("empty name"));
        }
    }
    Ok(o)
}

fn typed_component(comp: &[u8]) -> Result<Vec<u8>, Reject> {
    let mut o = Vec::with_capacity(comp.len());
    let mut i = 0usize;
    while let Some(&c) = comp.get(i) {
        if c == b'%' {
            let v = pct_at(comp, i).ok_or(rej("bad percent-escape"))?;
            if is_unreserved(v) {
                o.push(v);
            } else if matches!(v, b'&' | b'=' | b';' | b'+' | b'%' | 0) || !(0x20..0x7F).contains(&v) {
                return Err(rej("ambiguous percent-escape"));
            } else {
                push_pct(&mut o, v);
            }
            i = i.saturating_add(3);
            continue;
        }
        let lit = (is_pchar_lit(c) && !matches!(c, b'+' | b'&' | b'=')) || c == b'/' || c == b'?';
        if !lit {
            return Err(rej("forbidden character"));
        }
        o.push(c);
        i = i.saturating_add(1);
    }
    Ok(o)
}

fn typed(q: &[u8]) -> Result<Vec<u8>, Reject> {
    let mut out: Vec<u8> = Vec::with_capacity(q.len());
    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    for part in q.split(|&b| b == b'&') {
        if part.is_empty() {
            return Err(rej("empty pair"));
        }
        let mut comps = part.split(|&b| b == b'=');
        let (Some(n_raw), Some(v_raw), None) = (comps.next(), comps.next(), comps.next()) else {
            return Err(rej("pair must be exactly name=value"));
        };
        let n = typed_component(n_raw)?;
        let v = typed_component(v_raw)?;
        if n.is_empty() {
            return Err(rej("empty name"));
        }
        if !out.is_empty() {
            out.push(b'&');
        }
        out.extend_from_slice(&n);
        out.push(b'=');
        out.extend_from_slice(&v);
        if !seen.insert(n) {
            return Err(rej("duplicate name"));
        }
    }
    Ok(out)
}
