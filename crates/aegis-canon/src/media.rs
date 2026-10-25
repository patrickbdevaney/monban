//! Media type (Content-Type): `type/subtype` tchar tokens (no `*`), lowercased; parameters `; name=value` with
//! tchar names (lowercased) and unquoted tchar values (the `charset` value lowercased), no duplicates, no empty
//! parameters, no surrounding whitespace. Rejects answer 415.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use aegis_types::{Canon, kind::MediaType};

use crate::{Reject, is_tchar, seal};

const fn rej(reason: &'static str) -> Reject {
    Reject::new(415, "media-type", reason)
}

/// Canonicalize a media type to `type/subtype; name=value; ...`.
pub fn canon_media_type(input: &[u8]) -> Result<Canon<MediaType>, Reject> {
    if input.is_empty() || input.iter().any(|b| !(0x20..0x7F).contains(b)) {
        return Err(rej("empty/non-ASCII/control"));
    }
    if input.first() == Some(&b' ') || input.last() == Some(&b' ') {
        return Err(rej("surrounding whitespace"));
    }
    let mut parts = input.split(|&b| b == b';');
    let ess = parts.next().unwrap_or(b"");
    let mut halves = ess.split(|&b| b == b'/');
    let (Some(t), Some(s), None) = (halves.next(), halves.next(), halves.next()) else {
        return Err(rej("essence"));
    };
    let tok = |x: &[u8]| !x.is_empty() && x.iter().all(|&b| is_tchar(b) && b != b'*');
    if !tok(t) || !tok(s) {
        return Err(rej("essence"));
    }
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    out.extend_from_slice(&t.to_ascii_lowercase());
    out.push(b'/');
    out.extend_from_slice(&s.to_ascii_lowercase());
    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    for p in parts {
        let mut p = p;
        while let Some(rest) = p.strip_prefix(b" ") {
            p = rest;
        }
        if p.is_empty() {
            return Err(rej("empty parameter"));
        }
        let eq = p.iter().position(|&b| b == b'=').ok_or(rej("parameter without value"))?;
        let (n, v) = (p.get(..eq).unwrap_or(b""), p.get(eq.saturating_add(1)..).unwrap_or(b""));
        if n.is_empty() || !n.iter().all(|&b| is_tchar(b)) {
            return Err(rej("bad parameter name"));
        }
        if v.first() == Some(&b'"') {
            return Err(rej("quoted parameter value"));
        }
        if v.is_empty() || !v.iter().all(|&b| is_tchar(b)) {
            return Err(rej("bad parameter value"));
        }
        let n = n.to_ascii_lowercase();
        let v = if n == b"charset" { v.to_ascii_lowercase() } else { v.to_vec() };
        out.extend_from_slice(b"; ");
        out.extend_from_slice(&n);
        out.push(b'=');
        out.extend_from_slice(&v);
        if !seen.insert(n) {
            return Err(rej("duplicate parameter"));
        }
    }
    Ok(seal(out))
}
