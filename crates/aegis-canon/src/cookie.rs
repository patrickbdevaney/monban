//! Cookie request header (RFC 6265bis, strict): `name=value` pairs separated by `"; "`, names are tchar tokens
//! (no `$` legacy names, no '%'), values are cookie-octets (no quotes, no whitespace), duplicate names
//! (ASCII case-insensitive) and miscapitalized `__Host-`/`__Secure-` prefixes rejected. Non-ASCII (NBSP etc.) is
//! never trimmed, it is rejected.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use aegis_types::{Canon, kind::CookieJar};

use crate::{Reject, is_tchar, seal};

const fn rej(reason: &'static str) -> Reject {
    Reject::new(400, "cookie", reason)
}

fn is_cookie_octet(b: u8) -> bool {
    matches!(b, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E)
}

fn trim_ows(mut s: &[u8]) -> &[u8] {
    while let Some((&b, rest)) = s.split_first() {
        if b == b' ' || b == b'\t' {
            s = rest;
        } else {
            break;
        }
    }
    while let Some((&b, rest)) = s.split_last() {
        if b == b' ' || b == b'\t' {
            s = rest;
        } else {
            break;
        }
    }
    s
}

/// Canonicalize a Cookie header value to `n1=v1; n2=v2`.
pub fn canon_cookie(input: &[u8]) -> Result<Canon<CookieJar>, Reject> {
    if !input.is_ascii() {
        return Err(rej("non-ASCII (NBSP etc. never trimmed)"));
    }
    let c = trim_ows(input);
    if c.is_empty() {
        return Err(rej("empty"));
    }
    let mut out: Vec<u8> = Vec::with_capacity(c.len());
    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    for (i, part) in c.split(|&b| b == b';').enumerate() {
        let mut part = part;
        if i > 0 {
            while let Some(rest) = part.strip_prefix(b" ") {
                part = rest;
            }
        }
        if part.is_empty() {
            return Err(rej("empty cookie-pair"));
        }
        let eq = part.iter().position(|&b| b == b'=').ok_or(rej("nameless/valueless pair"))?;
        let (k, v) = (part.get(..eq).unwrap_or(b""), part.get(eq.saturating_add(1)..).unwrap_or(b""));
        if k.is_empty() || !k.iter().all(|&b| is_tchar(b)) {
            return Err(rej("bad name"));
        }
        if k.first() == Some(&b'$') || k.contains(&b'%') {
            return Err(rej("legacy/percent-encoded name"));
        }
        let kl = k.to_ascii_lowercase();
        let prefixed = kl.starts_with(b"__host-") || kl.starts_with(b"__secure-");
        if prefixed && !(k.starts_with(b"__Host-") || k.starts_with(b"__Secure-")) {
            return Err(rej("miscapitalized prefix"));
        }
        if seen.contains(&kl) {
            return Err(rej("duplicate name"));
        }
        if v.first() == Some(&b'"') {
            return Err(rej("quoted value"));
        }
        if !v.iter().all(|&b| is_cookie_octet(b)) {
            return Err(rej("bad value octet"));
        }
        seen.insert(kl);
        if i > 0 {
            out.extend_from_slice(b"; ");
        }
        out.extend_from_slice(k);
        out.push(b'=');
        out.extend_from_slice(v);
    }
    Ok(seal(out))
}
