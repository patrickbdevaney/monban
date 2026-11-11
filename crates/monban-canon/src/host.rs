//! Bare host (SNI), `:authority`/Host and Origin. Host rule: ASCII-lowercase exact A-label match; no IDNA and no
//! WHATWG parsing on ingress; `xn--` labels get a structural RFC 3492 check only (never a mapping).

use alloc::vec::Vec;

use monban_types::{
    Canon,
    kind::{Authority, Origin, Sni},
};

use crate::limits::MAX_HOST;
use crate::request::Scheme;
use crate::{Reject, punycode, seal, unicode};

/// Host check shared by the SNI, authority and Origin kinds: Ok(lowercased host) or the reason code.
pub(crate) fn host_inner(h: &[u8]) -> Result<Vec<u8>, &'static str> {
    if h.is_empty() {
        return Err("empty");
    }
    if !h.is_ascii() {
        return Err("non-ASCII (A-labels only, no IDNA on ingress)");
    }
    if h.len() > MAX_HOST {
        return Err("too long");
    }
    let h = h.to_ascii_lowercase();
    if h.last() == Some(&b'.') {
        return Err("trailing dot");
    }
    let labels: Vec<&[u8]> = h.split(|&b| b == b'.').collect();
    let last: &[u8] = labels.last().copied().unwrap_or(b"");
    let all_digits = |l: &[u8]| !l.is_empty() && l.iter().all(u8::is_ascii_digit);
    let ends_in_number = all_digits(last)
        || last
            .strip_prefix(b"0x")
            .is_some_and(|r| r.iter().all(|&b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    if ends_in_number {
        // WHATWG "ends in a number": only the canonical dotted quad is accepted.
        if labels.len() != 4 || !labels.iter().all(|l| all_digits(l)) {
            return Err("non-canonical IPv4");
        }
        for l in &labels {
            let leading_zero = l.len() > 1 && l.first() == Some(&b'0');
            let value = l.iter().try_fold(0u32, |a, &d| a.checked_mul(10)?.checked_add(u32::from(d - b'0')));
            if leading_zero || !matches!(value, Some(v) if v <= 255) {
                return Err("non-canonical IPv4");
            }
        }
        return Ok(h);
    }
    for l in &labels {
        let ldh = (1..=63).contains(&l.len())
            && l.iter().all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && l.first() != Some(&b'-')
            && l.last() != Some(&b'-');
        if !ldh {
            return Err("label not LDH");
        }
        if l.get(2..4) == Some(b"--") {
            let Some(body) = l.strip_prefix(b"xn--") else {
                return Err("reserved R-LDH label");
            };
            if !alabel_ok(body) {
                return Err("malformed A-label");
            }
        }
    }
    Ok(h)
}

/// Structural RFC 3492 check of an A-label's ACE suffix: it must decode to a non-ASCII string of letters, marks,
/// digits or '-', already NFC and already lowercase, that re-encodes to exactly the same suffix. Nothing is
/// mapped; the host is matched byte-exactly as the A-label.
fn alabel_ok(body: &[u8]) -> bool {
    if body.is_empty() {
        return false;
    }
    let Some(u) = punycode::decode(body) else {
        return false;
    };
    if u.iter().all(char::is_ascii) {
        return false;
    }
    if !u.iter().all(|&c| c == '-' || unicode::is_lmn(c)) {
        return false;
    }
    if !unicode::is_nfc_chars(&u) || u.iter().any(|&c| unicode::lowercase_changes(c)) {
        return false;
    }
    punycode::encode(&u).is_some_and(|e| e == body)
}

/// Canonicalize a bare host as sent in SNI (and used for the `host` oracle kind).
pub fn canon_sni(input: &[u8]) -> Result<Canon<Sni>, Reject> {
    host_inner(input).map(seal).map_err(|r| Reject::new(400, "host", r))
}

fn port_suffix(p: &[u8], scheme: Scheme) -> Result<Vec<u8>, &'static str> {
    if p.is_empty() || p.len() > 5 || !p.iter().all(u8::is_ascii_digit) || (p.len() > 1 && p.first() == Some(&b'0')) {
        return Err("bad port");
    }
    let n = p.iter().fold(0u32, |a, &d| a.saturating_mul(10).saturating_add(u32::from(d - b'0')));
    if !(1..=65535).contains(&n) {
        return Err("bad port");
    }
    if n == scheme.default_port() {
        return Ok(Vec::new());
    }
    let mut v = Vec::with_capacity(6);
    v.push(b':');
    v.extend_from_slice(p);
    Ok(v)
}

pub(crate) fn authority_inner(a: &[u8], scheme: Scheme) -> Result<Vec<u8>, &'static str> {
    if a.contains(&b'@') {
        return Err("userinfo");
    }
    if a.iter().any(|&b| b == b'[' || b == b']') {
        return Err("IP-literal not served");
    }
    let (host, port) = match a.iter().rposition(|&b| b == b':') {
        Some(i) => (a.get(..i).unwrap_or(b""), Some(a.get(i.saturating_add(1)..).unwrap_or(b""))),
        None => (a, None),
    };
    let suffix = match port {
        Some(p) => port_suffix(p, scheme)?,
        None => Vec::new(),
    };
    let mut h = host_inner(host)?;
    h.extend_from_slice(&suffix);
    Ok(h)
}

/// Canonicalize an `:authority` / Host value (`host[:port]`): userinfo and IP-literals rejected, host lowercased,
/// the scheme's default port stripped.
pub fn canon_authority(input: &[u8], scheme: Scheme) -> Result<Canon<Authority>, Reject> {
    authority_inner(input, scheme).map(seal).map_err(|r| Reject::new(400, "authority", r))
}

pub(crate) fn origin_inner(o: &[u8]) -> Result<Vec<u8>, &'static str> {
    if o == b"null" {
        return Err("opaque 'null'");
    }
    if o.iter().any(|&b| b <= 0x20 || b >= 0x7F) {
        return Err("non-ASCII/control/space");
    }
    // ^[A-Za-z][A-Za-z0-9+.-]*://[^/?#\\]*$
    let colon = o.iter().position(|&b| b == b':').ok_or("not a serialized origin")?;
    let (scheme, rest) = (o.get(..colon).unwrap_or(b""), o.get(colon..).unwrap_or(b""));
    let scheme_ok = scheme.first().is_some_and(u8::is_ascii_alphabetic)
        && scheme.iter().all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-'));
    let auth = rest.strip_prefix(b"://").ok_or("not a serialized origin")?;
    if !scheme_ok || auth.iter().any(|&b| matches!(b, b'/' | b'?' | b'#' | b'\\')) {
        return Err("not a serialized origin");
    }
    let scheme = Scheme::parse(&scheme.to_ascii_lowercase()).map_err(|_| "scheme")?;
    if auth.contains(&b'%') {
        return Err("percent-encoding in host");
    }
    let a = authority_inner(auth, scheme)?;
    let mut out = Vec::with_capacity(a.len().saturating_add(8));
    out.extend_from_slice(scheme.as_str().as_bytes());
    out.extend_from_slice(b"://");
    out.extend_from_slice(&a);
    Ok(out)
}

/// Canonicalize a serialized Origin (RFC 6454): `http`/`https` only, `null` rejected, authority as in
/// [`canon_authority`] with the scheme's default port stripped. Rejects answer 403.
pub fn canon_origin(input: &[u8]) -> Result<Canon<Origin>, Reject> {
    origin_inner(input).map(seal).map_err(|r| Reject::new(403, "origin", r))
}
