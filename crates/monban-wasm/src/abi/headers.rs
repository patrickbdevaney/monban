//! F14 I5 rules for `resp-headers`, checked by the worker before it forwards a `resp-head` (a breach traps the
//! request with code 7). The supervisor re-checks independently against the configured F8 limits; reject, never
//! repair (CANON-2).
//!
//! The worker is not told the configured `limits.max_header_fields` / `limits.max_header_list_size`, so it bounds
//! them by their F8 maxima here; the supervisor holds the configured values and refuses anything above them.
#![forbid(unsafe_code)]

use super::frame::Dec;

/// F8 `limits.max_header_fields` maximum.
pub const MAX_HEADER_FIELDS: u64 = 256;
/// F8 `limits.max_header_list_size` maximum (summed name + value + 32 per field).
pub const MAX_HEADER_LIST: u64 = 65_536;
/// Longest header name.
pub const MAX_NAME: usize = 64;

/// Framing and hop-by-hop fields a module may never set (plus every `proxy-*` field).
const BANNED: &[&[u8]] =
    &[b"content-length", b"transfer-encoding", b"connection", b"keep-alive", b"upgrade", b"te", b"trailer"];

/// Lower-case RFC 9110 tchar.
fn tchar(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn name_ok(n: &[u8]) -> bool {
    !n.is_empty()
        && n.len() <= MAX_NAME
        && n.iter().all(|&b| tchar(b))
        && !BANNED.contains(&n)
        && !n.starts_with(b"proxy-")
}

fn value_ok(v: &[u8]) -> bool {
    let ws = |b: &u8| *b == b' ' || *b == b'\t';
    v.iter().all(|&b| b == b' ' || b == b'\t' || (0x21..=0x7e).contains(&b))
        && !v.first().is_some_and(ws)
        && !v.last().is_some_and(ws)
}

/// Whether `enc` is exactly one `resp-headers` encoding (`[* [name: tstr, value: bstr]]`) that satisfies the I5
/// rules.
pub fn resp_headers_ok(enc: &[u8]) -> bool {
    let mut d = Dec::new(enc);
    let Some(n) = d.u() else { return false };
    if n > MAX_HEADER_FIELDS {
        return false;
    }
    let mut total: u64 = 0;
    for _ in 0..n {
        let (Some(name), Some(value)) = (d.bytes(), d.bytes()) else { return false };
        if !name_ok(name) || !value_ok(value) {
            return false;
        }
        let field = u64::try_from(name.len().saturating_add(value.len()).saturating_add(32)).unwrap_or(u64::MAX);
        total = total.saturating_add(field);
    }
    d.done() && total <= MAX_HEADER_LIST
}
