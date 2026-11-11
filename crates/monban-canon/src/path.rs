//! Route path (origin-form, no query). CANON-2 with the q4-008 per-clause outcomes (F8 `canon` block):
//! dot segments and encoded `/ \ ; NUL ctrl %` rejected; `//` answered with 308 to the slash-merged path; a trailing
//! slash is its own form; `%80-%FF` kept as opaque uppercase-hex octets, rejected unless the decoded path is strict
//! UTF-8 and NFC.

use alloc::vec::Vec;

use monban_types::{Canon, kind::RoutePath};

use crate::limits::MAX_PATH;
use crate::{Reject, cp_len, is_pchar_lit, is_unreserved, pct_at, push_pct, seal, unicode};

const K: &str = "path";

const fn rej(reason: &'static str) -> Reject {
    Reject::new(400, K, reason)
}

/// Canonicalize a route path. Lengths are in code points; above [`MAX_PATH`] the answer is 414.
pub fn canon_path(input: &[u8]) -> Result<Canon<RoutePath>, Reject> {
    if cp_len(input) > MAX_PATH {
        return Err(Reject::new(414, K, "too long"));
    }
    if input.first() != Some(&b'/') {
        return Err(rej("not origin-form"));
    }
    if input.iter().any(|&b| b == b'?' || b == b'#') {
        return Err(rej("query/fragment in path kind"));
    }
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while let Some(&c) = input.get(i) {
        if c == b'%' {
            let v = pct_at(input, i).ok_or(rej("bad percent-escape"))?;
            if is_unreserved(v) {
                out.push(v); // RFC 3986 6.2.2.2
            } else if matches!(v, b'/' | b'\\' | b';' | 0 | b'%') || v < 0x20 || v == 0x7F {
                return Err(rej("ambiguous percent-escape"));
            } else {
                push_pct(&mut out, v); // 6.2.2.1
            }
            i = i.saturating_add(3);
            continue;
        }
        if c != b'/' && !is_pchar_lit(c) {
            return Err(rej("forbidden character"));
        }
        out.push(c);
        i = i.saturating_add(1);
    }
    let segs: Vec<&[u8]> = out.split(|&b| b == b'/').skip(1).collect();
    if segs.iter().any(|s| *s == b"." || *s == b"..") {
        return Err(rej("dot segment"));
    }
    if out.contains(&b'%') {
        let raw = pct_decode(&out);
        let Ok(text) = core::str::from_utf8(&raw) else {
            return Err(rej("encoded octets are not valid UTF-8"));
        };
        if !unicode::is_nfc(text) {
            return Err(rej("encoded octets are not NFC"));
        }
    }
    if let Some((_, init)) = segs.split_last()
        && init.iter().any(|s| s.is_empty())
    {
        return Err(Reject::redirect(K, "empty segment", merge_slashes(&out).into_boxed_slice()));
    }
    Ok(seal(out))
}

/// Percent-decode an already validated path (every '%' starts a valid escape).
fn pct_decode(p: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(p.len());
    let mut i = 0usize;
    while let Some(&c) = p.get(i) {
        if c == b'%'
            && let Some(v) = pct_at(p, i)
        {
            b.push(v);
            i = i.saturating_add(3);
        } else {
            b.push(c);
            i = i.saturating_add(1);
        }
    }
    b
}

fn merge_slashes(p: &[u8]) -> Vec<u8> {
    let mut o = Vec::with_capacity(p.len());
    for &c in p {
        if !(c == b'/' && o.last() == Some(&b'/')) {
            o.push(c);
        }
    }
    o
}
