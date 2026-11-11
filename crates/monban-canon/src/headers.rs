//! HTTP/1.1 header block (H1 grammar (c), CANON-2). Every field is a singleton unless it is a declared list field;
//! obs-fold, obs-text, controls, whitespace before the colon, CL+TE, TE other than exactly `chunked`, a malformed
//! Content-Length and an empty Host are rejected. Names are lowercased, values trimmed of OWS.
//!
//! The canonical form is `name: value\r\n` per field, in input order; read it back with [`header_fields`].

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use monban_types::{Canon, kind::HeaderSet};

use crate::{Reject, is_tchar, seal};

const fn rej(reason: &'static str) -> Reject {
    Reject::new(400, "headers", reason)
}

const LIST_FIELDS: &[&[u8]] = &[
    b"accept",
    b"accept-charset",
    b"accept-encoding",
    b"accept-language",
    b"cache-control",
    b"pragma",
    b"via",
    b"warning",
    b"te",
    b"if-match",
    b"if-none-match",
];

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

/// Canonicalize a header block given as raw field lines (without CRLF).
pub fn canon_headers(lines: &[&[u8]]) -> Result<Canon<HeaderSet>, Reject> {
    let mut fields: Vec<(Vec<u8>, &[u8])> = Vec::with_capacity(lines.len());
    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    for &ln in lines {
        if !ln.is_ascii() {
            return Err(rej("obs-text"));
        }
        if matches!(ln.first(), Some(b' ' | b'\t')) {
            return Err(rej("obs-fold"));
        }
        if ln.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7F) {
            return Err(rej("control character"));
        }
        let colon = ln.iter().position(|&b| b == b':').ok_or(rej("no colon"))?;
        let (n, v) = (ln.get(..colon).unwrap_or(b""), ln.get(colon.saturating_add(1)..).unwrap_or(b""));
        if n.is_empty() || !n.iter().all(|&b| is_tchar(b)) {
            return Err(rej("bad field name (whitespace before colon?)"));
        }
        let n = n.to_ascii_lowercase();
        let v = trim_ows(v);
        if seen.contains(&n) && !LIST_FIELDS.contains(&n.as_slice()) {
            return Err(rej("duplicate singleton field"));
        }
        seen.insert(n.clone());
        fields.push((n, v));
    }
    if seen.contains(b"content-length".as_slice()) && seen.contains(b"transfer-encoding".as_slice()) {
        return Err(rej("CL+TE"));
    }
    for (n, v) in &fields {
        match n.as_slice() {
            b"transfer-encoding" if *v != b"chunked" => return Err(rej("TE not exactly 'chunked'")),
            b"content-length"
                if v.is_empty()
                    || !v.iter().all(u8::is_ascii_digit)
                    || (v.len() > 1 && v.first() == Some(&b'0'))
                    || v.len() > 18 =>
            {
                return Err(rej("bad Content-Length"));
            }
            b"host" if v.is_empty() => return Err(rej("empty Host")),
            _ => {}
        }
    }
    let mut out = Vec::new();
    for (n, v) in &fields {
        out.extend_from_slice(n);
        out.extend_from_slice(b": ");
        out.extend_from_slice(v);
        out.extend_from_slice(b"\r\n");
    }
    Ok(seal(out))
}

/// Iterator over the `(lowercased name, value)` fields of a canonical header set, in order.
#[derive(Debug, Clone)]
pub struct HeaderFields<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for HeaderFields<'a> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let end = self.rest.windows(2).position(|w| w == b"\r\n").unwrap_or(self.rest.len());
        let line = self.rest.get(..end).unwrap_or(b"");
        self.rest = self.rest.get(end.saturating_add(2)..).unwrap_or(b"");
        let colon = line.iter().position(|&b| b == b':').unwrap_or(line.len());
        let name = line.get(..colon).unwrap_or(b"");
        let value = line.get(colon.saturating_add(2)..).unwrap_or(b"");
        Some((name, value))
    }
}

/// Read back a canonical header set.
pub fn header_fields(c: &Canon<HeaderSet>) -> HeaderFields<'_> {
    HeaderFields { rest: c.as_bytes() }
}
