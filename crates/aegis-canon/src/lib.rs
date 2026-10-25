//! Sole identity canonicalizer, CANON-1..8. Reject, never repair (CANON-2).
//!
//! One `canon_*` function per kind (CANON-1). Each takes the raw bytes of one field and returns either the sealed
//! canonical value (`Canon<K>`, constructible only here, CANON-3) or a [`Reject`] that carries the HTTP status and
//! a static reason code. Every function is total: it never panics on any input (the crate denies `unwrap`,
//! `expect`, `panic!` and indexing, and the tests drive each kind with random bytes).
//!
//! | kind | function | statuses |
//! |---|---|---|
//! | route path | [`canon_path`] | 400, 414, 308 (empty segment, with the slash-merged target) |
//! | query (opaque / typed) | [`canon_query`] | 400, 414 |
//! | bare host (SNI) | [`canon_sni`] | 400 |
//! | `:authority` / Host | [`canon_authority`] | 400 |
//! | Origin | [`canon_origin`] | 403 |
//! | header set (H1 grammar (c)) | [`canon_headers`] | 400 |
//! | cookie jar | [`canon_cookie`] | 400 |
//! | media type | [`canon_media_type`] | 415 |
//! | JSON body (strict I-JSON, DEVIATIONS X-2) | [`canon_json`] | 400, 413 |
//! | principal / tenant id | [`canon_tenant`] | 400 |
//! | SNI / authority / Origin binding (CANON-6) | [`canon_request`] | 400, 403, 404, 421 |
//!
//! The only repairs are the RFC 3986 §6.2.2 safe set (uppercase percent-escape hex, decode percent-encoded
//! unreserved characters), ASCII lowercasing of case-insensitive tokens (scheme, host, media type and parameter
//! names, header names, charset value) and stripping the scheme's default port. Hosts are matched as exact
//! ASCII-lowercase A-labels: no IDNA mapping, `xn--` labels get a structural RFC 3492 check only.
//!
//! Idempotence (CANON-7) holds by construction: every canonical output is inside the accepted language and is a
//! fixed point of its canonicalizer (each repair maps into the set it accepts unchanged).
#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

mod cookie;
mod headers;
mod host;
mod json;
mod media;
mod path;
mod punycode;
mod query;
mod request;
mod tenant;
mod unicode;
#[rustfmt::skip]
mod unicode_tables;

use alloc::boxed::Box;
use core::fmt;

pub use cookie::canon_cookie;
pub use headers::{HeaderFields, canon_headers, header_fields};
pub use host::{canon_authority, canon_origin, canon_sni};
pub use json::{JsonValue, canon_json, parse_json};
pub use media::canon_media_type;
pub use path::canon_path;
pub use query::{QueryMode, canon_query};
pub use request::{Proto, RequestIdentity, Scheme, Vhost, canon_request};
pub use tenant::{TenantSlug, canon_tenant};
/// Unicode version of the NFC and A-label validity tables (must equal the canon-diff reference's).
pub use unicode_tables::UNICODE_VERSION;

pub use aegis_types::kind;
pub use aegis_types::{Canon, CanonKind};

/// Limits (bytes or code points as stated in each function's docs).
pub mod limits {
    /// Route path and query: maximum length in code points (414 above it).
    pub const MAX_PATH: usize = 8192;
    /// Bare host: maximum length.
    pub const MAX_HOST: usize = 253;
    /// JSON body: maximum length in code points (413 above it).
    pub const MAX_JSON: usize = 1 << 20;
    /// JSON body: maximum nesting depth of any value, member name or element (the top-level value is depth 0).
    pub const MAX_JSON_DEPTH: usize = 64;
}

/// A rejected input: the HTTP status to answer with, a static reason code, and for 308 the redirect target.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Reject {
    status: u16,
    kind: &'static str,
    reason: &'static str,
    redirect: Option<Box<[u8]>>,
}

impl Reject {
    pub(crate) const fn new(status: u16, kind: &'static str, reason: &'static str) -> Self {
        Self { status, kind, reason, redirect: None }
    }

    pub(crate) fn redirect(kind: &'static str, reason: &'static str, target: Box<[u8]>) -> Self {
        Self { status: 308, kind, reason, redirect: Some(target) }
    }

    /// The request envelope itself is malformed (unknown protocol or scheme, Host not a list): 400.
    pub const fn bad_envelope() -> Self {
        Self::new(400, "request", "bad envelope")
    }

    /// HTTP status: 308, 400, 403, 404, 413, 414, 415 or 421.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The kind that rejected (`path`, `query`, `host`, `authority`, `origin`, `headers`, `cookie`,
    /// `media-type`, `json`, `tenant`, `request`).
    pub fn kind(&self) -> &'static str {
        self.kind
    }

    /// Static reason code, e.g. `dot segment`.
    pub fn reason(&self) -> &'static str {
        self.reason
    }

    /// For a 308: the `Location` (an already canonical route path). `None` for every other status.
    pub fn redirect_target(&self) -> Option<&[u8]> {
        self.redirect.as_deref()
    }
}

/// `"<status> <kind>: <reason>"`, plus `", redirect to <target>"` for a 308.
impl fmt::Display for Reject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.status, self.kind, self.reason)?;
        if let Some(t) = &self.redirect {
            f.write_str(", redirect to ")?;
            for &b in t.iter() {
                // Targets are canonical paths (ASCII); anything else is escaped rather than trusted.
                if (0x21..0x7F).contains(&b) {
                    write!(f, "{}", char::from(b))?;
                } else {
                    write!(f, "%{b:02X}")?;
                }
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Reject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Reject({self})")
    }
}

// ---------------------------------------------------------------- shared byte classes and helpers

/// RFC 3986 unreserved.
pub(crate) fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// pchar literals without ';' (matrix-parameter confusion): unreserved / `!$&'()*+,=:@`.
pub(crate) fn is_pchar_lit(b: u8) -> bool {
    is_unreserved(b) || matches!(b, b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b'=' | b':' | b'@')
}

/// RFC 9110 tchar.
pub(crate) fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

pub(crate) fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// The two hex digits after a '%' at `pct` (which must be the index of the '%'), decoded.
pub(crate) fn pct_at(s: &[u8], pct: usize) -> Option<u8> {
    let hi = hex_val(*s.get(pct.checked_add(1)?)?)?;
    let lo = hex_val(*s.get(pct.checked_add(2)?)?)?;
    Some((hi << 4) | lo)
}

pub(crate) fn push_pct(out: &mut alloc::vec::Vec<u8>, v: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.push(b'%');
    out.push(HEX.get(usize::from(v >> 4)).copied().unwrap_or(b'0'));
    out.push(HEX.get(usize::from(v & 0xF)).copied().unwrap_or(b'0'));
}

/// Length in code points of UTF-8 (or WTF-8) text: the number of non-continuation bytes. For invalid input it is
/// still a total, deterministic count; such input is rejected later by every kind.
pub(crate) fn cp_len(s: &[u8]) -> usize {
    s.iter().filter(|&&b| (b & 0xC0) != 0x80).count()
}

pub(crate) fn seal<K: CanonKind>(v: alloc::vec::Vec<u8>) -> Canon<K> {
    aegis_types::canon_owner::seal(v.into_boxed_slice())
}

#[cfg(test)]
mod tests;
