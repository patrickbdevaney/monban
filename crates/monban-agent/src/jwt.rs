//! Bearer-token check for the listener (the mcp-corpus gateway profile): a compact JWS with `alg` exactly `HS256`
//! (RFC 7515/7519), verified in constant time with AWS-LC HMAC-SHA256, then `iss` exact, `sub` a non-empty string,
//! `exp` in the future, `nbf` (if present) not in the future, and `aud` equal to (or, for an array, containing) the
//! full route URL (RFC 8707 resource indicator: a token minted for another resource is refused).
//!
//! The header and claims are parsed by the one JSON owner (`monban_canon::parse_json`): duplicate or case-colliding
//! claim names, a BOM and non-finite numbers are refused before any claim is read. Claims are read only after the
//! signature verified. Every failure is the same 401 to the caller (no oracle on which check failed).
//!
//! Not a `Principal`: only monban-token mints those (F2 constructor gate). The verified subject is carried as
//! [`Subject`] and used for session binding and as the PDP principal id. Moving this profile into monban-token is a
//! backlog item.

use std::string::String;
use std::vec::Vec;

use aws_lc_rs::hmac;
use monban_canon::{JsonValue, parse_json};

use crate::b64;
use crate::emit::get;

/// Longest `Authorization` value accepted.
pub const MAX_TOKEN: usize = 4096;
/// Longest subject accepted.
pub const MAX_SUB: usize = 255;

/// The authenticated subject of a request (the token's `sub`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Subject(String);

impl Subject {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why a token was refused (diagnostics only; the wire answer is always 401).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// No `Authorization` field.
    Missing,
    /// Not `Bearer <token>`, or the token is not three base64url parts of JSON.
    Malformed,
    /// `alg` is not `HS256` (including `none`), or `crit` is present.
    Alg,
    /// Signature mismatch.
    Signature,
    /// `iss`, `sub`, `exp`, `nbf` or `aud` failed.
    Claims,
}

/// The HS256 profile: issuer and key.
pub struct JwtProfile {
    key: hmac::Key,
    issuer: String,
}

impl core::fmt::Debug for JwtProfile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JwtProfile").field("issuer", &self.issuer).finish_non_exhaustive()
    }
}

fn number(v: Option<&JsonValue>) -> Option<f64> {
    match v {
        Some(JsonValue::Int(i)) => Some(*i as f64),
        Some(JsonValue::Float(f)) => Some(*f),
        _ => None,
    }
}

impl JwtProfile {
    /// `secret` must be at least 32 bytes (RFC 7518 §3.2: a key of at least the hash output size).
    pub fn new(secret: &[u8], issuer: &str) -> Result<Self, String> {
        if secret.len() < 32 {
            return Err("HS256 secret must be at least 32 bytes".into());
        }
        if issuer.is_empty() {
            return Err("issuer must not be empty".into());
        }
        Ok(Self { key: hmac::Key::new(hmac::HMAC_SHA256, secret), issuer: issuer.into() })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Verify an `Authorization` field value for `audience` at unix time `now`.
    pub fn verify(&self, authorization: Option<&[u8]>, audience: &str, now: u64) -> Result<Subject, AuthError> {
        let a = authorization.ok_or(AuthError::Missing)?;
        if a.len() > MAX_TOKEN || a.len() < 8 {
            return Err(AuthError::Malformed);
        }
        let (scheme, tok) = a.split_at(7);
        if !scheme.eq_ignore_ascii_case(b"bearer ") {
            return Err(AuthError::Malformed);
        }
        let mut parts = tok.split(|&b| b == b'.');
        let (Some(h64), Some(p64), Some(s64), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
            return Err(AuthError::Malformed);
        };
        if h64.is_empty() || p64.is_empty() || s64.is_empty() {
            return Err(AuthError::Malformed);
        }
        let header = b64::decode_url(h64).ok_or(AuthError::Malformed)?;
        let header = parse_json(&header).map_err(|_| AuthError::Malformed)?;
        if !matches!(header, JsonValue::Object(_)) {
            return Err(AuthError::Malformed);
        }
        if !matches!(get(&header, "alg"), Some(JsonValue::String(s)) if s == "HS256") || get(&header, "crit").is_some()
        {
            return Err(AuthError::Alg);
        }
        if let Some(t) = get(&header, "typ")
            && !matches!(t, JsonValue::String(s) if s.eq_ignore_ascii_case("JWT") || s.eq_ignore_ascii_case("at+jwt"))
        {
            return Err(AuthError::Alg);
        }
        let sig = b64::decode_url(s64).ok_or(AuthError::Malformed)?;
        let signed_len = h64.len().saturating_add(1).saturating_add(p64.len());
        let signed = tok.get(..signed_len).ok_or(AuthError::Malformed)?;
        hmac::verify(&self.key, signed, &sig).map_err(|_| AuthError::Signature)?;
        // Claims: read only after the signature verified.
        let claims = b64::decode_url(p64).ok_or(AuthError::Malformed)?;
        let claims = parse_json(&claims).map_err(|_| AuthError::Malformed)?;
        if !matches!(claims, JsonValue::Object(_)) {
            return Err(AuthError::Malformed);
        }
        if !matches!(get(&claims, "iss"), Some(JsonValue::String(s)) if *s == self.issuer) {
            return Err(AuthError::Claims);
        }
        let sub = match get(&claims, "sub") {
            Some(JsonValue::String(s)) if !s.is_empty() && s.len() <= MAX_SUB && !s.chars().any(char::is_control) => {
                s.clone()
            }
            _ => return Err(AuthError::Claims),
        };
        let now_f = now as f64;
        match number(get(&claims, "exp")) {
            Some(exp) if exp > now_f => {}
            _ => return Err(AuthError::Claims),
        }
        if let Some(nbf) = get(&claims, "nbf") {
            match number(Some(nbf)) {
                Some(n) if n <= now_f => {}
                _ => return Err(AuthError::Claims),
            }
        }
        if let Some(iat) = get(&claims, "iat")
            && number(Some(iat)).is_none()
        {
            return Err(AuthError::Claims);
        }
        let aud_ok = match get(&claims, "aud") {
            Some(JsonValue::String(s)) => s == audience,
            Some(JsonValue::Array(xs)) => {
                xs.iter().all(|x| matches!(x, JsonValue::String(_)))
                    && xs.iter().any(|x| matches!(x, JsonValue::String(s) if s == audience))
            }
            _ => false,
        };
        if !aud_ok {
            return Err(AuthError::Claims);
        }
        Ok(Subject(sub))
    }
}

/// Test helper (and oracle-subject self-check): mint an HS256 token. Not used on any serving path.
pub fn mint_hs256(secret: &[u8], header_json: &str, claims_json: &str) -> String {
    fn enc(b: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut s = String::new();
        for c in b.chunks(3) {
            let n = c.iter().fold(0u32, |acc, &x| (acc << 8) | u32::from(x)) << (8 * (3 - c.len()));
            let k = c.len() + 1;
            for i in 0..k {
                let idx = ((n >> (18 - 6 * i)) & 63) as usize;
                s.push(char::from(A.get(idx).copied().unwrap_or(b'A')));
            }
        }
        s
    }
    let h = enc(header_json.as_bytes());
    let p = enc(claims_json.as_bytes());
    let signing = format!("{h}.{p}");
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, secret), signing.as_bytes());
    let mut out: Vec<u8> = signing.into_bytes();
    out.push(b'.');
    out.extend_from_slice(enc(tag.as_ref()).as_bytes());
    String::from_utf8(out).unwrap_or_default()
}
