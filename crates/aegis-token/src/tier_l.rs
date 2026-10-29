//! Tier L: macaroon-style HMAC-SHA256 chain over deterministic-CBOR caveats (F5 `token-l`, Lean `macChain`,
//! `verify`, `attenuate`).
//!
//! K_aud = HKDF-SHA256(ikm = K, salt = "", info = "aegis-cap-v1" ‖ be16(|aud|) ‖ aud ‖ be16(|kid|) ‖ kid), so
//! distinct (aud, kid) pairs never share an info string; the verifier derives it from ITS OWN
//! audience (`Req::aud`), so a token minted for another audience fails the MAC as well as the aud caveat.
//! tag = foldl (λ t c. HMAC(t, enc c)) (HMAC(K_aud, kid ‖ nonce)) caveats, compared in constant time.

use aws_lc_rs::{constant_time, hkdf, hmac};

use aegis_types::{Principal, TenantId, authn_path};

use crate::caveat::{Caveat, MAX_CAVEATS, MAX_DEPTH, Req, denote, depth_ok, mint_shape_ok};
use crate::cbor::{self, CborError, Dec};
use crate::{TokenError, VerifyError};

/// Encoded token cap (F5).
pub const MAX_TOKEN_BYTES: usize = 4096;
/// Issuer TTL cap: exp - mint_time ≤ 900 s (F5).
pub const MAX_TTL_SECS: u64 = 900;
pub const MAX_KID: usize = 32;
pub const NONCE_LEN: usize = 16;
pub const TAG_LEN: usize = 32;
const KDF_LABEL: &[u8] = b"aegis-cap-v1";

/// Issuer master keys by kid. Debug never prints key material.
#[derive(Clone, Default)]
pub struct KeyRing {
    keys: Vec<(Vec<u8>, [u8; 32])>,
}

impl core::fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyRing").field("kids", &self.keys.len()).finish()
    }
}

impl KeyRing {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds (or replaces) the master key for `kid` (1..32 bytes).
    pub fn insert(&mut self, kid: &[u8], key: [u8; 32]) -> Result<(), TokenError> {
        if kid.is_empty() || kid.len() > MAX_KID {
            return Err(TokenError::Invalid);
        }
        self.keys.retain(|(k, _)| k.as_slice() != kid);
        self.keys.push((kid.to_vec(), key));
        Ok(())
    }

    fn get(&self, kid: &[u8]) -> Option<&[u8; 32]> {
        self.keys.iter().find(|(k, _)| k.as_slice() == kid).map(|(_, v)| v)
    }
}

/// A decoded Tier-L token. The tag is the bearer secret, so Debug redacts it.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenL {
    pub kid: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
    pub caveats: Vec<Caveat>,
    pub tag: [u8; TAG_LEN],
}

impl core::fmt::Debug for TokenL {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TokenL")
            .field("kid", &self.kid)
            .field("nonce", &self.nonce)
            .field("caveats", &self.caveats)
            .field("tag", &"<redacted>")
            .finish()
    }
}

pub(crate) fn kid_ok(kid: &[u8]) -> bool {
    !kid.is_empty() && kid.len() <= MAX_KID
}

pub(crate) fn caveats_ok(cs: &[Caveat]) -> bool {
    !cs.is_empty() && cs.len() <= MAX_CAVEATS && cs.iter().all(Caveat::is_well_formed)
}

/// Encodes `[1, kid, nonce, caveats]` (the shared prefix of Tier L and the Tier X payload).
pub(crate) fn encode_body(out: &mut Vec<u8>, n: usize, kid: &[u8], nonce: &[u8], cs: &[Caveat]) {
    cbor::put_array(out, n);
    cbor::put_uint(out, 1);
    cbor::put_bstr(out, kid);
    cbor::put_bstr(out, nonce);
    cbor::put_array(out, cs.len());
    for c in cs {
        c.encode_into(out);
    }
}

/// (kid, nonce, caveats) of a decoded body.
pub(crate) type Body = (Vec<u8>, [u8; NONCE_LEN], Vec<Caveat>);

/// Decodes the body after the array head: version, kid, nonce, caveats.
pub(crate) fn decode_body(d: &mut Dec<'_>) -> Result<Body, CborError> {
    if d.uint()? != 1 {
        return Err(CborError);
    }
    let kid = d.bstr()?;
    if !kid_ok(kid) {
        return Err(CborError);
    }
    let nonce: [u8; NONCE_LEN] = d.bstr()?.try_into().map_err(|_| CborError)?;
    let n = d.array()?;
    if n == 0 || n > MAX_CAVEATS {
        return Err(CborError);
    }
    let mut cs = Vec::with_capacity(n);
    for _ in 0..n {
        cs.push(crate::caveat::decode_caveat(d)?);
    }
    Ok((kid.to_vec(), nonce, cs))
}

impl TokenL {
    /// Deterministic CBOR encoding; refuses tokens that break any F5 limit (including the 4096-byte cap).
    pub fn encode(&self) -> Result<Vec<u8>, TokenError> {
        if !kid_ok(&self.kid) || !caveats_ok(&self.caveats) {
            return Err(TokenError::Invalid);
        }
        let mut out = Vec::new();
        encode_body(&mut out, 5, &self.kid, &self.nonce, &self.caveats);
        cbor::put_bstr(&mut out, &self.tag);
        if out.len() > MAX_TOKEN_BYTES {
            return Err(TokenError::TooLarge);
        }
        Ok(out)
    }

    /// Total, length-capped decoder. Accepts only the canonical encoding (so `decode(b)?.encode() == b`).
    pub fn decode(bytes: &[u8]) -> Result<TokenL, CborError> {
        if bytes.len() > MAX_TOKEN_BYTES {
            return Err(CborError);
        }
        let mut d = Dec::new(bytes);
        if d.array()? != 5 {
            return Err(CborError);
        }
        let (kid, nonce, caveats) = decode_body(&mut d)?;
        let tag: [u8; TAG_LEN] = d.bstr()?.try_into().map_err(|_| CborError)?;
        d.finish()?;
        Ok(TokenL { kid, nonce, caveats, tag })
    }
}

fn derive_k_aud(master: &[u8; 32], aud: &str, kid: &[u8]) -> Result<hmac::Key, TokenError> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(master);
    let (a, k) = (aud.as_bytes(), kid);
    let a_len = u16::try_from(a.len()).map_err(|_| TokenError::Crypto)?.to_be_bytes();
    let k_len = u16::try_from(k.len()).map_err(|_| TokenError::Crypto)?.to_be_bytes();
    let info: [&[u8]; 5] = [KDF_LABEL, &a_len, a, &k_len, k];
    let okm = prk.expand(&info, hmac::HMAC_SHA256).map_err(|_| TokenError::Crypto)?;
    Ok(hmac::Key::from(okm))
}

fn chain(k_aud: &hmac::Key, kid: &[u8], nonce: &[u8], cs: &[Caveat]) -> Result<[u8; TAG_LEN], TokenError> {
    let mut root = Vec::with_capacity(kid.len() + nonce.len());
    root.extend_from_slice(kid);
    root.extend_from_slice(nonce);
    let mut t = to_tag(hmac::sign(k_aud, &root).as_ref())?;
    for c in cs {
        t = step(&t, c);
    }
    Ok(t)
}

fn to_tag(b: &[u8]) -> Result<[u8; TAG_LEN], TokenError> {
    b.try_into().map_err(|_| TokenError::Crypto)
}

fn step(t: &[u8; TAG_LEN], c: &Caveat) -> [u8; TAG_LEN] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, t);
    let mut out = [0u8; TAG_LEN];
    let s = hmac::sign(&k, &c.encode());
    for (o, b) in out.iter_mut().zip(s.as_ref()) {
        *o = *b;
    }
    out
}

/// Issuer-side raw chain: the tag a key holder computes over an arbitrary caveat list. Requires the master key;
/// `mint` is the checked entry point and should be preferred.
pub fn chain_tag(
    master: &[u8; 32],
    aud: &str,
    kid: &[u8],
    nonce: &[u8; NONCE_LEN],
    cs: &[Caveat],
) -> Result<[u8; TAG_LEN], TokenError> {
    let k = derive_k_aud(master, aud, kid)?;
    chain(&k, kid, nonce, cs)
}

/// Mint request. `extra` caveats are appended after the mandatory [aud, exp, depth_left] prefix.
#[derive(Clone, Debug)]
pub struct MintParams<'a> {
    pub kid: &'a [u8],
    pub aud: &'a str,
    pub nonce: [u8; NONCE_LEN],
    pub mint_time: u64,
    pub exp: u64,
    pub depth: u8,
    pub extra: Vec<Caveat>,
}

/// A fresh random nonce from the AWS-LC DRBG.
pub fn fresh_nonce() -> Result<[u8; NONCE_LEN], TokenError> {
    let mut n = [0u8; NONCE_LEN];
    aws_lc_rs::rand::fill(&mut n).map_err(|_| TokenError::Crypto)?;
    Ok(n)
}

/// Issuer mint: enforces the mint shape, mint_time < exp ≤ mint_time + 900, depth ≤ 16, extra ≤ depth (so the
/// token verifies), every wire limit, and the 4096-byte cap.
pub fn mint(keys: &KeyRing, p: MintParams<'_>) -> Result<TokenL, TokenError> {
    let master = keys.get(p.kid).ok_or(TokenError::UnknownKey)?;
    if p.exp <= p.mint_time || p.exp - p.mint_time > MAX_TTL_SECS {
        return Err(TokenError::Ttl);
    }
    if p.depth > MAX_DEPTH || p.extra.len() > usize::from(p.depth) {
        return Err(TokenError::Invalid);
    }
    let mut cs = vec![Caveat::Aud(p.aud.into()), Caveat::Exp(p.exp), Caveat::Depth(p.depth)];
    cs.extend(p.extra);
    let tag = chain_tag(master, p.aud, p.kid, &p.nonce, &cs)?;
    let t = TokenL { kid: p.kid.to_vec(), nonce: p.nonce, caveats: cs, tag };
    t.encode()?;
    Ok(t)
}

/// Holder-side attenuation (Lean `attenuate`): append one caveat and extend the chain, with no key. Fails only if
/// the result would break a wire limit (64 caveats, 4096 bytes, field shapes). Depth is judged at verify (D3).
pub fn attenuate(t: &TokenL, c: Caveat) -> Result<TokenL, TokenError> {
    let tag = step(&t.tag, &c);
    let mut caveats = t.caveats.clone();
    caveats.push(c);
    let out = TokenL { kid: t.kid.clone(), nonce: t.nonce, caveats, tag };
    out.encode()?;
    Ok(out)
}

/// The MAC conjunct of `verify`: the presented tag equals the chain under K_aud(K[kid], req.aud, kid),
/// compared in constant time. Unknown kid → false.
pub fn mac_valid(keys: &KeyRing, t: &TokenL, aud: &str) -> bool {
    let Some(master) = keys.get(&t.kid) else { return false };
    let Ok(k) = derive_k_aud(master, aud, &t.kid) else { return false };
    let Ok(want) = chain(&k, &t.kid, &t.nonce, &t.caveats) else { return false };
    constant_time::verify_slices_are_equal(&want, &t.tag).is_ok()
}

/// Lean `verify` ∧ the F5 mint-shape check, on an already-decoded token, as a boolean.
pub fn verify_decoded(keys: &KeyRing, t: &TokenL, r: &Req) -> bool {
    mac_valid(keys, t, &r.aud) && denote(&t.caveats, r) && depth_ok(&t.caveats) && mint_shape_ok(&t.caveats)
}

/// Full Tier-L verification of wire bytes. On success, and only then, mints the request's `Principal` through
/// `aegis_types::authn_path::mint` with tenant = `r.tenant` and subject = kid ‖ nonce.
pub fn verify(token: &[u8], keys: &KeyRing, r: &Req) -> Result<Principal, VerifyError> {
    let t = TokenL::decode(token).map_err(|_| VerifyError::Malformed)?;
    if !mac_valid(keys, &t, &r.aud) {
        return Err(VerifyError::BadTag);
    }
    if !mint_shape_ok(&t.caveats) {
        return Err(VerifyError::BadShape);
    }
    if !depth_ok(&t.caveats) {
        return Err(VerifyError::DepthExceeded);
    }
    if !denote(&t.caveats, r) {
        return Err(VerifyError::Denied);
    }
    principal_for(r, &t.kid, &t.nonce)
}

pub(crate) fn principal_for(r: &Req, kid: &[u8], nonce: &[u8]) -> Result<Principal, VerifyError> {
    let tenant = TenantId::new(r.tenant).map_err(|_| VerifyError::BadPrincipal)?;
    let mut subject = Vec::with_capacity(kid.len() + nonce.len());
    subject.extend_from_slice(kid);
    subject.extend_from_slice(nonce);
    authn_path::mint(tenant, Some(&subject)).map_err(|_| VerifyError::BadPrincipal)
}

#[cfg(test)]
mod kdf_tests {
    use super::*;

    /// F5 re-freeze 2026-10-29: ("api","k1") and ("apik","1") have the same plain concatenation and must still derive
    /// different keys.
    #[test]
    fn k_aud_info_is_length_prefixed() -> Result<(), TokenError> {
        let m = [7u8; 32];
        let a = hmac::sign(&derive_k_aud(&m, "api", b"k1")?, b"probe");
        let b = hmac::sign(&derive_k_aud(&m, "apik", b"1")?, b"probe");
        assert_ne!(a.as_ref(), b.as_ref());
        let c = hmac::sign(&derive_k_aud(&m, "api", b"k1")?, b"probe");
        assert_eq!(a.as_ref(), c.as_ref());
        Ok(())
    }
}
