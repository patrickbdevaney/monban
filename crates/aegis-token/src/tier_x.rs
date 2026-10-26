//! Tier X: COSE_Sign1 (RFC 9052) with ML-DSA-65 (COSE alg -49, RFC 9964), used only at trust-domain crossings.
//! Verify only; issuance is out of scope for this crate.
//!
//! Accepted encoding (strict, deterministic): `18([h'A10138 30', {}, payload, signature])`, i.e. tag 18, the
//! protected header is exactly the canonical map {1: -49}, the unprotected header is the empty map, the payload is
//! an attached bstr holding `[1, kid, nonce, caveats]` (F5 token-l without the tag), and the signature is a
//! 3309-byte ML-DSA-65 signature over Sig_structure `["Signature1", protected, h'', payload]`.
//! After the signature verifies, the same caveat semantics as Tier L apply (mint shape, depth, every caveat).

use aws_lc_rs::signature::{ML_DSA_65, UnparsedPublicKey};

use aegis_types::Principal;

use crate::caveat::{Caveat, Req, denote, depth_ok, mint_shape_ok};
use crate::cbor::{self, CborError, Dec};
use crate::tier_l::{MAX_TOKEN_BYTES, NONCE_LEN, decode_body, encode_body, kid_ok, principal_for};
use crate::{TokenError, VerifyError};

/// The only protected header accepted: canonical CBOR of {1: -49}.
pub const PROTECTED_MLDSA65: [u8; 4] = [0xA1, 0x01, 0x38, 0x30];
pub const COSE_SIGN1_TAG: u64 = 18;
pub const MLDSA65_SIG_LEN: usize = 3309;
pub const MLDSA65_PK_LEN: usize = 1952;
/// Envelope cap: payload ≤ 4096 plus signature and framing.
pub const MAX_COSE_BYTES: usize = 8192;

/// ML-DSA-65 public keys by kid.
#[derive(Clone, Debug, Default)]
pub struct XKeyRing {
    keys: Vec<(Vec<u8>, Vec<u8>)>,
}

impl XKeyRing {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds (or replaces) a raw 1952-byte ML-DSA-65 public key for `kid`.
    pub fn insert(&mut self, kid: &[u8], public_key: &[u8]) -> Result<(), TokenError> {
        if !kid_ok(kid) || public_key.len() != MLDSA65_PK_LEN {
            return Err(TokenError::Invalid);
        }
        self.keys.retain(|(k, _)| k.as_slice() != kid);
        self.keys.push((kid.to_vec(), public_key.to_vec()));
        Ok(())
    }

    fn get(&self, kid: &[u8]) -> Option<&[u8]> {
        self.keys.iter().find(|(k, _)| k.as_slice() == kid).map(|(_, v)| v.as_slice())
    }
}

/// The decoded payload of a Tier-X token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XPayload {
    pub kid: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
    pub caveats: Vec<Caveat>,
}

impl XPayload {
    pub fn encode(&self) -> Result<Vec<u8>, TokenError> {
        if !kid_ok(&self.kid) || !crate::tier_l::caveats_ok(&self.caveats) {
            return Err(TokenError::Invalid);
        }
        let mut out = Vec::new();
        encode_body(&mut out, 4, &self.kid, &self.nonce, &self.caveats);
        if out.len() > MAX_TOKEN_BYTES {
            return Err(TokenError::TooLarge);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<XPayload, CborError> {
        if bytes.len() > MAX_TOKEN_BYTES {
            return Err(CborError);
        }
        let mut d = Dec::new(bytes);
        if d.array()? != 4 {
            return Err(CborError);
        }
        let (kid, nonce, caveats) = decode_body(&mut d)?;
        d.finish()?;
        Ok(XPayload { kid, nonce, caveats })
    }
}

/// The bytes an issuer signs: Sig_structure = ["Signature1", protected, h'', payload].
pub fn sig_structure(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 32);
    cbor::put_array(&mut out, 4);
    cbor::put_tstr(&mut out, "Signature1");
    cbor::put_bstr(&mut out, &PROTECTED_MLDSA65);
    cbor::put_bstr(&mut out, &[]);
    cbor::put_bstr(&mut out, payload);
    out
}

/// Assembles the COSE_Sign1 envelope from an encoded payload and a signature.
pub fn envelope(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + signature.len() + 16);
    cbor::put_head(&mut out, cbor::MAJ_TAG, COSE_SIGN1_TAG);
    cbor::put_array(&mut out, 4);
    cbor::put_bstr(&mut out, &PROTECTED_MLDSA65);
    cbor::put_head(&mut out, cbor::MAJ_MAP, 0);
    cbor::put_bstr(&mut out, payload);
    cbor::put_bstr(&mut out, signature);
    out
}

/// Total, length-capped envelope decoder: returns (payload bytes, signature bytes).
pub fn decode_envelope(bytes: &[u8]) -> Result<(&[u8], &[u8]), CborError> {
    if bytes.len() > MAX_COSE_BYTES {
        return Err(CborError);
    }
    let mut d = Dec::new(bytes);
    if d.tag()? != COSE_SIGN1_TAG || d.array()? != 4 {
        return Err(CborError);
    }
    if d.bstr()? != PROTECTED_MLDSA65.as_slice() {
        return Err(CborError);
    }
    if d.map()? != 0 {
        return Err(CborError);
    }
    let payload = d.bstr()?;
    let sig = d.bstr()?;
    d.finish()?;
    if payload.len() > MAX_TOKEN_BYTES || sig.len() != MLDSA65_SIG_LEN {
        return Err(CborError);
    }
    Ok((payload, sig))
}

/// Tier-X verification. Signature first (over the exact received payload bytes), then the caveat conjunction.
/// Mints a `Principal` (tenant = `r.tenant`, subject = kid ‖ nonce) only on success.
pub fn verify_x(cose: &[u8], keys: &XKeyRing, r: &Req) -> Result<Principal, VerifyError> {
    let (payload, sig) = decode_envelope(cose).map_err(|_| VerifyError::Malformed)?;
    let p = XPayload::decode(payload).map_err(|_| VerifyError::Malformed)?;
    let pk = keys.get(&p.kid).ok_or(VerifyError::BadTag)?;
    let msg = sig_structure(payload);
    if UnparsedPublicKey::new(&ML_DSA_65, pk).verify(&msg, sig).is_err() {
        return Err(VerifyError::BadTag);
    }
    if !mint_shape_ok(&p.caveats) {
        return Err(VerifyError::BadShape);
    }
    if !depth_ok(&p.caveats) {
        return Err(VerifyError::DepthExceeded);
    }
    if !denote(&p.caveats, r) {
        return Err(VerifyError::Denied);
    }
    principal_for(r, &p.kid, &p.nonce)
}
