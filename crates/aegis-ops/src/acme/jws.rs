//! JWS (RFC 7515) flattened JSON serialization with ES256 (RFC 7518 §3.4), as ACME requires (RFC 8555 §6.2):
//! protected header `{alg, nonce, url}` plus exactly one of `jwk` (newAccount, revocation by key) or `kid`.
//! Account keys are P-256 ECDSA (aws-lc-rs, fixed-width r||s signatures). JWK thumbprint per RFC 7638.

use std::string::String;

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

use super::AcmeError;
use super::json::quote;
use crate::cert::b64::b64url_encode;

/// An ACME account key (ES256).
#[derive(Debug)]
pub struct AccountKey {
    kp: EcdsaKeyPair,
    jwk: String,
    thumbprint: String,
}

impl AccountKey {
    /// A fresh P-256 key.
    pub fn generate() -> Result<Self, AcmeError> {
        let kp = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).map_err(|_| AcmeError::Crypto("keygen"))?;
        Self::from_pair(kp)
    }

    /// Load a PKCS#8 P-256 key (persisted account key).
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, AcmeError> {
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der)
            .map_err(|_| AcmeError::Crypto("account key"))?;
        Self::from_pair(kp)
    }

    /// PKCS#8 v1 encoding (to persist).
    pub fn to_pkcs8(&self) -> Result<std::vec::Vec<u8>, AcmeError> {
        self.kp.to_pkcs8v1().map(|d| d.as_ref().to_vec()).map_err(|_| AcmeError::Crypto("pkcs8"))
    }

    fn from_pair(kp: EcdsaKeyPair) -> Result<Self, AcmeError> {
        let pt = kp.public_key().as_ref();
        let (x, y) = match pt.split_first() {
            Some((4, xy)) if xy.len() == 64 => xy.split_at(32),
            _ => return Err(AcmeError::Crypto("public key encoding")),
        };
        // RFC 7638 §3.2: required members only, lexicographic order, no whitespace.
        let jwk = std::format!(r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#, b64url_encode(x), b64url_encode(y));
        let thumbprint = b64url_encode(digest(&SHA256, jwk.as_bytes()).as_ref());
        Ok(Self { kp, jwk, thumbprint })
    }

    /// The public JWK (canonical form).
    pub fn jwk(&self) -> &str {
        &self.jwk
    }

    /// base64url(SHA-256(JWK)) (RFC 7638).
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    /// Key authorization `token.thumbprint` (RFC 8555 §8.1).
    pub fn key_authorization(&self, token: &str) -> String {
        std::format!("{token}.{}", self.thumbprint)
    }

    /// Raw ES256 signature (64 bytes r||s).
    pub fn sign_raw(&self, msg: &[u8]) -> Result<std::vec::Vec<u8>, AcmeError> {
        self.kp.sign(&SystemRandom::new(), msg).map(|s| s.as_ref().to_vec()).map_err(|_| AcmeError::Crypto("sign"))
    }
}

/// Which key identification the protected header carries.
#[derive(Clone, Copy, Debug)]
pub enum KeyId<'a> {
    /// `jwk` (newAccount).
    Jwk,
    /// `kid` = account URL.
    Kid(&'a str),
}

/// Build the flattened JWS. `payload = None` is POST-as-GET (empty payload, RFC 8555 §6.3). `signer` signs; it
/// is normally `key` (a different signer models the wrong-key mutation; the header still names `key`).
pub fn sign(
    key: &AccountKey,
    signer: &AccountKey,
    id: KeyId<'_>,
    nonce: &str,
    url: &str,
    payload: Option<&str>,
) -> Result<String, AcmeError> {
    let ident = match id {
        KeyId::Jwk => std::format!(r#""jwk":{}"#, key.jwk()),
        KeyId::Kid(k) => std::format!(r#""kid":{}"#, quote(k)),
    };
    let protected = std::format!(r#"{{"alg":"ES256",{ident},"nonce":{},"url":{}}}"#, quote(nonce), quote(url));
    let p64 = b64url_encode(protected.as_bytes());
    let pl64 = payload.map(|p| b64url_encode(p.as_bytes())).unwrap_or_default();
    let sig = signer.sign_raw(std::format!("{p64}.{pl64}").as_bytes())?;
    Ok(std::format!(r#"{{"protected":"{p64}","payload":"{pl64}","signature":"{}"}}"#, b64url_encode(&sig)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::cert::b64::b64url_decode;
    use aegis_canon::{JsonValue, parse_json};
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};

    fn field<'a>(v: &'a JsonValue, k: &str) -> &'a str {
        match super::super::json::get_str(v, k) {
            Some(s) => s,
            None => panic!("missing {k}"),
        }
    }

    #[test]
    fn jws_roundtrip_and_header() {
        let k = AccountKey::generate().unwrap();
        let j = sign(&k, &k, KeyId::Kid("https://ca/acct/1"), "n0nce", "https://ca/order", Some("{}")).unwrap();
        let v = parse_json(j.as_bytes()).unwrap();
        let p64 = field(&v, "protected");
        let pl64 = field(&v, "payload");
        let s = b64url_decode(field(&v, "signature")).unwrap();
        assert_eq!(s.len(), 64);
        let hdr = parse_json(&b64url_decode(p64).unwrap()).unwrap();
        assert_eq!(field(&hdr, "alg"), "ES256");
        assert_eq!(field(&hdr, "kid"), "https://ca/acct/1");
        assert_eq!(field(&hdr, "nonce"), "n0nce");
        assert_eq!(field(&hdr, "url"), "https://ca/order");
        assert!(super::super::json::get(&hdr, "jwk").is_none());
        let pk = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, k.kp.public_key().as_ref().to_vec());
        pk.verify(std::format!("{p64}.{pl64}").as_bytes(), &s).unwrap();
        // Wrong signer: verification under the named key fails.
        let other = AccountKey::generate().unwrap();
        let j = sign(&k, &other, KeyId::Jwk, "n", "https://ca/new-acct", None).unwrap();
        let v = parse_json(j.as_bytes()).unwrap();
        let s = b64url_decode(field(&v, "signature")).unwrap();
        assert_eq!(field(&v, "payload"), "");
        assert!(pk.verify(std::format!("{}.", field(&v, "protected")).as_bytes(), &s).is_err());
    }

    #[test]
    fn thumbprint_matches_jwk_and_pkcs8_roundtrip() {
        let k = AccountKey::generate().unwrap();
        let jwk = parse_json(k.jwk().as_bytes()).unwrap();
        assert_eq!(b64url_decode(field(&jwk, "x")).unwrap().len(), 32);
        assert_eq!(b64url_decode(k.thumbprint()).unwrap().len(), 32);
        let k2 = AccountKey::from_pkcs8(&k.to_pkcs8().unwrap()).unwrap();
        assert_eq!(k.jwk(), k2.jwk());
        assert_eq!(k.key_authorization("tok"), std::format!("tok.{}", k.thumbprint()));
    }
}
