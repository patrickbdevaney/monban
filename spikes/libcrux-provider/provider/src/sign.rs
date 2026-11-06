//! Server signing keys: ECDSA-P256-SHA256 (libcrux-ecdsa, random nonce from the OS RNG) and Ed25519
//! (libcrux-ed25519). Keys are loaded from PKCS#8 (RFC 5958) or, for P-256, SEC1 (RFC 5915) DER with a minimal
//! DER reader; anything else is refused.
use std::fmt;
use std::sync::Arc;

use rustls::crypto::KeyProvider;
use rustls::pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer, alg_id};
use rustls::sign::{Signer, SigningKey, public_key_to_spki};
use rustls::{Error, SignatureAlgorithm, SignatureScheme};
use zeroize::Zeroizing;

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

fn bad_key(what: &'static str) -> Error {
    Error::General(format!("lcx key: {what}"))
}

/// One DER TLV: (tag, value, rest). Definite lengths up to 2 length bytes.
fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&l0, rest) = rest.split_first()?;
    let (len, rest) = match l0 {
        0..=0x7f => (usize::from(l0), rest),
        0x81 => {
            let (&a, r) = rest.split_first()?;
            (usize::from(a), r)
        }
        0x82 => {
            let (&a, r) = rest.split_first()?;
            let (&b, r) = r.split_first()?;
            ((usize::from(a) << 8) | usize::from(b), r)
        }
        _ => return None,
    };
    let (value, rest) = rest.split_at_checked(len)?;
    Some((tag, value, rest))
}

fn expect(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (t, v, r) = tlv(input)?;
    (t == tag).then_some((v, r))
}

enum Parsed {
    P256(Zeroizing<[u8; 32]>),
    Ed25519(Zeroizing<[u8; 32]>),
}

/// ECPrivateKey ::= SEQUENCE { version 1, privateKey OCTET STRING (32), [0] params OPTIONAL, [1] pub OPTIONAL }
fn parse_sec1(der: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    let (seq, _) = expect(der, 0x30)?;
    let (ver, rest) = expect(seq, 0x02)?;
    if ver != [1] {
        return None;
    }
    let (sk, rest) = expect(rest, 0x04)?;
    if let Some((0xa0, params, _)) = tlv(rest) {
        let (oid, _) = expect(params, 0x06)?;
        if oid != OID_PRIME256V1 {
            return None;
        }
    }
    Some(Zeroizing::new(sk.try_into().ok()?))
}

/// PrivateKeyInfo / OneAsymmetricKey ::= SEQUENCE { version, AlgorithmIdentifier, privateKey OCTET STRING, ... }
fn parse_pkcs8(der: &[u8]) -> Option<Parsed> {
    let (seq, _) = expect(der, 0x30)?;
    let (ver, rest) = expect(seq, 0x02)?;
    if ver != [0] && ver != [1] {
        return None;
    }
    let (alg, rest) = expect(rest, 0x30)?;
    let (pk, _) = expect(rest, 0x04)?;
    let (oid, params) = expect(alg, 0x06)?;
    if oid == OID_ED25519 {
        // CurvePrivateKey ::= OCTET STRING (RFC 8410 7)
        let (inner, _) = expect(pk, 0x04)?;
        return Some(Parsed::Ed25519(Zeroizing::new(inner.try_into().ok()?)));
    }
    if oid == OID_EC_PUBLIC_KEY {
        let (curve, _) = expect(params, 0x06)?;
        if curve != OID_PRIME256V1 {
            return None;
        }
        return parse_sec1(pk).map(Parsed::P256);
    }
    None
}

/// The provider's key loader.
#[derive(Debug)]
pub struct Keys;

impl KeyProvider for Keys {
    fn load_private_key(&self, key_der: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        let parsed = match &key_der {
            PrivateKeyDer::Pkcs8(d) => parse_pkcs8(d.secret_pkcs8_der()),
            PrivateKeyDer::Sec1(d) => parse_sec1(d.secret_sec1_der()).map(Parsed::P256),
            _ => return Err(bad_key("only PKCS#8 (P-256, Ed25519) and SEC1 (P-256) keys are supported")),
        };
        match parsed.ok_or_else(|| bad_key("unparseable or unsupported private key"))? {
            Parsed::P256(sk) => Ok(Arc::new(EcdsaP256Key::new(sk)?)),
            Parsed::Ed25519(sk) => Ok(Arc::new(Ed25519Key::new(sk))),
        }
    }
}

/// ECDSA P-256 key; signs with SHA-256 (TLS 1.3 scheme ecdsa_secp256r1_sha256).
#[derive(Clone)]
pub struct EcdsaP256Key {
    sk: Zeroizing<[u8; 32]>,
    point: [u8; 65],
}

impl EcdsaP256Key {
    pub fn new(sk: Zeroizing<[u8; 32]>) -> Result<Self, Error> {
        let point = crate::kx::p256_public(&sk).map_err(|_| bad_key("p256 scalar out of range"))?;
        Ok(Self { sk, point })
    }

    /// DER-encoded ECDSA-SHA256 signature (random nonce from the OS RNG).
    pub fn sign_sha256(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let sk = libcrux_ecdsa::p256::PrivateKey::try_from(&*self.sk).map_err(|_| bad_key("p256 scalar"))?;
        let mut rng = getrandom::SysRng;
        let sig = libcrux_ecdsa::p256::rand::sign(libcrux_ecdsa::DigestAlgorithm::Sha256, message, &sk, &mut rng)
            .map_err(|_| Error::General("ecdsa sign failed".into()))?;
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

impl fmt::Debug for EcdsaP256Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EcdsaP256Key")
    }
}

impl SigningKey for EcdsaP256Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| Box::new(self.clone()) as Box<dyn Signer>)
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(public_key_to_spki(&alg_id::ECDSA_P256, self.point))
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl Signer for EcdsaP256Key {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.sign_sha256(message)
    }
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

/// Ed25519 key (RFC 8032 PureEdDSA).
#[derive(Clone)]
pub struct Ed25519Key {
    sk: Zeroizing<[u8; 32]>,
    pk: [u8; 32],
}

impl Ed25519Key {
    pub fn new(sk: Zeroizing<[u8; 32]>) -> Self {
        let mut pk = [0u8; 32];
        libcrux_ed25519::secret_to_public(&mut pk, &sk);
        Self { sk, pk }
    }
    pub fn public(&self) -> [u8; 32] {
        self.pk
    }
    pub fn sign_raw(&self, message: &[u8]) -> Result<[u8; 64], Error> {
        libcrux_ed25519::sign(message, &self.sk).map_err(|_| Error::General("ed25519 sign failed".into()))
    }
}

impl fmt::Debug for Ed25519Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ed25519Key")
    }
}

impl SigningKey for Ed25519Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&SignatureScheme::ED25519).then(|| Box::new(self.clone()) as Box<dyn Signer>)
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(public_key_to_spki(&alg_id::ED25519, self.pk))
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

impl Signer for Ed25519Key {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.sign_raw(message)?.to_vec())
    }
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}
