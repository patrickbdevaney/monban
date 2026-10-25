//! SecP384r1MLKEM1024 (TLS supported group 0x11ED) as a rustls `SupportedKxGroup`, built directly on
//! aws-lc-rs primitives (ECDH P-384 + ML-KEM-1024). Seed for `aegis-tls::kx` (ARCHITECTURE 3.2).
//!
//! Wire format and combiner: RFC 10024 (published Aug 2026 from draft-ietf-tls-ecdhe-mlkem; draft-05 text is
//! identical for this group):
//! - 4.1 client share  = P-384 uncompressed point (97) || ML-KEM-1024 encapsulation key (1568) = 1665 bytes
//! - 4.2 server share  = P-384 uncompressed point (97) || ML-KEM-1024 ciphertext (1568)        = 1665 bytes
//! - 4.3 shared secret = ECDHE x-coordinate (48) || ML-KEM shared secret (32)                    = 80 bytes
//!
//! Classical part FIRST in share and secret. This is the opposite of X25519MLKEM768 (ML-KEM first, 4.1 note)
//! and the same as SecP256r1MLKEM768. RFC 10024 section 5: the first secret is the one an SP 800-56Cr2
//! "Z || T" hybrid derivation treats as the approved Z, so for this group ECDH P-384 is the component that must
//! be FIPS-approved.
//!
//! Validation (RFC 10024 4.2): server runs the FIPS 203 sec 7.2 encapsulation-key (modulus) check
//! (aws-lc `mlk_kem_check_pk` inside encapsulate) and aborts with illegal_parameter; client checks the
//! ciphertext length; both run the RFC 9846 4.3.8.2 point checks (aws-lc EC_POINT_oct2point on-curve check).
//! rustls 0.23.46 maps every `start_and_complete` / `complete` error to illegal_parameter (server/tls13.rs:541,
//! client/tls13.rs:173). The RFC's "internal_error on other decapsulation failure" cannot occur: ML-KEM
//! decapsulation of a correctly sized ciphertext never fails (implicit rejection).
//!
//! Spike code: no unwrap/expect/panic/indexing (AEGIS workspace lints).

#![forbid(unsafe_code)]

use std::boxed::Box;
use std::vec::Vec;

use aws_lc_rs::{agreement, kem};
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};

/// IANA TLS Supported Groups value 4589 (RFC 10024 section 7.3). Not a named variant in rustls 0.23.46.
pub const CODEPOINT: u16 = 0x11ED;
pub const NAME: NamedGroup = NamedGroup::Unknown(CODEPOINT);

pub const P384_SHARE_LEN: usize = 97; // 0x04 || X(48) || Y(48)
pub const MLKEM1024_EK_LEN: usize = 1568;
pub const MLKEM1024_CT_LEN: usize = 1568;
pub const CLIENT_SHARE_LEN: usize = P384_SHARE_LEN + MLKEM1024_EK_LEN; // 1665
pub const SERVER_SHARE_LEN: usize = P384_SHARE_LEN + MLKEM1024_CT_LEN; // 1665
pub const P384_SECRET_LEN: usize = 48;
pub const MLKEM_SECRET_LEN: usize = 32;
pub const SHARED_SECRET_LEN: usize = P384_SECRET_LEN + MLKEM_SECRET_LEN; // 80

const UNCOMPRESSED: u8 = 0x04;

const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

fn internal(what: &'static str) -> Error {
    Error::General(what.into())
}

/// The group. Use via [`SECP384R1MLKEM1024`].
#[derive(Debug)]
pub struct SecP384r1MlKem1024;

/// `&'static dyn SupportedKxGroup` for `CryptoProvider::kx_groups`.
pub static SECP384R1MLKEM1024: &dyn SupportedKxGroup = &SecP384r1MlKem1024;

/// Split a received share into (P-384 point, ML-KEM part). Total length must be exact and the point must be
/// in uncompressed form (RFC 10024 4.1/4.2 -> RFC 9846 4.3.8.2: legacy_form = 4). aws-lc-rs would otherwise
/// also accept a compressed point, but the fixed total length already excludes that; the prefix check makes
/// it explicit.
fn split_share(share: &[u8], pq_len: usize) -> Result<(&[u8], &[u8]), Error> {
    if share.len() != P384_SHARE_LEN + pq_len {
        return Err(INVALID_KEY_SHARE);
    }
    let (ecdh, pq) = share.split_at_checked(P384_SHARE_LEN).ok_or(INVALID_KEY_SHARE)?;
    if ecdh.first() != Some(&UNCOMPRESSED) {
        return Err(INVALID_KEY_SHARE);
    }
    Ok((ecdh, pq))
}

/// ECDH P-384 with on-curve validation by aws-lc; returns the 48-byte x-coordinate (RFC 9846 7.4.2).
fn ecdh_p384(private: &agreement::PrivateKey, peer_point: &[u8]) -> Result<Vec<u8>, Error> {
    let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P384, peer_point);
    let z = agreement::agree(private, peer, INVALID_KEY_SHARE, |z| Ok(z.to_vec()))?;
    if z.len() != P384_SECRET_LEN {
        return Err(internal("p384: unexpected secret length"));
    }
    Ok(z)
}

fn p384_public(private: &agreement::PrivateKey) -> Result<Vec<u8>, Error> {
    let public = private
        .compute_public_key()
        .map_err(|_| internal("p384: public key"))?;
    let bytes = public.as_ref();
    if bytes.len() != P384_SHARE_LEN || bytes.first() != Some(&UNCOMPRESSED) {
        return Err(internal("p384: public key not uncompressed"));
    }
    Ok(bytes.to_vec())
}

/// RFC 10024 4.3: ECDHE secret first, then ML-KEM secret.
fn combine(ecdh: &[u8], mlkem: &[u8]) -> Result<SharedSecret, Error> {
    if ecdh.len() != P384_SECRET_LEN || mlkem.len() != MLKEM_SECRET_LEN {
        return Err(internal("combiner: component length"));
    }
    let mut z = Vec::with_capacity(SHARED_SECRET_LEN);
    z.extend_from_slice(ecdh);
    z.extend_from_slice(mlkem);
    // SharedSecret zeroizes on drop. The component Vec from ecdh_p384 is not zeroized (spike limit; the
    // aegis-tls version should use zeroize::Zeroizing).
    Ok(SharedSecret::from(z))
}

impl SupportedKxGroup for SecP384r1MlKem1024 {
    /// Client side: fresh P-384 key and ML-KEM-1024 decapsulation key.
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let ecdh = agreement::PrivateKey::generate(&agreement::ECDH_P384)
            .map_err(|_| internal("p384: keygen"))?;
        let dk = kem::DecapsulationKey::generate(&kem::ML_KEM_1024)
            .map_err(|_| internal("mlkem1024: keygen"))?;
        let ek = dk
            .encapsulation_key()
            .and_then(|ek| ek.key_bytes())
            .map_err(|_| internal("mlkem1024: encapsulation key"))?;
        let ek = ek.as_ref().to_vec();
        Active::new(ecdh, dk, &ek).map(|a| Box::new(a) as Box<dyn ActiveKeyExchange>)
    }

    /// Server side: validate the client share, encapsulate, and do ECDH with a fresh P-384 key.
    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (client_point, client_ek) = split_share(client_share, MLKEM1024_EK_LEN)?;

        // EncapsulationKey::new checks only the length; the FIPS 203 7.2 modulus check runs inside
        // encapsulate (aws-lc mlkem/kem.c: mlk_kem_check_pk before enc). Failure -> illegal_parameter.
        let ek = kem::EncapsulationKey::new(&kem::ML_KEM_1024, client_ek).map_err(|_| INVALID_KEY_SHARE)?;
        let (ct, mlkem_secret) = ek.encapsulate().map_err(|_| INVALID_KEY_SHARE)?;

        let ecdh = agreement::PrivateKey::generate(&agreement::ECDH_P384)
            .map_err(|_| internal("p384: keygen"))?;
        let ecdh_secret = ecdh_p384(&ecdh, client_point)?;
        let server_point = p384_public(&ecdh)?;

        let ct = ct.as_ref();
        if ct.len() != MLKEM1024_CT_LEN {
            return Err(internal("mlkem1024: ciphertext length"));
        }
        let mut pub_key = Vec::with_capacity(SERVER_SHARE_LEN);
        pub_key.extend_from_slice(&server_point);
        pub_key.extend_from_slice(ct);

        Ok(CompletedKeyExchange {
            group: NAME,
            pub_key,
            secret: combine(&ecdh_secret, mlkem_secret.as_ref())?,
        })
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NAME
    }

    /// SP 800-56Cr2 "Z || T": the first secret controls approval; for this group that is ECDH P-384
    /// (RFC 10024 section 5). Both primitives are inside the AWS-LC FIPS module boundary (see README "FIPS");
    /// this reports true only when aws-lc-rs runs in FIPS mode (aws-lc-fips-sys build). Same policy as
    /// rustls' own SECP256R1MLKEM768 (pq/hybrid.rs: classical.fips() when classical is first).
    fn fips(&self) -> bool {
        aws_lc_rs::try_fips_mode().is_ok()
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

/// Client-side in-flight exchange.
pub struct Active {
    ecdh: agreement::PrivateKey,
    dk: kem::DecapsulationKey<kem::AlgorithmId>,
    ecdh_point: Vec<u8>,
    pub_key: Vec<u8>,
}

impl Active {
    fn new(
        ecdh: agreement::PrivateKey,
        dk: kem::DecapsulationKey<kem::AlgorithmId>,
        ek: &[u8],
    ) -> Result<Self, Error> {
        let ecdh_point = p384_public(&ecdh)?;
        if ek.len() != MLKEM1024_EK_LEN {
            return Err(internal("mlkem1024: encapsulation key length"));
        }
        let mut pub_key = Vec::with_capacity(CLIENT_SHARE_LEN);
        pub_key.extend_from_slice(&ecdh_point);
        pub_key.extend_from_slice(ek);
        Ok(Self { ecdh, dk, ecdh_point, pub_key })
    }

    /// Known-answer-test constructor: fixed P-384 scalar (48 bytes) and ML-KEM-1024 decapsulation key
    /// (3168 bytes, FIPS 203 dk format). Never used on a live path.
    #[doc(hidden)]
    pub fn from_fixed_keys_for_kat(p384_scalar: &[u8], mlkem_dk: &[u8]) -> Result<Self, Error> {
        let ecdh = agreement::PrivateKey::from_private_key(&agreement::ECDH_P384, p384_scalar)
            .map_err(|_| internal("kat: p384 scalar"))?;
        let dk = kem::DecapsulationKey::new(&kem::ML_KEM_1024, mlkem_dk)
            .map_err(|_| internal("kat: mlkem dk"))?;
        // FIPS 203 dk = dk_pke (384*k = 1536) || ek (1568) || H(ek) (32) || z (32). aws-lc-rs cannot derive
        // the ek of an imported raw dk, so take it from the dk bytes.
        let ek = mlkem_dk
            .get(1536..1536 + MLKEM1024_EK_LEN)
            .ok_or_else(|| internal("kat: mlkem dk length"))?;
        Self::new(ecdh, dk, ek)
    }
}

impl ActiveKeyExchange for Active {
    fn complete(self: Box<Self>, server_share: &[u8]) -> Result<SharedSecret, Error> {
        // RFC 10024 4.2: client MUST check the ciphertext length -> illegal_parameter.
        let (server_point, ct) = split_share(server_share, MLKEM1024_CT_LEN)?;
        let mlkem_secret = self
            .dk
            .decapsulate(ct.into())
            .map_err(|_| internal("mlkem1024: decapsulation"))?;
        let ecdh_secret = ecdh_p384(&self.ecdh, server_point)?;
        combine(&ecdh_secret, mlkem_secret.as_ref())
    }

    /// Lets a rustls client that also lists secp384r1 reuse the P-384 half as its secp384r1 key share
    /// (same mechanism as rustls' built-in hybrids).
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((NamedGroup::secp384r1, &self.ecdh_point))
    }

    fn complete_hybrid_component(self: Box<Self>, peer_point: &[u8]) -> Result<SharedSecret, Error> {
        if peer_point.len() != P384_SHARE_LEN || peer_point.first() != Some(&UNCOMPRESSED) {
            return Err(INVALID_KEY_SHARE);
        }
        ecdh_p384(&self.ecdh, peer_point).map(SharedSecret::from)
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NAME
    }
}
