//! Key exchange: X25519 (libcrux-curve25519), secp256r1 (libcrux-p256), X25519MLKEM768 (libcrux-ml-kem +
//! libcrux-curve25519; draft-ietf-tls-ecdhe-mlkem / RFC 10024 wire format: ML-KEM part FIRST in shares and secret).
//!
//! The `pub fn` helpers are the only paths to the primitives; the groups and the KATs both use them.
use libcrux_ml_kem::mlkem768;
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved};
use zeroize::Zeroizing;

use crate::random;

pub const MLKEM768_EK_LEN: usize = 1184;
pub const MLKEM768_DK_LEN: usize = 2400;
pub const MLKEM768_CT_LEN: usize = 1088;
pub const X25519_LEN: usize = 32;
pub const P256_POINT_LEN: usize = 65;

fn bad_share() -> Error {
    Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
}

// ------------------------------------------------------------------------------------------- primitives

/// X25519(k, 9).
pub fn x25519_public(sk: &[u8; 32]) -> [u8; 32] {
    let mut pk = [0u8; 32];
    libcrux_curve25519::secret_to_public(&mut pk, sk);
    pk
}

/// X25519(k, u). Fails on a wrong-length peer value and on the all-zero output (RFC 7748 6.1, RFC 8446 7.4.2).
pub fn x25519(sk: &[u8; 32], peer: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let peer: &[u8; 32] = peer.try_into().map_err(|_| bad_share())?;
    let mut ss = Zeroizing::new([0u8; 32]);
    libcrux_curve25519::ecdh(&mut ss, peer, sk).map_err(|_| bad_share())?;
    Ok(ss)
}

/// P-256 public point (uncompressed, 65 bytes) for a scalar; fails if the scalar is not in [1, n-1].
pub fn p256_public(sk: &[u8; 32]) -> Result<[u8; P256_POINT_LEN], Error> {
    if !libcrux_p256::validate_private_key(sk) {
        return Err(Error::General("p256: invalid scalar".into()));
    }
    let mut raw = [0u8; 64];
    if !libcrux_p256::dh_initiator(&mut raw, sk) {
        return Err(Error::General("p256: keygen failed".into()));
    }
    let mut pk = [0u8; P256_POINT_LEN];
    libcrux_p256::raw_to_uncompressed(&raw, &mut pk);
    Ok(pk)
}

/// P-256 ECDH: x-coordinate of sk * peer. Peer must be an uncompressed point on the curve (RFC 8446 4.2.8.2).
pub fn p256(sk: &[u8; 32], peer: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    if peer.len() != P256_POINT_LEN || peer.first() != Some(&0x04) {
        return Err(bad_share());
    }
    let mut raw = [0u8; 64];
    if !libcrux_p256::uncompressed_to_raw(peer, &mut raw) {
        return Err(bad_share());
    }
    let mut out = Zeroizing::new([0u8; 64]);
    if !libcrux_p256::dh_responder(out.as_mut_slice(), &raw, sk) {
        return Err(bad_share());
    }
    let mut x = Zeroizing::new([0u8; 32]);
    x.copy_from_slice(out.get(..32).ok_or_else(bad_share)?);
    Ok(x)
}

/// ML-KEM-768 KeyGen_internal(d, z) with seed = d || z (FIPS 203 6.1). Returns (ek, dk).
pub fn mlkem768_keygen(seed: [u8; 64]) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let kp = mlkem768::generate_key_pair(seed);
    (kp.public_key().as_ref().to_vec(), Zeroizing::new(kp.private_key().as_ref().to_vec()))
}

/// ML-KEM-768 Encaps_internal(ek, m), after the FIPS 203 7.2 encapsulation-key check (length + modulus).
pub fn mlkem768_encaps(ek: &[u8], m: [u8; 32]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), Error> {
    let ek: [u8; MLKEM768_EK_LEN] = ek.try_into().map_err(|_| bad_share())?;
    let ek = mlkem768::MlKem768PublicKey::from(ek);
    if !mlkem768::validate_public_key(&ek) {
        return Err(bad_share());
    }
    let (ct, ss) = mlkem768::encapsulate(&ek, m);
    Ok((ct.as_ref().to_vec(), Zeroizing::new(ss)))
}

/// ML-KEM-768 Decaps_internal(dk, c) (implicit rejection on a bad ciphertext). Lengths are checked (FIPS 203 7.3).
pub fn mlkem768_decaps(dk: &[u8], ct: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let dk: [u8; MLKEM768_DK_LEN] = dk.try_into().map_err(|_| Error::General("mlkem: dk length".into()))?;
    let ct: [u8; MLKEM768_CT_LEN] = ct.try_into().map_err(|_| bad_share())?;
    let dk = Zeroizing::new(dk);
    let dk = mlkem768::MlKem768PrivateKey::from(*dk);
    let ct = mlkem768::MlKem768Ciphertext::from(ct);
    Ok(Zeroizing::new(mlkem768::decapsulate(&dk, &ct)))
}

// ------------------------------------------------------------------------------------------- groups

#[derive(Debug)]
pub struct X25519Group;
#[derive(Debug)]
pub struct P256Group;
#[derive(Debug)]
pub struct X25519MlKem768Group;

pub static X25519: &dyn SupportedKxGroup = &X25519Group;
pub static SECP256R1: &dyn SupportedKxGroup = &P256Group;
pub static X25519MLKEM768: &dyn SupportedKxGroup = &X25519MlKem768Group;

/// Server preference order: hybrid first.
pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[X25519MLKEM768, X25519, SECP256R1];

struct ActiveX25519 {
    sk: Zeroizing<[u8; 32]>,
    pk: [u8; 32],
}

impl SupportedKxGroup for X25519Group {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let sk = Zeroizing::new(random::<32>()?);
        let pk = x25519_public(&sk);
        Ok(Box::new(ActiveX25519 { sk, pk }))
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl ActiveKeyExchange for ActiveX25519 {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        Ok(SharedSecret::from(x25519(&self.sk, peer_pub_key)?.as_slice()))
    }
    fn pub_key(&self) -> &[u8] {
        &self.pk
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct ActiveP256 {
    sk: Zeroizing<[u8; 32]>,
    pk: [u8; P256_POINT_LEN],
}

impl SupportedKxGroup for P256Group {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        // Rejection sampling: a random 32-byte string is >= n with probability ~2^-32.
        for _ in 0..16 {
            let sk = Zeroizing::new(random::<32>()?);
            if let Ok(pk) = p256_public(&sk) {
                return Ok(Box::new(ActiveP256 { sk, pk }));
            }
        }
        Err(Error::FailedToGetRandomBytes)
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}

impl ActiveKeyExchange for ActiveP256 {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        Ok(SharedSecret::from(p256(&self.sk, peer_pub_key)?.as_slice()))
    }
    fn pub_key(&self) -> &[u8] {
        &self.pk
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}

/// Client half of X25519MLKEM768 (used by the KAT round trip; the spike's scope is the server half).
struct ActiveHybrid {
    dk: Zeroizing<Vec<u8>>,
    x_sk: Zeroizing<[u8; 32]>,
    share: Vec<u8>,
}

impl SupportedKxGroup for X25519MlKem768Group {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let seed = Zeroizing::new(random::<64>()?);
        let (ek, dk) = mlkem768_keygen(*seed);
        let x_sk = Zeroizing::new(random::<32>()?);
        let mut share = ek;
        share.extend_from_slice(&x25519_public(&x_sk));
        Ok(Box::new(ActiveHybrid { dk, x_sk, share }))
    }

    /// Server half: client share = ek (1184) || X25519 (32); server share = ct (1088) || X25519 (32);
    /// secret = ML-KEM ss (32) || X25519 ss (32).
    #[cfg(not(feature = "mutant-kx-swap"))]
    fn start_and_complete(&self, peer_pub_key: &[u8]) -> Result<CompletedKeyExchange, Error> {
        if peer_pub_key.len() != MLKEM768_EK_LEN + X25519_LEN {
            return Err(bad_share());
        }
        let (ek, x_peer) = peer_pub_key.split_at_checked(MLKEM768_EK_LEN).ok_or_else(bad_share)?;
        let m = Zeroizing::new(random::<32>()?);
        let (ct, k) = mlkem768_encaps(ek, *m)?;
        let x_sk = Zeroizing::new(random::<32>()?);
        let x_ss = x25519(&x_sk, x_peer)?;
        let mut pub_key = ct;
        pub_key.extend_from_slice(&x25519_public(&x_sk));
        let mut secret = Vec::with_capacity(64);
        secret.extend_from_slice(k.as_slice());
        secret.extend_from_slice(x_ss.as_slice());
        Ok(CompletedKeyExchange { group: NamedGroup::X25519MLKEM768, pub_key, secret: SharedSecret::from(secret) })
    }

    /// SELF-TEST MUTANT (gate.sh --self-test): the group is announced as X25519MLKEM768 but runs plain X25519 on
    /// the last 32 bytes of the client share and answers with a 32-byte X25519 share.
    #[cfg(feature = "mutant-kx-swap")]
    fn start_and_complete(&self, peer_pub_key: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let split = peer_pub_key.len().checked_sub(X25519_LEN).ok_or_else(bad_share)?;
        let (_, x_peer) = peer_pub_key.split_at_checked(split).ok_or_else(bad_share)?;
        let x_sk = Zeroizing::new(random::<32>()?);
        let x_ss = x25519(&x_sk, x_peer)?;
        Ok(CompletedKeyExchange {
            group: NamedGroup::X25519MLKEM768,
            pub_key: x25519_public(&x_sk).to_vec(),
            secret: SharedSecret::from(x_ss.as_slice()),
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

impl ActiveKeyExchange for ActiveHybrid {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != MLKEM768_CT_LEN + X25519_LEN {
            return Err(bad_share());
        }
        let (ct, x_peer) = peer_pub_key.split_at_checked(MLKEM768_CT_LEN).ok_or_else(bad_share)?;
        let k = mlkem768_decaps(&self.dk, ct)?;
        let x_ss = x25519(&self.x_sk, x_peer)?;
        let mut secret = Vec::with_capacity(64);
        secret.extend_from_slice(k.as_slice());
        secret.extend_from_slice(x_ss.as_slice());
        Ok(SharedSecret::from(secret))
    }
    fn pub_key(&self) -> &[u8] {
        &self.share
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}
