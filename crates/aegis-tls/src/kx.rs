//! SecP384r1MLKEM1024 (TLS supported group 0x11ED) as a rustls `SupportedKxGroup`, built on aws-lc-rs
//! primitives (ECDH P-384 + ML-KEM-1024). Ported from spike q4-026 (`spikes/q4-026/src/kx.rs`, verdict: keep;
//! interop with OpenSSL 3.5.9 and Go 1.26.10 recorded there). ARCHITECTURE 3.2: 0x11ED is AEGIS-owned code.
//!
//! Wire format and combiner (RFC 10024, from draft-ietf-tls-ecdhe-mlkem):
//! - 4.1 client share  = P-384 uncompressed point (97) || ML-KEM-1024 encapsulation key (1568) = 1665 bytes
//! - 4.2 server share  = P-384 uncompressed point (97) || ML-KEM-1024 ciphertext (1568)        = 1665 bytes
//! - 4.3 shared secret = ECDHE x-coordinate (48) || ML-KEM shared secret (32)                    = 80 bytes
//!
//! The classical part comes FIRST in share and secret: the opposite of X25519MLKEM768, the same as
//! SecP256r1MLKEM768 (RFC 10024 section 5).
//!
//! Validation (RFC 10024 4.2): the server runs the FIPS 203 sec 7.2 encapsulation-key check (inside aws-lc
//! `encapsulate`); the client checks the ciphertext length; both run the point checks (aws-lc on-curve check).
//! rustls 0.23.46 maps every `start_and_complete` / `complete` error to illegal_parameter (47).
//!
//! Secret hygiene: the 80-byte combined secret is assembled in place inside one buffer that becomes the rustls
//! `SharedSecret` (zeroized on drop); no intermediate copy of the ECDH or ML-KEM component is kept (the spike
//! left both in unzeroized `Vec`s). The aws-lc-rs ML-KEM `SharedSecret` zeroizes itself.
//!
//! Not yet done (Phase-6 gate, ARCHITECTURE 3.2): Kani panic-freedom harness on share parsing, BoringSSL interop.

use std::boxed::Box;
use std::vec::Vec;

use aws_lc_rs::{agreement, kem};
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};

/// IANA TLS Supported Groups value 4589 (RFC 10024 section 7.3). Not a named variant in rustls 0.23.46.
pub const CODEPOINT: u16 = 0x11ED;
/// The rustls name of the group.
pub const NAME: NamedGroup = NamedGroup::Unknown(CODEPOINT);

/// `0x04 || X(48) || Y(48)`.
pub const P384_SHARE_LEN: usize = 97;
/// FIPS 203 ML-KEM-1024 encapsulation key length.
pub const MLKEM1024_EK_LEN: usize = 1568;
/// FIPS 203 ML-KEM-1024 ciphertext length.
pub const MLKEM1024_CT_LEN: usize = 1568;
/// Client key share length (1665).
pub const CLIENT_SHARE_LEN: usize = P384_SHARE_LEN + MLKEM1024_EK_LEN;
/// Server key share length (1665).
pub const SERVER_SHARE_LEN: usize = P384_SHARE_LEN + MLKEM1024_CT_LEN;
/// ECDH P-384 x-coordinate length.
pub const P384_SECRET_LEN: usize = 48;
/// ML-KEM shared secret length.
pub const MLKEM_SECRET_LEN: usize = 32;
/// Combined shared secret length (80).
pub const SHARED_SECRET_LEN: usize = P384_SECRET_LEN + MLKEM_SECRET_LEN;

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

/// Split a received share into (P-384 point, ML-KEM part). The total length must be exact and the point must be
/// in uncompressed form (RFC 9846 4.3.8.2: legacy_form = 4).
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

/// ECDH P-384 with on-curve validation by aws-lc; appends the 48-byte x-coordinate (RFC 9846 7.4.2) to `out`.
fn ecdh_p384_into(private: &agreement::PrivateKey, peer_point: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
    let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P384, peer_point);
    agreement::agree(private, peer, INVALID_KEY_SHARE, |z| {
        if z.len() != P384_SECRET_LEN {
            return Err(internal("p384: unexpected secret length"));
        }
        out.extend_from_slice(z);
        Ok(())
    })
}

fn p384_public(private: &agreement::PrivateKey) -> Result<Vec<u8>, Error> {
    let public = private.compute_public_key().map_err(|_| internal("p384: public key"))?;
    let bytes = public.as_ref();
    if bytes.len() != P384_SHARE_LEN || bytes.first() != Some(&UNCOMPRESSED) {
        return Err(internal("p384: public key not uncompressed"));
    }
    Ok(bytes.to_vec())
}

/// RFC 10024 4.3: ECDHE secret first, then the ML-KEM secret, assembled in one buffer that becomes the
/// (zeroize-on-drop) rustls `SharedSecret`. On an error path the partial buffer is wrapped too, so it is
/// zeroized as well.
fn combine(private: &agreement::PrivateKey, peer_point: &[u8], mlkem: &[u8]) -> Result<SharedSecret, Error> {
    let mut z = Vec::with_capacity(SHARED_SECRET_LEN);
    let r = ecdh_p384_into(private, peer_point, &mut z);
    if r.is_ok() && mlkem.len() == MLKEM_SECRET_LEN {
        z.extend_from_slice(mlkem);
    }
    let secret = SharedSecret::from(z);
    r?;
    if secret.secret_bytes().len() != SHARED_SECRET_LEN {
        return Err(internal("combiner: component length"));
    }
    Ok(secret)
}

impl SupportedKxGroup for SecP384r1MlKem1024 {
    /// Client side: fresh P-384 key and ML-KEM-1024 decapsulation key.
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let ecdh = agreement::PrivateKey::generate(&agreement::ECDH_P384).map_err(|_| internal("p384: keygen"))?;
        let dk = kem::DecapsulationKey::generate(&kem::ML_KEM_1024).map_err(|_| internal("mlkem1024: keygen"))?;
        let ek = dk
            .encapsulation_key()
            .and_then(|ek| ek.key_bytes())
            .map_err(|_| internal("mlkem1024: encapsulation key"))?;
        Active::new(ecdh, dk, ek.as_ref()).map(|a| Box::new(a) as Box<dyn ActiveKeyExchange>)
    }

    /// Server side: validate the client share, encapsulate, and do ECDH with a fresh P-384 key.
    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (client_point, client_ek) = split_share(client_share, MLKEM1024_EK_LEN)?;

        // EncapsulationKey::new checks only the length; the FIPS 203 7.2 modulus check runs inside encapsulate.
        let ek = kem::EncapsulationKey::new(&kem::ML_KEM_1024, client_ek).map_err(|_| INVALID_KEY_SHARE)?;
        let (ct, mlkem_secret) = ek.encapsulate().map_err(|_| INVALID_KEY_SHARE)?;

        let ecdh = agreement::PrivateKey::generate(&agreement::ECDH_P384).map_err(|_| internal("p384: keygen"))?;
        let secret = combine(&ecdh, client_point, mlkem_secret.as_ref())?;
        let server_point = p384_public(&ecdh)?;

        let ct = ct.as_ref();
        if ct.len() != MLKEM1024_CT_LEN {
            return Err(internal("mlkem1024: ciphertext length"));
        }
        let mut pub_key = Vec::with_capacity(SERVER_SHARE_LEN);
        pub_key.extend_from_slice(&server_point);
        pub_key.extend_from_slice(ct);

        Ok(CompletedKeyExchange { group: NAME, pub_key, secret })
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NAME
    }

    /// Both primitives are inside the AWS-LC FIPS module boundary (spike q4-026 "FIPS boundary", desk check);
    /// reports true only when aws-lc-rs runs in FIPS mode. Same policy as rustls' SECP256R1MLKEM768. Module
    /// identity (P-PQ5) is not visible here: `try_fips_mode()` cannot tell 3.1.0 from 4.2.0.
    fn fips(&self) -> bool {
        aws_lc_rs::try_fips_mode().is_ok()
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

/// Client-side in-flight exchange (used by `start`; the server crate builds no rustls client, see
/// spikes/cmvp-client-policy, but the trait requires the client half and the KAT exercises it).
pub struct Active {
    ecdh: agreement::PrivateKey,
    dk: kem::DecapsulationKey<kem::AlgorithmId>,
    ecdh_point: Vec<u8>,
    pub_key: Vec<u8>,
}

impl core::fmt::Debug for Active {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Active").field("group", &NAME).finish_non_exhaustive()
    }
}

impl Active {
    fn new(ecdh: agreement::PrivateKey, dk: kem::DecapsulationKey<kem::AlgorithmId>, ek: &[u8]) -> Result<Self, Error> {
        let ecdh_point = p384_public(&ecdh)?;
        if ek.len() != MLKEM1024_EK_LEN {
            return Err(internal("mlkem1024: encapsulation key length"));
        }
        let mut pub_key = Vec::with_capacity(CLIENT_SHARE_LEN);
        pub_key.extend_from_slice(&ecdh_point);
        pub_key.extend_from_slice(ek);
        Ok(Self { ecdh, dk, ecdh_point, pub_key })
    }

    /// Known-answer-test constructor: fixed P-384 scalar (48 bytes) and ML-KEM-1024 decapsulation key (3168 bytes,
    /// FIPS 203 dk format). Test-only: `kem::DecapsulationKey::new` does not exist on the cmvp lock
    /// (aws-lc-rs 1.15.3), and a raw-dk import has no place on a live path.
    #[cfg(test)]
    pub(crate) fn from_fixed_keys_for_kat(p384_scalar: &[u8], mlkem_dk: &[u8]) -> Result<Self, Error> {
        let ecdh = agreement::PrivateKey::from_private_key(&agreement::ECDH_P384, p384_scalar)
            .map_err(|_| internal("kat: p384 scalar"))?;
        let dk = kem::DecapsulationKey::new(&kem::ML_KEM_1024, mlkem_dk).map_err(|_| internal("kat: mlkem dk"))?;
        // FIPS 203 dk = dk_pke (384*k = 1536) || ek (1568) || H(ek) (32) || z (32).
        let ek = mlkem_dk.get(1536..1536 + MLKEM1024_EK_LEN).ok_or_else(|| internal("kat: mlkem dk length"))?;
        Self::new(ecdh, dk, ek)
    }
}

impl ActiveKeyExchange for Active {
    fn complete(self: Box<Self>, server_share: &[u8]) -> Result<SharedSecret, Error> {
        // RFC 10024 4.2: the client MUST check the ciphertext length -> illegal_parameter.
        let (server_point, ct) = split_share(server_share, MLKEM1024_CT_LEN)?;
        let mlkem_secret = self.dk.decapsulate(ct.into()).map_err(|_| internal("mlkem1024: decapsulation"))?;
        combine(&self.ecdh, server_point, mlkem_secret.as_ref())
    }

    /// Lets a client that also lists secp384r1 reuse the P-384 half as its secp384r1 key share.
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((NamedGroup::secp384r1, &self.ecdh_point))
    }

    fn complete_hybrid_component(self: Box<Self>, peer_point: &[u8]) -> Result<SharedSecret, Error> {
        if peer_point.len() != P384_SHARE_LEN || peer_point.first() != Some(&UNCOMPRESSED) {
            return Err(INVALID_KEY_SHARE);
        }
        let mut z = Vec::with_capacity(P384_SECRET_LEN);
        let r = ecdh_p384_into(&self.ecdh, peer_point, &mut z);
        let secret = SharedSecret::from(z);
        r.map(|()| secret)
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

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    //! Ported from the q4-026 selftest. The handshake-level negative tests there drove a rustls client; this
    //! crate's default build constructs no `ClientConfig` (spikes/cmvp-client-policy), so the same malformed
    //! shares are fed to the group's two entry points directly (`start_and_complete` = server parsing a
    //! ClientHello share, `complete` = client parsing a ServerHello share). rustls maps every error from either
    //! to alert 47.
    use super::*;
    use std::collections::HashMap;

    const KAT_MLKEM: &str = include_str!("../kat/acvp-mlkem1024.txt");
    const KAT_P384: &str = include_str!("../kat/rfc5903-p384.txt");

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "odd hex");
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn p384() -> HashMap<&'static str, Vec<u8>> {
        KAT_P384
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split_once(' '))
            .map(|(k, v)| (k, hex(v)))
            .collect()
    }

    fn client_share() -> Vec<u8> {
        SECP384R1MLKEM1024.start().unwrap().pub_key().to_vec()
    }

    fn server_share_for(active: &dyn ActiveKeyExchange) -> Vec<u8> {
        SECP384R1MLKEM1024.start_and_complete(active.pub_key()).unwrap().pub_key
    }

    /// Composite KAT (spike K-dec-96..105): RFC 5903 8.2 P-384 scalar i + ACVP ML-KEM-1024 dk. The client share
    /// must be g^i || ek; given the server share g^r || c the secret must be exactly girx || k (80 bytes). Pins
    /// the layout, the split, the combiner order and the x-coordinate encoding against third-party numbers,
    /// including the 5 ACVP modified-ciphertext (implicit rejection) cases.
    #[test]
    fn kat_composite_decapsulation() {
        let p = p384();
        let gi = [vec![0x04], p["gix"].clone(), p["giy"].clone()].concat();
        let gr = [vec![0x04], p["grx"].clone(), p["gry"].clone()].concat();
        let mut n = 0;
        for line in KAT_MLKEM.lines().filter(|l| l.starts_with("dec ")) {
            let f: Vec<&str> = line.split(' ').collect();
            let (tc, dk, c, k) = (f[1], hex(f[2]), hex(f[3]), hex(f[4]));
            let active = Active::from_fixed_keys_for_kat(&p["i"], &dk).unwrap();
            assert_eq!(active.pub_key().len(), CLIENT_SHARE_LEN, "tc {tc}");
            assert_eq!(&active.pub_key()[..P384_SHARE_LEN], gi.as_slice(), "tc {tc}: client share = g^i || ek");
            assert_eq!(&active.pub_key()[P384_SHARE_LEN..], &dk[1536..1536 + MLKEM1024_EK_LEN], "tc {tc}");
            let secret = Box::new(active).complete(&[gr.clone(), c].concat()).unwrap();
            assert_eq!(secret.secret_bytes(), [p["girx"].clone(), k].concat().as_slice(), "tc {tc}: girx || k");
            n += 1;
        }
        assert_eq!(n, 10);
    }

    /// The order mutant (ML-KEM secret first, X25519MLKEM768 style) must not match the KAT: proves the KAT can go
    /// red on the one bug interop caught in the spike.
    #[test]
    fn kat_rejects_swapped_combiner_order() {
        let p = p384();
        let gr = [vec![0x04], p["grx"].clone(), p["gry"].clone()].concat();
        let line = KAT_MLKEM.lines().find(|l| l.starts_with("dec ")).unwrap();
        let f: Vec<&str> = line.split(' ').collect();
        let (dk, c, k) = (hex(f[2]), hex(f[3]), hex(f[4]));
        let secret =
            Box::new(Active::from_fixed_keys_for_kat(&p["i"], &dk).unwrap()).complete(&[gr, c].concat()).unwrap();
        let swapped = [k, p["girx"].clone()].concat();
        assert_ne!(secret.secret_bytes(), swapped.as_slice());
    }

    /// ACVP encapsulationKeyCheck (spike K-ekc-156..165) through the server entry point: the 5 invalid ek are
    /// rejected (FIPS 203 7.2 modulus check, -> alert 47), the 5 valid ek accepted.
    #[test]
    fn acvp_encapsulation_key_check() {
        let point = client_share()[..P384_SHARE_LEN].to_vec();
        let (mut valid, mut invalid) = (0, 0);
        for line in KAT_MLKEM.lines().filter(|l| l.starts_with("ekc ")) {
            let f: Vec<&str> = line.split(' ').collect();
            let (tc, ek, ok) = (f[1], hex(f[2]), f[3] == "1");
            let r = SECP384R1MLKEM1024.start_and_complete(&[point.clone(), ek].concat());
            if ok {
                assert!(r.is_ok(), "tc {tc}: valid ek rejected");
                valid += 1;
            } else {
                assert!(matches!(r, Err(INVALID_KEY_SHARE)), "tc {tc}: invalid ek accepted");
                invalid += 1;
            }
        }
        assert_eq!((valid, invalid), (5, 5));
    }

    #[test]
    fn round_trip_agrees() {
        let client = SECP384R1MLKEM1024.start().unwrap();
        assert_eq!(client.group(), NAME);
        let done = SECP384R1MLKEM1024.start_and_complete(client.pub_key()).unwrap();
        assert_eq!(done.group, NAME);
        assert_eq!(done.pub_key.len(), SERVER_SHARE_LEN);
        assert_eq!(done.pub_key[0], 0x04);
        let c = client.complete(&done.pub_key).unwrap();
        assert_eq!(c.secret_bytes().len(), SHARED_SECRET_LEN);
        assert_eq!(c.secret_bytes(), done.secret.secret_bytes());
    }

    #[test]
    fn hybrid_component_is_p384_half() {
        let client = SECP384R1MLKEM1024.start().unwrap();
        let (g, point) = client.hybrid_component().unwrap();
        assert_eq!(g, NamedGroup::secp384r1);
        assert_eq!(point, &client.pub_key()[..P384_SHARE_LEN]);
        let srv = agreement::PrivateKey::generate(&agreement::ECDH_P384).unwrap();
        let srv_pub = srv.compute_public_key().unwrap().as_ref().to_vec();
        let s = client.complete_hybrid_component(&srv_pub).unwrap();
        assert_eq!(s.secret_bytes().len(), P384_SECRET_LEN);
    }

    fn mutate(mut v: Vec<u8>, f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        f(&mut v);
        v
    }

    /// Spike N-c-*: the server must reject every malformed client share (rustls -> alert 47).
    #[test]
    fn negative_client_shares_rejected_by_server() {
        let mut bad_ek = vec![0u8; MLKEM1024_EK_LEN];
        bad_ek[0] = 0xFF;
        bad_ek[1] = 0x0F; // first 12-bit coefficient 0xFFF >= q = 3329
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("N-c-short1", mutate(client_share(), |v| v.truncate(CLIENT_SHARE_LEN - 1))),
            ("N-c-short-1568", mutate(client_share(), |v| v.truncate(P384_SHARE_LEN))),
            ("N-c-long1", mutate(client_share(), |v| v.push(0))),
            ("N-c-prefix02", mutate(client_share(), |v| v[0] = 0x02)),
            ("N-c-prefix00", mutate(client_share(), |v| v[0] = 0x00)),
            ("N-c-offcurve", mutate(client_share(), |v| v[96] ^= 0x01)),
            (
                "N-c-ek-coeff>q",
                mutate(client_share(), |v| {
                    v.truncate(P384_SHARE_LEN);
                    v.extend_from_slice(&bad_ek);
                }),
            ),
            ("N-c-empty", Vec::new()),
        ];
        for (id, share) in cases {
            let r = SECP384R1MLKEM1024.start_and_complete(&share);
            assert!(matches!(r, Err(INVALID_KEY_SHARE)), "{id}: not rejected with InvalidKeyShare");
        }
    }

    /// Spike N-s-*: the client must reject every malformed server share (rustls -> alert 47); a same-length
    /// ciphertext bit flip yields a different secret (implicit rejection), never the honest one.
    #[test]
    fn negative_server_shares_rejected_by_client() {
        type Case = (&'static str, fn(&mut Vec<u8>));
        let cases: [Case; 6] = [
            ("N-s-ct-short1", |v| v.truncate(SERVER_SHARE_LEN - 1)),
            ("N-s-ct-short-all", |v| v.truncate(P384_SHARE_LEN)),
            ("N-s-ct-long1", |v| v.push(0)),
            ("N-s-prefix02", |v| v[0] = 0x02),
            ("N-s-offcurve", |v| v[96] ^= 0x01),
            ("N-s-empty", |v| v.clear()),
        ];
        for (id, m) in cases {
            let client = SECP384R1MLKEM1024.start().unwrap();
            let share = mutate(server_share_for(client.as_ref()), m);
            assert!(client.complete(&share).is_err(), "{id}: accepted");
        }
        let client = SECP384R1MLKEM1024.start().unwrap();
        let done = SECP384R1MLKEM1024.start_and_complete(client.pub_key()).unwrap();
        let flipped = mutate(done.pub_key.clone(), |v| v[P384_SHARE_LEN + 10] ^= 0x01);
        let got = client.complete(&flipped).unwrap();
        assert_ne!(got.secret_bytes(), done.secret.secret_bytes(), "N-s-ct-bitflip: implicit rejection");
    }

    #[test]
    fn hybrid_component_rejects_bad_points() {
        for bad in [vec![], vec![0x04; P384_SHARE_LEN - 1], mutate(vec![0x04; P384_SHARE_LEN], |v| v[0] = 0x02)] {
            let client = SECP384R1MLKEM1024.start().unwrap();
            assert!(client.complete_hybrid_component(&bad).is_err());
        }
    }

    /// Spike F1 (reduced): random and edge-length inputs into both entry points never panic and are never
    /// accepted (a random 97-byte prefix is not a valid point).
    #[test]
    fn fuzz_entry_points_never_accept_garbage() {
        let mut seed: u64 = 0x11ED_0000_C0FF_EE00;
        let mut rnd = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for k in 0..600u32 {
            let len = match k % 4 {
                0 => (rnd() % 4000) as usize,
                1 => CLIENT_SHARE_LEN,
                2 => SERVER_SHARE_LEN + (rnd() % 3) as usize - 1,
                _ => P384_SHARE_LEN,
            };
            let mut v: Vec<u8> = (0..len).map(|_| rnd() as u8).collect();
            if k % 8 == 1 && !v.is_empty() {
                v[0] = 0x04;
            }
            assert!(SECP384R1MLKEM1024.start_and_complete(&v).is_err(), "iteration {k}: server accepted");
            assert!(SECP384R1MLKEM1024.start().unwrap().complete(&v).is_err(), "iteration {k}: client accepted");
        }
    }

    #[test]
    fn group_metadata() {
        assert_eq!(u16::from(SECP384R1MLKEM1024.name()), 0x11ED);
        assert!(SECP384R1MLKEM1024.usable_for_version(ProtocolVersion::TLSv1_3));
        assert!(!SECP384R1MLKEM1024.usable_for_version(ProtocolVersion::TLSv1_2));
        assert!(SECP384R1MLKEM1024.ffdhe_group().is_none());
        assert_eq!(SECP384R1MLKEM1024.fips(), aws_lc_rs::try_fips_mode().is_ok());
    }
}
