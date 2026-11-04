//! Profile builder tests (P-PQ1, P-PQ2, P-PQ4, F12 lists). Handshakes use a hand-built TLS 1.3 ClientHello fed to
//! a `ServerConnection` (same shape as oracles/hrr-verdicts); these tests build no rustls `ClientConfig` (the client
//! profile is tested in tests/client_profile.rs, feature `tls-client`).
#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use aegis_tls::profile::{group as g, kx_group};
use aegis_tls::{
    Profile, ProfileError, ProfileStatus, assert_profile, fips_status, negotiable_versions, server_config,
};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{self, EcdsaKeyPair, KeyPair, PqdsaKeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::ResolvesServerCert;
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{ProtocolVersion, ServerConnection, SignatureScheme};

const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11,
    0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];
const ALL_SIGS: [u16; 7] = [0x0403, 0x0503, 0x0804, 0x0807, 0x0904, 0x0905, 0x0906];

#[derive(Debug, PartialEq)]
enum Outcome {
    Hrr(u16),
    Sh(u16),
    Alert(u8),
    Other(String),
}

enum Key {
    EcdsaP256,
    EcdsaP384,
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

/// Server credential; the certificate bytes are a placeholder (the server never parses its own certificate,
/// `CertifiedKey::new` skips the key match), which is enough for selection and CertificateVerify scheme choice.
fn resolver(k: Key) -> Arc<dyn ResolvesServerCert> {
    let pkcs8 = match k {
        Key::EcdsaP256 => {
            EcdsaKeyPair::generate(&signature::ECDSA_P256_SHA256_ASN1_SIGNING).unwrap().to_pkcs8v1().unwrap()
        }
        Key::EcdsaP384 => {
            EcdsaKeyPair::generate(&signature::ECDSA_P384_SHA384_ASN1_SIGNING).unwrap().to_pkcs8v1().unwrap()
        }
        Key::MlDsa44 => PqdsaKeyPair::generate(&signature::ML_DSA_44_SIGNING).unwrap().to_pkcs8v1().unwrap(),
        Key::MlDsa65 => PqdsaKeyPair::generate(&signature::ML_DSA_65_SIGNING).unwrap().to_pkcs8v1().unwrap(),
        Key::MlDsa87 => PqdsaKeyPair::generate(&signature::ML_DSA_87_SIGNING).unwrap().to_pkcs8v1().unwrap(),
    };
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec()));
    let key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&der).unwrap();
    Arc::new(SingleCertAndKey::from(CertifiedKey::new(vec![CertificateDer::from(vec![0x30, 0x00])], key)))
}

fn share(group: u16) -> Vec<u8> {
    use aws_lc_rs::agreement::{ECDH_P256, ECDH_P384, PrivateKey, X25519};
    use aws_lc_rs::kem::{DecapsulationKey, ML_KEM_768, ML_KEM_1024};
    let ec = |a| PrivateKey::generate(a).unwrap().compute_public_key().unwrap().as_ref().to_vec();
    let mlkem =
        |a| DecapsulationKey::generate(a).unwrap().encapsulation_key().unwrap().key_bytes().unwrap().as_ref().to_vec();
    match group {
        g::X25519 => ec(&X25519),
        g::SECP256R1 => ec(&ECDH_P256),
        g::SECP384R1 => ec(&ECDH_P384),
        g::X25519MLKEM768 => [mlkem(&ML_KEM_768), ec(&X25519)].concat(),
        g::SECP256R1MLKEM768 => [ec(&ECDH_P256), mlkem(&ML_KEM_768)].concat(),
        g::SECP384R1MLKEM1024 => [ec(&ECDH_P384), mlkem(&ML_KEM_1024)].concat(),
        g::MLKEM1024 => mlkem(&ML_KEM_1024),
        _ => panic!("no share generator for {group:04x}"),
    }
}

fn ext(t: u16, body: &[u8]) -> Vec<u8> {
    [t.to_be_bytes().to_vec(), (body.len() as u16).to_be_bytes().to_vec(), body.to_vec()].concat()
}

fn list16(items: &[u16]) -> Vec<u8> {
    let b: Vec<u8> = items.iter().flat_map(|x| x.to_be_bytes()).collect();
    [(b.len() as u16).to_be_bytes().to_vec(), b].concat()
}

fn client_hello(groups: &[u16], shares: &[u16], sigs: &[u16], versions: &[u8]) -> Vec<u8> {
    let mut e = Vec::new();
    e.extend(ext(0x002b, &[&[versions.len() as u8][..], versions].concat()));
    e.extend(ext(0x000a, &list16(groups)));
    let mut ks = Vec::new();
    for s in shares {
        let k = share(*s);
        ks.extend(s.to_be_bytes());
        ks.extend((k.len() as u16).to_be_bytes());
        ks.extend(k);
    }
    e.extend(ext(0x0033, &[(ks.len() as u16).to_be_bytes().to_vec(), ks].concat()));
    e.extend(ext(0x000d, &list16(sigs)));
    let host = b"aegis.test";
    let mut sni = ((host.len() + 3) as u16).to_be_bytes().to_vec();
    sni.push(0);
    sni.extend((host.len() as u16).to_be_bytes());
    sni.extend(host);
    e.extend(ext(0x0000, &sni));
    let mut body = vec![0x03, 0x03];
    body.extend([0x11u8; 32]);
    body.push(32);
    body.extend([0x22u8; 32]);
    body.extend(list16(&[0x1301, 0x1302]));
    body.extend([0x01, 0x00]);
    body.extend((e.len() as u16).to_be_bytes());
    body.extend(e);
    let mut hs = vec![0x01];
    hs.extend(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend(body);
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend((hs.len() as u16).to_be_bytes());
    rec.extend(hs);
    rec
}

fn classify(out: &[u8]) -> Outcome {
    let b = |i: usize| out.get(i).copied();
    let u16at = |i: usize| Some(u16::from_be_bytes([b(i)?, b(i + 1)?]));
    if b(0) == Some(0x15) {
        return b(6).map(Outcome::Alert).unwrap_or(Outcome::Other("short alert".into()));
    }
    if b(0) != Some(0x16) || b(5) != Some(0x02) {
        return Outcome::Other(format!("first record {:02x?}", out.get(..6.min(out.len()))));
    }
    let hrr = out.get(11..43) == Some(&HRR_RANDOM[..]);
    let f = || -> Option<u16> {
        let mut i = 43;
        i += 1 + b(i)? as usize + 3;
        let end = i + 2 + u16at(i)? as usize;
        i += 2;
        while i + 4 <= end {
            if u16at(i)? == 0x0033 {
                return u16at(i + 4);
            }
            i += 4 + u16at(i + 2)? as usize;
        }
        None
    };
    match f() {
        Some(x) if hrr => Outcome::Hrr(x),
        Some(x) => Outcome::Sh(x),
        None => Outcome::Other("no key_share".into()),
    }
}

/// Returns the first-flight classification and, for a ServerHello, the server connection (to inspect it).
fn probe_with(
    profile: Profile,
    key: Key,
    groups: &[u16],
    shares: &[u16],
    sigs: &[u16],
    versions: &[u8],
) -> (Outcome, ServerConnection) {
    let cfg = Arc::new(server_config(profile, resolver(key)).unwrap());
    let mut s = ServerConnection::new(cfg).unwrap();
    let ch = client_hello(groups, shares, sigs, versions);
    let mut rd = &ch[..];
    while !rd.is_empty() {
        if s.read_tls(&mut rd).unwrap() == 0 {
            break;
        }
        if s.process_new_packets().is_err() {
            break;
        }
    }
    let mut out = Vec::new();
    while s.wants_write() {
        s.write_tls(&mut out).unwrap();
    }
    (classify(&out), s)
}

fn probe(profile: Profile, key: Key, groups: &[u16], shares: &[u16]) -> Outcome {
    probe_with(profile, key, groups, shares, &ALL_SIGS, &[0x03, 0x04]).0
}

fn configured(p: Profile) -> Vec<u16> {
    let cfg = server_config(p, resolver(Key::EcdsaP384)).unwrap();
    cfg.crypto_provider().kx_groups.iter().map(|x| u16::from(x.name())).collect()
}

#[test]
fn lists_match_f12_exactly() {
    use g::*;
    assert_eq!(
        Profile::PublicWeb.kx_groups(),
        [X25519MLKEM768, SECP384R1MLKEM1024, SECP256R1MLKEM768, X25519, SECP256R1]
    );
    assert_eq!(Profile::PqRequired.kx_groups(), [X25519MLKEM768]);
    assert_eq!(Profile::FipsFloor.kx_groups(), [SECP256R1MLKEM768, SECP256R1, SECP384R1]);
    assert_eq!(Profile::FipsCmvp.kx_groups(), [SECP256R1MLKEM768, SECP256R1, SECP384R1]);
    assert_eq!(Profile::FipsPqRequired.kx_groups(), [SECP256R1MLKEM768]);
    assert_eq!(Profile::Universal.kx_groups(), [SECP384R1MLKEM1024]);
    assert_eq!(Profile::BsiAlt.kx_groups(), [SECP384R1MLKEM1024, SECP256R1MLKEM768]);
    assert_eq!(Profile::Cnsa.kx_groups(), [MLKEM1024]);
    use SignatureScheme as S;
    assert_eq!(Profile::PublicWeb.sigalgs(), [S::ECDSA_NISTP256_SHA256]);
    assert_eq!(Profile::PqRequired.sigalgs(), [S::ECDSA_NISTP256_SHA256, S::ML_DSA_44]);
    assert_eq!(Profile::FipsFloor.sigalgs(), [S::ECDSA_NISTP256_SHA256, S::ECDSA_NISTP384_SHA384]);
    assert_eq!(Profile::FipsPqRequired.sigalgs(), [S::ECDSA_NISTP256_SHA256, S::ECDSA_NISTP384_SHA384]);
    assert_eq!(Profile::Universal.sigalgs(), [S::ML_DSA_87, S::ECDSA_NISTP384_SHA384]);
    assert_eq!(Profile::BsiAlt.sigalgs(), [S::ML_DSA_87, S::ECDSA_NISTP384_SHA384]);
    assert_eq!(Profile::Cnsa.sigalgs(), [S::ML_DSA_87]);
}

#[test]
fn every_listed_group_is_implemented_including_0x11ed() {
    for p in Profile::ALL {
        for c in p.kx_groups() {
            assert_eq!(kx_group(*c).map(|x| u16::from(x.name())), Some(*c), "{p:?} {c:04x}");
        }
    }
}

#[test]
fn names_round_trip() {
    for p in Profile::ALL {
        for n in [p.f12_name(), p.f8_name()].into_iter().flatten() {
            assert_eq!(Profile::from_name(n), Some(p));
        }
    }
    assert_eq!(Profile::from_name("PQ-REQUIRED"), Some(Profile::PqRequired));
    assert_eq!(Profile::from_name("P-PQ-REQUIRED"), Some(Profile::PqRequired));
    assert_eq!(Profile::from_name("FIPS"), Some(Profile::FipsFloor));
    // F8 has FIPS-PQ-REQUIRED (the same spelling as F12).
    assert_eq!(Profile::FipsPqRequired.f8_name(), Some("FIPS-PQ-REQUIRED"));
    assert_eq!(Profile::from_name("FIPS-PQ-REQUIRED"), Some(Profile::FipsPqRequired));
    assert_eq!(Profile::from_name("nope"), None);
}

#[test]
fn pending_profiles_are_refused_not_guessed() {
    // Since the 2026-11-04 F12 re-freeze only FIPS-CMVP (needs the cmvp build) is pending.
    for p in [Profile::Universal, Profile::BsiAlt, Profile::Cnsa] {
        assert_eq!(p.status(), ProfileStatus::Active, "{p:?}");
        assert_eq!(p.pending_reason(), None);
    }
    assert_eq!(Profile::FipsCmvp.status(), ProfileStatus::Pending);
    for p in Profile::ALL.into_iter().filter(|p| p.status() == ProfileStatus::Pending) {
        assert_eq!(p, Profile::FipsCmvp);
    }
    for p in Profile::ALL.into_iter().filter(|p| p.status() == ProfileStatus::Pending) {
        assert_eq!(p.status(), ProfileStatus::Pending);
        match server_config(p, resolver(Key::EcdsaP256)) {
            Err(ProfileError::Pending { profile, reason }) => {
                assert_eq!(profile, p);
                assert!(!reason.is_empty());
            }
            other => panic!("{p:?}: expected Pending, got {other:?}"),
        }
    }
}

#[test]
fn configured_groups_equal_profile_and_first_is_asserted() {
    for p in Profile::ALL.into_iter().filter(|p| p.status() != ProfileStatus::Pending) {
        assert_eq!(configured(p), p.kx_groups(), "{p:?}");
    }
    assert_eq!(configured(Profile::PublicWeb)[0], g::X25519MLKEM768);
}

#[test]
fn tls13_only_no_0rtt_no_tickets() {
    for p in Profile::ALL.into_iter().filter(|p| p.status() != ProfileStatus::Pending) {
        let cfg = server_config(p, resolver(Key::EcdsaP256)).unwrap();
        assert_eq!(negotiable_versions(&cfg), [ProtocolVersion::TLSv1_3], "{p:?}");
        assert_eq!(cfg.max_early_data_size, 0);
        assert_eq!(cfg.send_tls13_tickets, 0);
        let st = fips_status(&cfg);
        assert_eq!(st.config_fips, cfg.fips());
        assert!(!st.cmvp_claim);
        assert_eq!(st.module, None);
    }
}

#[test]
fn startup_assertion_catches_tampered_config() {
    let mut cfg = server_config(Profile::PqRequired, resolver(Key::EcdsaP256)).unwrap();
    assert!(assert_profile(&cfg, Profile::PqRequired).is_ok());
    assert!(matches!(assert_profile(&cfg, Profile::PublicWeb), Err(ProfileError::Assertion(_))));
    cfg.max_early_data_size = 16384;
    assert!(matches!(assert_profile(&cfg, Profile::PqRequired), Err(ProfileError::Assertion(_))));
    // X25519 prepended (the pq-required-x25519-first mutant) and appended (classical fallback)
    let base = server_config(Profile::PqRequired, resolver(Key::EcdsaP256)).unwrap();
    for kx in [
        vec![kx_group(g::X25519).unwrap(), kx_group(g::X25519MLKEM768).unwrap()],
        vec![kx_group(g::X25519MLKEM768).unwrap(), kx_group(g::X25519).unwrap()],
    ] {
        let p = rustls::crypto::CryptoProvider { kx_groups: kx, ..(**base.crypto_provider()).clone() };
        let c = rustls::ServerConfig::builder_with_provider(Arc::new(p))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(resolver(Key::EcdsaP256));
        assert!(matches!(assert_profile(&c, Profile::PqRequired), Err(ProfileError::Assertion(_))));
    }
}

// --- the floor verdicts of F12, at unit level (the oracle re-runs all of them against tls-subject)

#[test]
fn pub_t1_t5_t6_public_web() {
    use g::*;
    assert_eq!(
        probe(Profile::PublicWeb, Key::EcdsaP256, &[X25519MLKEM768, X25519], &[X25519]),
        Outcome::Hrr(X25519MLKEM768)
    );
    assert_eq!(
        probe(Profile::PublicWeb, Key::EcdsaP256, &[X25519MLKEM768, SECP256R1], &[SECP256R1]),
        Outcome::Hrr(X25519MLKEM768)
    );
    assert_eq!(
        probe(Profile::PublicWeb, Key::EcdsaP256, &[X25519MLKEM768, X25519], &[X25519MLKEM768]),
        Outcome::Sh(X25519MLKEM768)
    );
    // PUB-T2: documented client-order residual
    assert_eq!(probe(Profile::PublicWeb, Key::EcdsaP256, &[X25519, X25519MLKEM768], &[X25519]), Outcome::Sh(X25519));
}

#[test]
fn pub_t3_t4_pq_required_and_classical_sweep() {
    use g::*;
    assert_eq!(
        probe(Profile::PqRequired, Key::MlDsa44, &[X25519, X25519MLKEM768], &[X25519]),
        Outcome::Hrr(X25519MLKEM768)
    );
    for c in [X25519, SECP256R1, SECP384R1] {
        assert_eq!(probe(Profile::PqRequired, Key::MlDsa44, &[c], &[c]), Outcome::Alert(40), "P-PQ1 {c:04x}");
        assert_eq!(
            probe(Profile::FipsPqRequired, Key::EcdsaP256, &[c], &[c]),
            Outcome::Alert(40),
            "P-PQ1 fips {c:04x}"
        );
    }
}

#[test]
fn fips_floor_selection() {
    use g::*;
    assert_eq!(
        probe(Profile::FipsFloor, Key::EcdsaP256, &[X25519MLKEM768, SECP256R1MLKEM768], &[X25519MLKEM768]),
        Outcome::Hrr(SECP256R1MLKEM768)
    );
    assert_eq!(
        probe(
            Profile::FipsFloor,
            Key::EcdsaP256,
            &[X25519MLKEM768, SECP256R1MLKEM768],
            &[X25519MLKEM768, SECP256R1MLKEM768]
        ),
        Outcome::Sh(SECP256R1MLKEM768)
    );
    assert_eq!(probe(Profile::FipsFloor, Key::EcdsaP256, &[X25519MLKEM768], &[X25519MLKEM768]), Outcome::Alert(40));
}

#[test]
fn tls12_only_client_refused() {
    use g::*;
    let (o, _) =
        probe_with(Profile::PublicWeb, Key::EcdsaP256, &[X25519MLKEM768], &[X25519MLKEM768], &ALL_SIGS, &[0x03, 0x03]);
    assert!(matches!(o, Outcome::Alert(_)), "TLS 1.2-only hello: {o:?}");
}

// --- government profiles (F12 UNI/BSI/CNSA, re-frozen 2026-11-04), at unit level

const NO_GOV_SIGS: [u16; 4] = [0x0403, 0x0804, 0x0904, 0x0905];

#[test]
fn uni_t1_t5_universal() {
    use g::*;
    for k in [Key::MlDsa87, Key::EcdsaP384] {
        let p = Profile::Universal;
        assert_eq!(
            probe(p, k_clone(&k), &[X25519MLKEM768, SECP384R1MLKEM1024], &[X25519MLKEM768, SECP384R1MLKEM1024]),
            Outcome::Sh(SECP384R1MLKEM1024),
            "UNI-T1"
        );
        assert_eq!(
            probe(
                p,
                k_clone(&k),
                &[X25519MLKEM768, SECP256R1MLKEM768, SECP384R1MLKEM1024],
                &[X25519MLKEM768, SECP256R1MLKEM768]
            ),
            Outcome::Hrr(SECP384R1MLKEM1024),
            "UNI-T2"
        );
        assert_eq!(probe(p, k_clone(&k), &[X25519], &[X25519]), Outcome::Alert(40), "UNI-T3");
        assert_eq!(probe(p, k_clone(&k), &[SECP384R1], &[SECP384R1]), Outcome::Alert(40), "UNI-T4");
        let (o, _) = probe_with(p, k, &[SECP384R1MLKEM1024], &[SECP384R1MLKEM1024], &NO_GOV_SIGS, &[0x03, 0x04]);
        assert_eq!(o, Outcome::Alert(49), "UNI-T5: no in-profile sigalg offered -> resolver None -> 49");
    }
}

#[test]
fn bsi_alt_selection() {
    use g::*;
    let p = Profile::BsiAlt;
    assert_eq!(
        probe(p, Key::EcdsaP384, &[SECP256R1MLKEM768, SECP384R1MLKEM1024], &[SECP256R1MLKEM768, SECP384R1MLKEM1024]),
        Outcome::Sh(SECP256R1MLKEM768),
        "BSI-T1 client order"
    );
    assert_eq!(
        probe(p, Key::MlDsa87, &[SECP384R1MLKEM1024], &[SECP384R1MLKEM1024]),
        Outcome::Sh(SECP384R1MLKEM1024),
        "BSI-T2"
    );
    assert_eq!(probe(p, Key::MlDsa87, &[X25519MLKEM768], &[X25519MLKEM768]), Outcome::Alert(40), "BSI-T3");
    assert_eq!(probe(p, Key::MlDsa87, &[X25519, SECP256R1, SECP384R1], &[X25519]), Outcome::Alert(40), "BSI-T4");
    // Client lists 0x11ED first but sends only a 0x11EB share: client order picks 0x11ED, so retry to it.
    assert_eq!(
        probe(p, Key::MlDsa87, &[SECP384R1MLKEM1024, SECP256R1MLKEM768], &[SECP256R1MLKEM768]),
        Outcome::Hrr(SECP384R1MLKEM1024)
    );
    assert_eq!(
        probe(p, Key::MlDsa87, &[X25519MLKEM768, SECP384R1MLKEM1024], &[X25519MLKEM768]),
        Outcome::Hrr(SECP384R1MLKEM1024)
    );
    assert_eq!(probe(p, Key::MlDsa87, &[X25519, SECP256R1], &[X25519]), Outcome::Alert(40));
}

#[test]
fn cnsa_selection_and_sigalgs() {
    use g::*;
    let p = Profile::Cnsa;
    assert_eq!(probe(p, Key::MlDsa87, &[MLKEM1024], &[MLKEM1024]), Outcome::Sh(MLKEM1024));
    assert_eq!(probe(p, Key::MlDsa87, &[SECP384R1MLKEM1024], &[SECP384R1MLKEM1024]), Outcome::Alert(40));
    // ECDSA-P384 is not a CNSA credential: never served, even when the client offers ecdsa_secp384r1_sha384.
    assert_eq!(probe(p, Key::EcdsaP384, &[MLKEM1024], &[MLKEM1024]), Outcome::Alert(49));
    // CNSA-T3: only out-of-profile sigalgs offered.
    let (o, _) =
        probe_with(p, Key::MlDsa87, &[MLKEM1024], &[MLKEM1024], &[0x0403, 0x0503, 0x0904, 0x0905], &[0x03, 0x04]);
    assert_eq!(o, Outcome::Alert(49));
}

#[test]
fn public_web_serves_0x11ed() {
    use g::*;
    assert_eq!(
        probe(Profile::PublicWeb, Key::EcdsaP256, &[SECP384R1MLKEM1024], &[SECP384R1MLKEM1024]),
        Outcome::Sh(SECP384R1MLKEM1024)
    );
}

fn k_clone(k: &Key) -> Key {
    match k {
        Key::EcdsaP256 => Key::EcdsaP256,
        Key::EcdsaP384 => Key::EcdsaP384,
        Key::MlDsa44 => Key::MlDsa44,
        Key::MlDsa65 => Key::MlDsa65,
        Key::MlDsa87 => Key::MlDsa87,
    }
}

// --- P-PQ2 sigalg restriction through the resolver wrapper

#[test]
fn in_profile_key_is_served() {
    use g::*;
    for (p, k) in [
        (Profile::PublicWeb, Key::EcdsaP256),
        (Profile::PqRequired, Key::MlDsa44),
        (Profile::FipsFloor, Key::EcdsaP384),
    ] {
        let (o, _) = probe_with(p, k, &[p.kx_groups()[0]], &[p.kx_groups()[0]], &ALL_SIGS, &[0x03, 0x04]);
        assert_eq!(o, Outcome::Sh(p.kx_groups()[0]), "{p:?}");
    }
    let _ = X25519;
}

#[test]
fn out_of_profile_key_is_never_served() {
    use g::*;
    for (p, k) in [
        (Profile::PublicWeb, Key::MlDsa44),
        (Profile::PublicWeb, Key::EcdsaP384),
        (Profile::PqRequired, Key::MlDsa65),
        (Profile::FipsFloor, Key::MlDsa44),
    ] {
        let first = p.kx_groups()[0];
        let (o, _) = probe_with(p, k, &[first], &[first], &ALL_SIGS, &[0x03, 0x04]);
        // rustls 0.23.46 answers "no server certificate chain resolved" with access_denied (49)
        assert_eq!(o, Outcome::Alert(49), "{p:?}: out-of-profile credential must be refused");
    }
    // in-profile key, but the client offers only an out-of-profile scheme
    let (o, _) =
        probe_with(Profile::PqRequired, Key::MlDsa44, &[X25519MLKEM768], &[X25519MLKEM768], &[0x0905], &[0x03, 0x04]);
    assert_eq!(o, Outcome::Alert(49));
}

#[test]
fn pq_ok_with_ecdsa_too() {
    use g::*;
    let (o, _) =
        probe_with(Profile::PqRequired, Key::EcdsaP256, &[X25519MLKEM768], &[X25519MLKEM768], &ALL_SIGS, &[0x03, 0x04]);
    assert_eq!(o, Outcome::Sh(X25519MLKEM768));
}

#[test]
fn spki_of_generated_keys_is_der() {
    // sanity for the test credentials themselves
    let kp = EcdsaKeyPair::generate(&signature::ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
    assert_eq!(kp.public_key().as_der().unwrap().as_ref()[0], 0x30);
}
