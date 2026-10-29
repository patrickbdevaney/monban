//! Client profile tests (feature `tls-client`): the client kx list is the profile's own list, TLS 1.3 only,
//! resumption disabled, early data off, ALPN http/1.1; refused profiles are refused, and the startup assertion
//! rejects mutated configs. The first ClientHello is serialized and its extensions are read back.
#![cfg(feature = "tls-client")]
#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use aegis_tls::profile::{CLIENT_ALPN, group as g, kx_group};
use aegis_tls::{Profile, ProfileError, ProfileStatus, assert_client_profile, client_config};
use rustls::client::Resumption;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, ProtocolVersion, RootCertStore};

const CLIENT_PROFILES: [Profile; 3] = [Profile::PublicWeb, Profile::PqRequired, Profile::FipsPqRequired];

fn kx(cfg: &ClientConfig) -> Vec<u16> {
    cfg.crypto_provider().kx_groups.iter().map(|k| u16::from(k.name())).collect()
}

fn build(p: Profile) -> ClientConfig {
    client_config(p, RootCertStore::empty()).unwrap()
}

#[test]
fn floor_client_list_is_unchanged_from_egress() {
    // The list aegis-egress shipped before the move (its former CLIENT_KX), hybrid first.
    assert_eq!(kx(&build(Profile::PublicWeb)), [0x11EC, 0x11EB, 0x001D, 0x0017]);
}

#[test]
fn client_groups_equal_profile_table() {
    for p in CLIENT_PROFILES {
        assert_eq!(kx(&build(p)), p.kx_groups(), "{p:?}");
    }
    assert_eq!(kx(&build(Profile::PqRequired)), [g::X25519MLKEM768]);
    // P-PQ6 client shape.
    assert_eq!(kx(&build(Profile::FipsPqRequired)), [g::SECP256R1MLKEM768]);
}

#[test]
fn tls13_only_no_resumption_no_early_data_alpn() {
    for p in CLIENT_PROFILES {
        let cfg = build(p);
        let suites = &cfg.crypto_provider().cipher_suites;
        assert!(!suites.is_empty());
        assert!(suites.iter().all(|s| s.version().version == ProtocolVersion::TLSv1_3), "{p:?}");
        assert!(!cfg.enable_early_data, "{p:?}");
        let r = format!("{:?}", cfg.resumption);
        assert!(r.contains("NoClientSessionStorage") && r.contains("Disabled"), "{p:?}: {r}");
        assert_eq!(cfg.alpn_protocols, [CLIENT_ALPN.to_vec()]);
        assert!(assert_client_profile(&cfg, p).is_ok());
    }
    // FIPS: AES-GCM only (no ChaCha20), as for the server.
    let fips = build(Profile::FipsPqRequired);
    assert!(fips.crypto_provider().cipher_suites.iter().all(|s| !format!("{:?}", s.suite()).contains("CHACHA")));
}

#[test]
fn refused_profiles_are_refused_not_guessed() {
    for p in Profile::ALL.into_iter().filter(|p| p.status() == ProfileStatus::Pending) {
        match client_config(p, RootCertStore::empty()) {
            Err(ProfileError::Pending { profile, reason }) => {
                assert_eq!(profile, p);
                assert!(!reason.is_empty());
            }
            other => panic!("{p:?}: expected Pending, got {other:?}"),
        }
    }
    match client_config(Profile::FipsFloor, RootCertStore::empty()) {
        Err(ProfileError::NotForClients { profile: Profile::FipsFloor, reason }) => assert!(reason.contains("P-PQ6")),
        other => panic!("FIPS: expected NotForClients, got {other:?}"),
    }
    // The assertion refuses them too, whatever the config looks like.
    let cfg = build(Profile::FipsPqRequired);
    assert!(matches!(assert_client_profile(&cfg, Profile::FipsFloor), Err(ProfileError::NotForClients { .. })));
    assert!(matches!(assert_client_profile(&cfg, Profile::Universal), Err(ProfileError::Pending { .. })));
}

#[test]
fn assertion_rejects_mutated_configs() {
    let is_assertion = |r: Result<(), ProfileError>| matches!(r, Err(ProfileError::Assertion(_)));
    let base = build(Profile::PublicWeb);
    // Wrong profile for the built list.
    assert!(is_assertion(assert_client_profile(&base, Profile::PqRequired)));
    let mut c = base.clone();
    c.enable_early_data = true;
    assert!(is_assertion(assert_client_profile(&c, Profile::PublicWeb)));
    let mut c = base.clone();
    c.resumption = Resumption::in_memory_sessions(32);
    assert!(is_assertion(assert_client_profile(&c, Profile::PublicWeb)));
    let mut c = base.clone();
    c.resumption = Resumption::default();
    assert!(is_assertion(assert_client_profile(&c, Profile::PublicWeb)));
    let mut c = base.clone();
    c.alpn_protocols = vec![b"h2".to_vec(), CLIENT_ALPN.to_vec()];
    assert!(is_assertion(assert_client_profile(&c, Profile::PublicWeb)));
    let mut c = base.clone();
    c.alpn_protocols.clear();
    assert!(is_assertion(assert_client_profile(&c, Profile::PublicWeb)));
    // Classical first, and classical appended to a PQ-only list.
    for (p, list) in [
        (Profile::PublicWeb, vec![g::X25519, g::X25519MLKEM768, g::SECP256R1MLKEM768, g::SECP256R1]),
        (Profile::PqRequired, vec![g::X25519MLKEM768, g::X25519]),
        (Profile::FipsPqRequired, vec![g::SECP256R1MLKEM768, g::SECP256R1]),
    ] {
        let good = build(p);
        let prov = rustls::crypto::CryptoProvider {
            kx_groups: list.iter().map(|c| kx_group(*c).unwrap()).collect(),
            ..(**good.crypto_provider()).clone()
        };
        let mut c = ClientConfig::builder_with_provider(Arc::new(prov))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        c.resumption = Resumption::disabled();
        c.alpn_protocols = good.alpn_protocols.clone();
        assert!(is_assertion(assert_client_profile(&c, p)), "{p:?} {list:04x?}");
    }
}

/// Extensions of the first ClientHello record: (type, body).
fn hello_extensions(cfg: ClientConfig) -> Vec<(u16, Vec<u8>)> {
    let mut conn = ClientConnection::new(Arc::new(cfg), ServerName::try_from("a.example").unwrap()).unwrap();
    let mut out = Vec::new();
    conn.write_tls(&mut out).unwrap();
    assert_eq!(out[0], 0x16, "handshake record");
    let hs = &out[5..];
    assert_eq!(hs[0], 0x01, "ClientHello");
    let mut i = 4 + 2 + 32;
    i += 1 + hs[i] as usize; // session id
    i += 2 + u16::from_be_bytes([hs[i], hs[i + 1]]) as usize; // cipher suites
    i += 1 + hs[i] as usize; // compression
    let end = i + 2 + u16::from_be_bytes([hs[i], hs[i + 1]]) as usize;
    i += 2;
    let mut v = Vec::new();
    while i < end {
        let t = u16::from_be_bytes([hs[i], hs[i + 1]]);
        let l = u16::from_be_bytes([hs[i + 2], hs[i + 3]]) as usize;
        v.push((t, hs[i + 4..i + 4 + l].to_vec()));
        i += 4 + l;
    }
    v
}

fn u16s(b: &[u8]) -> Vec<u16> {
    b.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect()
}

#[test]
fn client_hello_offers_profile_groups_and_no_psk_or_early_data() {
    for p in CLIENT_PROFILES {
        let ext = hello_extensions(build(p));
        let get = |t: u16| ext.iter().find(|(x, _)| *x == t).map(|(_, b)| b.clone());
        let groups = get(0x000a).unwrap();
        assert_eq!(u16s(&groups[2..]), p.kx_groups(), "{p:?} supported_groups");
        let ks = get(0x0033).unwrap();
        let first_share = u16::from_be_bytes([ks[2], ks[3]]);
        assert_eq!(Some(&first_share), p.kx_groups().first(), "{p:?} first key share");
        assert_eq!(get(0x0029), None, "{p:?} pre_shared_key");
        assert_eq!(get(0x002a), None, "{p:?} early_data");
        let versions = get(0x002b).unwrap();
        assert_eq!(u16s(&versions[1..]), [0x0304], "{p:?} supported_versions");
        let alpn = get(0x0010).unwrap();
        assert_eq!(&alpn[3..], CLIENT_ALPN, "{p:?} ALPN");
    }
}
