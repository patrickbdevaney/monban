//! Tests that need a rustls client (feature `acme` only, so the feature-off test binary links no client code).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::io::{Read, Write};

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ServerConnection};

use super::*;
use crate::cert::testutil::pki;
use crate::cert::x509::parse_cert;
use crate::cert::{CertStore, FixedClock};
use monban_tls::Profile;

const T0: i64 = 1_792_929_600;

fn pump(c: &mut ClientConnection, s: &mut ServerConnection) {
    for _ in 0..20 {
        let mut buf = Vec::new();
        while c.wants_write() {
            c.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            s.read_tls(&mut &buf[..]).unwrap();
            s.process_new_packets().unwrap();
        }
        let mut buf2 = Vec::new();
        while s.wants_write() {
            s.write_tls(&mut buf2).unwrap();
        }
        if !buf2.is_empty() {
            c.read_tls(&mut &buf2[..]).unwrap();
            c.process_new_packets().unwrap();
        }
        if buf.is_empty() && buf2.is_empty() {
            break;
        }
    }
}

fn served_not_after(c: &ClientConnection) -> i64 {
    parse_cert(c.peer_certificates().unwrap()[0].as_ref()).unwrap().not_after
}

/// Atomic swap without dropping an established connection: a connection made before the swap keeps working
/// after it; a handshake after the swap gets the new certificate. Both chains verify against the root through
/// the ACME client's own (floor, PQ-first) ClientConfig.
#[test]
fn swap_keeps_established_connection() {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let clock = FixedClock::at(now);
    // Same root for both generations (rebuild b's chain under a's root is not needed: trust both roots).
    let a = pki(now - 60, now + 90 * 86_400, false);
    let b = pki(now - 60, now + 180 * 86_400, false);
    let store = Arc::new(CertStore::new());
    store
        .install_checked(
            a.chain.clone(),
            &a.leaf_key.pkcs8(),
            Profile::PublicWeb,
            &clock,
            std::slice::from_ref(&a.root),
        )
        .unwrap();
    let scfg = Arc::new(monban_tls::server_config(Profile::PublicWeb, store.clone()).unwrap());
    let ccfg = tls::client_config(&[a.root.clone(), b.root.clone()]).unwrap();
    let name = ServerName::try_from("monban.test").unwrap();

    let mut c1 = ClientConnection::new(ccfg.clone(), name.clone()).unwrap();
    let mut s1 = ServerConnection::new(scfg.clone()).unwrap();
    pump(&mut c1, &mut s1);
    assert!(!c1.is_handshaking());
    assert_eq!(served_not_after(&c1), now + 90 * 86_400);
    assert_eq!(
        c1.negotiated_key_exchange_group().map(|g| u16::from(g.name())),
        Some(monban_tls::profile::group::X25519MLKEM768)
    );

    store.install_checked(b.chain.clone(), &b.leaf_key.pkcs8(), Profile::PublicWeb, &clock, &[]).unwrap();

    let mut c2 = ClientConnection::new(ccfg, name).unwrap();
    let mut s2 = ServerConnection::new(scfg).unwrap();
    pump(&mut c2, &mut s2);
    assert_eq!(served_not_after(&c2), now + 180 * 86_400);

    // The pre-swap connection still carries data both ways.
    c1.writer().write_all(b"ping").unwrap();
    pump(&mut c1, &mut s1);
    let mut got = [0u8; 4];
    s1.reader().read_exact(&mut got).unwrap();
    assert_eq!(&got, b"ping");
    s1.writer().write_all(b"pong").unwrap();
    pump(&mut c1, &mut s1);
    c1.reader().read_exact(&mut got).unwrap();
    assert_eq!(&got, b"pong");
    let _ = T0;
}

#[test]
fn client_config_floor() {
    let a = pki(T0 - 60, T0 + 86_400, false);
    let cfg = tls::client_config(&[a.root]).unwrap();
    tls::assert_client_floor(&cfg).unwrap();
    assert!(!cfg.enable_early_data);
    assert!(format!("{:?}", cfg.resumption).contains("NoClientSessionStorage"), "{:?}", cfg.resumption);
    assert!(tls::client_config(&[]).is_err(), "no implicit trust");
}

#[test]
fn http01_token_table() {
    let t = Http01Tokens::new();
    t.publish("tok_-123", "tok_-123.thumb");
    assert_eq!(t.respond("/.well-known/acme-challenge/tok_-123").as_deref(), Some("tok_-123.thumb"));
    assert_eq!(t.respond("/.well-known/acme-challenge/other"), None);
    assert_eq!(t.respond("/tok_-123"), None);
    t.remove("tok_-123");
    assert_eq!(t.respond("/.well-known/acme-challenge/tok_-123"), None);
}

#[test]
fn retry_after_forms() {
    let mk = |v: &str| Response { status: 200, headers: vec![("retry-after".into(), v.into())], body: vec![] };
    assert_eq!(retry_after(&mk("3")), Some(3));
    assert_eq!(retry_after(&mk("Sun, 06 Nov 1994 08:49:37 GMT")), Some(0));
    assert_eq!(retry_after(&mk("-1")), None);
    assert_eq!(retry_after(&mk("99999999999")), None);
    assert!(valid_nonce("W-ZyrBddgZJMsLq0PYGOog"));
    assert!(!valid_nonce("a b"));
    assert!(!valid_nonce(""));
}

#[test]
fn problem_documents() {
    let r = Response {
        status: 400,
        headers: vec![],
        body: br#"{"type":"urn:ietf:params:acme:error:badNonce","detail":"JWS has an invalid anti-replay nonce"}"#
            .to_vec(),
    };
    assert!(matches!(problem(&r), AcmeError::Problem { status: 400, kind, .. } if kind == BAD_NONCE));
    let r = Response { status: 500, headers: vec![], body: b"<html>".to_vec() };
    assert!(matches!(problem(&r), AcmeError::Problem { status: 500, kind, .. } if kind.is_empty()));
}
