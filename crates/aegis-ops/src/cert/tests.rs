//! CERT-1..4 tests (feature-independent: server side only).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::testutil::{Key, pki};
use super::x509::parse_cert;
use super::*;

const T0: i64 = 1_792_929_600; // 2026-10-25T12:00:00Z
const NINETY_D: i64 = 90 * DAY;

#[test]
fn cert1_gauge_and_cert2_levels() {
    assert_eq!(seconds_to_expiry(T0 + 100, T0), 100);
    assert_eq!(seconds_to_expiry(T0, T0 + 5), -5);
    assert_eq!(alert_level(31 * DAY), AlertLevel::Ok);
    assert_eq!(alert_level(30 * DAY), AlertLevel::Days30);
    assert_eq!(alert_level(14 * DAY + 1), AlertLevel::Days30);
    assert_eq!(alert_level(14 * DAY), AlertLevel::Days14);
    assert_eq!(alert_level(7 * DAY), AlertLevel::Days7);
    assert_eq!(alert_level(3 * DAY), AlertLevel::Days3);
    assert_eq!(alert_level(1), AlertLevel::Days3);
    assert_eq!(alert_level(0), AlertLevel::Expired);
    assert_eq!(alert_level(i64::MIN), AlertLevel::Expired);
    assert_eq!(CERT_SECONDS_TO_EXPIRY, "cert_seconds_to_expiry");
}

#[test]
fn cert2_each_threshold_fires_once_in_order() {
    let clock = FixedClock::at(T0);
    let na = T0 + NINETY_D;
    let mut tr = ExpiryTracker::new();
    let mut fired = Vec::new();
    // Walk a day at a time through the whole lifetime and 5 days past it.
    for _ in 0..95 {
        let o = tr.observe(b"s1", na, clock.now());
        fired.extend(o.fired);
        clock.advance(DAY);
    }
    assert_eq!(
        fired,
        vec![AlertLevel::Days30, AlertLevel::Days14, AlertLevel::Days7, AlertLevel::Days3, AlertLevel::Expired]
    );
    // A new certificate re-arms the alerts.
    let o = tr.observe(b"s2", clock.now() + 10 * DAY, clock.now());
    assert_eq!(o.fired, vec![AlertLevel::Days30, AlertLevel::Days14]);
}

/// CERT-4: faketime +400 d, done with the injected clock. Without renewal the gauge goes negative, every alert
/// fires in the same observation, and the preflight refuses to (re)install the expired certificate.
#[test]
fn cert4_plus_400_days() {
    let clock = FixedClock::at(T0);
    let p = pki(T0 - 60, T0 + NINETY_D, false);
    let store = CertStore::new();
    let inst = store.install_checked(p.chain.clone(), &p.leaf_key.pkcs8(), Profile::PublicWeb, &clock, &[]).unwrap();
    let mut tr = ExpiryTracker::new();
    let o = tr.observe(&inst.report.serial, inst.report.not_after, clock.now());
    assert_eq!(o.level, AlertLevel::Ok);
    assert!(o.fired.is_empty());
    clock.advance(400 * DAY);
    let o = tr.observe(&inst.report.serial, inst.report.not_after, clock.now());
    assert_eq!(o.seconds_to_expiry, NINETY_D - 400 * DAY);
    assert_eq!(o.level, AlertLevel::Expired);
    assert_eq!(o.fired.len(), 5);
    let e = store.install_checked(p.chain.clone(), &p.leaf_key.pkcs8(), Profile::PublicWeb, &clock, &[]);
    assert!(matches!(e, Err(PreflightError::Expired { .. })), "{e:?}");
    assert_eq!(store.current().unwrap().generation, 1, "failed install must keep the old cert");
}

#[test]
fn cert3_preflight_accepts_good_chain() {
    let p = pki(T0 - 60, T0 + NINETY_D, false);
    let r = check_tls(&p.chain, &p.leaf_key.pkcs8(), Profile::PublicWeb, T0, std::slice::from_ref(&p.root)).unwrap();
    assert_eq!(r.serial, vec![0x00, 0x80, 0x01]);
    assert_eq!(r.not_after, T0 + NINETY_D);
    assert_eq!(r.dns_names, vec!["aegis.test".to_string()]);
    assert_eq!(r.scheme, rustls::SignatureScheme::ECDSA_NISTP256_SHA256);
    // FIPS floor also allows P-256.
    check_tls(&p.chain, &p.leaf_key.pkcs8(), Profile::FipsFloor, T0, &[]).unwrap();
}

#[test]
fn cert3_preflight_rejects_tampered_chain() {
    let p = pki(T0 - 60, T0 + NINETY_D, false);
    // Flip the last byte of the leaf (inside its signature): still DER, signature no longer verifies.
    let mut leaf = p.chain[0].as_ref().to_vec();
    let n = leaf.len();
    leaf[n - 1] ^= 0x01;
    let chain = vec![CertificateDer::from(leaf), p.chain[1].clone()];
    let e = check_tls(&chain, &p.leaf_key.pkcs8(), Profile::PublicWeb, T0, &[]);
    assert!(matches!(e, Err(PreflightError::Link { index: 0, .. }) | Err(PreflightError::Malformed { .. })), "{e:?}");
    // Swapped order.
    let swapped = vec![p.chain[1].clone(), p.chain[0].clone()];
    assert!(check_tls(&swapped, &p.leaf_key.pkcs8(), Profile::PublicWeb, T0, &[]).is_err());
    // Wrong root.
    let other = pki(T0 - 60, T0 + NINETY_D, false);
    let e = check_tls(&p.chain, &p.leaf_key.pkcs8(), Profile::PublicWeb, T0, &[other.root]);
    assert_eq!(e, Err(PreflightError::UntrustedRoot));
    // Truncated certificate.
    let t = vec![CertificateDer::from(p.chain[0].as_ref()[..50].to_vec())];
    assert!(matches!(
        check_tls(&t, &p.leaf_key.pkcs8(), Profile::PublicWeb, T0, &[]),
        Err(PreflightError::Malformed { .. })
    ));
    assert_eq!(check_tls(&[], &p.leaf_key.pkcs8(), Profile::PublicWeb, T0, &[]), Err(PreflightError::ChainLength));
}

#[test]
fn cert3_preflight_rejects_key_mismatch_profile_and_validity() {
    let p = pki(T0 - 60, T0 + NINETY_D, false);
    let other = Key::new(false);
    assert_eq!(check_tls(&p.chain, &other.pkcs8(), Profile::PublicWeb, T0, &[]), Err(PreflightError::KeyMismatch));
    // A P-384 leaf cannot sign ECDSA_NISTP256_SHA256, the only P-PUBLIC-WEB sigalg.
    let p384 = pki(T0 - 60, T0 + NINETY_D, true);
    assert!(matches!(
        check_tls(&p384.chain, &p384.leaf_key.pkcs8(), Profile::PublicWeb, T0, &[]),
        Err(PreflightError::SigalgNotInProfile { .. })
    ));
    check_tls(&p384.chain, &p384.leaf_key.pkcs8(), Profile::FipsFloor, T0, &[]).unwrap();
    assert!(matches!(
        check_tls(&p.chain, &p.leaf_key.pkcs8(), Profile::Universal, T0, &[]),
        Err(PreflightError::ProfilePending(_))
    ));
    assert!(matches!(
        check_tls(&p.chain, &p.leaf_key.pkcs8(), Profile::PublicWeb, T0 - 3600, &[]),
        Err(PreflightError::NotYetValid { .. })
    ));
    assert!(matches!(
        check_tls(&p.chain, &p.leaf_key.pkcs8(), Profile::PublicWeb, T0 + NINETY_D, &[]),
        Err(PreflightError::Expired { .. })
    ));
}

#[test]
fn store_swaps_atomically() {
    let clock = FixedClock::at(T0);
    let store = Arc::new(CertStore::new());
    assert!(store.current().is_none());
    let a = pki(T0 - 60, T0 + NINETY_D, false);
    let b = pki(T0 - 60, T0 + 2 * NINETY_D, false);
    store.install_checked(a.chain.clone(), &a.leaf_key.pkcs8(), Profile::PublicWeb, &clock, &[]).unwrap();
    let held = store.current().unwrap();
    // Concurrent readers always see a complete, consistent installation.
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let s = store.clone();
            std::thread::spawn(move || {
                for _ in 0..2000 {
                    let i = s.current().unwrap();
                    let leaf = parse_cert(i.key.cert[0].as_ref()).unwrap();
                    assert_eq!(leaf.not_after, i.report.not_after);
                }
            })
        })
        .collect();
    for _ in 0..50 {
        store.install_checked(b.chain.clone(), &b.leaf_key.pkcs8(), Profile::PublicWeb, &clock, &[]).unwrap();
        store.install_checked(a.chain.clone(), &a.leaf_key.pkcs8(), Profile::PublicWeb, &clock, &[]).unwrap();
    }
    for r in readers {
        r.join().unwrap();
    }
    assert_eq!(store.current().unwrap().generation, 101);
    // A reference taken before the swaps is still intact.
    assert_eq!(held.generation, 1);
    assert_eq!(held.key.cert, a.chain);
}

#[test]
fn x509_fields() {
    let p = pki(T0 - 60, T0 + NINETY_D, false);
    let leaf = parse_cert(p.chain[0].as_ref()).unwrap();
    assert_eq!(leaf.aki, Some(&[9u8, 9, 9][..]));
    assert_eq!(leaf.not_before, T0 - 60);
    let pem = std::format!(
        "junk\n-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        b64::b64_encode(p.chain[0].as_ref())
    );
    assert_eq!(x509::pem_certificates(&pem).unwrap(), vec![p.chain[0].as_ref().to_vec()]);
    assert!(x509::pem_certificates("-----BEGIN CERTIFICATE-----\nZm9v\n").is_none());
    assert!(x509::pem_certificates("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n").is_none());
}

#[test]
fn x509_total_on_mutations() {
    let p = pki(T0 - 60, T0 + NINETY_D, false);
    let base = p.chain[0].as_ref().to_vec();
    let mut x: u32 = 7;
    for i in 0..base.len() * 8 {
        let mut m = base.clone();
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
        m[i / 8] ^= 1 << (i % 8);
        let _ = parse_cert(&m);
        let cut = (x as usize) % base.len();
        let _ = parse_cert(&base[..cut]);
    }
}
