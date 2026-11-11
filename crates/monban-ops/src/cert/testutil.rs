//! Test PKI: a root, an intermediate and a leaf built with the in-crate DER encoder and aws-lc-rs ECDSA.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::vec::Vec;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use super::der::{self, oids, tag, tlv};

pub struct Key {
    pub kp: EcdsaKeyPair,
    pub p384: bool,
}

impl Key {
    pub fn new(p384: bool) -> Self {
        let alg: &'static EcdsaSigningAlgorithm =
            if p384 { &ECDSA_P384_SHA384_ASN1_SIGNING } else { &ECDSA_P256_SHA256_ASN1_SIGNING };
        Self { kp: EcdsaKeyPair::generate(alg).unwrap(), p384 }
    }
    pub fn spki(&self) -> Vec<u8> {
        let curve = if self.p384 { oids::P384 } else { oids::P256 };
        der::seq(&[
            &der::seq(&[&der::oid(oids::EC_PUBLIC_KEY), &der::oid(curve)]),
            &der::bit_string(self.kp.public_key().as_ref()),
        ])
    }
    pub fn sig_oid(&self) -> &'static [u8] {
        if self.p384 { oids::ECDSA_SHA384 } else { oids::ECDSA_SHA256 }
    }
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.kp.sign(&SystemRandom::new(), msg).unwrap().as_ref().to_vec()
    }
    pub fn pkcs8(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.kp.to_pkcs8v1().unwrap().as_ref().to_vec()))
    }
}

fn name(cn: &str) -> Vec<u8> {
    der::seq(&[&der::set(&[&der::seq(&[&der::oid(oids::COMMON_NAME), &tlv(tag::UTF8_STRING, cn.as_bytes())])])])
}

fn gtime(t: i64) -> Vec<u8> {
    let s = super::time::format_rfc3339(t); // YYYY-MM-DDTHH:MM:SSZ
    let digits: std::string::String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    tlv(tag::GENERALIZED_TIME, std::format!("{digits}Z").as_bytes())
}

/// Issue a certificate for `subject_key` signed by `issuer_key` (self-signed when they are the same CN).
#[allow(clippy::too_many_arguments)]
pub fn issue(
    serial: u64,
    subject_cn: &str,
    subject_key: &Key,
    issuer_cn: &str,
    issuer_key: &Key,
    not_before: i64,
    not_after: i64,
    dns: Option<&str>,
    aki: Option<&[u8]>,
) -> CertificateDer<'static> {
    let alg = der::seq(&[&der::oid(issuer_key.sig_oid())]);
    let mut exts = Vec::new();
    if let Some(d) = dns {
        let san = der::seq(&[&tlv(0x82, d.as_bytes())]);
        exts.push(der::seq(&[&der::oid(oids::SUBJECT_ALT_NAME), &tlv(tag::OCTET_STRING, &san)]));
    }
    if dns.is_none() {
        // CA certificate: basicConstraints cA=TRUE (critical), as webpki requires.
        let bc = der::seq(&[&tlv(tag::BOOLEAN, &[0xff])]);
        exts.push(der::seq(&[
            &der::oid(oids::BASIC_CONSTRAINTS),
            &tlv(tag::BOOLEAN, &[0xff]),
            &tlv(tag::OCTET_STRING, &bc),
        ]));
    }
    if let Some(k) = aki {
        let v = der::seq(&[&tlv(0x80, k)]);
        exts.push(der::seq(&[&der::oid(oids::AUTHORITY_KEY_ID), &tlv(tag::OCTET_STRING, &v)]));
    }
    let ext_refs: Vec<&[u8]> = exts.iter().map(|e| e.as_slice()).collect();
    let mut parts: Vec<Vec<u8>> = vec![
        tlv(0xa0, &der::uint(&[2])),
        der::uint(&serial.to_be_bytes()),
        alg.clone(),
        name(issuer_cn),
        der::seq(&[&gtime(not_before), &gtime(not_after)]),
        name(subject_cn),
        subject_key.spki(),
    ];
    if !exts.is_empty() {
        parts.push(tlv(0xa3, &der::seq(&ext_refs)));
    }
    let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    let tbs = der::seq(&refs);
    let sig = issuer_key.sign(&tbs);
    CertificateDer::from(der::seq(&[&tbs, &alg, &der::bit_string(&sig)]))
}

pub struct Pki {
    pub root: CertificateDer<'static>,
    pub chain: Vec<CertificateDer<'static>>,
    pub leaf_key: Key,
}

/// root → intermediate → leaf (`monban.test`), all P-256 unless `leaf_p384`.
pub fn pki(not_before: i64, not_after: i64, leaf_p384: bool) -> Pki {
    let rk = Key::new(false);
    let ik = Key::new(false);
    let lk = Key::new(leaf_p384);
    let root = issue(1, "root", &rk, "root", &rk, not_before - 86_400, not_after + 86_400 * 3650, None, None);
    let inter = issue(2, "inter", &ik, "root", &rk, not_before - 86_400, not_after + 86_400 * 365, None, None);
    let leaf =
        issue(0x80_01, "monban.test", &lk, "inter", &ik, not_before, not_after, Some("monban.test"), Some(&[9, 9, 9]));
    Pki { root, chain: vec![leaf, inter], leaf_key: lk }
}
