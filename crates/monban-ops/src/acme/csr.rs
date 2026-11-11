//! PKCS#10 certification request (RFC 2986) for the ACME finalize call (RFC 8555 §7.4), built with the in-crate
//! DER encoder. Key: P-256 ECDSA; signature ecdsa-with-SHA256; subject CN = first name; names in a
//! subjectAltName extension inside a PKCS#9 extensionRequest attribute.

use std::string::String;
use std::vec::Vec;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

use super::AcmeError;
use crate::cert::der::{self, oids, tag, tlv};

/// A DNS identifier acceptable to this client: LDH labels, 1..=63 per label, ≤253 total, lowercase ASCII. No
/// wildcards (HTTP-01 cannot validate them, RFC 8555 §8.3).
pub fn valid_dns_name(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}

/// A fresh certificate key and the CSR naming `domains`.
#[derive(Debug)]
pub struct CsrBundle {
    /// DER CSR.
    pub der: Vec<u8>,
    /// PKCS#8 private key of the certificate.
    pub key: PrivateKeyDer<'static>,
}

/// Generate a P-256 key and a CSR for `domains`.
pub fn build_csr(domains: &[String]) -> Result<CsrBundle, AcmeError> {
    if domains.is_empty() || domains.len() > 100 || !domains.iter().all(|d| valid_dns_name(d)) {
        return Err(AcmeError::BadIdentifier);
    }
    let kp = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).map_err(|_| AcmeError::Crypto("keygen"))?;
    let der = csr_der(domains, &kp)?;
    let pkcs8 = kp.to_pkcs8v1().map_err(|_| AcmeError::Crypto("pkcs8"))?;
    Ok(CsrBundle { der, key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec())) })
}

fn csr_der(domains: &[String], kp: &EcdsaKeyPair) -> Result<Vec<u8>, AcmeError> {
    let spki = der::seq(&[
        &der::seq(&[&der::oid(oids::EC_PUBLIC_KEY), &der::oid(oids::P256)]),
        &der::bit_string(kp.public_key().as_ref()),
    ]);
    let first = domains.first().ok_or(AcmeError::BadIdentifier)?;
    let subject = if first.len() <= 64 {
        der::seq(&[&der::set(&[&der::seq(&[&der::oid(oids::COMMON_NAME), &tlv(tag::UTF8_STRING, first.as_bytes())])])])
    } else {
        der::seq(&[])
    };
    let names: Vec<Vec<u8>> = domains.iter().map(|d| tlv(0x82, d.as_bytes())).collect();
    let name_refs: Vec<&[u8]> = names.iter().map(|n| n.as_slice()).collect();
    let san = der::seq(&[&der::oid(oids::SUBJECT_ALT_NAME), &tlv(tag::OCTET_STRING, &der::seq(&name_refs))]);
    let ext_req = der::seq(&[&der::oid(oids::EXTENSION_REQUEST), &der::set(&[&der::seq(&[&san])])]);
    let info = der::seq(&[&der::uint(&[0]), &subject, &spki, &tlv(0xa0, &ext_req)]);
    let sig = kp.sign(&SystemRandom::new(), &info).map_err(|_| AcmeError::Crypto("csr sign"))?;
    Ok(der::seq(&[&info, &der::seq(&[&der::oid(oids::ECDSA_SHA256)]), &der::bit_string(sig.as_ref())]))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::cert::der::Reader;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};

    #[test]
    fn csr_structure_and_signature() {
        let b = build_csr(&["a.test".into(), "b.a.test".into()]).unwrap();
        let outer = der::single(&b.der, tag::SEQUENCE).unwrap();
        let mut r = Reader::new(outer.value);
        let info = r.expect(tag::SEQUENCE).unwrap();
        let alg = r.expect(tag::SEQUENCE).unwrap();
        let sig = r.expect(tag::BIT_STRING).unwrap();
        r.finish().unwrap();
        assert_eq!(Reader::new(alg.value).expect(tag::OID).unwrap().value, oids::ECDSA_SHA256);
        let mut ir = Reader::new(info.value);
        assert_eq!(ir.expect(tag::INTEGER).unwrap().value, [0]);
        let _subject = ir.expect(tag::SEQUENCE).unwrap();
        let spki = ir.expect(tag::SEQUENCE).unwrap();
        let attrs = ir.expect(0xa0).unwrap();
        ir.finish().unwrap();
        let mut sr = Reader::new(spki.value);
        let _alg = sr.expect(tag::SEQUENCE).unwrap();
        let pk = der::bit_string_bytes(sr.expect(tag::BIT_STRING).unwrap().value).unwrap();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, pk)
            .verify(info.raw, der::bit_string_bytes(sig.value).unwrap())
            .unwrap();
        let hay = attrs.value;
        assert!(hay.windows(6).any(|w| w == b"a.test"));
        assert!(hay.windows(8).any(|w| w == b"b.a.test"));
        // The key matches the CSR's SPKI.
        let signer = rustls::crypto::aws_lc_rs::sign::any_supported_type(&b.key).unwrap();
        assert_eq!(signer.public_key().unwrap().as_ref(), spki.raw);
    }

    #[test]
    fn identifiers() {
        assert!(valid_dns_name("acme-subject.test"));
        for bad in ["", "*.a.test", "A.test", "a..test", "-a.test", "a_b.test", "a.test.", &"a".repeat(64)] {
            assert!(!valid_dns_name(bad), "{bad}");
        }
        assert!(build_csr(&[]).is_err());
        assert!(build_csr(&["*.x.test".into()]).is_err());
    }
}
