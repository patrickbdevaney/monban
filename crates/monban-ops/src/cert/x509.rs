//! Minimal X.509 v3 certificate reader (RFC 5280 §4.1) and chain-link signature check, plus a PEM reader
//! (RFC 7468). Only the fields CERT-1..4 and ARI need are extracted; everything else is skipped structurally.

use std::string::String;
use std::vec::Vec;

use aws_lc_rs::signature::{self, UnparsedPublicKey, VerificationAlgorithm};

use super::b64::b64_decode;
use super::der::{self, DerError, Reader, oids, tag};
use super::time::parse_asn1_time;

/// Upper bound for one certificate's DER (64 KiB).
pub const MAX_CERT_DER: usize = 64 * 1024;
/// Upper bound for a chain length.
pub const MAX_CHAIN: usize = 10;

/// The parts of a certificate the cert lifecycle uses. Borrowed from the DER.
#[derive(Clone, Debug)]
pub struct CertInfo<'a> {
    /// The signed TBSCertificate encoding.
    pub tbs: &'a [u8],
    /// `signatureAlgorithm` OID contents.
    pub sig_alg: &'a [u8],
    /// The signature bytes.
    pub signature: &'a [u8],
    /// Serial number INTEGER contents (as in the DER, without tag and length: RFC 9773 §4.1).
    pub serial: &'a [u8],
    /// Issuer Name encoding.
    pub issuer: &'a [u8],
    /// Subject Name encoding.
    pub subject: &'a [u8],
    /// notBefore, Unix seconds.
    pub not_before: i64,
    /// notAfter, Unix seconds.
    pub not_after: i64,
    /// SubjectPublicKeyInfo encoding.
    pub spki: &'a [u8],
    /// SPKI algorithm OID contents.
    pub key_alg: &'a [u8],
    /// SPKI named curve OID contents (EC keys).
    pub key_curve: Option<&'a [u8]>,
    /// SPKI subjectPublicKey bytes.
    pub key: &'a [u8],
    /// authorityKeyIdentifier keyIdentifier (RFC 5280 §4.2.1.1).
    pub aki: Option<&'a [u8]>,
    /// dNSName entries of subjectAltName.
    pub dns_names: Vec<&'a str>,
}

/// Parse a DER certificate.
pub fn parse_cert(der_bytes: &[u8]) -> Result<CertInfo<'_>, DerError> {
    if der_bytes.len() > MAX_CERT_DER {
        return Err(DerError("certificate too large"));
    }
    let cert = der::single(der_bytes, tag::SEQUENCE)?;
    let mut c = Reader::new(cert.value);
    let tbs = c.expect(tag::SEQUENCE)?;
    let alg = c.expect(tag::SEQUENCE)?;
    let sig = c.expect(tag::BIT_STRING)?;
    c.finish()?;
    let sig_alg = Reader::new(alg.value).expect(tag::OID)?.value;
    let signature = der::bit_string_bytes(sig.value)?;

    let mut t = Reader::new(tbs.value);
    if let Some(v) = t.optional(0xa0)? {
        let ver = der::single(v.value, tag::INTEGER)?;
        if ver.value != [2] {
            return Err(DerError("not an X.509 v3 certificate"));
        }
    } else {
        return Err(DerError("not an X.509 v3 certificate"));
    }
    let serial = t.expect(tag::INTEGER)?.value;
    if serial.is_empty() || serial.len() > 20 + 1 {
        return Err(DerError("bad serial"));
    }
    let inner_alg = t.expect(tag::SEQUENCE)?;
    if inner_alg.value != alg.value {
        return Err(DerError("signature algorithm mismatch"));
    }
    let issuer = t.expect(tag::SEQUENCE)?.raw;
    let validity = t.expect(tag::SEQUENCE)?;
    let mut vr = Reader::new(validity.value);
    let nb = vr.read()?;
    let na = vr.read()?;
    vr.finish()?;
    let not_before = parse_asn1_time(nb.tag, nb.value).ok_or(DerError("bad notBefore"))?;
    let not_after = parse_asn1_time(na.tag, na.value).ok_or(DerError("bad notAfter"))?;
    let subject = t.expect(tag::SEQUENCE)?.raw;
    let spki_tlv = t.expect(tag::SEQUENCE)?;
    let mut sr = Reader::new(spki_tlv.value);
    let kalg = sr.expect(tag::SEQUENCE)?;
    let key = der::bit_string_bytes(sr.expect(tag::BIT_STRING)?.value)?;
    sr.finish()?;
    let mut kr = Reader::new(kalg.value);
    let key_alg = kr.expect(tag::OID)?.value;
    let key_curve = kr.optional(tag::OID)?.map(|o| o.value);

    let mut aki = None;
    let mut dns_names = Vec::new();
    let _ = t.optional(0x81)?;
    let _ = t.optional(0x82)?;
    if let Some(exts) = t.optional(0xa3)? {
        let list = der::single(exts.value, tag::SEQUENCE)?;
        let mut er = Reader::new(list.value);
        while !er.is_empty() {
            let ext = er.expect(tag::SEQUENCE)?;
            let mut x = Reader::new(ext.value);
            let id = x.expect(tag::OID)?.value;
            let _critical = x.optional(tag::BOOLEAN)?;
            let val = x.expect(tag::OCTET_STRING)?.value;
            x.finish()?;
            if id == oids::AUTHORITY_KEY_ID {
                let a = der::single(val, tag::SEQUENCE)?;
                aki = Reader::new(a.value).optional(0x80)?.map(|k| k.value);
            } else if id == oids::SUBJECT_ALT_NAME {
                let names = der::single(val, tag::SEQUENCE)?;
                let mut nr = Reader::new(names.value);
                while !nr.is_empty() {
                    let n = nr.read()?;
                    if n.tag == 0x82 {
                        dns_names.push(core::str::from_utf8(n.value).map_err(|_| DerError("bad dNSName"))?);
                    }
                }
            }
        }
    }
    t.finish()?;
    Ok(CertInfo {
        tbs: tbs.raw,
        sig_alg,
        signature,
        serial,
        issuer,
        subject,
        not_before,
        not_after,
        spki: spki_tlv.raw,
        key_alg,
        key_curve,
        key,
        aki,
        dns_names,
    })
}

/// Why a chain link does not verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkError {
    /// The child's issuer is not the parent's subject.
    NameMismatch,
    /// The signature algorithm / issuer key combination is not supported (fail closed).
    Unsupported,
    /// The signature does not verify.
    BadSignature,
}

fn algorithm(sig_alg: &[u8], key_alg: &[u8], curve: Option<&[u8]>) -> Option<&'static dyn VerificationAlgorithm> {
    let ec = key_alg == oids::EC_PUBLIC_KEY;
    let rsa = key_alg == oids::RSA_ENCRYPTION;
    Some(match (sig_alg, ec, rsa, curve) {
        (s, true, _, Some(c)) if s == oids::ECDSA_SHA256 && c == oids::P256 => &signature::ECDSA_P256_SHA256_ASN1,
        (s, true, _, Some(c)) if s == oids::ECDSA_SHA384 && c == oids::P256 => &signature::ECDSA_P256_SHA384_ASN1,
        (s, true, _, Some(c)) if s == oids::ECDSA_SHA256 && c == oids::P384 => &signature::ECDSA_P384_SHA256_ASN1,
        (s, true, _, Some(c)) if s == oids::ECDSA_SHA384 && c == oids::P384 => &signature::ECDSA_P384_SHA384_ASN1,
        (s, _, true, _) if s == oids::RSA_SHA256 => &signature::RSA_PKCS1_2048_8192_SHA256,
        (s, _, true, _) if s == oids::RSA_SHA384 => &signature::RSA_PKCS1_2048_8192_SHA384,
        (s, _, true, _) if s == oids::RSA_SHA512 => &signature::RSA_PKCS1_2048_8192_SHA512,
        _ => return None,
    })
}

/// Check that `child` is issued by `parent`: name chaining and the signature over the child's TBSCertificate.
pub fn verify_link(child: &CertInfo<'_>, parent: &CertInfo<'_>) -> Result<(), LinkError> {
    if child.issuer != parent.subject {
        return Err(LinkError::NameMismatch);
    }
    let alg = algorithm(child.sig_alg, parent.key_alg, parent.key_curve).ok_or(LinkError::Unsupported)?;
    UnparsedPublicKey::new(alg, parent.key).verify(child.tbs, child.signature).map_err(|_| LinkError::BadSignature)
}

/// Read every `CERTIFICATE` block of a PEM document (RFC 7468 strict-ish: base64 lines, no headers). Other block
/// labels are skipped. Returns `None` on any malformed block or when the caps are exceeded.
pub fn pem_certificates(text: &str) -> Option<Vec<Vec<u8>>> {
    pem_blocks(text, "CERTIFICATE")
}

/// Read every block with the given label.
pub fn pem_blocks(text: &str, label: &str) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut lines = text.lines().map(|l| l.trim_end_matches('\r'));
    while let Some(line) = lines.next() {
        let Some(l) = line.strip_prefix("-----BEGIN ").and_then(|r| r.strip_suffix("-----")) else {
            continue;
        };
        let end = std::format!("-----END {l}-----");
        let mut body = String::new();
        loop {
            let b = lines.next()?;
            if b == end {
                break;
            }
            if body.len().saturating_add(b.len()) > MAX_CERT_DER * 2 {
                return None;
            }
            body.push_str(b.trim());
        }
        if l == label {
            out.push(b64_decode(&body)?);
            if out.len() > MAX_CHAIN {
                return None;
            }
        }
    }
    Some(out)
}

/// Hex of a byte string (serials in status lines).
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&std::format!("{b:02x}"));
    }
    s
}
