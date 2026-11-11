//! Minimal DER (X.690) reader and encoder: enough for X.509 certificates, CSRs and SPKIs. Total: every read is
//! bounds-checked, lengths are definite and minimally encoded (max 4 length octets), tags are single-octet.

use std::vec::Vec;

/// DER tags used here.
pub mod tag {
    /// BOOLEAN.
    pub const BOOLEAN: u8 = 0x01;
    /// INTEGER.
    pub const INTEGER: u8 = 0x02;
    /// BIT STRING.
    pub const BIT_STRING: u8 = 0x03;
    /// OCTET STRING.
    pub const OCTET_STRING: u8 = 0x04;
    /// NULL.
    pub const NULL: u8 = 0x05;
    /// OBJECT IDENTIFIER.
    pub const OID: u8 = 0x06;
    /// UTF8String.
    pub const UTF8_STRING: u8 = 0x0c;
    /// UTCTime.
    pub const UTC_TIME: u8 = 0x17;
    /// GeneralizedTime.
    pub const GENERALIZED_TIME: u8 = 0x18;
    /// SEQUENCE.
    pub const SEQUENCE: u8 = 0x30;
    /// SET.
    pub const SET: u8 = 0x31;
}

/// A DER decoding failure (static reason).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerError(pub &'static str);

impl core::fmt::Display for DerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DER: {}", self.0)
    }
}

/// One decoded TLV.
#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    /// The identifier octet.
    pub tag: u8,
    /// The contents octets.
    pub value: &'a [u8],
    /// The whole encoding (identifier + length + contents).
    pub raw: &'a [u8],
}

/// A cursor over a sequence of TLVs.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Read from `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    /// No bytes left.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Tag of the next TLV, if any.
    pub fn peek_tag(&self) -> Option<u8> {
        self.buf.first().copied()
    }

    /// Read the next TLV.
    pub fn read(&mut self) -> Result<Tlv<'a>, DerError> {
        let all = self.buf;
        let (&t, rest) = all.split_first().ok_or(DerError("truncated"))?;
        if t & 0x1f == 0x1f {
            return Err(DerError("multi-octet tag"));
        }
        let (&l0, rest) = rest.split_first().ok_or(DerError("truncated length"))?;
        let (len, rest) = if l0 < 0x80 {
            (usize::from(l0), rest)
        } else {
            let n = usize::from(l0 & 0x7f);
            if n == 0 || n > 4 {
                return Err(DerError("indefinite or oversized length"));
            }
            let lb = rest.get(..n).ok_or(DerError("truncated length"))?;
            if lb.first() == Some(&0) {
                return Err(DerError("non-minimal length"));
            }
            let mut len: usize = 0;
            for b in lb {
                len = (len << 8) | usize::from(*b);
            }
            if len < 0x80 {
                return Err(DerError("non-minimal length"));
            }
            (len, rest.get(n..).ok_or(DerError("truncated length"))?)
        };
        let value = rest.get(..len).ok_or(DerError("truncated value"))?;
        let header = all.len().saturating_sub(rest.len());
        let total = header.checked_add(len).ok_or(DerError("overflow"))?;
        let raw = all.get(..total).ok_or(DerError("truncated value"))?;
        self.buf = all.get(total..).ok_or(DerError("truncated value"))?;
        Ok(Tlv { tag: t, value, raw })
    }

    /// Read the next TLV and require its tag.
    pub fn expect(&mut self, t: u8) -> Result<Tlv<'a>, DerError> {
        let v = self.read()?;
        if v.tag != t {
            return Err(DerError("unexpected tag"));
        }
        Ok(v)
    }

    /// Read the next TLV only if it has tag `t`.
    pub fn optional(&mut self, t: u8) -> Result<Option<Tlv<'a>>, DerError> {
        if self.peek_tag() == Some(t) { self.read().map(Some) } else { Ok(None) }
    }

    /// Require that nothing is left.
    pub fn finish(&self) -> Result<(), DerError> {
        if self.buf.is_empty() { Ok(()) } else { Err(DerError("trailing data")) }
    }
}

/// Parse exactly one TLV with tag `t` covering all of `buf`.
pub fn single(buf: &[u8], t: u8) -> Result<Tlv<'_>, DerError> {
    let mut r = Reader::new(buf);
    let v = r.expect(t)?;
    r.finish()?;
    Ok(v)
}

/// BIT STRING contents with zero unused bits (keys and signatures).
pub fn bit_string_bytes(v: &[u8]) -> Result<&[u8], DerError> {
    match v.split_first() {
        Some((0, rest)) => Ok(rest),
        _ => Err(DerError("bit string with unused bits")),
    }
}

// ------------------------------------------------------------------------------------------------ encoder

/// Encode one TLV.
pub fn tlv(t: u8, content: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(content.len().saturating_add(6));
    v.push(t);
    let n = content.len();
    if n < 0x80 {
        v.push(n as u8);
    } else {
        let be = n.to_be_bytes();
        let lead = be.iter().take_while(|b| **b == 0).count();
        let bytes = be.get(lead..).unwrap_or(&[]);
        v.push(0x80 | bytes.len() as u8);
        v.extend_from_slice(bytes);
    }
    v.extend_from_slice(content);
    v
}

/// SEQUENCE of already-encoded parts.
pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(tag::SEQUENCE, &parts.concat())
}

/// SET of already-encoded parts (caller supplies DER order; single-element sets here).
pub fn set(parts: &[&[u8]]) -> Vec<u8> {
    tlv(tag::SET, &parts.concat())
}

/// OBJECT IDENTIFIER from its encoded contents.
pub fn oid(content: &[u8]) -> Vec<u8> {
    tlv(tag::OID, content)
}

/// BIT STRING with zero unused bits.
pub fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut c = Vec::with_capacity(bytes.len().saturating_add(1));
    c.push(0);
    c.extend_from_slice(bytes);
    tlv(tag::BIT_STRING, &c)
}

/// Non-negative INTEGER from big-endian magnitude bytes (minimal encoding, sign octet added if needed).
pub fn uint(be: &[u8]) -> Vec<u8> {
    let lead = be.iter().take_while(|b| **b == 0).count();
    let mag = be.get(lead..).unwrap_or(&[]);
    let mut c = Vec::with_capacity(mag.len().saturating_add(1));
    if mag.first().is_none_or(|b| *b & 0x80 != 0) {
        c.push(0);
    }
    c.extend_from_slice(mag);
    tlv(tag::INTEGER, &c)
}

/// Encoded OID contents used by the certificate code.
pub mod oids {
    /// id-ecPublicKey 1.2.840.10045.2.1.
    pub const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    /// prime256v1 1.2.840.10045.3.1.7.
    pub const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    /// secp384r1 1.3.132.0.34.
    pub const P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
    /// ecdsa-with-SHA256 1.2.840.10045.4.3.2.
    pub const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    /// ecdsa-with-SHA384 1.2.840.10045.4.3.3.
    pub const ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
    /// rsaEncryption 1.2.840.113549.1.1.1.
    pub const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    /// sha256WithRSAEncryption 1.2.840.113549.1.1.11.
    pub const RSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    /// sha384WithRSAEncryption 1.2.840.113549.1.1.12.
    pub const RSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
    /// sha512WithRSAEncryption 1.2.840.113549.1.1.13.
    pub const RSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
    /// pkcs-9 extensionRequest 1.2.840.113549.1.9.14.
    pub const EXTENSION_REQUEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e];
    /// id-at-commonName 2.5.4.3.
    pub const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
    /// id-ce-subjectAltName 2.5.29.17.
    pub const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
    /// id-ce-authorityKeyIdentifier 2.5.29.35.
    pub const AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1d, 0x23];
    /// id-ce-subjectKeyIdentifier 2.5.29.14.
    pub const SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1d, 0x0e];
    /// id-ce-basicConstraints 2.5.29.19.
    pub const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
    /// id-pe-acmeIdentifier 1.3.6.1.5.5.7.1.31 (RFC 8737, TLS-ALPN-01).
    pub const ACME_IDENTIFIER: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f];
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn roundtrip_lengths() {
        for n in [0usize, 1, 127, 128, 255, 256, 65535, 65536] {
            let c = vec![7u8; n];
            let e = tlv(tag::OCTET_STRING, &c);
            let v = single(&e, tag::OCTET_STRING).unwrap();
            assert_eq!(v.value.len(), n);
            assert_eq!(v.raw.len(), e.len());
        }
    }

    #[test]
    fn rejects_bad_lengths() {
        assert!(single(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5], 0x04).is_err()); // non-minimal long form
        assert!(single(&[0x04, 0x80], 0x04).is_err()); // indefinite
        assert!(single(&[0x04, 0x82, 0x00, 0x80], 0x04).is_err()); // leading zero length octet
        assert!(single(&[0x04, 0x05, 1, 2], 0x04).is_err()); // truncated
        assert!(single(&[0x04, 0x01, 1, 9], 0x04).is_err()); // trailing
        assert!(single(&[0x1f, 0x01, 0x00], 0x1f).is_err()); // high tag number
    }

    #[test]
    fn uint_minimal() {
        assert_eq!(uint(&[0]), vec![2, 1, 0]);
        assert_eq!(uint(&[0, 0, 0x7f]), vec![2, 1, 0x7f]);
        assert_eq!(uint(&[0x80]), vec![2, 2, 0, 0x80]);
    }

    #[test]
    fn total_on_random_input() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..50_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let bytes = x.to_le_bytes();
            let mut r = Reader::new(&bytes[..(x % 9) as usize]);
            while r.read().is_ok() {}
        }
    }
}
