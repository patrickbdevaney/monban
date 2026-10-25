//! Base64 codecs (RFC 4648): §5 base64url without padding (JOSE, ACME, ARI certID) and §4 standard base64 with
//! padding (PEM bodies). In-crate per DEVIATIONS X-6 (no base64 crate). Decoders are strict and total: any byte
//! outside the alphabet, a wrong length, or non-zero trailing bits is a rejection, never a repair.

use std::string::String;
use std::vec::Vec;

const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn sym(alphabet: &[u8; 64], idx: u32) -> char {
    char::from(alphabet.get((idx & 0x3f) as usize).copied().unwrap_or(b'A'))
}

fn encode(data: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(data.len().saturating_mul(4) / 3 + 4);
    for chunk in data.chunks(3) {
        let (n, b) = match chunk {
            [a, b, c] => (3, (u32::from(*a) << 16) | (u32::from(*b) << 8) | u32::from(*c)),
            [a, b] => (2, (u32::from(*a) << 16) | (u32::from(*b) << 8)),
            [a] => (1, u32::from(*a) << 16),
            _ => continue,
        };
        out.push(sym(alphabet, b >> 18));
        out.push(sym(alphabet, b >> 12));
        if n >= 2 {
            out.push(sym(alphabet, b >> 6));
        } else if pad {
            out.push('=');
        }
        if n == 3 {
            out.push(sym(alphabet, b));
        } else if pad {
            out.push('=');
        }
    }
    out
}

fn value(alphabet: &[u8; 64], c: u8) -> Option<u32> {
    alphabet.iter().position(|a| *a == c).and_then(|p| u32::try_from(p).ok())
}

fn decode_unpadded(s: &[u8], alphabet: &[u8; 64]) -> Option<Vec<u8>> {
    if s.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3 + 3);
    for chunk in s.chunks(4) {
        let mut acc: u32 = 0;
        for c in chunk {
            acc = (acc << 6) | value(alphabet, *c)?;
        }
        match chunk.len() {
            4 => {
                out.push((acc >> 16) as u8);
                out.push((acc >> 8) as u8);
                out.push(acc as u8);
            }
            3 => {
                // 18 bits: 16 data + 2 that must be zero.
                if acc & 0x3 != 0 {
                    return None;
                }
                out.push((acc >> 10) as u8);
                out.push((acc >> 2) as u8);
            }
            2 => {
                if acc & 0xf != 0 {
                    return None;
                }
                out.push((acc >> 4) as u8);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// base64url (RFC 4648 §5) without padding (RFC 7515 §2).
pub fn b64url_encode(data: &[u8]) -> String {
    encode(data, URL, false)
}

/// Strict base64url decode: unpadded, alphabet `A-Za-z0-9-_` only, canonical trailing bits.
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    decode_unpadded(s.as_bytes(), URL)
}

/// Standard base64 (RFC 4648 §4) with padding.
pub fn b64_encode(data: &[u8]) -> String {
    encode(data, STD, true)
}

/// Strict standard base64 decode with mandatory padding to a multiple of 4.
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    let pads = b.iter().rev().take_while(|c| **c == b'=').count();
    if pads > 2 {
        return None;
    }
    let body = b.get(..b.len().saturating_sub(pads))?;
    let out = decode_unpadded(body, STD)?;
    // A padded group must decode to exactly 3 - pads bytes (decode_unpadded already enforced canonical bits).
    if pads > 0 && body.len() % 4 != 4 - pads {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        let v: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (raw, enc) in v {
            assert_eq!(b64_encode(raw), enc);
            assert_eq!(b64_decode(enc).as_deref(), Some(raw));
            let url = enc.trim_end_matches('=');
            assert_eq!(b64url_encode(raw), url);
            assert_eq!(b64url_decode(url).as_deref(), Some(raw));
        }
    }

    #[test]
    fn strictness() {
        assert_eq!(b64url_decode("Zg=="), None); // padding not allowed in base64url form
        assert_eq!(b64url_decode("Zh"), None); // non-zero trailing bits
        assert_eq!(b64url_decode("Z"), None); // impossible length
        assert_eq!(b64url_decode("Zm+v"), None); // std alphabet char
        assert_eq!(b64_decode("Zm9"), None);
        assert_eq!(b64_decode("Z==="), None);
        assert_eq!(b64_decode("Zm-v"), None);
        assert_eq!(b64url_decode("_-8"), Some(vec![0xff, 0xef]));
    }

    #[test]
    fn total_on_random_input() {
        let mut x: u32 = 0x1234_5678;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let len = (x % 12) as usize;
            let bytes: Vec<u8> = (0..len).map(|i| (x.rotate_left(i as u32 * 3) & 0x7f) as u8).collect();
            let s = String::from_utf8_lossy(&bytes);
            if let Some(d) = b64url_decode(&s) {
                assert_eq!(b64url_encode(&d), s);
            }
            if let Some(d) = b64_decode(&s) {
                assert_eq!(b64_encode(&d), s);
            }
        }
    }
}
