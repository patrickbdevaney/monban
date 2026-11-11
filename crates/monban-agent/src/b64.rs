//! Strict base64 decoders (RFC 4648) and lowercase hex.
//!
//! * [`decode_url`]: base64url without padding (JWS compact serialization, RFC 7515 §2). Padding, whitespace,
//!   characters outside the alphabet, a length of 1 mod 4 and non-zero trailing bits are rejected, so every byte
//!   string has exactly one accepted encoding (CANON-2: one reading).
//! * [`decode_std`]: standard base64 with mandatory padding (the MCP header-value sentinel `=?base64?…?=`), with the
//!   same canonicality rules.

use std::string::String;
use std::vec::Vec;

fn val(c: u8, url: bool) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' if url => 62,
        b'_' if url => 63,
        b'+' if !url => 62,
        b'/' if !url => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

fn decode(s: &[u8], url: bool) -> Option<Vec<u8>> {
    if s.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3 + 2);
    for chunk in s.chunks(4) {
        let mut acc: u32 = 0;
        for &c in chunk {
            acc = (acc << 6) | val(c, url)?;
        }
        match chunk.len() {
            4 => {
                out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]);
            }
            3 => {
                // 18 bits: 16 data + 2 trailing bits that must be zero.
                if acc & 0x3 != 0 {
                    return None;
                }
                out.extend_from_slice(&[(acc >> 10) as u8, (acc >> 2) as u8]);
            }
            2 => {
                // 12 bits: 8 data + 4 trailing bits that must be zero.
                if acc & 0xF != 0 {
                    return None;
                }
                out.push((acc >> 4) as u8);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// base64url, unpadded, canonical.
pub fn decode_url(s: &[u8]) -> Option<Vec<u8>> {
    decode(s, true)
}

/// Standard base64, padded, canonical.
pub fn decode_std(s: &[u8]) -> Option<Vec<u8>> {
    if s.is_empty() {
        return Some(Vec::new());
    }
    if !s.len().is_multiple_of(4) {
        return None;
    }
    let body = match s {
        [rest @ .., b'=', b'='] => rest,
        [rest @ .., b'='] => rest,
        _ => s,
    };
    if body.contains(&b'=') {
        return None;
    }
    decode(body, false)
}

/// Standard base64, padded.
pub fn encode_std(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = c.iter().fold(0u32, |acc, &x| (acc << 8) | u32::from(x)) << (8 * (3 - c.len()));
        for i in 0..4 {
            if i <= c.len() {
                let idx = ((n >> (18 - 6 * i)) & 63) as usize;
                s.push(char::from(A.get(idx).copied().unwrap_or(b'A')));
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// Lowercase hex.
pub fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(char::from(H.get(usize::from(x >> 4)).copied().unwrap_or(b'0')));
        s.push(char::from(H.get(usize::from(x & 0xF)).copied().unwrap_or(b'0')));
    }
    s
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn url_round_trips_and_rejects() {
        assert_eq!(decode_url(b"").unwrap(), b"");
        assert_eq!(decode_url(b"Zg").unwrap(), b"f");
        assert_eq!(decode_url(b"Zm8").unwrap(), b"fo");
        assert_eq!(decode_url(b"Zm9v").unwrap(), b"foo");
        assert_eq!(decode_url(b"_-8").unwrap(), [0xff, 0xef]);
        assert!(decode_url(b"Zh").is_none(), "non-zero trailing bits");
        assert!(decode_url(b"Zm9").is_none(), "non-zero trailing bits");
        assert!(decode_url(b"Z").is_none(), "1 mod 4");
        assert!(decode_url(b"Zg==").is_none(), "padding");
        assert!(decode_url(b"Zm+v").is_none(), "std alphabet");
        assert!(decode_url(b"Zm 9").is_none(), "whitespace");
    }

    #[test]
    fn std_padded() {
        assert_eq!(decode_std(b"Zg==").unwrap(), b"f");
        assert_eq!(decode_std(b"Zm8=").unwrap(), b"fo");
        assert_eq!(decode_std(b"Zm9v").unwrap(), b"foo");
        assert!(decode_std(b"Zg").is_none());
        assert!(decode_std(b"Z===").is_none());
        assert!(decode_std(b"Zm=v").is_none());
        assert!(decode_std(b"Zm-v").is_none());
        assert_eq!(hex(&[0, 0xab, 0x10]), "00ab10");
        for v in [&b""[..], b"f", b"fo", b"foo", b"foob", b"\x00\xff\x10\x7f"] {
            assert_eq!(decode_std(encode_std(v).as_bytes()).unwrap(), v);
        }
        assert_eq!(encode_std(b"fo"), "Zm8=");
    }
}
