//! Base64 (RFC 4648 §4, padded, canonical per §3.5) and lowercase hex, as required by c2sp.org/signed-note@v1.1.0.

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const HEX: &[u8; 16] = b"0123456789abcdef";

fn b64_char(v: u32) -> char {
    B64.get((v & 63) as usize).map_or('A', |&c| c as char)
}

/// Standard padded base64.
pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(b64_char(n >> 18));
        out.push(b64_char(n >> 12));
        out.push(if chunk.len() > 1 { b64_char(n >> 6) } else { '=' });
        out.push(if chunk.len() > 2 { b64_char(n) } else { '=' });
    }
    out
}

fn b64_value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Strict decoder: padded input only, rejects non-canonical encodings (non-zero pad bits).
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let quads = bytes.len() / 4;
    for (i, q) in bytes.chunks(4).enumerate() {
        let last = i + 1 == quads;
        let pad = q.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n: u32 = 0;
        for (j, &c) in q.iter().enumerate() {
            let v = if j >= 4 - pad { 0 } else { b64_value(c)? };
            n = (n << 6) | v;
        }
        let [_, a, b, c] = n.to_be_bytes();
        out.push(a);
        match pad {
            0 => {
                out.push(b);
                out.push(c);
            }
            1 => {
                if c != 0 {
                    return None;
                }
                out.push(b);
            }
            _ => {
                if b != 0 || c != 0 {
                    return None;
                }
            }
        }
    }
    Some(out)
}

/// Lowercase hex.
pub fn hex_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for &b in input {
        out.push(HEX.get(usize::from(b >> 4)).map_or('0', |&c| c as char));
        out.push(HEX.get(usize::from(b & 15)).map_or('0', |&c| c as char));
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        let v = [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE=")];
        for (raw, enc) in v {
            assert_eq!(base64_encode(raw.as_bytes()), enc);
            assert_eq!(base64_decode(enc).unwrap(), raw.as_bytes());
        }
        assert_eq!(base64_decode("Zh=="), None, "non-canonical pad bits");
        assert_eq!(base64_decode("Zg="), None);
        assert_eq!(base64_decode("Zg==Zg=="), None);
        assert_eq!(hex_encode(&[0, 0xab, 0x10]), "00ab10");
    }

    #[test]
    fn roundtrip_all_lengths() {
        let data: Vec<u8> = (0..=255u8).collect();
        for n in 0..data.len() {
            assert_eq!(base64_decode(&base64_encode(&data[..n])).unwrap(), &data[..n]);
        }
    }
}
