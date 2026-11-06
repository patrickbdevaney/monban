//! PROXY protocol v2 header parse (aegis-wire `proxy::parse_v2`; F1 PROXY-1..3).
//!
//! Properties:
//! - total: `parse_v2` returns on every input, never panics;
//! - `parse_v2(b) = Ok((_, consumed))` implies `consumed = 16 + declared length`, `consumed <= b.len()` and
//!   `consumed <= 16 + MAX_DECLARED_LEN`;
//! - no read past the declared length: the result on `b[..16 + declared]` is the same, and every TLV and UNIX path
//!   field lies inside `b[..consumed]`; a declared length over the cap is refused from the fixed part alone;
//! - a v1 (text) header, or any prefix of one, is never accepted (F1 PROXY-3);
//! - a proper prefix of an accepted header is `Incomplete` (byte-by-byte reads reach the same verdict).
//!
//! Seeds: `fuzz/corpus/proxy_v2/` holds every oracles/proxy-l4 PROXY vector (spec, trailing, policy, hostile).
#![no_main]

use aegis_fuzz::selftest;
use aegis_wire::proxy::{Addresses, FIXED_LEN, MAX_DECLARED_LEN, ProxyError, parse_v2};
use libfuzzer_sys::fuzz_target;

fn inside(data: &[u8], consumed: usize, f: &[u8]) -> bool {
    let (d, s) = (data.as_ptr() as usize, f.as_ptr() as usize);
    f.is_empty() || (s >= d && s + f.len() <= d + consumed)
}

fuzz_target!(|data: &[u8]| {
    let r = parse_v2(data);
    let declared =
        data.get(14..16).and_then(|b| <[u8; 2]>::try_from(b).ok()).map(|b| usize::from(u16::from_be_bytes(b)));
    if let Ok((h, consumed)) = r {
        assert!(consumed <= data.len(), "consumed past the input");
        assert!(consumed <= FIXED_LEN + MAX_DECLARED_LEN, "consumed over the declared-length cap");
        assert_eq!(Some(consumed), declared.map(|n| FIXED_LEN + n), "consumed != 16 + declared length");
        assert!(!data.starts_with(b"PROXY"), "v1 header accepted");
        for t in h.tlvs() {
            assert!(inside(data, consumed, t.value), "TLV outside the header");
        }
        if let Addresses::Unix { src, dst } = h.addresses {
            assert!(inside(data, consumed, src) && inside(data, consumed, dst), "UNIX path outside the header");
        }
        let step = (consumed / 7).max(1);
        for k in (0..consumed).step_by(step) {
            assert_eq!(parse_v2(data.get(..k).unwrap_or(&[])), Err(ProxyError::Incomplete), "prefix not Incomplete");
        }
    }
    if let Some(n) = declared {
        if n > MAX_DECLARED_LEN {
            assert!(
                matches!(r, Err(ProxyError::TooLong | ProxyError::Malformed | ProxyError::V1Refused)),
                "over-cap length not refused"
            );
        }
        if let Some(prefix) = data.get(..FIXED_LEN + n) {
            assert_eq!(parse_v2(prefix), r, "result depends on bytes after the declared length");
        }
    }
    let m = data.len().min(5);
    if m > 0 && data.get(..m) == b"PROXY".get(..m) {
        assert_eq!(r, Err(ProxyError::V1Refused), "v1 prefix not refused");
    }
    selftest!(data.first() == Some(&0x0d) && data.get(1) == Some(&0x0a));
});
