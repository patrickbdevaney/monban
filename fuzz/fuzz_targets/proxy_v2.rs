//! PROXY protocol v2 header parse (aegis-wire `proxy::parse_v2`; F1 PROXY-1..3).
//!
//! P7-spec-002 registration stub; P7-wire-001 owns this file and adds the full property set and seeds.
//!
//! Properties (hold for the fail-closed stub and for the real parser):
//! - total: `parse_v2` returns on every input, never panics;
//! - `parse_v2(b) = Ok((_, consumed))` implies `consumed <= b.len()` and `consumed <= 16 + MAX_DECLARED_LEN`;
//! - a v1 (text) header is never accepted (F1 PROXY-3).
#![no_main]

use aegis_fuzz::selftest;
use aegis_wire::proxy::{MAX_DECLARED_LEN, parse_v2};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((_, consumed)) = parse_v2(data) {
        assert!(consumed <= data.len(), "consumed past the input");
        assert!(consumed <= 16 + MAX_DECLARED_LEN, "consumed over the declared-length cap");
        assert!(!data.starts_with(b"PROXY "), "v1 header accepted");
    }
    selftest!(data.first() == Some(&0x0d) && data.get(1) == Some(&0x0a));
});
