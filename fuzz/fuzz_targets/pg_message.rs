//! PG v3 backend message framing + parse (aegis-adapter-pg `wire::msg::{body_len, parse_backend}`; PREFLIGHT R14).
//!
//! P8-spec-002 registration stub; P8-hardening-001 owns this file and adds the full property set and seeds.
//!
//! Input: a byte stream of backend messages (`tag`, 4-byte big-endian length, body), split the way
//! `Connection::read_event` splits it: `body_len` validates each header against the default cap, then
//! `parse_backend` sees exactly that body.
//!
//! Properties (hold for today's codec and for any refinement of it):
//! - total: `body_len` and `parse_backend` return on every input, never panic;
//! - `body_len(t, l, cap) = Ok(n)` implies `n + 4` equals the declared length and `n + 4 <= min(cap, HARD_MAX)`.
#![no_main]

use aegis_adapter_pg::wire::msg::{DEFAULT_MAX_MESSAGE, HARD_MAX_MESSAGE, body_len, parse_backend};
use aegis_fuzz::selftest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut rest = data;
    while let (Some(&tag), Some(len)) = (rest.first(), rest.get(1..5)) {
        let Ok(len_field) = <[u8; 4]>::try_from(len) else { break };
        let Ok(n) = body_len(tag, len_field, DEFAULT_MAX_MESSAGE) else { break };
        let declared = i64::from(i32::from_be_bytes(len_field));
        assert_eq!(i64::try_from(n).ok().map(|n| n + 4), Some(declared), "body length != declared - 4");
        assert!(n + 4 <= DEFAULT_MAX_MESSAGE.min(HARD_MAX_MESSAGE), "body over the cap accepted");
        let Some(body) = rest.get(5..5 + n) else { break };
        let _ = parse_backend(tag, body);
        rest = rest.get(5 + n..).unwrap_or_default();
    }
    selftest!(data.first() == Some(&b'Z') && data.get(1) == Some(&0));
});
