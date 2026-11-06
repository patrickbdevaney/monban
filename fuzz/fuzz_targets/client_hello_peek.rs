//! TLS ClientHello peek (aegis-wire `tls_peek::client_hello`; F1 L4-1, SEL-1 input).
//!
//! P7-spec-002 registration stub; P7-wire-001 owns this file and adds the full property set and seeds.
//!
//! Properties (hold for the fail-closed stub and for the real peek):
//! - total: `client_hello` returns on every input, never panics;
//! - an accepted record is a handshake record (content type 22) of at most `MAX_RECORD` body bytes;
//! - every extracted field is a sub-slice of the input (no copy, no read outside it).
#![no_main]

use aegis_fuzz::selftest;
use aegis_wire::tls_peek::{MAX_RECORD, client_hello};
use libfuzzer_sys::fuzz_target;

fn inside(data: &[u8], field: Option<&[u8]>) -> bool {
    field.is_none_or(|f| {
        let (d, s) = (data.as_ptr() as usize, f.as_ptr() as usize);
        s >= d && s + f.len() <= d + data.len()
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = client_hello(data) {
        assert_eq!(data.first(), Some(&22), "non-handshake record accepted");
        let declared =
            data.get(3..5).and_then(|b| <[u8; 2]>::try_from(b).ok()).map(|b| usize::from(u16::from_be_bytes(b)));
        assert!(declared.is_some_and(|n| n <= MAX_RECORD), "record over MAX_RECORD (or no header) accepted");
        for f in [p.sni, p.alpn, p.versions, p.sigalgs, p.trust_anchors] {
            assert!(inside(data, f), "extracted field outside the input");
        }
    }
    selftest!(data.first() == Some(&0x16) && data.get(1) == Some(&0x03));
});
