//! TLS ClientHello peek (monban-wire `tls_peek::client_hello`; F1 L4-1, SEL-1 input).
//!
//! Properties:
//! - total: `client_hello` returns on every input, never panics;
//! - an accepted record is a handshake record (content type 22) of 1..=`MAX_RECORD` body bytes, and
//!   `consumed = 5 + record length <= input`;
//! - no read past the declared length: the result on `b[..5 + record length]` is the same, and every extracted field
//!   is a sub-slice of the record body (no copy, no read outside it); a record over the cap is refused from its header;
//! - the list iterators walk every validated field without panicking, and an accepted SNI is ASCII LDH;
//! - a proper prefix of an accepted record is `Incomplete`.
//!
//! Seeds: `fuzz/corpus/client_hello_peek/` holds every oracles/proxy-l4 ClientHello vector (valid and hostile).
#![no_main]

use monban_fuzz::selftest;
use monban_wire::tls_peek::{MAX_RECORD, PeekError, client_hello};
use libfuzzer_sys::fuzz_target;

fn inside(data: &[u8], consumed: usize, field: Option<&[u8]>) -> bool {
    field.is_none_or(|f| {
        let (d, s) = (data.as_ptr() as usize, f.as_ptr() as usize);
        s >= d + 5 && s + f.len() <= d + consumed
    })
}

fuzz_target!(|data: &[u8]| {
    let r = client_hello(data);
    let declared = data.get(3..5).and_then(|b| <[u8; 2]>::try_from(b).ok()).map(|b| usize::from(u16::from_be_bytes(b)));
    if let Ok(p) = r {
        assert_eq!(data.first(), Some(&22), "non-handshake record accepted");
        assert!(
            declared.is_some_and(|n| (1..=MAX_RECORD).contains(&n)),
            "record length outside 1..=MAX_RECORD accepted"
        );
        assert_eq!(Some(p.consumed), declared.map(|n| 5 + n), "consumed != 5 + record length");
        assert!(p.consumed <= data.len(), "consumed past the input");
        for f in [p.sni, p.alpn, p.versions, p.sigalgs, p.groups, p.trust_anchors] {
            assert!(inside(data, p.consumed, f), "extracted field outside the record");
        }
        if let Some(s) = p.sni {
            assert!(s.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'.'), "non-LDH SNI accepted");
        }
        assert!(p.alpn_protocols().all(|a| !a.is_empty()), "empty ALPN name accepted");
        assert!(p.trust_anchor_ids().all(|i| (1..=32).contains(&i.len())), "bad TrustAnchorID length accepted");
        let _ = p.version_list().chain(p.sigalg_list()).chain(p.group_list()).count();
        let step = (p.consumed / 7).max(1);
        for k in (0..p.consumed).step_by(step) {
            assert_eq!(client_hello(data.get(..k).unwrap_or(&[])), Err(PeekError::Incomplete), "prefix not Incomplete");
        }
    }
    if let Some(n) = declared {
        if n > MAX_RECORD {
            assert!(matches!(r, Err(PeekError::TooLong | PeekError::NotClientHello)), "oversized record not refused");
        }
        if let Some(prefix) = data.get(..5 + n) {
            assert_eq!(client_hello(prefix), r, "result depends on bytes after the record");
        }
    }
    selftest!(data.first() == Some(&0x16) && data.get(1) == Some(&0x03));
});
