//! PG v3 backend message framing + parse (aegis-adapter-pg `wire::msg::{body_len, parse_backend}`; PREFLIGHT R14).
//!
//! Registered by P8-spec-002; body by P8-hardening-001.
//!
//! Input byte 0 selects the mode:
//! - even: the rest is a raw byte stream of backend messages (`tag`, 4-byte big-endian length, body), split the way
//!   `Connection::read_event` splits it (`body_len` against the default cap, then `parse_backend` on exactly that
//!   body), until a header is refused or the input ends;
//! - odd: the rest is `tag, n, n bytes` triples with the framing synthesized, so the body grammar of every message
//!   type is reached without the fuzzer first having to find a valid length field (no seed corpus needed).
//!
//! Properties (they hold for today's codec and for any refinement of it):
//! - total: `body_len` and `parse_backend` return on every input, never panic;
//! - `body_len(t, l, cap) = Ok(n)` implies `n + 4` = the declared length and `n + 4 <= min(cap, HARD_MAX)`, a
//!   declared length under 4 or over the cap is refused, and the verdict for a cap is the same for every larger cap
//!   up to the declared length (monotone in the cap);
//! - deterministic: parsing the same body twice gives the same result;
//! - exact framing: for every message type whose grammar is fully delimited (all but the opaque-tail ones: SASL
//!   continue/final, BackendKeyData, MD5, CopyData, Copy*Response), an accepted body with one more byte appended, or
//!   with its last byte removed, is refused (no trailing junk, no short read accepted);
//! - shape: an accepted message stays inside the codec's caps (BackendKeyData secret 4..=256 bytes, at most 16 SASL
//!   mechanisms, at most 65,535 fields, at most 64 unrecognized protocol options, DataRow values and the
//!   ParameterDescription array fit in the body, ReadyForQuery is one status byte);
//! - an unknown message type is refused.
#![no_main]

use aegis_adapter_pg::wire::msg::{Auth, Backend, DEFAULT_MAX_MESSAGE, HARD_MAX_MESSAGE, body_len, parse_backend};
use aegis_fuzz::selftest;
use libfuzzer_sys::fuzz_target;

const KNOWN: &[u8] = b"RKSZ123nsIctTDCENAvGHWd";

/// Whether `m` (from `tag`) is a fully delimited message: its parse consumed the whole body by grammar, not by
/// taking an opaque tail.
fn delimited(m: &Backend) -> bool {
    !matches!(
        m,
        Backend::Authentication(Auth::SaslContinue(_) | Auth::SaslFinal(_) | Auth::Md5Password | Auth::Other(_))
            | Backend::BackendKeyData { .. }
            | Backend::CopyData(_)
            | Backend::CopyInResponse
            | Backend::CopyOutResponse
            | Backend::CopyBothResponse
    )
}

fn check_shape(tag: u8, body: &[u8], m: &Backend) {
    match m {
        Backend::BackendKeyData { secret, .. } => assert!((4..=256).contains(&secret.len()), "cancel key length"),
        Backend::Authentication(Auth::Sasl(mechs)) => {
            assert!(mechs.len() <= 16, "too many SASL mechanisms accepted");
            assert!(mechs.iter().all(|s| !s.is_empty() && !s.contains('\0')), "empty or NUL mechanism");
        }
        Backend::RowDescription(f) => assert!(f.len() <= 65_535, "too many fields"),
        Backend::DataRow(v) => {
            let bytes: usize = v.iter().map(|c| c.as_ref().map_or(4, |b| 4 + b.len())).sum();
            assert_eq!(bytes + 2, body.len(), "DataRow values do not add up to the body");
        }
        Backend::ParameterDescription(o) => assert_eq!(2 + 4 * o.len(), body.len(), "ParameterDescription length"),
        Backend::ReadyForQuery(_) => assert_eq!(body.len(), 1, "ReadyForQuery body"),
        Backend::NegotiateProtocolVersion { unrecognized, .. } => assert!(unrecognized.len() <= 64),
        Backend::ParseComplete
        | Backend::BindComplete
        | Backend::CloseComplete
        | Backend::NoData
        | Backend::PortalSuspended
        | Backend::EmptyQueryResponse
        | Backend::CopyDone => assert!(body.is_empty(), "empty message with a body"),
        _ => {}
    }
    assert!(KNOWN.contains(&tag), "unknown message type accepted");
}

fn one(tag: u8, body: &[u8]) {
    let r = parse_backend(tag, body);
    assert_eq!(parse_backend(tag, body), r, "parse is not deterministic");
    if !KNOWN.contains(&tag) {
        assert!(r.is_err(), "unknown message type accepted");
    }
    if let Ok(m) = &r {
        check_shape(tag, body, m);
        if delimited(m) {
            let mut longer = body.to_vec();
            longer.push(0);
            assert!(parse_backend(tag, &longer).is_err(), "trailing byte accepted after a delimited message");
            if let Some(short) = body.len().checked_sub(1).and_then(|n| body.get(..n)) {
                assert!(parse_backend(tag, short).is_err(), "short body accepted for a delimited message");
            }
        }
    }
}

fn header(tag: u8, len_field: [u8; 4]) -> Option<usize> {
    let declared = i64::from(i32::from_be_bytes(len_field));
    let r = body_len(tag, len_field, DEFAULT_MAX_MESSAGE);
    if let Ok(n) = r {
        assert_eq!(i64::try_from(n).ok().map(|n| n + 4), Some(declared), "body length != declared - 4");
        assert!(n + 4 <= DEFAULT_MAX_MESSAGE.min(HARD_MAX_MESSAGE), "body over the cap accepted");
    } else if (4..=i64::try_from(DEFAULT_MAX_MESSAGE).unwrap_or(i64::MAX)).contains(&declared) {
        panic!("in-range declared length {declared} refused");
    }
    // Monotone in the cap: any cap at or above the declared length gives the same verdict; a cap below refuses.
    if let Ok(d) = usize::try_from(declared) {
        for cap in [d, d.saturating_add(1), HARD_MAX_MESSAGE, usize::MAX] {
            let rc = body_len(tag, len_field, cap);
            if (4..=HARD_MAX_MESSAGE).contains(&d) {
                assert_eq!(rc.ok(), Some(d - 4), "verdict changed with a larger cap");
            } else {
                assert!(rc.is_err(), "length outside 4..=HARD_MAX accepted");
            }
        }
        if d >= 5 {
            assert!(body_len(tag, len_field, d - 1).is_err(), "declared length over the cap accepted");
        }
    }
    r.ok()
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, mut rest)) = data.split_first() else { return };
    if mode % 2 == 0 {
        while let (Some(&tag), Some(len)) = (rest.first(), rest.get(1..5)) {
            let Ok(len_field) = <[u8; 4]>::try_from(len) else { break };
            let Some(n) = header(tag, len_field) else { break };
            let Some(body) = rest.get(5..5 + n) else { break };
            one(tag, body);
            rest = rest.get(5 + n..).unwrap_or_default();
        }
    } else {
        while let (Some(&sel), Some(&n)) = (rest.first(), rest.get(1)) {
            // Map the selector onto the known tags most of the time, any byte otherwise.
            let tag = if sel < 0xE0 { KNOWN.get(usize::from(sel) % KNOWN.len()).copied().unwrap_or(sel) } else { sel };
            let n = usize::from(n);
            let body = rest.get(2..(2 + n).min(rest.len())).unwrap_or_default();
            one(tag, body);
            rest = rest.get((2 + n).min(rest.len())..).unwrap_or_default();
        }
    }
    selftest!(data.get(1) == Some(&b'Z') && data.get(2) == Some(&0));
});
