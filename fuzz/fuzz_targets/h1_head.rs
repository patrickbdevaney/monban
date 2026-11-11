//! F2/F3: strict HTTP/1.1 request framing (monban-transport `h1::H1Validator`, `h1::validate_head`, `FieldBlock`).
//!
//! Input: byte 0 picks the limits, byte 1 the chunking seed; the rest is the connection byte stream.
//! Properties:
//! - the forwarded bytes are a prefix of the input, unchanged (the filter never rewrites);
//! - feeding the stream in arbitrary pieces gives the same forwarded bytes and the same reject as one feed
//!   (no state is lost across reads);
//! - once rejected, the validator stays rejected with the same reject and forwards nothing more;
//! - with no reject and not mid-message, everything was forwarded;
//! - `validate_head` on any forwarded-and-complete head prefix is consistent with the validator (accepts it).
#![no_main]

use monban_fuzz::selftest;
use monban_transport::h1::{H1Reject, H1Validator, HeadLimits, validate_head};
use monban_transport::{FieldBlock, cookie_crumbs};
use libfuzzer_sys::fuzz_target;

const LIMITS: [HeadLimits; 3] = [
    HeadLimits { max_head_bytes: 24_592, max_field_bytes: 16_384, max_fields: 128 },
    HeadLimits { max_head_bytes: 256, max_field_bytes: 160, max_fields: 4 },
    HeadLimits { max_head_bytes: 64, max_field_bytes: 1 << 20, max_fields: 1 << 20 },
];

fn run_whole(lim: HeadLimits, s: &[u8]) -> (Vec<u8>, Option<H1Reject>, bool) {
    let mut v = H1Validator::new(lim);
    let mut out = Vec::new();
    let r = v.feed(s, &mut out);
    assert_eq!(r.err(), v.rejected(), "feed result disagrees with rejected()");
    (out, v.rejected(), v.mid_message())
}

fn run_pieces(lim: HeadLimits, s: &[u8], seed: u8) -> (Vec<u8>, Option<H1Reject>, bool) {
    let mut v = H1Validator::new(lim);
    let mut out = Vec::new();
    let mut rest = s;
    let mut x = u32::from(seed) | 1;
    let mut first_reject: Option<H1Reject> = None;
    while !rest.is_empty() {
        // xorshift piece sizes 1..=16
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        let n = usize::try_from(x % 16 + 1).unwrap_or(1).min(rest.len());
        let (now, later) = rest.split_at(n);
        rest = later;
        let before = out.len();
        let r = v.feed(now, &mut out);
        if let Some(prev) = first_reject {
            assert_eq!(r, Err(prev), "reject is not sticky");
            assert_eq!(out.len(), before, "bytes forwarded after a reject");
        }
        if let Err(e) = r {
            first_reject.get_or_insert(e);
        }
    }
    (out, v.rejected(), v.mid_message())
}

fuzz_target!(|data: &[u8]| {
    let (Some(&b0), Some(&b1)) = (data.first(), data.get(1)) else { return };
    let stream = data.get(2..).unwrap_or(&[]);
    let lim = LIMITS[usize::from(b0) % LIMITS.len()];

    let (whole, rej_w, mid_w) = run_whole(lim, stream);
    assert!(stream.starts_with(&whole), "forwarded bytes are not an unchanged prefix of the input");
    let (pieces, rej_p, mid_p) = run_pieces(lim, stream, b1);
    assert_eq!(whole, pieces, "split-dependent forwarding");
    assert_eq!(rej_w, rej_p, "split-dependent reject");
    assert_eq!(mid_w, mid_p, "split-dependent message state");
    if rej_w.is_none() && !mid_w {
        assert_eq!(whole.len(), stream.len(), "idle validator withheld bytes");
    }
    if let Some(r) = rej_w {
        assert!(matches!(r.status, 400 | 417 | 431), "unexpected reject status {}", r.status);
    }

    // The first head, if it was forwarded, must be accepted by validate_head on its own.
    if let Some(end) = whole.windows(4).position(|w| w == b"\r\n\r\n") {
        let head = whole.get(..end + 4).unwrap_or(&[]);
        assert!(validate_head(head, &lim).is_ok(), "forwarded head rejected by validate_head");
        // examples/seeds.rs forwards at most two heads; three pipelined requests need a mutation.
        selftest!(whole.windows(4).filter(|w| *w == b"\r\n\r\n").count() >= 3);
    }
    // validate_head is total on the raw stream too.
    let _ = validate_head(stream, &lim);

    // FieldBlock accounting is monotone and saturating.
    let mut fb = FieldBlock::new();
    for line in stream.split(|&b| b == b'\n').take(64) {
        let (name, value) = match line.iter().position(|&b| b == b':') {
            Some(i) => (line.get(..i).unwrap_or(&[]), line.get(i + 1..).unwrap_or(&[])),
            None => (line, &[][..]),
        };
        let (b, c) = (fb.bytes(), fb.count());
        fb.add(name, value);
        assert!(fb.bytes() > b || fb.bytes() == u64::MAX, "field bytes did not grow");
        assert!(fb.count() > c || fb.count() == u64::MAX, "field count did not grow");
        assert!(cookie_crumbs(value) >= 1);
    }
});
