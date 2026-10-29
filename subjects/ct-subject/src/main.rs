//! ct-subject: timing subject for oracles/ct-dudect. Times aegis-token's tag compare in-process, one call per
//! measurement, with `std::time::Instant` (no unsafe, no rdtsc).
//!
//! Protocol (binary, over stdin/stdout; see oracles/ct-dudect/README.md):
//!   - on start the subject writes one line `CT-SUBJECT 1 tag=<64 hex>`: the correct tag of its fixed token,
//!     so the oracle can build the input classes (equal, differs at the first byte, at the last byte, random).
//!   - the oracle writes a line `<target> <n>` (target = cmp | mac | verify, 1 <= n <= 1_000_000), then n*32
//!     bytes: one presented tag per measurement, in the oracle's (randomly interleaved) class order.
//!   - the subject answers n little-endian u64: the nanoseconds each call took, in the same order.
//!   - `quit` or EOF ends the session.
//!
//! The subject never sees class labels. Targets:
//!   - `cmp`: `aws_lc_rs::constant_time::verify_slices_are_equal(want, tag)`, the exact call `mac_valid` makes.
//!   - `mac`: `aegis_token::mac_valid(keys, token_with(tag), aud)` (HKDF + HMAC chain + compare).
//!   - `verify`: `aegis_token::verify(wire_with(tag), keys, req)` on the encoded wire bytes (decode + MAC + rest).
//!
//! `--mutant early-exit` replaces the compare with a byte-by-byte early-exit loop (oracle self-test only).
#![forbid(unsafe_code)]

use std::hint::black_box;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::time::Instant;

use aegis_token::{Caveat, KeyRing, Req, TokenL, chain_tag, denote, mac_valid, verify};

const TAG_LEN: usize = 32;
const MAX_BATCH: usize = 1_000_000;
const MASTER: [u8; 32] = [0x42; 32];
const KID: &[u8] = b"k1";
const AUD: &str = "api";
const NONCE: [u8; 16] = [0x17; 16];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Real,
    EarlyExit,
}

/// The self-test mutant: a variable-time compare that returns at the first differing byte. `black_box` on each
/// byte keeps the compiler from turning it into a (possibly wide, chunked) memcmp.
fn early_exit_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (x, y) in a.iter().zip(b) {
        if black_box(*x) != black_box(*y) {
            return false;
        }
    }
    true
}

struct Fixture {
    keys: KeyRing,
    token: TokenL,
    req: Req,
}

fn fixture() -> Option<Fixture> {
    let caveats = vec![
        Caveat::Aud(AUD.into()),
        Caveat::Exp(1_800_000_600),
        Caveat::Depth(4),
        Caveat::Res(vec!["t1".into(), "docs".into()]),
        Caveat::Tenant(7),
    ];
    let tag = chain_tag(&MASTER, AUD, KID, &NONCE, &caveats).ok()?;
    let token = TokenL { kid: KID.to_vec(), nonce: NONCE, caveats, tag };
    let mut keys = KeyRing::new();
    keys.insert(KID, MASTER).ok()?;
    let req = Req {
        aud: AUD.into(),
        ops: 1,
        res: vec!["t1".into(), "docs".into(), "a".into()],
        tenant: 7,
        holder: Vec::new(),
        tool: String::new(),
        args: Vec::new(),
        now: 1_800_000_000,
    };
    // Sanity: the genuine token verifies, so a forged-tag rejection below is a MAC rejection.
    verify(&token.encode().ok()?, &keys, &req).ok()?;
    Some(Fixture { keys, token, req })
}

fn ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// Times one batch. `tags` holds n presented tags back to back; returns n durations in ns.
fn run_batch(f: &Fixture, mode: Mode, target: &str, tags: &[u8]) -> Option<Vec<u64>> {
    let want = f.token.tag;
    let mut out = Vec::with_capacity(tags.len() / TAG_LEN);
    match target {
        "cmp" => {
            for tag in tags.as_chunks::<TAG_LEN>().0 {
                let s = Instant::now();
                let ok = match mode {
                    Mode::Real => {
                        aws_lc_rs::constant_time::verify_slices_are_equal(black_box(&want), black_box(tag)).is_ok()
                    }
                    Mode::EarlyExit => early_exit_eq(black_box(&want), black_box(tag)),
                };
                black_box(ok);
                out.push(ns(s));
            }
        }
        "mac" => {
            let mut t = f.token.clone();
            for tag in tags.as_chunks::<TAG_LEN>().0 {
                t.tag = *tag;
                let s = Instant::now();
                let ok = match mode {
                    Mode::Real => mac_valid(&f.keys, black_box(&t), AUD),
                    Mode::EarlyExit => chain_tag(&MASTER, AUD, &t.kid, &t.nonce, &t.caveats)
                        .is_ok_and(|w| early_exit_eq(&w, black_box(&t.tag))),
                };
                black_box(ok);
                out.push(ns(s));
            }
        }
        "verify" => {
            // Encode every wire token before timing; only the verify call is inside the measurement.
            let mut t = f.token.clone();
            let mut wires = Vec::with_capacity(tags.len() / TAG_LEN);
            for tag in tags.as_chunks::<TAG_LEN>().0 {
                t.tag = *tag;
                wires.push(t.encode().ok()?);
            }
            for w in &wires {
                let s = Instant::now();
                let ok = match mode {
                    Mode::Real => verify(black_box(w), &f.keys, &f.req).is_ok(),
                    Mode::EarlyExit => TokenL::decode(black_box(w)).is_ok_and(|d| {
                        chain_tag(&MASTER, AUD, &d.kid, &d.nonce, &d.caveats).is_ok_and(|x| early_exit_eq(&x, &d.tag))
                            && denote(&d.caveats, &f.req)
                    }),
                };
                black_box(ok);
                out.push(ns(s));
            }
        }
        _ => return None,
    }
    Some(out)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn serve(mode: Mode) -> Option<()> {
    let f = fixture()?;
    let mut input = BufReader::with_capacity(1 << 20, std::io::stdin().lock());
    let mut out = BufWriter::with_capacity(1 << 20, std::io::stdout().lock());
    writeln!(out, "CT-SUBJECT 1 tag={}", hex(&f.token.tag)).ok()?;
    out.flush().ok()?;
    let mut line = String::new();
    loop {
        line.clear();
        if input.read_line(&mut line).ok()? == 0 {
            return Some(());
        }
        let mut it = line.split_whitespace();
        let target = match it.next() {
            None | Some("quit") => return Some(()),
            Some(t) => t.to_owned(),
        };
        let n: usize = it.next()?.parse().ok()?;
        if n == 0 || n > MAX_BATCH || it.next().is_some() {
            return None;
        }
        let mut tags = vec![0u8; n.checked_mul(TAG_LEN)?];
        input.read_exact(&mut tags).ok()?;
        let times = run_batch(&f, mode, &target, &tags)?;
        let mut buf = Vec::with_capacity(times.len() * 8);
        for t in times {
            buf.extend_from_slice(&t.to_le_bytes());
        }
        out.write_all(&buf).ok()?;
        out.flush().ok()?;
    }
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        [] => Mode::Real,
        ["--mutant", "early-exit"] => Mode::EarlyExit,
        _ => {
            eprintln!("usage: ct-subject [--mutant early-exit]");
            return std::process::ExitCode::from(2);
        }
    };
    match serve(mode) {
        Some(()) => std::process::ExitCode::SUCCESS,
        None => {
            eprintln!("ct-subject: protocol or fixture error");
            std::process::ExitCode::from(1)
        }
    }
}
