//! Unit vectors for D1–D4, mint shape, TTL, size caps, tamper cases, Tier X and Tier 0; a random-bytes and
//! mutation totality loop for every decoder (≥1e6 inputs each in release); a coarse timing report for the tag compare.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::*;
use crate::tier_l::MAX_TOKEN_BYTES;
use crate::tier_x::{decode_envelope, envelope, sig_structure};

const NOW: u64 = 1_800_000_000;
const KID: &[u8] = b"k1";
const MASTER: [u8; 32] = [7u8; 32];

fn ring() -> KeyRing {
    let mut k = KeyRing::new();
    k.insert(KID, MASTER).unwrap();
    k
}

fn req() -> Req {
    Req {
        aud: "api.example".into(),
        ops: 1,
        res: path_segments("/t1/docs/42").unwrap(),
        tenant: 9,
        holder: vec![],
        tool: "search".into(),
        args: vec![("q".into(), ArgVal::Str("hello".into())), ("n".into(), ArgVal::Int(5))],
        now: NOW,
    }
}

fn minted(depth: u8, extra: Vec<Caveat>) -> TokenL {
    mint(
        &ring(),
        MintParams {
            kid: KID,
            aud: "api.example",
            nonce: [3u8; 16],
            mint_time: NOW - 10,
            exp: NOW + 100,
            depth,
            extra,
        },
    )
    .unwrap()
}

fn ok(t: &TokenL, r: &Req) -> Result<monban_types::Principal, VerifyError> {
    verify(&t.encode().unwrap(), &ring(), r)
}

#[test]
fn happy_path_and_principal() {
    let t = minted(4, vec![Caveat::Tenant(9), Caveat::Ops(3)]);
    let p = ok(&t, &req()).unwrap();
    assert_eq!(p.tenant().get(), 9);
    match p.subject() {
        monban_types::Subject::Authenticated(s) => assert_eq!(&s[..], &[b"k1".as_slice(), &[3u8; 16]].concat()[..]),
        monban_types::Subject::Public => panic!("public"),
    }
}

#[test]
fn every_caveat_roundtrips_canonically() {
    let cs = vec![
        Caveat::Aud("a".into()),
        Caveat::Exp(u64::MAX),
        Caveat::Nbf(0),
        Caveat::Ops(31),
        Caveat::Res(vec!["t1".into(), "x".into()]),
        Caveat::Cnf([9u8; 32]),
        Caveat::Tenant(1 << 40),
        Caveat::Tool(
            "t".into(),
            vec![
                ("a".into(), ArgPred::Eq(ArgVal::Int(i64::MIN))),
                ("b".into(), ArgPred::OneOf(vec![ArgVal::Str("x".into()), ArgVal::Int(-24)])),
                ("c".into(), ArgPred::Range(-1, i64::MAX)),
                ("d".into(), ArgPred::StrPrefix(String::new())),
            ],
        ),
        Caveat::Depth(16),
    ];
    for c in cs {
        let b = c.encode();
        assert_eq!(Caveat::decode(&b).unwrap(), c);
    }
    // Non-shortest head: [1, 5] with 5 encoded as 0x18 0x05.
    assert!(Caveat::decode(&[0x82, 0x01, 0x18, 0x05]).is_err());
    assert!(Caveat::decode(&[0x82, 0x01, 0x05]).is_ok());
    // Trailing byte, out-of-range ops / depth / tenant 0, unknown kind.
    assert!(Caveat::decode(&[0x82, 0x01, 0x05, 0x00]).is_err());
    assert!(Caveat::decode(&[0x82, 0x03, 0x18, 0x20]).is_err());
    assert!(Caveat::decode(&[0x82, 0x08, 0x11]).is_err());
    assert!(Caveat::decode(&[0x82, 0x06, 0x00]).is_err());
    assert!(Caveat::decode(&[0x82, 0x09, 0x00]).is_err());
    // Indefinite-length array.
    assert!(Caveat::decode(&[0x9f, 0x01, 0x05, 0xff]).is_err());
}

#[test]
fn d1_segment_prefix() {
    let t = minted(2, vec![Caveat::Res(vec!["t1".into()])]);
    assert!(ok(&t, &req()).is_ok());
    let mut r = req();
    r.res = path_segments("/t10/docs").unwrap();
    assert_eq!(ok(&t, &r), Err(VerifyError::Denied));
    r.res = path_segments("/t1").unwrap();
    assert!(ok(&t, &r).is_ok());
    assert_eq!(path_segments("/a//b"), None);
    assert_eq!(path_segments("a"), None);
    assert_eq!(path_segments("/"), Some(vec![]));
}

#[test]
fn d2_ops_subset() {
    let t = minted(1, vec![Caveat::Ops(1 | 4)]);
    let mut r = req();
    r.ops = 5;
    assert!(ok(&t, &r).is_ok());
    r.ops = 2;
    assert_eq!(ok(&t, &r), Err(VerifyError::Denied));
}

#[test]
fn d3_depth_at_verify() {
    let t = minted(1, vec![]);
    let t1 = attenuate(&t, Caveat::Ops(31)).unwrap();
    assert!(ok(&t1, &req()).is_ok());
    let t2 = attenuate(&t1, Caveat::Ops(31)).unwrap();
    assert_eq!(ok(&t2, &req()), Err(VerifyError::DepthExceeded));
    // An appended depth caveat lowers the bound.
    let t = minted(5, vec![]);
    let t = attenuate(&t, Caveat::Depth(0)).unwrap();
    assert_eq!(ok(&t, &req()), Err(VerifyError::DepthExceeded));
}

#[test]
fn d4_missing_arg_denies() {
    let con = |k: &str| Caveat::Tool("search".into(), vec![(k.into(), ArgPred::Range(0, 10))]);
    assert!(ok(&minted(1, vec![con("n")]), &req()).is_ok());
    assert_eq!(ok(&minted(1, vec![con("missing")]), &req()), Err(VerifyError::Denied));
    // Type mismatch: range over a string arg.
    assert_eq!(ok(&minted(1, vec![con("q")]), &req()), Err(VerifyError::Denied));
}

#[test]
fn conjunction_not_leaf_only() {
    // Parent narrows to tenant 8; child appends a satisfied caveat. Leaf-only would allow.
    let t = minted(2, vec![Caveat::Tenant(8)]);
    let t = attenuate(&t, Caveat::Tenant(9)).unwrap();
    assert_eq!(ok(&t, &req()), Err(VerifyError::Denied));
}

#[test]
fn expiry_and_nbf_use_parameter_now() {
    let t = minted(1, vec![Caveat::Nbf(NOW)]);
    let mut r = req();
    assert!(ok(&t, &r).is_ok());
    r.now = NOW - 1;
    assert_eq!(ok(&t, &r), Err(VerifyError::Denied));
    r.now = NOW + 100;
    assert_eq!(ok(&t, &r), Err(VerifyError::Denied));
    assert_eq!(eff_exp(&t.caveats), Some(NOW + 100));
}

#[test]
fn mint_checks() {
    let p = |exp, depth, extra| MintParams {
        kid: KID,
        aud: "api.example",
        nonce: [0u8; 16],
        mint_time: NOW,
        exp,
        depth,
        extra,
    };
    assert_eq!(mint(&ring(), p(NOW + 901, 1, vec![])), Err(TokenError::Ttl));
    assert_eq!(mint(&ring(), p(NOW, 1, vec![])), Err(TokenError::Ttl));
    assert!(mint(&ring(), p(NOW + 900, 1, vec![])).is_ok());
    assert_eq!(mint(&ring(), p(NOW + 900, 17, vec![])), Err(TokenError::Invalid));
    assert_eq!(mint(&ring(), p(NOW + 900, 0, vec![Caveat::Ops(1)])), Err(TokenError::Invalid));
    let mut q = p(NOW + 10, 1, vec![]);
    q.kid = b"nope";
    assert_eq!(mint(&ring(), q), Err(TokenError::UnknownKey));
}

#[test]
fn mint_shape_enforced_at_verify() {
    // A key holder chains a token whose prefix is not [aud, exp, depth]; the MAC is fine, the shape is not.
    let cs = vec![Caveat::Exp(NOW + 10), Caveat::Aud("api.example".into()), Caveat::Depth(3)];
    let tag = chain_tag(&MASTER, "api.example", KID, &[1u8; 16], &cs).unwrap();
    let t = TokenL { kid: KID.to_vec(), nonce: [1u8; 16], caveats: cs, tag };
    assert_eq!(ok(&t, &req()), Err(VerifyError::BadShape));
}

#[test]
fn tamper_and_audience() {
    let t = minted(2, vec![Caveat::Tenant(9)]);
    let mut x = t.clone();
    x.tag[31] ^= 1;
    assert_eq!(ok(&x, &req()), Err(VerifyError::BadTag));
    let mut x = t.clone();
    x.caveats.pop();
    assert_eq!(ok(&x, &req()), Err(VerifyError::BadTag));
    let mut x = t.clone();
    x.nonce[0] ^= 1;
    assert_eq!(ok(&x, &req()), Err(VerifyError::BadTag));
    let mut x = t.clone();
    x.kid = b"k2".to_vec();
    assert_eq!(ok(&x, &req()), Err(VerifyError::BadTag));
    let mut r = req();
    r.aud = "other".into();
    assert_eq!(ok(&t, &r), Err(VerifyError::BadTag));
    let mut r = req();
    r.tenant = 0;
    let t0 = minted(1, vec![]);
    assert_eq!(ok(&t0, &r), Err(VerifyError::BadPrincipal));
}

#[test]
fn size_and_count_caps() {
    let mut t = minted(16, vec![]);
    let big = Caveat::Res(vec!["s".repeat(255); 4]);
    let mut hit = false;
    for _ in 0..20 {
        match attenuate(&t, big.clone()) {
            Ok(n) => t = n,
            Err(e) => {
                assert_eq!(e, TokenError::TooLarge);
                hit = true;
                break;
            }
        }
    }
    assert!(hit);
    assert!(t.encode().unwrap().len() <= MAX_TOKEN_BYTES);
    let mut t = minted(16, vec![]);
    for _ in 0..61 {
        t = attenuate(&t, Caveat::Ops(1)).unwrap();
    }
    assert_eq!(t.caveats.len(), 64);
    assert_eq!(attenuate(&t, Caveat::Ops(1)), Err(TokenError::Invalid));
    assert!(TokenL::decode(&vec![0u8; MAX_TOKEN_BYTES + 1]).is_err());
}

#[cfg(not(feature = "cmvp"))]
#[test]
fn tier_x_roundtrip_and_tamper() {
    use aws_lc_rs::signature::{KeyPair as _, ML_DSA_65_SIGNING, PqdsaKeyPair};
    let kp = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &[5u8; 32]).unwrap();
    let mut keys = XKeyRing::new();
    keys.insert(KID, kp.public_key().as_ref()).unwrap();
    let payload = XPayload {
        kid: KID.to_vec(),
        nonce: [2u8; 16],
        caveats: vec![Caveat::Aud("api.example".into()), Caveat::Exp(NOW + 5), Caveat::Depth(0)],
    }
    .encode()
    .unwrap();
    let mut sig = vec![0u8; tier_x::MLDSA65_SIG_LEN];
    let n = kp.sign(&sig_structure(&payload), &mut sig).unwrap();
    assert_eq!(n, sig.len());
    let env = envelope(&payload, &sig);
    assert!(verify_x(&env, &keys, &req()).is_ok());
    let mut r = req();
    r.now = NOW + 5;
    assert_eq!(verify_x(&env, &keys, &r), Err(VerifyError::Denied));
    // Flip one payload byte (the nonce): signature fails.
    let mut bad = env.clone();
    let pos = bad.windows(16).position(|w| w == [2u8; 16]).unwrap();
    bad[pos] ^= 1;
    assert_eq!(verify_x(&bad, &keys, &req()), Err(VerifyError::BadTag));
    let mut bad = env.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert_eq!(verify_x(&bad, &keys, &req()), Err(VerifyError::BadTag));
    assert_eq!(verify_x(&env[1..], &keys, &req()), Err(VerifyError::Malformed));
    assert!(decode_envelope(&env).is_ok());
    assert_eq!(verify_x(&env, &XKeyRing::new(), &req()), Err(VerifyError::BadTag));
}

#[test]
fn tier0_table() {
    let mut tab = Tier0Table::new();
    let tenant = monban_types::TenantId::new(9).unwrap();
    let cs = vec![Caveat::Aud("api.example".into()), Caveat::Exp(NOW + 1)];
    let h = tab.insert(tenant, b"svc", cs).unwrap();
    assert!(tab.lookup(h.as_bytes(), &req()).is_ok());
    let mut wrong = *h.as_bytes();
    wrong[31] ^= 1;
    assert_eq!(tab.lookup(&wrong, &req()), Err(VerifyError::BadTag));
    assert!(!tab.revoke(&wrong));
    let mut r = req();
    r.tenant = 8;
    assert_eq!(tab.lookup(h.as_bytes(), &r), Err(VerifyError::Denied));
    assert_eq!(tab.lookup(&h.as_bytes()[..31], &req()), Err(VerifyError::BadTag));
    assert!(tab.revoke(h.as_bytes()));
    assert_eq!(tab.lookup(h.as_bytes(), &req()), Err(VerifyError::BadTag));
    assert!(tab.is_empty());
}

// ------------------------------------------------------------------------------------------ fuzz-style totality

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // splitmix64
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn iterations() -> usize {
    if cfg!(debug_assertions) { 20_000 } else { 1_000_000 }
}

/// Feeds `input` to every decoder; any accepted input must re-encode to exactly the same bytes (canonicality).
fn check_all(input: &[u8], accepted: &mut [usize; 4]) {
    if let Ok(t) = TokenL::decode(input) {
        assert_eq!(t.encode().unwrap(), input);
        accepted[0] += 1;
    }
    if let Ok(c) = Caveat::decode(input) {
        assert_eq!(c.encode(), input);
        accepted[1] += 1;
    }
    if let Ok(p) = XPayload::decode(input) {
        assert_eq!(p.encode().unwrap(), input);
        accepted[2] += 1;
    }
    if let Ok((p, s)) = decode_envelope(input) {
        assert_eq!(envelope(p, s), input);
        accepted[3] += 1;
    }
}

#[test]
fn decoders_total_on_random_bytes() {
    let mut rng = Rng(0xA5A5_0001);
    let mut acc = [0usize; 4];
    let mut buf = Vec::new();
    for _ in 0..iterations() {
        buf.clear();
        let n = rng.below(64);
        // Bias the first byte toward array heads so decoding gets past byte one.
        for i in 0..n {
            let b = rng.next() as u8;
            buf.push(if i == 0 && b & 1 == 0 { 0x80 | (b >> 4 & 0x07) } else { b });
        }
        check_all(&buf, &mut acc);
    }
    std::println!("random-bytes: {} inputs, accepted {acc:?}", iterations());
}

#[test]
fn decoders_total_on_mutated_tokens() {
    let mut rng = Rng(0xA5A5_0002);
    let t = minted(
        8,
        vec![
            Caveat::Tool(
                "search".into(),
                vec![("n".into(), ArgPred::Range(-5, 70_000)), ("q".into(), ArgPred::OneOf(vec![ArgVal::Int(1)]))],
            ),
            Caveat::Res(vec!["t1".into()]),
            Caveat::Cnf([1u8; 32]),
        ],
    );
    let seed = t.encode().unwrap();
    let xp = XPayload { kid: t.kid.clone(), nonce: t.nonce, caveats: t.caveats.clone() }.encode().unwrap();
    let env = envelope(&xp, &[0u8; tier_x::MLDSA65_SIG_LEN]);
    let seeds = [seed, xp, env, Caveat::Tenant(300).encode()];
    let mut acc = [0usize; 4];
    let mut buf = Vec::new();
    let keys = ring();
    let mut r2 = req();
    r2.holder = vec![1u8; 32];
    r2.args = vec![("n".into(), ArgVal::Int(5)), ("q".into(), ArgVal::Int(1))];
    assert!(verify(&seeds[0], &keys, &r2).is_ok());
    let mut verified = 0usize;
    for _ in 0..iterations() {
        buf.clear();
        buf.extend_from_slice(&seeds[rng.below(seeds.len())]);
        for _ in 0..1 + rng.below(4) {
            match rng.below(4) {
                0 if !buf.is_empty() => {
                    let i = rng.below(buf.len());
                    buf[i] ^= 1 << rng.below(8);
                }
                1 if !buf.is_empty() => {
                    let i = rng.below(buf.len());
                    buf[i] = rng.next() as u8;
                }
                2 if !buf.is_empty() => buf.truncate(rng.below(buf.len())),
                _ => {
                    let i = rng.below(buf.len() + 1);
                    buf.insert(i, rng.next() as u8);
                }
            }
        }
        check_all(&buf, &mut acc);
        if buf != seeds[0] && verify(&buf, &keys, &r2).is_ok() {
            verified += 1;
        }
    }
    // A mutated token must never verify (it would mean a MAC forgery or a non-canonical alias).
    assert_eq!(verified, 0);
    std::println!("mutation: {} inputs, accepted {acc:?}", iterations());
}

// ------------------------------------------------------------------------------------------ timing report

/// Coarse timing report for the constant-time tag compare (AWS-LC CRYPTO_memcmp): median ns of comparing equal
/// tags vs tags differing in the first or the last byte. Report only; the bound asserted is deliberately loose
/// (dudect-quality measurement is a follow-up).
#[test]
fn tag_compare_timing_report() {
    use aws_lc_rs::constant_time::verify_slices_are_equal;
    use std::time::Instant;
    let a = [0x5au8; 32];
    let mut first = a;
    first[0] ^= 0xff;
    let mut last = a;
    last[31] ^= 0xff;
    let reps = if cfg!(debug_assertions) { 2_000 } else { 20_000 };
    let batch = 64;
    let mut med = [0f64; 3];
    for (slot, other) in [a, first, last].iter().enumerate() {
        let mut v = Vec::with_capacity(reps);
        for _ in 0..reps {
            let s = Instant::now();
            for _ in 0..batch {
                let _ = std::hint::black_box(verify_slices_are_equal(std::hint::black_box(&a), other));
            }
            v.push(s.elapsed().as_nanos() as f64 / batch as f64);
        }
        v.sort_by(f64::total_cmp);
        med[slot] = v[reps / 2];
    }
    std::println!(
        "tag-compare median ns: equal {:.2}, first-byte-diff {:.2}, last-byte-diff {:.2}",
        med[0],
        med[1],
        med[2]
    );
    let (lo, hi) = (med.iter().cloned().fold(f64::MAX, f64::min), med.iter().cloned().fold(0.0, f64::max));
    assert!(hi <= lo * 3.0 + 5.0, "tag compare timing spread too large: {med:?}");
}

/// cmvp build (PLAN-6 D15): a Tier-X token with a valid ML-DSA-65 signature, a known key and satisfied caveats is
/// still denied (fail closed: the build has no ML-DSA-65 verifier). Signed here with the floor lock's aws-lc-rs.
#[cfg(feature = "cmvp")]
#[test]
fn tier_x_denied_on_cmvp() {
    use aws_lc_rs::signature::{KeyPair as _, ML_DSA_65_SIGNING, PqdsaKeyPair};
    let kp = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &[5u8; 32]).unwrap();
    let mut keys = XKeyRing::new();
    keys.insert(KID, kp.public_key().as_ref()).unwrap();
    let payload = XPayload {
        kid: KID.to_vec(),
        nonce: [2u8; 16],
        caveats: vec![Caveat::Aud("api.example".into()), Caveat::Exp(NOW + 5), Caveat::Depth(0)],
    }
    .encode()
    .unwrap();
    let mut sig = vec![0u8; tier_x::MLDSA65_SIG_LEN];
    kp.sign(&sig_structure(&payload), &mut sig).unwrap();
    let env = envelope(&payload, &sig);
    assert!(decode_envelope(&env).is_ok());
    assert_eq!(verify_x(&env, &keys, &req()), Err(VerifyError::Denied));
    assert_eq!(verify_x(&env, &XKeyRing::new(), &req()), Err(VerifyError::Denied));
}
