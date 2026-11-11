//! F5: capability token decode + verify (monban-token: Tier L det-CBOR HMAC chain, Tier X COSE ML-DSA-65, Tier 0
//! handles).
//!
//! Properties (raw bytes):
//! - every decoder (`TokenL`, `XPayload`, `Caveat`, COSE envelope) accepts only canonical bytes:
//!   `decode(b) = Ok(x)` implies `encode(x) = b`;
//! - no forgery: a decodable Tier-L token from the fuzzer is refused with `BadTag` (the MAC is checked first and the
//!   fuzzer does not hold the key); `verify_x` never accepts (the fuzzer holds no ML-DSA key); a Tier-0 lookup of
//!   any handle other than the registered one is refused.
//! Properties (structured: the input drives mint + attenuate under a known key):
//! - a minted / attenuated token is MAC-valid, round-trips, and `verify` never answers `Malformed`/`BadTag`/
//!   `BadShape` for it;
//! - any single-byte mutation of its encoding is never accepted (decode fails or verify answers `BadTag`).
#![no_main]

use std::sync::OnceLock;

use monban_fuzz::{ALNUM, LOWER, Unstructured, byte, bytes, flag, selftest, string_from, u64_};
use monban_token::tier_x::{decode_envelope, envelope};
use monban_token::{
    ArgPred, ArgVal, Caveat, KeyRing, MintParams, Req, Tier0Table, TokenL, VerifyError, XKeyRing, XPayload, attenuate,
    mac_valid, mint, verify, verify_x,
};
use monban_types::TenantId;
use libfuzzer_sys::fuzz_target;

const KID: &[u8] = b"k1";
const MASTER: [u8; 32] = [7u8; 32];
/// The raw-bytes path verifies under a key that minted nothing: the seeds (minted under `MASTER` by
/// `examples/seeds.rs`) and anything derived from them must then fail the MAC, so "never accepted" is a real
/// no-forgery property there. The structured path mints and verifies under `MASTER`.
const MASTER_RAW: [u8; 32] = [8u8; 32];

struct Fixture {
    keys: KeyRing,
    raw_keys: KeyRing,
    xkeys: XKeyRing,
    tier0: Tier0Table,
    handle: [u8; 32],
}

fn fixture() -> Option<&'static Fixture> {
    static F: OnceLock<Option<Fixture>> = OnceLock::new();
    F.get_or_init(|| {
        let mut keys = KeyRing::new();
        keys.insert(KID, MASTER).ok()?;
        let mut raw_keys = KeyRing::new();
        raw_keys.insert(KID, MASTER_RAW).ok()?;
        let mut xkeys = XKeyRing::new();
        // A fixed byte pattern of the right length: no signature can verify under it except by forgery.
        let pk: Vec<u8> = (0..monban_token::tier_x::MLDSA65_PK_LEN).map(|i| (i % 251) as u8).collect();
        xkeys.insert(b"kx", &pk).ok()?;
        let mut tier0 = Tier0Table::new();
        let h = tier0.insert(TenantId::new(1).ok()?, b"subject", vec![Caveat::Tenant(1)]).ok()?;
        Some(Fixture { keys, raw_keys, xkeys, tier0, handle: *h.as_bytes() })
    })
    .as_ref()
}

fn arg_val(u: &mut Unstructured<'_>) -> ArgVal {
    if flag(u) { ArgVal::Int(u64_(u) as i64 % 1000) } else { ArgVal::Str(string_from(u, 6, LOWER)) }
}

fn caveat(u: &mut Unstructured<'_>) -> Caveat {
    match byte(u) % 9 {
        0 => Caveat::Aud(string_from(u, 8, LOWER)),
        1 => Caveat::Exp(u64_(u) % 2000),
        2 => Caveat::Nbf(u64_(u) % 2000),
        3 => Caveat::Ops(byte(u) % 40),
        4 => Caveat::Res((0..byte(u) % 4).map(|_| string_from(u, 4, LOWER)).collect()),
        5 => {
            let mut c = [0u8; 32];
            c[0] = byte(u);
            Caveat::Cnf(c)
        }
        6 => Caveat::Tenant(u64_(u) % 4),
        7 => {
            let n = byte(u) % 3;
            let cons = (0..n)
                .map(|_| {
                    let k = string_from(u, 4, LOWER);
                    let p = match byte(u) % 4 {
                        0 => ArgPred::Eq(arg_val(u)),
                        1 => ArgPred::OneOf((0..byte(u) % 3).map(|_| arg_val(u)).collect()),
                        2 => ArgPred::Range(u64_(u) as i64 % 100, u64_(u) as i64 % 100),
                        _ => ArgPred::StrPrefix(string_from(u, 3, LOWER)),
                    };
                    (k, p)
                })
                .collect();
            Caveat::Tool(string_from(u, 6, LOWER), cons)
        }
        _ => Caveat::Depth(byte(u) % 20),
    }
}

fn req(u: &mut Unstructured<'_>, aud: &str) -> Req {
    Req {
        aud: aud.to_string(),
        ops: u64::from(byte(u) % 32),
        res: (0..byte(u) % 4).map(|_| string_from(u, 4, LOWER)).collect(),
        tenant: u64_(u) % 4,
        holder: bytes(u, 2).to_vec(),
        tool: string_from(u, 6, LOWER),
        args: (0..byte(u) % 3).map(|_| (string_from(u, 4, LOWER), arg_val(u))).collect(),
        now: u64_(u) % 2000,
    }
}

fn raw(fx: &Fixture, data: &[u8]) {
    let mut u = Unstructured::new(data);
    if let Ok(t) = TokenL::decode(data) {
        assert_eq!(t.encode().ok().as_deref(), Some(data), "TokenL decode accepted a non-canonical encoding");
        let aud = t.caveats.iter().find_map(|c| if let Caveat::Aud(a) = c { Some(a.clone()) } else { None });
        let r = req(&mut u, aud.as_deref().unwrap_or("api"));
        assert!(!mac_valid(&fx.raw_keys, &t, &r.aud), "forged Tier-L MAC accepted");
        assert_eq!(verify(data, &fx.raw_keys, &r), Err(VerifyError::BadTag), "fuzzer token not refused as BadTag");
    } else {
        let r = req(&mut u, "api");
        assert_eq!(verify(data, &fx.raw_keys, &r), Err(VerifyError::Malformed), "undecodable token not Malformed");
    }
    if let Ok(p) = XPayload::decode(data) {
        assert_eq!(p.encode().ok().as_deref(), Some(data), "XPayload decode accepted a non-canonical encoding");
    }
    if let Ok(c) = Caveat::decode(data) {
        assert_eq!(c.encode(), data, "Caveat decode accepted a non-canonical encoding");
        assert!(c.is_well_formed(), "Caveat decode accepted an ill-formed caveat");
    }
    if let Ok((p, s)) = decode_envelope(data) {
        assert_eq!(envelope(p, s), data, "COSE envelope decode accepted a non-canonical encoding");
    }
    let r = req(&mut Unstructured::new(data), "api");
    assert!(verify_x(data, &fx.xkeys, &r).is_err(), "Tier-X accepted without a signing key");
    if data != fx.handle {
        assert!(fx.tier0.lookup(data, &r).is_err(), "Tier-0 accepted an unregistered handle");
    }
}

fn structured(fx: &Fixture, data: &[u8]) {
    let mut u = Unstructured::new(data);
    let aud = string_from(&mut u, 8, ALNUM);
    let aud = if aud.is_empty() { String::from("api") } else { aud };
    let mut nonce = [0u8; 16];
    for b in nonce.iter_mut() {
        *b = byte(&mut u);
    }
    let mint_time = u64_(&mut u) % 1000;
    let exp = mint_time + 1 + u64_(&mut u) % 900;
    let depth = byte(&mut u) % 17;
    let extra: Vec<Caveat> = (0..byte(&mut u) % 4).map(|_| caveat(&mut u)).collect();
    let Ok(mut t) = mint(&fx.keys, MintParams { kid: KID, aud: &aud, nonce, mint_time, exp, depth, extra }) else {
        return;
    };
    let mut ancestors: Vec<Vec<u8>> = Vec::new();
    for _ in 0..byte(&mut u) % 4 {
        match attenuate(&t, caveat(&mut u)) {
            Ok(next) => {
                if let Ok(e) = t.encode() {
                    ancestors.push(e);
                }
                t = next;
            }
            Err(_) => break,
        }
    }
    assert!(mac_valid(&fx.keys, &t, &aud), "minted/attenuated token is not MAC-valid");
    let Ok(enc) = t.encode() else { panic!("minted/attenuated token does not encode") };
    assert_eq!(TokenL::decode(&enc).as_ref(), Ok(&t), "minted token does not round-trip");
    let mut r = req(&mut u, &aud);
    r.now = mint_time;
    match verify(&enc, &fx.keys, &r) {
        Err(VerifyError::Malformed | VerifyError::BadTag | VerifyError::BadShape) => {
            panic!("genuine token refused as malformed/forged/misshapen")
        }
        Ok(_) => {
            selftest!(t.caveats.len() >= 5);
            // INV-ATTEN: attenuation only narrows, so every ancestor of an accepted token accepts the same request.
            for a in &ancestors {
                assert!(verify(a, &fx.keys, &r).is_ok(), "ancestor refuses a request its attenuation accepts");
            }
        }
        Err(_) => {}
    }

    let pos = usize::from(byte(&mut u)) | (usize::from(byte(&mut u)) << 8);
    let mask = byte(&mut u) | 1;
    let mut m = enc.clone();
    if let Some(b) = m.get_mut(pos % enc.len().max(1)) {
        *b ^= mask;
    }
    if let Ok(t2) = TokenL::decode(&m) {
        assert_ne!(t2, t, "distinct bytes decoded to the same token");
        assert_eq!(verify(&m, &fx.keys, &r), Err(VerifyError::BadTag), "mutated token not refused as BadTag");
    } else {
        assert_eq!(verify(&m, &fx.keys, &r), Err(VerifyError::Malformed));
    }
}

fuzz_target!(|data: &[u8]| {
    let Some(fx) = fixture() else { panic!("token fixture setup failed") };
    raw(fx, data);
    structured(fx, data);
});
