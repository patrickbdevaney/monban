//! KATs and negative tests for the libcrux provider (gate.sh step "kat").
//!
//!   lcx-kat <kat dir>
//!
//! Every vector goes through the provider's own wrappers (lcx::aead::{seal,open}, lcx::kx::*, lcx::hash::*,
//! lcx::sign::*) or its rustls trait objects, i.e. the code the TLS server runs. Last line:
//!   LCX-KAT: PASS (<n> checks) | LCX-KAT: FAIL (<failed>/<n>: <first failures>)
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::process::ExitCode;

use lcx::aead::{self, Alg};
use lcx::hash::{self, HKDF_SHA256};
use lcx::kx;
use rustls::crypto::cipher::{InboundOpaqueMessage, OutboundChunks, OutboundPlainMessage, Tls13AeadAlgorithm};
use rustls::crypto::hash::Hash as _;
use rustls::crypto::hmac::Hmac as _;
use rustls::crypto::tls13::{Hkdf as _, HkdfExpander as _};
use rustls::{ContentType, ProtocolVersion};
use zeroize::Zeroizing;

type Rec = BTreeMap<String, Vec<u8>>;
type Step = fn(&mut T, &str) -> Result<(), String>;

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| s.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect()
}

fn load(dir: &str, file: &str) -> Result<Vec<(String, Rec)>, String> {
    let text = std::fs::read_to_string(format!("{dir}/{file}")).map_err(|e| format!("{file}: {e}"))?;
    let mut out = Vec::new();
    for ln in text.lines() {
        if ln.starts_with('#') || ln.trim().is_empty() {
            continue;
        }
        let mut it = ln.split_whitespace();
        let kind = it.next().unwrap_or_default().to_string();
        let mut rec = Rec::new();
        for kv in it {
            let (k, v) = kv.split_once('=').ok_or_else(|| format!("{file}: bad field {kv}"))?;
            rec.insert(k.to_string(), unhex(v).ok_or_else(|| format!("{file}: bad hex in {k}"))?);
        }
        out.push((kind, rec));
    }
    if out.is_empty() {
        return Err(format!("{file}: no vectors"));
    }
    Ok(out)
}

struct T {
    n: usize,
    failed: Vec<String>,
}

impl T {
    fn check(&mut self, name: &str, ok: bool) {
        self.n += 1;
        if !ok {
            self.failed.push(name.to_string());
            println!("  FAIL {name}");
        }
    }
}

fn f<'a>(r: &'a Rec, k: &str) -> &'a [u8] {
    r.get(k).map(Vec::as_slice).unwrap_or(&[])
}

fn a32(b: &[u8]) -> [u8; 32] {
    b.try_into().unwrap_or([0u8; 32])
}

fn a12(b: &[u8]) -> [u8; 12] {
    b.try_into().unwrap_or([0u8; 12])
}

fn flip_last(v: &[u8]) -> Vec<u8> {
    let mut w = v.to_vec();
    if let Some(b) = w.last_mut() {
        *b ^= 0x01;
    }
    w
}

fn flip_first(v: &[u8]) -> Vec<u8> {
    let mut w = v.to_vec();
    if let Some(b) = w.first_mut() {
        *b ^= 0x80;
    }
    w
}

fn x25519_kat(t: &mut T, dir: &str) -> Result<(), String> {
    for (i, (kind, r)) in load(dir, "rfc7748.txt")?.iter().enumerate() {
        match kind.as_str() {
            "x25519" => {
                let out = kx::x25519(&a32(f(r, "scalar")), f(r, "u")).map(|s| s.to_vec());
                t.check(&format!("rfc7748-5.2-{i}"), out.as_deref() == Ok(f(r, "out")));
            }
            "x25519iter" => {
                let n = f(r, "n").iter().fold(0u32, |a, b| (a << 8) | u32::from(*b));
                let mut k = [0u8; 32];
                k[0] = 9;
                let mut u = k;
                let mut ok = true;
                for _ in 0..n {
                    match kx::x25519(&k, &u) {
                        Ok(r) => {
                            u = k;
                            k = *r;
                        }
                        Err(_) => ok = false,
                    }
                }
                t.check(&format!("rfc7748-iter-{n}"), ok && k.as_slice() == f(r, "out"));
            }
            "x25519dh" => {
                let (a, b) = (a32(f(r, "a")), a32(f(r, "b")));
                t.check("rfc7748-6.1-apub", kx::x25519_public(&a).as_slice() == f(r, "apub"));
                t.check("rfc7748-6.1-bpub", kx::x25519_public(&b).as_slice() == f(r, "bpub"));
                let k1 = kx::x25519(&a, f(r, "bpub")).map(|s| s.to_vec());
                let k2 = kx::x25519(&b, f(r, "apub")).map(|s| s.to_vec());
                t.check("rfc7748-6.1-k-alice", k1.as_deref() == Ok(f(r, "k")));
                t.check("rfc7748-6.1-k-bob", k2.as_deref() == Ok(f(r, "k")));
                // Low-order input (u = 0) must give the all-zero output, which must be refused.
                t.check("x25519-reject-zero-output", kx::x25519(&a, &[0u8; 32]).is_err());
                t.check("x25519-reject-short", kx::x25519(&a, &[9u8; 31]).is_err());
            }
            _ => return Err(format!("rfc7748.txt: unknown kind {kind}")),
        }
    }
    Ok(())
}

fn aead_vec(t: &mut T, name: &str, alg: Alg, r: &Rec, expect_fail: bool) {
    let (key, nonce, aad) = (f(r, "key"), a12(if f(r, "iv").is_empty() { f(r, "nonce") } else { f(r, "iv") }), f(r, "aad"));
    let mut ct_tag = f(r, "ct").to_vec();
    ct_tag.extend_from_slice(f(r, "tag"));
    if expect_fail {
        t.check(&format!("{name}-reject"), aead::open(alg, key, &nonce, aad, &ct_tag).is_err());
        return;
    }
    if !f(r, "pt").is_empty() || r.contains_key("pt") {
        let sealed = aead::seal(alg, key, &nonce, aad, f(r, "pt"));
        t.check(&format!("{name}-seal"), sealed.as_deref() == Ok(ct_tag.as_slice()));
    }
    let opened = aead::open(alg, key, &nonce, aad, &ct_tag);
    t.check(&format!("{name}-open"), opened.as_deref() == Ok(f(r, "pt")));
    t.check(&format!("{name}-reject-tag"), aead::open(alg, key, &nonce, aad, &flip_last(&ct_tag)).is_err());
    if !f(r, "ct").is_empty() {
        t.check(&format!("{name}-reject-ct"), aead::open(alg, key, &nonce, aad, &flip_first(&ct_tag)).is_err());
    }
    let mut bad_aad = aad.to_vec();
    bad_aad.push(0);
    t.check(&format!("{name}-reject-aad"), aead::open(alg, key, &nonce, &bad_aad, &ct_tag).is_err());
}

fn gcm_kat(t: &mut T, dir: &str) -> Result<(), String> {
    for (i, (kind, r)) in load(dir, "nist-gcm.txt")?.iter().enumerate() {
        let alg = match f(r, "key").len() {
            16 => Alg::Aes128Gcm,
            32 => Alg::Aes256Gcm,
            n => return Err(format!("nist-gcm.txt: key length {n}")),
        };
        let fail = f(r, "fail") == [1];
        aead_vec(t, &format!("gcm-{kind}-{i}"), alg, r, fail);
    }
    Ok(())
}

fn chacha_kat(t: &mut T, dir: &str) -> Result<(), String> {
    for (i, (_, r)) in load(dir, "rfc8439.txt")?.iter().enumerate() {
        aead_vec(t, &format!("rfc8439-{i}"), Alg::ChaCha20Poly1305, r, false);
    }
    Ok(())
}

fn hkdf_kat(t: &mut T, dir: &str) -> Result<(), String> {
    for (i, (_, r)) in load(dir, "rfc5869.txt")?.iter().enumerate() {
        let len = f(r, "len").iter().fold(0usize, |a, b| (a << 8) | usize::from(*b));
        let ex = HKDF_SHA256.extract(Some(f(r, "salt")), f(r, "ikm"));
        t.check(&format!("rfc5869-{i}-prk"), ex.prk() == f(r, "prk"));
        let mut okm = vec![0u8; len];
        let ok = ex.expand_slice(&[f(r, "info")], &mut okm).is_ok();
        t.check(&format!("rfc5869-{i}-okm"), ok && okm == f(r, "okm"));
        // Same through the rustls trait object, with `info` split in two pieces.
        let info = f(r, "info");
        let (i1, i2) = info.split_at(info.len() / 2);
        let mut okm2 = vec![0u8; len];
        let ok2 = HKDF_SHA256.extract_from_secret(Some(f(r, "salt")), f(r, "ikm")).expand_slice(&[i1, i2], &mut okm2).is_ok();
        t.check(&format!("rfc5869-{i}-okm-trait"), ok2 && okm2 == f(r, "okm"));
    }
    Ok(())
}

fn hmac_kat(t: &mut T, dir: &str) -> Result<(), String> {
    for (i, (_, r)) in load(dir, "rfc4231.txt")?.iter().enumerate() {
        let (key, data) = (f(r, "key"), f(r, "data"));
        let t256 = hash::HMAC_SHA256.with_key(key).sign(&[data]);
        let t384 = hash::HMAC_SHA384.with_key(key).sign(&[data]);
        t.check(&format!("rfc4231-{i}-sha256"), t256.as_ref() == f(r, "sha256"));
        t.check(&format!("rfc4231-{i}-sha384"), t384.as_ref() == f(r, "sha384"));
        let (d1, d2) = data.split_at(data.len() / 3);
        let (d2, d3) = d2.split_at(d2.len() / 2);
        let tc = hash::HMAC_SHA384.with_key(key).sign_concat(d1, &[d2], d3);
        t.check(&format!("rfc4231-{i}-sha384-concat"), tc.as_ref() == f(r, "sha384"));
    }
    Ok(())
}

fn sha_kat(t: &mut T) {
    // FIPS 180-4 / NIST CSRC example values for "abc".
    let s256 = unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap_or_default();
    let s384 = unhex(
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    )
    .unwrap_or_default();
    t.check("sha256-abc", hash::SHA256.hash(b"abc").as_ref() == s256);
    t.check("sha384-abc", hash::SHA384.hash(b"abc").as_ref() == s384);
    let mut c = hash::SHA384.start();
    c.update(b"a");
    let fork = c.fork();
    c.update(b"bc");
    t.check("sha384-incremental", c.fork_finish().as_ref() == s384);
    let mut fork = fork;
    fork.update(b"bc");
    t.check("sha384-fork", fork.finish().as_ref() == s384);
}

fn ed25519_kat(t: &mut T, dir: &str) -> Result<(), String> {
    for (i, (_, r)) in load(dir, "rfc8032.txt")?.iter().enumerate() {
        let k = lcx::sign::Ed25519Key::new(Zeroizing::new(a32(f(r, "sk"))));
        t.check(&format!("rfc8032-{i}-pk"), k.public().as_slice() == f(r, "pk"));
        let sig = k.sign_raw(f(r, "msg"));
        t.check(&format!("rfc8032-{i}-sig"), sig.as_ref().map(|s| s.as_slice()) == Ok(f(r, "sig")));
    }
    Ok(())
}

fn p256_kat(t: &mut T, dir: &str) -> Result<(), String> {
    for (_, r) in load(dir, "rfc5903.txt")? {
        let pt = |x: &str, y: &str| [&[4u8][..], f(&r, x), f(&r, y)].concat();
        let (gi, gr) = (pt("gix", "giy"), pt("grx", "gry"));
        let (i, rr) = (a32(f(&r, "i")), a32(f(&r, "r")));
        t.check("rfc5903-8.1-gi", kx::p256_public(&i).map(|p| p.to_vec()).as_deref() == Ok(gi.as_slice()));
        t.check("rfc5903-8.1-gr", kx::p256_public(&rr).map(|p| p.to_vec()).as_deref() == Ok(gr.as_slice()));
        t.check("rfc5903-8.1-girx-i", kx::p256(&i, &gr).map(|s| s.to_vec()).as_deref() == Ok(f(&r, "girx")));
        t.check("rfc5903-8.1-girx-r", kx::p256(&rr, &gi).map(|s| s.to_vec()).as_deref() == Ok(f(&r, "girx")));
        t.check("p256-reject-offcurve", kx::p256(&i, &flip_last(&gr)).is_err());
        let mut compressed = gr.clone();
        if let Some(b) = compressed.first_mut() {
            *b = 2;
        }
        t.check("p256-reject-prefix", kx::p256(&i, &compressed).is_err());
        t.check("p256-reject-short", kx::p256(&i, gr.get(..64).unwrap_or(&[])).is_err());
        // ECDSA-P256-SHA256 sign (random nonce) then verify with libcrux-ecdsa.
        let key = lcx::sign::EcdsaP256Key::new(Zeroizing::new(i));
        let msg = b"lcx ecdsa self-check";
        let ok = key.as_ref().ok().and_then(|k| k.sign_sha256(msg).ok()).is_some_and(|der| {
            let sig = libcrux_ecdsa::p256::Signature::from_der(&der);
            let pk = libcrux_ecdsa::p256::PublicKey::try_from(gi.get(1..).unwrap_or(&[]));
            match (sig, pk) {
                (Ok(s), Ok(p)) => {
                    libcrux_ecdsa::p256::verify(libcrux_ecdsa::DigestAlgorithm::Sha256, msg, &s, &p).is_ok()
                        && libcrux_ecdsa::p256::verify(libcrux_ecdsa::DigestAlgorithm::Sha256, b"other", &s, &p)
                            .is_err()
                }
                _ => false,
            }
        });
        t.check("ecdsa-p256-sign-verify", ok);
    }
    Ok(())
}

fn mlkem_kat(t: &mut T, dir: &str) -> Result<(), String> {
    for (kind, r) in load(dir, "acvp-mlkem768.txt")? {
        let tc = f(&r, "tc").iter().fold(0u32, |a, b| (a << 8) | u32::from(*b));
        match kind.as_str() {
            "keygen" => {
                let seed: [u8; 64] = [f(&r, "d"), f(&r, "z")].concat().try_into().unwrap_or([0u8; 64]);
                let (ek, dk) = kx::mlkem768_keygen(seed);
                t.check(&format!("acvp-keygen-{tc}"), ek == f(&r, "ek") && dk.as_slice() == f(&r, "dk"));
            }
            "encap" => {
                let res = kx::mlkem768_encaps(f(&r, "ek"), a32(f(&r, "m")));
                let ok = res.is_ok_and(|(c, k)| c == f(&r, "c") && k.as_slice() == f(&r, "k"));
                t.check(&format!("acvp-encap-{tc}"), ok);
            }
            "decap" => {
                let res = kx::mlkem768_decaps(f(&r, "dk"), f(&r, "c"));
                t.check(&format!("acvp-decap-{tc}"), res.is_ok_and(|k| k.as_slice() == f(&r, "k")));
            }
            "ekcheck" => {
                let pass = f(&r, "pass") == [1];
                let res = kx::mlkem768_encaps(f(&r, "ek"), [0u8; 32]);
                t.check(&format!("acvp-ekcheck-{tc}"), res.is_ok() == pass);
            }
            _ => return Err(format!("acvp-mlkem768.txt: unknown kind {kind}")),
        }
    }
    Ok(())
}

/// Client start() -> server start_and_complete() -> client complete(): equal secrets, right lengths; plus
/// malformed client shares refused by the server half.
fn group_roundtrips(t: &mut T) {
    for (g, cli_len, srv_len, ss_len) in [
        (kx::X25519MLKEM768, 1216usize, 1120usize, 64usize),
        (kx::X25519, 32, 32, 32),
        (kx::SECP256R1, 65, 65, 32),
    ] {
        let name = format!("{:?}", g.name());
        let res = g.start().and_then(|c| {
            let share = c.pub_key().to_vec();
            let srv = g.start_and_complete(&share)?;
            let cs = c.complete(&srv.pub_key)?;
            Ok((share.len(), srv.pub_key.len(), srv.secret.secret_bytes().to_vec(), cs.secret_bytes().to_vec()))
        });
        let ok = res.is_ok_and(|(cl, sl, s1, s2)| cl == cli_len && sl == srv_len && s1.len() == ss_len && s1 == s2);
        t.check(&format!("roundtrip-{name}"), ok);
        let short = vec![4u8; cli_len - 1];
        t.check(&format!("reject-short-share-{name}"), g.start_and_complete(&short).is_err());
    }
    // FIPS 203 7.2 modulus check through the TLS server path: first ek coefficient = 0xFFF >= q.
    if let Ok(c) = kx::X25519MLKEM768.start() {
        let mut share = c.pub_key().to_vec();
        if let Some(b0) = share.first_mut() {
            *b0 = 0xff;
        }
        if let Some(b1) = share.get_mut(1) {
            *b1 |= 0x0f;
        }
        t.check("reject-mlkem-ek-coeff-ge-q", kx::X25519MLKEM768.start_and_complete(&share).is_err());
    }
}

/// TLS 1.3 record protection round trip per suite, and a tampered record refused.
fn record_roundtrips(t: &mut T) {
    for (name, alg) in [("aes128gcm", &aead::AES_128_GCM), ("aes256gcm", &aead::AES_256_GCM), ("chacha20", &aead::CHACHA20_POLY1305)] {
        // Keys of the suite's length via rustls' own HKDF-Expand-Label (on our HKDF).
        let secret = HKDF_SHA256.extract_from_secret(None, b"lcx record self-test");
        let key = || rustls::internal::derive_traffic_key(&*secret, alg);
        let iv = || rustls::internal::derive_traffic_iv(&*secret);
        let data = b"hello record layer";
        let mut enc = alg.encrypter(key(), iv());
        let mut dec = alg.decrypter(key(), iv());
        let msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(data),
        };
        let wire = enc.encrypt(msg, 3).map(|m| m.encode());
        let ok = wire.as_ref().is_ok_and(|w| {
            let mut body = w.get(5..).unwrap_or(&[]).to_vec();
            let m = InboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, &mut body);
            dec.decrypt(m, 3).is_ok_and(|p| p.payload == data && p.typ == ContentType::ApplicationData)
        });
        t.check(&format!("record-{name}-roundtrip"), ok);
        let tampered = wire.as_ref().is_ok_and(|w| {
            let mut body = flip_last(w.get(5..).unwrap_or(&[]));
            let m = InboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, &mut body);
            dec.decrypt(m, 4).is_err()
        });
        t.check(&format!("record-{name}-reject-tamper"), tampered);
    }
}

fn main() -> ExitCode {
    let Some(dir) = std::env::args().nth(1) else {
        eprintln!("usage: lcx-kat <kat dir>");
        return ExitCode::from(2);
    };
    let mut t = T { n: 0, failed: Vec::new() };
    let steps: [(&str, Step); 8] = [
        ("RFC 7748 X25519", x25519_kat),
        ("NIST CAVP AES-GCM", gcm_kat),
        ("RFC 8439 ChaCha20-Poly1305", chacha_kat),
        ("RFC 5869 HKDF-SHA-256", hkdf_kat),
        ("RFC 4231 HMAC-SHA-256/384", hmac_kat),
        ("RFC 8032 Ed25519", ed25519_kat),
        ("RFC 5903 P-256 ECDH + ECDSA", p256_kat),
        ("ACVP ML-KEM-768", mlkem_kat),
    ];
    for (name, step) in steps {
        let before = (t.n, t.failed.len());
        if let Err(e) = step(&mut t, &dir) {
            println!("LCX-KAT: FAIL (cannot load vectors: {e})");
            return ExitCode::from(1);
        }
        println!("kat {name}: {} checks, {} failed", t.n - before.0, t.failed.len() - before.1);
    }
    let before = (t.n, t.failed.len());
    sha_kat(&mut t);
    group_roundtrips(&mut t);
    record_roundtrips(&mut t);
    println!("kat SHA-2 / group round trips / record layer: {} checks, {} failed", t.n - before.0, t.failed.len() - before.1);
    if t.failed.is_empty() {
        println!("LCX-KAT: PASS ({} checks)", t.n);
        ExitCode::SUCCESS
    } else {
        let first: Vec<&str> = t.failed.iter().take(6).map(String::as_str).collect();
        println!("LCX-KAT: FAIL ({}/{}: {})", t.failed.len(), t.n, first.join(", "));
        ExitCode::from(1)
    }
}
