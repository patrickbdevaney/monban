//! F9: audit event encode / verify round-trip (aegis-audit: leaf encoding, checkpoints, signed notes, Merkle
//! proofs, base64).
//!
//! Properties:
//! - a leaf built from attacker-influenced strings is printable ASCII, within the leaf cap, and (when its numbers
//!   are I-JSON-safe and its strings NUL-free, which the strict aegis-canon parser requires) parses back to the same
//!   `object`, `action`, `seq` and detail strings;
//! - decoders accept only canonical text: `base64_decode(s) = Some(b)` => `base64_encode(b) = s`;
//!   `Checkpoint::parse(t) = Ok(c)` => `c.text() = t`;
//! - a checkpoint note signed with a known Ed25519 key opens to its text; any single-byte mutation of the note never
//!   opens (signed-note verify); `open_note` / `NoteVerifier::parse` are total on raw input;
//! - Merkle inclusion and consistency proofs from `MerkleStore` verify, and a proof with one flipped bit does not.
#![no_main]

use std::collections::BTreeMap;
use std::sync::OnceLock;

use aegis_audit::encoding::{base64_decode, base64_encode};
use aegis_audit::event::MAX_LEAF_BYTES;
use aegis_audit::{
    Action, Actor, AuditEvent, Checkpoint, Detail, DetailKey, DetailValue, Ed25519NoteSigner, EventClass, FipsStatus,
    MerkleStore, NoteSigner, NoteVerifier, Outcome, Untrusted, leaf_hash, open_note, sign_note, verify_consistency,
    verify_inclusion,
};
use aegis_canon::{JsonValue, parse_json};
use aegis_fuzz::{LOWER, Unstructured, byte, bytes, flag, selftest, string_from, u64_};
use aegis_types::TenantId;
use libfuzzer_sys::fuzz_target;

const SAFE: u64 = (1 << 53) - 1;

fn signer() -> Option<&'static (Ed25519NoteSigner, NoteVerifier)> {
    static S: OnceLock<Option<(Ed25519NoteSigner, NoteVerifier)>> = OnceLock::new();
    S.get_or_init(|| {
        let s = Ed25519NoteSigner::from_seed("fuzz.example/log", &[9u8; 32]).ok()?;
        let v = NoteVerifier::parse(&s.vkey()).ok()?;
        Some((s, v))
    })
    .as_ref()
}

fn field<'a>(obj: &'a [(String, JsonValue)], k: &str) -> Option<&'a JsonValue> {
    obj.iter().find(|(n, _)| n == k).map(|(_, v)| v)
}

fn leaf(u: &mut Unstructured<'_>) {
    let actor = match byte(u) % 4 {
        0 => Actor::public(),
        1 => Actor::system(),
        2 => Actor::admin(bytes(u, 16)),
        _ => match TenantId::new(u64_(u) % SAFE) {
            Ok(t) => Actor::principal(t, if flag(u) { Some(bytes(u, 16)) } else { None }),
            Err(_) => Actor::public(),
        },
    };
    let action_s = string_from(u, 12, b"abcdefghijklmnopqrstuvwxyz0123456789_.A-");
    let Ok(action) = Action::new(&action_s) else { return };
    let object_raw = bytes(u, 700);
    let object = Untrusted::object(object_raw);
    let mut detail = Detail::new();
    // Final rendered value per key when it is an attacker string (None: last write was another kind).
    let mut detail_strs: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut big_int = false;
    for _ in 0..byte(u) % 20 {
        let name = string_from(u, 6, LOWER);
        let Ok(k) = DetailKey::new(&name) else { continue };
        let (v, sv) = match byte(u) % 5 {
            0 => {
                let t = DetailValue::text(bytes(u, 200));
                let sv = if let DetailValue::Str(s) = &t { Some(s.as_str().to_string()) } else { None };
                (t, sv)
            }
            1 => {
                let n = u64_(u) as i64;
                big_int |= n.unsigned_abs() > SAFE;
                (DetailValue::Int(n), None)
            }
            2 => (DetailValue::Bool(flag(u)), None),
            3 => (DetailValue::Redacted, None),
            _ => (DetailValue::hashed(bytes(u, 8)), None),
        };
        if detail.insert(k, v).is_ok() {
            detail_strs.insert(name, sv);
        } else {
            assert!(detail.len() >= 16, "detail insert refused below the cap");
        }
        assert!(detail.len() <= 16, "detail over the cap");
    }
    let ev = AuditEvent {
        class: if flag(u) { EventClass::Admin } else { EventClass::DataPlane },
        actor,
        action,
        object,
        outcome: [Outcome::Allow, Outcome::Deny, Outcome::Error, Outcome::Applied, Outcome::RolledBack]
            [usize::from(byte(u)) % 5],
        req_id: [byte(u); 16],
        config_hash: [byte(u); 32],
        fips_status: [FipsStatus::None, FipsStatus::Floor, FipsStatus::Cmvp][usize::from(byte(u)) % 3],
        detail,
    };
    let seq = u64_(u) % (SAFE + 1);
    let ts = u64_(u) % 300_000_000_000_000;
    let Ok(l) = ev.encode_leaf(seq, ts) else { return };
    assert!(l.len() <= MAX_LEAF_BYTES, "leaf over the cap");
    assert!(l.iter().all(|&b| (0x20..0x7F).contains(&b)), "leaf is not printable ASCII");
    let nul = ev.object.as_str().contains('\0') || detail_strs.values().flatten().any(|s| s.contains('\0'));
    if big_int || nul {
        return; // valid RFC 8259 JSON, but outside strict I-JSON (canon rejects NUL and unsafe integers)
    }
    let parsed = parse_json(&l);
    let Ok(JsonValue::Object(o)) = parsed else { panic!("leaf is not a strict JSON object: {parsed:?}") };
    assert_eq!(field(&o, "object"), Some(&JsonValue::String(ev.object.as_str().to_string())), "object mangled");
    assert_eq!(field(&o, "action"), Some(&JsonValue::String(action_s)), "action mangled");
    assert_eq!(field(&o, "seq"), Some(&JsonValue::Int(seq as i64)), "seq mangled");
    let d = match field(&o, "detail") {
        Some(JsonValue::Object(d)) => d.as_slice(),
        None => &[],
        Some(other) => panic!("detail is not an object: {other:?}"),
    };
    assert_eq!(d.len(), detail_strs.len(), "detail entry count mangled");
    for (k, sv) in &detail_strs {
        let got = field(d, k);
        assert!(got.is_some(), "detail key {k:?} missing");
        if let Some(s) = sv {
            assert_eq!(got, Some(&JsonValue::String(s.clone())), "detail string mangled");
        }
    }
    selftest!(ev.object.as_str().chars().count() >= 8 && !ev.object.as_str().is_ascii());
}

fn notes(fx: &(Ed25519NoteSigner, NoteVerifier), u: &mut Unstructured<'_>, data: &[u8]) {
    let (s, v) = fx;
    // Raw input against every decoder.
    if let Ok(text) = core::str::from_utf8(data) {
        if let Some(b) = base64_decode(text) {
            assert_eq!(base64_encode(&b), text, "base64 decode accepted a non-canonical encoding");
        }
        if let Ok(c) = Checkpoint::parse(text) {
            assert_eq!(c.text(), text, "checkpoint parse accepted a non-canonical text");
        }
        let _ = NoteVerifier::parse(text);
        if let Ok((t, ids)) = open_note(text, std::slice::from_ref(v)) {
            // Only reachable by forging an Ed25519 signature of our key.
            panic!("open_note accepted fuzzer bytes: {t:?} {ids:?}");
        }
    }
    // Sign a checkpoint and mutate the note.
    let origin = string_from(u, 16, b"abcdefghijklmnopqrstuvwxyz./-0123456789 ");
    let mut root = [0u8; 32];
    for b in root.iter_mut() {
        *b = byte(u);
    }
    let Ok(cp) = Checkpoint::new(&origin, u64_(u), root) else { return };
    let text = cp.text();
    assert_eq!(Checkpoint::parse(&text).as_ref(), Ok(&cp), "checkpoint text does not round-trip");
    let Ok(note) = sign_note(&text, &[s as &dyn NoteSigner]) else { panic!("signing a valid checkpoint failed") };
    let opened = open_note(&note, std::slice::from_ref(v));
    assert_eq!(opened.as_ref().map(|(t, _)| *t), Ok(text.as_str()), "signed note does not open to its text");
    let mut m = note.clone().into_bytes();
    let pos = (usize::from(byte(u)) | usize::from(byte(u)) << 8) % m.len().max(1);
    if let Some(b) = m.get_mut(pos) {
        *b ^= byte(u) | 1;
    }
    if let Ok(ms) = String::from_utf8(m) {
        assert!(open_note(&ms, std::slice::from_ref(v)).is_err(), "mutated signed note still opens");
    }
}

fn merkle(u: &mut Unstructured<'_>) {
    let n = u64::from(byte(u) % 40) + 1;
    let mut st = MerkleStore::new();
    for i in 0..n {
        st.push_leaf(leaf_hash(&i.to_be_bytes()));
    }
    let size = 1 + u64_(u) % n;
    let idx = u64_(u) % size;
    let (Some(root), Some(proof)) = (st.root(size), st.inclusion_proof(idx, size)) else {
        panic!("root / inclusion proof unavailable for an in-range tree")
    };
    let lh = leaf_hash(&idx.to_be_bytes());
    assert!(verify_inclusion(idx, size, &lh, &proof, &root), "valid inclusion proof rejected");
    let old = 1 + u64_(u) % size;
    let (Some(old_root), Some(cproof)) = (st.root(old), st.consistency_proof(old, size)) else {
        panic!("consistency proof unavailable")
    };
    assert!(verify_consistency(old, size, &old_root, &root, &cproof), "valid consistency proof rejected");
    let bit = byte(u);
    let which = usize::from(byte(u));
    if !proof.is_empty() {
        let mut bad = proof.clone();
        let k = which % bad.len();
        if let Some(h) = bad.get_mut(k) {
            if let Some(x) = h.get_mut(usize::from(bit % 32)) {
                *x ^= 1 << (bit % 8);
            }
        }
        assert!(!verify_inclusion(idx, size, &lh, &bad, &root), "corrupted inclusion proof accepted");
    }
    if !cproof.is_empty() {
        let mut bad = cproof.clone();
        let k = which % bad.len();
        if let Some(h) = bad.get_mut(k) {
            if let Some(x) = h.get_mut(usize::from(bit % 32)) {
                *x ^= 1 << (bit % 8);
            }
        }
        assert!(!verify_consistency(old, size, &old_root, &root, &bad), "corrupted consistency proof accepted");
    }
}

fuzz_target!(|data: &[u8]| {
    let Some(fx) = signer() else { panic!("audit fixture setup failed") };
    let mut u = Unstructured::new(data);
    leaf(&mut u);
    notes(fx, &mut u, data);
    merkle(&mut u);
});
