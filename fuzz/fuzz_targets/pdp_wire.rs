//! PDP-1 wire decode (aegis-authz `pdp::{decode_header, decode_request, decode_request_body, decode_reply}`).
//!
//! Properties:
//! - one logical request has exactly one encoding: `decode_request(f) = Ok((id, Ok(r)))` implies
//!   `encode_request(id, r) = f`, and the same for bodies;
//! - `decode_reply` returns Allow/Deny only for the exact 12-byte reply echoing the expected id;
//! - structured requests: `encode` then `decode` then `encode` is stable, and every encodable request decodes.
#![no_main]

use aegis_authz::Decision;
use aegis_authz::pdp::{
    EntityData, HEADER_LEN, KIND_REQUEST, PdpRequest, REPLY_LEN, Uid, Value, decode_header, decode_reply,
    decode_request, decode_request_body, encode_reply, encode_request, encode_request_body,
};
use aegis_fuzz::{Unstructured, any_string, byte, flag, selftest, u64_};
use libfuzzer_sys::fuzz_target;

fn uid(u: &mut Unstructured<'_>) -> Uid {
    let ty = ["App::User", "App::Doc", "App::Action", ""][usize::from(byte(u)) % 4];
    Uid::new(ty, &any_string(u, 6))
}

fn value(u: &mut Unstructured<'_>, depth: u8) -> Value {
    match byte(u) % if depth > 9 { 4 } else { 6 } {
        0 => Value::Bool(flag(u)),
        1 => Value::Long(u64_(u) as i64),
        2 => Value::Str(any_string(u, 6)),
        3 => Value::Entity(uid(u)),
        4 => Value::Set((0..byte(u) % 4).map(|_| value(u, depth + 1)).collect()),
        _ => Value::Record(record(u, depth + 1)),
    }
}

fn record(u: &mut Unstructured<'_>, depth: u8) -> Vec<(String, Value)> {
    (0..byte(u) % 4).map(|_| (any_string(u, 4), value(u, depth))).collect()
}

fn request(u: &mut Unstructured<'_>) -> PdpRequest {
    PdpRequest {
        principal: uid(u),
        action: uid(u),
        resource: uid(u),
        context: record(u, 0),
        entities: (0..byte(u) % 4)
            .map(|_| EntityData {
                uid: uid(u),
                attrs: record(u, 0),
                parents: (0..byte(u) % 3).map(|_| uid(u)).collect(),
            })
            .collect(),
    }
}

fuzz_target!(|data: &[u8]| {
    // Raw frames.
    if let Ok((id, body)) = decode_request(data) {
        assert_ne!(id, 0, "request id 0 accepted");
        if let Ok(r) = body {
            assert_eq!(encode_request(id, &r).as_deref(), Ok(data), "non-canonical request frame accepted");
        }
    }
    if let Ok(r) = decode_request_body(data) {
        assert_eq!(encode_request_body(&r).as_deref(), Ok(data), "non-canonical request body accepted");
    }
    if let Ok((kind, id)) = decode_header(data) {
        assert!(id != 0 && kind <= 1);
        let expected = if data.len() >= HEADER_LEN { id } else { 1 };
        for (true_len, exp) in [(data.len(), expected), (REPLY_LEN, expected), (data.len(), expected ^ 1)] {
            let d = decode_reply(data, true_len, exp);
            if d != Decision::Error {
                assert_eq!(true_len, REPLY_LEN, "{d:?} with a wrong true length");
                assert_eq!(data.get(..REPLY_LEN), Some(&encode_reply(exp, d)[..]), "{d:?} from an inexact reply");
            }
        }
    }
    let d = decode_reply(data, data.len(), 1);
    if d != Decision::Error {
        assert_eq!(data, &encode_reply(1, d)[..], "{d:?} from an inexact reply");
    }

    // Structured requests.
    let mut u = Unstructured::new(data);
    let id = u64_(&mut u) | 1;
    let req = request(&mut u);
    if let Ok(f) = encode_request(id, &req) {
        assert_eq!(f.get(2), Some(&KIND_REQUEST));
        match decode_request(&f) {
            Ok((id2, Ok(r2))) => {
                assert_eq!(id2, id, "request id changed in transit");
                assert_eq!(encode_request(id, &r2).as_ref(), Ok(&f), "encode/decode/encode unstable");
                selftest!(r2.entities.len() >= 2 && r2.entities.iter().any(|e| !e.parents.is_empty()));
            }
            other => panic!("an encodable request does not decode: {other:?}"),
        }
    }
});
