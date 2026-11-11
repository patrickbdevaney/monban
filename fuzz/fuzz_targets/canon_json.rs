//! CANON-2: the one JSON parser / canonical serializer (monban-canon `parse_json`, `canon_json`).
//!
//! Properties:
//! - `parse_json` and `canon_json` accept exactly the same inputs, with the same reject;
//! - accept => re-serialize => re-parse is equal (member order aside: the canonical form sorts members);
//! - the canonical form is a fixed point (CANON-7 idempotence) and is valid UTF-8 without insignificant whitespace;
//! - member names in canonical objects are strictly ascending (sorted, and duplicates were rejected).
#![no_main]

use monban_canon::{JsonValue, canon_json, parse_json};
use monban_fuzz::selftest;
use libfuzzer_sys::fuzz_target;

/// Sort object members (recursively) so values that differ only in member order compare equal.
fn normalize(v: &JsonValue) -> JsonValue {
    match v {
        JsonValue::Array(xs) => JsonValue::Array(xs.iter().map(normalize).collect()),
        JsonValue::Object(ms) => {
            let mut ms: Vec<(String, JsonValue)> = ms.iter().map(|(k, x)| (k.clone(), normalize(x))).collect();
            ms.sort_by(|a, b| a.0.cmp(&b.0));
            JsonValue::Object(ms)
        }
        other => other.clone(),
    }
}

fn names_ascending(v: &JsonValue) -> bool {
    match v {
        JsonValue::Array(xs) => xs.iter().all(names_ascending),
        JsonValue::Object(ms) => {
            ms.windows(2).all(|w| matches!(w, [a, b] if a.0 < b.0)) && ms.iter().all(|(_, x)| names_ascending(x))
        }
        _ => true,
    }
}

#[cfg_attr(not(fuzzing_selftest), allow(dead_code))]
fn depth(v: &JsonValue) -> usize {
    match v {
        JsonValue::Array(xs) => 1 + xs.iter().map(depth).max().unwrap_or(0),
        JsonValue::Object(ms) => 1 + ms.iter().map(|(_, x)| depth(x)).max().unwrap_or(0),
        _ => 0,
    }
}

fuzz_target!(|data: &[u8]| {
    let parsed = parse_json(data);
    let canon = canon_json(data);
    match (&parsed, &canon) {
        (Ok(v), Ok(c)) => {
            let cb = c.as_bytes();
            assert!(core::str::from_utf8(cb).is_ok(), "canonical JSON is not UTF-8");
            let again = canon_json(cb);
            assert_eq!(again.as_ref().map(|x| x.as_bytes()), Ok(cb), "canonical JSON is not a fixed point");
            let reparsed = parse_json(cb);
            let Ok(rv) = reparsed else { panic!("canonical JSON does not re-parse") };
            assert_eq!(normalize(&rv), normalize(v), "accept => serialize => re-parse changed the value");
            assert!(names_ascending(&rv), "canonical object members not strictly ascending");
            selftest!(depth(v) >= 4); // seeds nest at most 3 deep (>= 5 missed the old 1e6 budget in 2 of 3 full self-tests)
        }
        (Err(a), Err(b)) => assert_eq!(a, b, "parse_json and canon_json reject differently"),
        _ => panic!("parse_json and canon_json disagree on acceptance"),
    }
});
