//! JSON emission for values the gate constructs (error objects, merged multiplexed tool lists, rewritten forward
//! bodies). Parsing and canonicalization stay with the one JSON owner (aegis-canon, DEVIATIONS X-2): every body the
//! gate forwards or relays is passed through `aegis_canon::canon_json`, so what leaves the gate is exactly the
//! owner's canonical form of a document the owner accepted (CANON-4).
//!
//! Numbers: integers in decimal; non-integers in Rust's shortest round-trip exponent form (`1.5e-7`, `0.0` for
//! zero), which the strict parser reads back as the same `Float` (a fixed-notation rendering of a large float would
//! read back as an out-of-range integer).

use std::fmt::Write as _;
use std::string::String;

use aegis_canon::JsonValue;

/// Append a JSON string literal.
pub fn string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 || c == '\u{7f}' => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Append a value.
pub fn value(v: &JsonValue, out: &mut String) {
    match v {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(true) => out.push_str("true"),
        JsonValue::Bool(false) => out.push_str("false"),
        JsonValue::Int(i) => {
            let _ = write!(out, "{i}");
        }
        JsonValue::Float(f) => {
            if *f == 0.0 {
                out.push_str("0.0");
            } else {
                let _ = write!(out, "{f:e}");
            }
        }
        JsonValue::String(s) => string(s, out),
        JsonValue::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                value(x, out);
            }
            out.push(']');
        }
        JsonValue::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                string(k, out);
                out.push(':');
                value(x, out);
            }
            out.push('}');
        }
    }
}

/// Serialize a value and canonicalize it through the JSON owner. `None` if the owner rejects it (fail closed).
pub fn canonical(v: &JsonValue) -> Option<std::vec::Vec<u8>> {
    let mut s = String::new();
    value(v, &mut s);
    aegis_canon::canon_json(s.as_bytes()).ok().map(|c| c.as_bytes().to_vec())
}

/// Member of an object by exact name.
pub fn get<'a>(v: &'a JsonValue, name: &str) -> Option<&'a JsonValue> {
    match v {
        JsonValue::Object(m) => m.iter().find(|(k, _)| k == name).map(|(_, x)| x),
        _ => None,
    }
}

/// String member of an object.
pub fn get_str<'a>(v: &'a JsonValue, name: &str) -> Option<&'a str> {
    match get(v, name) {
        Some(JsonValue::String(s)) => Some(s.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use aegis_canon::parse_json;

    #[test]
    fn round_trips_through_the_owner() {
        let src = br#"{"a":[1,-2,1.5,1e300,1e-300,0.0,2.5e-7,true,false,null],"s":"q\"\\\n\u0001\u00e9x","o":{}}"#;
        let v = parse_json(src).unwrap();
        let out = canonical(&v).unwrap();
        // Same document up to member order (the canonical form sorts members).
        assert_eq!(canonical(&parse_json(&out).unwrap()).unwrap(), out);
        assert_eq!(out, aegis_canon::canon_json(src).unwrap().as_bytes());
    }
}
