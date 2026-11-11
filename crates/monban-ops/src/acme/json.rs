//! JSON helpers over `monban_canon::JsonValue` (the one strict parser, DEVIATIONS X-2) and a string quoter for the
//! small request documents this client writes.

use std::string::String;

use monban_canon::JsonValue;

/// Member `k` of an object.
pub fn get<'a>(v: &'a JsonValue, k: &str) -> Option<&'a JsonValue> {
    match v {
        JsonValue::Object(m) => m.iter().find(|(n, _)| n == k).map(|(_, v)| v),
        _ => None,
    }
}

/// String member `k`.
pub fn get_str<'a>(v: &'a JsonValue, k: &str) -> Option<&'a str> {
    match get(v, k) {
        Some(JsonValue::String(s)) => Some(s),
        _ => None,
    }
}

/// Array member `k`.
pub fn get_array<'a>(v: &'a JsonValue, k: &str) -> Option<&'a [JsonValue]> {
    match get(v, k) {
        Some(JsonValue::Array(a)) => Some(a),
        _ => None,
    }
}

/// A JSON string literal (RFC 8259 §7 escaping).
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&std::format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn quote_roundtrips_through_strict_parser() {
        for s in ["", "plain", "q\"b\\s", "ctl\u{1}\n\t", "ünï"] {
            let q = quote(s);
            assert_eq!(monban_canon::parse_json(q.as_bytes()).unwrap(), JsonValue::String(s.into()));
        }
    }
}
