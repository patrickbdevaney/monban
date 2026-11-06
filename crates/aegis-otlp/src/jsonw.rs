//! Minimal JSON writer for the OTLP/HTTP JSON encoding. Output only: strings are escaped per RFC 8259, 64-bit
//! integers are written as decimal strings (proto3 JSON mapping), doubles as JSON numbers when finite and as the
//! proto3 special strings `"NaN"`, `"Infinity"`, `"-Infinity"` otherwise.

use core::fmt::Write as _;

/// Append `s` as a quoted, escaped JSON string.
pub fn str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Append a 64-bit integer as a decimal JSON string (proto3 JSON for int64/fixed64).
pub fn int<T: core::fmt::Display>(out: &mut String, v: T) {
    let _ = write!(out, "\"{v}\"");
}

/// Append a double. Finite values use Rust's shortest round-trip form (`Debug`: `0.25`, `-1500.0`, `1e300`), which
/// is valid JSON number syntax; non-finite values use the proto3 JSON strings.
pub fn f64(out: &mut String, v: f64) {
    if v.is_nan() {
        out.push_str("\"NaN\"");
    } else if v.is_infinite() {
        out.push_str(if v > 0.0 { "\"Infinity\"" } else { "\"-Infinity\"" });
    } else {
        let _ = write!(out, "{v:?}");
    }
}

/// Append `"key":` (key is a fixed ASCII field name).
pub fn key(out: &mut String, k: &str) {
    out.push('"');
    out.push_str(k);
    out.push_str("\":");
}

/// Append a string-valued OTLP `KeyValue`: `{"key":k,"value":{"stringValue":v}}`.
pub fn kv_str(out: &mut String, k: &str, v: &str) {
    out.push_str("{\"key\":");
    str(out, k);
    out.push_str(",\"value\":{\"stringValue\":");
    str(out, v);
    out.push_str("}}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_and_numbers() {
        let mut s = String::new();
        str(&mut s, "a\"b\\c\nd\u{1}é");
        assert_eq!(s, "\"a\\\"b\\\\c\\nd\\u0001é\"");
        let mut s = String::new();
        f64(&mut s, -1500.0);
        s.push(',');
        f64(&mut s, 0.0125);
        s.push(',');
        f64(&mut s, f64::NAN);
        s.push(',');
        f64(&mut s, f64::NEG_INFINITY);
        assert_eq!(s, "-1500.0,0.0125,\"NaN\",\"-Infinity\"");
    }
}
