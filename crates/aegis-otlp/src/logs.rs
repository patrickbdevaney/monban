//! Log line -> OTLP JSON `LogRecord` (oracles/otlp-export/README.md "Log line mapping").
//!
//! A line that aegis-canon's strict I-JSON parser accepts as an object gets the structured mapping (`ts`, `level`,
//! `msg`, `trace_id`, `span_id`, every other non-null key -> attributes). Anything else (plain text, non-object
//! JSON, broken or non-I-JSON input) becomes a string body. Lines are bounded by the reader ([`MAX_LINE`]).

use aegis_canon::JsonValue;

use crate::jsonw;

/// Longest log line exported; longer lines are truncated to this many bytes (at a UTF-8 boundary) and exported as
/// plain text.
pub const MAX_LINE: usize = 65_536;

const RESERVED: [&str; 5] = ["ts", "level", "msg", "trace_id", "span_id"];

/// OTLP SeverityNumber for a level, case-insensitive; 0 (unset) for anything else.
fn severity(level: &str) -> u8 {
    match level.to_ascii_uppercase().as_str() {
        "TRACE" => 1,
        "DEBUG" => 5,
        "INFO" => 9,
        "WARN" => 13,
        "ERROR" => 17,
        "FATAL" => 21,
        _ => 0,
    }
}

fn digits(s: &[u8]) -> Option<u64> {
    if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(s.iter().fold(0u64, |a, &d| a.saturating_mul(10).saturating_add(u64::from(d - b'0'))))
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: u64, d: u64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = m as i64;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// RFC 3339 timestamp (`YYYY-MM-DDTHH:MM:SS[.f{1,9}](Z|±hh:mm)`) to Unix nanoseconds. `None` when malformed,
/// out of range, or before the epoch.
pub fn rfc3339_ns(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    let field = |a: usize, z: usize| b.get(a..z).and_then(digits);
    let (y, mo, d) = (field(0, 4)?, field(5, 7)?, field(8, 10)?);
    let (h, mi, se) = (field(11, 13)?, field(14, 16)?, field(17, 19)?);
    if b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') || b.get(10) != Some(&b'T') {
        return None;
    }
    if b.get(13) != Some(&b':') || b.get(16) != Some(&b':') {
        return None;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let mdays = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let max_d = mdays.get(usize::try_from(mo).ok()?.checked_sub(1)?).copied()?;
    if !(1..=max_d).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let mut i = 19;
    let mut frac = 0u64;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        let n = i - start;
        if !(1..=9).contains(&n) {
            return None;
        }
        frac = digits(b.get(start..i)?)?;
        for _ in n..9 {
            frac *= 10;
        }
    }
    let offset: i64 = match b.get(i..)? {
        b"Z" => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let oh = digits(&[*h1, *h2])?;
            let om = digits(&[*m1, *m2])?;
            if oh > 23 || om > 59 {
                return None;
            }
            let off = (oh * 3600 + om * 60) as i64;
            if *sign == b'+' { off } else { -off }
        }
        _ => return None,
    };
    let days = days_from_civil(y as i64, mo, d);
    let secs = days * 86_400 + (h * 3600 + mi * 60 + se) as i64 - offset;
    let secs = u64::try_from(secs).ok()?;
    secs.checked_mul(1_000_000_000)?.checked_add(frac)
}

/// Append an AnyValue for a non-null JSON value (null members/elements are omitted by the callers).
fn any(out: &mut String, v: &JsonValue) {
    match v {
        JsonValue::Null => out.push_str("{}"),
        JsonValue::Bool(b) => out.push_str(if *b { "{\"boolValue\":true}" } else { "{\"boolValue\":false}" }),
        JsonValue::Int(i) => {
            out.push_str("{\"intValue\":");
            jsonw::int(out, i);
            out.push('}');
        }
        JsonValue::Float(f) => {
            out.push_str("{\"doubleValue\":");
            jsonw::f64(out, *f);
            out.push('}');
        }
        JsonValue::String(s) => {
            out.push_str("{\"stringValue\":");
            jsonw::str(out, s);
            out.push('}');
        }
        JsonValue::Array(items) => {
            out.push_str("{\"arrayValue\":{\"values\":[");
            let mut first = true;
            for x in items.iter().filter(|x| !matches!(x, JsonValue::Null)) {
                if !first {
                    out.push(',');
                }
                first = false;
                any(out, x);
            }
            out.push_str("]}}");
        }
        JsonValue::Object(members) => {
            out.push_str("{\"kvlistValue\":{\"values\":[");
            kvs(out, members.iter().filter(|(_, x)| !matches!(x, JsonValue::Null)));
            out.push_str("]}}");
        }
    }
}

fn kvs<'a>(out: &mut String, members: impl Iterator<Item = &'a (String, JsonValue)>) {
    for (i, (k, v)) in members.enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"key\":");
        jsonw::str(out, k);
        out.push_str(",\"value\":");
        any(out, v);
        out.push('}');
    }
}

fn plain(out: &mut String, line: &[u8]) {
    out.push_str(",\"body\":{\"stringValue\":");
    jsonw::str(out, &String::from_utf8_lossy(line));
    out.push_str("}}");
}

fn hex_id(v: Option<&JsonValue>, width: usize) -> Option<String> {
    match v {
        Some(JsonValue::String(s)) if s.len() == width && s.bytes().all(|b| b.is_ascii_hexdigit()) => {
            Some(s.to_ascii_lowercase())
        }
        _ => None,
    }
}

/// Encode one log line (without its newline) as a `LogRecord`. `truncated` lines are always plain text.
pub fn record(line: &[u8], truncated: bool, observed_ns: u64) -> String {
    let mut out = String::with_capacity(line.len().saturating_add(96));
    out.push_str("{\"observedTimeUnixNano\":");
    jsonw::int(&mut out, observed_ns);
    let obj = if truncated { None } else { aegis_canon::parse_json(line).ok() };
    let Some(JsonValue::Object(members)) = obj else {
        plain(&mut out, line);
        return out;
    };
    let get = |k: &str| members.iter().find(|(n, _)| n == k).map(|(_, v)| v);
    if let Some(JsonValue::String(ts)) = get("ts")
        && let Some(t) = rfc3339_ns(ts)
    {
        out.push_str(",\"timeUnixNano\":");
        jsonw::int(&mut out, t);
    }
    if let Some(JsonValue::String(level)) = get("level") {
        let n = severity(level);
        if n != 0 {
            out.push_str(",\"severityNumber\":");
            out.push_str(&n.to_string());
        }
        out.push_str(",\"severityText\":");
        jsonw::str(&mut out, level);
    }
    if let Some(msg) = get("msg").filter(|m| !matches!(m, JsonValue::Null)) {
        out.push_str(",\"body\":");
        any(&mut out, msg);
    }
    if let Some(t) = hex_id(get("trace_id"), 32) {
        out.push_str(",\"traceId\":");
        jsonw::str(&mut out, &t);
    }
    if let Some(s) = hex_id(get("span_id"), 16) {
        out.push_str(",\"spanId\":");
        jsonw::str(&mut out, &s);
    }
    let mut rest =
        members.iter().filter(|(k, v)| !RESERVED.contains(&k.as_str()) && !matches!(v, JsonValue::Null)).peekable();
    if rest.peek().is_some() {
        out.push_str(",\"attributes\":[");
        kvs(&mut out, rest);
        out.push(']');
    }
    out.push('}');
    out
}

/// Truncate to at most [`MAX_LINE`] bytes on a UTF-8 boundary (invalid UTF-8 is cut at `MAX_LINE`).
pub fn truncate(line: &[u8]) -> &[u8] {
    let cut = line.get(..MAX_LINE).unwrap_or(line);
    match core::str::from_utf8(cut) {
        Ok(_) => cut,
        Err(e) if e.error_len().is_none() => cut.get(..e.valid_up_to()).unwrap_or(cut),
        Err(_) => cut,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps() {
        assert_eq!(rfc3339_ns("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(rfc3339_ns("2026-11-06T12:00:00.000000001Z"), Some(1_793_966_400_000_000_001));
        assert_eq!(rfc3339_ns("2026-11-06T13:00:00.5+01:00"), Some(1_793_966_400_500_000_000));
        assert_eq!(rfc3339_ns("2026-02-29T00:00:00Z"), None);
        assert_eq!(rfc3339_ns("2026-11-06T12:00:00.0000000001Z"), None);
        assert_eq!(rfc3339_ns("2026-11-06 12:00:00Z"), None);
        assert_eq!(rfc3339_ns("1969-12-31T23:59:59Z"), None);
    }

    #[test]
    fn structured_and_plain() {
        let r = record(
            br#"{"ts":"1970-01-01T00:00:01Z","level":"warn","msg":"m","n":1,"x":null,"trace_id":"AB"}"#,
            false,
            7,
        );
        assert_eq!(
            r,
            "{\"observedTimeUnixNano\":\"7\",\"timeUnixNano\":\"1000000000\",\"severityNumber\":13,\"severityText\":\"warn\",\"body\":{\"stringValue\":\"m\"},\"attributes\":[{\"key\":\"n\",\"value\":{\"intValue\":\"1\"}}]}"
        );
        assert_eq!(record(b"[1]", false, 1), "{\"observedTimeUnixNano\":\"1\",\"body\":{\"stringValue\":\"[1]\"}}");
        assert_eq!(truncate("é".repeat(40_000).as_bytes()).len(), MAX_LINE);
    }
}
