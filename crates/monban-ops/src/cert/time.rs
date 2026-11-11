//! Time parsing and formatting for certificates and ACME: ASN.1 UTCTime / GeneralizedTime (RFC 5280 §4.1.2.5),
//! RFC 3339 timestamps (ARI suggestedWindow, RFC 9773 §4.2) and IMF-fixdate (HTTP Retry-After, RFC 9110 §5.6.7).
//! All values are Unix seconds (i64). Total: malformed input is `None`.

use std::string::String;

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's `days_from_civil`).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`].
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        _ => 0,
    }
}

fn digits(b: &[u8]) -> Option<u32> {
    if b.is_empty() || b.len() > 9 {
        return None;
    }
    let mut v: u32 = 0;
    for c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u32::from(c - b'0');
    }
    Some(v)
}

fn to_unix(y: i64, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> Option<i64> {
    if !(1..=12).contains(&mo) || d == 0 || d > days_in_month(y, mo) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    // A leap second (60) is folded into the next second.
    Some(days_from_civil(y, mo, d) * 86_400 + i64::from(h) * 3600 + i64::from(mi) * 60 + i64::from(s))
}

/// ASN.1 UTCTime (`YYMMDDHHMMSSZ`, RFC 5280: YY < 50 is 20YY) or GeneralizedTime (`YYYYMMDDHHMMSSZ`).
pub fn parse_asn1_time(tag: u8, v: &[u8]) -> Option<i64> {
    let (y, rest) = match (tag, v.len()) {
        (0x17, 13) => {
            let yy = i64::from(digits(v.get(..2)?)?);
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, v.get(2..)?)
        }
        (0x18, 15) => (i64::from(digits(v.get(..4)?)?), v.get(4..)?),
        _ => return None,
    };
    if rest.last() != Some(&b'Z') {
        return None;
    }
    let f = |a: usize| rest.get(a..a + 2).and_then(digits);
    to_unix(y, f(0)?, f(2)?, f(4)?, f(6)?, f(8)?)
}

/// RFC 3339 `date-time` (e.g. `2026-10-25T12:00:00.123Z`, `...+02:00`). Fractional seconds are truncated.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 || b.len() > 40 {
        return None;
    }
    let sep = |i: usize, c: &[u8]| b.get(i).is_some_and(|x| c.contains(x));
    if !(sep(4, b"-") && sep(7, b"-") && sep(10, b"Tt ") && sep(13, b":") && sep(16, b":")) {
        return None;
    }
    let num = |a: usize, n: usize| b.get(a..a + n).and_then(digits);
    let t = to_unix(i64::from(num(0, 4)?), num(5, 2)?, num(8, 2)?, num(11, 2)?, num(14, 2)?, num(17, 2)?)?;
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return None;
        }
    }
    let tz = b.get(i..)?;
    let off = match tz {
        b"Z" | b"z" => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let h = digits(&[*h1, *h2])?;
            let m = digits(&[*m1, *m2])?;
            if h > 23 || m > 59 {
                return None;
            }
            let o = i64::from(h * 3600 + m * 60);
            if *sign == b'+' { o } else { -o }
        }
        _ => return None,
    };
    Some(t - off)
}

/// Format Unix seconds as RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn format_rfc3339(t: i64) -> String {
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    std::format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3600, secs % 3600 / 60, secs % 60)
}

/// IMF-fixdate, e.g. `Sun, 06 Nov 1994 08:49:37 GMT` (the only HTTP-date form senders may generate).
pub fn parse_http_date(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 29 || b.get(3) != Some(&b',') || b.get(25..) != Some(b" GMT".as_slice()) {
        return None;
    }
    const MONTHS: [&[u8]; 12] =
        [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];
    let mon = b.get(8..11)?;
    let mo = MONTHS.iter().position(|m| *m == mon)? as u32 + 1;
    let num = |a: usize, n: usize| b.get(a..a + n).and_then(digits);
    if b.get(19) != Some(&b':') || b.get(22) != Some(&b':') {
        return None;
    }
    to_unix(i64::from(num(12, 4)?), mo, num(5, 2)?, num(17, 2)?, num(20, 2)?, num(23, 2)?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn vectors() {
        assert_eq!(parse_asn1_time(0x17, b"700101000000Z"), Some(0));
        assert_eq!(parse_asn1_time(0x17, b"491231235959Z"), Some(2_524_607_999));
        assert_eq!(parse_asn1_time(0x18, b"20991231235959Z"), Some(4_102_444_799));
        assert_eq!(parse_asn1_time(0x17, b"260230000000Z"), None);
        assert_eq!(parse_asn1_time(0x17, b"2601010000000"), None);
        assert_eq!(parse_rfc3339("2026-10-25T12:00:00Z"), Some(1_792_929_600));
        assert_eq!(parse_rfc3339("2026-10-25T14:00:00.5+02:00"), Some(1_792_929_600));
        assert_eq!(parse_rfc3339("2026-10-25T12:00:00"), None);
        assert_eq!(parse_rfc3339("2026-13-25T12:00:00Z"), None);
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784_111_777));
        assert_eq!(format_rfc3339(1_792_929_600), "2026-10-25T12:00:00Z");
        for t in [-86_400 * 400, 0, 951_782_400, 4_102_444_799] {
            assert_eq!(parse_rfc3339(&format_rfc3339(t)), Some(t));
        }
    }
}
