//! Strict I-JSON (RFC 8259 + RFC 7493) parser and canonical serializer (DEVIATIONS X-2: the one JSON parser,
//! owned by aegis-canon).
//!
//! Rejected: invalid UTF-8, a leading BOM, anything outside the RFC 8259 grammar (including `NaN`/`Infinity`,
//! trailing commas, leading zeros, trailing data), duplicate member names and names that collide under ASCII
//! case-folding (Go `encoding/json` matches fields case-insensitively), lone surrogates, NUL in strings, integers
//! outside +/-(2^53-1), `-0`, non-finite numbers, numbers that underflow to zero, numbers with more than 17
//! significant digits, nesting deeper than [`MAX_JSON_DEPTH`], more than [`MAX_JSON`] code points (413).
//!
//! Canonical serialization: object members sorted by name (code point order), `,` and `:` separators without
//! whitespace, UTF-8 without escapes except `\"`, `\\`, `\b \f \n \r \t` and `\u00XX` for other controls;
//! integers in decimal; non-integers (any number written with a fraction or exponent) as the shortest
//! round-trip decimal in fixed notation for exponents -4..=15 (always with a fractional part, e.g. `100.0`)
//! and scientific notation otherwise (`1e+16`, `1.5e-07`).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use aegis_types::{Canon, kind::JsonBody};

use crate::limits::{MAX_JSON, MAX_JSON_DEPTH};
use crate::{Reject, cp_len, seal};

const K: &str = "json";
const MAX_SAFE_INT: i64 = (1 << 53) - 1;

const fn rej(reason: &'static str) -> Reject {
    Reject::new(400, K, reason)
}

/// A parsed I-JSON value. Object members keep their input order here; the canonical serialization sorts them.
#[derive(Clone, Debug, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    /// An integer literal (no fraction, no exponent) within +/-(2^53-1).
    Int(i64),
    /// A number written with a fraction or an exponent: finite, not -0, not underflowed.
    Float(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

/// Parse a strict I-JSON document.
pub fn parse_json(input: &[u8]) -> Result<JsonValue, Reject> {
    let Ok(text) = core::str::from_utf8(input) else {
        return Err(rej("invalid UTF-8"));
    };
    if cp_len(input) > MAX_JSON {
        return Err(Reject::new(413, K, "too large"));
    }
    if text.starts_with('\u{FEFF}') {
        return Err(rej("BOM"));
    }
    let mut p = Parser { s: text.as_bytes(), i: 0 };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.s.len() {
        return Err(rej("syntax"));
    }
    Ok(v)
}

/// Canonicalize a JSON body: parse strictly, then serialize canonically.
pub fn canon_json(input: &[u8]) -> Result<Canon<JsonBody>, Reject> {
    let v = parse_json(input)?;
    let mut out = String::with_capacity(input.len());
    write_value(&v, &mut out);
    Ok(seal(out.into_bytes()))
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn bump(&mut self) {
        self.i = self.i.saturating_add(1);
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump();
        }
    }

    fn eat(&mut self, b: u8) -> Result<(), Reject> {
        if self.peek() == Some(b) {
            self.bump();
            Ok(())
        } else {
            Err(rej("syntax"))
        }
    }

    fn lit(&mut self, word: &[u8]) -> Result<(), Reject> {
        let end = self.i.saturating_add(word.len());
        if self.s.get(self.i..end) == Some(word) {
            self.i = end;
            Ok(())
        } else {
            Err(rej("syntax"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<JsonValue, Reject> {
        if depth > MAX_JSON_DEPTH {
            return Err(rej("too deep"));
        }
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(JsonValue::String),
            Some(b't') => self.lit(b"true").map(|()| JsonValue::Bool(true)),
            Some(b'f') => self.lit(b"false").map(|()| JsonValue::Bool(false)),
            Some(b'n') => self.lit(b"null").map(|()| JsonValue::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(rej("syntax")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<JsonValue, Reject> {
        self.eat(b'{')?;
        self.ws();
        let mut members: Vec<(String, JsonValue)> = Vec::new();
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok(JsonValue::Object(members));
        }
        let child = depth.saturating_add(1);
        loop {
            if child > MAX_JSON_DEPTH {
                return Err(rej("too deep"));
            }
            if self.peek() != Some(b'"') {
                return Err(rej("syntax"));
            }
            let name = self.string()?;
            self.ws();
            self.eat(b':')?;
            self.ws();
            let v = self.value(child)?;
            members.push((name, v));
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.bump();
                    self.ws();
                }
                Some(b'}') => {
                    self.bump();
                    break;
                }
                _ => return Err(rej("syntax")),
            }
        }
        // Duplicate names, and names equal under ASCII case-folding (ASCII names are folded, others kept).
        let mut folded: Vec<String> =
            members.iter().map(|(n, _)| if n.is_ascii() { n.to_ascii_lowercase() } else { n.clone() }).collect();
        folded.sort_unstable();
        if folded.windows(2).any(|w| w.first() == w.get(1)) {
            return Err(rej("duplicate name"));
        }
        Ok(JsonValue::Object(members))
    }

    fn array(&mut self, depth: usize) -> Result<JsonValue, Reject> {
        self.eat(b'[')?;
        self.ws();
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.bump();
            return Ok(JsonValue::Array(items));
        }
        let child = depth.saturating_add(1);
        loop {
            items.push(self.value(child)?);
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.bump();
                    self.ws();
                }
                Some(b']') => {
                    self.bump();
                    break;
                }
                _ => return Err(rej("syntax")),
            }
        }
        Ok(JsonValue::Array(items))
    }

    fn hex4(&mut self) -> Result<u32, Reject> {
        let mut v = 0u32;
        for _ in 0..4 {
            let d = self.peek().and_then(crate::hex_val).ok_or(rej("syntax"))?;
            v = (v << 4) | u32::from(d);
            self.bump();
        }
        Ok(v)
    }

    fn string(&mut self) -> Result<String, Reject> {
        self.eat(b'"')?;
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let Some(c) = self.peek() else {
                return Err(rej("syntax"));
            };
            match c {
                b'"' => {
                    self.bump();
                    break;
                }
                b'\\' => {
                    self.bump();
                    let e = self.peek().ok_or(rej("syntax"))?;
                    self.bump();
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => self.unicode_escape()?,
                        _ => return Err(rej("syntax")),
                    };
                    if ch == '\0' {
                        return Err(rej("NUL in string"));
                    }
                    let mut tmp = [0u8; 4];
                    buf.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
                }
                0x00..=0x1F => return Err(rej("control character in string")),
                _ => {
                    buf.push(c);
                    self.bump();
                }
            }
        }
        // The input was valid UTF-8 and escapes were pushed as whole scalar values.
        String::from_utf8(buf).map_err(|_| rej("invalid UTF-8"))
    }

    fn unicode_escape(&mut self) -> Result<char, Reject> {
        let u = self.hex4()?;
        if (0xD800..0xDC00).contains(&u) {
            if self.s.get(self.i..self.i.saturating_add(2)) != Some(b"\\u") {
                return Err(rej("lone surrogate"));
            }
            self.i = self.i.saturating_add(2);
            let lo = self.hex4()?;
            if !(0xDC00..0xE000).contains(&lo) {
                return Err(rej("lone surrogate"));
            }
            let cp = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00);
            return char::from_u32(cp).ok_or(rej("lone surrogate"));
        }
        char::from_u32(u).ok_or(rej("lone surrogate"))
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.bump();
        }
        self.i.saturating_sub(start)
    }

    fn number(&mut self) -> Result<JsonValue, Reject> {
        let start = self.i;
        let neg = self.peek() == Some(b'-');
        if neg {
            self.bump();
        }
        let int_start = self.i;
        match self.peek() {
            Some(b'0') => self.bump(),
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(rej("syntax")),
        }
        let int_end = self.i;
        let mut frac: (usize, usize) = (int_end, int_end);
        let mut is_float = false;
        if self.peek() == Some(b'.') && matches!(self.s.get(self.i.saturating_add(1)), Some(b'0'..=b'9')) {
            self.bump();
            let fs = self.i;
            self.digits();
            frac = (fs, self.i);
            is_float = true;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            let save = self.i;
            self.bump();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump();
            }
            if self.digits() == 0 {
                self.i = save; // not an exponent: the trailing 'e' is then a syntax error at the caller
            } else {
                is_float = true;
            }
        }
        let text = self.s.get(start..self.i).ok_or(rej("syntax"))?;
        let int_digits = self.s.get(int_start..int_end).ok_or(rej("syntax"))?;
        if !is_float {
            if neg && int_digits.iter().all(|&d| d == b'0') {
                return Err(rej("negative zero"));
            }
            if int_digits.len() > 16 {
                return Err(rej("integer outside I-JSON range"));
            }
            let mag = int_digits.iter().fold(0i64, |a, &d| a.saturating_mul(10).saturating_add(i64::from(d - b'0')));
            if mag > MAX_SAFE_INT {
                return Err(rej("integer outside I-JSON range"));
            }
            return Ok(JsonValue::Int(if neg { -mag } else { mag }));
        }
        let frac_digits = self.s.get(frac.0..frac.1).ok_or(rej("syntax"))?;
        let text = core::str::from_utf8(text).map_err(|_| rej("syntax"))?;
        let f: f64 = text.parse().map_err(|_| rej("syntax"))?;
        if !f.is_finite() {
            return Err(rej("non-finite number"));
        }
        // Significant digits of the mantissa: leading and trailing zeros stripped.
        let all = int_digits.iter().chain(frac_digits.iter());
        let lead = all.clone().take_while(|&&d| d == b'0').count();
        let total = int_digits.len().saturating_add(frac_digits.len());
        let trail = int_digits.iter().chain(frac_digits.iter()).rev().take_while(|&&d| d == b'0').count();
        let significant = total.saturating_sub(lead).saturating_sub(trail);
        let nonzero = lead < total;
        if f == 0.0 && nonzero {
            return Err(rej("underflow"));
        }
        if f == 0.0 && neg {
            return Err(rej("negative zero"));
        }
        if nonzero && significant > 17 {
            return Err(rej("precision beyond binary64"));
        }
        Ok(JsonValue::Float(f))
    }
}

fn write_string(s: &str, out: &mut String) {
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
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Shortest round-trip decimal, laid out as CPython's `float.__repr__` (the reference serializer).
fn write_float(f: f64, out: &mut String) {
    // Shortest digit count first; then, among the decimals of that length, the one closest to `f` (CPython's
    // repr picks the closest when several shortest strings round-trip; Rust's shortest mode need not).
    let mut sci = String::new();
    let _ = write!(sci, "{f:e}");
    let n = sci.split_once('e').map_or(sci.as_str(), |(m, _)| m).chars().filter(char::is_ascii_digit).count();
    let mut closest = String::new();
    let _ = write!(closest, "{:.*e}", n.saturating_sub(1), f);
    if closest.parse::<f64>().ok() == Some(f) {
        sci = closest;
    }
    let (neg, body) = match sci.strip_prefix('-') {
        Some(b) => (true, b),
        None => (false, sci.as_str()),
    };
    let (mant, exp) = body.split_once('e').unwrap_or((body, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: String = mant.chars().filter(char::is_ascii_digit).collect();
    let digits = if digits.is_empty() { String::from("0") } else { digits };
    if neg {
        out.push('-');
    }
    let nd = i32::try_from(digits.len()).unwrap_or(i32::MAX);
    if (-4..16).contains(&exp) {
        if exp >= 0 {
            let int_len = usize::try_from(exp.saturating_add(1)).unwrap_or(0);
            if nd <= exp.saturating_add(1) {
                out.push_str(&digits);
                for _ in 0..int_len.saturating_sub(digits.len()) {
                    out.push('0');
                }
                out.push_str(".0");
            } else {
                let (a, b) = digits.split_at(int_len.min(digits.len()));
                out.push_str(a);
                out.push('.');
                out.push_str(b);
            }
        } else {
            out.push_str("0.");
            for _ in 0..(-exp - 1) {
                out.push('0');
            }
            out.push_str(&digits);
        }
    } else {
        let mut cs = digits.chars();
        if let Some(c0) = cs.next() {
            out.push(c0);
        }
        let rest = cs.as_str();
        if !rest.is_empty() {
            out.push('.');
            out.push_str(rest);
        }
        let _ = write!(out, "e{}{:02}", if exp < 0 { '-' } else { '+' }, exp.unsigned_abs());
    }
}

fn write_value(v: &JsonValue, out: &mut String) {
    match v {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(true) => out.push_str("true"),
        JsonValue::Bool(false) => out.push_str("false"),
        JsonValue::Int(n) => {
            let _ = write!(out, "{n}");
        }
        JsonValue::Float(f) => write_float(*f, out),
        JsonValue::String(s) => write_string(s, out),
        JsonValue::Array(items) => {
            out.push('[');
            for (i, x) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(x, out);
            }
            out.push(']');
        }
        JsonValue::Object(members) => {
            let mut sorted: Vec<&(String, JsonValue)> = members.iter().collect();
            sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push('{');
            for (i, (k, x)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_value(x, out);
            }
            out.push('}');
        }
    }
}
