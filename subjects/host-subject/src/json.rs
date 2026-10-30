//! Minimal strict JSON reader (RFC 8259), copied from subjects/pg-subject (from subjects/admission-subject, after `xtask/src/json.rs`).
//!
//! Differences: numbers are kept as their validated source text (so a request id is echoed byte-exact), and
//! the grammar of numbers is checked strictly. Duplicate keys and trailing input are rejected.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    pub fn get(&self, k: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.get(k),
            _ => None,
        }
    }
    pub fn str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
}

pub fn parse(s: &str) -> Result<Json, String> {
    let mut p = P { b: s.as_bytes(), i: 0, depth: 0 };
    let v = p.value()?;
    p.ws();
    if p.i != p.b.len() {
        return Err(format!("trailing input at byte {}", p.i));
    }
    Ok(v)
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
}

impl P<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn bump(&mut self) {
        self.i = self.i.saturating_add(1);
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump();
        }
    }
    fn eat(&mut self, lit: &str) -> Result<(), String> {
        let end = self.i.saturating_add(lit.len());
        if self.b.get(self.i..end) == Some(lit.as_bytes()) {
            self.i = end;
            Ok(())
        } else {
            Err(format!("expected {lit} at byte {}", self.i))
        }
    }
    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        if self.depth >= 64 {
            return Err("nesting too deep".into());
        }
        self.depth += 1;
        let v = match self.peek() {
            Some(b'n') => self.eat("null").map(|_| Json::Null),
            Some(b't') => self.eat("true").map(|_| Json::Bool(true)),
            Some(b'f') => self.eat("false").map(|_| Json::Bool(false)),
            Some(b'"') => self.string().map(Json::Str),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(format!("unexpected byte at {}", self.i)),
        };
        self.depth -= 1;
        v
    }
    fn array(&mut self) -> Result<Json, String> {
        self.bump();
        let mut v = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.bump();
            return Ok(Json::Arr(v));
        }
        loop {
            v.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(b',') => self.bump(),
                Some(b']') => {
                    self.bump();
                    return Ok(Json::Arr(v));
                }
                _ => return Err(format!("bad array at {}", self.i)),
            }
        }
    }
    fn object(&mut self) -> Result<Json, String> {
        self.bump();
        let mut m = BTreeMap::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok(Json::Obj(m));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(format!("expected key at {}", self.i));
            }
            let k = self.string()?;
            self.ws();
            self.eat(":")?;
            let v = self.value()?;
            if m.contains_key(&k) {
                return Err(format!("duplicate key {k:?}"));
            }
            m.insert(k, v);
            self.ws();
            match self.peek() {
                Some(b',') => self.bump(),
                Some(b'}') => {
                    self.bump();
                    return Ok(Json::Obj(m));
                }
                _ => return Err(format!("bad object at {}", self.i)),
            }
        }
    }
    fn digits(&mut self) -> usize {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.bump();
        }
        self.i - start
    }
    /// RFC 8259 number: `-? (0 | [1-9][0-9]*) (\.[0-9]+)? ([eE][+-]?[0-9]+)?`.
    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        let bad = |i: usize| format!("bad number at byte {i}");
        if self.peek() == Some(b'-') {
            self.bump();
        }
        match self.peek() {
            Some(b'0') => self.bump(),
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(bad(start)),
        }
        if self.peek() == Some(b'.') {
            self.bump();
            if self.digits() == 0 {
                return Err(bad(start));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.bump();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump();
            }
            if self.digits() == 0 {
                return Err(bad(start));
            }
        }
        let t = self.b.get(start..self.i).ok_or_else(|| bad(start))?;
        let t = std::str::from_utf8(t).map_err(|e| e.to_string())?;
        Ok(Json::Num(t.to_string()))
    }
    fn hex4(&mut self) -> Result<u32, String> {
        let end = self.i.saturating_add(4);
        let h = self.b.get(self.i..end).ok_or("short \\u escape")?;
        let s = std::str::from_utf8(h).map_err(|e| e.to_string())?;
        if !s.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("bad \\u escape {s:?}"));
        }
        self.i = end;
        u32::from_str_radix(s, 16).map_err(|_| format!("bad \\u escape {s:?}"))
    }
    fn string(&mut self) -> Result<String, String> {
        self.bump();
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or("unterminated string")?;
            match c {
                b'"' => {
                    self.bump();
                    return Ok(out);
                }
                b'\\' => {
                    self.bump();
                    let e = self.peek().ok_or("bad escape")?;
                    self.bump();
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                self.eat("\\u")?;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err("lone high surrogate".into());
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err("lone low surrogate".into());
                            } else {
                                hi
                            };
                            out.push(char::from_u32(cp).ok_or("bad code point")?);
                        }
                        _ => return Err("bad escape".into()),
                    }
                }
                c if c < 0x20 => return Err("control byte in string".into()),
                _ => {
                    // Copy the run of plain bytes up to the next quote, backslash or control byte. The input is a
                    // &str, so any run that ends on an ASCII byte is valid UTF-8.
                    let start = self.i;
                    while matches!(self.peek(), Some(b) if b != b'"' && b != b'\\' && b >= 0x20) {
                        self.bump();
                    }
                    let seq = self.b.get(start..self.i).ok_or("truncated string")?;
                    out.push_str(std::str::from_utf8(seq).map_err(|e| e.to_string())?);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_rejects() {
        let v = parse(r#"{"a":[1,true,null,"xé😀"],"b":{"c":-2.5e3},"n":18446744073709551615}"#);
        assert!(matches!(v, Ok(Json::Obj(_))));
        assert_eq!(v.ok().and_then(|j| j.get("n").cloned()), Some(Json::Num("18446744073709551615".into())));
        for bad in [r#"{"a":1,"a":2}"#, "[1] x", r#""\ud800""#, "01", "1.", "-", "1e", "+1", r#""\u00g0""#] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        assert_eq!(parse(r#""é\n""#), Ok(Json::Str("é\n".into())));
    }
}
