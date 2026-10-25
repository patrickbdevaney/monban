//! Minimal strict JSON parser (RFC 8259) for reading `cargo metadata` and API responses.
//! Rejects duplicate object keys and trailing input, matching the repo's reject-don't-repair rule.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
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
    pub fn arr(&self) -> &[Json] {
        match self {
            Json::Arr(v) => v,
            _ => &[],
        }
    }
    pub fn path(&self, keys: &[&str]) -> Option<&Json> {
        keys.iter().try_fold(self, |j, k| j.get(k))
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
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }
    fn eat(&mut self, lit: &str) -> Result<(), String> {
        if self.b.get(self.i..self.i + lit.len()) == Some(lit.as_bytes()) {
            self.i += lit.len();
            Ok(())
        } else {
            Err(format!("expected {lit} at byte {}", self.i))
        }
    }
    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        self.depth += 1;
        if self.depth > 256 {
            return Err("nesting too deep".into());
        }
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
        self.i += 1;
        let mut v = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Json::Arr(v));
        }
        loop {
            v.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Json::Arr(v));
                }
                _ => return Err(format!("bad array at {}", self.i)),
            }
        }
    }
    fn object(&mut self) -> Result<Json, String> {
        self.i += 1;
        let mut m = BTreeMap::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
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
            if m.insert(k.clone(), v).is_some() {
                return Err(format!("duplicate key {k:?}"));
            }
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Json::Obj(m));
                }
                _ => return Err(format!("bad object at {}", self.i)),
            }
        }
    }
    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        while matches!(self.peek(), Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')) {
            self.i += 1;
        }
        let t = std::str::from_utf8(self.b.get(start..self.i).unwrap_or_default()).map_err(|e| e.to_string())?;
        t.parse::<f64>().map(Json::Num).map_err(|_| format!("bad number {t:?}"))
    }
    fn hex4(&mut self) -> Result<u32, String> {
        let h = self.b.get(self.i..self.i + 4).ok_or("short \\u escape")?;
        let s = std::str::from_utf8(h).map_err(|e| e.to_string())?;
        self.i += 4;
        u32::from_str_radix(s, 16).map_err(|_| format!("bad \\u escape {s:?}"))
    }
    fn string(&mut self) -> Result<String, String> {
        self.i += 1;
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or("unterminated string")?;
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = self.peek().ok_or("bad escape")?;
                    self.i += 1;
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
                    // Copy the full UTF-8 sequence starting at c.
                    let start = self.i - 1;
                    let len = match c {
                        0x00..=0x7F => 1,
                        0xC0..=0xDF => 2,
                        0xE0..=0xEF => 3,
                        _ => 4,
                    };
                    let seq = self.b.get(start..start + len).ok_or("truncated utf-8")?;
                    out.push_str(std::str::from_utf8(seq).map_err(|e| e.to_string())?);
                    self.i = start + len;
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
        let v = parse(r#"{"a":[1,true,null,"xé😀"],"b":{"c":-2.5e3}}"#);
        assert!(matches!(v, Ok(Json::Obj(_))));
        assert!(parse(r#"{"a":1,"a":2}"#).is_err());
        assert!(parse(r#"[1] x"#).is_err());
        assert!(parse(r#""\ud800""#).is_err());
        assert_eq!(parse(r#""é""#), Ok(Json::Str("é".into())));
    }
}
