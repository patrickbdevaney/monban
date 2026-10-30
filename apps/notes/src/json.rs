//! The little JSON this app needs: one flat request object (string, integer, boolean and null members; anything
//! nested is refused) and string escaping for replies. Strict: duplicate member names, trailing bytes, fractions,
//! exponents, leading zeros and unpaired surrogates are refused. Bounded by the input (the host caps the body).

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Val {
    Str(String),
    Int(i64),
    Bool(bool),
    Null,
}

struct P<'a> {
    s: &'a [u8],
    i: usize,
}

impl P<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.i = self.i.saturating_add(1);
        Some(c)
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i = self.i.saturating_add(1);
        }
    }
    fn eat(&mut self, c: u8) -> Option<()> {
        (self.bump()? == c).then_some(())
    }
    fn lit(&mut self, w: &[u8]) -> Option<()> {
        for &c in w {
            self.eat(c)?;
        }
        Some(())
    }
    fn hex4(&mut self) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..4 {
            v = (v << 4) | char::from(self.bump()?).to_digit(16)?;
        }
        Some(v)
    }
    fn string(&mut self) -> Option<String> {
        self.eat(b'"')?;
        let mut out = String::new();
        loop {
            let c = self.bump()?;
            match c {
                b'"' => return Some(out),
                b'\\' => {
                    let ch = match self.bump()? {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                self.lit(b"\\u")?;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return None;
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                hi
                            };
                            char::from_u32(cp)?
                        }
                        _ => return None,
                    };
                    out.push(ch);
                }
                0..=0x1f => return None,
                _ => {
                    // Copy one UTF-8 sequence (the input was validated as UTF-8 up front).
                    let start = self.i.saturating_sub(1);
                    let len = match c {
                        0x00..=0x7f => 1,
                        0xc0..=0xdf => 2,
                        0xe0..=0xef => 3,
                        _ => 4,
                    };
                    let end = start.saturating_add(len);
                    let seq = self.s.get(start..end)?;
                    out.push_str(core::str::from_utf8(seq).ok()?);
                    self.i = end;
                }
            }
        }
    }
    fn int(&mut self) -> Option<i64> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i = self.i.saturating_add(1);
        }
        let digits = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i = self.i.saturating_add(1);
        }
        let d = self.s.get(digits..self.i)?;
        if d.is_empty() || (d.len() > 1 && d.first() == Some(&b'0')) {
            return None;
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return None;
        }
        core::str::from_utf8(self.s.get(start..self.i)?).ok()?.parse().ok()
    }
    fn value(&mut self) -> Option<Val> {
        match self.peek()? {
            b'"' => self.string().map(Val::Str),
            b't' => self.lit(b"true").map(|()| Val::Bool(true)),
            b'f' => self.lit(b"false").map(|()| Val::Bool(false)),
            b'n' => self.lit(b"null").map(|()| Val::Null),
            b'-' | b'0'..=b'9' => self.int().map(Val::Int),
            _ => None,
        }
    }
}

/// Parse a flat JSON object. `None` for anything else.
pub fn parse_object(input: &[u8]) -> Option<Vec<(String, Val)>> {
    core::str::from_utf8(input).ok()?;
    let mut p = P { s: input, i: 0 };
    p.ws();
    p.eat(b'{')?;
    let mut out: Vec<(String, Val)> = Vec::new();
    p.ws();
    if p.peek() == Some(b'}') {
        p.bump()?;
    } else {
        loop {
            p.ws();
            let k = p.string()?;
            p.ws();
            p.eat(b':')?;
            p.ws();
            let v = p.value()?;
            if out.iter().any(|(n, _)| *n == k) {
                return None;
            }
            out.push((k, v));
            p.ws();
            match p.bump()? {
                b',' => continue,
                b'}' => break,
                _ => return None,
            }
        }
    }
    p.ws();
    (p.i == input.len()).then_some(out)
}

pub fn get<'a>(obj: &'a [(String, Val)], name: &str) -> Option<&'a Val> {
    obj.iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

/// Append `s` as a JSON string literal.
pub fn push_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 || c == '\u{2028}' || c == '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn objects() {
        let o = parse_object(br#" {"a":"x\u00e9\ud83d\ude00","b":-3,"c":true,"d":null} "#).unwrap();
        assert_eq!(get(&o, "a"), Some(&Val::Str("x\u{e9}\u{1f600}".into())));
        assert_eq!(get(&o, "b"), Some(&Val::Int(-3)));
        assert_eq!(parse_object(b"{}").unwrap(), vec![]);
        for bad in [
            &b"[]"[..],
            b"{\"a\":1,\"a\":2}",
            b"{\"a\":1.5}",
            b"{\"a\":01}",
            b"{\"a\":{}}",
            b"{} x",
            b"{\"a\":\"\\ud800\"}",
        ] {
            assert!(parse_object(bad).is_none(), "{:?}", String::from_utf8_lossy(bad));
        }
        let mut s = String::new();
        push_str(&mut s, "a\"\\\n\u{1}");
        assert_eq!(s, "\"a\\\"\\\\\\n\\u0001\"");
    }
}
