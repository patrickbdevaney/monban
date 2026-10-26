//! Minimal JSON reader/writer for the ssrf-corpus line protocol (copied from subjects/canon-subject/src/proto.rs;
//! it only frames the oracle's messages).

#[derive(Debug, Clone, PartialEq)]
pub enum Pj {
    Null,
    Bool(bool),
    Num(String),
    Str(Vec<u8>),
    Arr(Vec<Pj>),
    Obj(Vec<(Vec<u8>, Pj)>),
}

impl Pj {
    pub fn get(&self, key: &str) -> Option<&Pj> {
        match self {
            Pj::Obj(m) => m.iter().find(|(k, _)| k.as_slice() == key.as_bytes()).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Python truthiness (for `r.get(k) or default`).
    pub fn truthy(&self) -> bool {
        match self {
            Pj::Null => false,
            Pj::Bool(b) => *b,
            Pj::Num(n) => n.parse::<f64>().map(|f| f != 0.0).unwrap_or(true),
            Pj::Str(s) => !s.is_empty(),
            Pj::Arr(a) => !a.is_empty(),
            Pj::Obj(o) => !o.is_empty(),
        }
    }
}

struct P<'a> {
    s: &'a [u8],
    i: usize,
}

pub fn parse(s: &[u8]) -> Option<Pj> {
    let mut p = P { s, i: 0 };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    (p.i == s.len()).then_some(v)
}

fn push_wtf8(out: &mut Vec<u8>, cp: u32) {
    // Like UTF-8 but surrogates are encoded too (WTF-8 generalized), so they stay visible as invalid UTF-8.
    if cp < 0x80 {
        out.push(cp as u8);
    } else if cp < 0x800 {
        out.push(0xC0 | (cp >> 6) as u8);
        out.push(0x80 | (cp & 0x3F) as u8);
    } else if cp < 0x10000 {
        out.push(0xE0 | (cp >> 12) as u8);
        out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
        out.push(0x80 | (cp & 0x3F) as u8);
    } else {
        out.push(0xF0 | (cp >> 18) as u8);
        out.push(0x80 | ((cp >> 12) & 0x3F) as u8);
        out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
        out.push(0x80 | (cp & 0x3F) as u8);
    }
}

impl P<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }
    fn lit(&mut self, w: &[u8], v: Pj) -> Option<Pj> {
        if self.s.get(self.i..self.i + w.len()) == Some(w) {
            self.i += w.len();
            Some(v)
        } else {
            None
        }
    }
    fn value(&mut self, depth: usize) -> Option<Pj> {
        if depth > 512 {
            return None;
        }
        match self.peek()? {
            b'{' => {
                self.i += 1;
                let mut m = Vec::new();
                self.ws();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    return Some(Pj::Obj(m));
                }
                loop {
                    self.ws();
                    let k = self.string()?;
                    self.ws();
                    if self.peek()? != b':' {
                        return None;
                    }
                    self.i += 1;
                    self.ws();
                    let v = self.value(depth + 1)?;
                    m.push((k, v));
                    self.ws();
                    match self.peek()? {
                        b',' => self.i += 1,
                        b'}' => {
                            self.i += 1;
                            return Some(Pj::Obj(m));
                        }
                        _ => return None,
                    }
                }
            }
            b'[' => {
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Some(Pj::Arr(a));
                }
                loop {
                    self.ws();
                    a.push(self.value(depth + 1)?);
                    self.ws();
                    match self.peek()? {
                        b',' => self.i += 1,
                        b']' => {
                            self.i += 1;
                            return Some(Pj::Arr(a));
                        }
                        _ => return None,
                    }
                }
            }
            b'"' => self.string().map(Pj::Str),
            b't' => self.lit(b"true", Pj::Bool(true)),
            b'f' => self.lit(b"false", Pj::Bool(false)),
            b'n' => self.lit(b"null", Pj::Null),
            _ => {
                let st = self.i;
                while matches!(self.peek(), Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')) {
                    self.i += 1;
                }
                if st == self.i {
                    return None;
                }
                Some(Pj::Num(String::from_utf8_lossy(self.s.get(st..self.i)?).into_owned()))
            }
        }
    }
    fn hex4(&mut self) -> Option<u32> {
        let h = std::str::from_utf8(self.s.get(self.i..self.i + 4)?).ok()?;
        let v = u32::from_str_radix(h, 16).ok()?;
        self.i += 4;
        Some(v)
    }
    fn string(&mut self) -> Option<Vec<u8>> {
        if self.peek()? != b'"' {
            return None;
        }
        self.i += 1;
        let mut out = Vec::new();
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                b'"' => return Some(out),
                b'\\' => {
                    let e = self.peek()?;
                    self.i += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let u = self.hex4()?;
                            if (0xD800..0xDC00).contains(&u) && self.s.get(self.i..self.i + 2) == Some(b"\\u") {
                                let save = self.i;
                                self.i += 2;
                                let lo = self.hex4()?;
                                if (0xDC00..0xE000).contains(&lo) {
                                    push_wtf8(&mut out, 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00));
                                    continue;
                                }
                                self.i = save;
                            }
                            push_wtf8(&mut out, u);
                        }
                        _ => return None,
                    }
                }
                _ => out.push(c),
            }
        }
    }
}

/// Write `s` (UTF-8 expected; any invalid byte is written as U+FFFD) as an ASCII-only JSON string.
pub fn write_str(out: &mut String, s: &[u8]) {
    out.push('"');
    for ch in String::from_utf8_lossy(s).chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (' '..='~').contains(&c) => out.push(c),
            c => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{:04x}", u));
                }
            }
        }
    }
    out.push('"');
}
