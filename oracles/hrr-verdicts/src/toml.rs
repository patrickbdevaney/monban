//! Strict parser for the TOML subset used by tls/verdicts.toml: comments, `[a.b]` tables, `[[x]]` arrays of
//! tables, `key = value` with basic strings, decimal/hex integers, booleans and (multi-line) arrays of those.
//! Anything outside the subset is an error, never a silent misparse. (No crates: keeps the oracle's lock small.)

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    Array(Vec<Value>),
    Table(BTreeMap<String, Value>),
}

impl Value {
    pub fn get(&self, k: &str) -> Option<&Value> {
        match self {
            Value::Table(t) => t.get(k),
            _ => None,
        }
    }
    pub fn str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }
    pub fn bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn arr(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    pub fn table(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Table(t) => Some(t),
            _ => None,
        }
    }
}

struct P<'a> {
    s: &'a [u8],
    i: usize,
    line: usize,
}

impl<'a> P<'a> {
    fn err<T>(&self, m: &str) -> Result<T, String> {
        Err(format!("verdicts.toml line {}: {m}", self.line))
    }
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.i += 1;
        if c == b'\n' {
            self.line += 1;
        }
        Some(c)
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.bump();
        }
    }
    /// whitespace, newlines and comments (inside arrays)
    fn ws_nl(&mut self) {
        loop {
            match self.peek() {
                Some(b' ' | b'\t' | b'\r' | b'\n') => {
                    self.bump();
                }
                Some(b'#') => self.comment(),
                _ => break,
            }
        }
    }
    fn comment(&mut self) {
        while let Some(c) = self.peek() {
            if c == b'\n' {
                break;
            }
            self.bump();
        }
    }
    fn eol(&mut self) -> Result<(), String> {
        self.ws();
        if self.peek() == Some(b'#') {
            self.comment();
        }
        match self.peek() {
            None => Ok(()),
            Some(b'\r') | Some(b'\n') => {
                if self.peek() == Some(b'\r') {
                    self.bump();
                }
                if self.peek() == Some(b'\n') {
                    self.bump();
                }
                Ok(())
            }
            Some(c) => self.err(&format!("unexpected '{}' at end of line", c as char)),
        }
    }
    fn key(&mut self) -> Result<String, String> {
        self.ws();
        if self.peek() == Some(b'"') {
            return self.string();
        }
        let st = self.i;
        while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || c == b'_' || c == b'-') {
            self.bump();
        }
        if st == self.i {
            return self.err("expected key");
        }
        Ok(String::from_utf8_lossy(&self.s[st..self.i]).into_owned())
    }
    fn dotted(&mut self) -> Result<Vec<String>, String> {
        let mut v = vec![self.key()?];
        loop {
            self.ws();
            if self.peek() == Some(b'.') {
                self.bump();
                v.push(self.key()?);
            } else {
                return Ok(v);
            }
        }
    }
    fn string(&mut self) -> Result<String, String> {
        if self.bump() != Some(b'"') {
            return self.err("expected '\"'");
        }
        let mut out = Vec::new();
        loop {
            match self.bump() {
                None | Some(b'\n') => return self.err("unterminated string"),
                Some(b'"') => break,
                Some(b'\\') => match self.bump() {
                    Some(b'"') => out.push(b'"'),
                    Some(b'\\') => out.push(b'\\'),
                    Some(b'n') => out.push(b'\n'),
                    Some(b't') => out.push(b'\t'),
                    _ => return self.err("unsupported escape"),
                },
                Some(c) => out.push(c),
            }
        }
        String::from_utf8(out).or_else(|_| self.err("invalid utf-8"))
    }
    fn value(&mut self) -> Result<Value, String> {
        self.ws();
        match self.peek() {
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b'[') => {
                self.bump();
                let mut v = Vec::new();
                loop {
                    self.ws_nl();
                    if self.peek() == Some(b']') {
                        self.bump();
                        break;
                    }
                    v.push(self.value()?);
                    self.ws_nl();
                    match self.peek() {
                        Some(b',') => {
                            self.bump();
                        }
                        Some(b']') => {
                            self.bump();
                            break;
                        }
                        _ => return self.err("expected ',' or ']' in array"),
                    }
                }
                Ok(Value::Array(v))
            }
            Some(b't') if self.s[self.i..].starts_with(b"true") => {
                self.i += 4;
                Ok(Value::Bool(true))
            }
            Some(b'f') if self.s[self.i..].starts_with(b"false") => {
                self.i += 5;
                Ok(Value::Bool(false))
            }
            Some(c) if c.is_ascii_digit() || c == b'-' || c == b'+' => {
                let st = self.i;
                while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'+') {
                    self.bump();
                }
                let t = String::from_utf8_lossy(&self.s[st..self.i]).replace('_', "");
                let r = if let Some(h) = t.strip_prefix("0x") {
                    i64::from_str_radix(h, 16)
                } else {
                    t.parse::<i64>()
                };
                r.map(Value::Int).or_else(|_| self.err(&format!("bad integer '{t}'")))
            }
            _ => self.err("unsupported value"),
        }
    }
}

fn insert(root: &mut BTreeMap<String, Value>, path: &[String], k: String, v: Value, line: usize) -> Result<(), String> {
    let mut t = root;
    for p in path {
        let e = t.get_mut(p).ok_or_else(|| format!("line {line}: missing table {p}"))?;
        t = match e {
            Value::Table(m) => m,
            Value::Array(a) => match a.last_mut() {
                Some(Value::Table(m)) => m,
                _ => return Err(format!("line {line}: {p} is not a table")),
            },
            _ => return Err(format!("line {line}: {p} is not a table")),
        };
    }
    if t.contains_key(&k) {
        return Err(format!("line {line}: duplicate key {k}"));
    }
    t.insert(k, v);
    Ok(())
}

fn open(root: &mut BTreeMap<String, Value>, path: &[String], array: bool, line: usize) -> Result<(), String> {
    let mut t = root;
    for (n, p) in path.iter().enumerate() {
        let last = n + 1 == path.len();
        if last && array {
            let e = t.entry(p.clone()).or_insert_with(|| Value::Array(Vec::new()));
            match e {
                Value::Array(a) => a.push(Value::Table(BTreeMap::new())),
                _ => return Err(format!("line {line}: {p} redefined as array of tables")),
            }
            return Ok(());
        }
        let e = t.entry(p.clone()).or_insert_with(|| Value::Table(BTreeMap::new()));
        t = match e {
            Value::Table(m) => m,
            Value::Array(a) => match a.last_mut() {
                Some(Value::Table(m)) => m,
                _ => return Err(format!("line {line}: {p} is not a table")),
            },
            _ => return Err(format!("line {line}: {p} is not a table")),
        };
    }
    Ok(())
}

pub fn parse(src: &str) -> Result<Value, String> {
    let mut root = BTreeMap::new();
    let mut cur: Vec<String> = Vec::new();
    let mut p = P { s: src.as_bytes(), i: 0, line: 1 };
    loop {
        p.ws_nl();
        match p.peek() {
            None => break,
            Some(b'[') => {
                p.bump();
                let array = p.peek() == Some(b'[');
                if array {
                    p.bump();
                }
                let path = p.dotted()?;
                p.ws();
                if p.bump() != Some(b']') || (array && p.bump() != Some(b']')) {
                    return p.err("expected ']'");
                }
                p.eol()?;
                open(&mut root, &path, array, p.line)?;
                cur = path;
            }
            Some(_) => {
                let line = p.line;
                let k = p.key()?;
                p.ws();
                if p.bump() != Some(b'=') {
                    return p.err("expected '='");
                }
                let v = p.value()?;
                p.eol()?;
                insert(&mut root, &cur, k, v, line)?;
            }
        }
    }
    Ok(Value::Table(root))
}
