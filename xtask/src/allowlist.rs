//! `cargo xtask allowlist-lock [--check|--self-test]`: every committed `allowlist.<adapter>.lock` must be
//! byte-identical to the lock regenerated from its sibling `allowlist.<adapter>.decl` (gate allowlist-lock,
//! R-DB-3/4; P4-datair-001).
//!
//! xtask has no dependencies on purpose (see its Cargo.toml), so it cannot link `aegis_data_ir`. This file is
//! therefore an independent second implementation of the F4 lock format and the lock.rs declaration rules, with its
//! own FIPS 180-4 SHA-256. The denylist is not copied: it is read from the F4 source (`DenyEntry { item: ".." }` in
//! the `SQLITE_DENY` / `PG_DENY` / `RESP_DENY` tables of crates/aegis-data-ir/src/ir.rs), and a missing or empty
//! table fails the gate. The production generator is `aegis_data_ir::generate` (lock.rs + AWS-LC SHA-256, CLI:
//! `datair-subject lock <decl>`); crates/aegis-data-ir/tests/lock.rs regenerates every committed lock with it, so
//! both implementations must agree byte for byte on every lock in the repository.
//!
//! `--check` (default): find every declaration/lock pair (orphans fail; zero pairs fail), regenerate each lock
//! in-process and in two child processes that differ in LC_ALL/LANG, TZ, working directory, HOME and
//! SOURCE_DATE_EPOCH (each child also draws its own std hash seed; the generator uses no hash map), and require all
//! three to equal the committed bytes.
//! `--self-test`: the positive controls must pass, and every mutant must be caught: a mutated declaration, mutated
//! locks (byte flip, recomputed hash over a mutated body, reordered lines, CRLF, extra newline), denylisted entries
//! (Redis EVAL/FLUSHALL, SQLite REPLACE), an orphan lock, a broken denylist source and wrong SHA-256 vectors.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

const DECL_HEADER: &str = "aegis-allowlist-decl v1";
const LOCK_HEADER: &str = "aegis-allowlist-lock v1";
const LOCK_MAX_LINE: usize = 4096;
const MAX_PRED_DEPTH: usize = 64;
const KINDS: [&str; 5] = ["select", "insert", "update", "delete", "upsert"];
const FAMILIES: [&str; 4] = ["sqlite", "postgres", "redis", "valkey"];

// ------------------------------------------------------------------------------------------------- SHA-256

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] =
        [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    let mut data = msg.to_vec();
    let bits = (msg.len() as u64).wrapping_mul(8);
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bits.to_be_bytes());
    for block in data.as_chunks::<64>().0 {
        let mut w: Vec<u32> = block.as_chunks::<4>().0.iter().map(|c| u32::from_be_bytes(*c)).collect();
        let at = |w: &[u32], i: usize| w.get(i).copied().unwrap_or(0);
        for t in 16..64 {
            let (w15, w2) = (at(&w, t - 15), at(&w, t - 2));
            let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
            let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
            w.push(at(&w, t - 16).wrapping_add(s0).wrapping_add(at(&w, t - 7)).wrapping_add(s1));
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for (k, wt) in K.iter().zip(w.iter()) {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(*k).wrapping_add(*wt);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            (hh, g, f, e, d, c, b, a) = (g, f, e, d.wrapping_add(t1), c, b, a, t1.wrapping_add(t2));
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 32];
    for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(h) {
        *chunk = word.to_be_bytes();
    }
    out
}

fn sha256_hex(msg: &[u8]) -> String {
    sha256(msg).iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_kats() -> Vec<String> {
    let million_a = vec![b'a'; 1_000_000];
    let cases: [(&[u8], &str); 4] = [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (&million_a, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
    ];
    cases
        .iter()
        .filter(|(m, want)| sha256_hex(m) != *want)
        .map(|(m, _)| format!("sha256 known-answer mismatch on a {}-byte message", m.len()))
        .collect()
}

// ------------------------------------------------------------------------------------------------- denylist

/// Denylisted items per family, read from the F4 source.
#[derive(Clone, Debug)]
struct Deny {
    sqlite: Vec<String>,
    postgres: Vec<String>,
    resp: Vec<String>,
}

impl Deny {
    fn parse(src: &str) -> Result<Deny, String> {
        let table = |name: &str| -> Result<Vec<String>, String> {
            let start = src
                .find(&format!("const {name}: &[DenyEntry] = &["))
                .ok_or_else(|| format!("denylist table {name} not found in ir.rs"))?;
            let rest = src.get(start..).unwrap_or_default();
            let end = rest.find("];").ok_or_else(|| format!("denylist table {name} unterminated"))?;
            let body = rest.get(..end).unwrap_or_default();
            let items: Vec<String> =
                body.split("item: \"").skip(1).filter_map(|s| s.split('"').next()).map(str::to_string).collect();
            if items.is_empty() || items.iter().any(|i| i.is_empty() || i.bytes().any(|c| c.is_ascii_lowercase())) {
                return Err(format!("denylist table {name} is empty or malformed"));
            }
            Ok(items)
        };
        Ok(Deny { sqlite: table("SQLITE_DENY")?, postgres: table("PG_DENY")?, resp: table("RESP_DENY")? })
    }
    fn load(root: &Path) -> Result<Deny, String> {
        let p = root.join("crates/aegis-data-ir/src/ir.rs");
        Deny::parse(&std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?)
    }
    fn hit(&self, family: &str, word: &str) -> Option<String> {
        let list = match family {
            "sqlite" => &self.sqlite,
            "postgres" => &self.postgres,
            _ => &self.resp,
        };
        list.iter().find(|d| d.eq_ignore_ascii_case(word)).cloned()
    }
}

// ------------------------------------------------------------------------------------------------- grammar

fn valid_backend_id(s: &str) -> bool {
    let b = s.as_bytes();
    match b.split_first() {
        Some((f, rest)) => {
            f.is_ascii_lowercase()
                && rest.len() <= 31
                && rest.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        }
        None => false,
    }
}

fn valid_collection(s: &str) -> bool {
    let b = s.as_bytes();
    match b.split_first() {
        Some((f, rest)) => {
            (f.is_ascii_lowercase() || *f == b'_')
                && rest.len() < 63
                && rest.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
        }
        None => false,
    }
}

fn num(s: &str) -> Option<u32> {
    let ok = !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    if ok { s.parse().ok() } else { None }
}

/// `-` or a comma list of canonical decimal numbers.
fn fields(s: &str) -> Option<Vec<u32>> {
    if s == "-" { Some(Vec::new()) } else { s.split(',').map(num).collect() }
}

fn canon_fields(mut v: Vec<u32>) -> String {
    v.sort_unstable();
    v.dedup();
    if v.is_empty() { "-".into() } else { v.iter().map(u32::to_string).collect::<Vec<_>>().join(",") }
}

/// Parsed value-free shape.
#[derive(Clone, Debug, PartialEq)]
enum Shape {
    Tt,
    Ff,
    Atom(&'static str, u32),
    Bin(bool, Box<Shape>, Box<Shape>),
    Not(Box<Shape>),
}

impl Shape {
    fn reads(&self, out: &mut Vec<u32>) {
        match self {
            Shape::Atom(_, f) => out.push(*f),
            Shape::Bin(_, a, b) => {
                a.reads(out);
                b.reads(out);
            }
            Shape::Not(a) => a.reads(out),
            Shape::Tt | Shape::Ff => {}
        }
    }
    fn has_not(&self) -> bool {
        match self {
            Shape::Not(_) => true,
            Shape::Bin(_, a, b) => a.has_not() || b.has_not(),
            _ => false,
        }
    }
    fn connectives(&self, out: &mut Vec<&'static str>) {
        match self {
            Shape::Bin(and, a, b) => {
                out.push(if *and { "AND" } else { "OR" });
                a.connectives(out);
                b.connectives(out);
            }
            Shape::Not(a) => {
                out.push("NOT");
                a.connectives(out);
            }
            _ => {}
        }
    }
    fn render(&self, out: &mut String) {
        match self {
            Shape::Tt => out.push_str("tt"),
            Shape::Ff => out.push_str("ff"),
            Shape::Atom(tag, f) => out.push_str(&format!("{tag}({f})")),
            Shape::Bin(and, a, b) => {
                out.push_str(if *and { "and(" } else { "or(" });
                a.render(out);
                out.push(',');
                b.render(out);
                out.push(')');
            }
            Shape::Not(a) => {
                out.push_str("not(");
                a.render(out);
                out.push(')');
            }
        }
    }
}

fn parse_shape(s: &str) -> Option<Shape> {
    fn take<'a>(s: &'a str, lit: &str) -> Option<&'a str> {
        s.strip_prefix(lit)
    }
    fn go(s: &str, budget: usize) -> Option<(Shape, &str)> {
        let budget = budget.checked_sub(1)?;
        let word_len = s.bytes().take_while(u8::is_ascii_lowercase).count();
        let (word, rest) = s.split_at_checked(word_len)?;
        match word {
            "tt" => Some((Shape::Tt, rest)),
            "ff" => Some((Shape::Ff, rest)),
            "eq" | "in" | "range" | "pfx" => {
                let tag: &'static str = match word {
                    "eq" => "eq",
                    "in" => "in",
                    "range" => "range",
                    _ => "pfx",
                };
                let rest = take(rest, "(")?;
                let n = rest.bytes().take_while(u8::is_ascii_digit).count();
                let (digits, rest) = rest.split_at_checked(n)?;
                Some((Shape::Atom(tag, num(digits)?), take(rest, ")")?))
            }
            "and" | "or" => {
                let (a, rest) = go(take(rest, "(")?, budget)?;
                let (b, rest) = go(take(rest, ",")?, budget)?;
                Some((Shape::Bin(word == "and", Box::new(a), Box::new(b)), take(rest, ")")?))
            }
            "not" => {
                let (a, rest) = go(take(rest, "(")?, budget)?;
                Some((Shape::Not(Box::new(a)), take(rest, ")")?))
            }
            _ => None,
        }
    }
    match go(s, MAX_PRED_DEPTH)? {
        (shape, "") => Some(shape),
        _ => None,
    }
}

#[derive(Clone, Debug)]
struct DSchema {
    tenant: u32,
    keys: Vec<u32>,
    cols: Vec<u32>,
    permitted: Vec<u32>,
}

#[derive(Clone, Debug)]
struct DOp {
    line: usize,
    coll: String,
    kind: &'static str,
    shape: Shape,
    writes: Vec<u32>,
    returning: Vec<u32>,
}

fn e(line: usize, msg: &str) -> String {
    format!("line {line}: {msg}")
}

fn parse_schema(line: &str) -> Option<(String, DSchema)> {
    let t: Vec<&str> = line.split(' ').collect();
    let [kw, coll, tenant, key, cols, permitted] = t.as_slice() else { return None };
    if *kw != "schema" || !valid_collection(coll) {
        return None;
    }
    let tenant = num(tenant.strip_prefix("tenant=")?)?;
    let keys = fields(key.strip_prefix("key=")?)?;
    let cols = fields(cols.strip_prefix("cols=")?)?;
    let permitted = fields(permitted.strip_prefix("permitted=")?)?;
    let mut uniq = cols.clone();
    uniq.sort_unstable();
    uniq.dedup();
    let known = |f: &u32| uniq.contains(f);
    if keys.iter().all(|k| *k == tenant)
        || uniq.len() != cols.len()
        || !known(&tenant)
        || !keys.iter().all(known)
        || !permitted.iter().all(known)
    {
        return None;
    }
    // Non-tenant key columns only: the tenant is part of the arbiter anyway.
    let mut keys: Vec<u32> = keys.into_iter().filter(|k| *k != tenant).collect();
    keys.sort_unstable();
    keys.dedup();
    Some((coll.to_string(), DSchema { tenant, keys, cols: uniq, permitted }))
}

fn parse_op(line: &str, n: usize, family: &str, deny: &Deny) -> Result<DOp, String> {
    let t: Vec<&str> = line.split(' ').collect();
    let [kw, coll, kind, shape, w, r] = t.as_slice() else { return Err(e(n, "malformed op line")) };
    if *kw != "op" || !valid_collection(coll) {
        return Err(e(n, "malformed op line"));
    }
    let Some(kind) = KINDS.iter().find(|k| *k == kind).copied() else {
        return Err(match deny.hit(family, kind) {
            Some(item) => e(n, &format!("denylisted {item} (kind token)")),
            None => e(n, &format!("unknown op kind {kind:?}")),
        });
    };
    let shape = parse_shape(shape).ok_or_else(|| e(n, "malformed or too deep shape"))?;
    let writes = w.strip_prefix("w=").and_then(fields).ok_or_else(|| e(n, "malformed w="))?;
    let returning = r.strip_prefix("r=").and_then(fields).ok_or_else(|| e(n, "malformed r="))?;
    Ok(DOp { line: n, coll: coll.to_string(), kind, shape, writes, returning })
}

/// F4 check_schema + lower_op (SQL) or kv_plan (KV) rules over the declaration's all-Binary schema, then the
/// native word skeleton against the denylist. Returns the canonical lock line.
fn validate(op: &DOp, s: &DSchema, family: &str, deny: &Deny) -> Result<String, String> {
    let n = op.line;
    let kv = family == "redis" || family == "valkey";
    let mut reads = Vec::new();
    op.shape.reads(&mut reads);
    if let Some(f) = reads.iter().chain(&op.writes).chain(&op.returning).find(|f| !s.cols.contains(f)) {
        return Err(e(n, &format!("unknown field {f}")));
    }
    if op.writes.contains(&s.tenant) {
        return Err(e(n, "tenant field written"));
    }
    if let Some(f) = op.returning.iter().find(|f| !s.permitted.contains(f)) {
        return Err(e(n, &format!("returning field {f} not permitted")));
    }
    if kv && op.shape.has_not() {
        return Err(e(n, "Not requires an exact adapter"));
    }
    let only_writes = |allowed: &[u32]| op.writes.iter().all(|f| allowed.contains(f));
    let count = |f: u32| op.writes.iter().filter(|w| **w == f).count();
    let words: Vec<&'static str> = if kv {
        let rest: Vec<u32> = s.cols.iter().copied().filter(|c| *c != s.tenant).collect();
        let (kf, vf) = match (s.cols.len(), s.keys.as_slice(), rest.as_slice()) {
            (3, [k], [a, b]) if a == k || b == k => (*k, if a == k { *b } else { *a }),
            _ => return Err(e(n, "not a key-value schema (tenant, one key, one value)")),
        };
        let eq_key = op.shape == Shape::Atom("eq", kf);
        let bad = |m: &str| Err(e(n, m));
        match op.kind {
            "select" if op.writes.is_empty() => {
                if eq_key {
                    vec!["GET"]
                } else if op.shape == Shape::Tt || op.shape == Shape::Atom("pfx", kf) {
                    vec!["SCAN", "MATCH", "COUNT"]
                } else {
                    return bad("unsupported kv filter");
                }
            }
            "insert" | "upsert" if op.shape == Shape::Tt => {
                if op.writes.len() != 2 || !only_writes(&[kf, vf]) || count(kf) != 1 || count(vf) != 1 {
                    return bad("unsupported kv write");
                }
                if op.kind == "insert" { vec!["SET", "NX"] } else { vec!["SET"] }
            }
            "update" => {
                if !eq_key {
                    return bad("unsupported kv filter");
                }
                if op.writes.len() != 1 || !only_writes(&[vf]) {
                    return bad("unsupported kv write");
                }
                vec!["SET", "XX"]
            }
            "delete" if op.writes.is_empty() => {
                if !eq_key {
                    return bad("unsupported kv filter");
                }
                vec!["DEL"]
            }
            "insert" | "upsert" => return bad("unsupported kv filter"),
            _ => return bad("unsupported kv write"),
        }
    } else {
        if let Some(f) = op.writes.iter().find(|f| count(**f) > 1) {
            return Err(e(n, &format!("duplicate write {f}")));
        }
        let mut w: Vec<&'static str> = Vec::new();
        match op.kind {
            "select" | "delete" => {
                if !op.writes.is_empty() {
                    return Err(e(n, "select/delete write nothing"));
                }
                w.extend(if op.kind == "select" { ["SELECT", "FROM", "WHERE"] } else { ["DELETE", "FROM", "WHERE"] });
                w.push("AND");
                op.shape.connectives(&mut w);
            }
            "update" => {
                if op.writes.is_empty() {
                    return Err(e(n, "update sets nothing"));
                }
                if let Some(f) = op.writes.iter().find(|f| s.keys.contains(f)) {
                    return Err(e(n, &format!("update writes key column {f}")));
                }
                w.extend(["UPDATE", "SET", "WHERE", "AND"]);
                op.shape.connectives(&mut w);
            }
            _ => {
                if op.shape != Shape::Tt {
                    return Err(e(n, "insert/upsert take no filter"));
                }
                if let Some(k) = s.keys.iter().find(|k| !op.writes.contains(k)) {
                    return Err(e(n, &format!("insert/upsert lacks key column {k}")));
                }
                w.extend(["INSERT", "INTO", "VALUES"]);
                if op.kind == "upsert" {
                    w.extend(["ON", "CONFLICT", "DO"]);
                    if op.writes.iter().all(|f| s.keys.contains(f)) {
                        w.push("NOTHING");
                    } else {
                        w.extend(["UPDATE", "SET", "WHERE"]);
                    }
                }
            }
        }
        if !op.returning.is_empty() {
            w.push("RETURNING");
        }
        w
    };
    if let Some(item) = words.iter().find_map(|x| deny.hit(family, x)) {
        return Err(e(n, &format!("denylisted {item}")));
    }
    let mut shape = String::new();
    op.shape.render(&mut shape);
    let line = format!(
        "op {} {} {shape} w={} r={}",
        op.coll,
        op.kind,
        canon_fields(op.writes.clone()),
        canon_fields(op.returning.clone())
    );
    if line.len() > LOCK_MAX_LINE {
        return Err(e(n, "entry longer than LOCK_MAX_LINE"));
    }
    Ok(line)
}

/// Independent lock generator: declaration text → full lock file (body + sha256 trailer). Returns the adapter
/// named by the declaration too.
fn generate(decl: &str, deny: &Deny) -> Result<(String, String), String> {
    let mut lines = decl.split('\n').enumerate().map(|(i, l)| (i + 1, l));
    if lines.next().map(|(_, l)| l) != Some(DECL_HEADER) {
        return Err(e(1, "missing declaration header"));
    }
    let adapter = lines
        .next()
        .and_then(|(_, l)| l.strip_prefix("adapter "))
        .filter(|a| valid_backend_id(a))
        .ok_or_else(|| e(2, "bad adapter line"))?
        .to_string();
    let family = lines
        .next()
        .and_then(|(_, l)| l.strip_prefix("family "))
        .filter(|f| FAMILIES.contains(f))
        .ok_or_else(|| e(3, "bad family line"))?
        .to_string();
    let mut schemas: BTreeMap<String, DSchema> = BTreeMap::new();
    let mut ops = Vec::new();
    for (n, l) in lines {
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if l.starts_with("schema ") {
            let (coll, s) = parse_schema(l).ok_or_else(|| e(n, "malformed schema line"))?;
            if schemas.insert(coll, s).is_some() {
                return Err(e(n, "duplicate schema"));
            }
        } else if l.starts_with("op ") {
            ops.push(parse_op(l, n, &family, deny)?);
        } else {
            return Err(e(n, "unrecognised line"));
        }
    }
    if ops.is_empty() {
        return Err(e(0, "declaration has no op"));
    }
    let mut entries = Vec::with_capacity(ops.len());
    for op in &ops {
        let s = schemas.get(&op.coll).ok_or_else(|| e(op.line, "op on a collection without a schema line"))?;
        entries.push(validate(op, s, &family, deny)?);
    }
    entries.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    entries.dedup();
    let mut body = format!("{LOCK_HEADER}\nadapter {adapter}\nfamily {family}\n");
    for l in &entries {
        body.push_str(l);
        body.push('\n');
    }
    let hash = sha256_hex(body.as_bytes());
    body.push_str("sha256 ");
    body.push_str(&hash);
    body.push('\n');
    Ok((adapter, body))
}

// ------------------------------------------------------------------------------------------------- discovery

#[derive(Clone, Debug, Default)]
struct Found {
    /// (decl, lock) per (directory, adapter).
    pairs: Vec<(PathBuf, PathBuf)>,
    orphans: Vec<PathBuf>,
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut ents: Vec<_> = rd.flatten().collect();
    ents.sort_by_key(|e| e.file_name());
    for ent in ents {
        let name = ent.file_name().to_string_lossy().into_owned();
        let Ok(ft) = ent.file_type() else { continue };
        if ft.is_dir() {
            if !matches!(name.as_str(), "target" | ".git" | ".claude" | ".lake" | "node_modules" | "__pycache__") {
                walk(&ent.path(), out);
            }
        } else if ft.is_file() && name.starts_with("allowlist.") && (name.ends_with(".decl") || name.ends_with(".lock"))
        {
            out.push(ent.path());
        }
    }
}

fn discover(root: &Path) -> Found {
    let mut files = Vec::new();
    walk(root, &mut files);
    let mut found = Found::default();
    let stem = |p: &Path, ext: &str| {
        p.file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix("allowlist."))
            .and_then(|n| n.strip_suffix(ext))
            .map(str::to_string)
    };
    for f in &files {
        if let Some(a) = stem(f, ".decl") {
            let lock = f.with_file_name(format!("allowlist.{a}.lock"));
            if lock.is_file() { found.pairs.push((f.clone(), lock)) } else { found.orphans.push(f.clone()) }
        } else if let Some(a) = stem(f, ".lock")
            && !f.with_file_name(format!("allowlist.{a}.decl")).is_file()
        {
            found.orphans.push(f.clone());
        }
    }
    found
}

// ------------------------------------------------------------------------------------------------- check

fn read(p: &Path) -> Result<String, String> {
    std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))
}

/// The committed lock must equal the regenerated one; the file-name adapter must equal the declared one.
fn check_pair(decl: &str, lock: &str, file_adapter: Option<&str>, deny: &Deny) -> Result<usize, String> {
    let (adapter, regenerated) = generate(decl, deny)?;
    if let Some(fa) = file_adapter
        && fa != adapter
    {
        return Err(format!("file name says adapter {fa:?}, declaration says {adapter:?}"));
    }
    if regenerated != lock {
        return Err(format!("lock is not byte-identical to its regeneration ({})", first_diff(&regenerated, lock)));
    }
    Ok(regenerated.lines().filter(|l| l.starts_with("op ")).count())
}

fn first_diff(want: &str, got: &str) -> String {
    let n = want.bytes().zip(got.bytes()).take_while(|(a, b)| a == b).count();
    let line = want.get(..n).map_or(0, |p| p.matches('\n').count()) + 1;
    format!("first difference at byte {n}, line {line}; regenerated {} bytes, committed {}", want.len(), got.len())
}

/// Regenerate `decl` in a child process under a given environment and working directory.
fn emit_child(decl: &Path, env: &[(&str, &str)], cwd: &Path) -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let mut cmd = Command::new(exe);
    cmd.args(["allowlist-lock", "--emit"]).arg(decl).env_clear().current_dir(cwd);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().map_err(|e| format!("spawn emit child: {e}"))?;
    if !out.status.success() {
        return Err(format!("emit child failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    String::from_utf8(out.stdout).map_err(|e| e.to_string())
}

const ENV_A: &[(&str, &str)] = &[("LC_ALL", "C"), ("LANG", "C"), ("TZ", "UTC"), ("SOURCE_DATE_EPOCH", "0")];
const ENV_B: &[(&str, &str)] = &[
    ("LC_ALL", "tr_TR.UTF-8"),
    ("LANG", "tr_TR.UTF-8"),
    ("TZ", "Pacific/Chatham"),
    ("HOME", "/nonexistent"),
    ("SOURCE_DATE_EPOCH", "4102444800"),
];

fn check_repo(root: &Path, deny: &Deny, children: bool) -> (Vec<String>, usize, usize) {
    let found = discover(root);
    let mut v: Vec<String> = found.orphans.iter().map(|p| format!("{}: no sibling decl/lock", p.display())).collect();
    if found.pairs.is_empty() {
        v.push("no allowlist.<adapter>.decl / .lock pair found (an empty gate is not a gate)".into());
    }
    let mut entries = 0;
    let tmp = std::env::temp_dir();
    for (decl_p, lock_p) in &found.pairs {
        let fa = decl_p
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix("allowlist."))
            .and_then(|n| n.strip_suffix(".decl"));
        let (decl, lock) = match (read(decl_p), read(lock_p)) {
            (Ok(d), Ok(l)) => (d, l),
            (Err(x), _) | (_, Err(x)) => {
                v.push(x);
                continue;
            }
        };
        match check_pair(&decl, &lock, fa, deny) {
            Ok(n) => entries += n,
            Err(x) => {
                v.push(format!("{}: {x}", decl_p.display()));
                continue;
            }
        }
        if children {
            let abs = decl_p.canonicalize().unwrap_or_else(|_| decl_p.clone());
            for (env, cwd) in [(ENV_A, root), (ENV_B, tmp.as_path())] {
                match emit_child(&abs, env, cwd) {
                    Ok(out) if out == lock => {}
                    Ok(out) => v.push(format!(
                        "{}: regeneration under {env:?} in {} differs ({})",
                        decl_p.display(),
                        cwd.display(),
                        first_diff(&out, &lock)
                    )),
                    Err(x) => v.push(format!("{}: {x}", decl_p.display())),
                }
            }
        }
    }
    (v, found.pairs.len(), entries)
}

fn check(root: &Path) -> Result<(), String> {
    let mut v = sha256_kats();
    let deny = match Deny::load(root) {
        Ok(d) => Some(d),
        Err(x) => {
            v.push(x);
            None
        }
    };
    let (mut pv, pairs, entries) = match &deny {
        Some(d) => check_repo(root, d, true),
        None => (Vec::new(), 0, 0),
    };
    v.append(&mut pv);
    if v.is_empty() {
        println!(
            "ALLOWLIST-LOCK: PASS ({pairs} locks, {entries} entries; each byte-identical to its regeneration \
             in-process and in 2 child processes with different LC_ALL/TZ/PWD/HOME/SOURCE_DATE_EPOCH)"
        );
        Ok(())
    } else {
        for x in &v {
            println!("  - {x}");
        }
        Err(format!("ALLOWLIST-LOCK: FAIL ({} violations)", v.len()))
    }
}

// ------------------------------------------------------------------------------------------------- self-test

const FIX_KV: &str = "aegis-allowlist-decl v1\nadapter st-kv\nfamily redis\n\
                      schema kv tenant=0 key=1 cols=0,1,2 permitted=1,2\n\
                      op kv select eq(1) w=- r=-\nop kv select pfx(1) w=- r=-\nop kv upsert tt w=2,1 r=-\n\
                      op kv delete eq(1) w=- r=-\n";
const FIX_SQL: &str = "aegis-allowlist-decl v1\nadapter st-sql\nfamily sqlite\n\
                       schema notes tenant=0 key=1 cols=0,1,2 permitted=1,2\n\
                       op notes select and(eq(1),not(in(2))) w=- r=2,1\nop notes upsert tt w=1,2 r=1\n\
                       op notes update eq(1) w=2 r=-\n";

fn mutate_lock_body(lock: &str, f: impl Fn(&str) -> String) -> String {
    let cut = lock.rfind("sha256 ").unwrap_or(lock.len());
    let body = f(lock.get(..cut).unwrap_or_default());
    format!("{body}sha256 {}\n", sha256_hex(body.as_bytes()))
}

fn self_test_run(root: &Path) -> Result<(), String> {
    let mut failures: Vec<String> = Vec::new();
    // (mutant name, outcome, substring the rejection must contain); judged at the end.
    let mut cases: Vec<(String, Result<usize, String>, &'static str)> = Vec::new();
    let mut expect_red = |name: &str, r: Result<usize, String>, must_contain: &'static str| {
        cases.push((name.to_string(), r, must_contain));
    };

    // Positive controls: the SHA-256 vectors, the denylist source, the built-in fixtures and the repository.
    let kat = sha256_kats();
    let deny = Deny::load(root)?;
    let positive: Result<(), String> = (|| {
        if !kat.is_empty() {
            return Err(kat.join("; "));
        }
        if deny.hit("redis", "eval").is_none()
            || deny.hit("sqlite", "Attach").is_none()
            || deny.hit("postgres", "MERGE").is_none()
        {
            return Err("denylist source lacks EVAL/ATTACH/MERGE".into());
        }
        for fx in [FIX_KV, FIX_SQL] {
            let (_, lock) = generate(fx, &deny)?;
            check_pair(fx, &lock, None, &deny)?;
        }
        let (v, pairs, _) = check_repo(root, &deny, true);
        if !v.is_empty() {
            return Err(format!("repository check is red: {}", v.join("; ")));
        }
        if pairs == 0 {
            return Err("no repository pairs".into());
        }
        Ok(())
    })();
    if let Err(x) = positive {
        return Err(format!("ALLOWLIST-LOCK SELF-TEST: FAIL (positive control: {x})"));
    }

    let (_, kv_lock) = generate(FIX_KV, &deny)?;
    let (_, sql_lock) = generate(FIX_SQL, &deny)?;
    let stale = "not byte-identical";

    // Mutated declarations against the committed lock.
    expect_red("decl-op-changed", check_pair(&FIX_KV.replace("pfx(1)", "tt"), &kv_lock, None, &deny), stale);
    expect_red(
        "decl-op-dropped",
        check_pair(&FIX_SQL.replace("op notes update eq(1) w=2 r=-\n", ""), &sql_lock, None, &deny),
        stale,
    );
    expect_red(
        "decl-op-added",
        check_pair(&format!("{FIX_SQL}op notes delete eq(1) w=- r=-\n"), &sql_lock, None, &deny),
        stale,
    );
    expect_red(
        "decl-returning-widened",
        check_pair(&FIX_SQL.replace("r=2,1", "r=1,2,0"), &sql_lock, None, &deny),
        "not permitted",
    );
    expect_red(
        "decl-family-changed",
        check_pair(&FIX_SQL.replace("family sqlite", "family postgres"), &sql_lock, None, &deny),
        stale,
    );
    expect_red("decl-adapter-vs-filename", check_pair(FIX_SQL, &sql_lock, Some("other"), &deny), "file name");
    let found = discover(root);
    for (d, l) in &found.pairs {
        if let (Ok(decl), Ok(lock)) = (read(d), read(l)) {
            let renamed = decl.replacen("\nadapter ", "\nadapter z", 1);
            expect_red(&format!("repo-decl-mutated:{}", d.display()), check_pair(&renamed, &lock, None, &deny), stale);
        }
    }

    // Mutated locks against an unchanged declaration.
    expect_red("lock-byte-flip", check_pair(FIX_KV, &kv_lock.replacen("select", "selecu", 1), None, &deny), stale);
    expect_red(
        "lock-rehashed-body",
        check_pair(FIX_KV, &mutate_lock_body(&kv_lock, |b| b.replace("pfx(1)", "tt")), None, &deny),
        stale,
    );
    expect_red(
        "lock-reordered",
        check_pair(
            FIX_KV,
            &mutate_lock_body(&kv_lock, |b| {
                let mut ls: Vec<&str> = b.lines().collect();
                ls.reverse();
                format!("{}\n", ls.join("\n"))
            }),
            None,
            &deny,
        ),
        stale,
    );
    expect_red("lock-crlf", check_pair(FIX_KV, &kv_lock.replace('\n', "\r\n"), None, &deny), stale);
    expect_red("lock-trailing-newline", check_pair(FIX_KV, &format!("{kv_lock}\n"), None, &deny), stale);
    expect_red(
        "lock-hash-zeroed",
        check_pair(
            FIX_KV,
            &format!(
                "{}sha256 {}\n",
                kv_lock.get(..kv_lock.rfind("sha256 ").unwrap_or(0)).unwrap_or_default(),
                "0".repeat(64)
            ),
            None,
            &deny,
        ),
        stale,
    );

    // Denylisted entries: refused at generation, whatever the lock says.
    let eval_decl = format!("{FIX_KV}op kv eval tt w=- r=-\n");
    let eval_lock = mutate_lock_body(&kv_lock, |b| format!("{b}op kv eval tt w=- r=-\n"));
    expect_red("deny-redis-eval", check_pair(&eval_decl, &eval_lock, None, &deny), "denylisted EVAL");
    expect_red(
        "deny-redis-flushall",
        check_pair(&format!("{FIX_KV}op kv FlushAll tt w=- r=-\n"), &kv_lock, None, &deny),
        "denylisted FLUSHALL",
    );
    expect_red(
        "deny-valkey-keys",
        check_pair(
            &format!("{}op kv keys pfx(1) w=- r=-\n", FIX_KV.replace("family redis", "family valkey")),
            &kv_lock,
            None,
            &deny,
        ),
        "denylisted KEYS",
    );
    expect_red(
        "deny-sqlite-replace",
        check_pair(&format!("{FIX_SQL}op notes replace tt w=1,2 r=-\n"), &sql_lock, None, &deny),
        "denylisted REPLACE",
    );
    // Shape rules (kv_plan / lower_op) refuse entries no adapter can render safely.
    expect_red(
        "kv-delete-all",
        check_pair(&format!("{FIX_KV}op kv delete tt w=- r=-\n"), &kv_lock, None, &deny),
        "unsupported kv filter",
    );
    expect_red(
        "kv-not",
        check_pair(&format!("{FIX_KV}op kv select not(eq(1)) w=- r=-\n"), &kv_lock, None, &deny),
        "exact",
    );
    expect_red(
        "sql-tenant-written",
        check_pair(&format!("{FIX_SQL}op notes update tt w=0 r=-\n"), &sql_lock, None, &deny),
        "tenant field written",
    );
    expect_red(
        "sql-key-missing",
        check_pair(&format!("{FIX_SQL}op notes insert tt w=2 r=-\n"), &sql_lock, None, &deny),
        "lacks key column",
    );

    // Environment determinism comparator: a child output differing from the committed lock is reported.
    let tmp = std::env::temp_dir().join(format!("aegis-allowlist-selftest-{}", std::process::id()));
    let setup = std::fs::create_dir_all(&tmp)
        .and_then(|()| std::fs::write(tmp.join("allowlist.st-kv.decl"), FIX_KV))
        .map_err(|e| format!("temp dir: {e}"));
    match setup {
        Ok(()) => {
            let child = emit_child(&tmp.join("allowlist.st-kv.decl"), ENV_B, &tmp);
            match &child {
                Ok(out) if *out == kv_lock => {
                    let mutated = kv_lock.replacen("redis", "valkey", 1);
                    expect_red(
                        "env-child-differs",
                        if *out == mutated { Ok(0) } else { Err(format!("differs ({})", first_diff(out, &mutated))) },
                        "differs",
                    );
                }
                other => failures.push(format!("env child positive control: {other:?}")),
            }
            // Orphans: a lock without a declaration, and a declaration without a lock, are red.
            let _ = std::fs::write(tmp.join("allowlist.orphan.lock"), &kv_lock);
            let (v, _, _) = check_repo(&tmp, &deny, false);
            expect_red(
                "orphan-lock",
                if v.iter().any(|x| x.contains("orphan")) { Err("orphan".into()) } else { Ok(0) },
                "orphan",
            );
            let _ = std::fs::remove_file(tmp.join("allowlist.orphan.lock"));
            let (v, _, _) = check_repo(&tmp, &deny, false);
            expect_red("decl-without-lock", if v.is_empty() { Ok(0) } else { Err(v.join("; ")) }, "no sibling");
            let empty = tmp.join("empty");
            let _ = std::fs::create_dir_all(&empty);
            let (v, _, _) = check_repo(&empty, &deny, false);
            expect_red("no-pairs", if v.is_empty() { Ok(0) } else { Err(v.join("; ")) }, "empty gate");
        }
        Err(x) => failures.push(x),
    }
    let _ = std::fs::remove_dir_all(&tmp);

    // Fail-closed denylist source and SHA-256.
    let src = read(&root.join("crates/aegis-data-ir/src/ir.rs"))?;
    let no_resp = src.replace("const RESP_DENY", "const RESP_DENY_GONE");
    expect_red("denylist-table-missing", Deny::parse(&no_resp).map(|_| 0), "not found");
    let flipped = sha256_hex(b"abd");
    expect_red(
        "sha256-sensitivity",
        if flipped == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
            Ok(0)
        } else {
            Err("hash changed".into())
        },
        "changed",
    );

    let mut caught = 0usize;
    for (name, r, must) in cases {
        match r {
            Err(x) if x.contains(must) => caught += 1,
            Err(x) => failures.push(format!("{name}: rejected for the wrong reason: {x}")),
            Ok(_) => failures.push(format!("{name}: mutant NOT rejected")),
        }
    }
    if failures.is_empty() {
        println!(
            "ALLOWLIST-LOCK SELF-TEST: PASS ({n}/{n} mutants caught; positive controls (SHA-256 KATs, denylist source, \
             fixtures, {pairs} repository locks incl. env-varied child regeneration) PASS)",
            n = caught,
            pairs = found.pairs.len()
        );
        Ok(())
    } else {
        for f in &failures {
            println!("  - {f}");
        }
        Err(format!("ALLOWLIST-LOCK SELF-TEST: FAIL ({} problems, {} mutants caught)", failures.len(), caught))
    }
}

// ------------------------------------------------------------------------------------------------- entry

pub fn allowlist_lock(self_test: bool) -> Result<(), String> {
    let root = crate::root();
    let args: Vec<String> = std::env::args().collect();
    if let Some(p) = args.iter().position(|a| a == "--emit").and_then(|i| args.get(i + 1)) {
        let deny = Deny::load(&root)?;
        let (_, lock) = generate(&read(Path::new(p))?, &deny).map_err(|x| format!("{p}: {x}"))?;
        let mut out = std::io::stdout().lock();
        return out.write_all(lock.as_bytes()).and_then(|()| out.flush()).map_err(|e| e.to_string());
    }
    if self_test { self_test_run(&root) } else { check(&root) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_vectors() {
        assert!(sha256_kats().is_empty());
    }

    #[test]
    fn fixtures_generate_and_mutants_fail() {
        let deny = Deny::load(&crate::root()).unwrap_or_else(|e| unreachable!("{e}"));
        let (a, lock) = generate(FIX_KV, &deny).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(a, "st-kv");
        assert!(lock.starts_with("aegis-allowlist-lock v1\nadapter st-kv\nfamily redis\nop kv delete eq(1) w=- r=-\n"));
        assert!(check_pair(FIX_KV, &lock, Some("st-kv"), &deny).is_ok());
        assert!(check_pair(&format!("{FIX_KV}op kv eval tt w=- r=-\n"), &lock, None, &deny).is_err());
        assert_eq!(
            parse_shape("and(eq(1),not(in(20)))").map(|s| {
                let mut o = String::new();
                s.render(&mut o);
                o
            }),
            Some("and(eq(1),not(in(20)))".into())
        );
        assert_eq!(parse_shape("eq(01)"), None);
        let deep = format!("{}tt{}", "not(".repeat(MAX_PRED_DEPTH), ")".repeat(MAX_PRED_DEPTH));
        assert_eq!(parse_shape(&deep), None);
    }
}
