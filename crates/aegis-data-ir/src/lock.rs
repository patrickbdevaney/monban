//! Allowlist lock generator, reader and denylist scanners (P4-datair-001, R-DB-3/4, gate `allowlist-lock`).
//!
//! The lock file is F4 [`lock_body`] followed by one trailer line `sha256 <64 lower-case hex>\n` (SHA-256 of the body
//! bytes, `aws_lc_rs::digest::SHA256`). It is generated from a declaration file, `allowlist.<adapter>.decl`:
//!
//! ```text
//! aegis-allowlist-decl v1
//! adapter <adapter>                     (backend-id grammar; equals the <adapter> in the file name)
//! family <sqlite|postgres|redis|valkey|mariadb>
//! schema <collection> tenant=<f> key=<fields> cols=<fields> permitted=<fields>
//! op <collection> <kind> <shape> w=<fields> r=<fields>
//! ```
//!
//! The first three lines are fixed; `schema` and `op` lines follow in any order, with blank lines and `#` comment
//! lines allowed between them. `<fields>` is `-` or a comma list of decimal field numbers (no sign, no leading zero);
//! `<shape>` is the [`crate::pred_shape`] grammar. Every collection an `op` names needs exactly one `schema` line;
//! its columns are taken as Binary, the tenant NOT NULL, and its only unique index as (tenant, key...). That is the
//! shape the op set assumes; whether the live table conforms is the schema gate's job at boot (R-DB-7), not the
//! lock's.
//!
//! Each `op` is rebuilt as an F4 [`Op`] with placeholder values (values are parameters, not shape) and must pass,
//! for SQL families, [`lower_op`] (which runs `check_schema` as `Exact`) and, for KV families, [`kv_plan`]. The
//! native command words the entry lowers to ([`native_words`]) must not hit [`denylist`]; an `op` whose kind token
//! is itself a denylisted command (e.g. `eval` on Redis) is refused as denied. Generation is a pure function of the
//! declaration bytes: no clock, path, locale, environment or hash-map order reaches the output.

use crate::ir::{
    Collation, Column, DenyEntry, EngineFamily, Fidelity, Field, KvCommand, KvError, LockEntry, LockError,
    MARIADB_FORM_DASHDASH, MARIADB_FORM_EXEC_COMMENT, MARIADB_FORM_MULTI, MARIADB_FORM_ODKU, MARIADB_FORM_VARIABLE, Op,
    OpKind, Pred, Schema, SchemaError, UniqueIndex, Value, denied, kv_plan, lock_body, valid_backend_id,
    valid_collection,
};
use crate::lower::{LowerError, MAX_PRED_DEPTH, SqlExpr, Stmt, UpsertAction, lower_op};
use aegis_types::TenantId;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

/// First line of every `allowlist.<adapter>.decl`.
pub const DECL_HEADER: &str = "aegis-allowlist-decl v1";
/// Prefix of the lock's last line.
pub const LOCK_TRAILER_PREFIX: &str = "sha256 ";

/// Lower-case hex SHA-256 of `bytes` (AWS-LC, the SHA-256 already in the shipped graph).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
    let mut out = String::with_capacity(64);
    for b in d.as_ref() {
        for nib in [b >> 4, b & 0xf] {
            out.push(char::from_digit(u32::from(nib), 16).unwrap_or('0'));
        }
    }
    out
}

/// The complete lock file: [`lock_body`] plus the `sha256` trailer.
pub fn lock_file(adapter: &str, family: EngineFamily, entries: &[LockEntry]) -> Result<String, LockError> {
    let mut out = lock_body(adapter, family, entries)?;
    let h = sha256_hex(out.as_bytes());
    out.push_str(LOCK_TRAILER_PREFIX);
    out.push_str(&h);
    out.push('\n');
    Ok(out)
}

// ---------------------------------------------------------------------------------------------- denylist scanners

/// Words a KV command is sent as (command name and fixed option tokens; keys and values are arguments).
pub fn kv_command_words(c: &KvCommand) -> &'static [&'static str] {
    match c {
        KvCommand::Get { .. } => &["GET"],
        KvCommand::Scan { .. } => &["SCAN", "MATCH", "COUNT"],
        KvCommand::SetNx { .. } => &["SET", "NX"],
        KvCommand::Set { .. } => &["SET"],
        KvCommand::SetXx { .. } => &["SET", "XX"],
        KvCommand::Del { .. } => &["DEL"],
    }
}

/// SQL text with an unterminated literal, quoted identifier or block comment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unterminated;

/// The first denylisted unquoted keyword token in rendered SQL text, if any (ASCII case-insensitive, whole word).
/// Skips `'...'` literals, `"..."` identifiers (with doubled-quote escapes), `--` line comments and `/* */`
/// comments; an unterminated literal, identifier or comment is [`Unterminated`], so the caller refuses the text
/// (fail closed). Renderers run every statement they emit through this. `Mariadb` uses its own dialect scanner
/// ([`denied_in_mariadb`]).
pub fn denied_in_sql(family: EngineFamily, sql: &str) -> Result<Option<&'static DenyEntry>, Unterminated> {
    if family == EngineFamily::Mariadb {
        return denied_in_mariadb(sql);
    }
    let b = sql.as_bytes();
    let mut i = 0usize;
    let at = |k: usize| b.get(k).copied();
    while let Some(c) = at(i) {
        match c {
            b'\'' | b'"' => {
                let q = c;
                i += 1;
                loop {
                    match at(i) {
                        None => return Err(Unterminated),
                        Some(x) if x == q => {
                            if at(i + 1) == Some(q) {
                                i += 2;
                            } else {
                                i += 1;
                                break;
                            }
                        }
                        Some(_) => i += 1,
                    }
                }
            }
            b'-' if at(i + 1) == Some(b'-') => {
                while !matches!(at(i), None | Some(b'\n')) {
                    i += 1;
                }
            }
            b'/' if at(i + 1) == Some(b'*') => {
                i += 2;
                loop {
                    match at(i) {
                        None => return Err(Unterminated),
                        Some(b'*') if at(i + 1) == Some(b'/') => {
                            i += 2;
                            break;
                        }
                        Some(_) => i += 1,
                    }
                }
            }
            c if c.is_ascii_alphanumeric() || c == b'_' || c == b'$' => {
                let start = i;
                while matches!(at(i), Some(x) if x.is_ascii_alphanumeric() || x == b'_' || x == b'$') {
                    i += 1;
                }
                let word = sql.get(start..i).ok_or(Unterminated)?;
                if let Some(d) = denied(family, word) {
                    return Ok(Some(d));
                }
            }
            _ => i += 1,
        }
    }
    Ok(None)
}

/// One MariaDB token: a bare word, a backtick identifier (contents, escapes undone), or one punctuation byte.
/// Literals and comments are dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
enum MyTok<'a> {
    Word(&'a str),
    Ident(String),
    Punct(u8),
}

/// MariaDB dialect scanner (SPEC_INVARIANTS §F Phase-8 addendum DENY-M). Lexes like the server: `'..'` and `".."`
/// literals with backslash and doubled-quote escapes, `` `..` `` identifiers with doubled-backtick escapes, `#` and
/// `-- ` line comments, `/* */` block comments. Refused as forms: `@` (variables), `;` (multi-statements), `/*!` and
/// `/*M!` (executable comments), `--` not followed by a space or control byte, and `ON DUPLICATE KEY UPDATE` whose
/// assignments are not all the mandated tenant guard. Every bare word is checked against the MariaDB keyword items.
/// Unterminated literal, identifier or comment: [`Unterminated`]. The guard check is on shape only (one guard
/// column `t` for every assignment, never the assigned column); that `t` is the tenant column is the renderer's
/// obligation (it renders from the schema).
pub fn denied_in_mariadb(sql: &str) -> Result<Option<&'static DenyEntry>, Unterminated> {
    let b = sql.as_bytes();
    let at = |k: usize| b.get(k).copied();
    let mut toks: Vec<MyTok<'_>> = Vec::new();
    let mut i = 0usize;
    while let Some(c) = at(i) {
        match c {
            b'\'' | b'"' => {
                let q = c;
                i += 1;
                loop {
                    match at(i) {
                        None => return Err(Unterminated),
                        Some(b'\\') => {
                            if at(i + 1).is_none() {
                                return Err(Unterminated);
                            }
                            i += 2;
                        }
                        Some(x) if x == q => {
                            if at(i + 1) == Some(q) {
                                i += 2;
                            } else {
                                i += 1;
                                break;
                            }
                        }
                        Some(_) => i += 1,
                    }
                }
            }
            b'`' => {
                i += 1;
                let mut id = Vec::new();
                loop {
                    match at(i) {
                        None => return Err(Unterminated),
                        Some(b'`') if at(i + 1) == Some(b'`') => {
                            id.push(b'`');
                            i += 2;
                        }
                        Some(b'`') => {
                            i += 1;
                            break;
                        }
                        Some(x) => {
                            id.push(x);
                            i += 1;
                        }
                    }
                }
                toks.push(MyTok::Ident(String::from_utf8(id).map_err(|_| Unterminated)?));
            }
            b'#' => {
                while !matches!(at(i), None | Some(b'\n')) {
                    i += 1;
                }
            }
            b'-' if at(i + 1) == Some(b'-') => match at(i + 2) {
                Some(x) if x <= b' ' || x == 0x7f => {
                    while !matches!(at(i), None | Some(b'\n')) {
                        i += 1;
                    }
                }
                _ => return Ok(Some(&MARIADB_FORM_DASHDASH)),
            },
            b'/' if at(i + 1) == Some(b'*') => {
                if at(i + 2) == Some(b'!') || (at(i + 2) == Some(b'M') && at(i + 3) == Some(b'!')) {
                    return Ok(Some(&MARIADB_FORM_EXEC_COMMENT));
                }
                i += 2;
                loop {
                    match at(i) {
                        None => return Err(Unterminated),
                        Some(b'*') if at(i + 1) == Some(b'/') => {
                            i += 2;
                            break;
                        }
                        Some(_) => i += 1,
                    }
                }
            }
            b'@' => return Ok(Some(&MARIADB_FORM_VARIABLE)),
            b';' => return Ok(Some(&MARIADB_FORM_MULTI)),
            c if c.is_ascii_alphanumeric() || c == b'_' || c == b'$' || c >= 0x80 => {
                let start = i;
                while matches!(at(i), Some(x) if x.is_ascii_alphanumeric() || x == b'_' || x == b'$' || x >= 0x80) {
                    i += 1;
                }
                let word = sql.get(start..i).ok_or(Unterminated)?;
                if let Some(d) = denied(EngineFamily::Mariadb, word) {
                    return Ok(Some(d));
                }
                toks.push(MyTok::Word(word));
            }
            c if c.is_ascii_whitespace() => i += 1,
            c => {
                toks.push(MyTok::Punct(c));
                i += 1;
            }
        }
    }
    Ok(odku_unguarded(&toks).then_some(&MARIADB_FORM_ODKU))
}

fn kw(t: Option<&MyTok<'_>>, k: &str) -> bool {
    matches!(t, Some(MyTok::Word(w)) if w.eq_ignore_ascii_case(k))
}

fn ident<'t>(t: Option<&'t MyTok<'_>>) -> Option<&'t str> {
    match t {
        Some(MyTok::Ident(s)) => Some(s.as_str()),
        _ => None,
    }
}

/// True when some `ON DUPLICATE KEY UPDATE` is followed by anything other than a non-empty, comma-separated list of
/// guarded assignments `` `c` = IF(CAST(`t` AS BINARY) = CAST(VALUES(`t`) AS BINARY), VALUES(`c`), `c`) `` (one `t`
/// throughout, `t` != `c`), ending at the end of the text or at `RETURNING`.
fn odku_unguarded(toks: &[MyTok<'_>]) -> bool {
    let mut k = 0usize;
    while k < toks.len() {
        let at = |j: usize| toks.get(j);
        if !(kw(at(k), "ON") && kw(at(k + 1), "DUPLICATE")) {
            if kw(at(k), "DUPLICATE") {
                return true; // DUPLICATE anywhere but in a complete `ON DUPLICATE KEY UPDATE`
            }
            k += 1;
            continue;
        }
        if !(kw(at(k + 2), "KEY") && kw(at(k + 3), "UPDATE")) {
            return true;
        }
        let mut j = k + 4;
        let mut guard: Option<&str> = None;
        loop {
            let p = |n: usize, c: u8| matches!(at(j + n), Some(MyTok::Punct(x)) if *x == c);
            let (Some(c), Some(t), Some(t2), Some(c2), Some(c3)) =
                (ident(at(j)), ident(at(j + 6)), ident(at(j + 15)), ident(at(j + 23)), ident(at(j + 26)))
            else {
                return true;
            };
            let shape = p(1, b'=')
                && kw(at(j + 2), "IF")
                && p(3, b'(')
                && kw(at(j + 4), "CAST")
                && p(5, b'(')
                && kw(at(j + 7), "AS")
                && kw(at(j + 8), "BINARY")
                && p(9, b')')
                && p(10, b'=')
                && kw(at(j + 11), "CAST")
                && p(12, b'(')
                && kw(at(j + 13), "VALUES")
                && p(14, b'(')
                && p(16, b')')
                && kw(at(j + 17), "AS")
                && kw(at(j + 18), "BINARY")
                && p(19, b')')
                && p(20, b',')
                && kw(at(j + 21), "VALUES")
                && p(22, b'(')
                && p(24, b')')
                && p(25, b',')
                && p(27, b')');
            if !shape || t != t2 || c != c2 || c != c3 || c == t || guard.is_some_and(|g| g != t) {
                return true;
            }
            guard = Some(t);
            j += 28;
            match at(j) {
                Some(MyTok::Punct(b',')) => j += 1,
                None => return false,
                Some(x) if kw(Some(x), "RETURNING") => break,
                Some(_) => return true,
            }
        }
        k = j;
    }
    false
}

fn expr_words(e: &SqlExpr, out: &mut Vec<&'static str>) {
    match e {
        SqlExpr::And(a, b) | SqlExpr::Or(a, b) => {
            out.push(if matches!(e, SqlExpr::And(..)) { "AND" } else { "OR" });
            expr_words(a, out);
            expr_words(b, out);
        }
        SqlExpr::Not(a) => {
            out.push("NOT");
            expr_words(a, out);
        }
        _ => {}
    }
}

/// Error from [`native_words`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeError {
    Lower(LowerError),
    Kv(KvError),
}

/// The engine command or keyword skeleton an op lowers to: for KV families the [`kv_plan`] command words, for SQL
/// families the statement keywords of the engine-neutral [`Stmt`] plus the connectives of its filter. Adapters add
/// dialect tokens on top and check them with [`denied_in_sql`]; the lock generator checks this skeleton.
pub fn native_words(family: EngineFamily, op: &Op, schema: &Schema) -> Result<Vec<&'static str>, NativeError> {
    if family.is_kv() {
        let c = kv_plan(op, schema).map_err(NativeError::Kv)?;
        return Ok(kv_command_words(&c).to_vec());
    }
    let l = lower_op(op, schema, Fidelity::Exact).map_err(NativeError::Lower)?;
    let mut w: Vec<&'static str> = Vec::new();
    match &l.stmt {
        Stmt::Select { filter } => {
            w.extend(["SELECT", "FROM", "WHERE"]);
            expr_words(filter, &mut w);
        }
        Stmt::Delete { filter } => {
            w.extend(["DELETE", "FROM", "WHERE"]);
            expr_words(filter, &mut w);
        }
        Stmt::Update { filter, .. } => {
            w.extend(["UPDATE", "SET", "WHERE"]);
            expr_words(filter, &mut w);
        }
        Stmt::Insert { .. } => w.extend(["INSERT", "INTO", "VALUES"]),
        // MariaDB has no ON CONFLICT (and denies DO): its mandated upsert forms (q4-005, DENY-M).
        Stmt::Upsert { action, .. } if family == EngineFamily::Mariadb => match action {
            UpsertAction::Update { .. } => w.extend(["INSERT", "INTO", "VALUES", "ON", "DUPLICATE", "KEY", "UPDATE"]),
            UpsertAction::Nothing => w.extend(["INSERT", "INTO", "SELECT", "FROM", "DUAL", "WHERE", "NOT", "EXISTS"]),
        },
        Stmt::Upsert { action, .. } => {
            w.extend(["INSERT", "INTO", "VALUES", "ON", "CONFLICT", "DO"]);
            match action {
                UpsertAction::Nothing => w.push("NOTHING"),
                UpsertAction::Update { .. } => w.extend(["UPDATE", "SET", "WHERE"]),
            }
        }
    }
    if !l.returning.is_empty() {
        w.push("RETURNING");
    }
    Ok(w)
}

// ---------------------------------------------------------------------------------------------- line grammar

fn num(s: &str) -> Option<Field> {
    let ok = !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    if ok { s.parse().ok() } else { None }
}

fn fields(s: &str) -> Option<Vec<Field>> {
    if s == "-" {
        return Some(Vec::new());
    }
    s.split(',').map(num).collect()
}

fn tagged<'a>(tok: Option<&'a str>, tag: &str) -> Option<&'a str> {
    tok?.strip_prefix(tag)
}

struct ShapeParser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> ShapeParser<'a> {
    fn eat(&mut self, c: u8) -> Option<()> {
        if self.b.get(self.i) == Some(&c) {
            self.i += 1;
            Some(())
        } else {
            None
        }
    }
    fn word(&mut self) -> &'a [u8] {
        let b: &'a [u8] = self.b;
        let start = self.i;
        while matches!(b.get(self.i), Some(c) if c.is_ascii_lowercase()) {
            self.i += 1;
        }
        b.get(start..self.i).unwrap_or(&[])
    }
    fn field(&mut self) -> Option<Field> {
        self.eat(b'(')?;
        let start = self.i;
        while matches!(self.b.get(self.i), Some(c) if c.is_ascii_digit()) {
            self.i += 1;
        }
        let f = num(core::str::from_utf8(self.b.get(start..self.i)?).ok()?)?;
        self.eat(b')')?;
        Some(f)
    }
    fn pred(&mut self, budget: usize) -> Option<Pred> {
        let next = budget.checked_sub(1)?;
        let s = || Value::Str(String::new());
        Some(match self.word() {
            b"tt" => Pred::Tt,
            b"ff" => Pred::Ff,
            b"eq" => Pred::Eq(self.field()?, s()),
            b"in" => Pred::IsIn(self.field()?, Vec::new()),
            b"range" => Pred::Range(self.field()?, s(), s()),
            b"pfx" => Pred::Pfx(self.field()?, String::new()),
            w @ (b"and" | b"or") => {
                let and = w == b"and";
                self.eat(b'(')?;
                let a = self.pred(next)?;
                self.eat(b',')?;
                let b = self.pred(next)?;
                self.eat(b')')?;
                if and { Pred::And(Box::new(a), Box::new(b)) } else { Pred::Or(Box::new(a), Box::new(b)) }
            }
            b"not" => {
                self.eat(b'(')?;
                let a = self.pred(next)?;
                self.eat(b')')?;
                Pred::Not(Box::new(a))
            }
            _ => return None,
        })
    }
}

/// Parse a value-free shape back into a [`Pred`] with placeholder values (`""`, empty `IsIn` list). Depth is
/// bounded by [`MAX_PRED_DEPTH`]; trailing bytes are refused.
pub fn parse_shape(s: &str) -> Option<Pred> {
    let mut p = ShapeParser { b: s.as_bytes(), i: 0 };
    let pred = p.pred(MAX_PRED_DEPTH)?;
    if p.i == s.len() { Some(pred) } else { None }
}

fn placeholder_tenant() -> Option<TenantId> {
    TenantId::new(1).ok()
}

/// Why an `op` line did not parse. `Denied` is a kind token that is a denylisted command of the family.
enum OpLineError {
    Syntax,
    Denied(&'static str),
}

fn parse_op_line(line: &str, family: EngineFamily) -> Result<Op, OpLineError> {
    let mut t = line.split(' ');
    if t.next() != Some("op") {
        return Err(OpLineError::Syntax);
    }
    let coll = t.next().filter(|c| valid_collection(c)).ok_or(OpLineError::Syntax)?;
    let kind_tok = t.next().ok_or(OpLineError::Syntax)?;
    let kind = match OpKind::from_name(kind_tok) {
        Some(k) => k,
        None => {
            return Err(denied(family, kind_tok).map_or(OpLineError::Syntax, |d| OpLineError::Denied(d.item)));
        }
    };
    let filter = t.next().and_then(parse_shape).ok_or(OpLineError::Syntax)?;
    let writes = tagged(t.next(), "w=").and_then(fields).ok_or(OpLineError::Syntax)?;
    let returning = tagged(t.next(), "r=").and_then(fields).ok_or(OpLineError::Syntax)?;
    if t.next().is_some() {
        return Err(OpLineError::Syntax);
    }
    Ok(Op {
        tenant: placeholder_tenant().ok_or(OpLineError::Syntax)?,
        collection: coll.into(),
        kind,
        filter,
        writes: writes.into_iter().map(|f| (f, Value::Str(String::new()))).collect(),
        returning,
    })
}

fn parse_schema_line(line: &str) -> Option<Schema> {
    let mut t = line.split(' ');
    if t.next() != Some("schema") {
        return None;
    }
    let coll = t.next().filter(|c| valid_collection(c))?;
    let tenant = num(tagged(t.next(), "tenant=")?)?;
    let keys = fields(tagged(t.next(), "key=")?)?;
    let cols = fields(tagged(t.next(), "cols=")?)?;
    let permitted = fields(tagged(t.next(), "permitted=")?)?;
    if t.next().is_some() || keys.iter().all(|k| *k == tenant) {
        return None;
    }
    let mut sorted = cols.clone();
    sorted.sort_unstable();
    sorted.dedup();
    let known = |f: &Field| sorted.binary_search(f).is_ok();
    if sorted.len() != cols.len() || !known(&tenant) || !keys.iter().all(known) || !permitted.iter().all(known) {
        return None;
    }
    let mut index: Vec<Field> = keys.clone();
    index.push(tenant);
    index.sort_unstable();
    index.dedup();
    let columns = sorted
        .iter()
        .map(|f| Column {
            field: *f,
            name: String::new(),
            nullable: *f != tenant,
            collation: Collation::Binary,
            key: keys.contains(f),
        })
        .collect();
    Some(Schema {
        collection: coll.into(),
        tenant_field: tenant,
        columns,
        permitted,
        unique_indexes: alloc::vec![UniqueIndex { fields: index, prefix: false }],
    })
}

// ---------------------------------------------------------------------------------------------- generator

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeclErrorKind {
    /// First line is not [`DECL_HEADER`].
    Header,
    /// Second line is not `adapter <backend-id>`.
    Adapter,
    /// Third line is not `family <name>`.
    Family,
    /// A line that is not a comment, a blank line, a `schema` line or an `op` line, or a malformed one.
    Syntax,
    DuplicateSchema,
    /// An `op` names a collection without a `schema` line.
    UnknownCollection,
    /// A declaration with no `op` line (an empty allowlist is not written down; INV-NONEMPTY).
    NoOps,
    /// The entry names or lowers to a denylisted command or keyword (the item).
    Denied(&'static str),
    Schema(SchemaError),
    Lower(LowerError),
    Kv(KvError),
    Lock(LockError),
    /// The lock file is not byte-identical to the regenerated lock.
    Stale,
}

/// A declaration refusal; `line` is 1-based, 0 for the file as a whole.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclError {
    pub line: usize,
    pub kind: DeclErrorKind,
}

fn err(line: usize, kind: DeclErrorKind) -> DeclError {
    DeclError { line, kind }
}

/// A parsed and validated declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decl {
    adapter: String,
    family: EngineFamily,
    entries: Vec<LockEntry>,
}

impl Decl {
    pub fn adapter(&self) -> &str {
        &self.adapter
    }
    pub fn family(&self) -> EngineFamily {
        self.family
    }
    pub fn entries(&self) -> &[LockEntry] {
        &self.entries
    }
    /// The lock file this declaration generates.
    pub fn lock(&self) -> Result<String, DeclError> {
        lock_file(&self.adapter, self.family, &self.entries).map_err(|e| err(0, DeclErrorKind::Lock(e)))
    }
}

fn validate(family: EngineFamily, op: &Op, schema: &Schema, line: usize) -> Result<(), DeclError> {
    let words = native_words(family, op, schema).map_err(|e| match e {
        NativeError::Lower(LowerError::Schema(s)) | NativeError::Kv(KvError::Schema(s)) => {
            err(line, DeclErrorKind::Schema(s))
        }
        NativeError::Lower(l) => err(line, DeclErrorKind::Lower(l)),
        NativeError::Kv(k) => err(line, DeclErrorKind::Kv(k)),
    })?;
    match words.iter().find_map(|w| denied(family, w)) {
        Some(d) => Err(err(line, DeclErrorKind::Denied(d.item))),
        None => Ok(()),
    }
}

/// Parse and validate a declaration (grammar in the module docs). Total: never panics.
pub fn parse_decl(text: &str) -> Result<Decl, DeclError> {
    let mut lines = text.split('\n').enumerate().map(|(i, l)| (i + 1, l));
    if lines.next().map(|(_, l)| l) != Some(DECL_HEADER) {
        return Err(err(1, DeclErrorKind::Header));
    }
    let adapter = lines
        .next()
        .and_then(|(_, l)| l.strip_prefix("adapter "))
        .filter(|a| valid_backend_id(a))
        .ok_or(err(2, DeclErrorKind::Adapter))?;
    let family = lines
        .next()
        .and_then(|(_, l)| l.strip_prefix("family "))
        .and_then(EngineFamily::from_name)
        .ok_or(err(3, DeclErrorKind::Family))?;
    let mut schemas: Vec<Schema> = Vec::new();
    let mut ops: Vec<(usize, Op)> = Vec::new();
    for (n, l) in lines {
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if l.starts_with("schema ") {
            let s = parse_schema_line(l).ok_or(err(n, DeclErrorKind::Syntax))?;
            if schemas.iter().any(|x| x.collection == s.collection) {
                return Err(err(n, DeclErrorKind::DuplicateSchema));
            }
            schemas.push(s);
        } else if l.starts_with("op ") {
            let op = parse_op_line(l, family).map_err(|e| match e {
                OpLineError::Syntax => err(n, DeclErrorKind::Syntax),
                OpLineError::Denied(item) => err(n, DeclErrorKind::Denied(item)),
            })?;
            ops.push((n, op));
        } else {
            return Err(err(n, DeclErrorKind::Syntax));
        }
    }
    if ops.is_empty() {
        return Err(err(0, DeclErrorKind::NoOps));
    }
    let mut entries = Vec::with_capacity(ops.len());
    for (n, op) in &ops {
        let s =
            schemas.iter().find(|s| s.collection == op.collection).ok_or(err(*n, DeclErrorKind::UnknownCollection))?;
        validate(family, op, s, *n)?;
        entries.push(LockEntry::of(op).map_err(|e| err(*n, DeclErrorKind::Lock(e)))?);
    }
    Ok(Decl { adapter: adapter.into(), family, entries })
}

/// Regenerate the lock file from declaration text.
pub fn generate(decl: &str) -> Result<String, DeclError> {
    parse_decl(decl)?.lock()
}

/// Gate check: `lock` must be byte-identical to the lock regenerated from `decl`.
pub fn verify(decl: &str, lock: &str) -> Result<(), DeclError> {
    if generate(decl)? == lock { Ok(()) } else { Err(err(0, DeclErrorKind::Stale)) }
}

// ---------------------------------------------------------------------------------------------- runtime reader

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockFileError {
    /// Not a canonical lock: wrong header/adapter/family line, a line that does not re-render to itself, wrong
    /// order, a duplicate, CR or a missing final LF.
    NotCanonical,
    /// The trailer is missing or its hash does not match the body.
    Hash,
    /// No `op` line.
    Empty,
}

/// A verified lock, for the runtime check "refuse any op whose shape is not in the lock".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Allowlist {
    adapter: String,
    family: EngineFamily,
    /// Sorted ascending, no duplicates (as in the file).
    lines: Vec<String>,
}

impl Allowlist {
    /// Accepts `text` only if it is byte-identical to the canonical re-rendering of its own entries plus the
    /// correct trailer (fail closed).
    pub fn parse(text: &str) -> Result<Allowlist, LockFileError> {
        let body_len =
            text.strip_suffix('\n').and_then(|t| t.rfind('\n')).map(|i| i + 1).ok_or(LockFileError::NotCanonical)?;
        let (body, trailer) = text.split_at_checked(body_len).ok_or(LockFileError::NotCanonical)?;
        let hash = trailer.strip_prefix(LOCK_TRAILER_PREFIX).and_then(|h| h.strip_suffix('\n'));
        if hash != Some(sha256_hex(body.as_bytes()).as_str()) {
            return Err(LockFileError::Hash);
        }
        let mut lines = body.split('\n');
        if lines.next() != Some(crate::ir::LOCK_HEADER) {
            return Err(LockFileError::NotCanonical);
        }
        let adapter = lines.next().and_then(|l| l.strip_prefix("adapter ")).ok_or(LockFileError::NotCanonical)?;
        let family = lines
            .next()
            .and_then(|l| l.strip_prefix("family "))
            .and_then(EngineFamily::from_name)
            .ok_or(LockFileError::NotCanonical)?;
        let mut entries = Vec::new();
        for l in lines.filter(|l| !l.is_empty()) {
            let op = parse_op_line(l, family).map_err(|_| LockFileError::NotCanonical)?;
            let e = LockEntry::of(&op).map_err(|_| LockFileError::NotCanonical)?;
            if e.line() != l {
                return Err(LockFileError::NotCanonical);
            }
            entries.push(e);
        }
        if entries.is_empty() {
            return Err(LockFileError::Empty);
        }
        if lock_file(adapter, family, &entries).ok().as_deref() != Some(text) {
            return Err(LockFileError::NotCanonical);
        }
        let lines = entries.iter().map(|e| String::from(e.line())).collect();
        Ok(Allowlist { adapter: adapter.into(), family, lines })
    }
    pub fn adapter(&self) -> &str {
        &self.adapter
    }
    pub fn family(&self) -> EngineFamily {
        self.family
    }
    pub fn len(&self) -> usize {
        self.lines.len()
    }
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
    /// True iff the op's value-free shape is a line of the lock. Values never matter; an op whose shape cannot be
    /// rendered is not permitted.
    pub fn permits(&self, op: &Op) -> bool {
        match LockEntry::of(op) {
            Ok(e) => self.lines.binary_search_by(|l| l.as_str().cmp(e.line())).is_ok(),
            Err(_) => false,
        }
    }
}
