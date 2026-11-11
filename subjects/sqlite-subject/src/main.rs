//! sqlite-subject: the production `monban-adapter-sqlite` behind the oracle protocols.
//!
//!   sqlite-subject lowering [--mutant drop-tenant]
//!       lowering-read / lowering-write subject, protocol v2 (oracles/lowering-read/README.md, -write/README.md).
//!       read/update/delete/insert/upsert are lowered by `monban_data_ir::lower_op` and rendered by the adapter
//!       (`render_where` for read filters, `render_lowered` for statements). kv_* ops are answered from
//!       `monban_data_ir::kv_plan` (the offline Redis model runs beside SQLite). merge/cte/replace/raw_sql, rls_*,
//!       kv_acl, non-sqlite dialects and anything malformed are refused.
//!   sqlite-subject schema
//!       schema-gate subject, protocol v1 (oracles/schema-gate/README.md): mode sqlite opens `path` read-only through
//!       `SqliteDb::open` and runs the live `SqliteDb::check_schema` (the catalog, never `declared`); mode static runs
//!       F4 `check_schema` on the admission probe.
//!
//! Protocol → IR mapping (subject only, not adapter logic):
//! * columns get fields in name order; the tenant column is NOT NULL, every column Binary (the lowering protocols
//!   state no collations; the renderer is collation-independent, and collations are the schema gate's job);
//! * an upsert's `update` list narrows the DO UPDATE set of the lowered statement to that subset of the written
//!   non-key columns (F4 `Op` cannot say "insert these, update only those"); `render_lowered` re-validates it;
//! * JSON integers outside i64 (Lean `Value.int` is unbounded, stored SQLite integers are i64): `eq f big` and an
//!   `in` element `big` match no stored value, so `eq` becomes `in f []` (FALSE on a present column, UNKNOWN on
//!   NULL, exactly Lean's atom) and the element is dropped; a range bound is clamped to i64, and a range whose int
//!   bounds admit no i64 becomes `in f []`. Out-of-range values to write are refused.
//!
//! `--mutant drop-tenant` (self-test positive control): the tenant atom of every rendered filter is replaced by
//! `(1=1)` and its parameter dropped; KV keys and patterns lose the `t:{hex}:` prefix.
#![forbid(unsafe_code)]

mod json;

use json::Json;
use monban_adapter_sqlite::{ForeignKey, OpenMode, Rendered, SqliteDb, Table, render_lowered, render_where};
use monban_data_ir::{
    Collation, Column, Fidelity, Field, KvCommand, Op, OpKind, Pred, Schema, Stmt, UniqueIndex, UpsertAction, Value,
    check_schema, kv_key_prefix, kv_plan, lower_op, parse_tenant_text,
};
use monban_types::TenantId;
use std::collections::BTreeMap;
use std::io::{BufRead, BufWriter, Write};
use std::path::Path;
use std::process::ExitCode;

type Res<T> = Result<T, String>;

// ------------------------------------------------------------------------------------------------- JSON out

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn value_json(v: &Value) -> String {
    match v {
        Value::Int(i) => i.to_string(),
        Value::Str(s) => esc(s),
    }
}

fn sql_reply(r: &Rendered) -> String {
    let ps: Vec<String> = r.params.iter().map(value_json).collect();
    format!("\"sql\":{},\"params\":[{}]", esc(&r.sql), ps.join(","))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Res<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    let d = |c: u8| char::from(c).to_digit(16).ok_or_else(|| String::from("bad hex digit"));
    s.as_bytes()
        .chunks(2)
        .map(|p| match p {
            [a, b] => Ok(u8::try_from(d(*a)? * 16 + d(*b)?).map_err(|_| String::from("hex"))?),
            _ => Err("hex".into()),
        })
        .collect()
}

fn utf8_hex(j: Option<&Json>) -> Res<String> {
    let s = j.and_then(Json::str).ok_or("missing hex string")?;
    String::from_utf8(unhex(s)?).map_err(|_| "KV keys and values are UTF-8 text (Value::Str)".into())
}

// ------------------------------------------------------------------------------------------------- JSON in

/// A protocol literal: an IR value, or a JSON integer beyond i64 (`true` = positive).
enum Lit {
    V(Value),
    Big(bool),
}

fn lit(j: &Json) -> Res<Lit> {
    match j {
        Json::Str(s) => Ok(Lit::V(Value::Str(s.clone()))),
        Json::Num(t) => {
            let digits = t.strip_prefix('-').unwrap_or(t);
            if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
                return Err(format!("value {t} is not an integer (Lean Value is int | str)"));
            }
            Ok(match t.parse::<i64>() {
                Ok(i) => Lit::V(Value::Int(i)),
                Err(_) => Lit::Big(!t.starts_with('-')),
            })
        }
        _ => Err("value must be a JSON integer or string".into()),
    }
}

fn val(j: &Json) -> Res<Value> {
    match lit(j)? {
        Lit::V(v) => Ok(v),
        Lit::Big(_) => Err("integer outside i64 cannot be written".into()),
    }
}

fn arr(j: Option<&Json>) -> Res<&[Json]> {
    match j {
        Some(Json::Arr(a)) => Ok(a),
        _ => Err("expected an array".into()),
    }
}

fn s_of<'a>(j: Option<&'a Json>, what: &str) -> Res<&'a str> {
    j.and_then(Json::str).ok_or_else(|| format!("missing {what}"))
}

/// Column name → field, in name order.
struct Cols(BTreeMap<String, Field>);

impl Cols {
    fn new(j: Option<&Json>) -> Res<Cols> {
        let Some(Json::Obj(m)) = j else { return Err("missing columns".into()) };
        let mut out = BTreeMap::new();
        for (i, k) in m.keys().enumerate() {
            out.insert(k.clone(), Field::try_from(i).map_err(|_| "too many columns")?);
        }
        Ok(Cols(out))
    }
    fn f(&self, name: &str) -> Res<Field> {
        self.0.get(name).copied().ok_or_else(|| format!("unknown column {name:?}"))
    }
    fn fj(&self, j: &Json) -> Res<Field> {
        self.f(j.str().ok_or("column name must be a string")?)
    }
}

fn bin(a: Pred, b: Pred, and: bool) -> Pred {
    if and { Pred::And(Box::new(a), Box::new(b)) } else { Pred::Or(Box::new(a), Box::new(b)) }
}

/// Lit bound → (value, empty): an int bound beyond i64 is clamped; `empty` marks a range no i64 can satisfy.
fn bound(l: Lit, lo: bool) -> (Value, bool) {
    match l {
        Lit::V(v) => (v, false),
        Lit::Big(pos) => match (lo, pos) {
            (true, false) => (Value::Int(i64::MIN), false),
            (true, true) => (Value::Int(i64::MAX), true),
            (false, true) => (Value::Int(i64::MAX), false),
            (false, false) => (Value::Int(i64::MIN), true),
        },
    }
}

fn pred(j: &Json, cols: &Cols) -> Res<Pred> {
    let a = match j {
        Json::Arr(a) => a.as_slice(),
        _ => return Err("pred must be an array".into()),
    };
    let tag = a.first().and_then(Json::str).ok_or("pred tag")?;
    let bad = || format!("malformed pred {tag}");
    Ok(match (tag, a) {
        ("tt", [_]) => Pred::Tt,
        ("ff", [_]) => Pred::Ff,
        ("eq", [_, f, v]) => {
            let f = cols.fj(f)?;
            match lit(v)? {
                Lit::V(v) => Pred::Eq(f, v),
                Lit::Big(_) => Pred::IsIn(f, Vec::new()),
            }
        }
        ("in", [_, f, Json::Arr(vs)]) => {
            let f = cols.fj(f)?;
            let mut out = Vec::with_capacity(vs.len());
            for v in vs {
                if let Lit::V(v) = lit(v)? {
                    out.push(v);
                }
            }
            Pred::IsIn(f, out)
        }
        ("range", [_, f, lo, hi]) => {
            let f = cols.fj(f)?;
            let (lo, e1) = bound(lit(lo)?, true);
            let (hi, e2) = bound(lit(hi)?, false);
            if (e1 || e2) && matches!((&lo, &hi), (Value::Int(_), Value::Int(_))) {
                Pred::IsIn(f, Vec::new())
            } else {
                Pred::Range(f, lo, hi)
            }
        }
        ("pfx", [_, f, Json::Str(s)]) => Pred::Pfx(cols.fj(f)?, s.clone()),
        ("and" | "or", [_, p, q]) => bin(pred(p, cols)?, pred(q, cols)?, tag == "and"),
        ("not", [_, p]) => Pred::Not(Box::new(pred(p, cols)?)),
        ("andN" | "orN", [_, Json::Arr(ps)]) => {
            // Lean Pred.andN / orN: [] = tt / ff; p :: ps = and/or p (andN/orN ps).
            let and = tag == "andN";
            let mut acc = if and { Pred::Tt } else { Pred::Ff };
            for p in ps.iter().rev() {
                acc = bin(pred(p, cols)?, acc, and);
            }
            acc
        }
        _ => return Err(bad()),
    })
}

fn tenant(req: &Json) -> Res<TenantId> {
    let t = s_of(req.get("tenant"), "tenant")?;
    parse_tenant_text(t).ok_or_else(|| "tenant handle is not the D4 TenantId text (16 lower-case hex, non-zero)".into())
}

fn sqlite_dialect(req: &Json) -> Res<()> {
    match req.get("dialect").and_then(Json::str) {
        None | Some("sqlite") => Ok(()),
        Some(d) => Err(format!("dialect {d} is not served by the SQLite adapter")),
    }
}

// --------------------------------------------------------------------------------------------- drop-tenant

/// Mutant: replace the first tenant atom with `(1=1)` and drop its parameter.
fn strip_tenant(mut r: Rendered, tenant_col: &str) -> Rendered {
    for a in ["", "\"a\".", "\"b\"."] {
        let c = format!("{a}\"{}\"", tenant_col.replace('"', "\"\""));
        let atom =
            format!("(CASE WHEN {c} IS NULL THEN NULL ELSE (typeof({c}) = 'text' AND +{c} = ? COLLATE BINARY) END)");
        if let Some(pos) = r.sql.find(&atom) {
            let idx = r.sql.get(..pos).map(|p| p.matches('?').count()).unwrap_or(0);
            r.sql.replace_range(pos..pos.saturating_add(atom.len()), "(1=1)");
            if idx < r.params.len() {
                r.params.remove(idx);
            }
            return r;
        }
    }
    r
}

// ------------------------------------------------------------------------------------------------- lowering

struct Lowering {
    drop_tenant: bool,
}

impl Lowering {
    fn handle(&self, req: &Json) -> Res<String> {
        match req.get("op").and_then(Json::str).unwrap_or("") {
            "hello" => Ok(r#""name":"monban-adapter-sqlite","protocol":2"#.into()),
            "read" => self.read(req),
            op @ ("update" | "delete" | "insert" | "upsert") => self.write(req, op),
            op @ ("kv_key" | "kv_get" | "kv_scan" | "kv_set" | "kv_setnx" | "kv_setxx" | "kv_del") => self.kv(req, op),
            op @ ("merge" | "cte" | "replace" | "raw_sql") => Err(format!(
                "op {op} refused: not a mandated form (MERGE, data-modifying CTE, REPLACE family, raw SQL)"
            )),
            op => Err(format!("op {op:?} not served by the SQLite adapter subject")),
        }
    }

    fn read(&self, req: &Json) -> Res<String> {
        sqlite_dialect(req)?;
        let t = tenant(req)?;
        let cols = Cols::new(req.get("columns"))?;
        let tname = s_of(req.get("tenant_field"), "tenant_field")?;
        let tf = cols.f(tname)?;
        let table = s_of(req.get("table"), "table")?;
        let p = pred(req.get("pred").ok_or("missing pred")?, &cols)?;
        let schema = Schema {
            collection: table.into(),
            tenant_field: tf,
            columns: cols
                .0
                .iter()
                .map(|(n, f)| Column {
                    field: *f,
                    name: n.clone(),
                    nullable: *f != tf,
                    collation: Collation::Binary,
                    key: false,
                })
                .collect(),
            permitted: cols.0.values().copied().collect(),
            unique_indexes: Vec::new(),
        };
        let op = Op {
            tenant: t,
            collection: table.into(),
            kind: OpKind::Select,
            filter: p,
            writes: Vec::new(),
            returning: Vec::new(),
        };
        let l = lower_op(&op, &schema, Fidelity::Exact).map_err(|e| format!("{e:?}"))?;
        let alias = match req.get("alias") {
            None | Some(Json::Null) => None,
            Some(Json::Str(a)) => Some(a.as_str()),
            Some(_) => return Err("alias must be a string or null".into()),
        };
        let mut r = render_where(&l, &schema, alias).map_err(|e| format!("{e:?}"))?;
        if self.drop_tenant {
            r = strip_tenant(r, tname);
        }
        Ok(sql_reply(&r))
    }

    fn write(&self, req: &Json, op: &str) -> Res<String> {
        sqlite_dialect(req)?;
        let t = tenant(req)?;
        let cols = Cols::new(req.get("columns"))?;
        let tname = s_of(req.get("tenant_field"), "tenant_field")?;
        let tf = cols.f(tname)?;
        let table = s_of(req.get("table"), "table")?;
        let key: Vec<Field> = arr(req.get("key"))?.iter().map(|j| cols.fj(j)).collect::<Res<_>>()?;
        let unique: Vec<Vec<Field>> = match req.get("unique") {
            None | Some(Json::Null) => vec![key.clone()],
            j => arr(j)?.iter().map(|u| arr(Some(u))?.iter().map(|c| cols.fj(c)).collect()).collect::<Res<_>>()?,
        };
        let returning: Vec<Field> = match req.get("returning") {
            None | Some(Json::Null) => Vec::new(),
            j => arr(j)?.iter().map(|c| cols.fj(c)).collect::<Res<_>>()?,
        };
        let mut fks_out = Vec::new();
        if let Some(j @ Json::Arr(_)) = req.get("fks") {
            for fk in arr(Some(j))? {
                let local = arr(fk.get("columns"))?.iter().map(|c| cols.fj(c)).collect::<Res<Vec<_>>>()?;
                let remote = arr(fk.get("ref_columns"))?
                    .iter()
                    .map(|c| c.str().map(String::from).ok_or_else(|| String::from("ref column")))
                    .collect::<Res<Vec<_>>>()?;
                let rt = fk.get("ref_tenant_field").and_then(Json::str).unwrap_or(tname);
                fks_out.push(ForeignKey {
                    local,
                    remote_table: s_of(fk.get("ref_table"), "ref_table")?.into(),
                    remote,
                    remote_tenant: Some(rt.into()),
                });
            }
        }
        let schema = Schema {
            collection: table.into(),
            tenant_field: tf,
            columns: cols
                .0
                .iter()
                .map(|(n, f)| Column {
                    field: *f,
                    name: n.clone(),
                    nullable: *f != tf,
                    collation: Collation::Binary,
                    key: *f != tf && key.contains(f),
                })
                .collect(),
            permitted: returning.clone(),
            unique_indexes: unique.into_iter().map(|fields| UniqueIndex { fields, prefix: false }).collect(),
        };
        let entries = |name: &str| -> Res<Vec<(Field, Value)>> {
            match req.get(name) {
                Some(Json::Obj(m)) => m.iter().map(|(k, v)| Ok((cols.f(k)?, val(v)?))).collect(),
                _ => Err(format!("missing {name} object")),
            }
        };
        let (kind, filter, writes) = match op {
            "update" => (OpKind::Update, pred(req.get("pred").ok_or("missing pred")?, &cols)?, entries("set")?),
            "delete" => (OpKind::Delete, pred(req.get("pred").ok_or("missing pred")?, &cols)?, Vec::new()),
            "insert" => (OpKind::Insert, Pred::Tt, entries("row")?),
            _ => (OpKind::Upsert, Pred::Tt, entries("row")?),
        };
        let o = Op { tenant: t, collection: table.into(), kind, filter, writes, returning };
        let mut l = lower_op(&o, &schema, Fidelity::Exact).map_err(|e| format!("{e:?}"))?;
        if let Stmt::Upsert { row, action, .. } = &mut l.stmt {
            let upd: Vec<Field> = arr(req.get("update"))?.iter().map(|c| cols.fj(c)).collect::<Res<_>>()?;
            for f in &upd {
                if *f == tf || key.contains(f) || !row.iter().any(|(g, _)| g == f) {
                    return Err("DO UPDATE column must be a written non-key, non-tenant column".into());
                }
            }
            *action = if upd.is_empty() { UpsertAction::Nothing } else { UpsertAction::Update { set: upd, guard: tf } };
        }
        let tbl = Table { schema, fks_out, fks_in: Vec::new() };
        let mut r = render_lowered(&l, &tbl).map_err(|e| format!("{e:?}"))?;
        if self.drop_tenant && matches!(kind, OpKind::Update | OpKind::Delete) {
            r = strip_tenant(r, tname);
        }
        Ok(sql_reply(&r))
    }

    fn kv(&self, req: &Json, op: &str) -> Res<String> {
        let t = tenant(req)?;
        let coll = s_of(req.get("collection"), "collection")?;
        let col = |field: Field, name: &str, nullable: bool, key: bool| Column {
            field,
            name: name.into(),
            nullable,
            collation: Collation::Binary,
            key,
        };
        let schema = Schema {
            collection: coll.into(),
            tenant_field: 0,
            columns: vec![col(0, "tenant", false, false), col(1, "k", false, true), col(2, "v", true, false)],
            permitted: vec![1, 2],
            unique_indexes: vec![UniqueIndex { fields: vec![0, 1], prefix: false }],
        };
        let key = || utf8_hex(req.get("key_hex"));
        let value = || match req.get("value_hex") {
            None => Ok(String::new()),
            j => utf8_hex(j),
        };
        let (kind, filter, writes) = match op {
            "kv_key" | "kv_get" => (OpKind::Select, Pred::Eq(1, Value::Str(key()?)), Vec::new()),
            "kv_scan" => match req.get("prefix_hex") {
                None | Some(Json::Null) => (OpKind::Select, Pred::Tt, Vec::new()),
                j => (OpKind::Select, Pred::Pfx(1, utf8_hex(j)?), Vec::new()),
            },
            "kv_set" => (OpKind::Upsert, Pred::Tt, vec![(1, Value::Str(key()?)), (2, Value::Str(value()?))]),
            "kv_setnx" => (OpKind::Insert, Pred::Tt, vec![(1, Value::Str(key()?)), (2, Value::Str(value()?))]),
            "kv_setxx" => (OpKind::Update, Pred::Eq(1, Value::Str(key()?)), vec![(2, Value::Str(value()?))]),
            _ => (OpKind::Delete, Pred::Eq(1, Value::Str(key()?)), Vec::new()),
        };
        let o = Op { tenant: t, collection: coll.into(), kind, filter, writes, returning: Vec::new() };
        let cmd = kv_plan(&o, &schema).map_err(|e| format!("{e:?}"))?;
        let prefix = kv_key_prefix(t);
        let k = |s: &str| -> String {
            let s = if self.drop_tenant { s.strip_prefix(prefix.as_str()).unwrap_or(s) } else { s };
            hex(s.as_bytes())
        };
        let h = |s: &str| hex(s.as_bytes());
        let cmds =
            |c: Vec<String>| format!("\"commands\":[[{}]]", c.iter().map(|x| esc(x)).collect::<Vec<_>>().join(","));
        Ok(match (op, cmd) {
            ("kv_key", KvCommand::Get { key }) => format!("\"key_hex\":{}", esc(&k(&key))),
            ("kv_get", KvCommand::Get { key }) => cmds(vec![h("GET"), k(&key)]),
            ("kv_scan", KvCommand::Scan { pattern }) => format!("\"pattern_hex\":{}", esc(&k(&pattern))),
            ("kv_set", KvCommand::Set { key, value }) => cmds(vec![h("SET"), k(&key), h(&value)]),
            ("kv_setnx", KvCommand::SetNx { key, value }) => cmds(vec![h("SET"), k(&key), h(&value), h("NX")]),
            ("kv_setxx", KvCommand::SetXx { key, value }) => cmds(vec![h("SET"), k(&key), h(&value), h("XX")]),
            ("kv_del", KvCommand::Del { key }) => cmds(vec![h("DEL"), k(&key)]),
            _ => return Err("kv_plan chose another command".into()),
        })
    }
}

// --------------------------------------------------------------------------------------------- schema gate

fn field(j: &Json) -> Option<Field> {
    j.u64().and_then(|v| Field::try_from(v).ok())
}

fn fields(j: Option<&Json>) -> Option<Vec<Field>> {
    match j? {
        Json::Arr(a) => a.iter().map(field).collect(),
        _ => None,
    }
}

fn parse_schema(j: &Json) -> Option<Schema> {
    let Json::Arr(cols) = j.get("columns")? else { return None };
    let mut columns = Vec::with_capacity(cols.len());
    for c in cols {
        columns.push(Column {
            field: field(c.get("field")?)?,
            name: c.get("name")?.str()?.to_string(),
            nullable: c.get("nullable")?.bool()?,
            collation: match c.get("collation")?.str()? {
                "Binary" => Collation::Binary,
                "PadSpace" => Collation::PadSpace,
                "CaseInsensitive" => Collation::CaseInsensitive,
                "Nondeterministic" => Collation::Nondeterministic,
                _ => return None,
            },
            key: c.get("key")?.bool()?,
        });
    }
    let Json::Arr(idx) = j.get("unique_indexes")? else { return None };
    let mut unique_indexes = Vec::with_capacity(idx.len());
    for u in idx {
        unique_indexes.push(UniqueIndex { fields: fields(u.get("fields"))?, prefix: u.get("prefix")?.bool()? });
    }
    Some(Schema {
        collection: j.get("collection")?.str()?.to_string(),
        tenant_field: field(j.get("tenant_field")?)?,
        columns,
        permitted: fields(j.get("permitted"))?,
        unique_indexes,
    })
}

fn schema_gate(req: &Json) -> String {
    if req.get("op").and_then(Json::str) != Some("schema") {
        return r#""error":"unknown op""#.into();
    }
    match req.get("mode").and_then(Json::str) {
        Some("static") => {
            let Some(s) = req.get("schema").and_then(parse_schema) else {
                return r#""refuse":"Malformed(schema)""#.into();
            };
            let Ok(t) = TenantId::new(1) else { return r#""error":"tenant id""#.into() };
            let probe = Op {
                tenant: t,
                collection: s.collection.clone(),
                kind: OpKind::Upsert,
                filter: Pred::Tt,
                writes: Vec::new(),
                returning: Vec::new(),
            };
            match check_schema(&probe, &s, Fidelity::Exact) {
                Ok(()) => r#""ok":true"#.into(),
                Err(e) => format!("\"refuse\":{}", esc(&format!("{e:?}"))),
            }
        }
        Some("sqlite") => {
            let Some(mut declared) = req.get("declared").and_then(parse_schema) else {
                return r#""refuse":"Malformed(declared)""#.into();
            };
            let (Some(path), Some(coll)) =
                (req.get("path").and_then(Json::str), req.get("collection").and_then(Json::str))
            else {
                return r#""refuse":"Malformed(request)""#.into();
            };
            declared.collection = coll.into();
            let db = match SqliteDb::open(Path::new(path), OpenMode::ReadOnly) {
                Ok(db) => db,
                Err(e) => return format!("\"error\":{}", esc(&format!("open: {e:?}"))),
            };
            match db.check_schema(&declared, &|_| None) {
                Ok(_) => r#""ok":true"#.into(),
                Err(monban_adapter_sqlite::LiveError::Schema(e)) => format!("\"refuse\":{}", esc(&format!("{e:?}"))),
                Err(e) => format!("\"refuse\":{}", esc(&format!("{e:?}"))),
            }
        }
        Some(m) => format!("\"error\":{}", esc(&format!("mode {m} is not served by sqlite-subject"))),
        None => r#""error":"missing mode""#.into(),
    }
}

// ------------------------------------------------------------------------------------------------- serve

fn id_json(req: Option<&Json>) -> String {
    match req.and_then(|r| r.get("id")) {
        Some(Json::Num(n)) => n.clone(),
        Some(Json::Str(s)) => esc(s),
        _ => "null".into(),
    }
}

fn serve(v: u32, handle: &dyn Fn(&Json) -> String) -> ExitCode {
    let stdin = std::io::stdin();
    let mut out = BufWriter::new(std::io::stdout().lock());
    for line in stdin.lock().lines() {
        let Ok(line) = line else { return ExitCode::from(2) };
        if line.trim().is_empty() {
            continue;
        }
        let (id, body) = match json::parse(&line) {
            Ok(req) => (id_json(Some(&req)), handle(&req)),
            Err(e) => (id_json(None), format!("\"refuse\":{}", esc(&format!("bad json: {e}")))),
        };
        if writeln!(out, "{{\"v\":{v},\"id\":{id},{body}}}").and_then(|()| out.flush()).is_err() {
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["lowering"] | ["lowering", "--mutant", "drop-tenant"] => {
            let l = Lowering { drop_tenant: a.len() == 3 };
            serve(2, &|req| match l.handle(req) {
                Ok(body) => body,
                Err(why) => format!("\"refuse\":{}", esc(&why)),
            })
        }
        ["schema"] => serve(1, &schema_gate),
        _ => {
            eprintln!("usage: sqlite-subject lowering [--mutant drop-tenant] | sqlite-subject schema");
            ExitCode::from(2)
        }
    }
}
