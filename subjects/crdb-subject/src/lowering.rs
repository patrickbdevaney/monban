//! `crdb-subject lowering`: the lowering-read / lowering-write subject protocol v2 (oracles/lowering-read/README.md,
//! oracles/lowering-write/README.md, section "MariaDB and CockroachDB"), dialect `crdb`, served by the production
//! code path:
//!
//! request → F4 `Op` + `Schema` + renderer `PgTable` (from the request's declaration) → `aegis_data_ir::lower_op`
//! (F4 `check_schema`, shape rules, `lowerQ`) → `aegis_adapter_pg::lower::{render_dialect(.., Dialect::Crdb),
//! render_filter}`. The crdb forms are the postgres forms (`$n`, `c::text = $n::text COLLATE "C"`, `::bigint`,
//! `left(c::text, $n::int)`) with the q4-005 upsert guard `"t"."tenant"::text = excluded."tenant"::text COLLATE "C"`;
//! the `UPSERT` statement is never rendered.
//!
//! This file is pg-subject's `lowering.rs` with the dialect switched, so the two subjects map requests to the IR
//! identically.
//!
//! Protocol adaptation, stated so nothing is hidden:
//! * columns are numbered in name order (the JSON object's key order is not significant);
//! * the tenant column is declared Binary and NOT NULL in the F4 schema (the renderer compares it byte-wise under
//!   `COLLATE "C"` whatever the column's collation; the live collation is the schema gate's business, `schema` mode);
//! * JSON integers outside i64 (Lean `Value.int` is unbounded, F4 `Value::Int` is i64) are mapped to an equivalent
//!   in-range predicate: `eq f big` → the empty integer range `range f i64::MAX i64::MIN`, `in` drops them, `range`
//!   clamps (or becomes empty when a bound lies beyond the other end); in written values they are refused;
//! * an upsert's `update` list narrows `UpsertAction::Update.set` (F4 DO UPDATE sets every written non-key column);
//!   it must be a subset of the written non-key columns, an empty list is DO NOTHING;
//! * `rls_policy` / `rls_bind` are refused: row level security is not part of the crdb dialect (PREFLIGHT D-P7.8).
//!
//! `--mutant drop-tenant` (self-test only) removes the tenant conjunct (the left child of the root `And`) from every
//! lowered filter before rendering. Everything else is refused with a reason: any dialect but `crdb`, KV ops, RLS
//! ops, `merge`, `cte`, `replace`, `raw_sql`, unknown ops, malformed requests.

use std::collections::BTreeMap;
use std::process::ExitCode;

use aegis_adapter_pg::TenantId;
use aegis_adapter_pg::data_ir::{
    Collation, Column, Fidelity, Field, Lowered, Op, OpKind, Pred, Schema, SqlExpr, Stmt, UniqueIndex, UpsertAction,
    Value, lower_op, parse_tenant_text,
};
use aegis_adapter_pg::lower::{
    Dialect, Param, PgClass, PgColumn, PgForeignKey, PgTable, Rendered, render_dialect, render_filter,
};

use crate::json::{self, Json, emit, esc};

const PROTOCOL: u32 = 2;

type R<T> = Result<T, String>;

/// A JSON literal as a Lean value: in-range int, out-of-range int (sign), or string.
enum JVal {
    Int(i64),
    BigPos,
    BigNeg,
    Str(String),
}

fn jval(j: &Json) -> R<JVal> {
    match j {
        Json::Str(s) => Ok(JVal::Str(s.clone())),
        Json::Num(t) => {
            let digits = t.strip_prefix('-').unwrap_or(t);
            if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
                return Err(format!("value {t} is not an integer"));
            }
            match t.parse::<i64>() {
                Ok(i) => Ok(JVal::Int(i)),
                Err(_) if t.starts_with('-') => Ok(JVal::BigNeg),
                Err(_) => Ok(JVal::BigPos),
            }
        }
        _ => Err("value is not an int or a string".into()),
    }
}

fn write_value(j: &Json) -> R<Value> {
    match jval(j)? {
        JVal::Int(i) => Ok(Value::Int(i)),
        JVal::Str(s) => Ok(Value::Str(s)),
        JVal::BigPos | JVal::BigNeg => Err("written integer outside i64".into()),
    }
}

fn arr(j: Option<&Json>) -> R<&[Json]> {
    match j {
        Some(Json::Arr(a)) => Ok(a),
        _ => Err("expected an array".into()),
    }
}

fn obj(j: Option<&Json>) -> R<&BTreeMap<String, Json>> {
    match j {
        Some(Json::Obj(m)) => Ok(m),
        _ => Err("expected an object".into()),
    }
}

fn s<'a>(req: &'a Json, k: &str) -> R<&'a str> {
    req.get(k).and_then(Json::str).ok_or_else(|| format!("missing string {k}"))
}

/// The request's declared table: names (in name order = field numbers), PG classes.
struct Decl {
    names: Vec<String>,
    table: PgTable,
    tenant_field: Field,
}

impl Decl {
    fn field(&self, name: &str) -> R<Field> {
        let i = self.names.iter().position(|n| n == name).ok_or_else(|| format!("unknown column {name:?}"))?;
        u32::try_from(i).map_err(|_| "too many columns".to_string())
    }
    fn fields(&self, j: Option<&Json>) -> R<Vec<Field>> {
        arr(j)?
            .iter()
            .map(|n| n.str().ok_or_else(|| "column name not a string".to_string()).and_then(|n| self.field(n)))
            .collect()
    }
}

fn decl(req: &Json) -> R<Decl> {
    if s(req, "dialect")? != "crdb" {
        return Err("refused: crdb-subject renders the crdb dialect only".into());
    }
    let cols = obj(req.get("columns"))?;
    let mut names = Vec::with_capacity(cols.len());
    let mut columns = Vec::with_capacity(cols.len());
    for (i, (name, ty)) in cols.iter().enumerate() {
        let field = u32::try_from(i).map_err(|_| "too many columns".to_string())?;
        let ty = ty.str().ok_or("column type not a string")?;
        names.push(name.clone());
        columns.push(PgColumn { field, name: name.clone(), class: PgClass::of_type_name(ty) });
    }
    let table =
        PgTable { namespace: None, name: s(req, "table")?.to_owned(), columns, unique: Vec::new(), fks: Vec::new() };
    let mut d = Decl { names, table, tenant_field: 0 };
    d.tenant_field = d.field(s(req, "tenant_field")?)?;
    Ok(d)
}

fn tenant(req: &Json) -> R<TenantId> {
    req.get("tenant")
        .and_then(Json::str)
        .and_then(parse_tenant_text)
        .ok_or_else(|| "refused: tenant handle is not the D4 canonical TenantId text".to_string())
}

fn pred(d: &Decl, j: &Json) -> R<Pred> {
    let a = match j {
        Json::Arr(a) => a.as_slice(),
        _ => return Err("malformed pred".into()),
    };
    let (Some(k), rest) = (a.first().and_then(Json::str), a.get(1..).unwrap_or(&[])) else {
        return Err("malformed pred".into());
    };
    let fld = |i: usize| -> R<Field> {
        rest.get(i).and_then(Json::str).ok_or_else(|| format!("{k}: field")).and_then(|n| d.field(n))
    };
    let arg = |i: usize| rest.get(i).ok_or_else(|| format!("{k}: arity"));
    let n = rest.len();
    let empty_range = |f: Field| Pred::Range(f, Value::Int(i64::MAX), Value::Int(i64::MIN));
    Ok(match (k, n) {
        ("tt", 0) => Pred::Tt,
        ("ff", 0) => Pred::Ff,
        ("eq", 2) => {
            let f = fld(0)?;
            match jval(arg(1)?)? {
                JVal::Int(i) => Pred::Eq(f, Value::Int(i)),
                JVal::Str(v) => Pred::Eq(f, Value::Str(v)),
                JVal::BigPos | JVal::BigNeg => empty_range(f),
            }
        }
        ("in", 2) => {
            let f = fld(0)?;
            let mut vs = Vec::new();
            for v in arr(Some(arg(1)?))? {
                match jval(v)? {
                    JVal::Int(i) => vs.push(Value::Int(i)),
                    JVal::Str(v) => vs.push(Value::Str(v)),
                    JVal::BigPos | JVal::BigNeg => {}
                }
            }
            Pred::IsIn(f, vs)
        }
        ("range", 3) => {
            let f = fld(0)?;
            match (jval(arg(1)?)?, jval(arg(2)?)?) {
                (JVal::Str(a), JVal::Str(b)) => Pred::Range(f, Value::Str(a), Value::Str(b)),
                // Mixed classes never match (refLe); keep the string, any integer stands for the other bound.
                (JVal::Str(a), _) => Pred::Range(f, Value::Str(a), Value::Int(0)),
                (_, JVal::Str(b)) => Pred::Range(f, Value::Int(0), Value::Str(b)),
                (lo, hi) => {
                    let lo = match lo {
                        JVal::Int(i) => Some(i),
                        JVal::BigNeg => Some(i64::MIN),
                        _ => None, // above every i64: empty
                    };
                    let hi = match hi {
                        JVal::Int(i) => Some(i),
                        JVal::BigPos => Some(i64::MAX),
                        _ => None, // below every i64: empty
                    };
                    match (lo, hi) {
                        (Some(a), Some(b)) => Pred::Range(f, Value::Int(a), Value::Int(b)),
                        _ => empty_range(f),
                    }
                }
            }
        }
        ("pfx", 2) => Pred::Pfx(fld(0)?, arg(1)?.str().ok_or("pfx: string")?.to_owned()),
        ("and", 2) => Pred::And(Box::new(pred(d, arg(0)?)?), Box::new(pred(d, arg(1)?)?)),
        ("or", 2) => Pred::Or(Box::new(pred(d, arg(0)?)?), Box::new(pred(d, arg(1)?)?)),
        ("not", 1) => Pred::Not(Box::new(pred(d, arg(0)?)?)),
        ("andN", 1) | ("orN", 1) => {
            let ps = arr(Some(arg(0)?))?.iter().map(|p| pred(d, p)).collect::<R<Vec<_>>>()?;
            if k == "andN" { Pred::and_n(ps) } else { Pred::or_n(ps) }
        }
        _ => return Err(format!("malformed pred {k:?}")),
    })
}

/// The F4 schema for a request: tenant Binary NOT NULL, `key` flags, `unique` indexes, `permitted` as given.
fn schema(d: &Decl, keys: &[Field], unique: &[Vec<Field>], permitted: Vec<Field>) -> Schema {
    Schema {
        collection: d.table.name.clone(),
        tenant_field: d.tenant_field,
        columns: d
            .table
            .columns
            .iter()
            .map(|c| Column {
                field: c.field,
                name: c.name.clone(),
                nullable: c.field != d.tenant_field,
                collation: Collation::Binary,
                key: keys.contains(&c.field),
            })
            .collect(),
        permitted,
        unique_indexes: unique.iter().map(|u| UniqueIndex { fields: u.clone(), prefix: false }).collect(),
    }
}

fn drop_tenant(e: SqlExpr) -> SqlExpr {
    match e {
        SqlExpr::And(_, body) => *body,
        other => other,
    }
}

fn mutate(mut l: Lowered) -> Lowered {
    l.stmt = match l.stmt {
        Stmt::Select { filter } => Stmt::Select { filter: drop_tenant(filter) },
        Stmt::Delete { filter } => Stmt::Delete { filter: drop_tenant(filter) },
        Stmt::Update { set, filter } => Stmt::Update { set, filter: drop_tenant(filter) },
        other => other,
    };
    l
}

fn params_json(ps: &[Param]) -> String {
    let v: Vec<String> = ps
        .iter()
        .map(|p| match p {
            Param::Int(i) => i.to_string(),
            Param::Text(t) => esc(t),
        })
        .collect();
    format!("[{}]", v.join(","))
}

fn sql_reply(r: &Rendered) -> String {
    format!("\"sql\":{},\"params\":{}", esc(&r.sql), params_json(&r.params))
}

fn read(req: &Json, mutant: bool) -> R<String> {
    let d = decl(req)?;
    let t = tenant(req)?;
    let p = pred(&d, req.get("pred").ok_or("missing pred")?)?;
    let all: Vec<Field> = d.table.columns.iter().map(|c| c.field).collect();
    let sc = schema(&d, &[], &[], all);
    let op = Op {
        tenant: t,
        collection: d.table.name.clone(),
        kind: OpKind::Select,
        filter: p,
        writes: Vec::new(),
        returning: Vec::new(),
    };
    let mut l = lower_op(&op, &sc, Fidelity::Exact).map_err(|e| format!("refused: {e:?}"))?;
    if mutant {
        l = mutate(l);
    }
    let Stmt::Select { filter } = &l.stmt else { return Err("internal: not a select".into()) };
    let alias = match req.get("alias") {
        None | Some(Json::Null) => None,
        Some(Json::Str(a)) => Some(a.as_str()),
        _ => return Err("alias".into()),
    };
    let offset = match req.get("param_offset") {
        None => 0,
        Some(Json::Num(n)) => n.parse::<usize>().map_err(|_| "param_offset".to_string())?,
        _ => return Err("param_offset".into()),
    };
    let r = render_filter(filter, &d.table, alias, offset).map_err(|e| format!("refused: {e:?}"))?;
    Ok(sql_reply(&r))
}

fn write(req: &Json, op_name: &str, mutant: bool) -> R<String> {
    let mut d = decl(req)?;
    let t = tenant(req)?;
    let keys = d.fields(req.get("key"))?;
    let unique: Vec<Vec<Field>> = match req.get("unique") {
        None | Some(Json::Null) => vec![keys.clone()],
        Some(u) => arr(Some(u))?.iter().map(|k| d.fields(Some(k))).collect::<R<_>>()?,
    };
    let mut fks = Vec::new();
    if let Some(Json::Arr(list)) = req.get("fks") {
        for fk in list {
            let ref_columns = arr(fk.get("ref_columns"))?
                .iter()
                .map(|c| c.str().map(str::to_owned).ok_or_else(|| "ref column".to_string()))
                .collect::<R<Vec<_>>>()?;
            let ref_tenant = match fk.get("ref_tenant_field") {
                None => s(req, "tenant_field")?.to_owned(),
                Some(j) => j.str().ok_or("ref_tenant_field")?.to_owned(),
            };
            fks.push(PgForeignKey {
                columns: d.fields(fk.get("columns"))?,
                ref_table: s(fk, "ref_table")?.to_owned(),
                ref_columns,
                ref_tenant_column: Some(ref_tenant),
            });
        }
    }
    d.table.unique = unique.clone();
    d.table.fks = fks;
    let returning = d.fields(req.get("returning"))?;
    let sc = schema(&d, &keys, &unique, returning.clone());
    let assoc = |m: &BTreeMap<String, Json>| -> R<Vec<(Field, Value)>> {
        m.iter().map(|(k, v)| Ok((d.field(k)?, write_value(v)?))).collect()
    };
    let (kind, filter, writes) = match op_name {
        "update" => (OpKind::Update, pred(&d, req.get("pred").ok_or("missing pred")?)?, assoc(obj(req.get("set"))?)?),
        "delete" => (OpKind::Delete, pred(&d, req.get("pred").ok_or("missing pred")?)?, Vec::new()),
        "insert" => (OpKind::Insert, Pred::Tt, assoc(obj(req.get("row"))?)?),
        "upsert" => (OpKind::Upsert, Pred::Tt, assoc(obj(req.get("row"))?)?),
        _ => return Err(format!("unknown op {op_name:?}")),
    };
    let op = Op { tenant: t, collection: d.table.name.clone(), kind, filter, writes, returning };
    let mut l = lower_op(&op, &sc, Fidelity::Exact).map_err(|e| format!("refused: {e:?}"))?;
    if kind == OpKind::Upsert {
        let upd = d.fields(req.get("update"))?;
        if let Stmt::Upsert { action, .. } = &mut l.stmt {
            let allowed: Vec<Field> = match action {
                UpsertAction::Update { set, .. } => set.clone(),
                UpsertAction::Nothing => Vec::new(),
            };
            if let Some(f) = upd.iter().find(|f| !allowed.contains(f)) {
                return Err(format!("refused: DO UPDATE of column {f} (tenant, key or not written)"));
            }
            *action = if upd.is_empty() {
                UpsertAction::Nothing
            } else {
                UpsertAction::Update { set: upd, guard: d.tenant_field }
            };
        }
    }
    if mutant {
        l = mutate(l);
    }
    let r = render_dialect(&l, &d.table, Dialect::Crdb).map_err(|e| format!("refused: {e:?}"))?;
    Ok(sql_reply(&r))
}

fn handle(req: &Json, mutant: bool) -> R<String> {
    match req.get("op").and_then(Json::str) {
        Some("hello") => Ok(format!(
            "\"name\":\"crdb-subject lowering (aegis-adapter-pg::lower, Dialect::Crdb)\",\"protocol\":{PROTOCOL},\"mutants\":{}",
            if mutant { "[\"drop-tenant\"]" } else { "[]" }
        )),
        Some("read") => read(req, mutant),
        Some(op @ ("update" | "delete" | "insert" | "upsert")) => write(req, op, mutant),
        Some(op @ ("rls_policy" | "rls_bind")) => {
            Err(format!("refused: {op}: row level security is not part of the crdb dialect"))
        }
        Some(op @ ("merge" | "cte" | "replace" | "raw_sql")) => Err(format!("refused: op {op} is never rendered")),
        Some(op) if op.starts_with("kv_") => Err(format!("refused: {op} is not a CockroachDB op")),
        other => Err(format!("refused: unknown op {other:?}")),
    }
}

pub fn serve(mutant: bool) -> ExitCode {
    crate::serve_lines(|line| {
        let (id, body) = match line.map(json::parse) {
            None => (Json::Null, Err("request line too long".to_string())),
            Some(Err(e)) => (Json::Null, Err(format!("bad request: {e}"))),
            Some(Ok(req)) => (req.get("id").cloned().unwrap_or(Json::Null), handle(&req, mutant)),
        };
        let body = body.unwrap_or_else(|r| format!("\"refuse\":{}", esc(&r)));
        format!("{{\"v\":{PROTOCOL},\"id\":{},{body}}}", emit(&id))
    })
}
