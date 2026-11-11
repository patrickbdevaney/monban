//! `host-subject nonempty`: oracles/nonempty-props subject protocol (README "Subject protocol").
//!
//! Per request: the wire capset becomes an `Endowment` (the F8 `data` shape, parsed strictly: one malformed element
//! fails the whole capset), monban-adapter-host converts it to a `CapSet` (`host::endow::capset`), and the op goes
//! through `dispatch::prepare` (authorize → check_schema → allowlist → budget pre-debit → render) against the
//! adapter's renderer with the request's schema as the introspected schema. `decision` is whether the
//! authorization stage passed; `rendered` is whether `prepare` reached the renderer, as reported by the pipeline
//! itself (`Ok`, or `Refusal::Render`), never set by this file.

use std::io::{BufRead, Write};

use monban_adapter_host::dispatch::{self, DispatchMutations, Refusal, Renderer};
use monban_adapter_host::host::budget::{Remaining, RequestBudget};
use monban_adapter_host::host::endow::{self, CapParts, Endowment};
use monban_adapter_host::host::oop::OopRenderer;
use monban_data_ir::{Collation, Column, Op, OpKind, Pred, Schema, UniqueIndex, Value, parse_tenant_text};

use crate::engines::{KvRenderer, PgRenderer, SqliteRenderer};
use crate::json::{self, Json};

/// The five mutants the oracle requires (README "Self-test").
pub const MUTATIONS: &[&str] =
    &["empty-means-all", "missing-capset-means-all", "unrestricted-implicit", "deny-everything", "render-on-deny"];

pub fn mutations(name: &str) -> Option<DispatchMutations> {
    let mut m = DispatchMutations::NONE;
    match name {
        "empty-means-all" => m.empty_means_all = true,
        "missing-capset-means-all" => m.missing_means_all = true,
        "unrestricted-implicit" => m.unrestricted_implicit = true,
        "deny-everything" => m.deny_everything = true,
        "render-on-deny" => m.render_on_deny = true,
        _ => return None,
    }
    Some(m)
}

fn arr(j: &Json) -> Option<&[Json]> {
    match j {
        Json::Arr(v) => Some(v),
        _ => None,
    }
}

fn u32_of(j: &Json) -> Option<u32> {
    match j {
        Json::Num(t) => t.parse::<u32>().ok(),
        _ => None,
    }
}

fn i64_of(j: &Json) -> Option<i64> {
    match j {
        Json::Num(t) => t.parse::<i64>().ok(),
        _ => None,
    }
}

fn kind_of(s: &str) -> Option<OpKind> {
    OpKind::from_name(s)
}

/// F8-shaped capset → endowment. Absent → `Absent`; `null`, any non-list other than the exact `"unrestricted"`,
/// and any list with a malformed element → `Failed` (deny). A cap must have exactly the four members with the
/// right types; op names must be the five F8 names; columns u32.
fn endowment(req: &Json) -> Endowment {
    let Some(v) = req.get("capset") else { return Endowment::Absent };
    match v {
        Json::Str(s) if s == "unrestricted" => Endowment::Unrestricted,
        Json::Arr(items) => {
            let mut parts = Vec::with_capacity(items.len());
            for c in items {
                match cap_parts(c) {
                    Some(p) => parts.push(p),
                    None => return Endowment::Failed,
                }
            }
            Endowment::Caps(parts)
        }
        _ => Endowment::Failed,
    }
}

fn cap_parts(c: &Json) -> Option<CapParts> {
    let Json::Obj(m) = c else { return None };
    if m.len() != 4 {
        return None;
    }
    let backend = m.get("adapter")?.str()?.to_string();
    let collection = m.get("collection")?.str()?.to_string();
    let mut ops_bits = 0u8;
    for o in arr(m.get("ops")?)? {
        ops_bits |= kind_of(o.str()?)?.bit();
    }
    let mut fields = Vec::new();
    for f in arr(m.get("columns")?)? {
        fields.push(u32_of(f)?);
    }
    Some(CapParts { backend, collection, ops_bits, fields })
}

fn value(j: &Json) -> Option<Value> {
    match j {
        Json::Str(s) => Some(Value::Str(s.clone())),
        Json::Num(_) => i64_of(j).map(Value::Int),
        _ => None,
    }
}

const MAX_PRED_NEST: usize = 128;

fn pred(j: &Json, depth: usize) -> Option<Pred> {
    if depth > MAX_PRED_NEST {
        return None;
    }
    let a = arr(j)?;
    let (tag, rest) = a.split_first()?;
    let at = |i: usize| rest.get(i);
    Some(match (u32_of(tag)?, rest.len()) {
        (0, 0) => Pred::Tt,
        (1, 0) => Pred::Ff,
        (2, 2) => Pred::Eq(u32_of(at(0)?)?, value(at(1)?)?),
        (3, 2) => Pred::IsIn(u32_of(at(0)?)?, arr(at(1)?)?.iter().map(value).collect::<Option<Vec<_>>>()?),
        (4, 3) => Pred::Range(u32_of(at(0)?)?, value(at(1)?)?, value(at(2)?)?),
        (5, 2) => Pred::Pfx(u32_of(at(0)?)?, at(1)?.str()?.to_string()),
        (6, 2) => Pred::And(Box::new(pred(at(0)?, depth + 1)?), Box::new(pred(at(1)?, depth + 1)?)),
        (7, 2) => Pred::Or(Box::new(pred(at(0)?, depth + 1)?), Box::new(pred(at(1)?, depth + 1)?)),
        (8, 1) => Pred::Not(Box::new(pred(at(0)?, depth + 1)?)),
        _ => return None,
    })
}

fn data_op(j: &Json) -> Option<Op> {
    let tenant = parse_tenant_text(j.get("tenant")?.str()?)?;
    let collection = j.get("collection")?.str()?.to_string();
    let kind = kind_of(j.get("kind")?.str()?)?;
    let filter = pred(j.get("filter")?, 0)?;
    let mut writes = Vec::new();
    for w in arr(j.get("writes")?)? {
        let pair = arr(w)?;
        let [f, v] = pair else { return None };
        writes.push((u32_of(f)?, value(v)?));
    }
    let returning = arr(j.get("returning")?)?.iter().map(u32_of).collect::<Option<Vec<_>>>()?;
    Some(Op { tenant, collection, kind, filter, writes, returning })
}

fn collation(s: &str) -> Option<Collation> {
    Some(match s {
        "binary" => Collation::Binary,
        "padspace" => Collation::PadSpace,
        "nocase" | "case_insensitive" => Collation::CaseInsensitive,
        "nondeterministic" => Collation::Nondeterministic,
        _ => return None,
    })
}

fn schema(j: &Json) -> Option<Schema> {
    let mut columns = Vec::new();
    for c in arr(j.get("columns")?)? {
        columns.push(Column {
            field: u32_of(c.get("field")?)?,
            name: c.get("name")?.str()?.to_string(),
            nullable: matches!(c.get("nullable")?, Json::Bool(true)),
            collation: collation(c.get("collation")?.str()?)?,
            key: matches!(c.get("key")?, Json::Bool(true)),
        });
    }
    let mut unique_indexes = Vec::new();
    for u in arr(j.get("unique_indexes")?)? {
        unique_indexes.push(UniqueIndex {
            fields: arr(u.get("fields")?)?.iter().map(u32_of).collect::<Option<Vec<_>>>()?,
            prefix: matches!(u.get("prefix")?, Json::Bool(true)),
        });
    }
    Some(Schema {
        collection: j.get("collection")?.str()?.to_string(),
        tenant_field: u32_of(j.get("tenant_field")?)?,
        columns,
        permitted: arr(j.get("permitted")?)?.iter().map(u32_of).collect::<Option<Vec<_>>>()?,
        unique_indexes,
    })
}

/// (decision allowed, render reached) through the real pipeline.
fn judge<R: Renderer>(r: &R, caps: Option<&monban_data_ir::CapSet>, op: &Op, m: DispatchMutations) -> (bool, bool) {
    let budget = RequestBudget::new(Remaining::DEFAULT);
    match dispatch::prepare_with(caps, r, op, &budget, m) {
        Ok(_) => (true, true),
        Err((refusal, rendered)) => (refusal != Refusal::Denied, rendered),
    }
}

fn case(req: &Json, m: DispatchMutations) -> Result<(String, bool, bool), String> {
    let id = match req.get("case") {
        Some(Json::Num(t)) => t.clone(),
        _ => return Err("missing case".into()),
    };
    if req.get("op").and_then(Json::str) != Some("authorize") {
        return Err("op is not authorize".into());
    }
    let adapter = req.get("adapter").and_then(Json::str).ok_or("missing adapter")?;
    let schema = req.get("schema").and_then(schema).ok_or("bad schema")?;
    let op = req.get("data_op").and_then(data_op).ok_or("bad data_op")?;
    let conv = endow::capset_with(&endowment(req), m);
    let caps = conv.caps.as_ref();
    let (allow, rendered) = match adapter {
        "sqlite" => judge(&SqliteRenderer::new(adapter, vec![SqliteRenderer::table_of(schema)]), caps, &op, m),
        "pg" => judge(&PgRenderer::new(adapter, vec![PgRenderer::live_of(schema)]), caps, &op, m),
        "redis" => judge(&KvRenderer::new(adapter, vec![schema]), caps, &op, m),
        "oop" => judge(&OopRenderer::new(adapter, vec![schema]), caps, &op, m),
        _ => return Err(format!("unknown adapter {adapter:?}")),
    };
    Ok((id, allow, rendered))
}

pub fn serve(m: DispatchMutations) -> Result<(), String> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let req = json::parse(&line)?;
        let (id, allow, rendered) = case(&req, m)?;
        writeln!(
            out,
            "{{\"case\":{id},\"decision\":\"{}\",\"rendered\":{rendered}}}",
            if allow { "allow" } else { "deny" }
        )
        .map_err(|e| e.to_string())?;
    }
    out.flush().map_err(|e| e.to_string())
}
