//! datair-subject: the production `aegis-data-ir` behind two tool interfaces.
//!
//!   datair-subject schema          schema-gate subject (oracles/schema-gate/README.md), static mode: each request's
//!                                  F4 Schema is admitted iff `check_schema(probe, schema, Exact)` is Ok, with
//!                                  probe = Op{collection: schema.collection, kind: Upsert, filter: Tt, writes: [],
//!                                  returning: []}. The live modes (sqlite, pg) belong to the adapter subjects and
//!                                  get an `error` reply here.
//!   datair-subject lock <decl>     print the allowlist lock generated from `allowlist.<adapter>.decl` (lock.rs:
//!                                  `lock_body` + AWS-LC SHA-256 trailer); exit 1 with the refusal on stderr.
//!   datair-subject verify <decl> <lock>   exit 0 iff the lock is byte-identical to the regenerated one.
//!
//! A schema request that cannot be read as an F4 Schema is refused (`Malformed`), never admitted.
#![forbid(unsafe_code)]

mod json;

use aegis_data_ir::{
    Collation, Column, Fidelity, Op, OpKind, Pred, Schema, UniqueIndex, check_schema, generate, verify,
};
use aegis_types::TenantId;
use json::Json;
use std::io::{BufRead, BufWriter, Write};
use std::process::ExitCode;

fn field(j: &Json) -> Option<u32> {
    j.u64().and_then(|v| u32::try_from(v).ok())
}

fn fields(j: Option<&Json>) -> Option<Vec<u32>> {
    match j? {
        Json::Arr(a) => a.iter().map(field).collect(),
        _ => None,
    }
}

fn collation(s: &str) -> Option<Collation> {
    Some(match s {
        "Binary" => Collation::Binary,
        "PadSpace" => Collation::PadSpace,
        "CaseInsensitive" => Collation::CaseInsensitive,
        "Nondeterministic" => Collation::Nondeterministic,
        _ => return None,
    })
}

fn parse_schema(j: &Json) -> Option<Schema> {
    let cols = match j.get("columns")? {
        Json::Arr(a) => a,
        _ => return None,
    };
    let mut columns = Vec::with_capacity(cols.len());
    for c in cols {
        columns.push(Column {
            field: field(c.get("field")?)?,
            name: c.get("name")?.str()?.to_string(),
            nullable: c.get("nullable")?.bool()?,
            collation: collation(c.get("collation")?.str()?)?,
            key: c.get("key")?.bool()?,
        });
    }
    let idx = match j.get("unique_indexes")? {
        Json::Arr(a) => a,
        _ => return None,
    };
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

/// The reply body (without `v`/`id`) for one request.
fn handle(req: &Json) -> String {
    if req.get("op").and_then(Json::str) != Some("schema") {
        return r#""error":"unknown op""#.into();
    }
    match req.get("mode").and_then(Json::str) {
        Some("static") => {}
        Some(m) => return format!(r#""error":"mode {} is served by the adapter subjects""#, esc(m)),
        None => return r#""error":"missing mode""#.into(),
    }
    let Some(schema) = req.get("schema").and_then(parse_schema) else {
        return r#""refuse":"Malformed(schema)""#.into();
    };
    let Ok(tenant) = TenantId::new(1) else {
        return r#""refuse":"Malformed(tenant)""#.into();
    };
    let probe = Op {
        tenant,
        collection: schema.collection.clone(),
        kind: OpKind::Upsert,
        filter: Pred::Tt,
        writes: Vec::new(),
        returning: Vec::new(),
    };
    match check_schema(&probe, &schema, Fidelity::Exact) {
        Ok(()) => r#""ok":true"#.into(),
        Err(e) => format!(r#""refuse":"{}""#, esc(&format!("{e:?}"))),
    }
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Echo of the request id: numbers and strings round-trip; anything else (or no id) becomes null.
fn id_json(req: Option<&Json>) -> String {
    match req.and_then(|r| r.get("id")) {
        Some(Json::Num(n)) => n.clone(),
        Some(Json::Str(s)) => format!("\"{}\"", esc(s)),
        _ => "null".into(),
    }
}

fn serve() -> ExitCode {
    let stdin = std::io::stdin();
    let mut out = BufWriter::new(std::io::stdout().lock());
    for line in stdin.lock().lines() {
        let Ok(line) = line else { return ExitCode::from(2) };
        if line.trim().is_empty() {
            continue;
        }
        let (id, body) = match json::parse(&line) {
            Ok(req) => (id_json(Some(&req)), handle(&req)),
            Err(_) => (id_json(None), r#""error":"bad json""#.to_string()),
        };
        if writeln!(out, r#"{{"v":1,"id":{id},{body}}}"#).and_then(|()| out.flush()).is_err() {
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}

fn read(p: &str) -> Result<String, String> {
    std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))
}

fn run(args: &[String]) -> Result<(), String> {
    match args {
        [cmd, decl] if cmd == "lock" => {
            let lock = generate(&read(decl)?).map_err(|e| format!("{decl}: line {}: {:?}", e.line, e.kind))?;
            let mut o = std::io::stdout().lock();
            o.write_all(lock.as_bytes()).and_then(|()| o.flush()).map_err(|e| e.to_string())
        }
        [cmd, decl, lock] if cmd == "verify" => {
            verify(&read(decl)?, &read(lock)?).map_err(|e| format!("{lock}: line {}: {:?}", e.line, e.kind))
        }
        _ => Err("usage: datair-subject schema | lock <decl> | verify <decl> <lock>".into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 1 && args.first().map(String::as_str) == Some("schema") {
        return serve();
    }
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("datair-subject: {e}");
            ExitCode::FAILURE
        }
    }
}
