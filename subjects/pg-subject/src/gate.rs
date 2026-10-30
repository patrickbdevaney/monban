//! `pg-subject schema`: the schema-gate subject protocol (oracles/schema-gate/README.md).
//!
//! * `pg` mode: connect to `dsn` (version-gated, `connect_admitted`), then `aegis_adapter_pg::check_live_schema` on
//!   `namespace`.`collection`: the live catalog decides collations, NULL-ability, unique indexes, types, triggers,
//!   rules, FKs, partitioning and RLS; `declared` contributes only names, field numbers, roles and `permitted`.
//! * `static` mode: F4 `check_schema` on the admission probe (as datair-subject), for completeness.
//! * `sqlite` mode belongs to sqlite-subject: `error` reply.
//!
//! Replies: `{"ok":true}`, `{"refuse":"<Class>"}` (F4 classes as Rust Debug, e.g. `NonBinaryCollation(0)`), or
//! `{"error":...}` when the catalog could not be read (never an accept). Connections are kept per DSN while reusable.

use std::collections::HashMap;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use aegis_adapter_pg::TenantId;
use aegis_adapter_pg::data_ir::{Collation, Column, Fidelity, Op, OpKind, Pred, Schema, UniqueIndex, check_schema};
use aegis_adapter_pg::{ConnectConfig, ConnectError, Connection, check_live_schema, connect_admitted};

use crate::json::{self, Json, emit, esc};

const PER_REQUEST: Duration = Duration::from_secs(30);
const TERMINATE: Duration = Duration::from_millis(200);

fn u32_of(j: &Json) -> Option<u32> {
    match j {
        Json::Num(t) => t.parse().ok(),
        _ => None,
    }
}

fn bool_of(j: &Json) -> Option<bool> {
    match j {
        Json::Bool(b) => Some(*b),
        _ => None,
    }
}

fn fields(j: Option<&Json>) -> Option<Vec<u32>> {
    match j? {
        Json::Arr(a) => a.iter().map(u32_of).collect(),
        _ => None,
    }
}

fn parse_schema(j: &Json) -> Option<Schema> {
    let Json::Arr(cols) = j.get("columns")? else { return None };
    let mut columns = Vec::with_capacity(cols.len());
    for c in cols {
        columns.push(Column {
            field: u32_of(c.get("field")?)?,
            name: c.get("name")?.str()?.to_string(),
            nullable: bool_of(c.get("nullable")?)?,
            collation: match c.get("collation")?.str()? {
                "Binary" => Collation::Binary,
                "PadSpace" => Collation::PadSpace,
                "CaseInsensitive" => Collation::CaseInsensitive,
                "Nondeterministic" => Collation::Nondeterministic,
                _ => return None,
            },
            key: bool_of(c.get("key")?)?,
        });
    }
    let Json::Arr(idx) = j.get("unique_indexes")? else { return None };
    let mut unique_indexes = Vec::with_capacity(idx.len());
    for u in idx {
        unique_indexes.push(UniqueIndex { fields: fields(u.get("fields"))?, prefix: bool_of(u.get("prefix")?)? });
    }
    Some(Schema {
        collection: j.get("collection")?.str()?.to_string(),
        tenant_field: u32_of(j.get("tenant_field")?)?,
        columns,
        permitted: fields(j.get("permitted"))?,
        unique_indexes,
    })
}

#[derive(Default)]
struct Gate {
    pool: HashMap<String, Connection>,
}

impl Gate {
    fn conn(&mut self, dsn: &str) -> Result<Connection, String> {
        if let Some(c) = self.pool.remove(dsn) {
            if c.is_reusable() {
                return Ok(c);
            }
            c.terminate(TERMINATE);
        }
        let cfg = ConnectConfig::from_dsn(dsn).map_err(|e| e.to_string())?;
        match connect_admitted(&cfg, None) {
            Ok((c, _)) => Ok(c),
            Err(ConnectError::Refused(r)) => Err(format!("server refused by the version gate: {r}")),
            Err(ConnectError::Wire(e)) => Err(format!("connect failed: {e}")),
        }
    }

    /// Reply body (without `v`/`id`).
    fn handle(&mut self, req: &Json) -> String {
        if req.get("op").and_then(Json::str) != Some("schema") {
            return r#""error":"unknown op""#.into();
        }
        match req.get("mode").and_then(Json::str) {
            Some("static") => {
                let Some(schema) = req.get("schema").and_then(parse_schema) else {
                    return r#""refuse":"Malformed(schema)""#.into();
                };
                let Ok(tenant) = TenantId::new(1) else { return r#""error":"probe tenant""#.into() };
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
                    Err(e) => format!("\"refuse\":{}", esc(&format!("{e:?}"))),
                }
            }
            Some("pg") => self.pg(req),
            Some(m) => format!("\"error\":{}", esc(&format!("mode {m} is not served by pg-subject"))),
            None => r#""error":"missing mode""#.into(),
        }
    }

    fn pg(&mut self, req: &Json) -> String {
        let Some(declared) = req.get("declared").and_then(parse_schema) else {
            return r#""refuse":"Malformed(declared)""#.into();
        };
        let (Some(dsn), Some(ns)) = (req.get("dsn").and_then(Json::str), req.get("namespace").and_then(Json::str))
        else {
            return r#""refuse":"Malformed(dsn/namespace)""#.into();
        };
        if req.get("collection").and_then(Json::str) != Some(declared.collection.as_str()) {
            return r#""refuse":"CollectionMismatch""#.into();
        }
        let mut conn = match self.conn(dsn) {
            Ok(c) => c,
            Err(e) => return format!("\"error\":{}", esc(&e)),
        };
        let out = match check_live_schema(&mut conn, ns, &declared, Instant::now() + PER_REQUEST) {
            Ok(_) => r#""ok":true"#.into(),
            Err(e) => match e.class() {
                Some(c) => format!("\"refuse\":{}", esc(&c)),
                None => format!("\"error\":{}", esc(&e.to_string())),
            },
        };
        self.pool.insert(dsn.to_owned(), conn);
        out
    }
}

pub fn serve() -> ExitCode {
    let mut g = Gate::default();
    crate::serve_lines(|line| {
        let (id, body) = match line.map(json::parse) {
            None => (Json::Null, r#""error":"request line too long""#.to_string()),
            Some(Err(e)) => (Json::Null, format!("\"error\":{}", esc(&format!("bad request: {e}")))),
            Some(Ok(req)) => (req.get("id").cloned().unwrap_or(Json::Null), g.handle(&req)),
        };
        format!("{{\"v\":1,\"id\":{},{body}}}", emit(&id))
    })
}
