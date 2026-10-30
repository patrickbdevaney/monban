//! `apps/notes`: the example native application of modes A/D (oracles/native-e2e).
//!
//! A tenant-scoped note store over the F7 SDK alone. The host binds a route (`to.upstream = "app:notes"`) to this
//! app, verifies the token, mints the principal, and hands [`Notes`] a `Ctx` and a tenant-bound db view. The app
//! never names a tenant for the engine (the SDK overwrites `Op::tenant`), never sees a connection, and obtains each
//! capability through `Ctx::grant` (denied unless the route endowment and the token both grant the op kind).
//!
//! Endpoints (path relative to the route prefix; `T` = 16-hex tenant, which the host checks against the token):
//!
//! | request | op | success |
//! |---|---|---|
//! | `GET T/ID` | select | 200 `{"id","body"}` (the host renders the selected row: handlers never read row bytes) |
//! | `POST T/` `{"id","body"}` | insert | 201 `{"id","body"}` |
//! | `PATCH T/ID` `{"body"}` | update | 200 `{"id","body"}` |
//! | `PUT T/ID` `{"body"}` | upsert | 200 `{"id","body"}` |
//! | `DELETE T/ID` | delete | 200 `{"deleted":true,"id"}` |
//!
//! Test fields (oracle contract): `hold_ms` sleeps after the write inside the open transaction, `hold_after_ms`
//! after the commit, both 0..=10000.
//!
//! Every successful mutation's reply is a pure function of the request ([`Notes::committed`]), so the host can
//! write it into the same backend transaction as the rows (PLAN D14) before the commit point.
#![forbid(unsafe_code)]

mod json;

use aegis_sdk::query::{Op, OpKind, Pred, Value};
use aegis_sdk::{Ctx, ScopedHandler, SdkError, TenantDb, op_code};

/// The app name routes bind to (`app:notes`).
pub const NAME: &str = "notes";
/// The one collection.
pub const COLLECTION: &str = "notes";
/// Declared columns `(field, name, key)`; field 0 is the tenant column, bound by the host and never written here.
pub const COLUMNS: [(u32, &str, bool); 3] = [(0, "tenant", false), (1, "id", true), (2, "body", false)];
pub const TENANT_FIELD: u32 = 0;
pub const ID: u32 = 1;
pub const BODY: u32 = 2;
/// Columns a caller may read or return.
pub const PERMITTED: [u32; 2] = [ID, BODY];
/// Allowlist locks (`cargo xtask allowlist-lock`): every op shape this app can emit, per engine family.
pub const ALLOWLIST_SQLITE: &str = include_str!("../allowlist.notes-sqlite.lock");
pub const ALLOWLIST_PG: &str = include_str!("../allowlist.notes-pg.lock");

const MAX_HOLD_MS: u64 = 10_000;
const MAX_BODY: usize = 4096;

const SELECT: u8 = op_code(OpKind::Select);
const INSERT: u8 = op_code(OpKind::Insert);
const UPDATE: u8 = op_code(OpKind::Update);
const DELETE: u8 = op_code(OpKind::Delete);
const UPSERT: u8 = op_code(OpKind::Upsert);

/// Request method, as the host maps it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Patch,
    Put,
    Delete,
}

impl Method {
    /// The op kind an endpoint performs (the token's ops caveat is judged against it).
    pub fn op_kind(self) -> OpKind {
        match self {
            Method::Get => OpKind::Select,
            Method::Post => OpKind::Insert,
            Method::Patch => OpKind::Update,
            Method::Put => OpKind::Upsert,
            Method::Delete => OpKind::Delete,
        }
    }
}

/// Why a request was not turned into a handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The path does not name a note: answered exactly like a missing note (W6).
    NotFound,
    /// The body is not a valid request (400).
    BadBody,
}

/// What the handler answers. `Row` asks the host to render the row the scope's select returned (`{"id","body"}`),
/// because F7 handlers never read row bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Out {
    Json { status: u16, body: String },
    Row { status: u16 },
}

/// One parsed request: the handler value the host drives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notes {
    method: Method,
    tenant: String,
    id: String,
    body: String,
    hold_ms: u64,
    hold_after_ms: u64,
}

fn is_tenant(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// `[a-z0-9][a-z0-9-]{0,63}`.
fn is_id(s: &str) -> bool {
    let b = s.as_bytes();
    match b.split_first() {
        Some((f, rest)) => {
            (f.is_ascii_lowercase() || f.is_ascii_digit())
                && rest.len() <= 63
                && rest.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        }
        None => false,
    }
}

fn hold(obj: &[(String, json::Val)], name: &str) -> Result<u64, Refusal> {
    match json::get(obj, name) {
        None => Ok(0),
        Some(json::Val::Int(v)) => u64::try_from(*v).ok().filter(|v| *v <= MAX_HOLD_MS).ok_or(Refusal::BadBody),
        Some(_) => Err(Refusal::BadBody),
    }
}

fn note_body(obj: &[(String, json::Val)]) -> Result<String, Refusal> {
    match json::get(obj, "body") {
        Some(json::Val::Str(s)) if s.len() <= MAX_BODY && !s.contains('\0') => Ok(s.clone()),
        _ => Err(Refusal::BadBody),
    }
}

/// Parse one request: `rest` is the canonical path after the route prefix, `body` the request body.
pub fn parse(method: Method, rest: &str, body: &[u8]) -> Result<Notes, Refusal> {
    let (tenant, id) = rest.split_once('/').ok_or(Refusal::NotFound)?;
    if !is_tenant(tenant) {
        return Err(Refusal::NotFound);
    }
    let mut n = Notes {
        method,
        tenant: tenant.to_string(),
        id: String::new(),
        body: String::new(),
        hold_ms: 0,
        hold_after_ms: 0,
    };
    if method == Method::Post {
        if !id.is_empty() {
            return Err(Refusal::NotFound);
        }
    } else if !is_id(id) {
        return Err(Refusal::NotFound);
    } else {
        n.id = id.to_string();
    }
    if matches!(method, Method::Post | Method::Patch | Method::Put) {
        let obj = json::parse_object(body).ok_or(Refusal::BadBody)?;
        n.body = note_body(&obj)?;
        if method == Method::Post {
            match json::get(&obj, "id") {
                Some(json::Val::Str(s)) if is_id(s) => n.id = s.clone(),
                _ => return Err(Refusal::BadBody),
            }
        }
        n.hold_ms = hold(&obj, "hold_ms")?;
        n.hold_after_ms = hold(&obj, "hold_after_ms")?;
    }
    Ok(n)
}

impl Notes {
    /// The tenant the path names (the host refuses it uniformly unless it is the token's tenant).
    pub fn path_tenant(&self) -> &str {
        &self.tenant
    }

    pub fn method(&self) -> Method {
        self.method
    }

    /// The reply of this request if it commits: `Some` for every mutation (a pure function of the request), `None`
    /// for a read.
    pub fn committed(&self) -> Option<Out> {
        let note = || {
            let mut s = String::from("{\"id\":");
            json::push_str(&mut s, &self.id);
            s.push_str(",\"body\":");
            json::push_str(&mut s, &self.body);
            s.push('}');
            s
        };
        match self.method {
            Method::Get => None,
            Method::Post => Some(Out::Json { status: 201, body: note() }),
            Method::Patch | Method::Put => Some(Out::Json { status: 200, body: note() }),
            Method::Delete => {
                let mut s = String::from("{\"deleted\":true,\"id\":");
                json::push_str(&mut s, &self.id);
                s.push('}');
                Some(Out::Json { status: 200, body: s })
            }
        }
    }

    fn op(&self, ctx: &Ctx<'_>, kind: OpKind) -> Op {
        let key = || Pred::Eq(ID, Value::Str(self.id.clone()));
        let (filter, writes, returning) = match kind {
            OpKind::Select => (key(), Vec::new(), vec![ID, BODY]),
            OpKind::Insert | OpKind::Upsert => {
                (Pred::Tt, vec![(ID, Value::Str(self.id.clone())), (BODY, Value::Str(self.body.clone()))], Vec::new())
            }
            OpKind::Update => (key(), vec![(BODY, Value::Str(self.body.clone()))], vec![ID]),
            OpKind::Delete => (key(), Vec::new(), vec![ID]),
        };
        // The tenant is overwritten by the SDK with the principal's; stated here only because Op requires it.
        Op { tenant: ctx.principal().tenant(), collection: COLLECTION.into(), kind, filter, writes, returning }
    }

    fn pause(ms: u64) {
        if ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }

    fn write<'r, D: TenantDb<'r>, const K: u8>(&self, ctx: &Ctx<'r>, db: &D, kind: OpKind) -> Result<Out, SdkError> {
        let cap = ctx.grant::<K>()?;
        let reply = self.committed().ok_or(SdkError::Denied)?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &cap, self.op(ctx, kind))?;
        Self::pause(self.hold_ms);
        let _done = db.commit(tx)?;
        Self::pause(self.hold_after_ms);
        Ok(reply)
    }
}

impl ScopedHandler for Notes {
    type Response = Out;

    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<Out, SdkError> {
        match self.method {
            Method::Get => {
                let cap = ctx.grant::<SELECT>()?;
                let mut tx = db.begin()?;
                db.run(&mut tx, &cap, self.op(&ctx, OpKind::Select))?;
                let _done = db.commit(tx)?;
                Ok(Out::Row { status: 200 })
            }
            Method::Post => self.write::<D, INSERT>(&ctx, db, OpKind::Insert),
            Method::Patch => self.write::<D, UPDATE>(&ctx, db, OpKind::Update),
            Method::Put => self.write::<D, UPSERT>(&ctx, db, OpKind::Upsert),
            Method::Delete => self.write::<D, DELETE>(&ctx, db, OpKind::Delete),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    const T: &str = "00000000000000aa";

    #[test]
    fn parses_paths_and_bodies() {
        let n = parse(Method::Post, &format!("{T}/"), br#"{"id":"n1","body":"a\"b","hold_ms":5}"#).unwrap();
        assert_eq!((n.id.as_str(), n.body.as_str(), n.hold_ms), ("n1", "a\"b", 5));
        assert_eq!(n.committed(), Some(Out::Json { status: 201, body: r#"{"id":"n1","body":"a\"b"}"#.into() }));
        assert_eq!(parse(Method::Get, &format!("{T}/n1"), b"").unwrap().committed(), None);
        assert_eq!(parse(Method::Get, "00AA/n1", b""), Err(Refusal::NotFound));
        assert_eq!(parse(Method::Get, &format!("{T}/N1"), b""), Err(Refusal::NotFound));
        assert_eq!(parse(Method::Get, &format!("{T}/n1/x"), b""), Err(Refusal::NotFound));
        assert_eq!(parse(Method::Post, &format!("{T}/x"), b"{}"), Err(Refusal::NotFound));
        assert_eq!(parse(Method::Post, &format!("{T}/"), br#"{"id":"n1"}"#), Err(Refusal::BadBody));
        assert_eq!(parse(Method::Put, &format!("{T}/n1"), br#"{"body":"x","hold_ms":10001}"#), Err(Refusal::BadBody));
        assert_eq!(parse(Method::Put, &format!("{T}/n1"), br#"{"body":"x","hold_ms":-1}"#), Err(Refusal::BadBody));
        assert_eq!(parse(Method::Patch, &format!("{T}/n1"), b"[1]"), Err(Refusal::BadBody));
        let d = parse(Method::Delete, &format!("{T}/n-1"), b"").unwrap();
        assert_eq!(d.committed(), Some(Out::Json { status: 200, body: r#"{"deleted":true,"id":"n-1"}"#.into() }));
    }
}
