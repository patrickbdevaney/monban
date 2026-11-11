//! KV renderer: `monban_data_ir::kv_plan` output → RESP2 argument vectors, the per-tenant ACL user (R-DB-5), and
//! the executor with the W7 reply check.
//!
//! Every key and SCAN pattern comes from `kv_plan` (`t:{<16hex>}:<collection>:<key>`, glob-escaped prefixes,
//! [`KV_MAX_KEY_BYTES`]); this module never builds a key itself. The executor re-checks that every key it sends or
//! receives starts with the tenant's [`kv_key_prefix`] and the op's collection (defence in depth on top of the ACL
//! key pattern; W7).

use std::fmt;

use monban_data_ir::{
    Collation, Column, KV_MAX_KEY_BYTES, KvCommand, KvError, Op, OpKind, Pred, Schema, UniqueIndex, Value, glob_escape,
    kv_key_prefix, kv_plan, parse_tenant_text, tenant_text,
};
use monban_types::TenantId;

use crate::conn::{Connection, Error};
use crate::resp::Reply;

/// The RESP2 arguments for one planned command.
pub fn command_args(c: &KvCommand) -> Vec<Vec<u8>> {
    let v = |s: &str| s.as_bytes().to_vec();
    match c {
        KvCommand::Get { key } => vec![v("GET"), v(key)],
        KvCommand::Scan { pattern } => vec![v("SCAN"), v("0"), v("MATCH"), v(pattern)],
        KvCommand::SetNx { key, value } => vec![v("SET"), v(key), v(value), v("NX")],
        KvCommand::Set { key, value } => vec![v("SET"), v(key), v(value)],
        KvCommand::SetXx { key, value } => vec![v("SET"), v(key), v(value), v("XX")],
        KvCommand::Del { key } => vec![v("DEL"), v(key)],
    }
}

/// Field numbers of the canonical three-column KV schema used by [`kv_schema`].
pub const KV_TENANT: u32 = 0;
pub const KV_KEY: u32 = 1;
pub const KV_VALUE: u32 = 2;

/// The KV collection shape `kv_plan` accepts: tenant (not null), one key column, one value column, binary
/// collations, the only unique index (tenant, key).
pub fn kv_schema(collection: &str) -> Schema {
    let col = |field, name: &str, key| Column {
        field,
        name: name.into(),
        nullable: false,
        collation: Collation::Binary,
        key,
    };
    Schema {
        collection: collection.into(),
        tenant_field: KV_TENANT,
        columns: vec![col(KV_TENANT, "tenant", false), col(KV_KEY, "key", true), col(KV_VALUE, "value", false)],
        permitted: vec![KV_KEY, KV_VALUE],
        unique_indexes: vec![UniqueIndex { fields: vec![KV_TENANT, KV_KEY], prefix: false }],
    }
}

/// The logical KV operations of the lowering protocol (one per `kv_plan` row).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KvOp<'a> {
    Get {
        key: &'a str,
    },
    Scan {
        prefix: Option<&'a str>,
    },
    /// Upsert: `SET k v`.
    Set {
        key: &'a str,
        value: &'a str,
    },
    /// Insert: `SET k v NX`.
    SetNx {
        key: &'a str,
        value: &'a str,
    },
    /// Update: `SET k v XX`.
    SetXx {
        key: &'a str,
        value: &'a str,
    },
    Del {
        key: &'a str,
    },
}

/// Build the IR [`Op`] for a logical KV operation and plan it through `kv_plan` (the production path).
pub fn plan(tenant: TenantId, collection: &str, op: &KvOp<'_>) -> Result<KvCommand, KvError> {
    let s = |x: &str| Value::Str(x.into());
    let (kind, filter, writes) = match op {
        KvOp::Get { key } => (OpKind::Select, Pred::Eq(KV_KEY, s(key)), vec![]),
        KvOp::Scan { prefix: None } => (OpKind::Select, Pred::Tt, vec![]),
        KvOp::Scan { prefix: Some(p) } => (OpKind::Select, Pred::Pfx(KV_KEY, (*p).into()), vec![]),
        KvOp::Set { key, value } => (OpKind::Upsert, Pred::Tt, vec![(KV_KEY, s(key)), (KV_VALUE, s(value))]),
        KvOp::SetNx { key, value } => (OpKind::Insert, Pred::Tt, vec![(KV_KEY, s(key)), (KV_VALUE, s(value))]),
        KvOp::SetXx { key, value } => (OpKind::Update, Pred::Eq(KV_KEY, s(key)), vec![(KV_VALUE, s(value))]),
        KvOp::Del { key } => (OpKind::Delete, Pred::Eq(KV_KEY, s(key)), vec![]),
    };
    let op = Op { tenant, collection: collection.into(), kind, filter, writes, returning: vec![] };
    kv_plan(&op, &kv_schema(collection))
}

/// The physical key of one row (`kv_plan`'s `Get` key, so it is bounded and validated exactly like every op).
pub fn physical_key(tenant: TenantId, collection: &str, key: &str) -> Result<String, KvError> {
    match plan(tenant, collection, &KvOp::Get { key })? {
        KvCommand::Get { key } => Ok(key),
        _ => Err(KvError::UnsupportedFilter),
    }
}

// --------------------------------------------------------------------------------------- per-tenant ACL (R-DB-5)

/// The only commands a per-tenant ACL user may run: the key-bearing commands of `kv_plan` (`GET`, `SET`, `DEL`).
/// `SCAN` is deliberately absent: it takes no key argument (MATCH is not an ACL key), so `+scan` would let the user
/// list every tenant's key names. Consequence (PLAN D11): [`execute`] refuses `KvCommand::Scan` with [`ExecError::Unsupported`]; the renderer
/// still produces the escaped pattern ([`command_args`], checked by the read oracle).
pub const ACL_COMMANDS: &[&str] = &["get", "set", "del"];

/// `ACL SETUSER` rule tokens for `tenant`: no keys, no channels, no commands, then exactly the tenant's key pattern
/// `~t:{<16hex>}:*` (glob-escaped prefix; `}` and `:` pin the delimiter, so no other tenant's keys match) and
/// [`ACL_COMMANDS`]. No scripting (EVAL/FCALL/FUNCTION/SCRIPT), no admin, no keyspace-wide or connection-state
/// commands, no pub/sub.
pub fn tenant_acl_rules(tenant: TenantId) -> Vec<String> {
    let mut pat = String::from("~");
    pat.push_str(&glob_escape(&kv_key_prefix(tenant)));
    pat.push('*');
    let mut rules = vec!["resetkeys".to_string(), pat, "resetchannels".to_string(), "-@all".to_string()];
    rules.extend(ACL_COMMANDS.iter().map(|c| format!("+{c}")));
    rules
}

/// ACL user name for a tenant: `monban-t-<16hex>`.
pub fn tenant_username(tenant: TenantId) -> String {
    format!("monban-t-{}", tenant_text(tenant))
}

/// True iff `s` is exactly a [`tenant_username`].
pub fn is_tenant_username(s: &str) -> bool {
    s.strip_prefix("monban-t-").and_then(parse_tenant_text).is_some()
}

/// A per-tenant ACL user: name, password and rules. `Debug` redacts the password.
#[derive(Clone, PartialEq, Eq)]
pub struct TenantUser {
    tenant: TenantId,
    username: String,
    password: String,
}

impl fmt::Debug for TenantUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TenantUser")
            .field("tenant", &self.tenant)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

/// Password rules for [`TenantUser::new`].
pub const MIN_PASSWORD: usize = 32;
pub const MAX_PASSWORD: usize = 256;

impl TenantUser {
    /// `password` (minted by the core from its secret store) must be 32..=256 printable ASCII bytes with no space,
    /// so it cannot smuggle an extra `ACL SETUSER` token.
    pub fn new(tenant: TenantId, password: String) -> Result<TenantUser, Error> {
        if !(MIN_PASSWORD..=MAX_PASSWORD).contains(&password.len()) || !password.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(Error::Usage("tenant password must be 32..=256 printable ASCII bytes".into()));
        }
        Ok(TenantUser { tenant, username: tenant_username(tenant), password })
    }
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub fn username(&self) -> &str {
        &self.username
    }
    pub fn password(&self) -> &str {
        &self.password
    }
    pub fn rules(&self) -> Vec<String> {
        tenant_acl_rules(self.tenant)
    }
}

// ---------------------------------------------------------------------------------------------- executor (W7)

/// Result of one executed [`KvCommand`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KvOutcome {
    /// GET: the value, or `None` if absent.
    Value(Option<Vec<u8>>),
    /// SET / SET NX / SET XX: whether it was applied.
    Written(bool),
    /// DEL: whether a key was removed.
    Deleted(bool),
}

#[derive(Debug)]
pub enum ExecError {
    Conn(Error),
    /// The server refused the command (e.g. `NOPERM`).
    Server(String),
    /// A key outside the tenant's prefix/collection was about to be sent or came back (W7). Fail closed.
    Foreign,
    /// Reply shape does not match the command.
    Unexpected(String),
    /// `KvCommand::Scan` (Select Tt/Pfx): not executable under the per-tenant ACL user (PLAN D11). Nothing is sent.
    Unsupported,
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecError::Conn(e) => write!(f, "{e}"),
            ExecError::Server(e) => write!(f, "server error: {e}"),
            ExecError::Foreign => write!(f, "key outside the tenant namespace (W7)"),
            ExecError::Unexpected(e) => write!(f, "unexpected reply: {e}"),
            ExecError::Unsupported => write!(f, "KV listing (SCAN) is unsupported under per-tenant ACL users (D11)"),
        }
    }
}

impl std::error::Error for ExecError {}

impl From<Error> for ExecError {
    fn from(e: Error) -> Self {
        ExecError::Conn(e)
    }
}

fn server_err(r: &Reply) -> Option<ExecError> {
    r.error_text().map(|e| ExecError::Server(String::from_utf8_lossy(e).into_owned()))
}

/// Execute a planned command for `tenant`/`collection` on `conn` (which must be that tenant's own connection,
/// R-DB-5). Every key sent and every key returned must start with `t:{<tenant>}:<collection>:`.
pub fn execute(
    conn: &mut Connection,
    tenant: TenantId,
    collection: &str,
    c: &KvCommand,
) -> Result<KvOutcome, ExecError> {
    let mut base = kv_key_prefix(tenant);
    base.push_str(collection);
    base.push(':');
    let own = |k: &[u8]| k.starts_with(base.as_bytes()) && k.len() <= KV_MAX_KEY_BYTES;
    let target = match c {
        // D11 (PLAN): ACL cannot key-restrict SCAN, so the per-tenant user has no +scan and every connection is a
        // per-tenant one (R-DB-5). Select Tt/Pfx is refused here, before anything is sent (fail closed).
        KvCommand::Scan { .. } => return Err(ExecError::Unsupported),
        KvCommand::Get { key }
        | KvCommand::Set { key, .. }
        | KvCommand::SetNx { key, .. }
        | KvCommand::SetXx { key, .. }
        | KvCommand::Del { key } => key,
    };
    if !own(target.as_bytes()) {
        return Err(ExecError::Foreign);
    }
    let args = command_args(c);
    let refs: Vec<&[u8]> = args.iter().map(Vec::as_slice).collect();
    match c {
        KvCommand::Get { .. } => match conn.command(&refs)? {
            Reply::Bulk(v) => Ok(KvOutcome::Value(v)),
            r => Err(server_err(&r).unwrap_or_else(|| ExecError::Unexpected(format!("GET: {r:?}")))),
        },
        KvCommand::Set { .. } | KvCommand::SetNx { .. } | KvCommand::SetXx { .. } => match conn.command(&refs)? {
            Reply::Simple(s) if s == b"OK" => Ok(KvOutcome::Written(true)),
            Reply::Bulk(None) => Ok(KvOutcome::Written(false)),
            r => Err(server_err(&r).unwrap_or_else(|| ExecError::Unexpected(format!("SET: {r:?}")))),
        },
        KvCommand::Del { .. } => match conn.command(&refs)? {
            Reply::Int(n) if (0..=1).contains(&n) => Ok(KvOutcome::Deleted(n == 1)),
            r => Err(server_err(&r).unwrap_or_else(|| ExecError::Unexpected(format!("DEL: {r:?}")))),
        },
        // D11: unreachable (refused above); kept exhaustive without a wildcard.
        KvCommand::Scan { .. } => Err(ExecError::Unsupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid(v: u64) -> TenantId {
        TenantId::new(v).unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn plans_match_reference_layout() {
        let t = tid(0xacce55);
        let p = "t:{0000000000acce55}:notes:";
        assert_eq!(plan(t, "notes", &KvOp::Get { key: "k1" }), Ok(KvCommand::Get { key: format!("{p}k1") }));
        assert_eq!(plan(t, "notes", &KvOp::Scan { prefix: None }), Ok(KvCommand::Scan { pattern: format!("{p}*") }));
        assert_eq!(
            plan(t, "notes", &KvOp::Scan { prefix: Some("a*?[]\\:}{") }),
            Ok(KvCommand::Scan { pattern: format!("{p}a\\*\\?\\[\\]\\\\:}}{{*") })
        );
        assert_eq!(
            plan(t, "notes", &KvOp::SetNx { key: "k", value: "v" }),
            Ok(KvCommand::SetNx { key: format!("{p}k"), value: "v".into() })
        );
        assert_eq!(
            plan(t, "notes", &KvOp::SetXx { key: "k", value: "v" }),
            Ok(KvCommand::SetXx { key: format!("{p}k"), value: "v".into() })
        );
        assert_eq!(
            plan(t, "notes", &KvOp::Set { key: "k", value: "v" }),
            Ok(KvCommand::Set { key: format!("{p}k"), value: "v".into() })
        );
        assert_eq!(plan(t, "notes", &KvOp::Del { key: "k" }), Ok(KvCommand::Del { key: format!("{p}k") }));
        for bad in ["", "Notes", "a:b", "1x", "a-b", &"x".repeat(64)] {
            assert!(plan(t, bad, &KvOp::Get { key: "k" }).is_err(), "{bad}");
        }
        assert!(plan(t, "notes", &KvOp::Get { key: &"k".repeat(900) }).is_ok());
        assert_eq!(plan(t, "notes", &KvOp::Get { key: &"k".repeat(1024) }), Err(KvError::KeyTooLong));
        assert_eq!(plan(t, "notes", &KvOp::Scan { prefix: Some(&"*".repeat(600)) }), Err(KvError::KeyTooLong));
    }

    #[test]
    fn args_and_acl() {
        let a = command_args(&KvCommand::SetNx { key: "k".into(), value: "v".into() });
        assert_eq!(a, vec![b"SET".to_vec(), b"k".to_vec(), b"v".to_vec(), b"NX".to_vec()]);
        let t = tid(42);
        assert_eq!(
            tenant_acl_rules(t),
            vec!["resetkeys", "~t:{000000000000002a}:*", "resetchannels", "-@all", "+get", "+set", "+del"]
        );
        assert_eq!(tenant_username(t), "monban-t-000000000000002a");
        assert!(is_tenant_username("monban-t-000000000000002a"));
        for bad in ["monban-t-2a", "default", "monban-t-000000000000002A", "monban-t-0000000000000000"] {
            assert!(!is_tenant_username(bad), "{bad}");
        }
        assert!(TenantUser::new(t, "short".into()).is_err());
        assert!(TenantUser::new(t, format!("{} on", "x".repeat(40))).is_err());
        assert!(TenantUser::new(t, "x".repeat(40)).is_ok());
        assert!(!format!("{:?}", TenantUser::new(t, "s3cr3t".repeat(8))).contains("s3cr3t"));
    }
}
