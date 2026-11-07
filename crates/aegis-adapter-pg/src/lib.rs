//! PostgreSQL adapter: lowering, driver, NC3 checkin, per-tenant credentials.
//!
//! P4-pg-001: the owned PG v3 wire client ([`wire`], DEVIATIONS X-10), SCRAM-SHA-256 on aws-lc-rs ([`auth`]), and
//! the version gate compiled from `supply-chain/engine-pins.toml` ([`version`]; R-DB-1 floors, R-DB-8 PG19 block).
//! P4-pg-002: the renderer of the engine-neutral lowering tree ([`lower`]: `render`, `render_filter`, `render_op`,
//! `rls_policy`, `rls_bind`) and live schema introspection + gate ([`schema`]: `check_live_schema`, R-DB-7).
//! P4-pg-003: the connection pool keyed by (principal, tenant, login role, epoch) ([`pool`]; CRS C2/C5, R-DB-5) and
//! the NC3 release path ([`checkin`]: checkin predicate, quarantine, recovery within the op budget without a
//! CancelRequest, discard with a CancelRequest, NC4 charges, C8 reset on recycle).
//! P7-adapter-crdb-001 (feature `crdb`, PREFLIGHT D-P7.8): [`Dialect`]`::Crdb` for the renderer
//! ([`render_dialect`]: the q4-005 upsert guard fix, never `UPSERT`) and the schema gate
//! ([`check_live_schema_dialect`]), plus [`crdb`]: the CockroachDB version gate (floors compiled from the
//! `kind = "crdb"` pins) and the bounded whole-transaction SERIALIZABLE retry on 40001. Without the feature the
//! crate behaves exactly as before (`Dialect` has only `Postgres`).
//! Spec: `spec/SPEC_INVARIANTS.md`.
#![forbid(unsafe_code)]

pub mod auth;
pub mod checkin;
#[cfg(feature = "crdb")]
pub mod crdb;
pub mod lower;
pub mod pool;
pub mod saslprep;
pub mod schema;
pub mod version;
pub mod wire;

use std::fmt;
use std::time::Duration;

/// The IR and types crates this adapter's API speaks (re-exported for subjects and hosts).
pub use aegis_data_ir as data_ir;
pub use aegis_types::TenantId;
pub use checkin::{
    Charge, DISCARD_COST, Nc3Observer, NoObserver, PgConn, PgSession, Release, Released, ResetError, checkin_predicate,
};
pub use lower::{
    Dialect, Param, PgClass, PgColumn, PgForeignKey, PgTable, RenderError, Rendered, render, render_dialect,
    render_filter, render_op, render_op_dialect, rls_bind, rls_policy,
};
pub use pool::{
    AcquireError, Checkout, ConnId, Epoch, Idled, KeyError, PlainReuse, Pool, PoolConfig, PoolKey, Pooled, ResetPending,
};
pub use schema::{LiveSchemaError, LiveTable, check_live_schema, check_live_schema_dialect};
pub use version::{AdmittedVersion, VersionRefusal, admit_server_version, recheck};
pub use wire::{ConnectConfig, Connection};

/// Why [`connect_admitted`] produced no connection.
#[derive(Debug)]
pub enum ConnectError {
    Wire(wire::Error),
    /// Started, but the server version is refused by the gate; the connection was terminated.
    Refused(VersionRefusal),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectError::Wire(e) => write!(f, "{e}"),
            ConnectError::Refused(r) => write!(f, "{r}"),
        }
    }
}

impl std::error::Error for ConnectError {}

/// Bound on the Terminate write after a refusal.
const TERMINATE_TIMEOUT: Duration = Duration::from_millis(200);

/// Open + start up + authenticate, then gate the reported `server_version`. With `pinned = Some(a)` (a pooled key
/// that was admitted before) the new startup must report exactly `a`'s token, else it is refused as a version change
/// (R-DB-1: recycle after a minor upgrade). A refused connection is terminated, never returned.
pub fn connect_admitted(
    cfg: &ConnectConfig,
    pinned: Option<&AdmittedVersion>,
) -> Result<(Connection, AdmittedVersion), ConnectError> {
    let conn = Connection::connect(cfg).map_err(ConnectError::Wire)?;
    let verdict = match pinned {
        Some(a) => recheck(a, conn.server_version()),
        None => admit_server_version(conn.server_version()),
    };
    match verdict {
        Ok(v) => Ok((conn, v)),
        Err(r) => {
            conn.terminate(TERMINATE_TIMEOUT);
            Err(ConnectError::Refused(r))
        }
    }
}
