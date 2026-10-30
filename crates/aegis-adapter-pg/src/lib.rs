//! PostgreSQL adapter: lowering, driver, NC3 checkin, per-tenant credentials.
//!
//! P4-pg-001: the owned PG v3 wire client ([`wire`], DEVIATIONS X-10), SCRAM-SHA-256 on aws-lc-rs ([`auth`]), and
//! the version gate compiled from `supply-chain/engine-pins.toml` ([`version`]; R-DB-1 floors, R-DB-8 PG19 block).
//! Lowering/schema (P4-pg-002) and the pool with the NC3 checkin predicate (P4-pg-003) build on these.
//! Spec: `spec/SPEC_INVARIANTS.md`.
#![forbid(unsafe_code)]

pub mod auth;
pub mod version;
pub mod wire;

use std::fmt;
use std::time::Duration;

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
