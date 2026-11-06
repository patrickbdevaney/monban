//! MariaDB adapter (PREFLIGHT D-P7.8): owned MySQL wire client, renderer of the engine-neutral lowering tree, live
//! schema gate.
//!
//! P7-spec-002 stub: [`connect`] refuses with [`MysqlError::Unimplemented`], so no MariaDB family can serve a request
//! until P7-adapter-mysql-001 lands the adapter and its three gates pass.
#![forbid(unsafe_code)]

use std::fmt;
use std::time::Duration;

/// The IR and types crates this adapter's API speaks (re-exported for subjects and hosts, as aegis-adapter-pg does).
pub use aegis_data_ir as data_ir;
pub use aegis_types::TenantId;

/// Why a MariaDB operation was refused. Every variant fails the operation closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MysqlError {
    /// Not built yet (P7-spec-002 stub): fail closed.
    Unimplemented,
}

impl fmt::Display for MysqlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MysqlError::Unimplemented => f.write_str("MariaDB adapter not built (fail closed)"),
        }
    }
}

impl std::error::Error for MysqlError {}

/// Connection parameters (loopback or TLS only, PREFLIGHT D-P7.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectConfig {
    pub dsn: String,
    pub connect_timeout: Duration,
}

/// An open MariaDB connection.
#[derive(Debug)]
pub struct Connection {
    _private: (),
}

/// Open a connection.
///
/// Stub: always `Err(MysqlError::Unimplemented)`.
pub fn connect(cfg: &ConnectConfig) -> Result<Connection, MysqlError> {
    let _ = cfg;
    Err(MysqlError::Unimplemented)
}
