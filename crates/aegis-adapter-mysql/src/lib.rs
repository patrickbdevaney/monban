//! MariaDB adapter (PREFLIGHT D-P7.8): owned MySQL wire client, renderer of the engine-neutral lowering tree, live
//! schema gate.
//!
//! * [`conn`]: the wire client. Handshake v10, `mysql_native_password` (incl. AuthSwitchRequest), caching_sha2
//!   refused until a TLS path exists, loopback only, `COM_STMT_PREPARE` / `COM_STMT_EXECUTE` binary protocol only
//!   (no `COM_QUERY`), checked sequence ids, packet and result caps, connect and I/O deadlines, strict session
//!   `sql_mode` and utf8mb4 pinned at connect. [`packet`] is the pure, bounds-checked codec it uses.
//! * [`version`]: the server version gate (series and floor from `supply-chain/engine-pins.toml`), applied at
//!   connect before any credential is sent.
//! * [`lower`]: the renderer (`render`, `render_filter`, `render_op`) in the q4-005 mandated MariaDB forms.
//! * [`schema`]: live `information_schema` introspection + gate (`check_live_schema`, W3 amendment, plus
//!   `NonTransactionalEngine`).
//!
//! Non-golden until lowering-read-mariadb, lowering-write-mariadb and schema-gate-mariadb pass; then golden at rung
//! R2 (executed differential at the engine pin). Not in the default aegis-bin graph (feature `adapter-mariadb`).
#![forbid(unsafe_code)]

pub mod auth;
pub mod conn;
pub mod dsn;
pub mod lower;
pub mod packet;
pub mod schema;
pub mod version;

use std::fmt;

/// The IR and types crates this adapter's API speaks (re-exported for subjects and hosts, as aegis-adapter-pg does).
pub use aegis_data_ir as data_ir;
pub use aegis_types::TenantId;
pub use conn::{Connection, Limits, Param, QueryResult, SESSION_SQL_MODE};
pub use dsn::ConnectConfig;
pub use lower::{
    MyClass, MyColumn, MyForeignKey, MyTable, RenderError, Rendered, Statement, render, render_filter, render_op,
};
pub use packet::{Cell, ColumnDef, ServerError};
pub use schema::{LiveSchemaError, LiveTable, check_live_schema};
pub use version::{MariaVersion, admit_server_version};

/// Why a MariaDB operation was refused or failed. Every variant fails the operation closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MysqlError {
    /// The DSN is malformed or has an unsupported key.
    Dsn(String),
    /// The server is not on a loopback address and this client has no TLS path yet (D-P7.8: loopback or TLS).
    NotLoopback(String),
    /// TCP connect failed.
    Connect(String),
    /// Socket I/O failed (the connection is broken).
    Io(String),
    /// A deadline passed (the connection is broken).
    Timeout,
    /// The server sent bytes this client does not accept (the connection is broken).
    Protocol(String),
    /// A logical packet over the cap (the connection is broken).
    PacketTooLarge(usize),
    /// A result over [`Limits`] (the connection is broken).
    ResultTooLarge(String),
    /// Authentication with an unsupported plugin, or too many auth rounds.
    Auth(String),
    /// The server asked for caching_sha2_password.
    CachingSha2Refused,
    /// The server version is outside the pinned series or below the floor.
    VersionRefused(String),
    /// The session could not be pinned (sql_mode not strict, character set not utf8mb4).
    Session(String),
    /// A server ERR packet (the connection stays usable).
    Server(ServerError),
    /// The statement's parameter count differs from the bound parameters.
    Params { expected: usize, given: usize },
    /// The UPDATE RETURNING emulation was asked to run outside a transaction.
    NotInTransaction,
    /// The connection broke earlier and is never reused.
    Broken,
}

impl fmt::Display for MysqlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MysqlError::Dsn(m) => write!(f, "bad DSN: {m}"),
            MysqlError::NotLoopback(m) => {
                write!(
                    f,
                    "refused: {m}; the MariaDB client has no TLS path yet, so only loopback servers are spoken to"
                )
            }
            MysqlError::Connect(m) => write!(f, "connect failed: {m}"),
            MysqlError::Io(m) => write!(f, "I/O error: {m}"),
            MysqlError::Timeout => f.write_str("timeout"),
            MysqlError::Protocol(m) => write!(f, "protocol error: {m}"),
            MysqlError::PacketTooLarge(n) => write!(f, "packet of {n} bytes over the cap"),
            MysqlError::ResultTooLarge(m) => write!(f, "result over the cap: {m}"),
            MysqlError::Auth(m) => write!(f, "authentication refused: {m}"),
            MysqlError::CachingSha2Refused => f.write_str(
                "authentication refused: the server requires caching_sha2_password, which this client refuses until a \
                 TLS path exists (its full authentication sends the password over TLS or RSA); use a \
                 mysql_native_password account on a loopback server",
            ),
            MysqlError::VersionRefused(m) => write!(f, "server version refused: {m}"),
            MysqlError::Session(m) => write!(f, "session pin failed: {m}"),
            MysqlError::Server(e) => write!(f, "server error {} ({}): {}", e.code, e.state, e.message),
            MysqlError::Params { expected, given } => {
                write!(f, "statement has {expected} parameters, {given} given")
            }
            MysqlError::NotInTransaction => f.write_str("UPDATE RETURNING emulation needs an open transaction"),
            MysqlError::Broken => f.write_str("connection broken earlier; not reused"),
        }
    }
}

impl std::error::Error for MysqlError {}

/// Open a connection: loopback check, TCP connect, handshake, auth, version gate, session pin (all within
/// `cfg.connect_timeout`).
pub fn connect(cfg: &ConnectConfig) -> Result<Connection, MysqlError> {
    Connection::connect(cfg)
}
