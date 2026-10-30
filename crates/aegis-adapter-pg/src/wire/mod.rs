//! Owned PostgreSQL v3 wire client (DEVIATIONS X-10): blocking std sockets (TCP + Unix), startup, SCRAM-SHA-256,
//! extended query with text parameters, exact protocol-state tracking for NC3, CancelRequest.

pub mod conn;
pub mod dsn;
pub mod msg;
pub mod state;

pub use conn::{CancelKey, Connection, Error, Pipeline, QueryResult, ResultLimits, send_cancel};
pub use dsn::{ConnectConfig, DsnError, Endpoint};
pub use msg::{Backend, DbError, FieldDesc, TxnStatus, parse_backend};
pub use state::{Event, Expect, ProtoState, Unrecoverable};
