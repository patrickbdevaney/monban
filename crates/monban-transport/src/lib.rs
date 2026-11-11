//! hyper/h2 wrapper enforcing TBI-1..9, strict H1, and the Exchange model (F3).
//!
//! A [`Server`] owns a front end ([`App`]: the F3 [`exchange::FrontEnd`] hooks plus routing and the reply), its
//! vhosts and the [`WrapperLimits`] (F8 `limits`, golden defaults). [`Server::serve_tls`] /
//! [`Server::serve_plain`] drive one accepted connection: HTTP/2 over h2 with the Monban wrapper, HTTP/1.1 over
//! hyper behind the strict framing filter. Handlers see only canonical values ([`exchange::Head`], or the whole
//! [`Request`]: authority, path, query, header set) and the size-checked message; Host / `:authority` / SNI are
//! bound to one vhost through monban-canon (CANON-6: 421 on an SNI or vhost mismatch over h2, userinfo rejected).
//! [`App::handle`] is asynchronous (a reverse proxy forwards from it); the wrapper budgets (TBI-4 permit, TBI-5
//! reset bucket, TBI-6/7 ledger on both directions, TBI-8 deadlines) apply around it on both protocols.
//!
//! Upstream framing regeneration (R-TLS-3) is not in this unit.
#![forbid(unsafe_code)]

pub mod exchange;

mod counters;
mod fields;
pub mod h1;
mod h1srv;
mod h2srv;
mod ledger;
mod limits;
mod pipeline;
mod server;

pub use crate::counters::Counters;
pub use crate::fields::{FieldBlock, cookie_crumbs};
pub use crate::ledger::Ledger;
pub use crate::limits::{F8_BOUNDS, LimitsError, WrapperLimits};
pub use crate::pipeline::{App, ConnInfo, HandlerFuture, Reply, ReplyBody, Request, VhostTable};
pub use crate::server::{H2_PREFACE, Server};
pub use monban_canon::Scheme;
/// Re-exported so the assembly builds the acceptor from the same tokio-rustls the driver uses.
pub use tokio_rustls::TlsAcceptor;
