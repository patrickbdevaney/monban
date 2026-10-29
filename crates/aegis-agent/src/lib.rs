//! Agent-protocol listener gate (MCP both eras: 2026-07-28 primary, 2025-11-25 mandatory until ≥2027-07).
//!
//! The owned MCP transport of DEVIATIONS X-9: JSON-RPC 2.0 over Streamable HTTP (single JSON response per POST; no
//! SSE streams yet) on aegis-canon strict JSON, with the listener gate as a sans-I/O type ([`gate::Gate`]):
//! Host/Origin allowlists, `application/json` POST only, bearer JWT with the RFC 8707 audience, strict JSON-RPC
//! shape, the 2026-07-28 header/body consistency rules (-32020) and version check (-32022), 2025-11-25 sessions
//! bound to (subject, route), a fail-closed Cedar PDP decision ([`authz`]), and forward plans whose upstream calls
//! the assembly performs through aegis-egress. Every reject is decided before an upstream call exists.
//!
//! Layer 3: no sockets, no clock, no files here. The assembly (aegis-bin `agent` command) supplies the canonical
//! request from aegis-transport, the time, the PDP transport (aegis-adapter-host) and the egress fetcher.
//!
//! Rung: executed against oracles/mcp-corpus (black box, the shipped binary); no proof covers this code.
#![forbid(unsafe_code)]

pub mod authz;
pub mod b64;
pub mod config;
pub mod emit;
pub mod gate;
pub mod jwt;
pub mod session;

#[cfg(test)]
mod tests;

pub use authz::{Authorizer, DenyAll, PdpAuthorizer};
pub use config::AgentConfig;
pub use gate::{Forward, Gate, HttpRequest, Method, Response, Target, UpstreamCall, UpstreamReply, Verdict};
pub use jwt::{JwtProfile, Subject};
