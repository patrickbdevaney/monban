//! Adapter host: the F7/F7b SDK host, golden data dispatch, and the out-of-process module/PDP transports.
//!
//! * [`host`]: drives `aegis_sdk::host` (decision D2(b)) on the bounded blocking pool (DEVIATIONS X-11): a fresh
//!   session view and per-scope backend for every call, open, step, message and job; jobs kept after commit even
//!   when the handler errors; stream idle/step budgets in ticks; revoked sessions denied/unavailable; handler
//!   values served with fixed non-HTML content types and nosniff; idempotency leases that always end. Gate:
//!   `oracles/sdk-host` through `subjects/host-subject`.
//! * [`dispatch`]: the per-op host order `authorize(CapSet) → check_schema(introspected) → allowlist lock →
//!   budget pre-debit (NC4) → render → execute`, over a [`dispatch::Renderer`] (adapter) and a
//!   [`dispatch::Executor`] (connection or pool seam). Gate: `oracles/nonempty-props` (INV-NONEMPTY).
//! * [`pdp_uds`]: the effects side of the out-of-process Cedar PDP (DEVIATIONS X-8).
//!
//! The concrete SQLite/PG/Redis renderers are not linked here (same layer, no dependency edge); the assembly
//! pairs them with executors and hands them to [`dispatch`]. Spec: `spec/SPEC_INVARIANTS.md`.
#![forbid(unsafe_code)]

pub mod dispatch;
pub mod host;
pub mod pdp_uds;
