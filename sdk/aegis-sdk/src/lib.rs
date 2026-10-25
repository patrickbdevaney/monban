//! Handler SDK (B2 scoped adapter): `ScopedHandler<'r, E>`, `Ctx<'r, E>`, `TenantDb<'r>`, `Tx<Open> -> Committed`,
//! `Detached`, `Granted<Cap>`. Depends on L1/L2 only; application crates depend on this crate alone.
//!
//! Phase-0 stub. The request-scoped subset freezes as F7; streaming stays unstable until spike q4-001.
#![forbid(unsafe_code)]
