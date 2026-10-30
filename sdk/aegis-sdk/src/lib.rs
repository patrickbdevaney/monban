//! Handler SDK (B2 scoped adapter, frozen interfaces F7 request-scoped surface and F7b streaming).
//!
//! Application crates depend on this crate alone (no tokio/axum). A handler receives a `Ctx<'r>` whose lifetime
//! is the request; every effect needs a `Granted<C>` that only the host can produce from the verified token and
//! the route's static endowment (INV-NO-AMBIENT), obtained through `Ctx::grant`. Streaming bodies, SSE, WebSocket
//! sessions and detached jobs are host-driven `'static` values that never hold a request-scoped capability
//! (`streaming`, spike q4-001). The host driving loop is the `host` module (feature `host`, decision D2(b)); only
//! aegis-adapter-host may enable it.
//!
//! # Minting is SDK-private (compile-fail coverage, P4-spec-002)
//!
//! Positive control: an application handler that obtains a grant, runs an operation, commits and detaches a job
//! compiles against the public surface alone.
//!
//! ```
//! use aegis_data_ir::{Op, OpKind};
//! use aegis_sdk::{op_code, Committed, Ctx, DataCap, Granted, Job, JobQueue, Open, ScopedHandler, SdkError, TenantDb, Tx};
//!
//! const SELECT: u8 = op_code(OpKind::Select);
//! struct Audit;
//! impl Job for Audit {
//!     fn run<'j, D: TenantDb<'j>>(self, _ctx: Ctx<'j>, _db: &D) -> Result<(), SdkError> { Ok(()) }
//! }
//! fn read<'r, D: TenantDb<'r>>(db: &D, tx: &mut Tx<'r, Open>, cap: &Granted<'r, DataCap<SELECT>>, op: Op)
//!     -> Result<D::Rows, SdkError> { db.run(tx, cap, op) }
//! struct H;
//! impl ScopedHandler for H {
//!     type Response = ();
//!     fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<(), SdkError> {
//!         let _cap: Granted<'r, DataCap<SELECT>> = ctx.grant::<SELECT>()?;
//!         let tx = db.begin()?;
//!         let done: Tx<'r, Committed> = db.commit(tx)?;
//!         db.detach(&done, Audit)
//!     }
//! }
//! ```
//!
//! An application crate cannot build a `Ctx` (private fields, `pub(crate)` constructor):
//!
//! ```compile_fail
//! fn forge<'r>(principal: &'r aegis_types::Principal, route: aegis_types::RouteId) -> aegis_sdk::Ctx<'r> {
//!     aegis_sdk::Ctx { principal, route }
//! }
//! ```
//!
//! ```compile_fail,E0624
//! fn forge<'r>(principal: &'r aegis_types::Principal, route: aegis_types::RouteId) -> aegis_sdk::Ctx<'r> {
//!     aegis_sdk::Ctx::mint(principal, route, principal)
//! }
//! ```
//!
//! nor a `Granted` proof:
//!
//! ```compile_fail,E0451
//! use core::marker::PhantomData;
//! fn forge() -> aegis_sdk::Granted<'static, aegis_sdk::DataCap<1>> {
//!     aegis_sdk::Granted { _c: PhantomData, _r: PhantomData }
//! }
//! ```
//!
//! ```compile_fail,E0624
//! fn forge() -> aegis_sdk::Granted<'static, aegis_sdk::DataCap<1>> {
//!     aegis_sdk::Granted::mint()
//! }
//! ```
//!
//! nor a `Tx` in either state:
//!
//! ```compile_fail,E0451
//! use core::marker::PhantomData;
//! fn forge() -> aegis_sdk::Tx<'static, aegis_sdk::Committed> {
//!     aegis_sdk::Tx { _s: PhantomData, _r: PhantomData }
//! }
//! ```
//!
//! ```compile_fail,E0624
//! fn forge() -> aegis_sdk::Tx<'static, aegis_sdk::Open> {
//!     aegis_sdk::Tx::mint()
//! }
//! ```
//!
//! nor supply its own grant check:
//!
//! ```compile_fail,E0603
//! #[derive(Debug)]
//! struct Always;
//! impl aegis_sdk::Grants for Always {
//!     fn permits(&self, _: u8) -> bool { true }
//! }
//! ```
#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

#[cfg(feature = "host")]
pub mod host;
mod streaming;
mod surface;
pub use streaming::*;
pub use surface::*;
