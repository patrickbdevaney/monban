//! App-facing query surface (PLAN Phase 4 decision D13; not a frozen interface).
//!
//! Applications depend on aegis-sdk alone (layering rule), so the F4 types they need to build a data operation are
//! re-exported here. Building an `Op` grants nothing: `TenantDb::run` still needs a `Granted<DataCap<K>>` from
//! `Ctx::grant`, the SDK refuses an op whose `kind` is not `K`, and it overwrites `op.tenant` with the principal's
//! tenant before the host sees the op. The host then runs F4 `authorize` against the route's capability set,
//! `check_schema`, the budget pre-debit and the adapter's renderer (aegis-adapter-host `dispatch`).
//!
//! ```
//! use aegis_sdk::query::{Op, OpKind, Pred, Value};
//! use aegis_sdk::{op_code, Ctx, SdkError, TenantDb};
//!
//! const SELECT: u8 = op_code(OpKind::Select);
//! fn titles<'r, D: TenantDb<'r>>(ctx: &Ctx<'r>, db: &D) -> Result<D::Rows, SdkError> {
//!     let cap = ctx.grant::<SELECT>()?;
//!     let op = Op {
//!         tenant: ctx.principal().tenant(), // overwritten by the SDK anyway
//!         collection: "notes".into(),
//!         kind: OpKind::Select,
//!         filter: Pred::Eq(1, Value::Str("k".into())),
//!         writes: Vec::new(),
//!         returning: vec![2],
//!     };
//!     let mut tx = db.begin()?;
//!     db.run(&mut tx, &cap, op)
//! }
//! ```

pub use aegis_data_ir::{Field, Op, OpKind, Pred, Value};
