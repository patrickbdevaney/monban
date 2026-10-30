//! Host order per op (P4-host-001 notes): authorize(CapSet) → check_schema(introspected) → allowlist → budget
//! pre-debit (NC4) → render → execute. Render is never reached on a deny, a schema refusal or an exhausted budget,
//! and an unknown collection is refused only after authorization.

use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use aegis_adapter_host::dispatch::{self, DispatchError, Engine, EngineError, Executor, Refusal, Renderer, prepare};
use aegis_adapter_host::host::budget::{OpLimits, Remaining, RequestBudget, Usage};
use aegis_data_ir::{
    CapSet, Caps, Collation, Column, DataCap, Fidelity, Op, OpKind, OpMask, Pred, Schema, UniqueIndex, Value,
};
use aegis_types::TenantId;

struct Counting {
    schema: Schema,
    renders: AtomicUsize,
}

impl Renderer for Counting {
    type Rendered = String;
    fn backend_id(&self) -> &str {
        "main"
    }
    fn fidelity(&self) -> Fidelity {
        Fidelity::Refines
    }
    fn schema(&self, c: &str) -> Option<&Schema> {
        (c == self.schema.collection).then_some(&self.schema)
    }
    fn render(&self, op: &Op, _s: &Schema) -> Result<String, EngineError> {
        self.renders.fetch_add(1, Ordering::SeqCst);
        Ok(format!("{:?}", op.kind))
    }
}

struct Exec {
    executed: AtomicUsize,
    used: Usage,
}

impl Executor<String> for Exec {
    type Tx = ();
    type Rows = String;
    fn begin(&self, _t: TenantId) -> Result<(), EngineError> {
        Ok(())
    }
    fn execute(&self, _tx: &mut (), r: String, _l: OpLimits) -> Result<(String, Usage), EngineError> {
        self.executed.fetch_add(1, Ordering::SeqCst);
        Ok((r, self.used))
    }
    fn commit(&self, _tx: ()) -> Result<(), EngineError> {
        Ok(())
    }
    fn rollback(&self, _tx: ()) {}
}

fn schema() -> Schema {
    let col = |field, name: &str, key| Column {
        field,
        name: name.into(),
        nullable: false,
        collation: Collation::Binary,
        key,
    };
    Schema {
        collection: "notes".into(),
        tenant_field: 0,
        columns: vec![col(0, "tenant", false), col(1, "k", true), col(2, "body", false)],
        permitted: vec![1, 2],
        unique_indexes: vec![UniqueIndex { fields: vec![0, 1], prefix: false }],
    }
}

fn t() -> Result<TenantId, String> {
    TenantId::new(42).map_err(|_| "tenant".to_string())
}

fn select(coll: &str, ret: Vec<u32>) -> Result<Op, String> {
    Ok(Op {
        tenant: t()?,
        collection: coll.into(),
        kind: OpKind::Select,
        filter: Pred::Eq(1, Value::Str("a".into())),
        writes: vec![],
        returning: ret,
    })
}

fn caps(ops: u8, cols: Vec<u32>) -> Result<CapSet, String> {
    let m = OpMask::from_bits(ops).map_err(|e| format!("{e:?}"))?;
    let c = DataCap::new("main", "notes", m, cols).map_err(|e| format!("{e:?}"))?;
    Ok(CapSet::Caps(Caps::new(vec![c]).map_err(|e| format!("{e:?}"))?))
}

#[test]
fn deny_is_decided_before_render() -> Result<(), String> {
    let r = Counting { schema: schema(), renders: AtomicUsize::new(0) };
    let b = RequestBudget::new(Remaining::DEFAULT);
    // No data block, a non-covering cap (column 2 missing), wrong kind: all denied, render never reached.
    assert_eq!(prepare(None, &r, &select("notes", vec![2])?, &b).err(), Some(Refusal::Denied));
    assert_eq!(prepare(Some(&caps(1, vec![1])?), &r, &select("notes", vec![2])?, &b).err(), Some(Refusal::Denied));
    assert_eq!(prepare(Some(&caps(2, vec![1, 2])?), &r, &select("notes", vec![2])?, &b).err(), Some(Refusal::Denied));
    assert_eq!(r.renders.load(Ordering::SeqCst), 0);
    // Denials consume no budget.
    assert_eq!(b.remaining(), Remaining::DEFAULT);
    // Covering: rendered.
    assert!(prepare(Some(&caps(1, vec![1, 2])?), &r, &select("notes", vec![2])?, &b).is_ok());
    assert_eq!(r.renders.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn unknown_collection_only_after_authorization() -> Result<(), String> {
    let r = Counting { schema: schema(), renders: AtomicUsize::new(0) };
    let b = RequestBudget::new(Remaining::DEFAULT);
    // A caller without a covering cap gets the same Denied whether or not the collection exists (W6).
    assert_eq!(prepare(Some(&caps(1, vec![1, 2])?), &r, &select("ghost", vec![2])?, &b).err(), Some(Refusal::Denied));
    let any = CapSet::Unrestricted;
    assert_eq!(prepare(Some(&any), &r, &select("ghost", vec![2])?, &b).err(), Some(Refusal::NoSuchCollection));
    // Both look identical to a handler.
    let e1 = DispatchError::Refused(Refusal::Denied).to_sdk();
    let e2 = DispatchError::Refused(Refusal::NoSuchCollection).to_sdk();
    assert_eq!(e1, e2);
    assert_eq!(r.renders.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn schema_refusal_and_budget_precede_render() -> Result<(), String> {
    let r = Counting { schema: schema(), renders: AtomicUsize::new(0) };
    let any = CapSet::Unrestricted;
    let b = RequestBudget::new(Remaining::DEFAULT);
    // Returning the tenant column is not permitted: schema refusal (Unrestricted lifts the cap check only).
    assert!(matches!(prepare(Some(&any), &r, &select("notes", vec![0])?, &b), Err(Refusal::Schema(_))));
    // An exhausted budget refuses before render.
    let empty = RequestBudget::new(Remaining { ops: 0, ..Remaining::DEFAULT });
    assert_eq!(prepare(Some(&any), &r, &select("notes", vec![2])?, &empty).err(), Some(Refusal::Budget));
    assert_eq!(r.renders.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn run_settles_or_charges_the_debit() -> Result<(), String> {
    let cs = caps(1, vec![1, 2])?;
    let e = Engine {
        renderer: Counting { schema: schema(), renders: AtomicUsize::new(0) },
        executor: Exec { executed: AtomicUsize::new(0), used: Usage { rows: 3, bytes: 10, ms: 7 } },
    };
    let b = RequestBudget::new(Remaining::DEFAULT);
    let rows = dispatch::run(Some(&cs), &e, &select("notes", vec![2])?, &b, &mut ()).map_err(|e| format!("{e:?}"))?;
    assert_eq!(rows, "Select");
    let left = b.remaining();
    assert_eq!(left.ops, Remaining::DEFAULT.ops - 1);
    assert_eq!(left.rows, Remaining::DEFAULT.rows - 3);
    assert_eq!(left.ms, Remaining::DEFAULT.ms - 7);
    // A denied op never executes.
    assert!(dispatch::run(None, &e, &select("notes", vec![2])?, &b, &mut ()).is_err());
    assert_eq!(e.executor.executed.load(Ordering::SeqCst), 1);
    // Overrun (usage above the reservation): refused, and the reservation stays charged in full (NC4).
    let over = Engine {
        renderer: Counting { schema: schema(), renders: AtomicUsize::new(0) },
        executor: Exec { executed: AtomicUsize::new(0), used: Usage { rows: 20_000, bytes: 0, ms: 0 } },
    };
    let b2 = RequestBudget::new(Remaining::DEFAULT);
    assert_eq!(dispatch::run(Some(&cs), &over, &select("notes", vec![2])?, &b2, &mut ()), Err(DispatchError::Overrun));
    assert_eq!(b2.remaining().rows, 0);
    Ok(())
}

#[test]
fn dropped_debit_stays_charged() {
    let b = RequestBudget::new(Remaining::DEFAULT);
    let cancelled = Cell::new(false);
    if let Ok(d) = b.pre_debit() {
        drop(d); // a cancelled op: never settled
        cancelled.set(true);
    }
    assert!(cancelled.get());
    assert_eq!(b.remaining().ms, 0);
    assert_eq!(b.pre_debit().err(), Some(aegis_adapter_host::host::budget::Exhausted));
}
