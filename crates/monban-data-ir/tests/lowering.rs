//! Lowering tree (lower.rs): `lower_exact3` as a differential property (sql3 ∘ lower = eval3 for every Pred,
//! NOT included), the `lowerQ` tenant conjunct, `In []` UNKNOWN on NULL, the depth bound, and the statement tree.

use monban_data_ir::*;
use monban_types::TenantId;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn pick<T: Clone>(&mut self, xs: &[T]) -> T {
        let i = usize::try_from(self.below(xs.len() as u64)).unwrap_or(0);
        xs.get(i).cloned().unwrap_or_else(|| unreachable!())
    }
}

fn pool() -> Vec<Value> {
    let s = |x: &str| Value::Str(x.into());
    vec![Value::Int(-1), Value::Int(0), Value::Int(1), Value::Int(5), s(""), s("a"), s("ab"), s("b"), s("A"), s("é")]
}

fn gen_pred(r: &mut Rng, depth: u32) -> Pred {
    let vals = pool();
    let leaf = depth == 0 || r.below(3) == 0;
    let f = r.below(4) as Field;
    if leaf {
        match r.below(6) {
            0 => Pred::Tt,
            1 => Pred::Ff,
            2 => Pred::Eq(f, r.pick(&vals)),
            3 => {
                let n = r.below(3);
                Pred::IsIn(f, (0..n).map(|_| r.pick(&vals)).collect())
            }
            4 => Pred::Range(f, r.pick(&vals), r.pick(&vals)),
            _ => Pred::Pfx(f, r.pick(&["", "a", "é", "A"]).into()),
        }
    } else {
        match r.below(3) {
            0 => Pred::And(Box::new(gen_pred(r, depth - 1)), Box::new(gen_pred(r, depth - 1))),
            1 => Pred::Or(Box::new(gen_pred(r, depth - 1)), Box::new(gen_pred(r, depth - 1))),
            _ => Pred::Not(Box::new(gen_pred(r, depth - 1))),
        }
    }
}

fn tid(v: u64) -> TenantId {
    TenantId::new(v).unwrap_or_else(|_| unreachable!())
}

#[test]
fn lower_is_exact_under_three_valued_semantics() {
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    let vals = pool();
    let mut kept = 0u32;
    for _ in 0..100_000 {
        let p = gen_pred(&mut r, 5);
        let row: Vec<Option<Value>> =
            (0..4).map(|_| if r.below(4) == 0 { None } else { Some(r.pick(&vals)) }).collect();
        let get = |f: Field| row.get(f as usize).and_then(Option::as_ref);
        let e = lower(&p).unwrap_or_else(|_| unreachable!());
        assert_eq!(sql3(&get, &e), eval3(&get, &p), "{p:?} {row:?}");
        // lowerQ: tenant conjunct over field 0 holding a tenant text.
        let t = tid(1 + r.below(3));
        let mut trow = row.clone();
        if let Some(slot) = trow.get_mut(0) {
            *slot = Some(Value::Str(tenant_text(tid(1 + r.below(3)))));
        }
        let tget = |f: Field| trow.get(f as usize).and_then(Option::as_ref);
        let q = lower_q(0, t, &p).unwrap_or_else(|_| unreachable!());
        let refq = eval3(&tget, &Pred::And(Box::new(Pred::Eq(0, Value::Str(tenant_text(t)))), Box::new(p.clone())));
        let keeps = sql3(&tget, &q) == Ok(Some(true));
        assert_eq!(keeps, refq == Ok(Some(true)), "{p:?} {trow:?}");
        if keeps {
            kept += 1;
            assert_eq!(tget(0), Some(&Value::Str(tenant_text(t))), "a kept row always carries the bound tenant");
        }
    }
    assert!(kept > 1000, "non-vacuous: {kept} rows kept");
}

#[test]
fn lower_mirrors_lean_node_for_node() {
    let p = Pred::And(
        Box::new(Pred::Or(Box::new(Pred::Tt), Box::new(Pred::Ff))),
        Box::new(Pred::Not(Box::new(Pred::IsIn(2, vec![])))),
    );
    let want = SqlExpr::And(
        Box::new(SqlExpr::Or(Box::new(SqlExpr::Lit(true)), Box::new(SqlExpr::Lit(false)))),
        Box::new(SqlExpr::Not(Box::new(SqlExpr::InList(2, vec![])))),
    );
    assert_eq!(lower(&p), Ok(want));
    assert_eq!(
        lower(&Pred::Range(1, Value::Int(1), Value::Int(2))),
        Ok(SqlExpr::Between(1, Value::Int(1), Value::Int(2)))
    );
    assert_eq!(lower(&Pred::Pfx(1, "a".into())), Ok(SqlExpr::Pfx(1, "a".into())));
    assert_eq!(lower(&Pred::or_n(vec![])), Ok(SqlExpr::Lit(false)), "empty disjunction never widens");
    let q = lower_q(0, tid(42), &Pred::Tt);
    assert_eq!(
        q,
        Ok(SqlExpr::And(
            Box::new(SqlExpr::CmpEq(0, Value::Str("000000000000002a".into()))),
            Box::new(SqlExpr::Lit(true))
        ))
    );
}

#[test]
fn in_empty_is_unknown_on_null_and_false_on_present() {
    let e = SqlExpr::InList(1, vec![]);
    let none = |_: Field| None;
    let v = Value::Int(3);
    let present = |_: Field| Some(&v);
    assert_eq!(sql3(&none, &e), Ok(None));
    assert_eq!(sql3(&present, &e), Ok(Some(false)));
    let ne = SqlExpr::Not(Box::new(e));
    assert_eq!(sql3(&none, &ne), Ok(None), "NOT (x IN ()) must not keep a NULL row");
    assert_eq!(sql3(&present, &ne), Ok(Some(true)));
}

#[test]
fn depth_is_bounded() {
    let nest = |k: usize| (0..k).fold(Pred::Tt, |p, _| Pred::Not(Box::new(p)));
    assert!(lower(&nest(MAX_PRED_DEPTH - 1)).is_ok());
    assert_eq!(lower(&nest(MAX_PRED_DEPTH)), Err(LowerError::TooDeep));
    assert_eq!(lower(&nest(4_000)), Err(LowerError::TooDeep));
    assert_eq!(lower_q(0, tid(1), &nest(MAX_PRED_DEPTH)), Err(LowerError::TooDeep));
    let none = |_: Field| None;
    assert_eq!(eval3(&none, &nest(4_000)), Err(LowerError::TooDeep));
}

fn notes() -> Schema {
    let col =
        |field, key, nullable| Column { field, name: format!("c{field}"), nullable, collation: Collation::Binary, key };
    Schema {
        collection: "notes".into(),
        tenant_field: 0,
        columns: vec![col(0, false, false), col(1, true, false), col(2, false, true), col(3, false, true)],
        permitted: vec![1, 2, 3],
        unique_indexes: vec![UniqueIndex { fields: vec![1, 0], prefix: false }],
    }
}

fn op(kind: OpKind, filter: Pred, writes: Vec<(Field, Value)>, returning: Vec<Field>) -> Op {
    Op { tenant: tid(9), collection: "notes".into(), kind, filter, writes, returning }
}

#[test]
fn statement_tree_per_kind() {
    let s = notes();
    let t = Value::Str(tenant_text(tid(9)));
    let st = |v: &str| Value::Str(v.into());
    let tq = |p: SqlExpr| SqlExpr::And(Box::new(SqlExpr::CmpEq(0, t.clone())), Box::new(p));

    let sel = lower_op(&op(OpKind::Select, Pred::Eq(1, st("n1")), vec![], vec![2, 1, 2]), &s, Fidelity::Exact);
    let Ok(sel) = sel else { unreachable!() };
    assert_eq!(sel.stmt, Stmt::Select { filter: tq(SqlExpr::CmpEq(1, st("n1"))) });
    assert_eq!(sel.returning, vec![2, 1]);
    assert_eq!((sel.tenant_field, sel.tenant.clone(), sel.kind), (0, t.clone(), OpKind::Select));

    let ins = lower_op(&op(OpKind::Insert, Pred::Tt, vec![(2, st("x")), (1, st("n1"))], vec![]), &s, Fidelity::Exact);
    assert_eq!(ins.map(|l| l.stmt), Ok(Stmt::Insert { row: vec![(0, t.clone()), (2, st("x")), (1, st("n1"))] }));

    let up = lower_op(
        &op(OpKind::Upsert, Pred::Tt, vec![(1, st("n1")), (3, st("b")), (2, st("x"))], vec![1]),
        &s,
        Fidelity::Exact,
    );
    assert_eq!(
        up.map(|l| l.stmt),
        Ok(Stmt::Upsert {
            row: vec![(0, t.clone()), (1, st("n1")), (3, st("b")), (2, st("x"))],
            arbiter: vec![0, 1],
            action: UpsertAction::Update { set: vec![3, 2], guard: 0 },
        })
    );
    let nothing = lower_op(&op(OpKind::Upsert, Pred::Tt, vec![(1, st("n1"))], vec![]), &s, Fidelity::Exact);
    assert!(matches!(nothing.map(|l| l.stmt), Ok(Stmt::Upsert { action: UpsertAction::Nothing, .. })));

    let upd = lower_op(&op(OpKind::Update, Pred::Eq(1, st("n1")), vec![(2, st("y"))], vec![]), &s, Fidelity::Exact);
    assert_eq!(
        upd.map(|l| l.stmt),
        Ok(Stmt::Update { set: vec![(2, st("y"))], filter: tq(SqlExpr::CmpEq(1, st("n1"))) })
    );

    let del = lower_op(&op(OpKind::Delete, Pred::Tt, vec![], vec![]), &s, Fidelity::Exact);
    assert_eq!(del.map(|l| l.stmt), Ok(Stmt::Delete { filter: tq(SqlExpr::Lit(true)) }));
}

#[test]
fn statement_tree_refusals() {
    let s = notes();
    let st = |v: &str| Value::Str(v.into());
    let lo = |o: Op, f: Fidelity| lower_op(&o, &s, f).map(|_| ());
    let x = Fidelity::Exact;
    assert_eq!(lo(op(OpKind::Select, Pred::Tt, vec![(2, st("a"))], vec![]), x), Err(LowerError::WritesNotAllowed));
    assert_eq!(lo(op(OpKind::Delete, Pred::Tt, vec![(2, st("a"))], vec![]), x), Err(LowerError::WritesNotAllowed));
    assert_eq!(lo(op(OpKind::Update, Pred::Tt, vec![], vec![]), x), Err(LowerError::EmptyWrites));
    assert_eq!(lo(op(OpKind::Update, Pred::Tt, vec![(1, st("a"))], vec![]), x), Err(LowerError::KeyWritten(1)));
    assert_eq!(
        lo(op(OpKind::Update, Pred::Tt, vec![(2, st("a")), (2, st("b"))], vec![]), x),
        Err(LowerError::DuplicateWrite(2))
    );
    assert_eq!(lo(op(OpKind::Insert, Pred::Tt, vec![(2, st("a"))], vec![]), x), Err(LowerError::MissingKey(1)));
    assert_eq!(lo(op(OpKind::Upsert, Pred::Tt, vec![(2, st("a"))], vec![]), x), Err(LowerError::MissingKey(1)));
    assert_eq!(
        lo(op(OpKind::Insert, Pred::Eq(1, st("a")), vec![(1, st("a"))], vec![]), x),
        Err(LowerError::FilterOnInsert)
    );
    assert_eq!(
        lo(op(OpKind::Update, Pred::Tt, vec![(0, st("a"))], vec![]), x),
        Err(LowerError::Schema(SchemaError::TenantFieldWritten))
    );
    assert_eq!(
        lo(op(OpKind::Select, Pred::Not(Box::new(Pred::Tt)), vec![], vec![]), Fidelity::Refines),
        Err(LowerError::Schema(SchemaError::NotRequiresExact))
    );
    assert_eq!(
        lo(op(OpKind::Select, Pred::Tt, vec![], vec![0]), x),
        Err(LowerError::Schema(SchemaError::ReturningNotPermitted(0)))
    );
    let mut two = notes();
    two.unique_indexes.push(UniqueIndex { fields: vec![1], prefix: false });
    assert_eq!(
        lower_op(&op(OpKind::Upsert, Pred::Tt, vec![(1, st("a"))], vec![]), &two, x).map(|_| ()),
        Err(LowerError::Schema(SchemaError::UpsertArbiterNotTenantScoped))
    );
}
