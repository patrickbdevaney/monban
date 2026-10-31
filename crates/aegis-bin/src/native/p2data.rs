//! The P2 `data_run` store over the golden engines (features `native` and `p2`; P5-bin-002, PLAN D15: the
//! renderer/executor pairings live in the assembly).
//!
//! [`P2Store::stage`] runs the host order of `aegis_adapter_host::dispatch::prepare` for one decoded F14 op whose
//! tenant the supervisor already overwrote: F4 `authorize` on the route's endowment (absent = no capability,
//! INV-NONEMPTY) → F4 `check_schema` on the schema introspected at boot (an unknown collection is a uniform
//! refusal after authorization, W6) → op-budget pre-debit (NC4) → the engine's production renderer with its F4
//! denylist scan. The app's allowlist lock is not applied: it lists the op shapes the linked notes app emits, and a
//! P2 module is not that app (F8 has no allowlist field for modules; F14 I1 names authorize and check_schema).
//!
//! The returned closure is the effect: one transaction of its own per data_run (begin, execute within the reserved
//! limits, commit), through the engine's inner executor (the same SQLite/PG executors the native routes use, minus
//! the native request-context wrappers, which belong to SDK scopes). The supervisor calls it only after the
//! data_run's audit event is durable.

use std::sync::Arc;

use aegis_adapter_host::dispatch::{Engine, Executor, Renderer, ScopeInfo};
use aegis_adapter_host::host::CancelToken;
use aegis_adapter_host::host::budget::{Remaining, RequestBudget};
use aegis_data_ir::{CapSet, Op, OpKind, Pred, Value, authorize, check_schema};
use aegis_types::{Principal, TenantId};

use super::scope::{CtxExec, CtxRenderer, EngineHandle};
use super::sqlite::Rows;
use super::{Bindings, DataPlane};
use crate::p2::data::{Exec, POp, PPred, PValue, Store};

fn value(v: &PValue) -> Value {
    match v {
        PValue::Int(i) => Value::Int(*i),
        PValue::Str(s) => Value::Str(s.clone()),
    }
}

/// The decoded filter as an F4 `Pred` (the decoder already bounded its depth by F4 `MAX_PRED_DEPTH`).
fn pred(p: &PPred) -> Pred {
    match p {
        PPred::Tt => Pred::Tt,
        PPred::Ff => Pred::Ff,
        PPred::Eq(f, v) => Pred::Eq(*f, value(v)),
        PPred::IsIn(f, vs) => Pred::IsIn(*f, vs.iter().map(value).collect()),
        PPred::Range(f, a, b) => Pred::Range(*f, value(a), value(b)),
        PPred::Pfx(f, s) => Pred::Pfx(*f, s.clone()),
        PPred::And(a, b) => Pred::And(Box::new(pred(a)), Box::new(pred(b))),
        PPred::Or(a, b) => Pred::Or(Box::new(pred(a)), Box::new(pred(b))),
        PPred::Not(a) => Pred::Not(Box::new(pred(a))),
    }
}

/// The F4 `Op` of a decoded F10 op (kind code i is `OpKind::ALL[i]`). `None`: tenant 0 or a kind out of range
/// (both refused by the decoder already).
pub fn to_op(op: &POp) -> Option<Op> {
    Some(Op {
        tenant: TenantId::new(op.tenant).ok()?,
        collection: op.collection.clone(),
        kind: *OpKind::ALL.get(usize::from(op.kind))?,
        filter: pred(&op.filter),
        writes: op.writes.iter().map(|(f, v)| (*f, value(v))).collect(),
        returning: op.returning.clone(),
    })
}

/// One P2 request's data authority: the route's endowment on its backend, for the verified principal.
#[derive(Debug)]
pub struct P2Store {
    dp: Arc<DataPlane>,
    caps: Option<Arc<CapSet>>,
    backend: Option<usize>,
    principal: Principal,
}

/// The store of a P2 request on route (`host`, `route_id`), or `None` when no data plane is booted (no route of
/// the config holds a data block: every data_run is refused).
pub fn p2_store(
    dp: Option<&Arc<DataPlane>>,
    bindings: &Bindings,
    host: &str,
    route_id: u64,
    principal: Principal,
) -> Option<Box<dyn Store>> {
    let dp = Arc::clone(dp?);
    let (caps, backend) = bindings.get(host, route_id).map_or((None, None), |r| (r.caps.clone(), r.backend));
    Some(Box::new(P2Store { dp, caps, backend, principal }))
}

fn stage_on<'a, Rn, Ex>(
    engine: &'a Engine<CtxRenderer<Rn>, CtxExec<Ex>>,
    caps: &CapSet,
    op: &Op,
    principal: &'a Principal,
) -> Option<Exec<'a>>
where
    Rn: Renderer,
    Ex: Executor<Rn::Rendered, Rows = Rows>,
{
    let renderer = &engine.renderer.inner;
    authorize(caps, renderer.backend_id(), op).ok()?;
    let schema = renderer.schema(&op.collection)?;
    check_schema(op, schema, renderer.fidelity()).ok()?;
    let budget = RequestBudget::new(Remaining::DEFAULT);
    let debit = budget.pre_debit().ok()?;
    let rendered = renderer.render(op, schema).ok()?;
    let tenant = op.tenant;
    let exec = &engine.executor.inner;
    Some(Box::new(move || {
        let _scope = budget; // the debit settles against this scope's budget
        let cancel = CancelToken::new();
        let info = ScopeInfo { principal, tenant, cancel: &cancel };
        let mut tx = exec.begin(&info).ok()?;
        let Ok((rows, used)) = exec.execute(&mut tx, rendered, debit.limits()) else {
            exec.rollback(tx);
            return None;
        };
        if !debit.covers(&used) {
            exec.rollback(tx); // an adapter overrun: fail closed, the debit stays charged
            return None;
        }
        exec.commit(tx).ok()?;
        debit.settle(used);
        Some(rows)
    }))
}

impl Store for P2Store {
    fn stage<'a>(&'a self, op: &POp, skip_authorize: bool) -> Option<Exec<'a>> {
        let op = to_op(op)?;
        let unrestricted = CapSet::Unrestricted;
        let (caps, idx) = if skip_authorize {
            // NEGATIVE CONTROL `data-run-skips-authorize` (p2-mutants builds only): any route, first backend.
            (&unrestricted, self.backend.or_else(|| (!self.dp.engines.is_empty()).then_some(0))?)
        } else {
            (self.caps.as_deref()?, self.backend?)
        };
        match &self.dp.engines.get(idx)?.engine {
            EngineHandle::Sqlite { engine, .. } => stage_on(engine, caps, &op, &self.principal),
            EngineHandle::Pg { engine, .. } => stage_on(engine, caps, &op, &self.principal),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::p2::data::{MAX_PRED_DEPTH, decode_op};

    #[test]
    fn the_supervisor_depth_cap_is_f4s() {
        assert_eq!(MAX_PRED_DEPTH, aegis_data_ir::MAX_PRED_DEPTH);
    }

    #[test]
    fn decoded_ops_convert_positionally() {
        // f14.op(9, "notes", "update", eq(1, "a"), [(2, "b")], [1])
        let b = crate::p2::frame::Enc::new()
            .u(9)
            .bytes(b"notes")
            .u(2)
            .u(2)
            .u(1)
            .u(1)
            .bytes(b"a")
            .u(1)
            .u(2)
            .u(1)
            .bytes(b"b")
            .u(1)
            .u(1)
            .finish();
        let op = to_op(&decode_op(&b).unwrap()).unwrap();
        assert_eq!(op.tenant, TenantId::new(9).unwrap());
        assert_eq!(op.kind, OpKind::Update);
        assert_eq!(op.filter, Pred::Eq(1, Value::Str("a".into())));
        assert_eq!(op.writes, vec![(2, Value::Str("b".into()))]);
        assert_eq!(op.returning, vec![1]);
    }
}
