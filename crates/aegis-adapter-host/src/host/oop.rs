//! Out-of-process adapter (non-golden, no assurance claim): F10 request frames.
//!
//! The render step of an out-of-process module is the F10 request frame `[0, req-id, op]` for the checked op
//! (`interfaces/F10-module-wire.cddl`), in postcard's positional encoding: unsigned integers as LEB128 varints,
//! signed integers zigzag + varint, strings and sequences length-prefixed with a varint, enum variants as a varint
//! discriminant followed by their fields. Frames are capped at [`MAX_FRAME`] (64 KiB, F10 default).
//!
//! Only the host → module direction exists here. The module transport and the response decoder (which is verified
//! TCB per F10) are not wired in this unit: [`OopExecutor`] fails every op closed with `Unavailable`.

use std::collections::BTreeMap;

use aegis_data_ir::{Fidelity, MAX_PRED_DEPTH, Op, OpKind, Pred, Schema, Value};
use aegis_types::TenantId;

use crate::dispatch::{EngineError, Executor, Renderer, ScopeInfo};
use crate::host::budget::{OpLimits, Usage};

/// F10 default frame cap.
pub const MAX_FRAME: usize = 64 * 1024;

/// Why a frame could not be encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    TooLarge,
    TooDeep,
}

fn varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

fn len(out: &mut Vec<u8>, n: usize) {
    varint(out, n as u64);
}

fn text(out: &mut Vec<u8>, s: &str) {
    len(out, s.len());
    out.extend_from_slice(s.as_bytes());
}

fn value(out: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Int(i) => {
            varint(out, 0);
            varint(out, zigzag(*i));
        }
        Value::Str(s) => {
            varint(out, 1);
            text(out, s);
        }
    }
}

fn kind_code(k: OpKind) -> u64 {
    match k {
        OpKind::Select => 0,
        OpKind::Insert => 1,
        OpKind::Update => 2,
        OpKind::Delete => 3,
        OpKind::Upsert => 4,
    }
}

fn pred(out: &mut Vec<u8>, p: &Pred, depth: usize) -> Result<(), FrameError> {
    if depth > MAX_PRED_DEPTH {
        return Err(FrameError::TooDeep);
    }
    if out.len() > MAX_FRAME {
        return Err(FrameError::TooLarge);
    }
    match p {
        Pred::Tt => varint(out, 0),
        Pred::Ff => varint(out, 1),
        Pred::Eq(f, v) => {
            varint(out, 2);
            varint(out, u64::from(*f));
            value(out, v);
        }
        Pred::IsIn(f, vs) => {
            varint(out, 3);
            varint(out, u64::from(*f));
            len(out, vs.len());
            for v in vs {
                value(out, v);
            }
        }
        Pred::Range(f, lo, hi) => {
            varint(out, 4);
            varint(out, u64::from(*f));
            value(out, lo);
            value(out, hi);
        }
        Pred::Pfx(f, s) => {
            varint(out, 5);
            varint(out, u64::from(*f));
            text(out, s);
        }
        Pred::And(a, b) | Pred::Or(a, b) => {
            varint(out, if matches!(p, Pred::And(..)) { 6 } else { 7 });
            pred(out, a, depth + 1)?;
            pred(out, b, depth + 1)?;
        }
        Pred::Not(a) => {
            varint(out, 8);
            pred(out, a, depth + 1)?;
        }
    }
    Ok(())
}

/// Encode the F10 request frame `[0, req_id, op]`.
pub fn encode_request(req_id: u64, op: &Op) -> Result<Vec<u8>, FrameError> {
    let mut out = Vec::with_capacity(64);
    varint(&mut out, 0); // frame = request
    varint(&mut out, req_id);
    varint(&mut out, op.tenant.get());
    text(&mut out, &op.collection);
    varint(&mut out, kind_code(op.kind));
    pred(&mut out, &op.filter, 0)?;
    len(&mut out, op.writes.len());
    for (f, v) in &op.writes {
        varint(&mut out, u64::from(*f));
        value(&mut out, v);
    }
    len(&mut out, op.returning.len());
    for f in &op.returning {
        varint(&mut out, u64::from(*f));
    }
    if out.len() > MAX_FRAME { Err(FrameError::TooLarge) } else { Ok(out) }
}

/// The renderer of one out-of-process module: its backend id and the schemas it declared (checked by the host
/// before every request; the module's own catalog is not trusted). Fidelity is `Refines`: no `Not`.
#[derive(Debug)]
pub struct OopRenderer {
    backend: String,
    schemas: BTreeMap<String, Schema>,
}

impl OopRenderer {
    pub fn new(backend: &str, schemas: Vec<Schema>) -> OopRenderer {
        OopRenderer {
            backend: backend.into(),
            schemas: schemas.into_iter().map(|s| (s.collection.clone(), s)).collect(),
        }
    }
}

impl Renderer for OopRenderer {
    type Rendered = Vec<u8>;
    fn backend_id(&self) -> &str {
        &self.backend
    }
    fn fidelity(&self) -> Fidelity {
        Fidelity::Refines
    }
    fn schema(&self, collection: &str) -> Option<&Schema> {
        self.schemas.get(collection)
    }
    fn render(&self, op: &Op, _schema: &Schema) -> Result<Vec<u8>, EngineError> {
        encode_request(0, op).map_err(|e| EngineError::Refused(format!("{e:?}")))
    }
}

/// Placeholder executor: no module transport in this unit, so every op fails closed.
#[derive(Debug, Default)]
pub struct OopExecutor;

impl Executor<Vec<u8>> for OopExecutor {
    type Tx = TenantId;
    type Rows = Vec<Vec<Option<Value>>>;
    fn begin(&self, scope: &ScopeInfo<'_>) -> Result<TenantId, EngineError> {
        Ok(scope.tenant)
    }
    fn execute(&self, _tx: &mut TenantId, _r: Vec<u8>, _l: OpLimits) -> Result<(Self::Rows, Usage), EngineError> {
        Err(EngineError::Unavailable("out-of-process module transport not wired".into()))
    }
    fn commit(&self, _tx: TenantId) -> Result<(), EngineError> {
        Ok(())
    }
    fn rollback(&self, _tx: TenantId) {}
}
