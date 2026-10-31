//! One fresh Store and instance per request (PLAN-5 D1, D6; ARCHITECTURE §3.6: instance reuse produced 93 poisoned
//! answers and is rejected).
//!
//! [`Worker`] holds the engine and an `InstancePre` (resolved once per process, no compiler state). Every
//! [`Worker::handle`] call builds a new `Store` with a [`HostState`] limiter at the request's `memory_mib`, arms fuel
//! (accounting) and the epoch deadline (wall bound) before instantiation, so a start function runs under the same
//! bounds, calls `handle()`, and drops the Store, which returns the pool slot. No guest state survives a request.
#![forbid(unsafe_code)]

use std::fmt;

use wasmtime::{InstancePre, Linker, Module, ResourceLimiter, Store, Trap};

use crate::abi;
use crate::engine::{P2Engine, P2Limits, epoch_deadline_ticks};

/// Table elements per table allowed by the limiter (F8: table growth bounded by the same limiter).
pub const MAX_TABLE_ELEMENTS: usize = 10_000;

/// Effective limits of one request: the frame's values, never above the worker's boot ceilings (F14 `limits`:
/// "the worker applies min(frame value, its own boot ceilings) and never raises a limit").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestLimits {
    fuel: u64,
    wall_ms: u64,
    memory_bytes: u64,
}

impl RequestLimits {
    /// Limits exactly as configured.
    pub fn from_p2(l: &P2Limits) -> Self {
        Self { fuel: l.fuel(), wall_ms: l.wall_ms(), memory_bytes: l.memory_bytes() }
    }

    /// `min(requested, ceiling)` per field.
    pub fn clamped(requested: &P2Limits, ceiling: &P2Limits) -> Self {
        Self {
            fuel: requested.fuel().min(ceiling.fuel()),
            wall_ms: requested.wall_ms().min(ceiling.wall_ms()),
            memory_bytes: requested.memory_bytes().min(ceiling.memory_bytes()),
        }
    }

    /// Fuel for the request.
    pub fn fuel(&self) -> u64 {
        self.fuel
    }
    /// Wall bound in ms.
    pub fn wall_ms(&self) -> u64 {
        self.wall_ms
    }
    /// Linear-memory cap in bytes.
    pub fn memory_bytes(&self) -> u64 {
        self.memory_bytes
    }
}

impl From<P2Limits> for RequestLimits {
    fn from(l: P2Limits) -> Self {
        Self::from_p2(&l)
    }
}

/// Per-request store data: the ResourceLimiter. One linear memory, one table, one instance per Store.
#[derive(Debug)]
pub struct HostState {
    memory_cap: usize,
    limit_hit: bool,
}

impl HostState {
    fn new(limits: &RequestLimits) -> Self {
        Self { memory_cap: usize::try_from(limits.memory_bytes).unwrap_or(usize::MAX), limit_hit: false }
    }
}

impl ResourceLimiter for HostState {
    fn memory_growing(&mut self, _current: usize, desired: usize, _maximum: Option<usize>) -> wasmtime::Result<bool> {
        let ok = desired <= self.memory_cap;
        self.limit_hit |= !ok;
        Ok(ok)
    }
    fn table_growing(&mut self, _current: usize, desired: usize, _maximum: Option<usize>) -> wasmtime::Result<bool> {
        let ok = desired <= MAX_TABLE_ELEMENTS;
        self.limit_hit |= !ok;
        Ok(ok)
    }
    fn instances(&self) -> usize {
        1
    }
    fn tables(&self) -> usize {
        1
    }
    fn memories(&self) -> usize {
        1
    }
}

/// Why a request did not complete, with the F14 `trap` code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrapKind {
    /// 1: fuel exhausted.
    Fuel,
    /// 2: wall bound (epoch deadline).
    Wall,
    /// 3: memory or table limit (e.g. an initial memory above `memory_mib`).
    Memory,
    /// 4: any other Wasm trap or instantiation failure.
    Wasm,
}

impl TrapKind {
    /// F14 `trap` code.
    pub fn code(self) -> u32 {
        match self {
            Self::Fuel => 1,
            Self::Wall => 2,
            Self::Memory => 3,
            Self::Wasm => 4,
        }
    }
}

/// Raw result of one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// `handle()` returned this status (the i32 read as u32).
    Returned(u32),
    /// The request trapped (or failed to instantiate).
    Trapped(TrapKind),
}

/// The module's decision as one input to the F6 combiner (I7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// `handle()` returned 0.
    Allow,
    /// `handle()` returned 1.
    Deny,
    /// Any other status, or a trap: maps to Deny at the combiner.
    Error,
}

impl Outcome {
    /// F14 Part 1: 0 = Allow, 1 = Deny, anything else and every trap = Error.
    pub fn decision(&self) -> Decision {
        match self {
            Self::Returned(0) => Decision::Allow,
            Self::Returned(1) => Decision::Deny,
            Self::Returned(_) | Self::Trapped(_) => Decision::Error,
        }
    }
}

/// One request's outcome and the fuel it consumed (an untrusted report on the wire; accounting only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    /// What happened.
    pub outcome: Outcome,
    /// Fuel consumed (including the start function).
    pub fuel_used: u64,
}

/// Worker construction failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkerError {
    /// The module's imports cannot be resolved by the F14 linker (fail closed).
    Link(String),
}

impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Link(m) => write!(f, "link: {m}"),
        }
    }
}

impl std::error::Error for WorkerError {}

/// Engine plus pre-resolved module: the per-process state of a zygote or cordon.
pub struct Worker {
    engine: P2Engine,
    pre: InstancePre<HostState>,
}

impl fmt::Debug for Worker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Worker").field("engine", &self.engine).finish_non_exhaustive()
    }
}

impl Worker {
    /// Resolves `module` against the F14 linker once.
    pub fn new(engine: &P2Engine, module: &Module) -> Result<Self, WorkerError> {
        let mut linker = Linker::<HostState>::new(engine.wasmtime());
        abi::define_imports(&mut linker).map_err(|e| WorkerError::Link(e.to_string()))?;
        let pre = linker.instantiate_pre(module).map_err(|e| WorkerError::Link(format!("{e:#}")))?;
        Ok(Self { engine: engine.clone(), pre })
    }

    /// The engine.
    pub fn engine(&self) -> &P2Engine {
        &self.engine
    }

    /// Serves one request in a fresh Store and instance. The epoch must be advancing (an [`crate::EpochTicker`])
    /// for the wall bound to fire; without it only fuel bounds the request.
    pub fn handle(&self, limits: RequestLimits) -> Report {
        let mut store = Store::new(self.engine.wasmtime(), HostState::new(&limits));
        store.limiter(|s| s);
        if store.set_fuel(limits.fuel).is_err() {
            return Report { outcome: Outcome::Trapped(TrapKind::Wasm), fuel_used: 0 };
        }
        store.set_epoch_deadline(epoch_deadline_ticks(limits.wall_ms));
        store.epoch_deadline_trap();
        let outcome = self.run(&mut store);
        let left = store.get_fuel().unwrap_or(0);
        Report { outcome, fuel_used: limits.fuel.saturating_sub(left) }
        // `store` drops here: the instance and its memory go back to the pool, wiped by the allocator.
    }

    fn run(&self, store: &mut Store<HostState>) -> Outcome {
        let inst = match self.pre.instantiate(&mut *store) {
            Ok(i) => i,
            Err(e) => return Outcome::Trapped(classify(&e, store.data())),
        };
        let func = match inst.get_typed_func::<(), i32>(&mut *store, abi::EXPORT_HANDLE) {
            Ok(f) => f,
            Err(_) => return Outcome::Trapped(TrapKind::Wasm),
        };
        match func.call(&mut *store, ()) {
            Ok(v) => Outcome::Returned(u32::from_ne_bytes(v.to_ne_bytes())),
            Err(e) => Outcome::Trapped(classify(&e, store.data())),
        }
    }
}

fn classify(e: &wasmtime::Error, st: &HostState) -> TrapKind {
    match e.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => TrapKind::Fuel,
        Some(Trap::Interrupt) => TrapKind::Wall,
        Some(_) => TrapKind::Wasm,
        None if st.limit_hit => TrapKind::Memory,
        None => TrapKind::Wasm,
    }
}
