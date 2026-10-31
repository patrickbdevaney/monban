//! Fault-injection guest ABI of `oracles/isolation-fi` (feature `test-hooks` only, PLAN-5 D15; never in a golden
//! build). The oracle's guest exports `handle(id: i32, fault: i32) -> i32` and imports `env.host_fault(code: i32)`;
//! it is not an F14 module, so it gets its own compile check and Linker here. Everything else is the product path:
//! the same [`P2Engine`] (pooling, 4 GiB reservation, 32 MiB guards, fuel and epoch on), the same digest-checked
//! `.cwasm` load ([`crate::engine::cwasm::load`]), one fresh Store and instance per call with a limiter at the
//! request's memory cap, fuel armed before instantiation, and the epoch deadline of [`crate::Worker`].
//!
//! `env.host_fault` (F14 Part 1, test-only import): code 1 aborts the process (abort(3)), code 2 sets this
//! process's host-corruption flag ([`host_corrupted`]: every later reply of the process must be wrong, the oracle's
//! hostpoison class), any other code traps.
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};

use wasmtime::{ExternType, InstancePre, Linker, Module, ResourceLimiter, Store, Trap, TypedFunc, ValType};

use crate::engine::cwasm::{CwasmError, MAX_WASM_BYTES};
use crate::engine::{P2Engine, epoch_deadline_ticks};
use crate::store::{MAX_TABLE_ELEMENTS, RequestLimits, TrapKind};

/// The guest export.
pub const EXPORT: &str = "handle";

static HOST_CORRUPT: AtomicBool = AtomicBool::new(false);

/// Whether a guest called `env.host_fault(2)` in this process.
pub fn host_corrupted() -> bool {
    HOST_CORRUPT.load(Ordering::SeqCst)
}

/// Per-call store data: the limiter.
#[derive(Debug)]
pub struct FiState {
    memory_cap: usize,
    limit_hit: bool,
}

impl ResourceLimiter for FiState {
    fn memory_growing(&mut self, _c: usize, desired: usize, _m: Option<usize>) -> wasmtime::Result<bool> {
        let ok = desired <= self.memory_cap;
        self.limit_hit |= !ok;
        Ok(ok)
    }
    fn table_growing(&mut self, _c: usize, desired: usize, _m: Option<usize>) -> wasmtime::Result<bool> {
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

fn is_i32(t: &ValType) -> bool {
    matches!(t, ValType::I32)
}

/// Checks the fault-injection shape: imports only `env.host_fault: [i32] -> []`, exports `handle: [i32 i32] -> [i32]`.
fn check(module: &Module) -> Result<(), String> {
    for imp in module.imports() {
        let ok = imp.module() == "env"
            && imp.name() == "host_fault"
            && matches!(imp.ty(), ExternType::Func(ref f) if f.params().len() == 1 && f.params().all(|t| is_i32(&t)) && f.results().len() == 0);
        if !ok {
            return Err(format!("import {}.{} refused", imp.module(), imp.name()));
        }
    }
    let ok = module.exports().any(|e| {
        e.name() == EXPORT
            && matches!(e.ty(), ExternType::Func(ref f) if f.params().len() == 2 && f.params().all(|t| is_i32(&t)) && f.results().len() == 1 && f.results().all(|t| is_i32(&t)))
    });
    if ok { Ok(()) } else { Err(format!("missing export {EXPORT}: [i32 i32] -> [i32]")) }
}

/// Validates the fault-injection guest and returns the serialized `.cwasm` for this engine.
pub fn compile(engine: &P2Engine, wasm: &[u8]) -> Result<Vec<u8>, CwasmError> {
    if wasm.len() > MAX_WASM_BYTES {
        return Err(CwasmError::TooLarge(u64::try_from(wasm.len()).unwrap_or(u64::MAX)));
    }
    let module = Module::new(engine.wasmtime(), wasm).map_err(|e| CwasmError::Wasmtime(format!("{e:#}")))?;
    check(&module).map_err(CwasmError::Wasmtime)?;
    module.serialize().map_err(|e| CwasmError::Wasmtime(format!("{e:#}")))
}

/// Engine plus the pre-resolved fault-injection module.
pub struct FiWorker {
    engine: P2Engine,
    pre: InstancePre<FiState>,
}

impl std::fmt::Debug for FiWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FiWorker").finish_non_exhaustive()
    }
}

fn classify(e: &wasmtime::Error, st: &FiState) -> TrapKind {
    match e.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => TrapKind::Fuel,
        Some(Trap::Interrupt) => TrapKind::Wall,
        Some(_) => TrapKind::Wasm,
        None if st.limit_hit => TrapKind::Memory,
        None => TrapKind::Wasm,
    }
}

/// One live instance (the per-call unit; [`FiWorker::call`] makes and drops one per call).
pub struct FiInstance {
    store: Store<FiState>,
    func: TypedFunc<(i32, i32), i32>,
}

impl std::fmt::Debug for FiInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FiInstance").finish_non_exhaustive()
    }
}

impl FiInstance {
    /// Re-arms fuel and the epoch deadline, then calls `handle(id, fault)`.
    fn call(&mut self, limits: RequestLimits, id: u32, fault: u32) -> Result<u32, TrapKind> {
        self.store.set_fuel(limits.fuel()).map_err(|_| TrapKind::Wasm)?;
        self.store.set_epoch_deadline(epoch_deadline_ticks(limits.wall_ms()));
        let r = self
            .func
            .call(&mut self.store, (i32::from_ne_bytes(id.to_ne_bytes()), i32::from_ne_bytes(fault.to_ne_bytes())));
        r.map(|v| u32::from_ne_bytes(v.to_ne_bytes())).map_err(|e| classify(&e, self.store.data()))
    }
}

impl FiWorker {
    /// Resolves `module` (from [`crate::engine::cwasm::load`]) against the fault-injection Linker once.
    pub fn new(engine: &P2Engine, module: &Module) -> Result<Self, String> {
        check(module)?;
        let mut linker = Linker::<FiState>::new(engine.wasmtime());
        linker
            .func_wrap("env", "host_fault", |code: i32| -> wasmtime::Result<()> {
                match code {
                    // Stands in for a guest-triggerable host bug that takes the serving process down.
                    1 => std::process::abort(),
                    // Stands in for a guest-triggerable host bug that silently corrupts host state.
                    2 => {
                        HOST_CORRUPT.store(true, Ordering::SeqCst);
                        Ok(())
                    }
                    _ => Err(wasmtime::Error::msg("host_fault: unknown code")),
                }
            })
            .map_err(|e| format!("{e:#}"))?;
        let pre = linker.instantiate_pre(module).map_err(|e| format!("{e:#}"))?;
        Ok(Self { engine: engine.clone(), pre })
    }

    /// A fresh Store and instance with fuel and the epoch deadline armed before instantiation.
    pub fn instance(&self, limits: RequestLimits) -> Result<FiInstance, TrapKind> {
        let cap = usize::try_from(limits.memory_bytes()).unwrap_or(usize::MAX);
        let mut store = Store::new(self.engine.wasmtime(), FiState { memory_cap: cap, limit_hit: false });
        store.limiter(|s| s);
        store.set_fuel(limits.fuel()).map_err(|_| TrapKind::Wasm)?;
        store.set_epoch_deadline(epoch_deadline_ticks(limits.wall_ms()));
        store.epoch_deadline_trap();
        let inst = match self.pre.instantiate(&mut store) {
            Ok(i) => i,
            Err(e) => return Err(classify(&e, store.data())),
        };
        let func = inst.get_typed_func::<(i32, i32), i32>(&mut store, EXPORT).map_err(|_| TrapKind::Wasm)?;
        Ok(FiInstance { store, func })
    }

    /// One request in a fresh instance (dropped before returning).
    pub fn call(&self, limits: RequestLimits, id: u32, fault: u32) -> Result<u32, TrapKind> {
        self.instance(limits)?.call(limits, id, fault)
    }

    /// MUTANT reuse-instance support: calls `handle` again on a kept instance (oracle negative control only).
    #[cfg(feature = "mutants")]
    pub fn call_on(&self, inst: &mut FiInstance, limits: RequestLimits, id: u32, fault: u32) -> Result<u32, TrapKind> {
        inst.call(limits, id, fault)
    }
}
