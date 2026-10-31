//! The process-wide Engine (PLAN-5 D11, ARCHITECTURE §3.6 R-ISO-2).
//!
//! [`EngineSettings`] is the one value the Engine is built from: [`P2Engine::new`] applies every field to
//! `wasmtime::Config` / `PoolingAllocationConfig`, keeps the value, and `aegis-p2 config --json` prints
//! [`P2Engine::settings`] of the engine it just built through [`EngineSettings::to_json`]. There is no second
//! literal: the JSON cannot drift from the configuration (supply-chain/wasmtime-config.toml `[effective]`).
//!
//! Fixed by construction (no F8 knob can change them): pooling allocation, 4 GiB reservation, 32 MiB guard, guard
//! before linear memory, signals-based traps, memory64/gc off, threads/component model off (their wasmtime cargo
//! features are absent, so no setter exists and they are reported false), epoch interruption and fuel on. F8 sets
//! only the pool size (`cordon_slots`), the pooled memory cap (`memory_mib`) and MPK (`mpk`).
// `deny`, not `forbid`: the child module `cwasm` holds the crate's single audited unsafe site (X-14).
#![deny(unsafe_code)]

pub mod cwasm;

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use wasmtime::{Config, Enabled, Engine, InstanceAllocationStrategy, PoolingAllocationConfig, Strategy};

/// Linear-memory reservation per memory: wasmtime's 64-bit default, asserted, never shrunk (GHSA-6wgr, GHSA-394w).
pub const MEMORY_RESERVATION: u64 = 4 << 30;
/// Guard region after (and, with `guard_before_linear_memory`, before) each linear memory: never shrunk.
pub const MEMORY_GUARD_SIZE: u64 = 32 << 20;
/// Wasm page size.
pub const WASM_PAGE: u64 = 64 << 10;

/// F8 `p2.fuel` bounds and default (D6: accounting, not the DoS bound).
pub const FUEL_MIN: u64 = 10_000;
/// F8 `p2.fuel` maximum.
pub const FUEL_MAX: u64 = 1_000_000_000;
/// F8 `p2.fuel` default (q4-006: about 2 ms on the laptop).
pub const FUEL_DEFAULT: u64 = 15_000_000;
/// F8 `p2.wall_ms` bounds and default (R-ISO-3: the DoS bound).
pub const WALL_MS_MIN: u64 = 1;
/// F8 `p2.wall_ms` maximum.
pub const WALL_MS_MAX: u64 = 1_000;
/// F8 `p2.wall_ms` default.
pub const WALL_MS_DEFAULT: u64 = 100;
/// F8 `p2.memory_mib` bounds and default (ResourceLimiter cap).
pub const MEMORY_MIB_MIN: u32 = 1;
/// F8 `p2.memory_mib` maximum.
pub const MEMORY_MIB_MAX: u32 = 256;
/// F8 `p2.memory_mib` default.
pub const MEMORY_MIB_DEFAULT: u32 = 16;
/// F8 `p2.cordon_slots` bounds and default (pool size: core instances, memories and tables).
pub const POOL_SLOTS_MIN: u32 = 1;
/// F8 `p2.cordon_slots` maximum.
pub const POOL_SLOTS_MAX: u32 = 1_024;
/// F8 `p2.cordon_slots` default (D1: 64).
pub const POOL_SLOTS_DEFAULT: u32 = 64;

/// Epoch tick of [`EpochTicker`]. A request's deadline is [`epoch_deadline_ticks`] ticks.
pub const EPOCH_TICK: Duration = Duration::from_millis(1);

/// A bounded F8 value was out of range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// `p2.fuel` outside [`FUEL_MIN`]..=[`FUEL_MAX`].
    Fuel(u64),
    /// `p2.wall_ms` outside [`WALL_MS_MIN`]..=[`WALL_MS_MAX`].
    WallMs(u64),
    /// `p2.memory_mib` outside [`MEMORY_MIB_MIN`]..=[`MEMORY_MIB_MAX`].
    MemoryMib(u32),
    /// `p2.cordon_slots` outside [`POOL_SLOTS_MIN`]..=[`POOL_SLOTS_MAX`].
    PoolSlots(u32),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fuel(v) => write!(f, "p2.fuel {v} outside {FUEL_MIN}..={FUEL_MAX}"),
            Self::WallMs(v) => write!(f, "p2.wall_ms {v} outside {WALL_MS_MIN}..={WALL_MS_MAX}"),
            Self::MemoryMib(v) => write!(f, "p2.memory_mib {v} outside {MEMORY_MIB_MIN}..={MEMORY_MIB_MAX}"),
            Self::PoolSlots(v) => write!(f, "p2.cordon_slots {v} outside {POOL_SLOTS_MIN}..={POOL_SLOTS_MAX}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Per-request limits from F8 (`p2.fuel`, `p2.wall_ms`, `p2.memory_mib`, or a module's override), bounds-checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P2Limits {
    fuel: u64,
    wall_ms: u64,
    memory_mib: u32,
}

impl P2Limits {
    /// The F8 defaults: 15,000,000 fuel, 100 ms, 16 MiB.
    pub const DEFAULT: Self = Self { fuel: FUEL_DEFAULT, wall_ms: WALL_MS_DEFAULT, memory_mib: MEMORY_MIB_DEFAULT };

    /// Bounds-checked constructor (the F8 schema bounds; a value outside them is refused, never clamped).
    pub fn new(fuel: u64, wall_ms: u64, memory_mib: u32) -> Result<Self, ConfigError> {
        if !(FUEL_MIN..=FUEL_MAX).contains(&fuel) {
            return Err(ConfigError::Fuel(fuel));
        }
        if !(WALL_MS_MIN..=WALL_MS_MAX).contains(&wall_ms) {
            return Err(ConfigError::WallMs(wall_ms));
        }
        if !(MEMORY_MIB_MIN..=MEMORY_MIB_MAX).contains(&memory_mib) {
            return Err(ConfigError::MemoryMib(memory_mib));
        }
        Ok(Self { fuel, wall_ms, memory_mib })
    }

    /// Fuel units per request.
    pub fn fuel(&self) -> u64 {
        self.fuel
    }
    /// Wall-clock bound per request, in ms.
    pub fn wall_ms(&self) -> u64 {
        self.wall_ms
    }
    /// Linear-memory cap per instance, in MiB.
    pub fn memory_mib(&self) -> u32 {
        self.memory_mib
    }
    /// Linear-memory cap per instance, in bytes.
    pub fn memory_bytes(&self) -> u64 {
        u64::from(self.memory_mib) << 20
    }
}

impl Default for P2Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// wasmtime `Enabled` for `PoolingAllocationConfig::memory_protection_keys`. `Auto` is not representable: it is
/// host-dependent, and the effective configuration must be a fixed value (wasmtime-config.toml).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mpk {
    /// `Enabled::No` (F8 `p2.mpk = false`, the default).
    No,
    /// `Enabled::Yes` (F8 `p2.mpk = true`): engine construction fails on a host without MPK, never silently off.
    Yes,
}

impl Mpk {
    fn as_str(self) -> &'static str {
        match self {
            Self::No => "no",
            Self::Yes => "yes",
        }
    }
    fn enabled(self) -> Enabled {
        match self {
            Self::No => Enabled::No,
            Self::Yes => Enabled::Yes,
        }
    }
}

/// The complete effective engine configuration. Fields are private: the only constructors are
/// [`EngineSettings::from_p2`] and [`EngineSettings::defaults`], which fix every security-relevant field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineSettings {
    memory_reservation: u64,
    memory_guard_size: u64,
    guard_before_linear_memory: bool,
    signals_based_traps: bool,
    pooling_total_core_instances: u32,
    pooling_total_memories: u32,
    pooling_total_tables: u32,
    pooling_max_memory_size: u64,
    memory_protection_keys: Mpk,
    wasm_memory64: bool,
    wasm_gc: bool,
    wasm_threads: bool,
    wasm_component_model: bool,
    epoch_interruption: bool,
    consume_fuel: bool,
}

impl EngineSettings {
    /// Settings from the F8 `p2` block: `memory_mib` is the largest per-module memory cap the process serves (the
    /// pooled slot size; the per-request ResourceLimiter cap can only be lower), `pool_slots` is `cordon_slots`.
    pub fn from_p2(memory_mib: u32, pool_slots: u32, mpk: bool) -> Result<Self, ConfigError> {
        if !(MEMORY_MIB_MIN..=MEMORY_MIB_MAX).contains(&memory_mib) {
            return Err(ConfigError::MemoryMib(memory_mib));
        }
        if !(POOL_SLOTS_MIN..=POOL_SLOTS_MAX).contains(&pool_slots) {
            return Err(ConfigError::PoolSlots(pool_slots));
        }
        Ok(Self::fixed(memory_mib, pool_slots, mpk))
    }

    /// The built-in F8 defaults (no config file): `memory_mib` 16, `cordon_slots` 64, MPK as given.
    pub fn defaults(mpk: bool) -> Self {
        Self::fixed(MEMORY_MIB_DEFAULT, POOL_SLOTS_DEFAULT, mpk)
    }

    /// Every field not set by F8 is fixed here, once.
    fn fixed(memory_mib: u32, pool_slots: u32, mpk: bool) -> Self {
        Self {
            memory_reservation: MEMORY_RESERVATION,
            memory_guard_size: MEMORY_GUARD_SIZE,
            guard_before_linear_memory: true,
            signals_based_traps: true,
            pooling_total_core_instances: pool_slots,
            pooling_total_memories: pool_slots,
            pooling_total_tables: pool_slots,
            pooling_max_memory_size: u64::from(memory_mib) << 20,
            memory_protection_keys: if mpk { Mpk::Yes } else { Mpk::No },
            wasm_memory64: false,
            wasm_gc: false,
            wasm_threads: false,
            wasm_component_model: false,
            epoch_interruption: true,
            consume_fuel: true,
        }
    }

    /// The MPK setting.
    pub fn mpk(&self) -> Mpk {
        self.memory_protection_keys
    }
    /// The pooled per-memory cap in bytes.
    pub fn pooling_max_memory_size(&self) -> u64 {
        self.pooling_max_memory_size
    }
    /// Pool size (core instances = memories = tables).
    pub fn pool_slots(&self) -> u32 {
        self.pooling_total_core_instances
    }

    /// Whether wasmtime can enable MPK on this host (`Mpk::Yes` engines fail to build where it cannot; wasmtime 50
    /// enables MPK on Linux x86_64 Intel CPUs with the PKU CPUID bit only, so AMD hosts report false).
    pub fn host_supports_mpk() -> bool {
        PoolingAllocationConfig::are_memory_protection_keys_available()
    }

    /// Builds the `wasmtime::Config` from these settings without building an Engine (for `config --json --mpk` on
    /// a host without MPK, where the Engine itself cannot be built).
    pub fn check_config(&self) -> Result<(), EngineError> {
        self.wasmtime_config().map(drop)
    }

    /// Applies every field to a fresh `wasmtime::Config`. This is the only place a Config is made.
    fn wasmtime_config(&self) -> Result<Config, EngineError> {
        let max_mem =
            usize::try_from(self.pooling_max_memory_size).map_err(|_| EngineError::Build("max_memory_size".into()))?;
        let mut pool = PoolingAllocationConfig::new();
        pool.total_core_instances(self.pooling_total_core_instances);
        pool.total_memories(self.pooling_total_memories);
        pool.total_tables(self.pooling_total_tables);
        pool.max_memory_size(max_mem);
        pool.memory_protection_keys(self.memory_protection_keys.enabled());

        let mut c = Config::new();
        c.strategy(Strategy::Cranelift);
        c.allocation_strategy(InstanceAllocationStrategy::Pooling(pool));
        c.memory_reservation(self.memory_reservation);
        c.memory_guard_size(self.memory_guard_size);
        c.guard_before_linear_memory(self.guard_before_linear_memory);
        c.signals_based_traps(self.signals_based_traps);
        c.wasm_memory64(self.wasm_memory64);
        c.wasm_gc(self.wasm_gc);
        // wasm_threads / wasm_component_model: wasmtime is built without the `threads` and `component-model`
        // features (Cargo.toml pin, gate wasmtime-config tree check), so neither setter exists and both are off.
        c.epoch_interruption(self.epoch_interruption);
        c.consume_fuel(self.consume_fuel);
        Ok(c)
    }

    /// The effective configuration as one JSON object, keys = wasmtime 50 setter names (pooling_* =
    /// PoolingAllocationConfig), in a fixed order. Compared verbatim by `ci/wasmtime-config.py check`.
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\"allocation_strategy\":\"pooling\",",
                "\"memory_reservation\":{},",
                "\"memory_guard_size\":{},",
                "\"guard_before_linear_memory\":{},",
                "\"signals_based_traps\":{},",
                "\"pooling_total_core_instances\":{},",
                "\"pooling_total_memories\":{},",
                "\"pooling_total_tables\":{},",
                "\"pooling_max_memory_size\":{},",
                "\"memory_protection_keys\":\"{}\",",
                "\"wasm_memory64\":{},",
                "\"wasm_gc\":{},",
                "\"wasm_threads\":{},",
                "\"wasm_component_model\":{},",
                "\"epoch_interruption\":{},",
                "\"consume_fuel\":{}}}"
            ),
            self.memory_reservation,
            self.memory_guard_size,
            self.guard_before_linear_memory,
            self.signals_based_traps,
            self.pooling_total_core_instances,
            self.pooling_total_memories,
            self.pooling_total_tables,
            self.pooling_max_memory_size,
            self.memory_protection_keys.as_str(),
            self.wasm_memory64,
            self.wasm_gc,
            self.wasm_threads,
            self.wasm_component_model,
            self.epoch_interruption,
            self.consume_fuel,
        )
    }
}

/// Engine construction failed (bad settings, or MPK requested on a host without it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineError {
    /// wasmtime refused the configuration.
    Build(String),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Build(m) => write!(f, "wasmtime engine: {m}"),
        }
    }
}

impl std::error::Error for EngineError {}

/// The process-wide engine together with the settings it was built from.
#[derive(Clone)]
pub struct P2Engine {
    engine: Engine,
    settings: EngineSettings,
}

impl fmt::Debug for P2Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("P2Engine").field("settings", &self.settings).finish_non_exhaustive()
    }
}

impl P2Engine {
    /// Builds the engine from `settings` (and keeps `settings` for [`P2Engine::settings`]).
    pub fn new(settings: EngineSettings) -> Result<Self, EngineError> {
        let config = settings.wasmtime_config()?;
        let engine = Engine::new(&config).map_err(|e| EngineError::Build(format!("{e:#}")))?;
        Ok(Self { engine, settings })
    }

    /// The settings this engine was built from (the `config --json` source).
    pub fn settings(&self) -> &EngineSettings {
        &self.settings
    }

    /// The wasmtime engine.
    pub fn wasmtime(&self) -> &Engine {
        &self.engine
    }
}

/// Whether instantiation failed only because the pool, or with MPK the Store's stripe, had no free slot.
pub fn is_pool_full(e: &wasmtime::Error) -> bool {
    e.downcast_ref::<wasmtime::PoolConcurrencyLimitError>().is_some()
}

/// How many further Stores one request may try when its Store's pool stripe is full. With MPK (F8 `p2.mpk`, D11)
/// wasmtime splits the pool into one stripe per protection key and assigns each new Store the next stripe
/// round-robin; a stripe holds only `pool_slots / stripes` instances (64 slots over 16 keys: 4 per stripe on the
/// laptop, i9-14900HX), so a cordon with more than 4 requests in flight saw "maximum concurrent limit of 4 for
/// memory stripe N reached" on healthy requests (P5-iso-003, isolation-fi MPK cell). One retry per pool slot visits
/// every stripe. Without MPK there is one stripe: a full pool stays full, so no retry.
pub fn pool_retry_limit(engine: &P2Engine) -> u32 {
    if engine.settings.memory_protection_keys == Mpk::Yes { engine.settings.pool_slots() } else { 0 }
}

/// Epoch deadline, in [`EPOCH_TICK`] ticks, for a wall bound of `wall_ms`. The deadline fires once the epoch has
/// advanced this many ticks past the arming point. It is set a tenth under `wall_ms` (at least one tick under,
/// minimum 1 tick) so that the arming phase within a tick plus the ticker's wake-up latency still lands the trap
/// within `wall_ms`.
pub fn epoch_deadline_ticks(wall_ms: u64) -> u64 {
    let tick_ms = u64::try_from(EPOCH_TICK.as_millis()).unwrap_or(1).max(1);
    let ticks = wall_ms / tick_ms;
    ticks.saturating_sub((ticks / 10).max(1)).max(1)
}

/// Background thread that advances the engine epoch by wall-clock time (cordon path, R-ISO-3). Each wake-up brings
/// the epoch to the number of whole ticks elapsed since start, so oversleeping never accumulates into a late
/// deadline. Stopped and joined on drop. The fork+Wasm child uses ITIMER_REAL instead (aegis-iso, D6).
pub struct EpochTicker {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl fmt::Debug for EpochTicker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EpochTicker").field("running", &self.thread.is_some()).finish()
    }
}

impl EpochTicker {
    /// Starts the ticker for `engine`.
    pub fn start(engine: &P2Engine) -> std::io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let eng = engine.engine.clone();
        let thread = std::thread::Builder::new().name("aegis-epoch".into()).spawn(move || {
            let start = Instant::now();
            let tick_ns = EPOCH_TICK.as_nanos().max(1);
            let mut done: u128 = 0;
            while !flag.load(Ordering::Relaxed) {
                std::thread::sleep(EPOCH_TICK);
                let due = start.elapsed().as_nanos() / tick_ns;
                while done < due {
                    eng.increment_epoch();
                    done = done.saturating_add(1);
                }
            }
        })?;
        Ok(Self { stop, thread: Some(thread) })
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
