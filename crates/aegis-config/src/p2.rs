//! F8 `p2` block (Phase 5, P5-spec-001) and the `{"wasm": <module-id>}` route target.
//!
//! What the types make unrepresentable:
//! * **A cordon shared by principals** (PLAN D1). The cordon key is always the principal and is not configurable:
//!   no field of [`P2Block`], [`P2Module`], [`CrashBudget`] or any other F8 block names, shares or merges a
//!   cordon. The parser accepts exactly the F8 member sets (`additionalProperties: false`), so a document that
//!   tries (`"cordon_key"`, `"shared"`, `"cordon": "x"`, ...) is an `UnknownField` load error.
//! * **An unbounded P2 limit** (INV-NONEMPTY). Every limit has a schema minimum, maximum and default
//!   ([`P2Limits::BOUNDS`], [`CrashBudget::BOUNDS`]); per-module overrides carry the same bounds and are resolved
//!   at load, so [`P2Module`] holds the effective value, never an `Option`.
//! * **A wasm route without a module.** `{"wasm": id}` must name a declared `p2.modules[]` entry; with no `p2`
//!   block the load fails (`UnknownModule`).
//!
//! D1 default path, as amended by D23 option (b) (operator, 2026-10-31): `p2.isolation` is [`IsolationSetting`],
//! default `auto`. [`resolve_isolation`] turns it into the effective [`Isolation`] from the usable CPU count
//! (fewer than [`AUTO_CORDON_BELOW_CPUS`] → cordon, else forkwasm); explicit `forkwasm` / `cordon` are used as
//! written. [`P2Block::isolation_for`] applies that to multi-principal modules; single-tenant modules always run
//! in a per-principal cordon. The CPU count is read by the assembly (aegis-bin) at boot and at every reload; this
//! crate stays pure, and the effective config hash covers the configured value only, so it is host-independent. D6: `fuel` is accounting,
//! `wall_ms` is the DoS bound. D7: [`CrashBudget`] defaults 3 faults / 60 s → 429 for 600 s, minimums 1 so a gate
//! can scale the window down. D11: `mpk` defaults to false.

use crate::Config;

/// Most modules in the `p2` block (F8 `p2.modules` maxItems).
pub const MAX_P2_MODULES: usize = 256;

/// The effective path a multi-principal module runs on (PLAN D1), after [`resolve_isolation`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Isolation {
    /// Fork child of an exec-spawned single-threaded zygote; fresh instance per request.
    ForkWasm,
    /// One exec-spawned cordon per principal; fresh instance per request.
    Cordon,
}

impl Isolation {
    pub fn as_str(self) -> &'static str {
        match self {
            Isolation::ForkWasm => "forkwasm",
            Isolation::Cordon => "cordon",
        }
    }
}

/// F8 `p2.isolation` as configured (PLAN D1, D23 option b): `auto` (default), `forkwasm` or `cordon`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum IsolationSetting {
    /// Resolved from the usable CPU count at boot and at every reload ([`resolve_isolation`]).
    #[default]
    Auto,
    /// Always forkwasm.
    ForkWasm,
    /// Always cordon.
    Cordon,
}

impl IsolationSetting {
    pub(crate) const ALL: [(&'static str, IsolationSetting); 3] = [
        ("auto", IsolationSetting::Auto),
        ("forkwasm", IsolationSetting::ForkWasm),
        ("cordon", IsolationSetting::Cordon),
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            IsolationSetting::Auto => "auto",
            IsolationSetting::ForkWasm => "forkwasm",
            IsolationSetting::Cordon => "cordon",
        }
    }
}

/// D23 option (b): `auto` picks cordon on hosts with fewer usable CPUs than this, forkwasm otherwise. kamrui
/// (Intel N95, 4 cores) measured forkwasm oom recovery p99 at 6.7-7.1 ms against the 5 ms gate while cordon held
/// 1.6 ms; the 32-thread laptop (the reference) passes forkwasm. Nothing between was measured, so 8 is a
/// conservative split that puts typical VPS sizes (1-4 vCPU) on cordon (PLAN-5 D23).
pub const AUTO_CORDON_BELOW_CPUS: usize = 8;

/// The effective path for multi-principal modules (pure; D23 option b). `usable_cpus` is the size of the process's
/// CPU affinity set (so a taskset- or cpuset-pinned process counts only its CPUs); 0 (unknown) counts as small.
pub fn resolve_isolation(setting: IsolationSetting, usable_cpus: usize) -> Isolation {
    match setting {
        IsolationSetting::ForkWasm => Isolation::ForkWasm,
        IsolationSetting::Cordon => Isolation::Cordon,
        IsolationSetting::Auto if usable_cpus < AUTO_CORDON_BELOW_CPUS => Isolation::Cordon,
        IsolationSetting::Auto => Isolation::ForkWasm,
    }
}

/// F8 `p2_module.tenancy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum Tenancy {
    /// Runs on `p2.isolation`, resolved (default `auto`).
    #[default]
    Multi,
    /// Always runs in a per-principal cordon (D1).
    Single,
}

impl Tenancy {
    pub(crate) const ALL: [(&'static str, Tenancy); 2] = [("multi", Tenancy::Multi), ("single", Tenancy::Single)];
    pub fn as_str(self) -> &'static str {
        match self {
            Tenancy::Multi => "multi",
            Tenancy::Single => "single",
        }
    }
}

macro_rules! bounded {
    ($(#[$doc:meta])* $name:ident { $( $field:ident : $min:expr, $max:expr, $default:expr; )* }) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $name {
            $( pub $field: u64, )*
        }

        impl $name {
            /// (field, minimum, maximum, default), in F8 schema order.
            pub const BOUNDS: &'static [(&'static str, u64, u64, u64)] = &[
                $( (stringify!($field), $min, $max, $default), )*
            ];

            /// Values in `BOUNDS` order.
            pub fn values(&self) -> Vec<u64> {
                vec![$( self.$field, )*]
            }

            pub(crate) fn set(&mut self, name: &str, v: u64) {
                match name {
                    $( stringify!($field) => self.$field = v, )*
                    _ => {}
                }
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self { $( $field: $default, )* }
            }
        }
    };
}

bounded! {
    /// The bounded integer members of the `p2` block, defaults applied (F8 schema order).
    P2Limits {
        fuel: 10_000, 1_000_000_000, 15_000_000;
        wall_ms: 1, 1000, 100;
        memory_mib: 1, 256, 16;
        max_host_calls: 1, 1_000_000, 10_000;
        max_data_runs: 0, 1024, 64;
        max_data_bytes: 0, 67_108_864, 4_194_304;
        max_resp_bytes: 0, 16_777_216, 1_048_576;
        max_log_bytes: 0, 1_048_576, 65_536;
        frame_max_bytes: 4096, 1_048_576, 65_536;
        cordon_slots: 1, 1024, 64;
        max_cordons: 1, 4096, 64;
        cordon_idle_s: 1, 86_400, 300;
    }
}

bounded! {
    /// F8 `p2.crash_budget` (D7): `crashes` crash-attributable faults within `window_s` → 429 for `penalty_s`.
    CrashBudget {
        crashes: 1, 100, 3;
        window_s: 1, 3600, 60;
        penalty_s: 1, 86_400, 600;
    }
}

impl P2Limits {
    /// Bounds of the per-module overrides (`p2_module.fuel` / `wall_ms` / `memory_mib`): the same as the block's.
    pub const FUEL_BOUNDS: (u64, u64) = (10_000, 1_000_000_000);
    pub const WALL_MS_BOUNDS: (u64, u64) = (1, 1000);
    pub const MEMORY_MIB_BOUNDS: (u64, u64) = (1, 256);
}

/// One P2 core Wasm module (F8 `p2_module`), with the per-module limits resolved (override, else the block's).
/// Constructible only by the parser.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct P2Module {
    pub(crate) id: String,
    pub(crate) path: String,
    pub(crate) sha256: [u8; 32],
    pub(crate) tenancy: Tenancy,
    pub(crate) fuel: u64,
    pub(crate) wall_ms: u64,
    pub(crate) memory_mib: u64,
}

impl P2Module {
    /// The F8 `p2_module` member set, schema order (`additionalProperties: false`).
    pub const MEMBERS: &'static [&'static str] = &["id", "path", "sha256", "tenancy", "fuel", "wall_ms", "memory_mib"];

    /// `^[a-z][a-z0-9-]{0,31}$`, unique within the block.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Absolute path of the `.wasm`.
    pub fn path(&self) -> &str {
        &self.path
    }
    /// Expected SHA-256 of the `.wasm` file; a mismatch at boot or reload refuses the module.
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
    /// Lowercase hex of [`P2Module::sha256`] (the F8 text form).
    pub fn sha256_hex(&self) -> String {
        crate::hex(&self.sha256)
    }
    pub fn tenancy(&self) -> Tenancy {
        self.tenancy
    }
    /// Effective per-request fuel (override, else `p2.fuel`).
    pub fn fuel(&self) -> u64 {
        self.fuel
    }
    /// Effective per-request wall bound in ms (override, else `p2.wall_ms`).
    pub fn wall_ms(&self) -> u64 {
        self.wall_ms
    }
    /// Effective linear-memory cap in MiB (override, else `p2.memory_mib`).
    pub fn memory_mib(&self) -> u64 {
        self.memory_mib
    }
}

/// The F8 `p2` block, defaults applied. Constructible only by the parser. There is deliberately no field that
/// keys, names or shares a cordon: the cordon key is the principal (D1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct P2Block {
    pub(crate) worker: String,
    pub(crate) cache_dir: Option<String>,
    pub(crate) isolation: IsolationSetting,
    pub(crate) limits: P2Limits,
    pub(crate) crash_budget: CrashBudget,
    pub(crate) mpk: bool,
    /// 1..=256, unique ids, document order.
    pub(crate) modules: Vec<P2Module>,
}

impl P2Block {
    /// The F8 `p2` member set, schema order (`additionalProperties: false`). None of them names a cordon.
    pub const MEMBERS: &'static [&'static str] = &[
        "worker",
        "cache_dir",
        "isolation",
        "fuel",
        "wall_ms",
        "memory_mib",
        "max_host_calls",
        "max_data_runs",
        "max_data_bytes",
        "max_resp_bytes",
        "max_log_bytes",
        "frame_max_bytes",
        "cordon_slots",
        "max_cordons",
        "cordon_idle_s",
        "crash_budget",
        "mpk",
        "modules",
    ];

    /// Absolute path of the aegis-p2 worker binary.
    pub fn worker(&self) -> &str {
        &self.worker
    }
    /// `None` when absent (the assembly uses `$RUNTIME_DIRECTORY/p2`).
    pub fn cache_dir(&self) -> Option<&str> {
        self.cache_dir.as_deref()
    }
    /// The configured default path for multi-principal modules, as written (default `auto`).
    pub fn isolation(&self) -> IsolationSetting {
        self.isolation
    }
    /// The effective path for multi-principal modules on a host with `usable_cpus` usable CPUs (D23 option b).
    pub fn effective_isolation(&self, usable_cpus: usize) -> Isolation {
        resolve_isolation(self.isolation, usable_cpus)
    }
    pub fn limits(&self) -> &P2Limits {
        &self.limits
    }
    pub fn crash_budget(&self) -> &CrashBudget {
        &self.crash_budget
    }
    /// Wasmtime memory protection keys as a density option (default false, D11).
    pub fn mpk(&self) -> bool {
        self.mpk
    }
    pub fn modules(&self) -> &[P2Module] {
        &self.modules
    }
    pub fn module(&self, id: &str) -> Option<&P2Module> {
        self.modules.iter().find(|m| m.id == id)
    }
    /// The path a module runs on (D1): single-tenant → cordon (per principal); multi → `p2.isolation` resolved for
    /// `usable_cpus` ([`P2Block::effective_isolation`]).
    pub fn isolation_for(&self, m: &P2Module, usable_cpus: usize) -> Isolation {
        match m.tenancy {
            Tenancy::Single => Isolation::Cordon,
            Tenancy::Multi => self.effective_isolation(usable_cpus),
        }
    }
}

impl Config {
    /// The `p2` block; `None` when absent (then no wasm route can be configured).
    pub fn p2(&self) -> Option<&P2Block> {
        self.p2.as_ref()
    }
}
