//! Oracle negative controls of the F14 worker (PLAN-5 D15; oracles/hostile-modules README "Self-test").
//!
//! A `mutants` build reads `AEGIS_P2_MUTANT` once per process. Only the five worker mutant names below are
//! recognised; any other value (for example a supervisor mutant inherited through the environment) leaves the
//! worker golden, as the oracle requires. A build without the `mutants` feature never reads the variable:
//! [`active`] is the constant `None`, so every mutant branch is dead code that the compiler removes.
#![forbid(unsafe_code)]

/// The worker-level negative controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutant {
    /// `extra-import`: the static check and the Linker accept `env.host_fault` in a build without `test-hooks`.
    ExtraImport,
    /// `handle-not-cleared`: the handle table and its generation are carried into the next request of the
    /// session (a cordon connection), so a handle issued to request n still resolves in request n+1.
    HandleNotCleared,
    /// `no-hostcall-quota`: `max_host_calls` is not enforced.
    NoHostcallQuota,
    /// `no-fuel-no-epoch`: no fuel limit and no epoch deadline (the worker binary also skips `ITIMER_REAL`).
    NoFuelNoEpoch,
    /// `no-limiter`: the ResourceLimiter allows every memory and table growth (the worker binary also sizes the
    /// pooled slot at the F8 maximum, so that the per-request limiter is the only memory bound left to remove).
    NoLimiter,
}

impl Mutant {
    /// Every worker mutant.
    pub const ALL: [Self; 5] =
        [Self::ExtraImport, Self::HandleNotCleared, Self::NoHostcallQuota, Self::NoFuelNoEpoch, Self::NoLimiter];

    /// The `AEGIS_P2_MUTANT` value that selects this mutant.
    pub fn name(self) -> &'static str {
        match self {
            Self::ExtraImport => "extra-import",
            Self::HandleNotCleared => "handle-not-cleared",
            Self::NoHostcallQuota => "no-hostcall-quota",
            Self::NoFuelNoEpoch => "no-fuel-no-epoch",
            Self::NoLimiter => "no-limiter",
        }
    }

    /// The mutant an `AEGIS_P2_MUTANT` value selects, if it names a worker mutant.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.name() == s)
    }
}

/// The selected mutant (`mutants` builds only; read once per process).
#[cfg(feature = "mutants")]
pub fn active() -> Option<Mutant> {
    static SELECTED: std::sync::OnceLock<Option<Mutant>> = std::sync::OnceLock::new();
    *SELECTED.get_or_init(|| std::env::var("AEGIS_P2_MUTANT").ok().and_then(|v| Mutant::parse(v.trim())))
}

/// Golden builds: never a mutant.
#[cfg(not(feature = "mutants"))]
#[inline(always)]
pub fn active() -> Option<Mutant> {
    None
}

/// Whether `m` is the selected mutant.
#[inline]
pub fn is(m: Mutant) -> bool {
    active() == Some(m)
}
