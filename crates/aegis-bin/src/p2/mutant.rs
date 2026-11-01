//! Supervisor negative controls of oracles/p2-e2e and oracles/hostile-modules `--level host` (PLAN-5 D15; feature
//! `p2-mutants` only).
//!
//! A `p2-mutants` build reads `AEGIS_P2_MUTANT` once per process. The variable is also passed through to the
//! workers (aegis-iso supervisor), which ignore every name that is not one of their own. A build without
//! `p2-mutants` never reads it: [`active`] is the constant `None`, so every mutant branch is dead code.
//!
//! `dumpable-1` is a worker mutant (the sandbox skips `PR_SET_DUMPABLE(0)`); the supervisor has nothing to break
//! for it and only recognises the name so the banner names it.
#![forbid(unsafe_code)]

/// The supervisor-level negative controls (oracles/p2-e2e README "Negative controls"). In a golden build only
/// the unit tests name them.
#[cfg_attr(not(feature = "p2-mutants"), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutant {
    /// `shared-cordon`: the cordon key is constant, so every principal lands in one cordon.
    SharedCordon,
    /// `fork-respawn`: a replacement worker keeps the template's layout instead of a fresh ASLR layout. aegis-bin
    /// cannot fork (forbid(unsafe_code)); the observable effect of a fork-from-template (the same load base before
    /// and after a respawn) is produced by starting every worker with ASLR disabled (`setarch -R`).
    ForkRespawn,
    /// `global-crash-budget`: one budget for all principals.
    GlobalCrashBudget,
    /// `no-crash-budget`: crashes are never recorded, so they never lead to 429.
    NoCrashBudget,
    /// `budget-counts-healthy`: a Deny (healthy failure) is charged as a crash.
    BudgetCountsHealthy,
    /// `dumpable-1`: worker-side (aegis-iso sandbox); nothing changes here.
    Dumpable1,
    /// `no-reload-switch`: after a reload that changes the isolation path, P2 routes fail.
    NoReloadSwitch,
    /// `boot-without-landlock-accepted`: a worker's refusal at boot (compile exit 78) is ignored and the
    /// supervisor listens anyway.
    BootWithoutLandlockAccepted,
    /// `auto-ignores-cpus`: `p2.isolation = "auto"` resolves to forkwasm whatever the usable CPU count (D23(b)
    /// says cordon below 8). Only the serving runtime is mutated; the check-config dump stays truthful, so the
    /// oracle must catch it from the process tree.
    AutoIgnoresCpus,
    // oracles/hostile-modules --level host (README "Self-test"):
    /// `raw-passthrough`: the supervisor skips its I5 re-check of `resp-head` (status range, header names and
    /// values), so a compromised worker's header bytes reach the client unchecked.
    RawPassthrough,
    /// `double-response-accepted`: a second `resp-head` replaces the first, and after `resp-end(trap)` a late
    /// `resp-head`/`resp-body`/`resp-end(0)` for the finished req-id is accepted as the answer.
    DoubleResponseAccepted,
    /// `audit-after-effect`: an authorized data_run executes before its audit event is appended.
    AuditAfterEffect,
    /// `no-audit-on-trap`: authorized data_runs are audited only when the request ends without a fault.
    NoAuditOnTrap,
    /// `trap-maps-to-allow`: a trap ends the request as Allow with whatever the module wrote.
    TrapMapsToAllow,
    /// `data-run-skips-authorize`: data_run skips the CapSet check (any route reaches the first backend).
    DataRunSkipsAuthorize,
    /// `tenant-not-overwritten`: data_run keeps the module's tenant field instead of the route-bound tenant.
    TenantNotOverwritten,
}

#[cfg_attr(not(feature = "p2-mutants"), allow(dead_code))]
impl Mutant {
    pub const ALL: [Self; 16] = [
        Self::SharedCordon,
        Self::ForkRespawn,
        Self::GlobalCrashBudget,
        Self::NoCrashBudget,
        Self::BudgetCountsHealthy,
        Self::Dumpable1,
        Self::NoReloadSwitch,
        Self::BootWithoutLandlockAccepted,
        Self::AutoIgnoresCpus,
        Self::RawPassthrough,
        Self::DoubleResponseAccepted,
        Self::AuditAfterEffect,
        Self::NoAuditOnTrap,
        Self::TrapMapsToAllow,
        Self::DataRunSkipsAuthorize,
        Self::TenantNotOverwritten,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::SharedCordon => "shared-cordon",
            Self::ForkRespawn => "fork-respawn",
            Self::GlobalCrashBudget => "global-crash-budget",
            Self::NoCrashBudget => "no-crash-budget",
            Self::BudgetCountsHealthy => "budget-counts-healthy",
            Self::Dumpable1 => "dumpable-1",
            Self::NoReloadSwitch => "no-reload-switch",
            Self::BootWithoutLandlockAccepted => "boot-without-landlock-accepted",
            Self::AutoIgnoresCpus => "auto-ignores-cpus",
            Self::RawPassthrough => "raw-passthrough",
            Self::DoubleResponseAccepted => "double-response-accepted",
            Self::AuditAfterEffect => "audit-after-effect",
            Self::NoAuditOnTrap => "no-audit-on-trap",
            Self::TrapMapsToAllow => "trap-maps-to-allow",
            Self::DataRunSkipsAuthorize => "data-run-skips-authorize",
            Self::TenantNotOverwritten => "tenant-not-overwritten",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.name() == s)
    }
}

/// The selected mutant (`p2-mutants` builds only; read once per process).
#[cfg(feature = "p2-mutants")]
pub fn active() -> Option<Mutant> {
    static SELECTED: std::sync::OnceLock<Option<Mutant>> = std::sync::OnceLock::new();
    *SELECTED.get_or_init(|| {
        let m = std::env::var("AEGIS_P2_MUTANT").ok().and_then(|v| Mutant::parse(v.trim()));
        if let Some(m) = m {
            eprintln!("aegis: P2 NEGATIVE-CONTROL BUILD, mutant active: {}", m.name());
        }
        m
    })
}

/// Golden builds: never a mutant.
#[cfg(not(feature = "p2-mutants"))]
#[inline(always)]
pub fn active() -> Option<Mutant> {
    None
}

/// Whether `m` is the selected mutant.
#[inline]
pub fn is(m: Mutant) -> bool {
    active() == Some(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip_and_golden_is_inert() {
        for m in Mutant::ALL {
            assert_eq!(Mutant::parse(m.name()), Some(m));
        }
        assert_eq!(Mutant::parse("no-limiter"), None); // a worker mutant leaves the supervisor golden
        if !cfg!(feature = "p2-mutants") {
            assert_eq!(active(), None);
        }
    }
}
