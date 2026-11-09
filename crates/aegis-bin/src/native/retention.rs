//! IDEMP-R in the assembly (F8 `state.idempotency_retention_s`, SPEC_INVARIANTS §F; PREFLIGHT R12; P8-bin-002).
//!
//! aegis-bin keeps idempotency outcomes in band, in each backend's `aegis_idem` table (PLAN D14), not in an
//! aegis-state `State`; so `State::set_retention` / `State::purge_expired` have no store to act on here, and this
//! module applies the same rule to the in-band rows:
//! * a row carries `committed_at`, the wall-clock second of its commit point, written in the scope's own transaction
//!   with the outcome ([`super::scope::HostSql::write_idem`]);
//! * with a retention `R` set, a row with `now - committed_at >= R` is forgotten: the lookup answers "no outcome" and
//!   the request runs as new ([`expired`]). The new outcome replaces the expired row in the same transaction. Within
//!   the window INV-IDEMP is unchanged (a replay returns the stored outcome);
//! * a row from the future (the clock went back) is kept, and a row without a stamp (written before Phase 8) never
//!   expires: the aegis-state rule;
//! * expired rows are deleted once at boot and then every [`period`] by a purge thread ([`super::spawn_purge`]).
//!
//! Absent (the default) = never expire, today's behaviour: the `aegis_idem` shape, its DDL and every lookup are the
//! pre-Phase-8 ones unless the table already has the stamp column.
//!
//! Engines: SQLite only. aegis-bin owns the SQLite `aegis_idem` (it creates it), so it adds the nullable stamp column
//! when a retention is set. The PG, CockroachDB and MariaDB tables are operator-provisioned in an exact shape with
//! no stamp column and no DELETE grant, and under FORCE RLS a cross-tenant purge has no role to run as; a retention
//! set with one of those backends is refused at boot (fail closed, [`refuse_unstamped`]) rather than silently kept
//! forever. That narrowing is the R12 residual row in SECURITY_CLAIMS.md.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The stamp column added to the SQLite `aegis_idem` when a retention is set.
pub const STAMP_COLUMN: &str = "committed_at";

/// Wall-clock seconds since the Unix epoch (0 if the clock is before it).
pub fn now_s() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// IDEMP-R: is a row committed at `committed_at` forgotten at `now` under `retention`? Never without a retention,
/// never without a stamp, never for a stamp from the future.
pub fn expired(committed_at: Option<u64>, now: u64, retention: Option<u64>) -> bool {
    match (retention, committed_at) {
        (Some(r), Some(t)) => now >= t && now - t >= r,
        _ => false,
    }
}

/// The newest stamp that is expired at `now` (rows with `committed_at <= cutoff` are forgotten); `None`: nothing can
/// be expired yet.
pub fn cutoff(now: u64, retention: u64) -> Option<u64> {
    now.checked_sub(retention)
}

/// How often the purge thread runs: a quarter of the window, between 15 s and 1 h.
pub fn period(retention: u64) -> Duration {
    Duration::from_secs((retention / 4).clamp(15, 3600))
}

/// Boot refusal for a backend whose `aegis_idem` cannot carry the stamp (see the module docs).
pub fn refuse_unstamped(engine: &str) -> String {
    format!(
        "state.idempotency_retention_s is set, but the {engine} aegis_idem is operator-provisioned without a \
         {STAMP_COLUMN} column or a purge role, so its keys would never expire; aegis-bin applies the retention on \
         SQLite backends only (fail closed; SECURITY_CLAIMS R12). Remove the state block or the backend."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_aegis_state_rule() {
        assert!(!expired(Some(0), 10_000, None), "absent: never");
        assert!(!expired(None, 10_000, Some(60)), "unstamped: never");
        assert!(!expired(Some(100), 159, Some(60)), "inside the window");
        assert!(expired(Some(100), 160, Some(60)), "at the window");
        assert!(!expired(Some(200), 100, Some(60)), "from the future: kept");
        assert_eq!(cutoff(160, 60), Some(100));
        assert_eq!(cutoff(10, 60), None);
        assert_eq!(period(60), Duration::from_secs(15));
        assert_eq!(period(2_592_000), Duration::from_secs(3600));
    }
}
