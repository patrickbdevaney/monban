//! `cargo xtask allowlist-lock [--check|--self-test]`: the allowlist lock must regenerate byte-identically
//! (gate allowlist-lock, R-DB-3/4). Fail-closed stub from P4-spec-002: the body (regenerate with
//! `aegis_data_ir::lock_body` + `sha256` trailer and compare; self-test on a mutated lock) is P4-datair-001's.
//! Until then both modes report FAIL, so the gate cannot pass without the real check.

pub fn allowlist_lock(self_test: bool) -> Result<(), String> {
    let mode = if self_test { "ALLOWLIST-LOCK SELF-TEST" } else { "ALLOWLIST-LOCK" };
    Err(format!("{mode}: FAIL (not implemented: fail-closed stub, body owned by P4-datair-001)"))
}
