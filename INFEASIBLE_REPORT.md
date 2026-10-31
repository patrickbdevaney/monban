# INFEASIBLE_REPORT: P5-bin-002, one acceptance criterion only

Scope: only the size clause of `units/phase-5/P5-bin-002.json` `acceptance.must` is infeasible for this unit.
Everything else in the unit is implemented, and every oracle and gate it names is green (see the unit JSON
`status`).

- **Spec clause.** `acceptance.must`: "the native,p2 build stays within the X-12 native ceiling (8.0 MB)".
  `xtask/src/budget.rs` `MAX_NATIVE_STRIPPED_BYTES = 8_000_000`. DEVIATIONS X-12 sets that ceiling for the
  `--features native` build.
- **Failing measurement.** Stripped `aegis` (release profile, `strip = "symbols"`; the `strip` tool confirms the
  same size), `-p aegis-bin --features aegis-bin/p2,aegis-bin/native`, laptop, 2026-10-31:
  - baseline main 54ed56d (P5-bin-001, before this unit): **8,045,624 B**, already 45,624 B over the ceiling;
  - with P5-bin-002: **8,068,472 B**, so this unit adds 22,848 B: the F10 op decoder, the data_run pipeline and
    audit event, and the SQLite/PG store pairing.
  - For comparison, the builds the budget gate does judge are green: `cargo xtask budget` gives BUDGET: PASS, with
    native 7,958,680 B (<= 8,000,000), default 5,364,952 B and p2-worker 9,720,328 B.
- **Minimal reason.** The combination was over the ceiling before this unit started. Getting under it would mean
  removing about 68.5 KB from aegis-bin code that this unit does not own the behaviour of. The largest aegis-bin
  symbols are `native::boot` (59 KB, the P4 PG/SQLite schema gates) and the agent and upstream pipelines. The
  other way is to change the ceiling. The release profile and the ceiling are integrator files (Cargo.toml,
  xtask), and moving a limit is not an implementer resolution (CLAUDE.md). No gate measures the native,p2
  combination today: `budget` judges default, native, the p2 worker and the third-party crate counts of p2 and
  native,p2.
- **Needs.** An integrator decision: either a ceiling for the native,p2 build (a new X-12 row), or a ruling that
  the native ceiling applies to `--features native` only, as `cargo xtask budget` measures it.
