# sdk-trybuild: compile-fail corpus against the real monban-sdk (gate sdk-trybuild)

Unit P4-oracle-trybuild-001 (spec author). This gate checks the B2 handler SDK (`sdk/monban-sdk`, frozen F7 + F7b,
re-frozen by P4-spec-002 with `Ctx::grant`, the `host` feature and `TenantDb: JobQueue`). It checks that the
capability discipline holds at compile time. Covers INV-NO-AMBIENT, INV-NOMUT-C and ARCHITECTURE §3.12
("B2 25/32 ... residual {M15, M16} after the lint tier"), under decision D5 of `units/phase-4/PLAN.md`.

```
ci/heavy.sh oracles/sdk-trybuild/run              # gate
ci/heavy.sh oracles/sdk-trybuild/run --self-test  # must show the gate red on every mutated SDK
oracles/sdk-trybuild/run --bless                  # re-measure snapshots.txt (review the diff; rustc bump only)
```
`run` deletes `target/` afterwards unless `KEEP_TARGET=1` is set. The gate is `remote = true`; it runs on the LAN box
through ci/remote.sh.

## What runs

1. `cargo build -p monban-sdk --features host --locked` (main workspace and lock, `--offline` first). The corpus is
   compiled against the `host` build. That is the worst case: an out-of-tree app could enable the feature too.
2. `cargo test --doc -p monban-sdk --locked`, in its own target dir: P4-spec-002's privacy compile_fail checks are doc
   tests, and the `tests` gate (`--all-targets`) skips doc tests. Then the same compile_fail blocks are replicated
   with rustc, so the self-test can apply them to mutated SDK copies. The replication must agree on the real SDK
   (7/7).
3. Every case (`corpus.py`) is compiled by the pinned rustc (metadata only), with externs `monban_sdk`,
   `monban_types`, `monban_data_ir` and `monban_authz`. A real app may depend on monban-sdk alone (`cargo xtask
   layering`), so the corpus is more permissive than a real app, and every catch here is conservative.
   - If rustc accepts a case, clippy-driver runs next with the workspace lints (`forbid(unsafe_code)`, the deny
     list) and the ban list in `clippy.toml`.
   - If clippy accepts it too, an owner scan flags any naming of `monban_sdk::host`. That is the in-oracle
     equivalent of `cargo xtask layering`, which only scans workspace crates.
4. Compiled B2 cases and the baseline go into one harness binary. It drives the handlers through the SDK's own
   host loop (`monban_sdk::host::drive`) over a recording backend, and checks what reaches the backend: the
   tenant, writes under a read endowment, the owner conjunct on delete, the archived filter on list, a forged
   owner on insert, and a transaction left open.
   - The harness needs `Principal` minting, which only the authn path has. So monban-types (feature
     `authn-path`), monban-data-ir and monban-sdk are recompiled by rustc against the cargo-built third-party rlibs.
     One cargo target dir cannot hold both feature sets, because cargo reuses the artifact file names.
5. Verdict against `expected.txt` (frozen) and `snapshots.txt`. Categories:
   - **caught**: rustc or the lint tier rejects the case.
   - **neutralized**: the case compiles lint-clean, and the harness shows no violation reaches the backend.
   - **residual**: the case compiles lint-clean, and the harness sees a violation or has no check for it.

   Each rejection must include one of the case's intended codes (`must`). It must also equal its snapshot exactly
   (stage + code set), the way trybuild compares `.stderr` files.

trybuild itself is not used. It is in no workspace lock (only in the spike-local `spikes/q4-001/Cargo.lock`).
Adding it to an oracle-local lock would mean a new third-party dependency, fetched while crates.io is
rate-limiting. Driving rustc and clippy-driver directly gives the same compile-fail and snapshot semantics with zero
dependencies. The rustc pin (`expected.txt`, 1.99.1 = rust-toolchain.toml) is checked first, because snapshots are
rustc-specific.

## Result (rustc 1.99.1, desktop via ci/remote.sh, 2026-10-30)

`SDK-TRYBUILD: PASS (B2 caught 28/32 (rustc type 15, dependency/API absent 10, lint 3), neutralized M6,M8, residual M15,M16; F7b 19/19; controls 7/7; doc tests ok)`

`SDK-TRYBUILD SELF-TEST: PASS (6/6 SDK mutants turn the gate red)`

Per id (stage and codes in `snapshots.txt`):

| id | port to F7 | outcome |
|---|---|---|
| M1 | unscoped `db.query(..)` | absent E0599: no unscoped/raw query exists |
| M2 | `Principal::default()` | type E0599 |
| M3 | app-built cache in `static Mutex` | lint: disallowed_types |
| M4 | research `Resp::html(format!(..))` | absent E0433: F7 has no HTML/response builder (see probe M4s) |
| M5 | `detach(&tx_open, ..)` | type E0308 (needs `Tx<Committed>`) |
| M6 | `ctx.grant::<INSERT>()` in the list handler | **neutralized**: `Ctx::grant` denies under the read endowment; nothing reaches the backend |
| M7 | `Principal { .. }` literal | type E0451 |
| M8 | `op.tenant = TenantId::new(path)` | **neutralized**: the SDK host overwrites `Op::tenant` |
| M9 | SQL string + `db.query` | absent E0599: no raw-SQL surface |
| M10 | grant line removed | type E0425: `run` needs the `Granted` proof |
| M11 | `Ctx` pushed into `static Mutex<Vec<Ctx<'static>>>` | type E0277+E0521 |
| M12 | `std::net::TcpStream::connect(param)` | lint: disallowed_methods (no egress capability in F7) |
| M13 | `ctx.token()` into a log | absent E0599: the token never reaches the app |
| M14 | `run(&mut tx)` after `commit(tx)` | type E0382 |
| M15, M16 | owner conjunct / archived filter dropped | **residual** (harness: `owner`, `archived`), goes to Cedar + oracle tests |
| N1, N1b, N3, N12, N13, N15 | handle, `Ctx`, leaked `Ctx` or `Tx` into `std::thread::spawn` / `Box<dyn Any + Send>` | type E0277 (`dyn Grants`/`D` not Send/Sync; masks the lifetime) |
| N2, N4 | `Ctx` in `static OnceLock` / `Arc<Mutex<Vec<Ctx<'static>>>>` handler | type E0277+E0521 / E0521 |
| N5, N6, N7, N8 | axum middleware / axum route / tokio timeout / tokio select | absent E0433 (D5: dependency absence) |
| N9 | `std::mem::forget(tx)` | lint: disallowed_methods (at run time the host also rolls back a scope left open) |
| N10 | std guard held across `.await` | absent E0433+E0728 (sync F7, no tokio) |
| N11 | write handler on an axum GET route | absent E0433: no app-side route registration; verb/endowment is F8 config (runtime: as M6) |
| N14 | `transmute::<&D, &'static D>` then spawn | type E0277: rejected before the `forbid(unsafe_code)` tier is reached |
| E1–E17, E12b (F7b) | q4-001 D2 mutants, `tokio::spawn` → `std::thread::spawn`, `ctx.detach` → `db.detach` | type: E0521 / LT / E0277 / E0599 (no Clone) / E0308 / E0382 / E0451 |
| E18 (F7b) | `transmute` `Granted<'r>` → `'static` (Granted is Send) | lint only: unsafe_code + disallowed_methods |
| H1 (probe) | app calls `monban_sdk::host::drive` | compiles; caught only by the owner scan |
| M4s (probe) | markup returned as a `String` Response | **compiles** (frozen as residual): escaping is a host obligation |

### Decision D5 bookkeeping
- Residual frozen at {M15, M16} in `expected.txt` before the first run (commit f2b22df). Measured {M15, M16}.
- N5–N8 and N10 count as caught by dependency absence. N11 counts the same way: the research form is a route
  registration, and F7 apps have none.
- M1, M4, M9 and M13 also count as absence catches: the research construct (unscoped query, HTML builder, raw
  SQL, token access) has no F7 analogue. They are labelled `absent`, not `type`.
- Not counting any absence catch: 18/32. Counting only D5's N5–N8/N10: 23/32 (below 25). The 25/32 threshold
  therefore depends on the M1/M4/M9/M13/N11 absence catches.
- N9 is caught by the ban list. N14 is caught by rustc's Send check. No INFEASIBLE_REPORT was needed.
- M6 and M8 compile in F7 (B2 in research rejected them by type). F7 has no static read/write handler split, and
  `Op::tenant` is a public field. The host defeats both at run time, and the harness proves this on every run.
  They are frozen as `neutralized`, outside both the caught count and the residual.

### Self-test (mutated SDK copies, rustc-built; each must turn the verdict red)
| SDK mutant | detected by |
|---|---|
| `Ctx: Clone` | E4 snapshot (E0599 → E0277) |
| `Granted` fields `pub` | E17 compiles; doc compile_fail E0451 compiles |
| `detach(&Tx<'r, S>)` (no `Committed`) | M5 and E13 compile |
| `Ctx` constructible (`pub fn mint`, `pub trait Grants`) | doc compile_fail E0624 → E0277; E0603 block compiles |
| host does not overwrite `Op::tenant` | M8 moves neutralized → residual (harness `tenant`) |
| `Ctx::grant` ignores the session | M6/M8 → residual, BASE `write-on-read` |

## Provenance (untrusted input, re-expressed, never executed)
- `research/state/raw/round-004/05-work/mutants.py`, sha256 e51ad969893b48e7be35aba67a83c1cdb33cb42b3c154b39323403c7016cdbef
  (32 ids, shape b2nd; research results: 28/32 compile-rejected, accepted M3 neutralized, M15, M16, N9 lint).
- `research/state/raw/round-004/05-work/app_b2/clippy.toml`, sha256 6a7efceeb1d2fd96ed05aa988edf01334e2f9eaa0bd7ab0d5aa6d9da20b81975.
- `spikes/q4-001/gen_mutants.py`, sha256 29cf0b82aace98d730abdc80917dbbac078d7bf00b4dd6bad7a3ee896cc260c6 (D2: 19/19).

## Known limits
- **The ban list is enforced here, not on `apps/*`.** No `clippy.toml` or app-scoped lint config exists in the
  workspace. M3, M12 and N9 are caught only because this oracle applies `clippy.toml`. The integrator should apply
  the same list to `apps/*`; that is outside this unit's write scope.
- **F7 apps cannot construct an `Op`.** Layering allows app → monban-sdk only, and monban-sdk does not re-export
  `monban_data_ir::{Op, OpKind, Pred, Value}` (the P4-spec-002 doc test uses monban_data_ir directly). The corpus
  gets monban_data_ir and monban_types as externs. Re-exporting or adding Op builders is an SDK (spec-author) change.
- F7 gives a handler no request input. The corpus models parsed input as data on the handler value (`Raw`), with
  no token field.
- Absence catches prove that the surface is missing, not that the property holds. In particular, M4's XSS
  obligation moves to the host's Response serialization, and the M4s probe shows a markup String compiles. This
  belongs to P4-host-001 / native-e2e.
- The neutralized verdicts rest on the SDK's own host loop over a recording backend, not on monban-adapter-host.
- The mutants are self-built, as in the research and the spike. The counts are not a general rejection rate.
- Only one rustc (1.99.1). A toolchain bump needs `--bless` and a review of the snapshot diff.
