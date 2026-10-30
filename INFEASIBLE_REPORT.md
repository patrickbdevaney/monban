# INFEASIBLE_REPORT: P4-spec-002 (spec author / integrator), 2026-10-30, base 1941930

The unit cannot be finished inside its `write_scope` under the binding decisions (PLAN.md "Decisions") without editing
a frozen file outside the scope or weakening a check. There are two independent blockers. Per CLAUDE.md I stopped:
nothing except this report was changed. Fixing either blocker needs an integrator or operator decision, set out below.

## Blocker 1: D2(b) cannot be built without amending frozen F7 (`sdk/aegis-sdk/src/surface.rs`)

- **Spec clauses.** PLAN.md D2(b): "the host driving loop lives in aegis-sdk and minting stays `pub(crate)`".
  Unit spec_ref F7: "Ctx/Granted/Tx have private fields and no constructor". Unit write_scope: `sdk/aegis-sdk/src/{lib,host}.rs`,
  but not `surface.rs`. CLAUDE.md: changing a frozen file needs a re-freeze (`ci/interfaces.py freeze`, which writes
  `interfaces/MANIFEST.sha256`) in the same commit. `interfaces/` is owned by the parallel unit P4-spec-001.
- **Failing case 1 (minting).** Rust field privacy is per module. `Ctx`, `Granted` and `Tx` are defined in module
  `surface` with private fields, so only `surface` and its child modules can construct them. A child module would have
  to be declared inside `surface.rs`. `host.rs` is a sibling module and cannot mint any of the three. I checked the
  only workaround that leaves `surface.rs` untouched, which is to wrap the frozen text with
  `mod surface { include!("surface.rs"); mod host; }`. rustc rejects it: `error[E0753]: expected outer doc comment`,
  because the frozen file starts with an inner `//!` doc comment (tested with rustc 1.99.1 through ci/heavy.sh).
  Safe code has no other way to construct a struct with private fields, and `unsafe` is forbidden.
- **Failing case 2 (grant acquisition), also in frozen text.** F7 gives a handler no way to *obtain* a
  `Granted<'r, DataCap<K>>`. `ScopedHandler::handle(ctx, db)` receives none, `Ctx` exposes only `principal()` and
  `route()`, and `TenantDb` has no grant method. The q4-001 spike hit the same gap: its mirror needed
  `MIRROR-DEVIATION: Ctx::grant` plus an endowment link in `Ctx` (spikes/q4-001/f7x/src/surface.rs:48-109), and its
  README says "The host has to sit in the same crate to mint grants". F7b's `JobQueue<'r>` has the same problem: no
  handler signature receives one.
- **Minimal reason.** Any host, whether D2(a) or D2(b), needs (i) `pub(crate)` constructors inside `surface.rs` and
  (ii) one public grant path on `Ctx`. Both are F7 changes that need a re-freeze. They are not possible from
  `host.rs`/`lib.rs` alone.
- **Proposed resolution (integrator).** Add `sdk/aegis-sdk/src/surface.rs`, `sdk/aegis-sdk/src/streaming.rs` (only if
  the JobQueue path is fixed) and the F7/F7b lines of `interfaces/MANIFEST.sha256` to P4-spec-002's write scope.
  Sequence it after P4-spec-001's re-freeze, or let one unit do both re-freezes, so the two units do not race on the
  manifest. P4-oracle-trybuild-001 must then freeze its corpus against the amended F7. The proposed amendment is
  additive except for one new public method:

  ```rust
  // surface.rs (F7 re-freeze; reason: D2(b) host seam)
  pub struct Ctx<'r> { principal: &'r Principal, route: RouteId, grants: &'r dyn Grants }
  pub(crate) trait Grants { fn permits(&self, op_code: u8) -> bool; }       // implemented only in host.rs
  impl<'r> Ctx<'r> {
      pub(crate) fn mint(principal: &'r Principal, route: RouteId, grants: &'r dyn Grants) -> Self;
      /// Host-checked grant for data capability K, tied to 'r; Denied unless the route endowment and live session permit K.
      pub fn grant<const K: u8>(&self) -> Result<Granted<'r, DataCap<K>>, SdkError>;
  }
  impl<'r, C> Granted<'r, C> { pub(crate) fn mint() -> Self; }
  impl<'r, S> Tx<'r, S>      { pub(crate) fn mint() -> Self; }
  ```

  Proposed host seam once that lands (`sdk/aegis-sdk/src/host.rs`, behind cargo feature `host`; core/alloc only, no
  IO and no tokio; only `aegis-adapter-host` may enable the feature or name `aegis_sdk::host`, enforced by xtask):

  ```rust
  pub trait Backend {                        // the only effect seam; implemented by aegis-adapter-host
      type Rows;
      fn begin(&self) -> Result<(), SdkError>;
      fn run(&self, op: Op) -> Result<Self::Rows, SdkError>;   // SDK has already checked op_code(op.kind) == K
      fn commit(&self) -> Result<(), SdkError>;
      fn rollback(&self);                     // an Open Tx not committed when the drive returns
  }
  pub trait Session {                         // route endowment + live revocation state
      fn permits(&self, op_code: u8) -> bool;
      fn live(&self) -> bool;
  }
  pub struct Request<'r, B: Backend, S: Session> { pub principal: &'r Principal, pub route: RouteId, pub backend: &'r B, pub session: &'r S }
  pub fn drive<H: ScopedHandler, B: Backend, S: Session>(h: &H, req: Request<'_, B, S>) -> Result<H::Response, SdkError>;
  pub fn open_body<H: BodyHandler, B: Backend, S: Session>(h: &H, req: Request<'_, B, S>) -> Result<H::Gen, SdkError>;
  pub fn open_sse<H: SseHandler, B: Backend, S: Session>(h: &H, req: Request<'_, B, S>, last_event_id: Option<u64>) -> Result<H::Gen, SdkError>;
  pub fn open_ws<H: WsHandler, B: Backend, S: Session>(h: &H, req: Request<'_, B, S>) -> Result<H::Session, SdkError>;
  /// Fresh Ctx and db view per call; returns Err(Unavailable) without calling the generator if !session.live().
  pub fn step<G: StreamGen, B: Backend, S: Session>(g: &mut G, req: Request<'_, B, S>) -> Result<Step<G::Item>, SdkError>;
  pub fn on_ws_message<W: WsSession, B: Backend, S: Session>(w: &mut W, req: Request<'_, B, S>, msg: &WsMsg) -> Result<WsReply, SdkError>;
  pub fn run_job<J: Job, B: Backend, S: Session>(j: J, req: Request<'_, B, S>) -> Result<(), SdkError>;  // Denied if !live
  ```

  Inside the SDK, a private `HostDb<'r, B>` implements `TenantDb<'r>` (`Rows = B::Rows`, at most one open Tx per
  drive) by delegating to `Backend`. Minting stays `pub(crate)` in `surface.rs`.

## Blocker 2: `rusqlite =0.40.2` (bundled) cannot be vet-covered with zero exemptions

- **Spec clauses.** CLAUDE.md and the unit brief require every new dependency to be "vet-covered with zero
  exemptions". The unit note asks for "rusqlite =0.40.2 bundled (SQLite 3.53.2, the crash-harness pin)", and the
  golden floor is SQLite ≥ 3.51.3 (oracles/crash-harness/README.md:127).
- **Failing case.** The resolved graph is rusqlite 0.40.2, libsqlite3-sys 0.38.2, fallible-iterator 0.3.0,
  fallible-streaming-iterator 0.1.9, bitflags 2.13.2 and smallvec. bitflags and smallvec are already locked. I
  checked the current audits.toml of all six configured imports (fetched 2026-10-30, UA `aegis-ci`):
  - rusqlite: safe-to-deploy chain ends at **0.37.0** (mozilla 0.33→0.37, zcash 0.36→0.37). 0.37→0.40.2 is unaudited.
  - libsqlite3-sys: chain ends at **0.35.0** (mozilla 0.31→0.35). 0.35→0.38.2 is unaudited.
  - fallible-iterator 0.3.0 and fallible-streaming-iterator 0.1.9 are covered.
  - The newest fully import-covered pair (rusqlite 0.37.0 / libsqlite3-sys 0.35.0) bundles **SQLite 3.50.2**,
    which is below the 3.51.3 floor. libsqlite3-sys 0.36.0 bundles 3.51.1 and 0.37.0 bundles 3.51.3; neither is
    covered. I read these versions from each crate's `sqlite3/sqlite3.h`.
- **Minimal reason.** Zero-exemption coverage would need first-party delta audits in supply-chain/audits.toml for
  rusqlite 0.37.0→0.40.2 and libsqlite3-sys 0.35.0→0.38.2. The second includes the SQLite amalgamation diff
  3.50.2→3.53.2 (sqlite3.c is 269,376 lines at 0.38.2). An honest audit of that is not possible in this unit, and a
  rubber-stamp audit entry would itself weaken the vet check. supply-chain/POLICY.md §1 does allow intake exemptions
  (baseline entries in the dependency's intake commit), but that contradicts the explicit "zero exemptions" rule for
  this unit.
- **Operator options.** (a) Allow the POLICY.md §1 intake route for exactly `rusqlite:0.40.2` and
  `libsqlite3-sys:0.38.2`, each with a one-line reason, plus a ledger note that the bundled SQLite is trusted,
  unverified C (as D3 already states). (b) Commission real delta audits. (c) Wait until an import covers ≥0.40.2 /
  ≥0.38.2. Choosing (a) needs an explicit operator statement, because it overrides the CLAUDE.md wording.

## Facts measured for the re-run (no repository files changed)

- **Budget.** aegis-bin has 41 third-party crates today (`cargo tree --locked -e normal,no-proc-macro -p aegis-bin`).
  rusqlite bundled adds 4 (rusqlite, libsqlite3-sys, fallible-iterator, fallible-streaming-iterator), giving
  **45/60**. This is projected from resolution, not from a release build. aws-lc-rs and rustix for the PG/Redis
  adapters are already in the lock.
- **X-10 counts avoided** (fresh resolution 2026-10-30, `-e normal,no-proc-macro`):
  - tokio-postgres 0.7.18: 52 crates in total, 42 of them not already in aegis-bin. These include md-5, sha2, hmac,
    rand and getrandom: a second, non-aws-lc crypto stack (RustCrypto).
  - redis 0.32.7 with tokio-comp: 45 in total, 33 new (url/idna/icu4x, num-bigint, combine).
  - Together they would add roughly 60 or more crates (exact overlap not computed), against a budget of 41/60.
- **Q5 (partial).** The normal-edge graph of rusqlite 0.40.2 bundled contains no aws-lc, ring or openssl node. Its
  build dependencies (cc, pkg-config) are not crypto. The unchanged cmvp lock graph (`cargo xtask fips-lock`) was not
  checked, because no lock change was made.
- **Everything else in the unit is feasible but was not started, per "stop":** the xtask layering changes (app
  layer, SDK owner check plus a self-test mutant, INTRA_LAYER), ci/no-crate.sh with its fixture, and DEVIATIONS X-10
  and X-11.
