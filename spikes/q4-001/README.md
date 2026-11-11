# q4-001: B2 streaming / SSE / WebSocket / detached jobs without a leaky `'static`

**Verdict: keep.** The B2 scoped adapter does not need a leaky `'static` hatch. Two designs keep every
request-scoped capability inside the request: D1 borrows the stream and lets the host drive it; D2 is a host-owned
stream capability. The proposed F7 extension takes D2's shape, because it is the only design that covers all four
features and also rejects the two semantic mutants D1 lets through. The naive `tokio::spawn` idiom (D3) does need a
leak, and with that leak it accepts 17/20 mutants.
Exact proposed API: `verdict.json` → `decision_effect`.

## Method
- `f7x/src/surface.rs` mirrors the frozen F7 `sdk/monban-sdk/src/surface.rs`: the same `Granted<'r,C>`, `Ctx<'r>`,
  `TenantDb<'r>`, `Tx<'r,S>` and `ScopedHandler`, the same `PhantomData<&'r ()>` covariance, no `Clone`, and no
  public constructor. Mirror deviations are marked `MIRROR-DEVIATION`: `Ctx::grant`, an `Endowment` holding the
  live policy and revocation state, a concrete `Rows` (bound `Db<'r>`), and a `Tx` write buffer.
- Three candidate extensions:
  - **D1 borrowing** (`f7x/src/d1.rs`): `fn stream<'r, D: Db<'r>>(&'r self, Ctx<'r>, &'r D, Sink<'r, _>) -> impl
    Future + Send + 'r`, with `WsSession<'r>` for WebSockets. The host runs the handler inside one connection future
    that creates and owns the scope. That future is `'static` without any capability being `'static`.
    D1 has no way to express a detached job.
  - **D2 host-owned stream capability** (`f7x/src/d2.rs`): `open` (request-scoped) returns a `'static` generator or
    session value. For each step or message the host re-derives the principal, re-checks the session and mints a
    fresh `Ctx<'m>` and db view (`'m` is higher-ranked). `Ctx::detach(&Tx<'r, Committed>, J: Job + 'static)`
    enqueues a job, and the host later runs it with a fresh `Ctx<'j>`. All of this is sync and core/alloc only.
  - **D3 naive spawn** (`f7x/src/d3.rs`): the handler `tokio::spawn`s a producer. That needs `'static` owned
    `OwnedCtx`/`OwnedGranted`/`OwnedDb` (Arc-backed), which is the leaky hatch. The `d3strict_*` cases show the
    same idiom against F7 types does not compile.
- `f7x/src/host.rs` is a mock host. Every driver returns a `Send + 'static` future that owns its scope. The tests
  run these futures through `tokio::spawn` on a current-thread runtime.
- `corpus/src/lib.rs` holds the baseline handlers: (a) body, (b) SSE, (c) WS, (d) detached, for each design.
  `corpus/tests/runtime.rs` is the runtime oracle. `gen_mutants.py` writes `corpus/mutants/*.rs`; each file is one
  baseline with one smuggling edit. Every case is a standalone crate with `#![forbid(unsafe_code)]` and has tokio
  available (worst case). `corpus/tests/mutants.rs` is the trybuild corpus. `expected.txt` holds the locked
  measurement, and a `.stderr` snapshot sits next to each rejected case.

## Mutant table (rustc 1.99.1; R = compile-rejected, A = compiles, n/a = no such construct in the design)

| id | smuggling attempt | D1 borrow | D2 host-owned | D3 leaky-static |
|---|---|---|---|---|
| E1 | `Granted` moved into `tokio::spawn` | R (lifetime) | R E0521 | A |
| E2 | whole `Ctx` moved into spawn | R (lifetime) | R E0521 | A |
| E3 | SSE producer task: db + grant moved into spawn | R (lifetime) | R E0521 | A |
| E4 | `ctx.clone()`, clone moved into spawn | R E0599 (no Clone) | R E0599 | A |
| E5 | `Granted` stored in `static OnceLock` | R (lifetime) | R E0521 | A |
| E6 | `Ctx` stashed in `thread_local! RefCell` | R (lifetime) | R E0521 | A |
| E7 | `Granted` sent over typed channel to static consumer | R (lifetime) | R E0521 | A |
| E8 | `Ctx` sent as `Box<dyn Any + Send>` | R (lifetime) | R (lifetime) | A |
| E9 | `Arc<Granted>` clone moved into spawn | R (lifetime) | R E0521 | A |
| E10 | `Box::leak(Granted)` then spawn | R (lifetime) | R (lifetime) | A |
| E11 | detached job keeps the request's `Granted` | n/a | R (lifetime, `Job: 'static`) | A |
| E12 | detached job keeps the request's db handle | n/a | R E0277 (`D` !Send/!Sync; masks lifetime) | A |
| E12b | detached job keeps `&'r Principal` (Sync, so only the lifetime can stop it) | n/a | R (lifetime) | A |
| E13 | job enqueued before commit (effect before commit) | n/a | R E0308 (needs `&Tx<Committed>`) | A |
| E14 | WS reuses the first grant for every later message | **A** | R (lifetime, generator `'static`) | A |
| E15 | `Tx<Open>` held across streamed chunks (writes after response head) | **A** | R (lifetime) | A |
| E16 | `Tx` used after commit | R E0382 | R E0382 | R E0382 |
| E17 | forged `Granted` struct literal | R E0451 | R E0451 | R E0423 |
| E18 | `unsafe` transmute to `'static` | R (forbid lint) | R (forbid lint) | R (forbid lint) |
| E19 | WS outbound half moved into a spawned pusher | R (lifetime) | n/a (no outbound handle) | A |
| C1 | CONTROL: `std::thread::scope` borrowing a grant | A | A | A |
| C2 | CONTROL: plain data moved into spawn | A | A | A |
| S1–S4 | naive spawn (body/SSE/WS/job) against F7 types | – | – | D3-strict: R 4/4 (3x E0521, 1x not-Send) |

Totals:
- `'static` escapes (E1–E12, E12b, E19): D1 rejects 11/11 applicable, D2 13/13, D3 0/14.
- All mutants: D1 14/16, D2 19/19, D3 3/20.
- E18 is caught only by the lint tier. Controls compile 6/6.

## Raw results
- `results/measure.raw.log`: trybuild measurement with every case declared compile_fail. Lines saying "Expected
  test case to fail to compile, but it succeeded" are the accepted cases.
- `results/verify.log`: cold lock-mode run, 65/65 cases match `expected.txt`, runtime 7/7, trybuild phase 12.2 s.
  The 20 min wall time is time spent waiting for the machine-wide heavy lock. Peak `target/` was 508 MB (deleted).
- `results/runtime.log`, `results/corpus.json` (case index), `results/lock-age.txt` (all 30 crates are ≥11 days
  old; tokio pinned to 1.53.3 because 1.54.1 is 4 days old).
- Runtime oracle, `corpus/tests/runtime.rs`:
  - One capability revoked mid-WS: D1 baseline gives `[a, err:Denied, err:Denied]`; D1 with the E14 pattern gives
    `[a, a, a]` (stale grant still usable); D2 gives `[a, err:Denied, err:Denied]`, and D2 cannot hold a grant by
    construction.
  - Session revoked mid-stream: D1 and D2 both fail closed after 1 message.
  - Detached job after the session is revoked: D2 `run_jobs` gives `Denied` and nothing is written; D3 with the
    E11 pattern lands the write.
  - Tenant binding holds in all three designs.

## Reproduce
```
cd spikes/q4-001
python3 -I gen_mutants.py                       # regenerate cases (expected.txt = locked outcome)
/home/patrickd/aegis/ci/heavy.sh ./verify.sh    # cold build + runtime oracle + trybuild (lock mode)
/home/patrickd/aegis/ci/heavy.sh ./measure.sh   # re-measure (all compile_fail, TRYBUILD=overwrite)
rm -rf target
```

## Honest limits
- This is a mirror, not the real `monban-sdk`. The host has to sit in the same crate to mint grants. The real
  `Rows` is associated, not concrete, and the proposed text uses `TenantDb<'m>`.
- No axum and no sockets: WS and SSE are message lists, and backpressure is a yield. Only one rustc (1.99.1).
  Clippy tier not run.
- The mutants were written by the same author as the designs; the counts are not a general rejection rate.
- In D2, E12 and d3strict_S1 are rejected by Send/Sync before the lifetime check fires. E12b isolates the lifetime
  check.
- D2 costs, not measured:
  - Handlers become explicit state machines: no async/await, no long-held DB cursor.
  - A high-rate SSE stream re-queries on every step.
  - `Step::Idle` needs a host change-feed or timer wake-up, which is not built.
- D1's E14/E15 are not escapes. They are freshness and atomicity gaps: grants live as long as the session, and a
  transaction can be held open across the response. A host could re-check inside `TenantDb::run`, but that would
  weaken "Granted is proof".
- The ARCHITECTURE §3.12 residual {M15, M16, N9, N14} belongs to the 32-mutant non-streaming corpus. Here N14's
  analogue (E18, unsafe) is again lint-only. N9 (`mem::forget`) was not re-tested.
- The flip condition ("leaky `'static` needed") did not occur. The recommended extension is still host-driven
  (D2), which is the shape the plan's flip branch named. B2 itself stands.
