# cancel-sweep: oracle for INV-NOMUT-C (cancellation)

Gates `spec/SPEC_INVARIANTS.md` §B **INV-NOMUT-C**:
- **NC1**: termination before the commit point ⇒ Failed, and no durable user rows changed.
- **NC2**: from the commit point on, the request is latched; a timer after CP yields 202.
- **NC3**: discard-on-cancel. Check a connection back in only if ReadyForQuery ∧ txn `I` ∧ no outstanding replies ∧
  all server objects closed.
- **NC5**: a cancelled authz stage ⇒ Deny.

It also checks **NC4** (debit before work; cancels are charged; no refunds) and **CRS C5** (epoch revocation: an
upstream connection is never used at an epoch other than the one it was created at), plus C2 (scope: a connection is
never reused for a different principal).

Research only *specified* this harness (round-003/06, node `ac.l5-cancel-sweep-harness`, evidence B). This oracle
implements the spec as a deterministic reference model in `python3 -I`, plus checkers that see **only events**, so
the Rust implementation plugs in with `--subject` without the oracle changing.

## Usage

```
oracles/cancel-sweep/run                    # 200 seeds x every await point x 5 modes (PR-gate size)
oracles/cancel-sweep/run --seeds 20000      # nightly size
oracles/cancel-sweep/run --self-test        # 7 mutations; the plan's two named ones must go red within 100 seeds
oracles/cancel-sweep/run --subject '<cmd>'  # external subject speaking the event protocol below
oracles/cancel-sweep/run --subject 'python3 -I oracles/cancel-sweep/cancelsweep.py --as-subject'   # protocol self-check
```

`run` executes under `ci/heavy.sh`. The last line is `CANCEL-SWEEP: PASS|FAIL (...)` (or
`CANCEL-SWEEP SELF-TEST: PASS|FAIL (...)`), and the exit code is 0 only on PASS.

## The sweep

Each seed generates a scenario with two principals and these requests:
- `W0`: alice warm-up; it puts an upstream connection in the pool.
- `R0`: alice target. It has 1–2 authz stages, an optional session-level prepared statement (PARSE before BEGIN, then
  a non-DB await, CLOSE after commit: the tokio-postgres #1374 window where the txn is `I` and no reply is outstanding
  but a server object is open), BEGIN, an idempotency lease, 2–5 random steps (read, write, a
  prepared statement PARSE/BIND/EXEC/CLOSE, a savepoint block, an upstream call), the outcome record, and COMMIT.
- An optional auth/config **epoch bump** (always on even seeds, w.p. ½ otherwise).
- `F1`–`F3`: bob follow-ups on the **size-1 DB pool** (O2: "the next 3 requests from a different principal").
- `F4`: alice after the bump (C5).

The oracle runs `R0` uncancelled and counts its await points K. Every simulated I/O returns Pending once before
Ready ("interleave pending"), so K = number of I/O awaits. It then re-runs the whole scenario with
`CancelAt<N>` on `R0` for every N in 0..K−1 and every mode:

| mode | meaning (research m-number) | host behaviour required |
|---|---|---|
| drop | future dropped (m1) | pre-CP: Failed, no response; post-CP: latched, commit completes |
| rst | client h2 RST_STREAM (m3) | same as drop |
| timeout | request timeout (m5) | pre-CP: 408; post-CP: **202** + idempotency retrieval |
| stage_timeout | timeout of the awaited stage only | authz stage ⇒ Error ⇒ **Deny** (403); other stages = timeout |
| crash | kill -9 at that await (m8) | durable state all-or-nothing; pools gone |

Coverage: every await site seen in an uncancelled run must be cancelled at least once, otherwise FAIL.

The **reference model** consists of:
- a pgwire-level DB fake: the server executes a message on arrival and queues its reply; it has txn status I/T/E,
  autocommit outside a txn, named statements/portals/savepoints, and a close that rolls back;
- the client-side state a driver can see: last txn status, outstanding replies, created objects armed at *send* time
  (CR6 drop-guard shape);
- the host: size-1 DB pool with the NC3 `reusable(c)` predicate; an upstream pool keyed by the whole config
  (authority, principal, auth ctx, **epoch**); limiter debit before work; authz tri-state; an idempotency row and its
  outcome record inside the txn; a commit-point latch.

Handlers use the send-before-yield shape that creates the real-world hazard (sqlx #4393, redis-py CVE-2023-28858,
tokio-postgres #1374).

## Checks (from events only)

| clause | check |
|---|---|
| NC1 | no `cp` ⇒ the durable user-row delta (`u:*`, `idem:*`) is empty, outcome Failed, no 2xx |
| NC2 | `cp` ⇒ delta == exactly the request's writes + idempotency row `done`, outcome Committed, status ∈ {200, 202}, and 202 when a timer fired after CP. On crash: all or nothing |
| NC3 / O2 hygiene | every `checkin` has server truth txn `I`, 0 queued replies, no open objects (no "idle in transaction", no leaked statements) |
| O2 functional | bob's follow-ups read exactly bob's committed rows, commit, and change exactly their own rows (no stale reply, no inherited txn) |
| NC5 | a cancelled authz stage records `deny`, does no work after it, sends no 2xx; no work without an Allow for every stage |
| NC4 | first debit precedes any work; a cancel before CP is charged; no zero/negative debit |
| C5 / C2 | a reused upstream connection was created at the current epoch and for the same principal |

## Self-test (mutations of the reference model; each must turn its clause red)

| mutation | clause | budget |
|---|---|---|
| `always-reusable`: checkin predicate "always reusable" (plan) | O2 / NC3 | ≤100 seeds |
| `pool-key-no-epoch`: epoch removed from the upstream pool key (plan) | C5 | ≤100 seeds |
| `checkin-ignores-txn` (sqlx #4393 shape) | O2 / NC1 / NC3 | ≤100 seeds |
| `checkin-ignores-objects` (tokio-postgres #1374 shape) | NC3 | ≤100 seeds |
| `no-cp-latch`: commit inside the cancellable future | NC2 | ≤100 seeds |
| `authz-fail-open`: timed-out stage skipped | NC5 | ≤100 seeds |
| `debit-after-work`: post-hoc debit | NC4 | ≤100 seeds |

`--self-test --subject '<cmd>'` runs the same plan against the subject, appending `--mutate <name>` to its command
line. A subject that supports self-test must implement these mutations behind that flag.

## Subject event protocol (for the Rust implementation under the DST shell)

The subject is one long-lived process with JSON lines on stdin/stdout. The oracle sends:

```
{"op":"hello"}                                   -> {"ev":"hello","impl":"...","modes":[...]}
{"op":"run","seed":S,"world":{row:val},"requests":[REQ...],"bumps_before":[idx],"target":idx,
 "cancel_at":N|null,"mode":"drop|rst|timeout|stage_timeout|crash"|null}
                                                 -> EVENT lines ..., then {"ev":"end"}
{"op":"quit"}
REQ = {"id","principal","role","idem_key","cost","authority","authz":[stage...],"pre_prepare":bool,
       "steps":[["read",[keys]] | ["write",key,val] | ["prepared",name,key,val] | ["savepoint",name,key,val] | ["upstream"]]}
```

For a `run`, the subject seeds the harness DB fake with `world`, executes the requests in order, applies an epoch bump
before each index in `bumps_before`, and wraps the target request's handler future in `CancelAt<cancel_at>` with the
given mode. Events (field `req` = request id):

```
durable        {at:"start"|"after:<id>", rows}   harness DB snapshot (from the pgwire fake, not the subject's view)
await          {n, site[, detached]}             each Pending of the top-level handler future (site = shim call site)
cancel         {n, site, mode}                   CancelAt fired
debit          {principal, cost, reason:"admission"|"cancel"}
authz          {stage, decision:"allow"|"deny"|"error", cancelled}
conn_acquire   {conn, reused}     wire {conn, msg}     reply {conn, msg}     result {rows}
cp             {}                                COMMIT handed to the wire
latched        {}                                cancellation arrived after CP; the rest runs in a must-complete task
checkin        {conn, truth:{txn, queued, objects}}   truth = server-side state from the fake
discard        {conn}
upstream_connect {conn}   upstream_acquire {conn, reused}   upstream_release {conn}   upstream_close {conn}
epoch_bump     {epoch}                           (no req)
outcome        {outcome:"Committed"|"Failed"|"Pending"}
response       {status}
crash          {}
```

`durable` and `checkin.truth` come from the harness's DB fake. That fake is trusted harness code, not part of the unit
under test. Everything else is emitted by the host instrumentation. The reference model is exposed over the same
protocol (`--as-subject`), and running it through `--subject` must give the same verdict as the in-process run.

## Provenance (untrusted research input: read, never executed)

| file (research/state/raw/) | sha256 |
|---|---|
| round-003/06-bridge-async-cancellation-failure-atomicity.json | dc2f6aa4b7617190a34ea26b57c6ab74fbe0966dc3ea0167607f35ffa8ed6856 |
| round-003/06-bridge-async-cancellation-failure-atomicity.progress.md | ea4bfbd83ac8b83c2fa8bf24e08427744380a24d1d2d2852f40d6afd8b4275cf |

Ported from nodes `ac.l5-cancel-sweep-harness` (enumeration, modes, oracles O1–O8, self-test), `ac.l5-inv-nomut-c`
(NC1–NC8 definitions, reusable(c)) and `ac.principle-cancel-equals-crash`. Research ran no experiment here (machine
safety §0e), so there are no research numbers to compare against.

## Re-run in repo (2026-10-25, laptop)

- `./run`: `CANCEL-SWEEP: PASS (NC1 NC2 NC3 NC4 NC5 O2 C5 over 17245 runs, 3409 await points, 200 seeds x 5 modes)`
  in 3.3 s; 17 await sites, all cancelled at least once.
- `./run --subject 'python3 -I .../cancelsweep.py --as-subject'`: the same verdict and counts over the protocol (25 s).
- `./run --self-test` (in-process and over `--subject`): `CANCEL-SWEEP SELF-TEST: PASS (7/7 mutations caught; ...)`.
  - always-reusable: O2 red at seed 1 (bob's follow-up read alice's stale reply).
  - pool-key-no-epoch: C5 red at seed 2.
  - checkin-ignores-txn: seed 3 (bob's commit carried alice's partial writes).
  - checkin-ignores-objects: seed 1.
  - no-cp-latch, authz-fail-open, debit-after-work: seed 1.
- During the port, `checkin-ignores-objects` was first MISSED: every leaked object sat inside an open txn, so the
  txn-status check always fired first. The session-level `pre_prepare` window was added so that this mutation is
  distinguishable.

## Known limits

- This is a reference **model**, not the Rust code: a PASS says the specified host discipline satisfies NC1–NC5 over
  the swept await points, and that the checkers can go red. Real-code coverage comes only from `--subject` with the
  Rust host under DST (CancelAt + interleave-pending shim, ~150 LOC per research).
- Modes m2 (JoinHandle::abort), m4 (h1 FIN), m6 (graceful-shutdown deadline) and m7 (Wasm epoch trap) collapse onto
  drop/rst/timeout in the model. O5 (outbox), O6 (liveness/futurelock, NC8), O7 (Wasm Store discard) and O8 (retry
  with the same key) are not modelled. NC6/NC7/NC8 are not checked.
- The named regression corpus (sqlx #4393, diesel_async #304, tokio-postgres #1374, redis-py #2624, Go CVE-2025-47907,
  Wasmtime CVE-2026-27195 / RUSTSEC-2026-0354, omicron #3140, futurelock #9259) needs the real drivers. Three shapes
  appear here as mutations only (`checkin-ignores-txn`, `checkin-ignores-objects`, and the redis-py stale-reply shape
  via `always-reusable`).
- One request is cancelled per scenario; concurrent requests and pool contention (size > 1) are not modelled.
