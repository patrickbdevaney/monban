# cancel-sweep: oracle for INV-NOMUT-C (cancellation)

Gates `spec/SPEC_INVARIANTS.md` §B **INV-NOMUT-C**:
- **NC1**: termination before the commit point ⇒ Failed, and no durable user rows changed.
- **NC2**: from the commit point on, the request is latched; a timer after CP yields 202.
- **NC3** (rewritten by spike q3-008, DEVIATIONS X-4; widened per BACKLOG 2026-10-25 to the frozen text "a resource
  in D(r) that a cancelled request touched, or that was left mid-protocol"): such a connection is quarantined, then
  recovered within
  T_recover = op budget (drain every outstanding reply to ReadyForQuery **without** a CancelRequest, ROLLBACK if the
  txn status is not `I`, DISCARD ALL, driver cache-generation bump), else discarded; a discard sends a CancelRequest;
  a CancelRequest is never sent on a connection that is checked back in. Checkin predicate unchanged: ReadyForQuery ∧
  txn `I` ∧ no outstanding replies ∧ all server objects closed.
- **NC5**: a cancelled authz stage ⇒ Deny.

It also checks **NC4** (debit before work; cancels are charged; no refunds; since q3-008 quarantine time and discards
are charged to the cancelling principal) and **CRS C5** (epoch revocation: an
upstream connection is never used at an epoch other than the one it was created at), plus C2 (scope: a connection is
never reused for a different principal).

Research only *specified* this harness (round-003/06, node `ac.l5-cancel-sweep-harness`, evidence B). This oracle
implements the spec as a deterministic reference model in `python3 -I`, plus checkers that see **only events**, so
the Rust implementation plugs in with `--subject` without the oracle changing.

## Usage

```
oracles/cancel-sweep/run                    # 200 seeds x every await point x 5 modes (PR-gate size)
oracles/cancel-sweep/run --seeds 20000      # nightly size
oracles/cancel-sweep/run --self-test        # 11 mutations, each must go red within 100 seeds
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
- `E1`, `E2`: alice requests whose **handler returns an error** before CP (NC1 "return/error", no cancellation). `E1`
  errors right after its session-level PARSE (txn `I`, nothing outstanding, a server object open); `E2` errors inside
  its txn (txn `T`, nothing outstanding). This exercises NC3's second disjunct ("left mid-protocol"), where the
  checkin predicate alone decides quarantine. `F5`: a bob follow-up after them. These three are appended after every
  earlier random draw, so `W0`..`F4` are unchanged per seed.

R0's session-level `SET` (w.p. 0.7) is followed by a non-DB host call (`session.ready`) before BEGIN. A cancel there
leaves a connection that passes the checkin predicate (txn `I`, no outstanding replies, no objects unless
`pre_prepare`) but carries session state: the window the NC3 widening closes.

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
- the host: size-1 DB pool with the NC3 `reusable(c)` predicate and the q3-008 quarantine/recovery path (below); an
  upstream pool keyed by the whole config
  (authority, principal, auth ctx, **epoch**); limiter debit before work; authz tri-state; an idempotency row and its
  outcome record inside the txn; a commit-point latch.

NC3 recovery in the model (`Host.release_cancelled`). When a cancelled request (before CP) still holds a DB connection,
it is **always** quarantined (widened NC3: touched by a cancelled request), whether or not `reusable(c)` holds. When a
handler returns an error before CP (`E1`/`E2`), the connection is quarantined iff `reusable(c)` fails ("left
mid-protocol"); otherwise it gets the ordinary checkin. On quarantine (`quarantine` event) the host:
  1. drains every outstanding reply (no CancelRequest);
  2. sends ROLLBACK if the reported txn status is not `I`;
  3. sends DISCARD ALL;
  4. bumps the driver cache generation (`gen_bump`).
- Each drained reply costs its statement time (`stmt_ticks` for EXEC/SELECT); ROLLBACK and DISCARD ALL cost 1 tick each.
- If the total stays within `op_budget` with no error and `reusable(c)` holds afterwards, the connection is checked in.
  Otherwise it is discarded: CancelRequest, then close.
- The cancelling principal is debited the quarantine ticks (`reason: "quarantine"`, at least 1), plus `DISCARD_COST` = 3
  on a discard (`reason: "discard"`).
- Scenario knobs: `op_budget` 2–5, `stmt_ticks` 1–3. R0 sets a session-level GUC (`SET app.principal`) before BEGIN
  w.p. 0.7 and RESETs it after COMMIT. The default run quarantines 50,816 connections: 49,052 are recovered and 1,764
  are discarded (before the widening: 10,584 / 8,820 / 1,764; the extra quarantines are protocol-clean cancelled
  connections, which recover in 1–2 ticks, plus `E1`/`E2`).
- The DB fake models a CancelRequest as **not statement-bound and delivered late**: it cancels the next message the
  backend executes (SQLSTATE 57014). This is the q3-008 race (3 of 24,997 N95 cycles hit the next request), taken as the
  worst case. Other fake details: DISCARD ALL inside a txn errors (25001), any statement in a failed txn errors (25P02),
  and COMMIT of a failed txn answers ROLLBACK. A server error fails the request (500, ordinary cleanup).

Handlers use the send-before-yield shape that creates the real-world hazard (sqlx #4393, redis-py CVE-2023-28858,
tokio-postgres #1374).

## Checks (from events only)

| clause | check |
|---|---|
| NC1 | no `cp` ⇒ the durable user-row delta (`u:*`, `idem:*`) is empty, outcome Failed, no 2xx; a handler error (`abort`) ⇒ Failed + 500 |
| NC2 | `cp` ⇒ delta == exactly the request's writes + idempotency row `done`, outcome Committed, status ∈ {200, 202}, and 202 when a timer fired after CP. On crash: all or nothing |
| NC3 / O2 hygiene | every `checkin` has server truth txn `I`, 0 queued replies, no open objects and no session state (no "idle in transaction", no leaked statements, no leaked GUCs) |
| NC3 widened | every DB connection acquired by a request that was cancelled before CP is `quarantine`d before its `checkin`, even when it passes the checkin predicate (session state is invisible to the predicate) |
| NC3 recovery (q3-008) | a quarantined connection is checked in only after a `recover` with `completed: true` and `ticks` ≤ the request's `op_budget`, a DISCARD ALL on the wire and a `gen_bump`; it is never acquired while quarantined; a connection that received a `cancel_request` is never checked in again; every `discard` is preceded by a `cancel_request` on that connection |
| O2 functional | bob's follow-ups read exactly bob's committed rows, see an empty session (`show`), commit, and change exactly their own rows (no stale reply, no inherited txn, no inherited session state, no stray cancel) |
| NC5 | a cancelled authz stage records `deny`, does no work after it, sends no 2xx; no work without an Allow for every stage |
| NC4 | first debit precedes any work; a cancel before CP is charged; no zero/negative debit; every debit is to the request's own principal; each `recover` is charged its `ticks` (`quarantine`), and a discard after quarantine is charged (`discard`) |
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
| `reuse-after-cancelrequest` (q3-008): recovery sends a CancelRequest to speed up the drain, then checks the connection in; the stray cancel hits bob's next statement | O2 / NC3 | ≤100 seeds |
| `recovery-no-discard-all` (q3-008): drain + ROLLBACK but no DISCARD ALL; alice's session GUC and open statements reach bob | O2 / NC3 | ≤100 seeds |
| `quarantine-not-charged` (q3-008): no `quarantine`/`discard` debit | NC4 | ≤100 seeds |
| `cancelled-session-no-discard` (NC3 widening, BACKLOG 2026-10-25): a cancelled connection that passes the checkin predicate gets the ordinary checkin without DISCARD ALL (the pre-widening model) | NC3 / O2 | ≤100 seeds |

Since the widening, the three checkin-predicate mutations (`always-reusable`, `checkin-ignores-txn`,
`checkin-ignores-objects`) go red first on the `E1`/`E2` handler-error path: a cancelled connection is always
recovered, so the predicate only decides quarantine on the "left mid-protocol" path. No check was removed or relaxed.

`--self-test --subject '<cmd>'` runs the same plan against the subject, appending `--mutate <name>` to its command
line. A subject that supports self-test must implement these mutations behind that flag.

## Subject event protocol (for the Rust implementation under the DST shell)

The subject is one long-lived process with JSON lines on stdin/stdout. The oracle sends:

```
{"op":"hello"}                                   -> {"ev":"hello","impl":"...","host":"async|sync","modes":[...]}
{"op":"run","seed":S,"world":{row:val},"requests":[REQ...],"bumps_before":[idx],"target":idx,
 "cancel_at":N|null,"mode":"drop|rst|timeout|stage_timeout|crash"|null}
                                                 -> EVENT lines ..., then {"ev":"end"}
{"op":"quit"}
REQ = {"id","principal","role","idem_key","cost","authority","authz":[stage...],"pre_prepare":bool,
       "session_set":bool, "op_budget":ticks, "stmt_ticks":ticks,
       "steps":[["read",[keys]] | ["write",key,val] | ["prepared",name,key,val] | ["savepoint",name,key,val] | ["upstream"]
                | ["show"]],
       "abort": "before_begin"|"in_txn"   (optional; absent = none)}
```

`abort` (added with the NC3 widening): the handler returns an application error (no cancellation) at that point:
`before_begin` = right after the `pre_prepare` statement-cache insert (before the SET and BEGIN), `in_txn` = after the
last step, before the outcome record. The host must then answer Failed/500 and apply the NC3 "left mid-protocol" rule.
`host` in `hello` is optional (default `async`); any other value than `async`/`sync` fails the run.

For a `run`, the subject seeds the harness DB fake with `world`, executes the requests in order, applies an epoch bump
before each index in `bumps_before`, and wraps the target request's handler future in `CancelAt<cancel_at>` with the
given mode. Events (field `req` = request id):

```
durable        {at:"start"|"after:<id>", rows}   harness DB snapshot (from the pgwire fake, not the subject's view)
await          {n, site[, detached]}             each cancellation point (async: Pending of the handler future; sync: host-call boundary, see below)
cancel         {n, site, mode}                   CancelAt fired
debit          {principal, cost, reason:"admission"|"cancel"|"quarantine"|"discard"}
authz          {stage, decision:"allow"|"deny"|"error", cancelled}
conn_acquire   {conn, reused}     wire {conn, msg}     reply {conn, msg[, drain]}     result {rows[, kind:"session"]}
cp             {}                                COMMIT handed to the wire
latched        {}                                cancellation arrived after CP; the rest runs in a must-complete task
checkin        {conn, truth:{txn, queued, objects, session}}   truth = server-side state from the fake
discard        {conn}
quarantine     {conn}                            NC3: connection left mid-protocol by a cancelled request
recover        {conn, ticks, completed}          end of the recovery attempt (ticks = quarantine time charged)
gen_bump       {conn, gen}                       driver-side statement/type cache invalidated
cancel_request {conn}                            CancelRequest sent for this connection's backend
upstream_connect {conn}   upstream_acquire {conn, reused}   upstream_release {conn}   upstream_close {conn}
epoch_bump     {epoch}                           (no req)
outcome        {outcome:"Committed"|"Failed"|"Pending"}
response       {status}
crash          {}
```

## Synchronous host (DEVIATIONS X-11, Decision D6 of units/phase-4/PLAN.md)

F7 handlers are synchronous (no handler futures). They run on a **bounded blocking pool**, as the PDP client does, and
the **cancellation points are host-call boundaries**, not Pendings. A subject with a synchronous host says
`"host":"sync"` in `hello` and maps the protocol as follows:

- **Cancellation points.** Every driver round trip is one cancellation point: each message of each `TenantDb::run`
  (and of every other host-owned driver call) is written to the wire first, then the host checks the cancel token
  **before reading the reply**. This keeps the send-before-yield hazard shape of the async model (a cancelled request
  can leave a reply outstanding). Every non-DB host call (limiter debit, each authz stage, pool acquire, statement-cache
  insert, `session.ready`, upstream acquire/response) is one cancellation point at its boundary. The subject emits
  `await {n, site}` at each of them, in order, with `n` counting from 0 per request. There are no other cancellation
  points: handler code between host calls cannot be interrupted.
- **Site names.** `db.<MSG>` for a driver round trip (MSG = the protocol message, e.g. `db.BEGIN`, `db.COMMIT`),
  `authz.<stage>` for an authz stage (the NC5 checker keys on the `authz.` prefix), and stable names for the other host
  calls. Every site seen in an uncancelled run must be cancellable (coverage check).
- **CancelAt<N>.** When the N-th cancellation point fires, that host call returns `Err(Cancelled)` without performing
  its effect (a round trip whose message is already on the wire leaves the connection mid-protocol). The host revokes
  the handler's capabilities at that moment: every later host call by that handler returns `Err(Cancelled)` at once,
  with no effect and no `await` event. Host-owned cleanup (NC3 quarantine/recovery/discard, upstream release/close, the
  NC4 cancel debit, Failed/408) runs at the cancellation point, on the host's side; it does not wait for the handler's
  pool thread to return. `drop` and `rst` both mean "the client is gone; the token is cancelled". `timeout` is the
  request deadline. `stage_timeout` at `authz.<stage>` = that stage evaluates to Error ⇒ Deny. `crash` = kill -9 at
  that point.
- **After CP.** From the moment COMMIT is handed to the wire, the token is ignored (NC2 latch): the commit round trip
  and the rest of the request complete on the host side. A cancellation that arrives after CP emits `latched`, and the
  remaining cancellation points are reported as `await {n: null, site, detached: true}`. A timer after CP answers 202.
- **Pool bound.** A handler that never makes a host call cannot be cancelled. It keeps its pool thread until it
  returns, and that thread counts against the pool bound (back-pressure at admission). Wall-clock limits on handler
  code are NC8 / native-e2e's job, not this oracle's.

The event set, the checks and the verdict are the same for both host kinds. The reference model is an async host
(`"host":"async"`); its generator yields are exactly the sync host's cancellation points under the mapping above, so
a sync subject that follows the mapping produces the same event shapes.

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

## Re-run in repo (2026-10-30, laptop, after the NC3 widening and the X-11 sync-host amendment)

- `./run`: `CANCEL-SWEEP: PASS (NC1 NC2 NC3(quarantine/recovery) NC4 NC5 O2 C5 over 19840 runs, 3928 await points, 200 seeds x 5 modes)`
  in 9.8 s. 20 await sites (new: `session.ready`), all cancelled at least once. 50,816 connections quarantined: 49,052
  recovered, 1,764 discarded.
- `./run --subject 'python3 -I .../cancelsweep.py --as-subject'`: the same verdict and counts over the protocol (30 s).
- `./run --self-test` (in-process and over `--subject`): `CANCEL-SWEEP SELF-TEST: PASS (11/11 mutations caught within 100 seeds each, ...)`.
  - always-reusable and checkin-ignores-txn: O2 red at seed 1 (F5 committed E2's leaked txn writes).
  - checkin-ignores-objects: NC3 red at seed 1 (E1 checked in with `stmt:cached` open).
  - recovery-no-discard-all: NC3 red at seed 1; quarantine-not-charged: NC4 red at seed 1.
  - pool-key-no-epoch (seed 2), no-cp-latch, authz-fail-open, debit-after-work, reuse-after-cancelrequest (seed 1):
    unchanged.
  - cancelled-session-no-discard: NC3 red at seed 3 (R0 cancelled at `session.ready`, checked in with
    `{'app.principal': 'alice'}`); the widened-NC3 event rule and O2 (bob's `show`) go red on the same runs.

## Re-run in repo (2026-10-25, laptop, after the q3-008 NC3 update)

- `./run`: `CANCEL-SWEEP: PASS (NC1 NC2 NC3(quarantine/recovery) NC4 NC5 O2 C5 over 19150 runs, 3790 await points, 200 seeds x 5 modes)`
  in 6.3 s. 19 await sites, all cancelled at least once. 10,584 connections quarantined: 8,820 recovered, 1,764 discarded.
- `./run --subject 'python3 -I .../cancelsweep.py --as-subject'`: the same verdict and counts over the protocol (23 s).
- `./run --self-test` (in-process and over `--subject`): `CANCEL-SWEEP SELF-TEST: PASS (10/10 mutations caught within 100 seeds each, ...)`.
  - always-reusable: O2 red at seed 1 (bob read alice's stale reply).
  - pool-key-no-epoch: C5 red at seed 2.
  - checkin-ignores-txn: O2 red at seed 2 (bob's commit carried alice's partial writes).
  - checkin-ignores-objects: NC3 red at seed 1.
  - no-cp-latch, authz-fail-open, debit-after-work: seed 1.
  - reuse-after-cancelrequest: O2 red at seed 1 (bob's F1 failed with 500 after the stray 57014). The NC3 event rule
    "checked in after a CancelRequest" and NC1 also go red.
  - recovery-no-discard-all: NC3 red at seed 2 (no DISCARD ALL before checkin). Functionally, O2 goes red at seed 3:
    bob's `show` sees `{'app.principal': 'alice'}`.
  - quarantine-not-charged: NC4 red at seed 1.
- History: during the first port, `checkin-ignores-objects` was MISSED, because every leaked object sat inside an
  open txn and the txn-status check always fired first. The session-level `pre_prepare` window was added so that this
  mutation is distinguishable.

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
- One request is cancelled per scenario; concurrent requests and pool contention (size > 1) are not modelled. Recovery
  therefore runs to completion before the next request, so "never handed to another request while quarantined" is
  checked but cannot fail in the reference model.
- "Left mid-protocol" is read as "the checkin predicate fails". Until 2026-10-30 a cancelled connection that passed
  the predicate got the ordinary checkin, so a `SET` on a protocol-clean connection was not reset. The frozen NC3 text
  ("touched by a cancelled request, or left mid-protocol") already closes this. The model now follows it, the
  `session.ready` window produces that state, and `cancelled-session-no-discard` proves the check. A connection
  released by a handler **error** (not a cancel) that passes the predicate still gets the ordinary checkin; `E1`/`E2`
  never carry session state there. CRS C8 (DISCARD ALL on every recycle regardless of cancellation) belongs to the PG
  adapter unit (P4-pg-003) and is not checked here beyond the `checkin.truth.session` rule.
- Sync host (X-11): the oracle cannot tell whether a sync subject placed its cancellation points at every host-call
  boundary. It sees only the `await` events it is given. The coverage check and the DST shell inside the subject are
  the only guards.
- Op-budget ticks are abstract (statement time = 1–3 ticks, ROLLBACK/DISCARD ALL = 1 tick, budget 2–5). The real
  T_recover is checked only by `--subject` under DST. The stray-cancel delivery is the worst case (always late), not a
  measured distribution. COPY, LISTEN and unknown protocol states (NC3: always discard) are not modelled.
