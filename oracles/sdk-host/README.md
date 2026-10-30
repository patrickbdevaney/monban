# sdk-host: F7b streaming host obligations (gate `sdk-host`)

Gate `sdk-host` in `gates/phase-4.toml`, implemented by P4-host-001 (aegis-adapter-host + `subjects/host-subject`).
Written in P4-oracle-host-001 (spec author). Source of the obligations: spikes/APPLIED.md q4-001 ("host obligations
to be checked by an adapter-host oracle"), the module docs of `sdk/aegis-sdk/src/streaming.rs` (F7b) and
`sdk/aegis-sdk/src/host.rs` (decision D2(b)), and DEVIATIONS X-11 (decision D6).

Under D2(b) the SDK owns minting: every `drive` / `open_body` / `open_sse` / `open_ws` / `step` / `on_ws_message` /
`run_job` call checks `Session::live()`, mints one fresh `Ctx` and db view, rolls back a transaction left open, and
returns `Driven { result, jobs }`. What the SDK cannot enforce is left to the host, and that is what this oracle judges:

| obligation (host.rs / streaming.rs / X-11) | clause here | spec |
|---|---|---|
| one SDK call per step or message, so each gets a freshly minted context: Ctx minting count == step count | MINT | INV-NO-AMBIENT (Held re-derived per step) |
| never cache a Ctx or a grant/liveness snapshot across calls: grants follow the session at the moment of the call (epoch bumps) | GRANT-FRESH | INV-NO-AMBIENT, CRS C5 (epoch revocation) |
| revocation mid-stream: every later step/message is `Unavailable` (generator not called), every later open is `Denied` | REVOKE | INV-NO-AMBIENT, INV-FAILCLOSED, C5 |
| revoked sessions deny their queued jobs: `Denied`, no mint, no backend call (nothing written) | JOB-REVOKE | INV-NO-AMBIENT, C5 |
| keep `Driven.jobs` even when `Driven.result` is an error (jobs exist only after a commit), and run each exactly once via `run_job` | JOB-KEEP | INV-NOMUT-C |
| detach only with `Tx<Committed>`: a job detached before commit, or after a failed commit, never runs | DETACH-COMMIT | INV-NOMUT-C |
| idle budget per stream | IDLE-BUDGET | ARCHITECTURE §3.8 budgets, F7b |
| step budget per stream | STEP-BUDGET | same |
| handlers run on the bounded blocking pool: fixed capacity, admission-rejected when full, never queued, never inline | POOL | DEVIATIONS X-11 |
| backend calls and minted contexts carry the session principal's tenant | TENANT | INV-NO-AMBIENT, F7 tenant binding |
| well-formed replies | PROTO | |

## Usage

```
oracles/sdk-host/run                          # reference subject, 200 seeds (about 8 s)
oracles/sdk-host/run --seeds N --tail N       # more seeds / longer random tails
oracles/sdk-host/run --subject '<cmd>'        # host-subject: target/release/host-subject sdk-host
oracles/sdk-host/run --mutate <m> [--subject '<cmd>']   # one mutant, for diagnosis
oracles/sdk-host/run --self-test              # 11 reference mutants, each red on its own clause
oracles/sdk-host/run --self-test --subject '<cmd>'      # + subject clean, and '<cmd> --mutate m' red for every required m
```

Last line: `SDK-HOST: PASS|FAIL (...)` or `SDK-HOST SELF-TEST: PASS|FAIL (...)`; exit 0 only on PASS. Python stdlib
only, `python3 -I -B`. No compile: the gate builds host-subject through `ci/heavy.sh` before calling this.

## What one seed does

One subject process per seed. The oracle sends ops, keeps an independent model (sessions, streams and their
counters, the job queue, pool slots) and compares each op's full event list with the model's prediction. **A seed
stops at its first divergence** (the model can no longer predict the subject), and the divergence is classified into
the clause it breaks.

1. **Scripted prelude** (identical every seed, touches every clause): `config pool=2`; sessions A {select, insert} and
   B {select}. Jobs: a call commits and detaches J1; a call commits, detaches J2 and then returns `err:conflict` (J2
   must still run); a call detaches J3 *before* its commit (refused); `fail_commit A`, then a call whose commit fails
   (J4 never reached); `run_jobs` (J1, J2 run). SSE s1 (idle 3, step 20): item, idle, idle, item (idle counter reset),
   `bump_epoch A {select}`, a step that asks for insert (denied) and select (granted), three idles (closed at the third),
   one more step (closed, no mint). Body b1 (step budget 3): four steps (closed after the third). WS w1 (idle 2):
   message, tick, message, tick, tick (closed), message (closed). Pool: two holds fill it; a third hold, a step and a
   call are rejected; release one, the step is admitted. Revocation: B opens s3 and w2, steps s3, queues J5; A queues J6;
   `revoke B`; step s3 and message w2 → `Unavailable`; open on B → `Denied`; `run_jobs` → J5 denied, J6 runs.
2. **Random tail** (`--tail`, default 60 ops, seeded): new sessions with random permits, revocations, epoch bumps
   (permits may become empty), armed commit failures, opens of sse/body/ws (20% on any session, revoked included) with
   random budgets (idle 1–4, step 2–8), steps / messages / ticks (also on closed streams), scoped calls, `run_jobs`,
   holds and releases. Scripts are random over the app vocabulary below (grants of granted and ungranted kinds, runs
   with and without a grant, double begin, commits, detaches before and after commit, errors).
3. **Finish**: release every hold, `run_jobs`.

**Vacuity guard**: the run fails unless mints, revocations, epoch bumps, jobs run, jobs denied, jobs from errored
scopes, holds, rejections, unavailable steps, denied opens, idle and step budget closes, ticks and closed-stream
steps are all non-zero.

## Subject protocol (normative; what host-subject must implement)

Invocation: `<cmd>` (the gate uses `target/release/host-subject sdk-host`); for mutants the oracle appends
`--mutate <name>`. The subject is the host: real aegis-adapter-host code driving the real `aegis_sdk::host` functions,
with a scripted test application, an instrumented `Backend` and the host's own `Session`. Nothing in the
host's obligations may be simulated in the subject's glue.

**Framing.** On start the subject prints one line `{"ready":true,"mutations":[...]}` (the mutations it implements).
Then it reads one JSON object per line from stdin. For each op it prints zero or more event lines, then
`{"ev":"end","seq":<op seq>}`. All output is on stdout, one JSON object per line. Key order and whitespace are
free; the oracle compares parsed objects exactly, so no extra members. `{"op":"quit"}` ends the process (no reply).
An unexpected condition is reported as `{"ev":"error","msg":"..."}` before `end` (counted as PROTO). Each reply
must arrive within 20 s, and within 5 s for any op sent while the pool is full.

Tenants are 16-digit lowercase hex (decision D4). Kinds are `select|insert|update|delete|upsert` (= `op_code` 1, 2, 4,
8, 16). Errors on the wire: `denied|conflict|unavailable` (`SdkError`), plus `closed` (host-level, below).

### Ops (all carry `"seq"`, a positive integer, echoed in `end`)

| op | members | meaning | events |
|---|---|---|---|
| `config` | `pool` | blocking-pool capacity for this process (sent first) | none |
| `session` | `session`, `tenant`, `permits` | a live session: principal with that tenant; route endowment ∩ token = `permits` | none |
| `revoke` | `session` | the session/token is revoked: `Session::live()` is false from now on | none |
| `bump_epoch` | `session`, `permits` | grant epoch change: `Session::permits` answers from the new set (may be empty); still live | none |
| `fail_commit` | `session` | the next `Backend::commit` of any scope of this session returns `Err(Unavailable)` | none |
| `open` | `stream`, `kind` (`sse`\|`body`\|`ws`), `session`, `idle_budget`, `step_budget`, `script`, `jobs` | `open_sse` / `open_body` / `open_ws` with the app running `script` | below |
| `step` | `stream`, and either `script` + `jobs` (+ `msg` for ws) or nothing (ws tick) | gen stream: one `host::step`; ws with `msg`: one `on_ws_message`; ws without `msg`: an idle tick, no SDK call | below |
| `call` | `call`, `session`, `script`, `jobs` | one `host::drive` of a scoped handler running `script` | below |
| `run_jobs` | | run every queued `PendingJob` once, FIFO in queueing order, each via `host::run_job` with its session; the queue is then empty | per job, below |
| `hold` | `call`, `session` | submit a scoped handler that blocks until `release` | `minted`, `held` or `rejected` |
| `release` | `call` | unblock that handler and wait for it | `result ok "ok"` |

`jobs` maps each job name used by a `detach:` action in `script` to that job's own script. The oracle never sends
`run_jobs` while the pool is full, never `hold` on a non-live session, and job scripts contain no `detach:`.

### App semantics (the scripted test application; every callback that receives a `Ctx`)

On entry the app prints `{"ev":"minted","call":C,"tenant":T}` with C = `open|step|msg|call|job|hold` and T =
`ctx.principal()`'s tenant. It keeps, for this callback only: the capability proofs it obtained, an optional
`Tx<Open>` and an optional `Tx<Committed>`. Then it runs the script in order:

| action | behaviour | events |
|---|---|---|
| `grant:K` | `ctx.grant::<K>()`; on `Ok` keep the proof; on `Err` continue | `{"ev":"decision","cap":K,"result":"granted"\|"denied"}` |
| `begin` | `db.begin()`; `Err` ends the script with that error (SDK: `conflict` if one is already open) | backend `begin` if reached |
| `run:K` | if no proof for K or no open Tx: end with `denied` (no call); else `db.run(tx, proof, op)` with an `Op` of kind K | backend `run` |
| `commit` | no open Tx: end with `denied`; else `db.commit(tx)`; `Err` ends the script with that error; `Ok` keeps the committed proof | backend `commit` (+ `rollback` on failure, by the SDK) |
| `detach:J` | with a committed proof: `db.detach(&committed, job J)`; without one: do not call | `{"ev":"detach","job":J,"result":"accepted"\|"refused"}` |
| `err:E` | return `Err(E)` | |
| terminal | return `Ok`: open/call/job `ok`; step `item` (an Event/Chunk), `idle`, `done`; ws `send` (one message), `close` | |
| (end of script) | return `Ok("ok")` | |

The instrumented `Backend` prints `{"ev":"backend","call":"begin"}`, `{"ev":"backend","call":"run","kind":K,
"tenant":T}` (T = the `op.tenant` it received, i.e. after the SDK overwrote it), `{"ev":"backend","call":"commit",
"ok":true|false}`, `{"ev":"backend","call":"rollback"}`. The SDK rolls back a transaction still open when the callback
returns; that rollback is printed after the app's events. After the SDK call returns, the host prints
`{"ev":"result","ok":V}` (V = the terminal, or `"ok"`) or `{"ev":"result","err":E}`.

### Host semantics (the obligations)

- **Pool (X-11).** Every SDK call (`open`, `step` with a script, `call`, every job of `run_jobs`, `hold`) runs on the
  bounded blocking pool with the configured capacity. When all slots are taken (only `hold`s keep a slot across ops),
  the call is not made and the reply is exactly `{"ev":"rejected","reason":"pool_full"}`, promptly (never queued,
  never run on the I/O thread). A `hold` that is admitted prints the app's `minted`, then `{"ev":"held","call":C}`
  once the handler is running on its pool thread.
- **Open.** If admitted: session not live → `result err denied` (from the SDK, no mint). Otherwise app events and
  `result`. On `Ok` the stream exists with counters steps = 0, idle = 0. On `Err` it does not exist.
- **Step on a stream** (unknown, never opened, or closed) → exactly `{"ev":"result","err":"closed"}`, no SDK call.
- **WS tick**: idle += 1; no SDK call, no pool. At idle = `idle_budget`: `{"ev":"closed","stream":S,"reason":
  "idle_budget"}`.
- **Gen step / ws message**, if admitted: session not live → `result err unavailable` (the SDK does not call the
  generator; no mint), optionally followed by `closed reason "revoked"`; counters unchanged. Otherwise app events and
  `result`, steps += 1, then the first that applies: `Err` → `closed "error"`; `done`/`close` → `closed "done"`;
  `idle` → idle += 1 and, at idle = `idle_budget`, `closed "idle_budget"`; `item`/`send` → idle = 0. Then, if not
  closed and steps = `step_budget`, `closed "step_budget"`. A closed stream is dropped and never pulled again.
- **Jobs.** Every `PendingJob` in `Driven.jobs` of any call is queued, **also when `Driven.result` is `Err`**. A
  `run_jobs` op runs each queued job via `run_job` with the job's session as it is now: live → app events (`minted`
  call `job`, ...), `result`, then `{"ev":"job","job":J,"result":"ran"}`; not live → `result err denied`, then
  `{"ev":"job","job":J,"result":"denied"}` (no mint, no backend call). J is the name from the `detach:` action (the
  app's job value carries it).
- **Freshness.** The `Session` handed to the SDK answers `live()` and `permits()` from the current state at the moment
  of each call; nothing is snapshotted at open or at detach time.

### Mutations (`--mutate <name>`)

Each must turn its clause red within 10 seeds (in practice at seed 1, in the prelude). A subject must implement every
mutation except `detach-before-commit`, which the frozen SDK makes inexpressible in Rust (`detach` needs a
`&Tx<Committed>`); if the subject advertises it in `ready.mutations`, it is run too.

| mutation | host bug | clause | reference, first red (2026-10-30) |
|---|---|---|---|
| `mint-once-per-session` | Session wrapper snapshots live + permits at open; every step uses the open-time grants (the only Rust form of a cached Ctx: a real `Ctx<'m>` cannot outlive its scope) | GRANT-FRESH | seed 1, step after `bump_epoch` (insert still granted) |
| `revoked-stream-keeps-serving` | liveness snapshotted at open, permits fresh | REVOKE | seed 1, step on s3 after `revoke B` |
| `step-retry-double-mint` | host pulls again when the generator answered `Idle` | MINT | seed 1, first idle step (2 mints) |
| `job-ignores-revocation` | jobs run with the liveness/permits captured when queued | JOB-REVOKE | seed 1, J5 ran after `revoke B` |
| `drop-jobs-on-error` | `Driven.jobs` discarded when `result` is `Err` | JOB-KEEP | seed 1, J2 missing |
| `detach-before-commit` | JobQueue accepts a job without a committed proof (reference only) | DETACH-COMMIT | seed 1, J3 accepted |
| `no-idle-budget` | idle streams never closed | IDLE-BUDGET | seed 1, s1 third idle |
| `no-step-budget` | step budget not enforced | STEP-BUDGET | seed 1, b1 third step |
| `unbounded-pool` | admission never refuses | POOL | seed 1, third hold admitted |
| `inline-handler` | handler calls bypass the pool (run on the I/O loop) | POOL | seed 1, step admitted while full |
| `queueing-pool` | admission waits for a free slot (`spawn_blocking`-style queue) | POOL | seed 1, third hold not answered in 5 s |

Negative control of the subject path: a subject that ignores `--mutate` fails the self-test (every required mutation
MISSED; checked 2026-10-30 with a wrapper that drops the argument). With the prelude removed, the random tail alone
catches every mutation within 22 seeds (2026-10-30: double-mint, detach, idle, pool at seed 1; step budget 2;
drop-jobs 10; job-revocation 15; revoked-stream 16; mint-once 22).

## Re-run in repo (2026-10-30, laptop)

- `oracles/sdk-host/run`: `SDK-HOST: PASS (... over 200 seeds, 10516 mints, 673+211 jobs ran/denied)`, 7.6 s.
- `oracles/sdk-host/run --self-test`: 11/11 reference mutations caught, about 9 s (5 s of it is the queueing-pool
  timeout).
- `oracles/sdk-host/run --self-test --subject 'python3 -I -B oracles/sdk-host/ref_subject.py'` (the protocol path):
  22/22 caught.

Provenance: no research artifact is ported. The obligations are the frozen F7b/host.rs doc text and APPLIED q4-001;
the reference subject (`ref_subject.py`) ports `sdk/aegis-sdk/src/host.rs` (scope, `HostDb`, `run_job`) line for
line and adds a host layer. The oracle's model (`interp` and the op handlers in `sdk_host.py`) is a separate
restatement that does not import the reference.

## Known limits

- **Minting is observed as app invocations.** The SDK's `Ctx::mint` is `pub(crate)` and cannot be instrumented from
  the subject, so `minted` means "the app callback was entered with a `Ctx`". Under D2(b) each entry is a fresh scope,
  so the count is exact; a cached context can only appear as stale grants or liveness, which GRANT-FRESH and REVOKE
  check.
- **Budgets are in ticks, not wall time.** One oracle `step` is one host poll. A host whose real idle budget is
  time-based must map it onto this tick in host-subject; the oracle does not check the clock source.
- **Pool concurrency is observed through holds only.** The oracle sees admission and rejection, not thread counts.
  `inline-handler` is caught only because a pool-bypassing call is admitted while the pool is full.
- **Cancellation (X-11 host-call boundaries)** is the cancel-sweep's job (P4-oracle-state-001), not this oracle's.
- **Tenant binding** of `Op::tenant` is also enforced by the SDK; TENANT here only checks that the host builds the
  `Principal` and `Backend` from the right session.
- The subject's glue (app interpreter, instrumented backend) is trusted to report faithfully. The gate's value
  depends on host-subject driving the real aegis-adapter-host host loop, not a re-implementation.
