# state-props: oracle for INV-IDEMP, the NC2 commit-point latch and the NC6 outbox

Gates `spec/SPEC_INVARIANTS.md` §B:
- **INV-IDEMP**: key = (principal, idempotency-key); replay of a completed key returns the stored outcome; exactly-once
  is not claimed.
- **INV-NOMUT-C NC2**: from CP(r) on, the outcome is latched; a timer after CP yields 202 + idempotency retrieval.
- **INV-NOMUT-C NC6**: external effects only through the outbox.
- **NC1** as it applies to the store: a request that ends before CP (abort or SIGKILL) leaves no durable row and no
  delivered effect, and its key is free again.
- **INV-DURABLE** across SIGKILL: an answered COMMIT survives a kill of the process (page cache intact; the
  power-loss/EIO cases are crash-harness's job).

Gate `state-props` in `gates/phase-4.toml`, implemented by P4-state-002 (aegis-state idem/outbox/latch). Written in
P4-oracle-state-001. The semantics follow ARCHITECTURE §3.7 R-STATE-2/3 (draft-ietf-httpapi-idempotency-key-header-08
and Stripe: 409 for a key in flight, 422-class for a payload mismatch, stored outcome replayed).

## Usage

```
oracles/state-props/run                       # reference subject, 60 seeds (PR size)
oracles/state-props/run --seeds 1000          # nightly size
oracles/state-props/run --self-test           # 6 mutations of the reference subject, each red within 10 seeds
oracles/state-props/run --subject '<cmd> {dir}'              # the aegis-state wrapper (P4-state-002)
oracles/state-props/run --self-test --subject '<cmd> {dir}'  # + every mutation the subject advertises
```

`run` executes under `ci/heavy.sh`. The last line is `STATE-PROPS: PASS|FAIL (...)` (or
`STATE-PROPS SELF-TEST: PASS|FAIL (...)`), and the exit code is 0 only on PASS. Python stdlib only (`python3 -I`).
Store directories are temporary (`$TMPDIR`) and are deleted after each seed.

## What one seed does

The oracle drives the subject over the line protocol below and keeps its own model (completed keys and outcomes,
in-flight keys, committed user rows, committed effects). It kills the subject with **SIGKILL** and restarts it on the
same directory. Kills happen between protocol steps, with a COMMIT in flight (no reply read yet), and after the first
EFF line of a DELIVER. Every reply is checked against the model. The oracle is the outbox's external sink: an effect
is "visible" when the subject prints its EFF line.

1. **Scripted prelude** (same every seed, so every property is touched every seed):
   alice `k1` NEW, WRITE, EFFECT, **DELIVER before COMMIT** (nothing may be visible), COMMIT. Then alice `k1` again
   (REPLAY, byte-identical), bob `k1` (NEW: another principal's key is independent; bob commits), alice `k1` with
   another digest (CONFLICT). alice `k2` NEW, alice `k2` again while in flight (INFLIGHT), then COMMIT with the timer
   firing after CP (202) and retrieval by key (REPLAY of the latched outcome). bob `k3` ABORT, then NEW again (key
   freed), then SIGKILL with bob `k3` in flight, then NEW again and COMMIT. SIGKILL with committed effects undelivered,
   DUMP, replay of alice `k1` after the restart, DELIVER killed after its first EFF line, DELIVER again.
2. **Random tail** (`--tail`, default 40 actions, seeded): up to 3 open requests across alice/bob and a growing key set
   (40% fresh keys, 20% foreign digests). Actions: BEGIN, WRITE, EFFECT, COMMIT (30% with timer), ABORT, DELIVER (30%
   killed after its first EFF), COMMIT cut by SIGKILL, plain SIGKILL, DUMP.
3. **Finish**: SIGKILL, restart, DUMP, DELIVER twice. Every committed effect must have been delivered at least once.

A COMMIT cut by SIGKILL may land either way. After the restart the oracle probes the key (BEGIN with the same
principal, key and digest). REPLAY with exactly that outcome means it committed: its rows and effects become
expected. NEW means it did not: the probe is ABORTed, and its effects must never appear.

## Checks

| clause | check |
|---|---|
| INV-IDEMP replay | BEGIN of a completed (principal, key) with the same digest ⇒ `REPLAY` with the stored status and body **byte-identical**, before and after restarts; `NEW` there = re-execution |
| INV-IDEMP principal | the same key under another principal ⇒ `NEW` (independent), never that principal's outcome, conflict or lease |
| INV-IDEMP conflict | completed key + different request digest ⇒ `CONFLICT` (422-class) |
| INV-IDEMP in flight | key held by an open request ⇒ `INFLIGHT` (409-class); with a different digest `INFLIGHT` or `CONFLICT` |
| NC1 | after ABORT or a SIGKILL before CP the key answers `NEW`, no user row changed, and no effect of that attempt is ever delivered |
| NC2 | COMMIT with timer=0 answers the committed status/body; with timer=1 (timer after CP) it answers **202**, and retrieval by key returns the latched outcome; a COMMIT cut by SIGKILL is all or nothing |
| NC6 before commit | no EFF line for an effect whose request has not committed (open, aborted, killed, or rolled back) |
| NC6 delivery | every committed effect is delivered at least once across SIGKILL restarts |
| NC6 dedupe | an effect keeps one dedupe key across redeliveries; a dedupe key never names two different effects |
| NC1/DURABLE | DUMP after every restart (and at random points) equals exactly the committed requests' writes, in commit order |
| PROTO | malformed or missing reply, wrong rid, timeout (20 s per line), early exit |

## Self-test (mutations of the reference subject; each must turn its clause red within 10 seeds)

| mutation (`--mutate <name>`) | clause | first red (2026-10-30) |
|---|---|---|
| `idem-key-without-principal`: the key is the client key alone | INV-IDEMP | seed 1 (bob `k1` got CONFLICT on alice's key) |
| `replay-reexecutes`: a completed key with the same digest runs again | INV-IDEMP | seed 1 (alice `k1` got NEW) |
| `effect-before-commit`: EFFECT inserts the outbox row at once (autocommit) | NC6 | seed 1 (visible at the pre-commit DELIVER) |
| `outbox-drop-on-restart`: undelivered outbox rows dropped on open | NC6 | seed 1 (4 committed effects never delivered) |
| `latch-returns-408`: a timer after CP answers 408 | NC2 | seed 1 |
| extra, not in the unit list: `dedupe-unstable`: a fresh dedupe key on every delivery | NC6 | seed 1 (redelivery after the mid-DELIVER kill) |

The self-test first runs the unmutated reference for 3 seeds and fails if that is red, so a mutant caught by a broken
oracle does not count. With `--subject`, the subject's READY line must advertise at least `idem-key-without-principal`
and `replay-reexecutes` (P4-state-002 acceptance), else FAIL. Every advertised mutation among the five is run with
`--mutate <name>` appended to the subject command and must go red within 10 seeds. Subjects should also advertise and
implement the other four (and `dedupe-unstable`); P4-state-002 only requires the two above.

Extra negative control (2026-10-30, not part of `--self-test`): a wrapper that deletes the store on every start goes
red on INV-IDEMP, NC1/DURABLE and NC6 at seed 1.

## Subject protocol

The subject is one executable. `{dir}` in `--subject` is replaced by the store directory (appended if absent), and
self-test mutations are appended as `--mutate <name>`. On start it opens or creates the store in `{dir}`, runs
recovery, and prints one line: `READY <free text> [mutations=a,b,...]`, or `ERR open <msg>` and exits non-zero. It then
reads newline-terminated commands on stdin. Each command gets exactly one reply line, except DELIVER and DUMP, which
reply with several lines ending in `END`.

```
BEGIN <rid> <principal> <key> <digest>   -> NEW <rid>                          key free: lease taken (in memory)
                                            REPLAY <rid> <status> <bodyhex>    completed, same digest: stored outcome
                                            CONFLICT <rid>                     completed (or in flight), other digest
                                            INFLIGHT <rid>                     held by an open request
WRITE <rid> <row> <valhex>               -> OK <rid>      user-row write inside rid's transaction (not yet durable)
EFFECT <rid> <payloadhex>                -> OK <rid>      external effect of rid, through the outbox (NC6)
COMMIT <rid> <status> <bodyhex> <timer>  -> RESP <rid> <code> <bodyhex|->
        commit point: rid's rows, its outcome record (principal, key, digest, status, body) and its outbox rows
        become durable atomically BEFORE the reply. timer=0: code/body = the committed status/body. timer=1 (the
        request timer fired after CP): code 202 and body "-"; the outcome stays retrievable via BEGIN (NC2 latch).
ABORT <rid>                              -> OK <rid>      termination before CP: nothing durable; key released
DELIVER                                  -> EFF <dedupe> <payloadhex> ... END
        one outbox relay pass: every committed, undelivered effect, oldest first. After each EFF line the subject
        reads one line from the oracle (the sink): ACK means the sink took the effect, and only then may it be marked
        delivered (at-least-once); anything else, or EOF, ends the pass without marking. A line written but not ACKed
        is not delivered (it may sit unread in the pipe when the oracle SIGKILLs mid-pass). <dedupe> is stable
        across redeliveries.
DUMP                                     -> ROW <row> <valhex> ... END   (committed user rows)
QUIT / EOF                               -> exit 0
```

Tokens: `rid`, `principal`, `key`, `row` match `[A-Za-z0-9_-]+`; `digest`, `bodyhex`, `valhex`, `payloadhex` are
lowercase hex; `status` is a decimal HTTP status. Pre-CP state (leases, buffered writes and effects) must not be
durable: after a SIGKILL an open request is gone, and its key answers NEW. Each reply line must be flushed before the
next command is read.

How the aegis-state crate maps onto it (P4-state-002): `idem.rs` answers BEGIN from the (principal, key) table and the
in-flight set; `latch.rs` is the COMMIT path (one SQLite transaction for rows + outcome + outbox, then the response,
202 when the request timer has fired after CP); `outbox.rs` is DELIVER (relay pass, mark after the sink's ACK) with a dedupe key
derived from the idempotency key and the effect's position. The subject wrapper (`subjects/state-subject`) only parses
lines.

## Reference subject

`ref_subject.py` (stdlib `sqlite3`, WAL, `synchronous=FULL`, journal-mode re-check after the schema write): tables
`idem(principal, key, digest, status, body)`, `rows(k, v)`, `outbox(seq, dedupe UNIQUE, payload, delivered)`. The
in-flight set lives in memory. COMMIT is one `BEGIN IMMEDIATE` transaction. The dedupe key is
`sha256(principal \0 key \0 index)[:32]`. It implements all six mutations behind `--mutate`.

## Provenance

No research harness existed for these properties. The oracle was written from SPEC §B INV-IDEMP / NC1 / NC2 / NC6,
ARCHITECTURE §3.7 (R-STATE-2/3) and the unit text of P4-oracle-state-001. Nothing was ported or executed from
`research/state/raw/`.

## Re-run in repo (2026-10-30, laptop)

- `./run`: `STATE-PROPS: PASS (INV-IDEMP NC1 NC2 NC6 over 60 seeds, 882 store lives, 822 SIGKILLs, 321 deliveries)`
  in 19.3 s. 51 COMMITs were cut by SIGKILL (25 landed, 26 rolled back), 63 DELIVERs were killed after their first EFF
  line, and 42 effects were redelivered. BEGIN replies expected: NEW 690, REPLAY 459, CONFLICT 133, INFLIGHT 89. 350
  commits, 90 with the timer after CP. The script is seeded, but where a kill lands inside COMMIT/DELIVER depends on
  timing, so delivery counts vary slightly between runs (318–321 seen).
- `./run --subject 'python3 -I .../ref_subject.py {dir}' --seeds 20`: PASS over the external path.
- `./run --self-test` and `--self-test --subject '.../ref_subject.py'`: `STATE-PROPS SELF-TEST: PASS (6/6 ...)` and
  `(12/12 ...)`, every mutation red at seed 1.

## Known limits

- One subject process, with requests interleaved over one stdin. There is no real concurrency: two OS threads racing
  on the same key are not tested. That race needs the DST shell or a loom test in aegis-state.
- SIGKILL only (page cache survives). Power loss, torn writes and fsync EIO for this store are crash-harness's job
  (P4-state-001 runs its store under it); state-props does not re-run them.
- The timer is a protocol flag. The subject is told "the timer fired after CP", so the host's own timer wiring is not
  exercised here; native-e2e (P4-bin-001) covers it end to end.
- In-flight leases do not survive a restart (the model requires the key to be free after a SIGKILL before CP). This
  matches NC1 (idempotency rows are user rows in cancel-sweep's NC1 check). A design with durable leases plus expiry
  would need a protocol change here.
- Effect classes ("effect classes declared", INV-IDEMP) are not modelled. Every effect is an outbox effect with
  at-least-once delivery and a dedupe key. Exactly-once is not claimed and not checked.
- Redelivery depends on the kill landing between the EFF write and the delivered mark. With the reference subject this
  happened 42 times in the default 60-seed run; a faster subject may hit it less often.
