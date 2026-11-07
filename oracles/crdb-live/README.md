# crdb-live: aegis-bin adapter-crdb against a live CockroachDB

Unit P8-oracle-001. Gate `crdb-live` (gates/phase-8.toml, `remote = "kamrui"`). Implementer P8-bin-001. Closes PREFLIGHT
R8: the crdb adapter's 40001 handling was only unit-tested and CancelRequest was untested against a server through
the binary.

```
ci/engines.sh with crdb -- oracles/crdb-live/run --dsn @crdb --binary target/release/aegis   # aegis --features adapter-crdb (gate)
ci/engines.sh with crdb -- oracles/crdb-live/run --dsn @crdb                                 # the reference subject
ci/engines.sh with crdb -- oracles/crdb-live/run --self-test --dsn @crdb                     # reference PASS, 3 mutants FAIL
```

`run` execs `python3 -I oracle.py` from the repo root. Stdlib only. The last line is `CRDB-LIVE: PASS|FAIL (...)` or
`CRDB-LIVE SELF-TEST: PASS|FAIL (...)`, exit 0 only on PASS. `--subject` is an alias of `--binary`. `--dsn` is the
root DSN `ci/engines.sh` prints for the pinned CockroachDB (v25.4.19, `start-single-node --insecure`, in-memory,
loopback only); the oracle refuses a DSN whose `version()` is not CockroachDB. Needs the `openssl` CLI (one throwaway
P-256 certificate). It reuses oracles/native-e2e (`e2e.py`: F5 minting and the TLS client; `wire.py`: PG v3 with
BackendKeyData and CancelRequest; `ref_subject.py`: the reference, whose `crdb` engine is defined there).
`needs` = `own-gate`. One run takes about 50 s.

## Subject contract

The native-e2e contract (oracles/native-e2e/README.md "Subject contract": CLI, tokens, endpoints, idempotency,
`hold_ms`, `aegis-deadline-ms`, NC1/NC2/NC7) with one backend:

```json
"data": {"backends": [{"id": "cr", "engine": "crdb", "dsn_ref": "env:AEGIS_E2E_CRDB_DSN", "pin": "crdb", "op_budget_ms": 5000}]},
"vhosts": [{"host": "aegis.test", "routes": [{"id": 1, "path": "/cr/", "to": {"upstream": "app:notes"}, "authz": "allow-all",
  "data": [{"backend": "cr", "collection": "notes", "ops": ["select","insert","update","delete","upsert"], "columns": ["id","body"]}]}]}]
```

Provisioned by the oracle as root, recreated per run:
- `public.notes (tenant STRING NOT NULL, id STRING NOT NULL, body STRING NOT NULL, PRIMARY KEY (tenant, id))`
  (the crdb schema gate's golden shape; CockroachDB has no RLS here, so isolation is the rendered tenant conjunct);
- `public.aegis_idem` exactly as aegis-bin's `CRDB_IDEM_DDL`;
- user `aegis_app` (insecure mode: no password) with `SELECT, INSERT, UPDATE, DELETE` on notes and `SELECT, INSERT`
  on aegis_idem, nothing else. `AEGIS_E2E_CRDB_DSN` = `postgresql://aegis_app@127.0.0.1:<port>/defaultdb`; the
  subject never sees root. The oracle finds the subject's sessions and queries by `user_name = 'aegis_app'`.

What the subject must do (the residual):
- **40001.** A transaction that fails with SQLSTATE 40001 is never answered as a success. Retrying the whole
  transaction (handler included) is allowed and is what the reference does; failing the request (any non-2xx, no
  effect) is also correct.
- **Cancel.** When a request's deadline passes (or the client goes) while a statement is running, the answer comes
  within the deadline, the statement stops on the server (PG CancelRequest with the session's BackendKeyData; closing
  the connection also stops it), and the connection is either reset (ROLLBACK, the C8/NC3 recovery) before it is
  pooled again, or retired. The pool keeps serving correct answers.

## What is checked

| check | how | clause |
|---|---|---|
| `baseline.*` | insert / select / update through the subject, durable rows read as root | modes A/D on crdb |
| `contention.<op><i>.forced-abort` | the subject PATCHes / PUTs / DELETEs / POSTs with `hold_ms` 1200; 350 ms in, the oracle commits a conflicting write to the same row in a `PRIORITY HIGH` transaction; it must commit in < 0.8 s, i.e. it aborted the subject's open transaction (verified on v25.4.19: the subject's COMMIT then fails with 40001 `TransactionAbortedError(ABORT_REASON_ABORT_SPAN)`) | R8 workload |
| `contention.<op><i>.never-wrong` | a 2xx ⇒ the durable row is the subject's answered value (update/upsert), gone (delete), the subject's insert; a non-2xx ⇒ the row is the oracle's value (no effect). A 201 on the insert round while the oracle's row stands is the stale answer | INV-DURABLE (ack ⇒ durable), NC7, R8 |
| `contention.<op><i>.replay-latched` / `.replay-executes` | the same Idempotency-Key again: a 2xx is latched and returned unchanged; a failure before CP is not latched and re-executes now | INV-IDEMP |
| `contention.produced-40001` | `crdb_internal.node_metrics` `txn.restarts.txnaborted` rose over the workload (6 contended requests: 2 update, 2 upsert, 1 delete, 1 insert) | the workload really produced 40001s |
| `cancel.<update\|select>.answer-within-deadline` | the oracle holds an uncommitted write on the row; the subject's PATCH (or GET) with `aegis-deadline-ms: 800` blocks on it; the answer is a 504 within 0.8 + 0.7 s | NC1 deadline, R8 |
| `cancel.*.statement-stopped` | 1 s after the deadline (lock still held): `SHOW CLUSTER QUERIES` lists no query of `aegis_app` | CancelRequest |
| `cancel.*.connection-reset-or-retired` | at the same moment `crdb_internal.cluster_sessions` lists no `aegis_app` session with an open transaction (`kv_txn IS NOT NULL`; a cancelled statement leaves its session's transaction open and aborted until ROLLBACK, verified on v25.4.19) | C8/NC3 pool reset |
| `cancel.*.no-late-effect` | after the lock is released, the row still has its pre-image | NC1 |
| `cancel.*.pool-serves-after` | 6 × (PATCH, GET) afterwards all answer correctly | pool health |

**PASS** iff every check passes (30 checks).

## Self-test (negative controls)

The reference is `oracles/native-e2e/ref_subject.py` with its `crdb` engine (`CrdbPool`: LIFO, so the connection a
cancelled request used is handed out next; `CrdbTx`: SERIALIZABLE, a watch thread sends CancelRequest when the
request is cancelled, ROLLBACK before pooling; `Server.execute`: whole-transaction retry on 40001, at most 3). It must
PASS; then each mutant (env `AEGIS_E2E_MUTANT`, reference only) must FAIL:

| mutant | planted bug | caught by |
|---|---|---|
| `crdb-40001-as-success` | a 40001 at COMMIT answered with the success the handler computed (stale data) | `contention.*.never-wrong` |
| `crdb-cancel-ignored` | no CancelRequest: the 504 still goes out on time, but the statement keeps running | `cancel.*.statement-stopped`, `cancel.*.connection-reset-or-retired` |
| `crdb-no-reset` | a connection whose transaction failed is pooled without ROLLBACK | `cancel.*.connection-reset-or-retired`, `cancel.*.pool-serves-after` |

## Recorded runs (kamrui, CockroachDB v25.4.19 from ci/engines.sh)

- `run --dsn @crdb` (reference): PASS, 30 checks (first run red on `produced-40001`, which then required one abort
  per round; CockroachDB files some aborts under other `txn.restarts.*` reasons, so the counter is now an "at all"
  check and per-round evidence is `forced-abort`).
- `run --self-test --dsn @crdb`: `CRDB-LIVE SELF-TEST: PASS (reference green; 3/3 mutants caught: crdb-40001-as-success,
  crdb-cancel-ignored, crdb-no-reset)`. Caught by: 40001-as-success 5 checks (every never-wrong but delete), cancel-ignored
  4 (statement-stopped, connection-reset-or-retired, both rounds), no-reset 4 (connection-reset-or-retired,
  pool-serves-after, both rounds).
- **Today's binary** (`--features adapter-crdb` at base 0e27b11): `CRDB-LIVE: FAIL (4 failed:
  cancel.update.statement-stopped, cancel.update.connection-reset-or-retired, cancel.select.statement-stopped,
  cancel.select.connection-reset-or-retired)`. 26 of 30 pass: the 40001 rounds are answered with a clean failure and
  no effect (no retry, but never wrong), and the 504 comes on time. The residual is real: 1 s after the 504 the
  blocked UPDATE / SELECT is still running on the server and the session still holds an open transaction (its last
  statement the transaction-local `set_config('statement_timeout', ...)`), i.e. no CancelRequest and no reset at the
  deadline.

## Known limits

- The oracle cannot tell a CancelRequest from closing the connection: both stop the statement, and both are accepted
  (reset or retired).
- 40001 is forced by priority aborts at COMMIT. Read-refresh failures and retry errors on a statement inside the
  transaction are not driven separately; the rule (never a 2xx without the effect) is the same.
- Single node, in-memory store, loopback: no clock-uncertainty restarts and no network faults.
- Timing: the pushes land 350 ms into a 1200 ms hold; a heavily loaded host could push before the subject wrote,
  which turns a round into a plain write-write wait (`forced-abort` goes red rather than a false pass).
