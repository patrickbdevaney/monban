# q3-008: PG reconnect under discard-on-cancel (NC3)

**Question (plan):** "q3-008 PG reconnect under discard-on-cancel — >20 ms p50 or <200 cancels/s → state-tracked reuse".
**Verdict: flip** (grade B: laptop + LAN box standing in for a VPS). Both triggers fire on 1-vCPU-class
configurations. Unconditional discard + reconnect costs 1–2 PostgreSQL backend forks per cancel, and those forks
saturate one core at 30–266 cancels/s. State-tracked reuse is 2–4× cheaper with a CancelRequest and about 20× cheaper
in CPU without one. The variant to adopt is **drain-and-reset without a CancelRequest** ("reuse-wait"), with discard as
the fallback. A CancelRequest-based reuse was measured to cancel the *next* request on the reused connection
(see correctness).

## Method
- Harness `harness/` (Rust, tokio current-thread runtime, tokio-postgres 0.7.18, tokio-postgres-rustls 0.14.0, rustls
  0.23.45 with the aws-lc-rs provider, TLS 1.3 only). Every crate in `harness/Cargo.lock` was ≥7 days old on
  2026-10-25 (`lock_age.py`, `raw/lock_age.txt`; 5 transitive crates were downgraded to get there). PR #1374 is **not**
  applied. In the reuse path, `DISCARD ALL` closes any server object the #1374 window might leak.
- Server: a throwaway `postgres:17` container (17.11, Debian trixie, OpenSSL 3.5.7) on the laptop and
  `postgres:17-alpine` (17.11, musl) on kamrui, started by `pg.sh`. Host network with `listen_addresses=127.0.0.1`
  keeps it on loopback only, with no docker-proxy in the path. `ssl=on` with a throwaway P-256 CA and leaf
  (`gen_certs.sh`); PG17 offers only `ssl_ecdh_curve=prime256v1`, so the client offers secp256r1 only (no
  HelloRetryRequest). Settings: max_connections=400, everything else default (scram_iterations 4096). Auth is
  `trust` (role trustu) or `scram-sha-256` (role postgres). The container was removed after each run.
- Pinning: client `taskset -c <core>`, server `docker --cpuset-cpus`. **split** = server on its own core (the rate is
  then bounded by the PG core). **shared** = the server is moved onto the client's core (`docker update`) = a 1-vCPU box
  running both Monban and PG. Laptop: client on core 8, server on core 10 (P-cores, other HT siblings unused by the
  bench). kamrui: client on core 2, server on core 3.
- CPU accounting: client = getrusage(RUSAGE_SELF). Server = the container cgroup's `cpu.stat usage_usec`, which counts
  postmaster, backend fork/init/exit, cancel-request children and orphan backends.
- Cycles (one per measured sample; latency is timed from the moment the in-flight future is dropped):
  - `connect`: connect (TCP + [TLS] + auth + backend fork) + `SELECT 1`, then drop. Pure reconnect.
  - `discard` (the NC3 baseline): on a held conn, `BEGIN`, then `SELECT pg_sleep(0.05)`, whose future is dropped by a
    2 ms timeout (mid-protocol). Fire-and-forget CancelRequest so the orphan backend stops, drop the conn, connect a
    replacement, `SELECT 1`.
  - `discard-nocancel`: as `discard` but without the CancelRequest. The orphan backend runs the statement out and then
    sees EOF.
  - `reuse`: same mid-protocol state. Await the CancelRequest, then `ROLLBACK`, `DISCARD ALL`, `clear_type_cache()`,
    and a `SELECT 1` sentinel on the same conn. Any error ⇒ `reuse_fail` and fall back to discard.
  - `reuse-wait`: as `reuse` but **without** a CancelRequest. `ROLLBACK` queues behind the in-flight statement (48 ms
    remaining here, so latency ≈ the remaining statement time).
- Latency runs: concurrency 1, 1000–2000 cycles after 100 warm-up cycles. Rate runs: 16 concurrent workers for 8 s.
  Everything on the laptop ran under `ci/heavy.sh` (nice 15). kamrui has no heavy.sh, so it ran at nice 0.

## Hardware and conditions (honest)
- **Laptop**: Intel Core i9-14900HX (8P+16E), kernel 6.17, governor powersave. **The machine was heavily loaded** by
  other jobs (loadavg 20–25 at start). Repeat runs differ by up to ±30% (compare the two laptop files).
- **kamrui (weak-VPS stand-in, LAN box, not a VPS)**: Intel N95 (4 E-cores, no SMT), 15 GB, kernel 6.17, governor
  powersave. First suite: loadavg 0.44 at start. During the later `race`/`extra` runs, other agents' Kani/cbmc/hsbench
  jobs were active (a nice-15 cbmc on the server core 3), so those rows are pessimistic by about 30–50%.
- A real $5 VPS vCPU is typically slower and noisier than a dedicated N95 core (steal time). The N95 rows are not an
  upper bound for a shared vCPU.

## Headline numbers
Reconnect after cancel (`discard`), p50 / p99 in ms, concurrency 1:

| | trust/plain | SCRAM/plain | SCRAM/TLS1.3 |
|---|---|---|---|
| laptop, split | 4.87 / 15.5 (rerun 3.51 / 19.2) | 3.89 / 9.4 | 5.40 / 11.2 (rerun 5.56 / 13.9) |
| laptop, shared core | 14.3 / 21.6 | 6.9 / 55.7 | 8.9 / 87.0 |
| N95, split | 11.8 / 49.1 | 12.8 / 35.5 | 17.1 / 28.3 (contended rerun **21.9** / 33.8) |
| N95, shared core | **21.7** / 34.3 | **25.5** / 43.3 | **37.7** / 72.4 |

Sustainable cancel+replace rate (16 workers, closed loop), cancels/s:

| | trust/plain | SCRAM/plain | SCRAM/TLS1.3 |
|---|---|---|---|
| laptop, 1 shared core: discard | **189** (rerun 266) | **167** | **115** (rerun 135) |
| laptop, 1 shared core: reuse (CancelRequest) | 213 (rerun 619) | 507 | 276 (rerun 370) |
| laptop, split (PG core saturated): discard | 295 | 293 | 225 |
| N95, 1 shared core: discard | **53** | **39** | **30** |
| N95, 1 shared core: reuse (CancelRequest) | 187 | 179 | 82 |
| N95, split (PG core saturated): discard | 68 | 79 | 48 |
| reuse-wait (both hosts, shared) | 293–307 | — | 290–298 |

reuse-wait is bounded by pool occupancy (16 conns × 48 ms of remaining statement), not by CPU. Its CPU cost is in the
next table.

CPU per cancel cycle, client + server (µs). The theoretical 1-core ceiling is 1e6 / sum.

| | discard | discard-nocancel | reuse (CancelRequest) | reuse-wait | connect |
|---|---|---|---|---|---|
| laptop trust/plain | 230 + 4814 | 157 + 3603 | 142 + 1745 | 146 + 229 | 126 + 2759 (rerun 67 + 1919) |
| laptop SCRAM/TLS | 1905 + 4672 | 1625 + 3714 | 650 + 2360 | 148 + 304 | 1393 + 2614 |
| N95 trust/plain | 743 + 13307 | 554 + 8899 | 450 + 4488 | 404 + 605 | 346 + 6989 |
| N95 SCRAM/TLS | 5620 + 18227 | 4408 + 12487 | 2461 + 8443 | 493 + 759 | 3600 + 10298 |

Server-side backend fork cost (one fresh PG backend: fork + init + auth + exit, trust/plain): **≈2.0–2.8 ms CPU on the
i9 P-core, ≈7.0–10 ms on the N95**. The PG17 CancelRequest is handled in its own forked child: (discard −
discard-nocancel) ≈ 1.0–1.2 ms (i9) and ≈ 4.4–5.7 ms (N95). SCRAM adds ≈0.9–1.5 ms of **client** CPU (PBKDF2 4096
iterations, pure-Rust `postgres-protocol`) and little server CPU. TLS 1.3 (P-256, ECDSA) adds ≈0.4–2 ms client and
≈0.2–3 ms server CPU per handshake.
Even with PG on another host, the Monban-side cost alone of discard with SCRAM/TLS on an N95 core is 5.6–7.4 ms ⇒
**≈135–180 cancels/s per core, below 200**.

## Verdict against the flip rule
- `<200 cancels/s` fires: every 1-core (shared) configuration on both machines (laptop 115–266, N95 30–53).
  It also fires on the N95 when PG has its own core (48–79, PG-bound), and for the Monban-side CPU alone with
  SCRAM/TLS on the N95.
- `>20 ms p50` fires on the N95 shared core (21.7 / 25.5 / 37.7 ms) and on the contended N95 split TLS rerun (21.9 ms).
  It does not fire on the laptop (3.5–14 ms).
- ⇒ **flip to state-tracked reuse.** Reuse with a CancelRequest still fails 200/s on the N95 with TLS (74–82/s),
  because the CancelRequest is itself a TLS connection plus a fork. Only the no-CancelRequest variant (reuse-wait,
  ≈0.4–1.3 ms CPU per cancel) clears the budget on the weak box.

## Correctness risk of each option
**Discard (current NC3).** It has the lowest protocol risk: the next request gets a fresh session, and stray cancels
are harmless because the session is gone. Its risks are cost and DoS:
1. Each cancel costs a fork plus auth. An attacker's cancel storm becomes a fork storm on PG (the CPU above), and with
   SCRAM it is also a client CPU storm. This is mitigated only by NC4 cancel charging.
2. Without a CancelRequest, the orphan backend keeps running the statement, holding locks and a connection slot,
   until it finishes or `statement_timeout` fires. Under a storm that means R × remaining-time extra backends, and
   max_connections can be exhausted. With a CancelRequest you pay a second fork. Set `statement_timeout` = op budget
   and `client_connection_check_interval` (PG ≥14) as a cheaper orphan reaper.
3. TCP churn: we saw 1 s SYN-retransmit outliers (p99 ≈1.02–1.08 s) in rate runs on the N95. Ephemeral ports and
   TIME_WAIT accumulate.

**State-tracked reuse with CancelRequest (`reuse`).** Measured stray cancels. PG's CancelRequest is not tied to a
statement: it signals whatever the backend is running when the signal is processed. On kamrui (`race.sh`, 25k cycles,
trust/plain):
- with a 50 ms statement: 15 of 5000 resets were hit (the cancel aborted ROLLBACK, DISCARD ALL or the sentinel; this
  was detected and fell back to discard);
- with 1–3 ms statements cancelled at 1–2 ms: 6 resets were hit, and **3 of 15,000 cancels landed on the *next*
  request after the sentinel had passed** (its `BEGIN` failed with SQLSTATE 57014). Outside the race probe: laptop 0 in 42,392 reuse cycles; N95 suites
  1 reset hit in 16,843 (0 next-request hits).

A stray cancel fails safe under NC1 (the victim request fails, no mutation), but it is cross-request interference.
The pool is per tenant (R-DB-5), so one principal's cancel can fail another principal's request in the same tenant.
The sentinel cannot close this window. Do not use a CancelRequest on a connection that will be reused.

**State-tracked reuse without CancelRequest (`reuse-wait`, recommended).** It has no stray-cancel risk by construction
(0 errors, 0 reuse_fail in 13,586 cycles across both hosts). Its residual risks:
1. The connection is held out of the pool for the remaining statement time (bounded by `statement_timeout` = the op
   budget, ≤5 s). Under a storm the pool, not the CPU, is what gets exhausted, so NC4 must charge the held time.
2. Driver desync. Every outstanding reply must be drained to ReadyForQuery. tokio-postgres does this in its connection
   task; sqlx #4393 and diesel_async #304 did not.
3. `DISCARD ALL` invalidates server prepared statements and the driver caches that refer to them (tokio-postgres
   type-info cache: `clear_type_cache()`; any app or pool statement cache must be bumped by a session generation).
4. `DISCARD ALL` cannot run inside a transaction block, so ROLLBACK must come first. It does not cover COPY
   in progress, LISTEN-dependent logic in flight, or extension or dblink session state. In those states: discard.
5. The reuse decision must be made on server-reported state (ReadyForQuery txn byte = `I`), not on what the client
   believes.

## Reproduce
```
cd spikes/q3-008
./gen_certs.sh
(cd harness && CARGO_TARGET_DIR=$PWD/../target ../../../ci/heavy.sh cargo build --release --locked)
../../ci/heavy.sh ./suite.sh raw/laptop-i9-14900HX.jsonl postgres:17 8 10 2000 8
../../ci/heavy.sh ./extra.sh raw/laptop-extra.jsonl postgres:17 8 10 1000 8
# kamrui: copy suite.sh extra.sh race.sh pg.sh certs/ target/release/q3008 to ~/q3008-tmp, then
./suite.sh raw/kamrui-N95.jsonl postgres:17-alpine 2 3 1000 8
./extra.sh raw/kamrui-extra.jsonl postgres:17-alpine 2 3 1000 8
./race.sh  raw/kamrui-race.jsonl  postgres:17-alpine 2 3 5000
python3 summarize.py raw/*.jsonl
rm -rf target
```
The first suites (`laptop-i9-14900HX`, `kamrui-N95`) ran on a binary without the `reuse-wait` mode and without the
env knobs. Defaults (50 ms statement, cancel at 2 ms) are unchanged, so the rows are comparable.

## Limits
- Laptop and LAN box only (grade B cap). The laptop was heavily contended, and the later kamrui runs were contended by
  other agents' jobs. No real 1-vCPU VPS run.
- PG17 only (prefork). PG18's `ssl_groups` (X25519MLKEM768 hybrid) was not measured. Hybrid KEX would add client and
  server handshake CPU to every reconnect and CancelRequest, which strengthens the verdict.
- ECDSA P-256 server cert. RSA-2048 would add ≈1 ms of server CPU per handshake.
- No PgBouncer. A pooler in front of PG absorbs the backend fork (transaction mode) but still costs a client↔pooler
  TLS + SCRAM handshake per discard. It also changes CancelRequest semantics (the pooler forwards the cancel to the
  current server connection, where it can hit another client's statement), which is worse for the `reuse` variant.
- Workload: a single `pg_sleep` statement inside a txn. Real handlers with session state (prepared statements, SET
  LOCAL, temp tables) make DISCARD ALL slightly dearer, and `reuse-wait` latency equals the remaining statement time.
- The race mechanism (why an awaited CancelRequest can still land after the sentinel) was observed, not root-caused
  in PG source. The rate was 3 in 15k on a contended N95. The rate on other hardware is unknown.

## Raw results

### raw/laptop-i9-14900HX.jsonl

- host `patrickd-Legion-5-16IRX9`, CPU Intel(R) Core(TM) i9-14900HX, kernel 6.17.0-14-generic, governor powersave, image postgres:17, client cpu 8, server cpu 10, loadavg at start 23.50 23.19 20.53, 2026-10-25T09:10:50-04:00

| run | auth/tls | mode | n | rate/s | p50 ms | p90 ms | p99 ms | p99.9 ms | client CPU µs/cycle | server CPU µs/cycle | err | reuse_fail |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| lat-split c1 | trust/plain | connect | 2000 | 320 | 3.08 | 4.00 | 7.00 | 20.02 | 126 | 2759 | 0 | 0 |
| lat-split c1 | trust/plain | discard | 2000 | 112 | 4.87 | 6.92 | 15.49 | 38.93 | 230 | 4814 | 0 | 0 |
| lat-split c1 | trust/plain | discard-nocancel | 2000 | 130 | 3.00 | 5.92 | 12.01 | 51.02 | 157 | 3603 | 0 | 0 |
| lat-split c1 | trust/plain | reuse | 2000 | 164 | 1.95 | 5.86 | 8.00 | 29.48 | 142 | 1745 | 0 | 0 |
| lat-split c1 | SCRAM/plain | connect | 2000 | 280 | 3.12 | 4.82 | 7.72 | 14.25 | 1030 | 2397 | 0 | 0 |
| lat-split c1 | SCRAM/plain | discard | 2000 | 130 | 3.89 | 6.42 | 9.43 | 15.48 | 1213 | 3620 | 0 | 0 |
| lat-split c1 | SCRAM/plain | discard-nocancel | 2000 | 151 | 3.25 | 5.17 | 8.63 | 11.09 | 1070 | 2628 | 0 | 0 |
| lat-split c1 | SCRAM/plain | reuse | 2000 | 197 | 1.39 | 3.04 | 5.04 | 7.04 | 126 | 1319 | 0 | 0 |
| lat-split c1 | SCRAM/TLS1.3-p256 | connect | 2000 | 251 | 3.90 | 4.18 | 5.96 | 14.25 | 1393 | 2614 | 0 | 0 |
| lat-split c1 | SCRAM/TLS1.3-p256 | discard | 2000 | 114 | 5.40 | 7.09 | 11.17 | 16.59 | 1905 | 4672 | 0 | 0 |
| lat-split c1 | SCRAM/TLS1.3-p256 | discard-nocancel | 2000 | 121 | 4.78 | 7.28 | 10.87 | 15.84 | 1625 | 3714 | 0 | 0 |
| lat-split c1 | SCRAM/TLS1.3-p256 | reuse | 2000 | 152 | 2.82 | 5.36 | 10.36 | 13.56 | 650 | 2360 | 0 | 0 |
| rate-split c16 | trust/plain | connect | 3884 | 484 | 32.98 | 42.84 | 52.43 | 98.77 | 88 | 2055 | 0 | 0 |
| rate-split c16 | trust/plain | discard | 2379 | 295 | 52.05 | 64.56 | 69.01 | 73.69 | 173 | 3362 | 0 | 0 |
| rate-split c16 | trust/plain | reuse | 6694 | 831 | 11.52 | 42.59 | 55.05 | 64.64 | 104 | 1194 | 0 | 0 |
| rate-split c16 | SCRAM/plain | connect | 3339 | 415 | 38.05 | 44.95 | 62.26 | 72.33 | 1009 | 2220 | 0 | 0 |
| rate-split c16 | SCRAM/plain | discard | 2357 | 293 | 46.96 | 63.88 | 73.58 | 88.45 | 1089 | 3385 | 0 | 0 |
| rate-split c16 | SCRAM/plain | reuse | 7097 | 881 | 10.47 | 37.86 | 54.43 | 60.49 | 94 | 1125 | 0 | 0 |
| rate-split c16 | SCRAM/TLS1.3-p256 | connect | 3018 | 376 | 42.32 | 50.11 | 59.88 | 68.98 | 1351 | 2580 | 0 | 0 |
| rate-split c16 | SCRAM/TLS1.3-p256 | discard | 1817 | 225 | 63.10 | 86.39 | 101.64 | 111.41 | 1787 | 4410 | 0 | 0 |
| rate-split c16 | SCRAM/TLS1.3-p256 | reuse | 4601 | 572 | 23.75 | 35.05 | 44.52 | 52.39 | 418 | 1735 | 0 | 0 |
| rate-shared c16 | trust/plain | connect | 3429 | 427 | 36.47 | 42.58 | 48.84 | 56.16 | 97 | 2229 | 0 | 0 |
| rate-shared c16 | trust/plain | discard | 1521 | 189 | 57.63 | 113.94 | 179.70 | 192.70 | 191 | 4223 | 0 | 0 |
| rate-shared c16 | trust/plain | reuse | 1728 | 213 | 57.10 | 81.73 | 92.16 | 99.65 | 137 | 1997 | 0 | 0 |
| lat-shared c1 | trust/plain | discard | 2000 | 56 | 14.26 | 18.00 | 21.64 | 46.29 | 380 | 6615 | 0 | 0 |
| rate-shared c16 | SCRAM/plain | connect | 1888 | 234 | 72.79 | 84.22 | 88.23 | 367.86 | 1150 | 2933 | 0 | 0 |
| rate-shared c16 | SCRAM/plain | discard | 1344 | 167 | 66.28 | 93.69 | 502.49 | 516.64 | 1033 | 3693 | 0 | 0 |
| rate-shared c16 | SCRAM/plain | reuse | 4096 | 507 | 19.06 | 28.70 | 65.20 | 72.92 | 84 | 1339 | 0 | 0 |
| lat-shared c1 | SCRAM/plain | discard | 2000 | 68 | 6.94 | 24.40 | 55.73 | 126.43 | 1240 | 4821 | 0 | 0 |
| rate-shared c16 | SCRAM/TLS1.3-p256 | connect | 1824 | 227 | 62.53 | 82.88 | 101.20 | 101.39 | 1326 | 3064 | 0 | 0 |
| rate-shared c16 | SCRAM/TLS1.3-p256 | discard | 928 | 115 | 97.12 | 157.34 | 1052.57 | 1067.56 | 1749 | 5187 | 0 | 0 |
| rate-shared c16 | SCRAM/TLS1.3-p256 | reuse | 2224 | 276 | 34.33 | 49.35 | 356.26 | 377.24 | 416 | 2010 | 0 | 0 |
| lat-shared c1 | SCRAM/TLS1.3-p256 | discard | 2000 | 64 | 8.89 | 14.75 | 87.01 | 426.32 | 1949 | 5730 | 0 | 0 |

### raw/laptop-extra.jsonl

- host `patrickd-Legion-5-16IRX9`, CPU Intel(R) Core(TM) i9-14900HX, kernel 6.17.0-14-generic, governor , image postgres:17, client cpu 8, server cpu 10, loadavg at start 25.64 25.49 22.29, 2026-10-25T09:42:12-04:00

| run | auth/tls | mode | n | rate/s | p50 ms | p90 ms | p99 ms | p99.9 ms | client CPU µs/cycle | server CPU µs/cycle | err | reuse_fail |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| lat-split c1 | trust/plain | connect | 1000 | 489 | 1.94 | 2.02 | 5.00 | 7.00 | 67 | 1919 | 0 | 0 |
| lat-split c1 | trust/plain | discard | 1000 | 126 | 3.51 | 5.74 | 19.20 | 68.96 | 189 | 3883 | 0 | 0 |
| lat-split c1 | trust/plain | reuse | 1000 | 198 | 1.34 | 3.09 | 5.99 | 51.01 | 127 | 1496 | 0 | 0 |
| lat-split c1 | trust/plain | reuse-wait | 1000 | 19 | 47.25 | 50.91 | 70.02 | 119.16 | 146 | 229 | 0 | 0 |
| lat-split c1 | SCRAM/TLS1.3-p256 | connect | 1000 | 234 | 4.00 | 4.84 | 7.56 | 13.46 | 1425 | 2714 | 0 | 0 |
| lat-split c1 | SCRAM/TLS1.3-p256 | discard | 1000 | 111 | 5.56 | 7.80 | 13.93 | 18.89 | 1901 | 4611 | 0 | 0 |
| lat-split c1 | SCRAM/TLS1.3-p256 | reuse | 1000 | 174 | 2.24 | 4.08 | 9.41 | 13.01 | 525 | 1950 | 0 | 0 |
| lat-split c1 | SCRAM/TLS1.3-p256 | reuse-wait | 1000 | 20 | 47.46 | 49.20 | 51.78 | 54.08 | 148 | 304 | 0 | 0 |
| rate-shared c16 | trust/plain | connect | 3731 | 464 | 34.21 | 42.95 | 53.56 | 70.78 | 83 | 2058 | 0 | 0 |
| rate-shared c16 | trust/plain | discard | 2144 | 266 | 46.99 | 63.08 | 83.45 | 105.33 | 160 | 3573 | 0 | 0 |
| rate-shared c16 | trust/plain | reuse | 4976 | 619 | 18.66 | 22.52 | 36.16 | 79.23 | 74 | 1220 | 0 | 0 |
| rate-shared c16 | trust/plain | reuse-wait | 2368 | 293 | 49.71 | 54.69 | 56.91 | 57.35 | 40 | 98 | 0 | 0 |
| rate-shared c16 | SCRAM/TLS1.3-p256 | connect | 1983 | 246 | 64.30 | 66.67 | 69.29 | 86.67 | 1233 | 2796 | 0 | 0 |
| rate-shared c16 | SCRAM/TLS1.3-p256 | discard | 1088 | 135 | 95.83 | 134.91 | 168.58 | 171.21 | 1708 | 5223 | 0 | 0 |
| rate-shared c16 | SCRAM/TLS1.3-p256 | reuse | 2976 | 370 | 32.86 | 37.75 | 45.09 | 54.96 | 384 | 1872 | 0 | 0 |
| rate-shared c16 | SCRAM/TLS1.3-p256 | reuse-wait | 2336 | 290 | 50.33 | 55.07 | 57.28 | 58.53 | 57 | 134 | 0 | 0 |

### raw/kamrui-N95.jsonl

- host `patrickd-kamrui`, CPU Intel(R) N95, kernel 6.17.0-41-generic, governor powersave, image postgres:17-alpine, client cpu 2, server cpu 3, loadavg at start 0.44 0.49 0.73, 2026-10-25T09:10:43-04:00

| run | auth/tls | mode | n | rate/s | p50 ms | p90 ms | p99 ms | p99.9 ms | client CPU µs/cycle | server CPU µs/cycle | err | reuse_fail |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| lat-split c1 | trust/plain | connect | 1000 | 140 | 6.70 | 9.27 | 10.96 | 12.46 | 346 | 6989 | 0 | 0 |
| lat-split c1 | trust/plain | discard | 1000 | 52 | 11.80 | 24.91 | 49.13 | 62.99 | 743 | 13307 | 0 | 0 |
| lat-split c1 | trust/plain | discard-nocancel | 1000 | 94 | 7.13 | 10.35 | 13.89 | 14.57 | 554 | 8899 | 0 | 0 |
| lat-split c1 | trust/plain | reuse | 1000 | 200 | 1.37 | 2.79 | 4.34 | 11.16 | 450 | 4488 | 0 | 1 |
| lat-split c1 | SCRAM/plain | connect | 1000 | 123 | 7.95 | 9.55 | 11.75 | 15.04 | 1706 | 6967 | 0 | 0 |
| lat-split c1 | SCRAM/plain | discard | 1000 | 55 | 12.83 | 19.20 | 35.47 | 67.24 | 2355 | 13574 | 0 | 0 |
| lat-split c1 | SCRAM/plain | discard-nocancel | 1000 | 82 | 8.79 | 10.05 | 14.40 | 21.77 | 2134 | 9045 | 0 | 0 |
| lat-split c1 | SCRAM/plain | reuse | 1000 | 191 | 1.57 | 3.06 | 4.84 | 6.98 | 488 | 4730 | 0 | 0 |
| lat-split c1 | SCRAM/TLS1.3-p256 | connect | 1000 | 79 | 11.17 | 17.30 | 20.50 | 31.08 | 3600 | 10298 | 0 | 0 |
| lat-split c1 | SCRAM/TLS1.3-p256 | discard | 1000 | 46 | 17.14 | 22.64 | 28.25 | 39.14 | 5620 | 18227 | 0 | 0 |
| lat-split c1 | SCRAM/TLS1.3-p256 | discard-nocancel | 1000 | 58 | 13.11 | 17.18 | 24.50 | 42.83 | 4408 | 12487 | 0 | 0 |
| lat-split c1 | SCRAM/TLS1.3-p256 | reuse | 1000 | 91 | 6.78 | 10.16 | 21.06 | 41.07 | 2461 | 8443 | 0 | 0 |
| rate-split c16 | trust/plain | connect | 798 | 99 | 156.07 | 229.96 | 310.73 | 411.26 | 450 | 9910 | 0 | 0 |
| rate-split c16 | trust/plain | discard | 562 | 68 | 215.32 | 270.36 | 312.81 | 340.31 | 736 | 14475 | 0 | 0 |
| rate-split c16 | trust/plain | reuse | 2293 | 276 | 47.60 | 56.80 | 1019.56 | 1061.81 | 393 | 3585 | 0 | 0 |
| rate-split c16 | SCRAM/plain | connect | 1058 | 130 | 118.32 | 167.76 | 238.07 | 282.00 | 1889 | 7614 | 0 | 0 |
| rate-split c16 | SCRAM/plain | discard | 647 | 79 | 188.21 | 221.82 | 257.01 | 273.87 | 2170 | 12560 | 0 | 0 |
| rate-split c16 | SCRAM/plain | reuse | 2327 | 286 | 47.13 | 54.82 | 1025.90 | 1064.77 | 383 | 3446 | 0 | 0 |
| rate-split c16 | SCRAM/TLS1.3-p256 | connect | 811 | 100 | 160.13 | 188.95 | 230.87 | 280.10 | 3482 | 9973 | 0 | 0 |
| rate-split c16 | SCRAM/TLS1.3-p256 | discard | 397 | 48 | 305.88 | 369.69 | 418.18 | 428.11 | 7415 | 20617 | 0 | 0 |
| rate-split c16 | SCRAM/TLS1.3-p256 | reuse | 894 | 110 | 136.04 | 160.03 | 189.38 | 219.25 | 2577 | 9044 | 0 | 0 |
| rate-shared c16 | trust/plain | connect | 800 | 98 | 154.62 | 222.19 | 353.23 | 439.07 | 484 | 9624 | 0 | 0 |
| rate-shared c16 | trust/plain | discard | 442 | 53 | 278.71 | 351.82 | 410.83 | 432.78 | 934 | 17640 | 0 | 0 |
| rate-shared c16 | trust/plain | reuse | 1543 | 187 | 57.57 | 68.62 | 1040.04 | 1063.44 | 665 | 4579 | 0 | 0 |
| lat-shared c1 | trust/plain | discard | 1000 | 38 | 21.69 | 26.70 | 34.29 | 226.54 | 1399 | 20921 | 0 | 0 |
| rate-shared c16 | SCRAM/plain | connect | 520 | 64 | 251.51 | 310.17 | 362.21 | 418.31 | 2729 | 12836 | 0 | 0 |
| rate-shared c16 | SCRAM/plain | discard | 322 | 39 | 384.13 | 430.59 | 467.95 | 483.86 | 3477 | 22127 | 0 | 0 |
| rate-shared c16 | SCRAM/plain | reuse | 1592 | 179 | 56.20 | 67.55 | 1051.68 | 1069.05 | 638 | 4837 | 0 | 0 |
| lat-shared c1 | SCRAM/plain | discard | 1000 | 33 | 25.48 | 31.67 | 43.31 | 127.28 | 3540 | 21001 | 0 | 0 |
| rate-shared c16 | SCRAM/TLS1.3-p256 | connect | 371 | 45 | 353.01 | 415.78 | 504.04 | 524.90 | 5204 | 16768 | 0 | 0 |
| rate-shared c16 | SCRAM/TLS1.3-p256 | discard | 244 | 30 | 467.72 | 610.67 | 703.65 | 830.34 | 7602 | 26062 | 0 | 0 |
| rate-shared c16 | SCRAM/TLS1.3-p256 | reuse | 676 | 82 | 182.14 | 237.37 | 283.21 | 316.54 | 2646 | 9440 | 0 | 0 |
| lat-shared c1 | SCRAM/TLS1.3-p256 | discard | 1000 | 23 | 37.74 | 45.29 | 72.36 | 110.44 | 8558 | 28076 | 0 | 0 |

### raw/kamrui-extra.jsonl

- host `patrickd-kamrui`, CPU Intel(R) N95, kernel 6.17.0-41-generic, governor , image postgres:17-alpine, client cpu 2, server cpu 3, loadavg at start 4.42 5.57 5.43, 2026-10-25T09:46:13-04:00

| run | auth/tls | mode | n | rate/s | p50 ms | p90 ms | p99 ms | p99.9 ms | client CPU µs/cycle | server CPU µs/cycle | err | reuse_fail |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| lat-split c1 | trust/plain | connect | 1000 | 97 | 10.09 | 11.81 | 14.05 | 17.22 | 488 | 10023 | 0 | 0 |
| lat-split c1 | trust/plain | discard | 1000 | 55 | 14.23 | 16.73 | 19.29 | 23.80 | 951 | 15721 | 0 | 0 |
| lat-split c1 | trust/plain | reuse | 1000 | 136 | 3.79 | 5.50 | 10.29 | 25.73 | 822 | 7054 | 0 | 0 |
| lat-split c1 | trust/plain | reuse-wait | 1000 | 20 | 47.69 | 48.08 | 49.91 | 50.77 | 404 | 605 | 0 | 0 |
| lat-split c1 | SCRAM/TLS1.3-p256 | connect | 1000 | 65 | 14.66 | 17.55 | 21.39 | 32.50 | 4334 | 12853 | 0 | 0 |
| lat-split c1 | SCRAM/TLS1.3-p256 | discard | 1000 | 38 | 21.87 | 26.00 | 33.84 | 41.99 | 6705 | 22255 | 0 | 0 |
| lat-split c1 | SCRAM/TLS1.3-p256 | reuse | 1000 | 86 | 7.71 | 10.93 | 15.66 | 33.49 | 2805 | 9548 | 0 | 0 |
| lat-split c1 | SCRAM/TLS1.3-p256 | reuse-wait | 1000 | 20 | 47.84 | 48.55 | 50.05 | 50.94 | 493 | 759 | 0 | 0 |
| rate-shared c16 | trust/plain | connect | 744 | 91 | 175.14 | 228.31 | 297.09 | 385.65 | 508 | 10257 | 0 | 0 |
| rate-shared c16 | trust/plain | discard | 421 | 51 | 301.25 | 346.70 | 376.52 | 383.27 | 1000 | 18324 | 0 | 0 |
| rate-shared c16 | trust/plain | reuse | 1916 | 216 | 50.26 | 61.10 | 1040.57 | 1078.18 | 480 | 4084 | 0 | 0 |
| rate-shared c16 | trust/plain | reuse-wait | 2474 | 307 | 47.99 | 49.17 | 51.02 | 73.83 | 207 | 413 | 0 | 0 |
| rate-shared c16 | SCRAM/TLS1.3-p256 | connect | 488 | 60 | 263.93 | 316.87 | 376.27 | 395.82 | 4131 | 12474 | 0 | 0 |
| rate-shared c16 | SCRAM/TLS1.3-p256 | discard | 284 | 34 | 439.66 | 494.60 | 538.89 | 558.45 | 6815 | 22636 | 0 | 0 |
| rate-shared c16 | SCRAM/TLS1.3-p256 | reuse | 602 | 74 | 204.06 | 245.11 | 283.45 | 307.12 | 2996 | 10489 | 0 | 0 |
| rate-shared c16 | SCRAM/TLS1.3-p256 | reuse-wait | 2408 | 298 | 48.52 | 49.98 | 52.63 | 66.08 | 303 | 583 | 0 | 0 |

### raw/kamrui-race.jsonl


| run | auth/tls | mode | n | rate/s | p50 ms | p90 ms | p99 ms | p99.9 ms | client CPU µs/cycle | server CPU µs/cycle | err | reuse_fail |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| race-s50-a2 c1 | trust/plain | reuse | 5000 | 110 | 5.16 | 7.87 | 15.31 | 26.59 | 995 | 8197 | 0 | 15 |
| race-s3-a2 c1 | trust/plain | reuse | 4999 | 116 | 4.59 | 8.77 | 12.51 | 17.70 | 984 | 8352 | 1 | 2 |
| race-s2-a2 c1 | trust/plain | reuse | 4999 | 116 | 4.55 | 8.15 | 11.66 | 17.83 | 962 | 8374 | 1 | 2 |
| race-s2-a1 c1 | trust/plain | reuse | 4999 | 118 | 5.05 | 9.21 | 13.68 | 36.68 | 937 | 8065 | 1 | 2 |
| race-s1-a1 c1 | trust/plain | reuse | 5000 | 132 | 4.57 | 8.59 | 12.57 | 20.63 | 851 | 7430 | 0 | 0 |

`race` rows: `err` = the next cycle's request on the reused connection failed with 57014 (stray cancel after the sentinel); `reuse_fail` = the reset sequence itself was cancelled (detected; fell back to discard). Files: `raw/*.jsonl` (one JSON per run, plus meta lines), `raw/*.log` (stderr).
