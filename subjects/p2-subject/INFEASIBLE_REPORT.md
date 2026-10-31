# P5-iso-003: the MPK cell is blocked by write scope only (two patches supplied)

No check, threshold, oracle or limit was weakened. Everything in P5-iso-003's acceptance is green on the committed
tree except the MPK run of p2-fault-cordon. That run needs two small changes in files outside this unit's write
scope. Both are supplied as patches under `subjects/p2-subject/patches/`. With them applied, the MPK cell passes.

## Spec clause

- `units/phase-5/P5-iso-003.json` acceptance: `oracles/isolation-fi/run --trials 3 --path cordon --subject
  'target/p2/release/p2-subject serve cordon --threads 64 --mpk {guest} {data}'` must PASS ("with and without MPK").
- PLAN-5 D11: MPK (`memory_protection_keys`) is a density option. The reservation and guards stay unchanged.
  `supply-chain/wasmtime-config.toml [effective_mpk]` sets only `memory_protection_keys = "yes"`, with the same
  64-slot pool.

## Failing case on the committed tree (laptop, Linux 6.17.0-14, Landlock ABI 7, i9-14900HX with PKU)

1. **The seccomp filter kills the cordon on its first request.** With MPK, wasmtime 50.0.1 calls
   `pkey_mprotect(2)` (x86_64 nr 329) on every instance allocation. `strace -f` shows `mmap(MAP_FIXED, memfd)` and
   then `pkey_mprotect(..., PROT_READ|PROT_WRITE, 1)` right before `+++ killed by SIGSYS +++`. pkey_mprotect is not
   in `crates/aegis-iso/src/sandbox/filter.rs` `ALLOWLIST`. Its 128 calls at pool creation and the `pkey_alloc`
   calls all happen before `sandbox::install`, so only the per-instance calls hit the filter. Result: `isolation-fi
   ... --mpk`: `FAIL (cordon: baseline error: server not ready)`. Measured at load 5-7 (`--trials 3`) and at load
   53 (`--trials 1`).
2. **With the filter fixed, healthy requests still fail at the MPK stripe limit.** wasmtime splits the 64-slot pool
   into one stripe per protection key (16 here, so 4 slots each) and gives each new Store the next stripe, round
   robin. A stripe that already holds 4 live instances refuses the next one: `maximum concurrent limit of 4 for
   memory stripe 7 reached` (PoolConcurrencyLimitError). `FiWorker::instance` maps that to a trap, so the oracle
   counts a healthy failure. Result: `isolation-fi --trials 1 ... --mpk` with only the filter patch: `FAIL G0
   baseline healthy_fail=8; G1 panic 0.618, abort 1.179, segv 0.323, loop 0.212, oom 0.077, poison 0.579 > 0.05`
   (load 8-12).

## Minimal resolution (patches supplied, not applied)

- `patches/P5-iso-003-filter-pkey_mprotect.patch`: in `crates/aegis-iso/src/sandbox/filter.rs`, add
  `nr::PKEY_MPROTECT = 329` to `ALLOWLIST`, with a comment. A process can only use pkey_mprotect on its own mappings,
  with keys it already holds. pkey_alloc stays denied after install, so this gives no more power than mprotect. The
  DENYLIST is unchanged and so are the child filter and the clone/prctl/setsockopt rules. The aegis-iso tests (all
  of them, sandbox_filter included) pass with it, and so does clippy.
  Owner: P5-iso-001 (done). Not in any open unit's scope.
- `patches/P5-iso-003-aegis-wasm-mpk-stripe-retry.patch`:
  - `engine/mod.rs` gets `is_pool_full(&wasmtime::Error)` and `pool_retry_limit(&P2Engine)`. The limit is the pool
    size with MPK and 0 without.
  - `Worker::handle` (`store/mod.rs`) and `FiWorker::instance` (`fi.rs`) drop a Store whose stripe is full and try a
    new Store, which gets the next stripe. They try at most `pool_retry_limit` times.
  - No guest code runs before the pool hands out a slot, and the effective engine configuration is unchanged.
  - Without MPK the retry limit is 0, so behaviour does not change.
  - aegis-wasm tests pass with the patch (test-hooks, 10/10, desktop), and so does clippy -D warnings
    (test-hooks + mutants).
  - Owners: `engine/mod.rs` and `store/mod.rs` belong to P5-wasm-001 (done). **`fi.rs` belongs to P5-wasm-002 (PLAN
    D20), which runs in parallel.** That file is reported here, not edited.

## Evidence with both patches applied (uncommitted build in target/p2-patched, deleted afterwards)

`isolation-fi --trials 3 --path cordon --subject '<patched p2-subject> serve cordon --threads 64 --mpk ...'`:
`ISOLATION-FI: PASS`, with 0 healthy failures and 0 wrong answers on the six gated classes. Recovery p99: oom 3108 us,
loop 1145 us. Loop throughput x0.68. Load average 7.6 at start, 7.4 at end.

## Investigated and not the cause

- **EpochTicker catch-up.** I suspected it of firing deadlines early, but it does not. The failing calls really
  lasted 110-127 ms of wall time after only 22 fuel units, and capping the catch-up at 5 ticks changed nothing.
  No patch is proposed.
- **What actually caused the stalls: idle-thread churn in the cordon.** 64 threads parked in accept() for 16
  clients, on one pinned core, stalled running requests for more than 100 ms. That was fixed inside this unit's
  scope: `aegis_iso::cordon::serve` starts threads on demand, up to `--threads`.
