# P5-iso-002: blocked on one aegis-wasm addition outside the write scope

## Spec clause

- `units/phase-5/P5-iso-002.json` acceptance: `oracles/isolation-fi/run ... --subject 'target/p2/release/p2-subject
  serve forkwasm {guest} {data}'` (gate p2-fault-forkwasm) and its `--mutant-subject` self-test.
- `oracles/isolation-fi/README.md`, "Real subject contract": the p2-subject runs the oracle's guest, which exports
  `handle(id, fault) -> u32` and imports `env.host_fault(code)`. It must honour codes 1 (abort the serving process) and
  2 (corrupt that process's later replies).
- PLAN-5 "Roles": p2-subject has path dependencies only (aegis-iso, aegis-wasm), never wasmtime directly.

## Failing case

With the committed tree alone, p2-subject cannot run that guest:

- `aegis_wasm::Worker` (P5-wasm-001) runs only the F14 shape, `handle() -> i32`. It has no way to pass `(id, fault)`.
- `abi::define_imports` defines no host function, so a module that imports `env.host_fault` cannot be linked.
- `cwasm::compile` refuses every module that is not F14.
- aegis-wasm does not re-export wasmtime, so no path-only crate can build a Linker or Store itself.
- `crates/aegis-wasm/**` belongs to P5-wasm-001 (done) and P5-wasm-002 (`abi/**`, which depends on this unit). It is
  outside P5-iso-002's write scope.

Without an addition to aegis-wasm, p2-subject cannot serve the guest at all, so the gate cannot be met.

## Minimal resolution (patch supplied, not committed)

`subjects/p2-subject/aegis-wasm-fi.patch` adds `crates/aegis-wasm/src/fi.rs` and one cfg'd line in
`crates/aegis-wasm/src/lib.rs`:

- `#[cfg(feature = "test-hooks")] pub mod fi;`, so golden builds do not change. D15 already reserves
  `env.host_fault` for test-hooks builds, and gate wasmtime-config still passes.
- `#![forbid(unsafe_code)]`, no new dependency. Loading goes through the existing digest-checked `cwasm::load`, which
  is still the crate's single unsafe site.
- `fi::compile` checks the fault-injection shape: the only import allowed is `env.host_fault: [i32] -> []`, and the
  module must export `handle: [i32 i32] -> [i32]`.
- `FiWorker` uses the same P2Engine. Each call gets a fresh Store and instance. The limiter, fuel and epoch deadline
  are armed before instantiation, the same way `Worker::handle` does it.
- `env.host_fault`: code 1 calls abort(3), code 2 sets a process-wide flag that `fi::host_corrupted()` reports, and
  any other code traps. These are the F14 test-import semantics.
- `call_on` exists only under `mutants`, for the reuse-instance negative control.

To apply it: `git apply subjects/p2-subject/aegis-wasm-fi.patch`, then re-lock. The re-lock adds one path-only line
(`"aegis-wasm"` in p2-subject's dependency list in Cargo.lock) and changes no third-party version.

## Evidence with the patch applied

These results come from this worktree with the patch applied (uncommitted) and the one-line local re-lock, on the
laptop (i9-14900HX, Linux 6.17.0-14, Landlock ABI 7) on 2026-10-31. Load averages are in brackets.

| step | result |
|---|---|
| `CARGO_TARGET_DIR=target/p2 ... build --locked -p p2-subject`, then `-p aegis-p2` (two invocations, D18) | exit 0 |
| `CARGO_TARGET_DIR=target/p2-mutants ... -p p2-subject --features p2-subject/mutants` | exit 0 |
| `isolation-fi --trials 3 --path forkwasm` (gate timing mode) [5.0] | `ISOLATION-FI: PASS (forkwasm; 8 fault classes at 1%; 3 trial(s) per cell; 21s)`. No retries. 0 healthy failures and 0 wrong answers in every cell. Recovery p99 (us): panic 685, abort 851, segv 681, loop 1700, oom 3112, poison 518, hostabort 712, hostpoison 687. Loop throughput x0.905. 72-100 faults injected per class |
| `isolation-fi --self-test --path forkwasm --subject ... --mutant-subject ...` [8.6] | PASS, 3/3 caught. no-fork: G2 hostpoison 983 wrong. no-deadline: G4 loop x0.192, G3 unrecovered. reuse-instance: G2 poison 188 wrong and G2 hostpoison 52 wrong. Both controls PASS |
| `isolation-fi --self-test` (reference, part of the gate selftest) [8.5] | PASS, 7/7 |
| `syscall-negative --subject 'target/p2/release/p2-subject probe'` [9.3] | PASS, 77 cells, 5 masked controls |
| `syscall-negative --subject 'target/p2-test/release/aegis-p2 probe'` (gate form) [8.8] | PASS, 77 cells |
| `syscall-negative ... aegis-p2 probe' --path forkwasm` (the acceptance literal) | exit 2. synneg.py has no `--path` option ("unrecognized arguments"). The gate cmd does not pass it |
| `syscall-negative --self-test` | PASS, 7/7 |
| child filter install cost per fork (`p2-subject forkcost --n 3000`, 2 runs) [4.6] | install p50 21.8/21.7 us, p99 25.3/25.6 us. fork + fresh instance + call: p50 167/169 us with the filter, 148/149 us without |

An earlier `--trials 3` run at load 8 to 53 also passed, with several timing-only re-drives. Its worst cell was
panic recovery p99 3803 us.

## Acceptance-command defects (spec side, recorded only)

1. The acceptance builds `-p p2-subject -p aegis-p2` in one cargo invocation. PLAN D18 (integrator, after W1) forbids
   this, because feature unification would put aegis-iso/aegis-wasm `test-hooks` into the shipped aegis-p2. The runs
   above use the D18 split. The gate cmd in gates/phase-5.toml already builds p2-subject alone.
2. The last command appends `--path forkwasm` to `oracles/syscall-negative/run`, which rejects the option (exit 2).
   The gate form, without `--path`, passes on all three stages.
