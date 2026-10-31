# P5-wasm-002: blocked by write scope (no check weakened)

Unit P5-wasm-002 (gate `p2-hostile-worker`). Base f29d17f. Spec: F14 Parts 1–2, SPEC §H I1/I2, R-ISO-2, PLAN D13,
D15, D17, D18, D20.

## What is done inside the write scope

`crates/aegis-wasm/src/abi/**` now holds the whole F14 worker side:

- the static check (`check_module`), refusing non-F14 imports before instantiation;
- the frame codec (`frame`), the I5 header rules (`headers`), and the host functions with per-request
  generation-tagged handles and the five quotas (`host`);
- `F14Worker`/`Session` (`serve`): a fresh Store per request, fuel and epoch armed before instantiation, the limiter,
  cancel, and out-of-order frames ending the session;
- the five worker mutants (`mutant`).

`crates/aegis-wasm/tests/abi.rs` has 18 tests (19 with `test-hooks`).

## Why the gate cannot pass from this scope alone

1. **The worker binary must call the new code.** `crates/aegis-p2/src/zygote.rs` still serves through
   `aegis_wasm::Worker`, which has no host functions. Owner: P5-iso-002 (passed, closed; P5-iso-003 owns
   `main.rs` and `cordon.rs`, not `zygote.rs`).
   - Fix: `patches/aegis-p2-zygote.patch` (`git apply` on f29d17f). It switches the fork child to
     `F14Worker::session(..).serve_one(arm ITIMER_REAL)` and drops zygote.rs's private codec, which now lives in
     `abi::frame`.
   - It also adds the two binary-side mutant hooks that only the binary can express:
     - `no-fuel-no-epoch` also drops ITIMER_REAL (`Spec::mutant_no_deadline`);
     - `no-limiter` sizes the pooled slot at the F8 maximum. Otherwise the pool at `memory_mib` still caps growth,
       and the mutant cannot be told apart from golden.
2. **The cordon path.** Every worker case runs on both paths. `aegis-p2 cordon` exits 78 until P5-iso-003, so the
   gate's 21 runtime cordon cells fail, and handle-not-cleared can only go red on a cordon.
   - `patches/aegis-p2-cordon-sketch.patch` (apply it after the zygote patch) is a minimal cordon used only to
     verify the cordon cells: load, sandbox, epoch ticker after the sandbox install, accept, then
     `Session::serve_all`.
   - It is guidance for P5-iso-003, not a proposal to bypass it. It has no registry, crash budget or idle reaping.
3. **Oracle defect (integrator, `oracles/`).** `mutants` builds send the D8 `layout` frame (integrator note: needed
   by p2-e2e). `oracles/hostile-modules/hostile.py` `exchange()` treats it as "frame for unknown req-id None".
   - Effect: under any mutant, every zygote cell turns red for that reason (100 of 112 red cells in the measured
     self-test). The self-test is therefore vacuous on the zygote path.
   - Fix: `patches/hostile-modules-layout.patch` accepts one layout frame before any other frame of an exchange.

## Measured (laptop, Linux 6.17.0-14; desktop for cargo test)

Unless a row says "as committed", it uses the zygote patch applied locally, not committed.

| run | result | load |
|---|---|---|
| gate cmd, as committed | FAIL 26 ok / 42 failed: only the 13 must-refuse cases pass, on both paths. zygote.rs still links the import-free `aegis_wasm::Worker`, and cordon exits 78. | 30.1 |
| gate cmd, both paths (no cordon) | FAIL 47 ok / 21 failed: 34 zygote ok + 13 refused cordon cells ok; all 21 runtime cordon cells fail with "cordon: not implemented yet (P5-iso-003)" | 4.58 |
| gate cmd `--paths zygote` | PASS 34/34 | 30.3 |
| gate cmd, both paths, + cordon sketch | PASS 68/68 | 11.8 |
| gate selftest, + cordon sketch, unmodified oracle | PASS. But every zygote mutant cell is red only on the layout frame; the cordon cells are red on exactly the expected case: extra-import import-host-fault, handle-not-cleared previous-request, no-hostcall-quota hostcall-flood, no-fuel-no-epoch fuel + loop, no-limiter memory-bomb | 26–61 |
| gate selftest, + cordon sketch, layout-tolerant oracle | PASS. Control 68/68 green. Red cells: extra-import 2, handle-not-cleared 1, no-hostcall-quota 2, no-fuel-no-epoch 4, no-limiter 2 (memory-bomb on both paths). No other cell is red. | 4.4 |
| `ci/remote.sh ci/heavy.sh cargo test --locked -q -p aegis-wasm` | abi 18/18, engine 10/10 (test-hooks: 19 + 10; mutants: 18 + 10) | 0.3–1.7 (desktop) |

no-limiter reaches 2 cells, not the reference's 6. In the real worker, `w-i2-memory-initial` is refused at compile
time (wasmtime checks the module against the pooling limits) and `w-i2-table-bomb` is capped by the pool's table
size. Both are golden bounds that remain when the limiter is gone, not a gap in the mutant.

## Minimal resolution

The integrator applies `aegis-p2-zygote.patch` (or assigns zygote.rs to this unit) and `hostile-modules-layout.patch`.
P5-iso-003's cordon calls `F14Worker::session(conn).serve_all()` after sending `frame::ready`. The gate is then
expected to pass as measured above with the sketch.
