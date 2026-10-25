# Spike q2-013: Kani/Verus RAM (R-FORMAL-2)

**Verdict: keep.** Every representative F5 obligation fits the 6 GB CI cap with a wide margin. The largest peak was
2.09 GB, and that came from a deliberately heavy control. The real obligations peaked at 0.37 GB or less. Kani built
from main ≥ PR #4910 fails closed on OOM and on timeout: 0 false passes in 4 runs. What limits us is **solver time**,
not RAM. Two obligation shapes time out: unrolled traces, and invariants that need `T*(a+b) = T*a + T*b`. So the gate
needs an obligation-shape rule for Kani, not a bigger runner.

Grade B: measured on the LAN box **kamrui** (Intel N95, 4 cores, 14 GB, Ubuntu 25.10), standing in for the CI
prover box.

## Toolchains (all user-space under `~/aegis-ci` on kamrui, no sudo)
| tool | pin | install | disk |
|---|---|---|---|
| Kani | main `9461e07af7ec` (2026-10-14). PR #4910 (merge `16c774cf`, 2026-09-30) verified as an ancestor (`raw/setup.log`) | `cargo build-dev -- --release`: 7 min 10 s, max RSS 1.36 GB, cgroup peak 2.63 GB | runtime 2.25 GB (nightly-2026-10-12 1.6 GB + `target/kani` 442 MB + CBMC 212 MB); build tree +1.12 GB; source 142 MB |
| CBMC | 6.11.0 (what `kani-dependencies` requires), ubuntu-24.04 .deb extracted with `dpkg-deb -x` | — | 212 MB |
| Verus | release/0.2026.10.18.7d82994 (the pinned one), Z3 4.16.0 | prebuilt zip | 1.6 GB + rustc 1.99.1 minimal 593 MB = **2.2 GB** (REPO_LAYOUT says 3.16 GB) |

What PR #4910 fixes (#4905): when CBMC hits `bad_alloc` while writing `--json-ui` it closes the JSON cleanly and exits
6. Release 0.68.0 ignored that status whenever a result array existed, so a truncated list could print
`VERIFICATION:- SUCCESSFUL`. Since #4910 the driver accepts a result array only on exit 0 or 10 (or 6 with an ERROR
property). Anything else, signals included, is a FAIL, and "Out of memory" maps to `ExitStatus::OutOfMemory`.

**Gate gotcha:** the main build still reports `Kani Rust Verifier 0.68.0`. The version string cannot tell the fixed
build from the broken release, so the gate has to check the recorded commit by git ancestry.

## Harnesses
`harness/kani/budget.rs` covers the TBI-9 RST bucket (burst 100, refill 33/s, u64 ns time, fixed point
1 token = 1e9 token-ns, saturating refill, clamp at CAP) and the GCRA admit with I1/I2. `harness/kani/oom.rs` has a
real failing assertion placed after a memory-heavy bubble sort. `harness/verus/permit_ledger.rs` is the
per-connection permit ledger: ghost `Multiset<u64> permits_out`, invariant `|permits_out| + available == S` (S = 100),
unique unforgeable ids, queue ≤ 400, acquire / release / enqueue / dequeue_and_start, and a looping `burst`.

All runs used `scripts/heavy.sh` (installed as `~/aegis-ci/bin/heavy`): MemoryMax=6G, swap off, nice 15, and a
timeout (1800 s by default; shorter where stated). "peak" below is cgroup `memory.peak` for the whole process tree.

| obligation | result | wall | peak |
|---|---|---|---|
| Kani `rst_step_inductive` (any state with inv, any time: inv kept, no overflow, minted ≤ RATE·dt, backwards clock mints 0) | OK | 1.3 s | 40 MB |
| Kani `rst_rate_bound_trace` (N=6, accepted ≤ BURST + RATE·elapsed) | OK | 2.9 s | 46 MB |
| Kani `gcra_step` (I2 per key, TAT monotone, deny leaves state alone, `tat−now ≤ τ+T·c`) | OK | 12.5 s | 43 MB |
| Kani `gcra_window_inductive_credit` (I1 inductive, ghost credit = Σ T·cost, symbolic T, τ) | OK | 495 s | 68 MB |
| Kani `gcra_window_bound_trace` (I1 unrolled, symbolic T) | TIMEOUT at N=6 (1800 s) and N=2 (900 s) | — | 167 MB |
| Kani `gcra_window_bound_trace_fixed_t` (T = 30,303,030 ns) | N=2 OK in 32 s; N=3 and N=4 TIMEOUT (900 s) | — | ≤ 66 MB |
| Kani `gcra_window_inductive[_fixed_t]` (I1 inductive via T·sum) | TIMEOUT (1500 s / 900 s) on a 13,240-variable, 66,574-clause instance | — | ≤ 93 MB |
| Verus `permit_ledger.rs` | 10 verified, 0 errors | 1.6 s | 224 MB (max RSS 365 MB) |

Mutation controls: dropping the CAP clamp makes both RST harnesses FAIL (`b.inv()`). `permit_ledger_mutant.rs`
(release does not return the permit) fails 1 postcondition.

### Kani exit codes under forced OOM (`scripts/oom-test.sh`, `raw/oom*.txt`)
| case | Kani output | exit |
|---|---|---|
| cgroup MemoryMax=150M, OOMPolicy=continue (CBMC OOM-killed, `oom_kill 1`) | "CBMC appears to have run out of memory", `VERIFICATION:- FAILED` | 1 |
| cgroup 150M, OOMPolicy=stop (systemd default) | same message, then systemd tears the scope down | 143 |
| `ulimit -v 400MB` on CBMC only (`scripts/cbmc-ulimit/cbmc`): `bad_alloc` inside CBMC, the #4905 path | "Out of memory", `FAILED` | 1 |
| positive control K=8 at 6 GB | `FAILED`, failed check "real bug" | 1 |
| heavy control K=32 at 6 GB | no verdict in 1500 s | 124 (timeout) |

No case printed SUCCESSFUL. On a CI box using systemd scopes, 143 and 124 also have to count as FAIL. They do under
the rule "exit ∉ {0} ⇒ FAIL".

## Why the GCRA variants time out
These runs are small in memory (at most 167 MB) but CDCL makes no progress on them. The unrolled I1 trace, and the
inductive I1 stated through `T·sum`, both need distributivity of a bit-blasted multiplier (`T·(sum+c) = T·sum + T·c`),
which SAT solvers handle badly. Stating I1 in emission-time units fixes it: keep a ghost `credit += T·cost` per
admission, so the invariant needs only additions plus one `T·cost` with cost ≤ 64. That version proves the same
window bound for **every** N in 8 min. Proposed rule for VERIFICATION_PLAN §2, F5 row: *Kani obligations are
single-step inductive lemmas over symbolic state; window bounds are stated in emission-time units; no unrolled trace
harnesses; symbolic×symbolic multiplication only when one factor is ≤ 8 bits.*

## Other findings for the gate (VERIFICATION_PLAN §3)
- Step 8: check Kani "main ≥ #4910" by git ancestry of the recorded commit, not by version (see above).
- Step 9: `-V check-erasure` is **not an option** in Verus 0.2026.10.18 ("unexpected extended option"). The erasure
  check runs by default and the opt-out is `--no-erasure-check`, so the gate should deny that flag instead.
- This Verus release uses the new mutable-reference syntax: postconditions must say `final(self)` or `old(self)`, and
  bare `self` is rejected. The multiset lemmas come in through
  `broadcast use vstd::multiset::group_multiset_axioms, group_multiset_properties`. Spec authors will need this.

## Reproduce (kamrui)
```
~/aegis-ci/bin/setup-toolchains.sh     # rustup, Verus zip, CBMC deb, Kani clone at the pinned commit
~/aegis-ci/bin/build-kani.sh
~/aegis-ci/bin/run-kani.sh rst_step_inductive rst_rate_bound_trace gcra_step gcra_window_inductive_credit
~/aegis-ci/bin/run-verus.sh
ROUND=1 ~/aegis-ci/bin/oom-test.sh; ROUND=2 ~/aegis-ci/bin/oom-test.sh
~/aegis-ci/bin/scale-gcra.sh           # timeouts are expected (they are the finding)
```
Work dir: `~/aegis-ci/work/q2-013`. The scripts here are the exact copies installed in `~/aegis-ci/bin`. The
work-dir copy of `budget.rs` was edited incrementally during the spike; the final file is identical to
`harness/kani/budget.rs`.

## kamrui footprint (left in place as the CI prover box)
`~/aegis-ci` = **9.6 GB**: rustup 2.1 GB (nightly-2026-10-12 1.6 GB, 1.99.1 593 MB), cargo 167 MB, Verus 1.6 GB,
CBMC 212 MB, Kani source + build 1.7 GB, elan/Lean v4.34.1 3.0 GB and cedar-spec 514 MB (spike cedar-axioms),
downloads 535 MB (deletable). Disk free afterwards: 769 GB.

## Limits
- 4 Kani and 1 Verus obligations, not the first 10 real ones. The Verus ledger is small (no maps, no collection of
  connections), so Verus RAM on large ledgers is still an extrapolation, though far from 16 GB.
- The release-0.68.0 false pass was not reproduced as a control; fail-closed behaviour is shown only for the pinned
  main build. Whether CBMC exited with status 6 in the ulimit case is inferred from Kani's message.
- Some timed runs overlapped with one other CBMC job on the 4-core box, so wall times are upper bounds. Kani's max RSS
  (≤ 179 MB) is dominated by kani-compiler.
- LAN box, one host: grade B.
