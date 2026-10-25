# swarm-sim: round-3 swarm simulator + C1–C12 acceptance table (ADVISORY, record_only)

> **Every number this oracle prints or this file quotes is grade D: uncalibrated, simulator-only, and fitted
> in-sample on the same seeds it is reported on.** This is the `swarm-sim` gate in IMPLEMENTATION_PLAN §4
> (`pass: "record_only"`, "ADVISORY until calibrated [D]"). It never blocks a phase. The blocking admission checks
> are in `oracles/admission-props`.

```
oracles/swarm-sim/run                                   # TUNED (ARCHITECTURE §3.4 table), 10 scenarios x seeds 1..10
oracles/swarm-sim/run --configs TUNED,R2,PERIP          # also the round-2 defaults and the per-IP-only baseline
oracles/swarm-sim/run --seeds 3 --scenarios mixed,baseline
oracles/swarm-sim/run --self-test
```
Run it through `ci/heavy.sh`: the default panel takes 1–3 min, and `TUNED,R2,PERIP` takes much longer because the
PERIP sims have unbounded concurrency.

## Pass criterion (what PASS means)

`SWARM-SIM: PASS (advisory: record_only)` means three things. The panel completed. The same panel run in **two
fresh interpreter processes at once** produced byte-identical canonical JSON (same seed ⇒ same output sha256;
separate processes also expose `hash()` randomization). The acceptance table was printed. It does **not** mean the
admission design meets C1–C12. The table is recorded, never gated.
`SWARM-SIM: FAIL (...)` means only: a worker crashed, or the output hashes differed (nondeterminism).

`--subject` is reserved and fails for now. The sim models the pipeline in Python. Driving the real Rust pipeline
under the simulator is part of v2.

## Self-test

1. Control: `TUNED` × {baseline, mixed} × seeds {1,2} in two processes must hash-equal.
2. Mutant `time`: wall-clock nanoseconds mixed into the RNG seed. The determinism check must FAIL.
3. Mutant `hash`: the per-scenario seed is mixed with `hash(scenario_name)`, which is randomized per interpreter
   under `-I`. The determinism check must FAIL.
4. Broken defence: `BROKEN` = TUNED without the expensive-tier aggregates, without the fresh class and without the
   expensive concurrency cap (that is, relying on per-identity budgets, against I11). On `mixed` seeds 1–3 it must
   evaluate C1 = FAIL, while TUNED on the same panel evaluates C1 = PASS, so the evaluator is not always red.

## Acceptance criteria (from `r3e07-L5-swarm-acceptance-criteria`; thresholds are the researcher's, grade D)

| id | criterion | evaluated on |
|---|---|---|
| C1 | human failure ≤ 2% | worst seed, every scenario |
| C2 | human server-side p99 ≤ 3× unloaded (unloaded = mean baseline p99 of the same config) | worst seed, every scenario |
| C3 | verified agents ≥ 99% admitted | worst seed, every scenario |
| C4 | attacker-admitted **expensive** (cost ≥ 20) units/s ≤ 667 (20% of 3,333 = 1 vCPU / 30 ms × 100) | worst seed, attack scenarios |
| C5 | CG-NAT and no-JS human FP ≤ 5% | worst seed, every non-baseline scenario |
| C6 | cheap flood (cost 5): human FP ≤ 2% | cheap_flood |
| C7 | aged-cookie swarm: FP ≤ 5% and expensive units ≤ 667 | aged_swarm |
| C8 | heavy hitter 300 rps: FP ≤ 1% and ≤ 1 ok_exp/s | heavy_only |
| C9 | humans only: FP ≤ 1% | baseline |
| C10 | accept-window overhead utilisation ≤ 85% (the sim reports only the **last** 5 ms window) | worst seed, every scenario |
| C11 | no-fail-open and key-churn memory bound | not simulated → `oracles/admission-props` I7/I4 |
| C12 | PoW-solved share; > 50% attacker ⇒ PoW layer ineffective (r2 criterion 9) | swarm_solver_1k, record only |

## Research provenance (untrusted: read, copied into this directory, re-run here, never executed in place)

| source | sha256 | use |
|---|---|---|
| research/state/raw/round-003/07-work/swarm_sim.py | 8a5558be9fd69858c6217e46ae3aa7584c8e598d007e54541bb2182bb2fe92d9 | ported verbatim as `swarm_sim.py`. The only changes are lines tagged `# AEGIS-PORT:` (mutation hook, `run(mutate=)`, named configs, `__main__` removed). |
| research/state/raw/round-003/07-work/cost_model.py | d529d7eaf614a930a25f2a7a2556e8f68d9019c328da0d99a2e58f5ad903334e | ported as `cost_model.py` (print and file write removed). Re-run here, its `out` equals research `cost_model.json` exactly. |
| research/state/raw/round-003/07-work/cost_model.json | 5086f95148c08c8596f94874ae7b12dac0576a54a85e158bf7ac100e4d0be3bb | equality check above |
| research/state/raw/round-003/07-work/tuned.json | 567201de35e33503944ee8b6522b6a47277a8fe08e16413de12f6e1f4902d5ea | embedded as `CONFIGS["TUNED"]` |
| research/state/raw/round-003/07-work/panel.py | 8a70f518261ce5593208ba1dbc2ce5c55163a34993b6d8d251a5a1d595693853 | panel statistics (worst seed over seeds 1–10), re-implemented in `panel_stats` |
| research/state/raw/round-003/07-work/exp.py | a6b0226647d9bb84e7d2afa70493855b24f57867b4bd8f1b05d69dd82e8e671e | `agg()` means (re-implemented) |
| research/state/raw/round-003/07-work/sweep1.py, sweep2.py, show.py | 5b1e5534c7dad2bc90e43e6817f5e96cd4255b6bb99dfe9f1524d53c45cf8a99, 41073d4ca9a6fea1f9a78ef69bade1c8bc8c67953293e88e7f3f93e9bbec2701, 5af8f93668905aac901b10d4ee8e2579728b0dd32bf6932cd6ea52dda67410da | read only. The sweeps are the in-sample tuning that produced `tuned.json` and are not re-run. |
| research/state/raw/round-003/07-work/gcra_bench.rs | 707732bc0bb116e749d433c3dd51da5b5e22d1190735b3cbca9224d364fd4df1 | read only (S1 cost numbers in the cost model) |
| research/state/raw/round-003/07-work/panel_tuned2.jsonl, panel_r2.jsonl, panel_perip.jsonl | 7ccd3cd8c65156f97c19e19c9516b3ab670d9a6d6a4b6a0de3e9a0e5c48dddb3, 8c76c1a95a1f7f7e57ef52e6ee581856aebda2374ffef18448a26b52b3a9d174, d6d3d2a490daebcd67d02aeac9799d54ae33646a5354dd7ad06b869fedef33c0 | extracted into `research_panel.json`. `run` compares its own panel statistics against these (seeds 1–10). |
| research/state/raw/round-003/07-abuse-economics-and-swarm-simulation.json | 04c75684df1185f11a0b33c55189172592e3fca71db0380d1d738ebb6ca8df28 | C1–C12 text and claimed results |
| research/state/raw/round-003/07-abuse-economics-and-swarm-simulation.nodes.jsonl | d9fca1e5e10b54bd601762f9fce7abe2baf74440556770e357098c44067a75f0 | same nodes |
| research/state/raw/round-003/07-abuse-economics-and-swarm-simulation.progress.md | 75572454484f4c7e7e8b13fe8f539ec1f704823a0065a48b1740ed8daa141067 | parameter provenance (PoW rates, Gradient2 defaults, prices) |
| research/state/raw/round-002/04-abuse-admission-control-under-swarms.json | 6b8b0649f5d0ad1c0327ae8a5502e1b866eec8191d7a2c96d7a73d0af8006177 | original swarm spec (`abuse-L5-swarm-sim-spec`, criteria 1–9) |

Note: `research/state/raw/*/*-work/` is gitignored. The research inputs above exist only on this machine, so the
sha256 values are the durable record.

## Re-run in repo (2026-10-25)

All values are **D**. They were run through `ci/heavy.sh` on the operator laptop, in about 12 min wall time for
three configs under a contended heavy lock.

- `ci/heavy.sh oracles/swarm-sim/run --configs TUNED,R2,PERIP`: two processes, output sha256
  `2f2fe576fc1a1914fe6c0d52f755c8f48fa301f6be8a0f917ec96d782c5c613d` (identical), so the run is deterministic.
  **Reproduction vs the research panels: 210/210 statistics identical** (7 statistics × 10 scenarios × 3
  configs, seeds 1–10). The port reproduces round 3 exactly, and the ported cost model equals `cost_model.json`.
  Last line: `SWARM-SIM: PASS (advisory: record_only)`.
- TUNED acceptance (D): **7 PASS, 3 FAIL of C1–C10.**
  - C1 FAILs: aged_swarm 3.16%, flash_crowd 2.84%, dc_swarm_1k_ips 2.34% (worst seed).
  - C2 FAILs: cheap_flood 215 ms > 141 ms.
  - C5 FAILs: flash_crowd CG-NAT 26.2%.
  - C3 99.98% min, C4 510 max (aged_swarm), C10 0.56 max, C12 attacker 99.9% of solved challenges (PoW
    ineffective, confirmed).
- R2 (round-2 defaults): 0/10 PASS, human failure 99.41% worst (mixed). PERIP (S0+S1 only): 2/10 PASS (C9, C10).
- `run --self-test`: control deterministic; `time` and `hash` mutants caught by the determinism check; BROKEN
  fails C1 at 90.95% (and C4 at 1,682 units/s) on mixed seeds 1–3, while TUNED passes C1 at 0.90%. Last line:
  `SWARM-SIM SELF-TEST: PASS (...)`.

Discrepancies between the research claims and the reconstruction. The data reproduce exactly. The differences
are in the prose summaries:
1. Node `r3e07-L5-swarm-acceptance-criteria` reports C1 and C2 for TUNED as PASS, quoting `mixed` only. Evaluated
   on every scenario (worst seed), C1 fails in 3 scenarios and C2 fails under cheap_flood. ARCHITECTURE §3.4
   "Honest status" already records this, and the reconstruction matches it exactly.
2. The same node quotes C7 aged-swarm human FP "max 3.7%". The panel data and our re-run give 3.16% (3.49% is the
   CG-NAT sub-population max).
3. C10 is quoted as 0.27–0.45 (TUNED) and 0.75–0.78 (R2). Those are seed means of a last-window-only metric. The
   worst seeds are 0.56 and 0.90, so R2 also fails C10 on the worst seed.
4. C4 for cheap_flood: the research `units_s_max` (1,955.8) counts cost-5 requests. C4 is about *expensive*
   units, so this oracle counts only cost ≥ 20 and reports cheap_flood under C6/C2 instead.
5. C12 is phrased as "100% of fresh-class admits". The sim does not report that quantity. The attacker share of
   solved challenges is 99.9% (TUNED) and 100% (R2).

## What q3-005 (sim v2) needs before any of this can gate

1. **Held-out traffic traces.** Real request logs from at least one public forge or wiki under a documented
   swarm (arrival times, per-IP/ASN/prefix keys, paths mapped to cost classes, TLS full versus resumed, cookie
   ages, challenge outcomes). They must be split by time into a tuning set and a **held-out** set, and the
   held-out set is never used to choose `tuned.json`. Today every TUNED number was fitted on seeds 1–10 and is
   reported on seeds 1–10.
2. **Calibrated service and stage costs** in place of E-grade assumptions: the 1-vCPU handshake cost (q3-001),
   parse/classify/429/challenge costs, the handler cost distribution per class (not fixed 0.2/1/4/30 ms), and
   the I/O multiple. That means measuring the real aegis pipeline on the target VPS class.
3. **A trace-replay mode** that drives the simulator, and later the real `aegis-admission` crate through the
   `--subject` hook, from recorded traces rather than synthetic Poisson actors. It should also cover the
   rdnlsmith and GNOME shapes named in the round-2 spec.
4. **Out-of-sample seeds and nightly random seeds**, with the worst seed reported. Acceptance should be judged
   on held-out traces, with any threshold change justified outside the tuning data.
5. **Missing behaviours**: pre-crypto PSK visibility (q3-003), ASN/subnet keying, Privacy Pass/WBA issuers,
   a real C10 metric (time-averaged accept-window utilisation, not the last window), and C11 under key churn.

Until then the table is a record of a model, not evidence about the server.

## Known limits

- The port is faithful, so the simulator's modelling assumptions are inherited unchanged: processor-sharing CPU,
  5 ms accept windows, Poisson actors, fixed per-class service times, the `cpu_scale` 0.5 VPS factor (E) and
  `human_hps` 1.5e5 (C/D).
- `cpu_ovh_util_last` (C10) is a single end-of-run window.
- C12 is reported as the attacker share of solved challenges. The research phrasing ("100% of fresh-class
  admits") is not directly measurable from the sim's report.
