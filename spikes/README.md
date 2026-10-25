# Phase 1 spikes (decision-flipping experiments)

Each spike answers one question from IMPLEMENTATION_PLAN Phase 1 / ARCHITECTURE §9 and writes a journaled verdict.
Flips are applied to F1–F13 by the spec author (re-freeze) before Phase 2.

## Contract
- Directory `spikes/<id>/` (id = queue id, e.g. `q4-004`). Nothing outside it is edited by the spike agent.
- `verdict.json`:
  `{"id", "question", "flips_if" (copied from the plan), "measured" (numbers with units, hardware, conditions),
    "verdict": "keep" | "flip" | "inconclusive", "decision_effect" (which rule/interface changes, exact text),
    "rung" (R0–R5 or measurement grade A–E), "reproduce" (exact commands), "limits", "date"}`
- `README.md`: method, raw results, reproduction, honest limits. Raw data files alongside (keep them small).
- Measurements on this laptop or a LAN box standing in for a VPS are labelled as such and capped at grade B.
- Machine safety: every compile/benchmark through `ci/heavy.sh`; ≤1.5 GB disk incl. build output; delete target/
  after measuring; no Docker image >500 MB; no apt/sudo. Pinned crates must be ≥7 days old (check crates.io).
- An inconclusive verdict with a precise reason beats a confident wrong one.
