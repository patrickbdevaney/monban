# R4 E01 lean-check-lowering-and-token-proofs — progress
started 2026-10-25 03:30 EDT (restart after laptop memory crash; no prior progress file existed)
plan: (a) elan+lean v4.35.0 into scratchpad via heavy.sh (no Mathlib); (b) build Lowering.lean; (c) close lower_sound_full;
(d) transcribe token T1-T6 -> Token.lean; (e) axiom audit + paranoid replay + CI gate script; (f) measure disk/RSS/wall;
(g) Cedar drafts: need cedar-spec deps -> assess feasibility; (h) web: release notes, soundness issues, zulip.
## 03:50 checkpoint
- lean v4.35.0 tarball 594,481,375 B sha256 7289597a...268f6d (GitHub release 2026-10-12, commit eb6cafb). elan 4.2.4 (2026-08-25) 13 MB in scratchpad; `elan toolchain link leanprover/lean4:v4.35.0 <carved dir>` works.
- carved subset (bin/* + lib/lean/Init + libleanshared*.so + libInit_shared + libLake_shared + runtime .so) = 712 MB (read: du).
- r3 lakefile.lean FAILS on Init-only subset: `unknown namespace Lake` (needs Lean+Lake oleans 1.46 GB). -> lakefile.toml.
- r3 Lowering.lean AS WRITTEN: 3 errors (anyEq_sound simp [List.contains] maxRecDepth x2 at 154/155; isIn case type mismatch contains vs ∈ at 210) + sorry at 246. wall 1.05s, RSS 519 MB.
- fixed (proof-only) + lower_sound_full PROVED (Exact atoms) + lowerQ_sound_full + not_absent_permits spec-gap witness. Clean: 1.32 s / 525 MB.
- bundled lean4lean: "incompatible header" on every Init olean (reproduces r2 vfg-lean-multikernel-paranoid-check).
- combine_failclosed (graph node vfg-policy-tristate-failclosed-invariant, graded A "proven in Lean"): NO Lean file exists anywhere in state/raw -> overclaim; writing Combine.lean.
