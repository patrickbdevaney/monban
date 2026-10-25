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
## 04:10 checkpoint (executed results)
- Token.lean (T1-T6 transcribed, 16 theorems), Combine.lean (4), Vacuity.lean (9 witnesses) all build; 45 theorems, 0 sorry.
- axiom_audit.py PASS: max axiom set {propext, Classical.choice, Quot.sound}; token T1/T4/T5 propext-only; enc_injective/parse_canonical/combine_ne_error axiom-free.
- lake check (6 kernels via --paranoid): ALL ACCEPT, 58,609-58,612 decls, 227.9 s, 996 MB RSS; plain lake check 72.6 s / 1.0 GB. bwrap sandbox FAILS (AppArmor kernel.apparmor_restrict_unprivileged_userns=1: "setting up uid map: Permission denied") -> ran --inadvisably-no-sandbox.
- lean4lean accepts via lake check export path (r2 "incompatible header" = direct-olean invocation is wrong path).
- NEEDLE: Lean 4.35 native_decide emits per-theorem aux axiom `<thm>._native.native_decide.ax_1_1`, NOT Lean.ofReduceBool -> denylist scripts grepping ofReduceBool miss it; allowlist catches it. lake check rejects (exit 1) sorryAx, custom axiom, native aux axiom (negative control, 74.3 s).
- timings: cold lake build median 2.23 s (2.23/1.03/2.25, load ~10, i9-14900HX 32 thr), peak 546 MB; no-op 0.16 s / 106 MB. .lake 3.7 MB. toolchain carved 712 MB + elan 13 MB.
- Cedar: cedar-spec@301bdd2 cedar-lean 387 files/125,621 LOC; requires batteries v4.35.0 + lakefile.lean (import Lake => full toolchain). TPE closure 159 modules/41,282 LOC incl. Cedar.Data.Int64 (2 native_decide in library code). SymCC/Data/Ext 8 native_decide. Cedar CI = `lake build Cedar SymCC` only, no axiom audit/checker. r3 cedar/*.lean byte-identical to upstream. Build = spike (>1.5 GB).
## 04:30 sources so far (web/gh)
1 GH release v4.35.0 (2026-10-12, assets 594,481,375 B) 2 lean-lang.org releases/v4.35.0 notes (#14953 remove ofReduceBool/trustCompiler; #14990 lake check; #15145 --paranoid; #15005 bwrap; #15156 no-sandbox flag; #15241/#15289 kernel UAF fixes; #15288 UB)
3 PR #14953 body (merged 2026-08-28) 4 PRs verified merged #14990 09-07, #15145 09-14, #15241 09-23, #15289 09-24, #15288 09-23, #15005 09-09, #15156 09-14, #15055 09-08
5 issue #15908 (2026-10-24) prelude-replacement False via export -> closed not-a-bug; comparator rejects ('Const does not match ... Nat.add') -> lake check --from-export of 3rd-party exports is a TCB hole unless prelude compared
6 #14576 wrong-structure projection axiom-free False (fixed #14577, toolchain 4.32.2, July 2026); #14484 (fixed #14498, 4.32.1, 2026-07-22) ; #15100/#15101 leanchecker accepted malformed exports (closed 2026-09-09)
7 comparator README: deprecated, merged into core 4.35 as lake comparator/lake check; assumptions list
8 Lean ref ValidatingProofs 4.35.0: ladder; "_native" axioms since 4.29.0; trustCompiler removed 4.35.0
9 hackmd soundness guide (de Moura account): alt prelude = adversarial input; metaprogramming not TCB
10 Lean4Lean TYPES 2025 LIPIcs (arXiv 2403.14064): 20-50% slower, incomplete verification
11 etbe.coker.com.au Ubuntu 24.04 & bubblewrap (AppArmor userns); local Ubuntu 24.04.4 has no bwrap profile
12 MongoDB $ne docs: matches docs lacking the field -> confirms not_absent_permits hazard for doc adapters
13 Guagliardo-Libkin PVLDB 11(1) formal SQL semantics w/ nulls; arXiv 2003.11331 SQL-with-nulls formalization
14 arXiv 2609.06500 CAPMAS (macaroon plaintext caveat collusion) — to verify
15 cedar-spec 301bdd2 sparse clone (code read); nanoda_lib/lean4export/lean4lean repos Apache-2.0 active Oct 2026
