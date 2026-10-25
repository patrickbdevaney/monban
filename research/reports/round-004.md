# AEGIS round 4 report (2026-10-25)

Integrator: the only writer of map state for round 4. Inputs: 12 explorers (raw JSON in `state/raw/round-004/`) and 12 two-sided verifier passes. The blind-research rule (§0a) held: the integrator did not open `state/prior_treatments/` or `state/seed_conversation.md`.

Crash recovery note. This integration ran after the operator's machine crashed from memory exhaustion ("continue, my system crashed from memory").
- State check before writing: no record had `first_seen_round: 4` or `revision_round: 4`, and there was no `reports/round-004.md`, so the integration started clean.
- The integrator ran no heavy jobs; everything was stdlib Python over JSONL.
- Verifier verdicts again existed only in the orchestrator payload. The last two verifier results (Lean, isolation) were missing from the 10-minute journal mirror. All 12 were extracted from the live agent journal (`~/.claude/projects/.../wf_91eef32d-868/journal.jsonl`) and re-keyed into `state/raw/round-004/_verify_r4_verdicts.json` (150 verdicts) and `_verify_r4_missed.json` (80 missed items, 19 promoted nodes).
- Script: `state/raw/round-004/_integrate_r4.py`, derived from the round-3 script. It is deterministic, refuses to run twice (checked after the run), and rewrites the queue and predictions via temp file plus rename. Pre-write backups are in the session scratchpad.

## 1. Delta

| metric | value |
|---|---|
| new nodes appended to `state/graph.jsonl` | **182**: 163 from explorers, 19 promoted from verifier "missed" lists (`v4.*`) |
| by layer (new) | L1 4 · L2 9 · L3 23 · L4 101 · L5 45 (**80% at L4/L5**, same as round 3) |
| by grade (new, after verification) | A 59 · B 91 · C 24 · D 2 · E 6 |
| revision records of existing nodes | 31: 13 calibration re-verifications (explorer 12) and 18 integrator corrections from round-4 evidence (3 ids got both). Same id, `revision_round: 4`, never renamed |
| merges (same-as) | 3 cross-explorer duplicates: `sc.lean-kernel-soundness-2026` → `r4e01.lean-kernel-soundness-2026-record`; `r4i04.m0-escape-rate-denominators` → `wasmtime-advisory-share-by-config`; `r4tri.cmvp-pin-carries-advisories` → `ops.fips-module-boundary-pin` |
| edges appended to `state/edges.jsonl` | 266: 210 explorer, 3 same-as, 27 refines, 5 contradicts, 21 integrator bridges. 0 dangling |
| canonical URLs appended to `state/seen.jsonl` | 498: 449 new, 49 re-seen and marked `revisit` |
| queries merged into `state/queries.jsonl` | 334 |
| frontier queue (rebuilt) | 575 items: 326 open, 39 partial, 45 done, 165 absorbed. 17 earlier items closed or advanced (§6) |
| predictions | 9 new (total 43); all 34 earlier predictions now carry `status`, `last_checked`, `suggested_p` from explorer 12's scorecard |
| verification | 150 of 176 explorer records (85%) checked two-sided: **15 up, 43 down, 92 unchanged**. Over-claim ratio 2.9:1 (round 3: 13:1) |
| refuted or materially corrected (kept with grade and reason, never pruned) | `r4i04.kernelctf-reachability-under-allowlist` B→C (own mapping; the 111-CVE listing did not re-derive); `l4.conformance-suite-gap-origin-only` B→C (both cited issues are about other things); `r4e01.lake-check-paranoid-six-kernels`, `r4e01.from-export-prelude-trust-hole`, `r4e01.lean-kernel-soundness-2026-record`, `r4e01.bwrap-apparmor-blocks-lake-check` A→B (checker disagreement on #15908; release attribution unsupported; PR #15156 is about comparator); `r4i04.blast-radius-table` A→B (single machine, naive native baseline); `ops.fips-module-boundary-pin` calibration range 1.15.1-1.17.2 is **wrong** (1.17.2 yanked; window 1.15.2-1.17.1); `r3e07-L5-swarm-acceptance-criteria` stays D with an overclaim disclosed (C1/C2 were mixed-scenario only); `econ.who-switches-first` D 0.4 and `econ.agent-gateway-criteria` C 0.5 (quotes not visible in the fetched thread); `uu11.outage-class-frequency-table` duration median does not reproduce (57.2 min over 76 rows, not 52.9 over 64); Django ticket 34225 dropped as a citation from `wpo-upsert-keyspace-capture` |

### Mechanical novelty

`python3 -I tools/novelty_gate.py metrics --round 4`, run after the verifier files were written and before any state write, copied verbatim (also in `state/raw/round-004/_metrics_r4.txt`):

```json
{
 "round": 4,
 "queries": 334,
 "urls": 497,
 "nodes": 176,
 "url_novelty": 0.9094567404426559,
 "query_novelty": 0.9820359281437125,
 "node_novelty": 0.9602272727272727,
 "axis_cell_novelty": 0.9580838323353293,
 "intra_round_query_dup_rate": 0.0688622754491018,
 "mechanical_novelty": 0.9094567404426559
}
```

- **delta.novelty_ratio = 0.909** (the mechanical value; round 3 was 0.881).
- Node novelty: the gate counts 176 explorer nodes. The 7 non-novel ones are among explorer 12's 13 re-verifications of existing ids, which became revision records and earn zero novelty credit; the 3 same-as merges also earn zero. Merge-adjusted node novelty is 160 / 176 = 0.909, which equals the binding URL term.
- The intra-round query dup rate (0.069) is twenty times round 3's. It comes almost entirely from one explorer that logged forum thread fetches as queries (§ direction diversity).
- **Saturation (§0c): not met.** The threshold is mechanical_novelty < 0.2 in two consecutive rounds; round 4 is 0.909.

### Singletons and unseen mass

- **Singletons: 160** of the 163 new explorer nodes were found by exactly one explorer and match nothing existing.
- **Strict singletons: 40.** These additionally have no edge to another explorer's node or to an earlier-round node. Examples: `wpo-upsert-keyspace-capture`, `r4e07.diff-corpus-executed`, `r4i04.coredump-pipe-hang`, `sc.do333-credit-scope`, `uu11.retry-herd-class`.
- Cross-explorer near-duplicate scan (title+summary Jaccard ≥ 0.2): one pair, `r4e01.from-export-prelude-trust-hole` vs `v4.lean-checker-disagreement-15908` (0.28), recorded as a `contradicts` edge, not merged.
- Good-Turing unseen-mass estimate: 160 / 182 ≈ **0.88** (strict 40 / 182 = 0.22; round 3 was 0.96 / 0.29).
- Reading: the map is still finding mostly unique material, but less of it stands alone (123 of 163 new explorer nodes link across explorers or rounds). Three topics were found twice by different explorers: the Lean soundness record, the Wasmtime escape rate and the FIPS pin advisories. That is the first visible sign of overlap.

### Direction diversity (§8a)

- Queries 334, distinct 4-axis cells (pillar | source type | stance | era) **111**: **direction_diversity = 0.332** (round 3: 0.366). With the vocabulary axis there are 153 cells: **0.458**.
- The forum-mining explorer logged 114 queries in only 8 cells, 94 of them near-dups of each other ("HN item <id>"-style fetches). Without it: 220 queries, 103 cells, **0.468**, which would be the highest yet.
- Pillar labels are now one canonical W-* pillar per target, as round-3 proposal 4 asked. So 47% of queries in unused cells (round 3: 70%) is partly the removal of label inflation, not a loss of breadth.
- Cross-explorer near-dups 0. Prior-round near-dups 6, all re-reads to verify a specific claim (CISA bad-practices, Redis ACL docs, CMVP #5314 and others).
- Axis totals:
  - source type: forum 101, repo-advisory 70, spec-rfc 48, web-other 37, cve-incident 32, vendor-doc 24, paper 19, benchmark 3
  - stance: proponent 175, skeptic-negative 125, attacker 34. Proponent is 52%, down from 69%: the round-3 stance quota worked.
  - era: 2025-26 286, historical 22, last-60d 26
  - vocabulary: PL-formal 67, economics 59, systems 53, offensive 49, standards-policy 32, cryptography 32, network-SRE 25, database 9, web-dev 8
  - scale: unspecified 251, enterprise 35, government 28, household 12, hyperscaler 8
- Yield (new non-merged L4/L5 nodes per query):

| explorer | queries | new nodes | L4/L5 | per query |
|---|---|---|---|---|
| non-us-national-pqc-crypto-regimes | 16 | 20 | 17 | 1.06 (primary PDFs in DE/FR/EN/JA) |
| fips-golden-version-triangle-one-lock | 9 | 9 | 8 | 0.89 (executed resolver + FIPS probe) |
| lean-check-lowering-and-token-proofs | 23 | 20 | 19 | 0.83 (first Lean execution) |
| write-path-lowering-differential-oracle | 15 | 11 | 11 | 0.73 (executed write oracle) |
| dx-capability-sdk-mutants-real-axum-async | 13 | 12 | 9 | 0.69 (compiled mutants) |
| uu-incident-dataset-outage-root-causes | 19 | 16 | 11 | 0.58 (hand-coded dataset) |
| isolation-crash-blast-radius-measured | 25 | 19 | 14 | 0.56 (740-cell fault injection) |
| mcp-gateway-conformance-corpus-executed | 17 | 8 | 8 | 0.47 (executed corpus) |
| bridge-canonical-identity-one-owner | 34 | 17 | 13 | 0.38 (executed differential) |
| safety-critical-certification-assurance-historical | 31 | 16 | 11 | 0.35 |
| calibration-two-sided-top-findings-r3 | 18 | 3 | 3 | 0.17 (+13 revisions) |
| switching-economics-practitioner-forums | 114 | 12 | 2 | 0.02 (L1-L3 demand evidence by design) |

- Redundant directions flagged in `state/directions.md`: forum fetches logged as queries; three duplicate recomputations across explorers; two explorers stating the aws-lc-rs FIPS window differently.
- Under-explored: W-STATE, W-ABUSE, W-PERF, W-OPS had no target (0, 0, 1, 1 new nodes); benchmark sources 3; household 12; database vocabulary 9.

## 2. Top findings (actionability × grade; L4/L5 first)

1. **Lean was executed for the first time, and the drafts did not check as written** (`r4e01.lowering-r3-draft-failed-check` A 0.95; `r4e01.lower-sound-full-proved` A 0.95; `r4e01.token-T1-T6-checked` A 0.93; `r4e01.combine-failclosed-first-check` A 0.93).
   - The r3 Lowering.lean had 3 elaboration errors besides its sorry. With proofs fixed and definitions byte-identical, `lower_sound_full` is closed.
   - 45 theorems across Lowering, Token and Combine, 0 sorry, standard axioms only, accepted by all 6 checkers.
   - Round 2's "combine_failclosed proven in Lean" (graded A) had **no file behind it**. It now exists and checks.
   - New rule: no proof claim above grade C without a file path and a gate log.
2. **Refines is not enough once NOT is in the IR** (`r4e01.exact-vs-refines-not-witness` A 0.92; `r4e01.not-absent-permits-spec-gap` A 0.90).
   - A checked counterexample, plus a real completeness bug: PG BUG #19645, where partition pruning with a nondeterministic collation drops matching rows.
   - Adapters exposing negation must show leak = 0 **and** miss = 0.
   - The two-valued reference widens on absent fields, as MongoDB `$ne` does. A spec decision for the freeze: a three-valued reference.
3. **Write path: upserts capture other tenants' rows** (`wpo-upsert-keyspace-capture` A 0.90; `wpo-pg-onconflict-where-peek` A 0.86 up; `wpo-rls-with-check-masked-by-select-policy` A; `wpo-sqlite-replace-authorizer-gap` A).
   - 261/300 on PG 17.11, 19rc1 and SQLite with a non-tenant arbiter.
   - A column-free write leaks 100/100 under a WITH CHECK(true) policy that every other test masked.
   - PG evaluates ON CONFLICT WHERE before the RLS check (two independent pgsql-hackers reports, a patch pending; precedent CVE-2017-15099).
   - SQLite's authorizer misses REPLACE's implicit deletes.
   - Golden: INV-WRITE-SUBSET W1-W7, composite arbiters, FORCE + WITH CHECK, a write denylist, and PG19 adoption gated on the fix (new R-DB-8).
4. **The FIPS triangle is empty at the security floor** (`r4tri.no-co-resolvable-lock` A 0.95 up; `r4tri.fips-sys-decoy-lock` A 0.92; `r4tri.try-fips-mode-blind` A; `r4tri.yanked-1.17.2` A 0.95 up).
   - No lock has rustls ≥0.23.44 together with CMVP-listed fips-sys 0.13.11. Two lock profiles are needed.
   - Pinning fips-sys directly beside rustls 0.23.46 silently links FIPS 4.2.0 while grep passes, and `try_fips_mode()` cannot tell 3.1.0 from 4.2.0.
   - The window is aws-lc-rs 1.15.2-1.17.1. The cmvp lock carries 0042/0043/0349 and runs only on Amazon Linux 2023 operational environments.
5. **Pure ML-KEM is non-conformant in France, and the one universal group is missing from rustls** (`r4e10.anssi-pg083-pure-nonconformant` A; `r4e10.asd-ism-2026-09` A; `r4e10.bsi-tr02102-2026` A; `r4e10.golden-tls-kex-profiles` B; `r4e10.rustls-secp384r1mlkem1024-gap` B).
   - Australia stops approving ML-KEM-768/ML-DSA-65 and all classical asymmetric crypto beyond 2030.
   - BSI intends SecP256r1MLKEM768/SecP384r1MLKEM1024, not X25519MLKEM768.
   - Golden: a typed profile set with P-UNIVERSAL = 0x11ED (SecP384r1MLKEM1024), which rustls 0.23.46 lacks. R-PQC-3 changes direction.
6. **Crash blast radius measured, with PHP-FPM as control** (`r4i04.blast-radius-table` B; `r4i04.php-fpm-measured-control` B; `r4i04.state-leak-c8-measured` A; `r4i04.coredump-pipe-hang` A).
   - PHP-FPM: 0 healthy failures across 7 fault classes. Fork: 7/7 parity. Fresh Wasm: 6/6. Native: 1/7.
   - Any reused context poisons nearly all later requests (Wasm instance reuse 383 wrong answers per poisoning).
   - Apport's core pipe hangs each crash for ~100 ms unless dumpable=0.
   - New R-ISO-5 crash-containment invariants and a fault-injection CI gate. P2 cordons become per-tenant.
7. **One owner per request identity drives parser disagreement to zero** (`r4e07.canon-ref-zero-disagreement` A; `r4e07.diff-corpus-executed` A; `r4e07.hyper-h2-authority-host-unchecked` A; `r4e07.json-parser-dup-key-matrix` A up; `r4e07.cookie-rs-nbsp-trim` B up).
   - 12 Rust parsers + CPython disagree everywhere on an adversarial corpus. A strict reject-don't-repair canonicalizer takes accepted-input disagreement from 331/331/69 to 0/0/0.
   - hyper/h2 never compare Host with :authority.
   - Rust ecosystem findings: simd-json maps a lone surrogate to U+0000 (#481 open), and cookie-rs trims NBSP from cookie names (the Hono CVE class, unreported).
   - New R-ING-4. The R-ING-1 identity sub-claim moves C → B.
8. **Scoped capability handlers survive real axum; owned extractors do not** (`dx.r4-real-axum-mutant-scores` B; `dx.r4-owned-extractor-static-escape` B up; `dx.r4-tokio-scoped-impossible` A up).
   - Compile-rejected: 25/32 scoped adapter vs 16/32 owned extractors vs 3/32 plain axum.
   - Owned handles are `'static`, so they escape by spawn, static or leak.
   - Safe scoped spawn on tokio is closed not-planned. R-DX-1 moves C → B.
9. **Repo-level advisories never reach the audit gates** (`r4c12.repo-ghsa-osv-blindspot` A 0.88; `v4.cooldown-holds-vulnerable-webpki` A).
   - On 2026-10-25, 7 of 133 repo GHSAs were invisible to OSV, including a cedar HIGH and three quinn HIGH. One was invisible for 4 months.
   - The re-executed 7-day cooldown lands the vulnerable webpki 0.103.15.
   - New R-SUP-6 (gate G10).
10. **Non-adversarial outages are a different threat model** (`uu11.cfg-push-class` A; `uu11.cert-lifecycle-class` B; `uu11.worker-exhaustion-class` B; `uu11.outage-class-frequency-table` C).
    - 160 coded middle-tier outages: config push 17.5%, latent bug 12.5%, exhaustion 10.6%, certificates 5%.
    - **0** were caused by memory corruption or parser differentials.
    - New R-THR-6 and R-OPS-9 (CFG/CERT/UPS/OPS gates).
11. **Proof-checker gates must allowlist, and checkers disagree on adversarial input** (`r4e01.native-decide-aux-axiom-naming` A; `r4e01.lakefile-toml-init-only` A; `r4e01.lean-build-footprint-measured` A; `v4.lean-checker-disagreement-15908` B).
    - Lean 4.35 deleted ofReduceBool, and native_decide now adds per-theorem axioms, so a denylist passes it silently.
    - Toolchain: the Init-only Lean carve is 712 MB. The paranoid gate takes ~4 min and 1.0 GB, so it runs in CI only.
12. **Demand: nobody switches for PQ or proofs** (`econ.differentiators-absent` C; `econ.deal-breakers` B; `econ.ingress-nginx-migration-cost` B).
    - 0 of ~8,175 selection-thread comments name PQ as a criterion. Confounder: PQ is already an invisible default.
    - Deal breakers: migration parity, default drift (Nine: 4 incidents), paywalls, governance.
    - New R-GAP-4: assurance as an invisible default, migration parity first.

## 3. New bridges (21 edges, `origin: integrator-bridge`)

1. **Engine bugs break the adapter contract from both sides.** PG BUG #19645 is a completeness failure and the ON CONFLICT ordering is a side-effect soundness failure. So the two-sided DRT and the write oracle re-run on every engine bump (`r4e01.exact-vs-refines-not-witness` ↔ `wpo-pg-onconflict-where-peek`).
2. **One three-valued reference** serves both the absent-field NOT widening and the write W1 Pred clause. Make the reference Option-Bool before freezing W1-W7.
3. **FIPS × jurisdiction.** The FIPS provider does not refuse X25519MLKEM768, so every compliance profile is an explicit allowlist. The universal group (0x11ED) missing from rustls puts a custom KxGroup on the critical path.
4. **Audit gates both ways.** The cmvp lock fails cargo-audit by design while repo-only GHSAs pass every lock: the gate needs reachability-justified ignores plus a repo-GHSA poll. The cmvp lock's RUSTSEC-2026-0349 is mitigated only by server HRR, so the HRR test runs against both profiles.
5. **Proof-gate qualification.** The allowlist, the native_decide ban, the known-false-proof corpus and the 6-checker run make one TQL-5-style argument. An executed gate with a negative control is exactly DO-330 user-context evidence.
6. **Lab twin of a field class.** The measured fd-leak gray failure (liveness never trips) matches the 10.6% outage class (ProxySQL LimitNOFILE clamp). Crash budgets and the min-healthy floor are one control-plane rule.
7. **Kernel surface.** kTLS (11 kernelCTF LPEs), BPF and io_uring stay unreachable from worker sandboxes; kTLS is at most a front-process option. Userns cuts both ways: deny it in workers, provision a bwrap profile in CI.
8. **Listener gate = CANON-6.** MCP SDK Host/Origin defaults and hyper's missing Host/:authority check have one fix: a core authority owner below every handler era. The -32020 header/body check needs one JSON owner, because simd-json/sonic-rs (first-wins) and serde (last-wins) disagree.
9. **Demand vs mandate.** PQ and proofs are absent from forums but mandated by dated national rules. Neither CVEs (0/101) nor memory corruption (0/160 outages) drive switching or downtime.
10. **Buyer credit = checked models.** CC EAL7 and SA-17(1) credit a formal policy model, which is what the checked Lean models are; code proofs exceed what regulators credit.
11. Others:
    - The SDK Drop guard vs host NC3 discard-on-cancel.
    - CRS C8 measured (fresh instance is the only zero).
    - Epistemics: the r2 phantom proof and 9 stale tags lead to the file + log rule.
    - Config totality and canon totality share one proof rung.

## 4. Protocol changes (rule diffs, with evidence; full text in `ARCHITECTURE-DRAFT.md` §R)

- **11 new rules; 28 amended; 1 with a direction change; 0 deleted. Total 97.**
- **Direction change:** **R-PQC-3**. The pure CNSA profile is demoted from the golden gov posture to an opt-in US-NSS profile. Reasons: pure ML-KEM is non-conformant in France and only hybrid-recommended by BSI/ECCG. R-PQC-8 makes SecP384r1MLKEM1024 the universal gov group.
- **New:**
  - R-GAP-4 positioning from demand
  - R-THR-6 non-adversarial outage classes
  - R-ING-4 CANON one owner per identity
  - R-PQC-8 jurisdiction profile set
  - R-ISO-5 crash containment + fault-injection gate
  - R-DB-8 write-path soundness
  - R-AGENT-7 executed listener corpus + 2026-07-28 delta
  - R-OPS-9 CFG/CERT/UPS/OPS gates
  - R-OPS-10 government-buyer route
  - R-FORMAL-5 assurance-case structure + checker qualification
  - R-SUP-6 repo-GHSA gate + certified-pin exceptions
- **Grade moves:**
  - R-DB-7 theorem E → A for the model.
  - R-AUTHZ-6 statements → A for the model.
  - R-AUTHZ-5 A/B → A (first real file).
  - R-ING-1 identity C → B.
  - R-DX-1 decision C → B.
  - R-SUP-1 narrowed (A 0.75).
  - R-ISO-1 tag fixed.
- **Stale-grade fixes (9, from calibration):**
  - R-ISO-1 tag; cedar-lean-proofs (B, not A); compliance-map (A, not B)
  - R-PQC-2 "resolved"; R-SUP-1 OSV-blind; R-MOD-1 same-core budget
  - R-ABUSE-4 mixed-only C1/C2; R-DX-2 C node; R-ISO-2 aarch64 floor
- **Decision stability (for the saturation judge):** 85 of 86 round-3 rules kept direction (**0.988**), above the 0.75 bar. Novelty is 0.909, and several open areas could still flip load-bearing decisions (§6).

### Anchoring check (§0a, integrator scope)

The integrator did not read the prior treatments, so it cannot name prior-treatment picks. It can say which round-4 decisions rest only on our own design text, without independent evidence: the CANON invariant (E), R-OPS-9's numeric thresholds (C), the expected-loss ranking (E) and the profile names in R-PQC-8 (B decision). Every other new rule cites executed or primary evidence. The Synthesize stage must run the real anchoring audit.

## 5. Calibration notes (two-sided verification)

- **Up (15), including:**
  - `r4tri.no-co-resolvable-lock` (crates.io metadata alone proves the empty triangle)
  - `r4tri.yanked-1.17.2` (yank confirmed 2026-07-17)
  - `wpo-pg-onconflict-where-peek` (second independent report with a patch)
  - `r4e07.whatwg-914-rust-url-divergence`, `r4e07.json-parser-dup-key-matrix`, `r4e07.cookie-rs-nbsp-trim` (upstream issues and code confirmed)
  - `r4i04.wasmtime-serve-reuse-defaults` (serve.rs defaults and maintainer quote confirmed)
  - `dx.r4-tokio-scoped-impossible` (tokio#3162 dates confirmed)
  - `sc.lean-kernel-soundness-2026` and `sc.ferrocene-qualified-rustc` (primaries fetched)
  - `r4e10.china-ngcc-round1` (CAS team independently broke 16 candidates)
- **Down (43), by class:**
  - **Single-machine experiments** (isolation rows A → B): naive native baseline, contended laptop.
  - **Citation mismatch:** conformance #553/#570 do not say what was claimed; PR #15156 is about comparator; the HotOS'19 abstract does not mention ASLR; Django 34225 is unrelated.
  - **Own mapping presented as data:** kernelCTF reachability (C).
  - **Absence-of-evidence over thin samples:** forum demand claims C/D.
  - **Version-pinned snapshots:** rustls 0x11ED gap; national primaries not re-fetched by the verifier (A 0.82-0.90).
  - **Checker independence overstated:** the #15908 disagreement.
- **Calibration explorer (12) revisions (13):**
  - Wasmtime M0 rate band refined to a 2.21/yr planning value; the 6-month trigger is a coin flip and is replaced.
  - Threat-ledger numbers reproduce only with hand relabels.
  - rustls PQ cost upheld (+12.5/+15.0%).
  - IPC budget scope narrowed (cross-core 8.07 µs).
  - Tenuo still unfixed on main.
  - Cooldown re-executed (lands 0382).
  - Oracle seeds 3 post-fix, not 4.
  - Swarm table overclaim (D).
  - FIPS pin carries 0042/0043 (its range statement was then corrected by `r4tri.yanked-1.17.2`).
  - CI gate list OSV-blind.
  - SJE near-miss (duplicate of `sdg-sje-rls-2026`, linked by refines).
  - R-ISO-1 tag stale.
  - R-DX-1 prior art unadopted (cap-std is the mature base).
- **Prediction scorecard:**
  - Resolved: `pred-cve-volume-2026` resolved **TRUE** (NVD 88,663 CVEs by 2026-10-25).
  - At risk: Kani #4910 release (p 0.85 → 0.5), sqlx f1e94ec release (0.6 → 0.45), Tenuo advisory.
  - Repriced up: privacypass batched tokens (0.6 → 0.75, IETF Last Call).
  - Repriced down: Pingora (0.8 → 0.65; fix on main, unreleased).
  - Fields written into `state/predictions.jsonl`.
- **Verifier-promoted nodes (19, `v4.*`):** among them `v4.lean-checker-disagreement-15908`, `v4.native-decide-unverifiable-external`, `v4.cmvp-lock-carries-rustsec-0349` (A), `v4.pingora-userinfo-authority-reject` (A), `v4.pg-onconflict-rls-second-report`, `v4.cve-2017-15099-onconflict-precedent`, `v4.redis-acl-side-channels-search-prefix`, `v4.mcp-default-off-dns-rebinding-cves`, `v4.cooldown-holds-vulnerable-webpki` (A), `v4.pq-hybrid-invisible-default` (C).

## 6. Open frontier (top of `state/frontier_queue.jsonl`)

- Closed this round: q1-013 (crash blast radius), q2-008 (MCP corpus pass rates), q3-004 (FIPS triangle), q3-012 (real axum mutants), q3-020 (check Lowering.lean), q2-051 (paranoid wall time), q3-100 (Lean tag).
- Advanced (partial): q3-006 (write path: Mongo/MySQL left), q2-011, q1-038 (reddit walled), q1-024, q1-046, q3-067, q3-045, q3-060, q2-070, q1-048.

| id | score | question (abridged) | closes by |
|---|---|---|---|
| q3-001 | 0.80 | rustls full vs resumed handshake CPU on a real $5 vCPU | spike (R-ABUSE-1, R-PERF-1) |
| q4-001 | 0.80 | Extend the B2 scoped adapter to streaming/SSE/WS and detached jobs without reopening `'static` escapes | spike (R-DX-1 reversal) |
| q1-009 | 0.80 | LLM-found vs human-found advisory rates | research (R-THR-2) |
| q3-002 | 0.75 | ipcbench on a real 1-vCPU KVM VPS (same-core vs cross-core) | spike (R-MOD-1 budget) |
| q4-002 | 0.70 | Coding-agent repair success on B2 diagnostics vs plain axum | spike (R-DX-1 reversal) |
| q4-003 | 0.70 | Do FIPS/FedRAMP/CNSA/CRA procurement texts score PQ-TLS, memory safety or formal assurance? | research (R-GAP-4 reversal) |
| q2-009 | 0.75 | Window-0 stalled flow-control harness vs golden pins | spike |
| q3-005 | 0.70 | Swarm simulator v2 (measured handshake cost, resumption, /64 churn, RST storms); held-out seeds | spike (R-ABUSE-4) |
| q4-004 | 0.60 | Three-valued IR reference and re-prove lower_sound_full; Mongo `$ne`+`$exists` Exact? | Lean (R-DB-7 spec gap) |
| q4-005 | 0.60 | Write oracle on MySQL/MariaDB + CockroachDB RLS ON CONFLICT | spike (R-DB-8) |
| q4-006 | 0.60 | Fuel budget 10 ms + 64-slot pool: does Wasm loop p99 fall from ×35 to ≤5×? | spike (R-ISO-5 gate) |
| q4-008 | 0.60 | False-reject rate of strict canon_* on 1M real request lines | spike (R-ING-4 CANON-2) |
| q4-026 / q4-028 | 0.50 | RFC 10024 order + custom rustls SupportedKxGroup for 0x11ED (check rustls-post-quantum first); interop vs OpenSSL 3.5/BoringSSL | spike (R-PQC-8 blocker) |
| q4-014 | 0.50 | Cedar `lake check --paranoid` + `#print axioms` on a CI runner | spike (R-AUTHZ-1 A vs B) |

**Decisions that could still flip** (load-bearing, support at E/C/D):
- R-ISO-1: expected-loss model E; kernel reachability C; per-tenant cordon cost.
- R-ING-4 CANON-2: false-reject rate.
- R-PQC-8: rustls 0x11ED and BSI's 2027 list.
- R-DB-7: three-valued reference.
- R-DB-8: PG ON CONFLICT fix; MySQL/Mongo writes.
- R-GAP-4: procurement evidence.
- R-ABUSE-1: D.

All except q4-003 and q1-009 close by implementation-phase spikes, not more literature (§0c). That supports pivoting to building after the round cap.

## 7. Self-improvement (summary; full text appended to `state/self_improvement.md`)

- **Verifiers still do not write their own verdict files.** This is the fourth round running. Worse, the 10-minute journal mirror missed the last two verifier results, so the integrator had to read the live agent journal. Make verifiers write `_verify_rNNN_verdicts.json` and `_missed.json` into the round dir before returning.
- **Proof claims need artifacts.** No proof claim above C without a file path + gate log; grep the graph for "measured"/"executed" before claiming instrument novelty (explorer 01).
- **Log search strategies, not fetches.** The forum explorer's 114 "queries" were mostly thread fetches, which inflated the intra-round dup rate to 0.069 and depressed direction diversity.
- **Give calibration targets the list of numbers other targets will touch**, to avoid duplicate recomputation (three merges this round) and contradicting statements (the aws-lc-rs window).
- **heavy.sh:** checks free space only on /home but the scratchpad is on /; lock waits exceed the 120 s tool timeout (run builds with run_in_background); harnesses must kill by process group, never `pkill -f` a pattern.
- **Progress files before the first heavy command.** Three explorers restarted from zero after the crash.
