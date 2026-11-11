# IMPLEMENTATION_PLAN (template, v4, 2026-10-25)

Source: ARCHITECTURE.md v4 §8–§9 and the plan synthesis. Hours are agent-hours under a driver loop and are **[E]** (no measured velocity; self-report overestimates 4–7×). The driver instruments real throughput and re-plans after Phase 2.

## 0. Shape

Lock toolchains → port the verify wall (oracles that already ran in research) with every negative control red → run the decision-flipping spikes → ship in risk order: **R** reverse proxy → **G** agent gateway → **A/D** native handlers + data plane → **P2** isolation → profiles/FIPS/release → deferred modules.

**Minimum shippable cut line:** Phases 0–2 with gates 0–8, 12, 18, 21 and the metrics gate (SUPPLY_CHAIN §D numbering). Phases 4–6 are conditional on q4-003 (procurement), q1-009 (AI-found exploitation) and the velocity measured after Phase 2. Phases 0–6 total ≈ 1,050–2,050 agent-hours [E] + 8–14 person-weeks expert spec review + 2–4 person-weeks checker qualification.

## 1. Frozen interfaces (before implementation)

Hashed, read-only under `spec/` or `interfaces/`; CODEOWNERS + a PreToolUse deny hook block implementer agents; changes only by spec-change PR from the spec-author role, which re-runs every dependent gate.

| # | artifact | ratification at freeze |
|---|---|---|
| F1 | SPEC_INVARIANTS.md + Lean statement files | statement sha256 committed; proof PRs cannot touch them |
| F2 | monban-types API | Principal constructible only on the authn path |
| F3 | Exchange + front-end hook trait | R-ING-1 reverses if a front end needs >2 hooks |
| F4 | Op IR + Adapter + allowlist lock format | **3VL reference** (q4-004): `eval : Option Bool`, or reject Not over nullable fields at type check |
| F5 | token CDDL, closed caveats, K_aud | D1 segment prefix, D2 op-bitmask subset, D3 depth at verify, D4 missing arg denies; mint-shape check |
| F6 | policy API + Cedar schema | tri-state; Error/timeout/crash ⇒ Deny |
| F7 | SDK surface | streaming shape **blocked on q4-001**: freeze request-scoped subset; streaming unstable |
| F8 | config schema + hard limits | CANON-2 reject vs 308 per clause **after q4-008** |
| F9 | audit event schema | — |
| F10 | out-of-process wire | — |
| F11 | upgrade handover messages | — |
| F12 | `tls/verdicts.toml` (PUB-T1..T6, FIPS-F1..F6) + profile group/sigalg lists | 0x11ED from our KxGroup |
| F13 | conformance report schema | — |

## 2. Verify wall (built before code)

No unit is assigned until its oracle exists outside the implementer's write scope and has failed on a negative control. Research artifacts in `state/raw/round-00N/` are **untrusted input**: port, re-run negative control in repo CI, then gate.

| component | status from research | port effort [E] |
|---|---|---|
| Lean gate + 45 theorems | executed PASS 245 s / 1.0 GB; negative control FAILs (A) | hours |
| known-false-proof corpus (Lean #14484/#14576/#15908, native_decide, sorry, Z3 unsound-unsat, Kani OOM) | specified (B) | 2–4 pw |
| read lowering oracle (SQLite/PG/Redis, 78-case corpus) | executed (A 0.85); add 4 post-fix seeds + self-join family | days |
| write oracle W1/W2/W4 | executed on PG 17.11/19rc1, SQLite, Valkey, Redis (A) | days |
| CANON-DIFF G1–G4 | G2 executed 331/331/69 → 0/0/0 (A) | days |
| MCP 43-case corpus | executed vs 5 implementations (B) | days |
| verdicts + fips_lock_gate | executed (A) | hours |
| cancel sweep | specified (B) | 1–2 wk |
| crash harness | executed (A); add double-fault + EIO | days + q2-007 |
| isolation FI gate | executed 740 cells (B; counts robust, latency not) | days |
| trybuild corpus | executed (B) | hours |
| supply-chain G1–G10 | each executed (A); never end to end | 1 wk |
| swarm simulator | executed, uncalibrated (D) | v2 (q3-005); advisory only |
| ipcbench / bench | laptop (A for laptop) | hours |

Every oracle ships a mutation self-test (e.g. checkin predicate "always reusable" must fail within 100 seeds; removing epoch from the pool key turns CRS C5 red). An oracle that cannot be made red is not a gate.

## 3. Phases

### Phase 0 — repo, pins, wall (≈40–80 h)
Deliverables: skeleton with fail-closed stubs (return `Error`, no `todo!()`); pins; F1–F13 frozen; wall ported; CODEOWNERS + agent deny hooks on `spec/ oracles/ sdk/ ci/ Cargo.lock .github/`.
```
ci/gate.sh                               -> PASS; negative control -> FAIL listing each bad axiom
xtask layering                           -> 0 violations; injected upward edge -> FAIL
cargo deny check && cargo audit --deny warnings && cargo vet --locked   (zero exemptions)
xtask repo-advisories --lock Cargo.lock  -> 0 matches
xtask lock-age --min 7d                  -> 0 unlabelled entries
zizmor --pedantic .github/               -> 0 findings; pull_request_target PR -> FAIL
repro double build                       -> equal sha256; without registry remap -> differ
every oracle self-test                   -> red on mutated subject
```
Go: all pass on a clean checkout with zero manual overrides.

### Phase 1 — decision-flipping spikes (≈60–120 h; ≤2 compiling jobs, `heavy.sh` 6 GB cap)

| spike | flips if |
|---|---|
| q3-001 handshake on a real $5 1-vCPU KVM (full/resumed × X25519/hybrid; steal, kernel) | hybrid >1.3× → R-PERF-1; <500 full hs/s → S0.5 retune |
| q3-002 ipcbench same/cross core on VPS | hop >12 µs → R-MOD-1 budget <≈8k calls/s/core |
| q4-008 CANON false-reject on 1M real request lines (own logs or public corpora) | >0.1% per clause → 308/repair for that clause |
| q4-001 B2 streaming/SSE/WS/detached | leaky `'static` needed → host-owned stream capability |
| q4-004 3VL Lean re-proof | fails → reject Not over nullable (F4) |
| q3-008 PG reconnect under discard-on-cancel | >20 ms p50 or <200 cancels/s → state-tracked reuse |
| q2-007 double-fault + EIO stages | SQLite FULL fails → redb default (or vice versa) |
| q2-009 window-0 stall harness | wrapper does not bound memory → lower stream cap |
| q4-006 fuel + 64-slot pool loop gate **+ VPS fork-cost run** | decides fresh-Wasm cordon vs fork+Wasm as multi-principal P2 default |
| q4-026 0x11ED KxGroup interop + FIPS-boundary check | interop fails → P-UNIVERSAL fallback (P-BSI-ALT minus 0x11ED + pure ML-KEM-1024) |
| q4-005 MySQL/MariaDB + CockroachDB write oracle | leaks → extend denylist; adapters non-golden until 0 leaks |
| cmvp client policy (compiled-out vs PQ-only) | neither gate passes → cmvp ledger entry for 0349 invalid; cmvp ships without clients |
| release drill (advisory → TUF release) | sets the ≤6 h target's real number |

Reading tasks in parallel: q4-003, q1-009. Go: every spike writes a journaled verdict file; flips applied to F1–F13 by the spec author before Phase 2.

### Phase 2 — reverse-proxy mode "R" (≈200–400 h): first shippable
Scope: canon, budget, transport, tls (P-PUBLIC-WEB hybrid-first with PreferServerOrder backport; pq-required agent/API profile), admission S0–S3 (numbers provisional), config, ops (ACME, CERT, upgrade), audit, **metrics endpoint**, iso supervisor (socket holder), H1/H2 upstream with framing regeneration.
Gates: CANON-DIFF green; Kani TBI H1–H5 (serial, 6 GB, OOM/timeout FAIL); fuzz resource-ratio over Rapid Reset, MadeYouReset, CONTINUATION, HTTP/2 Bomb, Header Accordion, VU#885548 corpus, 0 violations at 1e8 execs; HTTP Garden 0 new cells; h2spec 100%; verdicts.toml unchanged; fail-closed default boot; budget gate; systemd ≤2 + runtime test; CFG fuzz 1e7/0 panics + 3× oversize serves last-known-good; CERT-4 faketime; upgrade harness 0 drops before D over 100 reloads; **metrics gate**: admin endpoint present without any feature flag, all golden counters exported; **perf gate** (below).
Go: ship `monban-proxy` 0.1 only if every gate passes; otherwise stop and profile.

### Phase 3 — agent gateway "G" (≈150–300 h)
Scope: agent (listener gate, both eras, sealed handles), authz (Cedar + combiner), token (Tier 0 + L; Tier X verify), egress, Web Bot Auth after S1.
Gates: 43-case corpus 100% with 0 handler invocations on rejects; 33 advisory cases; Lean Combine/Token gate; DRT Lean vs Rust verifier 1e6 cases 0 divergence; fuzz F1–F9 1e8/target; dudect on MAC compare (no leak); host-mapping DST (timeout/crash/panic → Error → Deny); Cedar `#print axioms` recorded (theorems cited at B until then); SSRF corpus 0 connects to non-allowlisted addresses.

### Phase 4 — data plane + native handlers "A/D" (≈300–600 h; conditional)
Scope: data-ir; PG/SQLite/Redis adapters; state (idempotency, outbox, latch); SDK B2 (+streaming if q4-001 passed); adapter-host.
Gates: read oracle leak=0 ∧ miss=0, ≥100k cases at ENGINE_PIN; write oracle hardened forms 0/300 per family; schema gate refuses every counterexample schema; INV-NONEMPTY 100k/adapter; allowlist lock regenerates byte-identically; cancel sweep green + self-test red ≤100 seeds; CRS differentials incl. nginx CVE-2025-23419 replica; trybuild ≥25/32, residual as frozen; crash harness incl. double fault; PG minor floor asserted; PG19 blocked until ON CONFLICT fix; pg_query (if used) only at build time or out of process (`cargo metadata` check: no `pg_query` in `monban-bin` graph).

### Phase 5 — P2 isolation (≈150–300 h; conditional)
Scope: iso full (exec zygote, per-tenant cordons, **fork+Wasm mode**, crash budgets, dumpable=0); wasm (fresh instance per request, fuel, epoch watchdog, MPK density option behind GHSA-6wgr/394w assertions). **Both P2 paths are built and gated**, because P(R1 fires within 12 months) ≈ 0.38 at the 2.21/yr planning rate; the Phase-1 verdict chooses the default.
Gates (each path): ≤0.05 crash-attributable healthy failures per fault at 1%; 0 wrong answers; poison 0; recovery p99 ≤5 ms; throughput ≥0.5× at 1% loop; negative syscall tests (CLONE_NEWUSER, socket, TCP_ULP, bpf, io_uring killed/ENOSYS); hostile-module corpus I1, I2, I5, I6-host, I7 hold; wasmtime pin/config assertions. Re-run on a quiet VPS-class runner; thresholds move only if shifted >2×.

### Phase 6 — profiles, compliance, release (≈150–250 h; conditional)
Scope: P-UNIVERSAL/P-BSI-ALT/P-CNSA; floor + cmvp locks; FIPS-string gate; cmvp client policy gate; COMPLIANCE_MAP + SA-17(1); CRA steward file set; release pipeline (attest in a separate job, independent rebuild on a second runner image, TUF 3/5, **triple signature** Ed25519 + SLH-DSA-SHA2-128s + ML-DSA-87); conformance suite.
Gates: `fips_lock_gate --profile cmvp` (exactly one fips-sys node, reachable from aws-lc-rs, `AWS-LC FIPS 3.1.0` string present); exception ledger valid (no expired entry; 0349 entry cites the passing client-policy gate); per-profile ClientHello matrix; **Lean group-selection model checked; 0x11ED KATs + interop (OpenSSL 3.5+, BoringSSL) + Kani share-parsing harness**; second-runner hash = attested digest; conformance C0–C2 100%.

### Phase 7 — deferred (each off by default, own TCB line)
HTTP/3 (after h3 #366/#377/#378 + 6 months without HIGH quinn advisory) · L4/PROXY · WebTransport · more adapters (F4 + two-sided oracle) · io_uring front opt-in · MTC CredentialSelector · **libcrux-based non-FIPS CryptoProvider spike** (shrink Tier-S C for P-PUBLIC-WEB; claim "smaller C surface") · OTLP if not resolved earlier · 64-core scaling run.

## 4. Machine-checkable perf and advisory gates

```yaml
- name: perf-w1
  cmd: "bench/run --workload W1 --tier T1 --metric cgroup_us_per_req --reps 5 --abba --baseline nginx-1.31.8"
  pass: "median(monban_us) <= 2.0 * median(nginx_us) over >=5 ABBA reps, same run, same TLS group"   # >=0.5x nginx
  note: "provisional on laptop tier until T1 run; grade cap B"
- name: goodput-w7         # ADVISORY until first run sets numbers [E]
  cmd: "bench/run --workload W7 --tier T1 --attack-rates corpus.toml"
  pass: "record_only"
- name: ai-redteam         # ADVISORY until first run sets per-model ASR baseline [E]
  cmd: "redteam/run --episodes 20 --families smuggling,ssrf,authz,mcp-poison,dos"
  pass: "canary_triggers == 0; asr: record_only"
- name: swarm-sim          # ADVISORY until calibrated [D]
  pass: "record_only"
```

## 5. Phase gate template (`gates/phase-N.yaml`, run by `xtask gate phase N`)

```yaml
phase: 2
requires: [phase-1-verdicts.json]
gates:
  - {name: canon-diff,  cmd: "oracles/canon-diff --g1 100000 --g2 pinned --g3 ledger", pass: "nonzero_cells == 0"}
  - {name: tbi-kani,    cmd: "ci/kani.sh --serial --mem 6G tbi_*", pass: "all VERIFICATION SUCCESSFUL and cbmc_exit in {0,10}"}
  - {name: budget,      cmd: "xtask budget", pass: "stripped_mb<=6.0 && crates<=60 && idle_rss_mb<=8 && tls1k_mb<=25"}
  - {name: metrics,     cmd: "xtask metrics-check --no-features", pass: "missing_counters == 0"}
  - {name: upgrade,     cmd: "oracles/upgrade-harness --reloads 100", pass: "dropped_before_D == 0"}
  - {name: verdicts,    cmd: "oracles/hrr-verdicts --file tls/verdicts.toml", pass: "diff == 0"}
negative_controls: [canon-diff:inject-lenient-path, tbi-kani:remove-stall-timer, metrics:drop-counter]
go_no_go: "all gates pass && all negative controls fail"
```

## 6. How coding agents execute it (META PROTOCOL §2)

1. **Roles.** Spec author (F1–F13, Lean statements, oracle expectations, thresholds; never implements). Implementer (read-only on `spec/ oracles/ sdk/ ci/`). Prover (one lemma per session against hashed statements). Reviewer (different model family; a screen, never a gate). Proposers never score themselves.
2. **INFEASIBLE exit.** Every prompt and the Stop gate accept a certified `INFEASIBLE_REPORT.md` (spec clause, failing case, minimal reason); an abort option cut cheating from 54% to 9% (`e-impossiblebench` B). Weakening a test is never a resolution.
3. **Stop gate.** Block via stdout `{"decision":"block","reason":…}` with exit 0 (never exit 2: #99171 fails open); hash-pinned oracle path; internal timeout blocks on oracle error; refusal counter below `CLAUDE_CODE_STOP_HOOK_BLOCK_CAP` (8); at MAX_REFUSALS allow stop + write INFEASIBLE report.
4. **Units and partitions.** Units <~1 h; driver owns the DAG; partition by crate per layering; hub files (`Cargo.toml`, `Cargo.lock`, `monban-types`, `spec/`) integrator-only; leaves parallel, shared-interface writers serialized; worktrees created serially with absolute paths; assert `git merge-base --is-ancestor <integration-HEAD> HEAD`; test combined tree after each merge, bisect on failure.
5. **Laptop concurrency (§0e).** ≤2 compiling agents; every build under `heavy.sh` (6 GB, nice 15); `run_in_background` for builds waiting on the lock; progress file within 2 min; subagent depth 1, ≤5 spawns per worker, "do not spawn" line in every worker prompt.
6. **Journaling.** Hash-chained journal keyed by (run_id, step, tool_use_id); pin Claude Code version, model ids, CLAUDE.md sha256; SDK resume is never replay.
7. **Dependency intake.** Only via the `cargo add` wrapper and the G5 gate; sandbox has no crates.io token.
8. **Proof work.** LLM synthesis optional, cloud only; plan must succeed with humans/Claude writing Lean against the 712 MB toolchain; no Lean claim above C without file path + gate log.
9. **Honest loop evaluation.** Single-run deltas <~3pp are noise; ≥5 runs per arm; never estimate speed-ups from self-report.

Unit template (`units/<id>.json`; immutable except `passes`, `journal`):
```json
{"id":"P2-transport-017","crate":"monban-transport","spec_refs":["F1#TBI-8","F3"],
 "spec_sha256":"…","oracles":["oracles/stall-dst --seeds 200","kani:tbi_h4"],
 "acceptance":{"cmd":"xtask gate unit P2-transport-017","must":"exit 0"},
 "write_scope":["crates/monban-transport/src/stall.rs","crates/monban-transport/tests/stall.rs"],
 "infeasible_exit":true,"max_retries":30,"passes":false}
```

## 7. Migration path for existing apps [C ordering]

| mode | user change | invariants that hold | do **not** hold |
|---|---|---|---|
| R reverse proxy | DNS/port in front of nginx/Node/PHP/Go | TBI, CANON at edge (forward exactly as checked), PQ KX, fail-closed admission, CRS for tickets/pools, edge audit, UP/CERT/CFG | anything inside the app; CANON-8 per-upstream folding profile required |
| G gateway | MCP/API behind listener gate; tokens | + listener gate, audience, Cedar fail-closed, SSRF guard, sealed handles | app DB access and side effects |
| A native handlers | port routes to B2 one by one (strangler) | + capability-typed handlers, INV-NOMUT-C, idempotency | unported routes |
| D data plane | ported routes via Op IR + per-tenant creds | + INV-NONEMPTY, two-sided lowering, INV-WRITE-SUBSET (golden adapters) | PEP-only families with third-party adapters |
| P2 | agent-generated/third-party handlers as Wasm | + crash containment, no poisoning | microarchitectural isolation in a shared process |

Parity deliverables for R (R-GAP-4): ingress-nginx annotation translator with an unsupported list; defaults-compatible profile with a Nine-style default-diff checklist; graceful reload, rate limiting, metrics at v1 (no paywall); household 3-line config, auto-ACME, static binary. Kubernetes Gateway API surface later (distribution channel matters more for that segment, `v4.ingress-migration-distro-channel` C).

## 8. What the plan does not claim
Phase gates prove models and executed oracles, not the Rust code (all proofs R4). Renderer = Lean `lower` by DRT only. hyper H1 framing, tokio, Wasmtime runtime, aws-lc C outside verified parts, rustc/LLVM are residuals. No regulator credits code proofs. All admission numbers D; all laptop perf numbers provisional until T1.
