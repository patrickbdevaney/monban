# 05 authz-capabilities-with-formal-semantics — progress (2026-10-24)
## Sources 1-6 (Cedar)
- cedar-spec @301bdd2 (2026-10-23), Lean v4.35.0: 387 .lean files, 125,621 LOC total; Thm/ 226 files 96,228 LOC; 3,912 `theorem` decls; 0 `sorry`; 1 `partial def` (SMT S-expr decoder, SymCC/Decoder.lean:161); 2 @[implemented_by] in CedarFFI (solver). Thm files: Authorization (forbid_trumps_permit, default_deny, allowed_only_if_explicitly_permitted), Validation (validation_is_sound, validate_with_level_is_sound), SymbolicCompilation (compile_is_sound/complete, isAuthorized_is_sound/complete), Verification (verifyNeverErrors/AlwaysMatches sound+complete), PolicySlice, TPE (partial eval reauthorize_is_sound), BatchedEvaluator.
- cedar-drt fuzz targets ~60+ incl abac, rbac, symcc-*-drt, protobuf roundtrip.
- crates: cedar-policy 4.14.0 (2026-10-17), cedar-policy-symcc 0.8.0 (2026-10-17).
- GHSA-m84h-6f26-p3p7 (high, 2026-10-22): parser OOM, 258-byte policy -> ~29GB alloc; >=4.3,<4.13. Parser error path to_string expands Arc sharing. OUTSIDE Lean model.
- GHSA-c33x-vcv4-vg3g (low, 2026-06-25): JSON template `is in` slot-id silent correction -> panic / decision divergence; fixed 4.11.1/3.4.3. Outside model (JSON->AST conversion).
- arXiv 2403.04651 (= PACMPL OOPSLA1 2024, Cutler et al.): Cedar 28.7-35.2x faster than OpenFGA, 42.8-80.8x faster than Rego; median 4-5us (gdrive), ~11us (github), p99 <10/<20us on m5.4xlarge, Cedar 3.0.1. SMT analysis ~75.1ms avg. Encoding decidable sound complete (CVC5 sets, bitvectors).
- arXiv 2407.01688 (FSE Companion 2024): VGD; proofs found 4 validator bugs, DRT+PBT 21 more.
## Sources 7-16
- SymCert (Torlak, FMCAD 2026, amazon.science): Lean framework; verified symbolic compiler + hierarchy enforcer + cex extractor; 5 AWS analyses modeled+proved in ~1 work day; extensions 4-8 days each.
- CaMeL arXiv 2503.18813 v? (updated 2025-06-24), SaTML 2026 pp.587-618: 77% AgentDojo tasks w/ provable security vs 84% undefended. repo google-research/camel-prompt-injection.
- Progent 2504.11703 (v3 2026-05-14): symbolic rules over tool names/args; SMT decides policy update narrowing (auto) vs expansion (approval) -> "monotonic confinement". AgentDojo+ASB.
- FIDES 2505.23643 (MSR): formal model of planners; characterizes properties enforceable by dynamic taint tracking; conf+integrity labels; github microsoft/fides.
- Tallam&Miller 2505.22852: Operationalizing CaMeL (critique: trusted user prompt assumption, side channels, dual-LLM cost).
- Beurer-Kellner et al 2506.08837 design patterns (plan-then-execute, action-selector, dual LLM, code-then-execute, context minimization...).
- arXiv recent (Aug-Oct 2026) agent IFC/authz wave: SPIDES 2610.24277 (IFC for browser agents), Can CaMeLs Talk 2610.05640 (multi-agent), Ajar 2609.26900 (measuring open privilege), From Approval to Abuse 2610.22987 (priv-esc on harness-protected coding agents), Kairos 2610.18457, ToolFence 2609.37196, Authority Is Not a String 2609.08371, Silent Failures harness 2609.32691, CaMeLoT 2609.18674, crypto-bound capability tokens 2609.30824.
- Biscuit: spec SPECIFICATIONS.md datalog v3.0-v3.3, no negation (reject if from v3.3), signature algs ed25519|secp256r1 ONLY (no PQC), scopes/trusting annotations. biscuit-auth 6.0.0 (2025-07-16) - no release in 15 months though repo commits Oct 2026. CVE-2024-41949 / GHSA-p9w4-585h-g3c7 third-party block public-key confusion. No formal model found (negative search).
- UCAN spec README "Version 1.0.0" (repo pushed 2026-10-22); delegation spec v1.0.0; sigs Ed25519/P-256/secp256k1 via Varsig, canonical sig required; jq-subset policy language; replay via CID uniqueness. No PQC alg in spec ("off spec" extension via varsig header).
- Rego: no formal semantics paper found (negative search, needs one more needle).
## Sources 17-26
- Swasey/Garg/Dreyer OOPSLA 2017 (PACMPL 1, art.89) OCPL: Iris/Coq mechanized robust safety for ocap patterns (sealing, membrane, caretaker). Distinguished paper.
- Zelkova FMCAD 2018 (Backes et al., DOI 10.23919/FMCAD.2018.8602994): SMT (strings/regex/bv), PSPACE-complete, "many millions of times daily"; basis of S3 Block Public Access. No "billion" figure confirmed.
- OCapN repo (pushed 2026-10-13): draft-specifications CapTP, Locators, Model, Netlayers; no tagged releases -> draft.
- Rego: Kreuze MS thesis Brown Feb 2024 (advisors Lewis, Krishnamurthi): Lean 4 formalization of Rego + XACML 3.0 fragment, policy equivalence; only academic formalization found. No verified OPA evaluator. opa-mcp-server rego_verify Z3 tool (simple string/regex only).
- AgentDojo results page: newest row 2025-02-24 (claude-3-7-sonnet none: util 88.66%, ASR 7.31%); gpt-4o baseline ASR 47.69%; tool_filter 6.84%; spotlighting 41.65%; pi_detector 7.95% (util 41%). Page says "not a leaderboard". No CaMeL/Progent rows -> numbers come from papers.
- Can CaMeLs Talk 2610.05640: CaMeL guarantees DO NOT COMPOSE in hierarchical multi-agent; concrete attack; multi-CaMeL ASR 0.0% vs 0.2% CaMeL vs 12.9% none (MultiAgentDojo).
- SPIDES 2610.24277 (MSR): element-level HTML conf/integrity labels gate browser actions; 0% ASR by design on MicroNet (28 sites).
- Ajar 2609.26900: "open privilege" third axis; Progent, CaMeL, AC4A, Permission Assistant, Claude Code Auto mode leave widely different privilege open; not derivable from ASR/utility.
- From Approval to Abuse 2610.22987: injected repo context steers agents to request broad allow-rules; 58% elicitation in Claude Code/Codex CLI; rules cover 56.9% of capability tests; 47/58 (81%) silent goal completion conditional on approval. => approval-gated privilege expansion (Progent-style) is an attack surface.
- Kairos 2610.18457: reference monitor at isolation boundary (file+network ops), deferred effects held, bounded-authority oracle; AgentDojo ASR 47.0% -> 2.7% at undefended utility.
- ToolFence 2609.37196: typed authorization blueprint compiled pre-execution, deterministic monitor, judge grants capabilities; near-zero ASR, -3.80pp utility (Qwen3-max); critiques CaMeL latency.
## Sources 27-36
- Biscuit RunLimits default (biscuit-auth 6.0.0 src/datalog/mod.rs:751): max_facts 1000, max_iterations 100, max_time 1ms WALL CLOCK => decision can depend on load (nondeterministic deny); no fuzz/ proptest dirs in repo.
- FIPS 204 (2024-08-13) Table 2: ML-DSA-44 pk 1312 sk 2560 sig 2420; -65 pk 1952 sk 4032 sig 3309; -87 pk 2592 sk 4896 sig 4627.
- FIPS 205 Table 2: SLH-DSA-128s pk 32 sig 7856; 128f pk 32 sig 17088; 192s pk48 sig 16224.
- FIPS 206 FN-DSA still draft (submitted for approval 2025-08-28 per secondary); draft-ietf-lamps-fn-dsa-certificates-00 (May 2026).
- ZCAP: CCG work item, v0.3 out of sync with prod; v0.4 plan (Apr 2026, Zagidulin); W3C no budget for security WG (Sporny Jul 2025). DIF: zCaps and UCAN only chained-delegation options.
- SpiceDB consistency doc: minimize_latency default for checks (new-enemy window), at_least_as_fresh w/ ZedToken, at_exact_snapshot, fully_consistent (not read-after-write on CockroachDB). No formal verification mentioned.
- Devriese/Birkedal/Piessens EuroS&P 2016 pp.147-162: logical relation + effect parametricity; prior formal characterisations of capability safety insufficient.
- Repo status (2026-10-24): osohq/oso ARCHIVED (last release 2024-06); openfga v1.22.0 (2026-10-06) 29 GHSAs total, 12 "Improper Policy Enforcement"/bypass since 2025 (exclusion `but not` + error/wildcard paths); spicedb v1.57.0 (2026-10-20) 18 GHSAs incl GHSA-4vrg-r928-h5vv (caveat+intersection/exclusion under concurrency -> HAS_PERMISSION instead of CONDITIONAL); OPA v1.21.4 (2026-10-23) 4 GHSAs incl GHSA-g2pf-6v5v-qcc8 (2026-10-19 high: unsigned bundles accepted when keyid omitted), GHSA-6m8w-jc87-6cr7 (Rego injection via Data API path), GHSA-f524-rf33-2jjr (with-keyword bypass of unsafe builtins); cedar 2 GHSAs; souffle 2.5 (2025-03); camel repo last push 2025-06-20 (research artifact); microsoft/fides last push 2025-05-30.
## Sources 37-44
- CapScope "Authority Is Not a String" 2609.08371: typed caps outside model ctx, per-subagent; injected effect 3/75 vs 33-47/75 baselines; 68/75 completion.
- CaMeLoT 2609.18674: plan -> finite transition system, CTL via nuXmv before execution.
- 2609.30824 crypto-bound capability tokens (OAuth agent profile + DID/VC) proposal.
- Silent Failures 2609.32691: tool-identity scoring 21.7% ASR vs argument-level 1.2%; a model reported 62.8% -> 0% corrected. Benchmark validity is load-bearing.
- seL4 Sewell ITP 2011 integrity + authority confinement (Isabelle, refined to C); Murray S&P 2013 noninterference (modified scheduler; timing excluded).
- Li & Mitchell CSFW 2003/IJIS: SPKI/SDSI FOL semantics; RFC 2693 proof procedure semantically incomplete; tags problematic.
- Macaroons NDSS 2014 (DOI 10.14722/ndss.2014.23212): chained HMAC caveats, formalized in authorization logic.
- Cedar docs: skip-on-error: erroring policy (incl forbid) is skipped -> erroring forbid cannot deny.
