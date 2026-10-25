#!/usr/bin/env python3
"""AEGIS round-1 integrator: dedup, verifier grades, graph/edges/seen/queue/queries/directions. Deterministic."""
import json, glob, os, re, sys, collections
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

R = 1
DATE = '2026-10-24'
ROOT = '/home/patrickd/aegis/research'
ST = ROOT + '/state'
RAW = ST + '/raw/round-001'

# ---------------- verifier verdicts (two-sided, round 1) ----------------
# id: (grade, confidence, direction, note)
V = {
# 01 threat
'threat-ledger-middle-tier-2023-2026': ('B',.75,'unchanged','Ranking is judgement; GHSA-publishing projects (Envoy/Caddy/undici) over-counted vs nginx/httpd; "dominates KEV" holds for gateway/appliance products, not OSS servers (<=5 OSS KEV entries).'),
'result-memory-safety-would-not-prevent-fraction': ('B',.8,'unchanged','Verifier recomputed KEV non-memory 81.2% (723/890) vs claimed 80.3%; CWE-list dependent; nginx 2026 alone is ~19/26 memory, so the 23% nginx logic share is a multi-year average.'),
'threat-h2-h3-resource-exhaustion': ('A',.9,'up','HTTP/2 Bomb CVE-2026-49975 (Calif/Codex, 2026-06-02) is a protocol-composition bug (HPACK amplification + zero window) that hit nginx, httpd, IIS, Envoy, Pingora in default config (>880k hosts); Varnish VSV00017 shows MadeYouReset bypassed the Rapid Reset limit.'),
'threat-request-smuggling-desync': ('A',.88,'unchanged','nginx 2026 adds 3 injection/desync advisories (CVE-2026-42926, -95101, -1642); Kettle bounty total not re-resolved.'),
'threat-path-canonicalization-authz-bypass': ('A',.85,'unchanged','KEV entries confirmed; CVE-2025-24813 is CWE-44/502 and CVE-2024-38475 is CWE-116, i.e. path-equivalence/escaping rather than pure authz bypass.'),
'threat-fail-open-config-and-auth-logic': ('B',.8,'down','CWE-287/288/306 KEV dominance is proprietary appliances (Fortinet/F5/Ivanti), not OSS middle-tier; OSS examples are single advisories.'),
'threat-memory-corruption-c-servers': ('A',.88,'up','nginx 26 (2026) vs 2 (2025), ~19 memory; CVE-2026-42533 CVSS4 9.2 / v3.1 8.1, RCE needs ASLR bypass, no public PoC per SOC Prime; F5 BIG-IP KEV CVE-2025-53521 and CVE-2026-94127 are fresh appliance memory entries.'),
'threat-decompression-parser-complexity': ('B',.8,'unchanged','Only the OSV API root is cited; HTTP/2 Bomb (HPACK) suggests impact above medium.'),
'threat-tls-validation-logic': ('B',.75,'unchanged','nginx 2026 TLS-adjacent CVE-2026-97629, -28755, -40701 strengthen the class; Envoy/undici/Go/rustls ids not re-read.'),
'threat-mcp-agent-layer': ('B',.75,'unchanged','SDK advisories confirmed in OSV (CVE-2026-111771 published 2026-10-20); Langflow 6-KEV and postmark-mcp priority not verified.'),
'result-ai-discovery-capability-2025-2026': ('B',.75,'unchanged','AIxCC real-vuln patches 11/18 with 0/6 C; USENIX Sec 2026 SoK: finalist CRSs unusable outside the competition cloud; CyberGym "97%" not found (91.2-91.3% vendor, E2E 63-66%); ExploitGym tallies give 17.5%/13.4% on 898 instances.'),
'result-time-to-exploit-trend': ('B',.72,'unchanged','Mandiant samples n=112 (2024)/138 (2023); 2025 -7d is a GTIG estimate; VulnCheck day-zero share FELL 28.9% (2025) -> 23.4% (1H2026); CVE-to-KEV median 80d (from 120d).'),
'skeptic-ai-exploit-overhype': ('B',.72,'down','14/1061 confirmed but window is short (Glasswing began April); Glasswing "126 CVEs" is secondary-only; VulnCheck denominators unstable (225/75/40; 2,736 of 26,153 disclosed).'),
'observation-2026-advisory-surge': ('B',.8,'unchanged','CVE IDs >100000 already in use: normalise trends against overall CNA volume; GHSA-vs-page publishing conventions differ.'),
'l5-structural-controls-implied': ('E',.7,'unchanged','Design inference, hypotheses for next stage.'),
# 02 gap
'gap.pingora': ('A',.92,'unchanged','CVE-2026-2836 is high (not critical) and an insecure-by-default cache key; Oct-20 trio are CVE-2026-105297/8/9.'),
'gap.envoy': ('A',.88,'unchanged','Advisory API capped at 100: total is a lower bound.'),
'gap.nginx': ('A',.85,'unchanged',''),
'gap.nginx-unit': ('A',.88,'unchanged','FreeUnit has 7 GHSA (omitted by explorer).'),
'gap.caddy': ('A',.85,'unchanged','Go 1.24 PQ default via secondary source.'),
'gap.ferron': ('A',.85,'unchanged','2026-09-25 batch is 1 critical + 5 high + 1 medium (6 high/critical, not 7).'),
'gap.spin': ('A',.85,'unchanged',''),
'gap.wasm-hosts-other': ('A',.8,'unchanged','workerd has 2 GHSA (explorer omitted).'),
'gap.wasmtime-adv': ('A',.9,'unchanged','81 published GHSA via API matches.'),
'gap.hyperlight': ('B',.72,'unchanged','Latency figures vendor-only.'),
'gap.firecracker': ('A',.85,'unchanged','"kani" 17 hits but "kani::proof" 9: ~9 harness sites; Kani is bounded model checking.'),
'gap.docker-mcp-gateway': ('A',.88,'unchanged','Also CVE-2026-55887 (high), -76095 (file:// read), two Oct-2026 advisories; no GitHub "latest" release so v0.44.2 unconfirmed.'),
'gap.agentgateway': ('A',.85,'unchanged','CVE-2026-29791 is medium; two further medium policy-scoping advisories.'),
'gap.unserved-combination': ('C',.65,'unchanged','Absence claim over ~45 repos; closed products not checked; conjunction shrinks match set by construction.'),
'gap.no-assurance-claims': ('C',.62,'unchanged','Code search misses Lean/Coq/TLA+ in other repos; Coq/VST verified HTTP KV server (ITP 2021) exists as research precedent.'),
# 03 formal
'proof-verus-sosp24-casestudies': ('B',.85,'unchanged','Not re-fetched; tool-author effort.'),
'proof-anvil-osdi24': ('B',.75,'unchanged',''),
'proof-verismo-osdi24': ('B',.85,'unchanged',''),
'proof-vostd-asterinas': ('B',.75,'unchanged','1,387-line/23-function figures unconfirmed.'),
'llm-verusage-2025': ('B',.8,'unchanged','Abstract confirms >80% and >90% unfinished-human tasks; per-model numbers, costs and cheating rates not verified; PLDI keynote says 9 projects vs paper 8.'),
'llm-kverus-2026': ('B',.75,'unchanged','Repo-level 51.0% vs 4.5% (183/359) confirmed; CortenMM only 31.3%; weak baseline.'),
'llm-vericoding-2025': ('B',.75,'unchanged','82/44/27 are model-union headline figures; per-model bests unverified; task set 12,504 full vs 10,868 retained.'),
'llm-dafny-agents': ('C',.7,'down','AxDafny 92.7% confirmed (arXiv 2606.32007) but DafnyComp 3.69% is from 2025 models: apples-to-oranges; DafnyBench likely contaminated.'),
'llm-lean-provers-transfer': ('B',.7,'unchanged','VeriSoftBench qualitative claim confirmed; per-model numbers unverified.'),
'proof-aeneas-symcrypt': ('B',.85,'up','Code public on microsoft/SymCrypt feature/verifiedcrypto; safety + panic-freedom + functional correctness on x86-64 and ARM; specs still human-designed; FrodoKEM/ML-DSA/HPKE experimental.'),
'proof-everparse-hyperv': ('B',.85,'unchanged','Primary URL is an IETF slide deck.'),
'proof-vest-verdict': ('B',.75,'unchanged','Crates 0.1.x.'),
'gap-verified-http1-parser': ('C',.65,'up','CVE-2026-69216 is http4s Ember (TE.TE chunk-size), not a Rust/nginx server; research precedents exist (Coq/VST HTTP KV server ITP 2021, TRX verified parser interpreter): gap is production-grade machine-proved HTTP/1.1 framing.'),
'proof-cedar-lean': ('B',.8,'down','4 proof bugs + 21 DRT/PBT bugs confirmed; LOC figures unconfirmed.'),
'proof-aws-authz-dafny': ('B',.8,'unchanged','Perf claim conflicts: 3x (ICSE abstract) vs 65% (re:Inforce 2024); Dafny->Java adds compiler + JVM to TCB.'),
# 04 isolation
'iso-glue-not-boundary-pattern': ('B',.7,'down','Own examples contradict "rarely the core": CVE-2026-34971 is codegen inside the sandbox compiler; Januscape is a KVM-core bug. No denominator/base rate.'),
'wasmtime-ghsa-record-2021-2026': ('B',.8,'down','"81" is the Security-tab badge; the 57-in-2026 count and severity split are unverified (RustSec counts 41 for wasmtime in 2026); CVE-2026-34971 range NVD 32.0.0+ vs Wiz 37.0.0-42.0.1/43.0.0.'),
'wasmtime-llm-audit-sprint-2026-04': ('A',.88,'up','Primary post: 12 advisories = 2 critical/7 moderate/3 low; 11 LLM-found; 12th (GHSA-hfr4-7c6c-48w2) user-found; patches also for 24.0.7.'),
'cranelift-veriisle-ci': ('B',.7,'down','README confirms the CI job and thinner x64 coverage, but not the stale-at-32.0.0 / caught-CVE-2026-34971 narrative or merge-gating; needs workflow YAML check.'),
'wasmtime-memory64-spectre-config': ('B',.75,'unchanged','Second "aarch64 critical" (CVE-2026-34987 Winch) not shown memory64-gated; config is recommendation.'),
'wasmtime-pooling-local-bench': ('A',.88,'unchanged','Raw output matches every figure; single-threaded laptop, wasmtime 36.0.19, tiny core module.'),
'nanvix-same-hw-coldstart-2026': ('B',.78,'unchanged','Numbers extracted from PDF confirmed; authors build Nanvix and compare with Microsoft Hyperlight (home-field); unoptimized Firecracker boot baseline; preprint.'),
'kvm-januscape-cve-2026-53359': ('B',.8,'down','Post says risk is for untrusted guests with nested virt exposed; "every KVM substrate inherits" overstates; $250k tier not on page.'),
'hyperlight-microvm': ('B',.72,'unchanged',''),
'v8-isolates-security-posture': ('B',.82,'unchanged','workerd README warning confirmed.'),
'wasi-resource-isolation-attack-usenix25': ('A',.85,'up','USENIX Sec 2025 pp.1111-1128 confirmed; mitigation is cgroup v2 io.max + process separation (outside Wasm).'),
'fuel-not-a-security-bound': ('B',.8,'down','PR #3699 says "twice as fast for some workloads" (2021-22); fuel CVE ids unverified; fuel is deterministic, epoch is not.'),
'crash-isolation-semantics': ('A',.86,'unchanged','run2 output confirms; single run.'),
'rust-type-system-not-adversarial-boundary': ('A',.9,'unchanged','166 open I-unsound confirmed.'),
'spectre-posture-matrix': ('B',.72,'unchanged','No source re-fetched; post-2021 variants (Retbleed/Inception/BHI) not covered.'),
# 05 authz
'authz-formal-pdp-comparison': ('B',.82,'unchanged','UCAN 1.0 has empty Releases page: final status unconfirmed; IETF agent-attenuation drafts are competitors for (d).'),
'cedar-lean-proofs-2026-10': ('A',.88,'down','Counts from explorer clone at 301bdd2; not independently recounted.'),
'cedar-policy-crate-4.14': ('B',.85,'unchanged','Both GHSAs confirmed; GHSA-m84h trigger is a nested-attribute "has" path; perf figures vendor-authored on 3.0.1.'),
'cedar-drt-harness': ('B',.88,'unchanged','21 is DRT+PBT combined.'),
'cedar-skip-on-error-semantics': ('B',.8,'unchanged',''),
'biscuit-auth-6.0': ('B',.8,'down','RunLimits defaults and CVE-2024-41949 detail not re-verified.'),
'macaroons-ndss2014': ('B',.85,'unchanged','32 B/caveat and PQ-safe are explorer inferences.'),
'rego-formal-status': ('B',.8,'up','GHSA-g2pf (high, 2026-10-19) and GHSA-6m8w confirmed exactly.'),
'rebac-decision-bug-cluster': ('B',.75,'down','Counts and ids not re-fetched; title-based classification.'),
'ocap-formal-foundations': ('B',.82,'unchanged',''),
'camel-2503.18813': ('B',.82,'unchanged',''),
'camel-noncompositional-2610.05640': ('B',.82,'up','ASR 12.9/0.2/0.0 confirmed; self-built benchmark; preprint.'),
'progent-2504.11703': ('B',.85,'up','SMT narrowing/expansion confirmed; policy itself LLM-generated.'),
'spides-2610.24277': ('B',.75,'unchanged','MicroNet is self-built (28 sites); code at microsoft/SPIDES.'),
'approval-to-abuse-2610.22987': ('B',.85,'up','58% / 56.9% / 81.0% (47/58 conditional on approval) confirmed.'),
# 06 transport/pqc
'std-rfc10024-ecdhe-mlkem': ('A',.96,'unchanged','RFC 9954 is Informational; pure ML-KEM draft-ietf-tls-mlkem contested (blocked, author input required).'),
'std-pq-x509-rfcs': ('A',.93,'unchanged','ML-DSA-in-TLS still a draft: PQ handshake auth not standardized.'),
'std-mtc-plants': ('B',.85,'unchanged','draft-07 IESG state "I-D Exists"; Chrome phases are plans; ACME-only not seen in blog.'),
'std-cnsa2-dates': ('C',.75,'unchanged','Secondary sources only; a 2031-12-31 general date also circulates; check NSA primary.'),
'std-nist-ir-8547': ('B',.88,'unchanged','A June 2026 EO/OMB memo treating dates as deadlines is reported by one secondary source, unverified.'),
'std-sp800-227': ('C',.7,'down','RHEL-94614/RHEL-95239: X25519MLKEM768 not negotiable in FIPS mode; only SecP256r1MLKEM768/SecP384r1MLKEM1024; X25519MLKEM768 shared-secret order is reversed vs SP 800-227 convention. FIPS-approvable != FIPS-deployable.'),
'fips-cmvp-mlkem-modules': ('A',.9,'unchanged','Only #5314 re-verified; negative claims go stale.'),
'crate-aws-lc-rs': ('A',.9,'unchanged','1.17.2 yanked (2026-07-17); 1.17.4 and 1.18.1 released together 2026-09-01: pin =1.17.4 for FIPS.'),
'pq-share-telemetry': ('B',.8,'unchanged','Radar figure is client SUPPORT, not negotiated share; >65% Apr 2026 not found; origin-side PQ ~10%.'),
'crate-rustls-pq': ('A',.9,'unchanged','0.24.0-dev.2 same day as 0.23.46: 0.24 imminent.'),
'adv-rustls-2026-wave': ('A',.88,'unchanged',''),
'pq-size-mtu-reality': ('B',.8,'unchanged','Sizes follow from parameters; vendor fix dates unverified.'),
'pq-verified-mlkem-impls': ('B',.82,'unchanged','OpenSSH 10.6 (2026-10-06) ssh-mldsa44-ed25519 confirmed; libcrux vendoring from mlkem_mldsa.sh, not release note; proof counts from workshop PDF.'),
'crate-hyper-h2': ('A',.88,'unchanged',''),
'crate-quinn': ('A',.9,'unchanged','11 unique 2026 GHSAs (CVE-2026-31812 likely = GHSA-6xvm); 7 of 11 between 2026-08-17 and 09-30: accelerating.'),
# 07 agent protocol
'j-mcp-2026-07-28': ('A',.96,'unchanged','RC date May 21 (search) vs May 29 (explorer) unresolved.'),
'j-mcp-stateless-no-sessions': ('A',.96,'unchanged','Also: ping/logging/setLevel removed, subscriptions/listen replaces GET, resultType + ttlMs/cacheScope required, OTel _meta, Roots/Sampling/Logging deprecated (SEP-2577); DCR deprecation is PR #2858.'),
'j-mcp-auth': ('B',.85,'down','iss: AS SHOULD include, client MUST validate only if present; MUST/SHOULD levels and draft revs not re-fetched.'),
'j-mcp-security-bp': ('B',.8,'down','Not re-fetched; docs page, informative.'),
'j-mcp-transports': ('A',.88,'unchanged','Deprecated != removed.'),
'j-mcp-extensions': ('B',.82,'down','Final status of 2127/1865/2640 not re-verified; TS v2.4.0 ships Skills.'),
'j-mcp-sdk-advisories': ('A',.9,'unchanged','rmcp 7 and TS 10 exact; Python 10+ (page 2 unseen); listings show no CVE ids: per-advisory verification needed; window is Dec 2025-Oct 2026; OAuth client credential leak to attacker-chosen AS (TS GHSA-6qxp-vccf-f47h, Py GHSA-qx49-fqc8-xw99); rmcp GHSA-5p52 is an incomplete fix.'),
'j-rmcp-sdk': ('B',.84,'down','v3.7.0 date not seen; README confirms 2026-07-28 + 2025-11-25 compat.'),
'j-a2a-1-0': ('A',.9,'unchanged','v1.0.1 May 26 vs 28.'),
'j-x402-spec': ('B',.8,'down','Partly secondary.'),
'j-x402-volume': ('C',.55,'down','Mixes windows (30-day vs cumulative since May 2025: TRM $52.7M / 198.9M settlements); Artemis wash share ~50% vs 63.94% across sources; x402.org widget last updated 2026-08-25.'),
'j-webbotauth': ('A',.92,'unchanged',''),
'j-rfc9421': ('A',.95,'unchanged',''),
'j-bot-verification-programs': ('B',.8,'unchanged','Trust-band scores only planned for Radar.'),
'j-aipref': ('A',.88,'unchanged','vocab-08 text disclaims consensus; datatracker boilerplate says Yes; Aug 2026 IESG milestone slipped.'),
# 08 supply/assure
'sc.vet-import-sets': ('A',.85,'unchanged','cargo-vet 0.10.3 (2026-10-22) confirmed.'),
'sc.vet-ci-gate': ('C',.7,'down','Design; trusted-publisher entries would NOT have blocked arrayref (account takeover of legit publisher); only new-transitive-crate rule, lock pinning and cooldown do.'),
'sc.deny-audit-gate': ('A',.8,'unchanged',''),
'sc.rustsec-volume': ('A',.8,'down','~2.3x vs 2025 is defensible; "4-5x" mixes bulk wasmtime batches; ID-year artifacts.'),
'sc.arrayref-incident': ('A',.92,'up','Rust blog + RUSTSEC-2026-0260 confirm 86/90/107 min, 2,285 downloads.'),
'sc.crates-malicious-record': ('A',.8,'unchanged','Age/download filters would not stop arrayref-style takeover.'),
'sc.slopsquat-rates': ('B',.72,'unchanged','2605.17062 models are small/mid tier (Haiku 4.5, Sonnet 4.6, Gemini 2.5 Pro, DeepSeek V3.2, GPT-5.4-mini); PyPI/npm only; single author.'),
'sc.cooldown-policy': ('C',.8,'down','HEADLINE REFUTED: Cargo RFC 3923 min-publish-age accepted, implemented (cargo PR #17012, -Zmin-publish-age), stabilized (PR #17335, tracking #17009 closed 2026-08-28), targeting Rust 1.100 (~mid-Nov 2026). Third-party cooldown proxies exist.'),
'sc.unsafe-budget': ('A',.82,'unchanged',''),
'sc.repro-build-experiment': ('A',.75,'down','Single host, rustc 1.88; pinned "1.99.1" unconfirmed (1.99.0 = 2026-10-01).'),
'sc.rustc-bootstrap-trust': ('B',.75,'unchanged','mrustc binary-equality is to official 1.91.1; 1.19 not fully repeatable.'),
'sc.slsa-attest': ('B',.78,'unchanged',''),
'sc.sigstore-tuf-threshold': ('B',.72,'unchanged','GHSA-8m7c published 2026-04-24 (added to DB 2026-05-05).'),
'sc.gha-hardening': ('B',.8,'unchanged',''),
'sc.build-system-alternatives': ('D',.5,'unchanged','Absence of head-to-head evidence.'),
# 09 state / db gate
'sdg-embedded-store-selection': ('B',.82,'unchanged','Rebello ATC20: SQLite/LMDB/LevelDB/Redis/PG all mishandle fsync failure; SQLite rates WAL-reset bug below SSD fault rate.'),
'sdg-sqlite-wal': ('A',.92,'unchanged','wal.html (2026-08-24): external reproducer without test hooks exists; 3.52.0 withdrawn.'),
'sdg-redb': ('A',.88,'up','#1334: 8163/8224 single-byte flips silent/undetected; closed not-planned same day; 4.1.0 notes many fixes found by AI coding agents.'),
'sdg-fjall': ('B',.8,'down','Fix mapped via release notes; maintainer fixed "blind" without fault-injection repro; Buffer mode only.'),
'sdg-lmdb-heed': ('B',.7,'down','heed UB was concurrent create/open violating LMDB rule, not general open.'),
'sdg-sled': ('A',.92,'unchanged',''),
'sdg-alice-osdi14': ('A',.88,'unchanged','2014, does not cover fsync-error behaviour.'),
'sdg-power-osdi25': ('A',.88,'unchanged',''),
'sdg-jepsen-tigerbeetle': ('A',.9,'unchanged','VOPR originally corrupted whole sectors and missed byte-level faults.'),
'sdg-jepsen-nats': ('A',.93,'unchanged','Status as of Dec 2025.'),
'sdg-fsyncgate': ('A',.92,'up','Rebello et al. ATC 2020 answers the open question: assume embedded stores do not robustly obey fsync-fail=abort.'),
'sdg-idempotency-draft': ('A',.95,'unchanged',''),
'sdg-stripe-idempotency': ('A',.95,'up',''),
'sdg-exactly-once-boundary': ('B',.82,'down','2608.03836 covers LangGraph/CrewAI/pydantic-graph only; general claim rests on vendor docs + Netherite impossibility.'),
'sdg-temporal': ('B',.85,'unchanged',''),
# 10 history
'hist-erlang-nines-unsourced': ('A',.85,'unchanged','Wiger: several years of field measurements support >5 nines; 9 nines was one network in an initial trial.'),
'hist-erlang-crash-domain-vm': ('A',.85,'unchanged',''),
'hist-php-sharednothing-mechanism': ('C',.65,'unchanged',''),
'hist-cgi-fastcgi-aolserver-pooling': ('C',.6,'unchanged',''),
'hist-urweb-guarantees-and-nonguarantees': ('A',.88,'unchanged',''),
'hist-urweb-adoption-bus-factor': ('A',.85,'unchanged','Last push 2024-05-28.'),
'hist-hails-lio-numbers-dormancy': ('A',.85,'unchanged',''),
'hist-lweb-storm-fixed-overhead': ('A',.75,'down','Disco 107 users; restricted controllers; author case studies.'),
'hist-joee-waterken-taming': ('A',.82,'unchanged',''),
'hist-webkey-capability-url-leak': ('B',.72,'unchanged',''),
'hist-caja-to-ses-endo': ('A',.82,'unchanged','Archival causality is inference.'),
'hist-ironfleet-cost-vs-llm': ('B',.68,'unchanged','"No verified end-to-end HTTP server" is wrong for research: Coq/VST HTTP KV server (ITP 2021); Everest verified TLS pieces.'),
'hist-llm-typed-languages': ('B',.6,'unchanged','FPEval (2601.02060): Haskell pass@1 42.3% with GPT-5, OCaml lower; PROBE (2607.13820): Rust hardest mainstream language.'),
'hist-sel4-no-verified-web': ('B',.72,'unchanged',''),
'hist-techempower-sunset': ('A',.96,'up',''),
# 11 recency
'rec60-wasmtime-cranelift-crit-2026-10': ('A',.92,'unchanged','Confirmed fixes 36.0.19 and >=43; ">=49.0.4" pin unconfirmed; only 2-3 of ~37 are escape-class; GHSA-m9f7-9w4p-gv38 fs symlink-rename escape (High).'),
'rec60-mcp-2026-07-28': ('A',.96,'unchanged','"iss MUST" overstated (MUST validate only when present).'),
'rec60-ai-desync-http-terminator': ('B',.78,'unchanged','Published 2026-08-05 (updated 10-06), not 09-28; source ALREADY released (Terminator, Smuggler update, Turbo Intruder MCP).'),
'rec60-go-1.27.2-batch': ('A',.94,'up','Also cmd/go checksum-DB bypasses for golang.org/toolchain and fips140 (CVE-2026-94447, -94444).'),
'rec60-header-accordions-qpack': ('B',.8,'unchanged','FoxIO URL 404; quic-go (0.57.0) and quiche (0.29.3) already fixed; 4000:1 is Bun only (others 15-50x); Bun/h3/aioquic unpatched ~10-22.'),
'rec60-quinn-advisory-wave': ('A',.88,'unchanged','All DoS-class; 0185->0341 fix-of-fix.'),
'rec60-rustls-0.23.46-downgrade': ('A',.92,'unchanged',''),
'rec60-rfc-10024-hybrid-tls': ('A',.9,'unchanged','Also deprecates X25519Kyber768Draft00 (25497) and SecP256r1Kyber768Draft00 (25498).'),
'rec60-mtc-plants-chrome-apple-le': ('B',.75,'unchanged','Apple terms via secondary site from CT-policy list; meaningful production ~2028.'),
'rec60-name-constraints-emsign-wave': ('A',.87,'unchanged','emSign fix needs rustls-webpki >=0.103.16 (RUSTSEC-2026-0382); intermediates private keys public.'),
'rec60-pingora-envoy-haproxy-nginx-h2h3': ('A',.88,'unchanged','Pingora Oct GHSAs vx4q-2c55-cvmg, mgg9-6xw2-jfgp, 7gpj-mj4q-x62x; nginx "26 YTD" unverified; nginx ones Medium.'),
'rec60-rust-prover-llm-proofs': ('B',.76,'unchanged','Competitive-programming scale; specs given.'),
'rec60-cryptoprover-symcrypt': ('B',.74,'down','Agent authorship of SymCrypt proofs not visible in abstract; extension to FrodoKEM/ML-DSA/HPKE experimental.'),
'rec60-spec-fidelity-verus': ('A',.86,'unchanged','SOUNDGATE ~12k admissions/s, ~1 ms/write, TLC 7.5e7 states; Verus #3029 fix PR #3225 open.'),
'rec60-agent-authz-attacks': ('B',.78,'up','2610.21063: 27,108 trials, forged-narration success 0.54->0.03.'),
# 12 calibration
'cal-mcp-2026-07-28': ('A',.96,'unchanged',''),
'cal-spargio': ('A',.95,'unchanged',''),
'cal-kverus': ('A',.95,'unchanged',''),
'cal-aip': ('B',.94,'unchanged','Paper also reports 2.35 ms overhead (0.086% e2e) in multi-agent deployment.'),
'cal-wasmtime-13467': ('A',.97,'unchanged','cfallin: fuel-per-second unstable; argues against fuel-rate design.'),
'cal-x402-volume': ('C',.8,'unchanged','Widget says last updated 2026-08-25.'),
'cal-rfc-9680': ('A',.99,'unchanged',''),
'cal-crates-existence': ('A',.93,'unchanged',''),
}

# ---------------- verifier "missed" items promoted to nodes ----------------
VNODES = [
 dict(id='v.http2-bomb-cve-2026-49975', layer='L4', pillar='W-THREAT', type='failure', title='HTTP/2 Bomb CVE-2026-49975: one composition bug hit nginx, httpd, IIS, Envoy, Pingora (default config)',
      summary='Disclosed 2026-06-02 (Calif, found with Codex). HPACK header amplification plus zero-byte flow-control window. >880k exposed hosts; IIS, Envoy and Pingora had no fix at disclosure. Language-independent: a protocol-composition flaw, not a memory bug.',
      urls=['https://blog.calif.io/p/codex-discovered-a-hidden-http2-bomb','https://labs.cloudsecurityalliance.org/research/csa-research-note-http2-bomb-ai-discovered-dos-20260604-csa/'], evidence_grade='B', confidence=.85, actionability=.9, load_bearing=True, found_by='verifier-01'),
 dict(id='v.aixcc-sok-usenix26', layer='L4', pillar='W-THREAT', type='result', title='USENIX Sec 2026 SoK on AIxCC: CRSs unusable outside competition cloud; 0/6 C zero-days patched',
      summary='All seven finalist CRSs were unusable outside the competition cloud after the event; systems patched 0 of 6 C-codebase zero-days vs 11 of 12 Java. DARPA corrected synthetic count 70 -> 63. Undercuts "open-source CRSs harden C servers".',
      urls=['https://www.darpa.mil/news/2025/aixcc-results'], evidence_grade='C', confidence=.65, actionability=.5, load_bearing=False, found_by='verifier-01'),
 dict(id='v.cybergym-e2e', layer='L4', pillar='W-THREAT', type='benchmark', title='CyberGym E2E (Berkeley RDI): GPT-5.4 ~66%, Opus 4.6 ~63% on 920 end-to-end tasks',
      summary='Better grounded than self-reported 91-97% leaderboard figures; no 97% figure found. Mythos Preview 83.1% in Anthropic materials (vendor, D).',
      urls=['https://rdi.berkeley.edu/blog/cybergym-e2e'], evidence_grade='B', confidence=.7, actionability=.5, load_bearing=False, found_by='verifier-01'),
 dict(id='v.coq-vst-http-kv-itp2021', layer='L3', pillar='S-FORMAL-WEB', type='result', title='Verified HTTP key-value server in C with Interaction Trees + VST (Coq, ITP 2021)',
      summary='Research existence proof of an end-to-end verified (small) HTTP server; contradicts "no verified HTTP server exists". Not production-grade, not HTTP/1.1 framing-complete; Project Everest verified TLS/parser pieces separately.',
      urls=['https://drops.dagstuhl.de/opus/volltexte/2021/13927'], evidence_grade='B', confidence=.8, actionability=.6, load_bearing=True, found_by='verifier-03/10'),
 dict(id='v.rebello-atc20-fsync-failures', layer='L3', pillar='W-STATE', type='result', title='Rebello et al., "Can Applications Recover from fsync Failures?" (USENIX ATC 2020)',
      summary='Tested SQLite, LMDB, LevelDB, Redis, PostgreSQL: none handled fsync failure adequately. Implication: assume embedded stores do not robustly implement fsync-error => abort; our harness must inject EIO.',
      urls=['https://www.usenix.org/conference/atc20/presentation/rebello'], evidence_grade='A', confidence=.85, actionability=.85, load_bearing=True, found_by='verifier-09'),
 dict(id='v.cargo-min-publish-age-rfc3923', layer='L4', pillar='W-SUPPLY', type='standard', title='Cargo min-publish-age (RFC 3923): native dependency cooldown, stabilized for Rust 1.100',
      summary='RFC accepted 2026-02-23; cargo PR #17012 (nightly -Zmin-publish-age since 2026-06-21); stabilization PR #17335; tracking issue #17009 closed 2026-08-28; ships in Rust 1.100 (~mid-Nov 2026). Refutes "no native Cargo cooldown".',
      urls=['https://github.com/rust-lang/cargo/issues/17009'], evidence_grade='B', confidence=.8, actionability=.9, load_bearing=True, found_by='verifier-08'),
 dict(id='v.rhel-fips-hybrid-groups', layer='L4', pillar='W-PQC', type='result', title='FIPS mode reality: X25519MLKEM768 not negotiable in RHEL FIPS mode; P-256/P-384 hybrids are',
      summary='Red Hat RHEL-94614/RHEL-95239: only secp256r1MLKEM768 and secp384r1MLKEM1024 work in FIPS mode. OpenSSL docs: X25519MLKEM768 orders shared-secret parts opposite to SP 800-227 convention. FIPS profile should default to SecP256r1MLKEM768 (0x11EB).',
      urls=['https://issues.redhat.com/browse/RHEL-94614','https://docs.openssl.org/master/man7/EVP_PKEY-MLX-KEM'], evidence_grade='B', confidence=.75, actionability=.9, load_bearing=True, found_by='verifier-06'),
 dict(id='v.pure-mlkem-tls-draft-contested', layer='L4', pillar='W-PQC', type='standard', title='Pure ML-KEM TLS draft (draft-ietf-tls-mlkem-10) contested; RFC Ed queue blocked',
      summary='No WG consensus at WGLC Dec 2025; IETF LC 2026-07-30; in RFC Ed queue "blocked: author input required"; possible patent-license concern. Risk to any pure-ML-KEM-1024 (CNSA 2.0) TLS profile.',
      urls=['https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/10/'], evidence_grade='B', confidence=.8, actionability=.7, load_bearing=False, found_by='verifier-06'),
 dict(id='v.origin-pq-adoption-10pct', layer='L4', pillar='W-PQC', type='result', title='Origin-side PQ key agreement on Cloudflare ~10% (vs >60% client support)',
      summary='Server-side ecosystem is thin: <1% at start of 2025 -> ~10%; clients >60% support (Feb 2026). A PQ-default origin is ahead of the field, not behind.',
      urls=['https://blog.cloudflare.com/radar-origin-pq-key-transparency-aspa/'], evidence_grade='B', confidence=.8, actionability=.6, load_bearing=False, found_by='verifier-06'),
 dict(id='v.fpeval-probe-2026', layer='L4', pillar='W-DX', type='benchmark', title='FPEval (2601.02060) and PROBE (2607.13820): LLM pass rates on Haskell/OCaml/Rust',
      summary='FPEval: Haskell pass@1 42.3% with GPT-5, OCaml lower, ~9-18 pts below Java; no agent loop. PROBE: Rust hardest of mainstream languages tested. One-shot evidence only.',
      urls=['https://arxiv.org/abs/2601.02060','https://arxiv.org/abs/2607.13820'], evidence_grade='B', confidence=.6, actionability=.6, load_bearing=False, found_by='verifier-10'),
 dict(id='v.ietf-agent-attenuation-drafts', layer='L3', pillar='W-AUTHZ', type='standard', title='IETF agent attenuation drafts: draft-niyikiza-oauth-attenuating-agent-tokens-01, draft-asor-wimse-agent-delegation-chain-01',
      summary='Offline derivation of narrower tokens; the WIMSE draft argues OAuth Token Exchange "act" claims cannot enforce attenuation at depth >=2. Seen via search only: existence must be fetched before grading above E.',
      urls=[], evidence_grade='E', confidence=.5, actionability=.6, load_bearing=False, found_by='verifier-05'),
 dict(id='v.neurips26-authority-attenuation', layer='L3', pillar='W-AUTHZ', type='source', title='NeurIPS 2026 "Authority Attenuation: Structural Invariants for Meta-Agent Oversight" (signed Mandates, no-amplification)',
      summary='Reported via neurips.cc virtual page 169824; not fetched. Prior art for the attenuation-monotonicity gate.', urls=[], evidence_grade='E', confidence=.4, actionability=.4, load_bearing=False, found_by='verifier-05'),
]

ALIAS_LETTER = {  # explorer prefix -> {letter: pillar}
 '03': {'P': 'W-FORMAL', 'S': 'S-FORMAL-WEB'}, '05': {'G': 'W-AUTHZ', 'S': 'S-FORMAL-WEB'},
 '06': {'C+D': 'W-TRANSPORT', 'C': 'W-TRANSPORT', 'D': 'W-PQC'}, '07': {'J': 'W-AGENT-PROTOCOL'},
 '08': {'N': 'W-SUPPLY', 'O': 'W-ASSURE', 'N+O': 'W-ASSURE'}, '09': {'F-STATE': 'W-STATE', 'H-DATA-GATE': 'W-DATA-GATE'},
 '10': {'R+S': 'R-HISTORY', 'S': 'S-FORMAL-WEB', 'R': 'R-HISTORY', 'R+S+F': 'R-HISTORY'}, '12': {'K': 'K-CALIBRATION'},
}
def pillar(prefix, dom):
    m = re.search(r'W-[A-Z]+(?:-[A-Z]+)*', dom or '')
    if m:
        p = m.group(0)
        return {'W-DATA': 'W-DATA-GATE', 'W-AGENT': 'W-AGENT-PROTOCOL'}.get(p, p)
    return ALIAS_LETTER.get(prefix, {}).get(dom.strip(), 'W-?' + dom)

# ---------------- integrator dedup clusters ----------------
SAME_AS = [  # (dup, canonical, note)
 ('rec60-mcp-2026-07-28', 'j-mcp-2026-07-28', 'same spec revision'), ('cal-mcp-2026-07-28', 'j-mcp-2026-07-28', 'calibration verdict on same revision'),
 ('gap.wasmtime-adv', 'wasmtime-ghsa-record-2021-2026', 'same advisory stream'),
 ('http1-desync-2025', 'threat-request-smuggling-desync', 'explorer-declared'),
 ('rec60-quinn-advisory-wave', 'crate-quinn', 'same advisory wave'),
 ('rec60-rustls-0.23.46-downgrade', 'adv-rustls-2026-wave', 'same advisory set'),
 ('rec60-rfc-10024-hybrid-tls', 'std-rfc10024-ecdhe-mlkem', 'same RFC'),
 ('rec60-mtc-plants-chrome-apple-le', 'std-mtc-plants', 'same draft/track'),
 ('cal-kverus', 'llm-kverus-2026', 'same paper'),
 ('proof-cedar-lean', 'cedar-lean-proofs-2026-10', 'same proof artifact; 05 has newer counts'),
 ('everparse-for-front', 'proof-everparse-hyperv', 'explorer-declared'),
 ('proof-power-capybarakv', 'sdg-power-osdi25', 'same paper'),
 ('gap.hyperlight', 'hyperlight-microvm', 'same system'), ('gap.firecracker', 'firecracker-spec-numbers', 'same system'),
 ('rec60-h2-hyper-releases', 'crate-hyper-h2', 'same releases'),
 ('cal-x402-volume', 'j-x402-volume', 'same quantity'),
 ('rec60-supply-chain-incidents', 'sc.arrayref-incident', 'arrayref incident core (rec60 adds tokio yank, Nix/Lix, CHAINDROP)'),
]
REFINES = [  # (src refines dst)
 ('rec60-wasmtime-cranelift-crit-2026-10', 'wasmtime-ghsa-record-2021-2026'), ('wasmtime-llm-audit-sprint-2026-04', 'wasmtime-ghsa-record-2021-2026'),
 ('rec60-ai-desync-http-terminator', 'threat-request-smuggling-desync'), ('rec60-header-accordions-qpack', 'threat-h2-h3-resource-exhaustion'),
 ('v.http2-bomb-cve-2026-49975', 'threat-h2-h3-resource-exhaustion'), ('j-mcp-sdk-advisories', 'threat-mcp-agent-layer'),
 ('rec60-pingora-envoy-haproxy-nginx-h2h3', 'gap.pingora'), ('rec60-cryptoprover-symcrypt', 'proof-aeneas-symcrypt'),
 ('rec60-spec-fidelity-verus', 'fail-spec-fidelity-studies'), ('rec60-spec-fidelity-verus', 'fail-verifier-soundness-bugs'),
 ('rec60-kernel-isolation', 'io-uring-security-record'), ('rec60-kernel-isolation', 'kvm-januscape-cve-2026-53359'),
 ('rec60-agent-authz-attacks', 'approval-to-abuse-2610.22987'), ('rec60-agent-authz-attacks', 'cedar-policy-crate-4.14'),
 ('as.fuzz-gate', 'ossfuzz-coverage-transport'), ('as.tigerbeetle-vopr', 'sdg-jepsen-tigerbeetle'),
 ('hist-ironfleet-cost-vs-llm', 'llm-vericoding-2025'), ('v.coq-vst-http-kv-itp2021', 'gap-verified-http1-parser'),
 ('v.coq-vst-http-kv-itp2021', 'gap.no-assurance-claims'), ('v.rebello-atc20-fsync-failures', 'sdg-fsyncgate'),
 ('v.cargo-min-publish-age-rfc3923', 'sc.cooldown-policy'), ('v.rhel-fips-hybrid-groups', 'std-sp800-227'),
 ('v.origin-pq-adoption-10pct', 'pq-share-telemetry'), ('v.fpeval-probe-2026', 'hist-llm-typed-languages'),
 ('v.aixcc-sok-usenix26', 'result-ai-discovery-capability-2025-2026'), ('v.cybergym-e2e', 'result-ai-discovery-capability-2025-2026'),
 ('v.pure-mlkem-tls-draft-contested', 'std-cnsa2-dates'), ('v.ietf-agent-attenuation-drafts', 'gap-verified-attenuable-pq-token'),
 ('v.neurips26-authority-attenuation', 'inv-attenuation-monotonicity'), ('cal-crates-existence', 'rec60-tokio-axum-rmcp-versions'),
 ('rec60-name-constraints-emsign-wave', 'crate-rustls-pq'), ('gap.pq-status', 'pq-share-telemetry'),
 ('cal-wasmtime-13467', 'fuel-not-a-security-bound'), ('rec60-rust-prover-llm-proofs', 'llm-verusage-2025'),
 ('rec60-ai-offense-trend', 'result-ai-discovery-capability-2025-2026'), ('gap.unikraft', 'unikernel-hardening-gaps'),
 ('gap.wasm-hosts-other', 'v8-isolates-security-posture'), ('threat-tls-validation-logic', 'adv-rustls-2026-wave'),
]
CONTRADICTS = [
 ('v.cargo-min-publish-age-rfc3923', 'sc.cooldown-policy', 'native cooldown exists (Rust 1.100)'),
 ('v.coq-vst-http-kv-itp2021', 'hist-sel4-no-verified-web', 'verified HTTP server precedent (research)'),
 ('v.rhel-fips-hybrid-groups', 'std-sp800-227', 'X25519 hybrid not deployable in FIPS mode on RHEL'),
 ('kvm-januscape-cve-2026-53359', 'iso-glue-not-boundary-pattern', 'core hardware-virt bug'),
 ('result-time-to-exploit-trend', 'l5-structural-controls-implied', 'day-zero share falling 28.9->23.4% weakens absolute no-patch-window framing (keep hours-scale pipeline)'),
]

def canon(u):
    try: p = urlsplit(u.strip())
    except ValueError: return u.strip()
    host = (p.hostname or '').lower()
    if host.startswith('www.'): host = host[4:]
    if p.scheme == 'file': return u.strip()
    if host == 'arxiv.org':
        m = re.search(r'(\d{4}\.\d{4,5})', p.path)
        if m: return 'arxiv:' + m.group(1)
    if host == 'github.com':
        parts = [x for x in p.path.split('/') if x]
        if len(parts) == 2: return f'gh:{parts[0]}/{parts[1]}'
    q = [(k, v) for k, v in parse_qsl(p.query) if not k.lower().startswith(('utm_', 'ref', 'fbclid', 'gclid'))]
    path = re.sub(r'/+$', '', p.path) or '/'
    return urlunsplit(('https', host, path, urlencode(sorted(q)), ''))

def walk_urls(o, acc):
    if isinstance(o, str):
        for u in re.findall(r'(?:https?|file)://[^\s"\'<>)\]]+', o): acc.add(u.rstrip('.,;'))
    elif isinstance(o, dict):
        for v in o.values(): walk_urls(v, acc)
    elif isinstance(o, list):
        for v in o: walk_urls(v, acc)

STOP = set('a an the of and or for to in on with by from at as is are be vs via into over under than that this these those what which how why when its it their our your using use based new 2023 2024 2025 2026 rust http https www com org does do any can'.split())
def toks(s):
    out = set()
    for w in re.findall(r'[a-z0-9][a-z0-9_.+#-]*', (s or '').lower()):
        w = w.strip('.-')
        if len(w) < 2 or w in STOP: continue
        if len(w) > 4 and w.endswith('s') and not w.endswith('ss'): w = w[:-1]
        out.add(w)
    return out
def jac(a, b): return len(a & b) / len(a | b) if a and b else 0.0

# ---------------- load ----------------
files = sorted(glob.glob(RAW + '/[0-9]*.json'))
nodes, edges, seeds, explorer_of, raw_by = [], [], [], {}, {}
for f in files:
    pre = os.path.basename(f)[:2]
    label = re.sub(r'^\d+-', '', os.path.basename(f)[:-5])
    o = json.load(open(f)); raw_by[pre] = o
    for n in o['nodes']:
        n = dict(n); n['explorer'] = f'{pre}-{label}'; explorer_of[n['id']] = pre
        n['pillar'] = pillar(pre, n.get('domain', ''))
        nodes.append(n)
    for e in o['edges']:
        edges.append({'src': e['src'], 'dst': e['dst'], 'type': e['type'], 'note': e.get('note', ''), 'evidence_url': '', 'origin': f'explorer-{pre}', 'round': R})
    for s in o['seeds']:
        s = dict(s); s['from_explorer'] = pre; seeds.append(s)

for vn in VNODES:
    n = dict(vn); n['domain'] = vn['pillar']; n['explorer'] = vn['found_by']; n['specifics'] = ''
    n['overclaim_risk'] = n.get('overclaim_risk', 'Verifier-sourced; single verification pass.'); n['underclaim_risk'] = ''
    explorer_of[n['id']] = 'V' + vn['found_by'].split('-')[1][:2]
    nodes.append(n)

ids = {n['id'] for n in nodes}
for a, b, note in SAME_AS: assert a in ids and b in ids, (a, b)
for a, b in REFINES: assert a in ids and b in ids, (a, b)
for a, b, _ in CONTRADICTS: assert a in ids and b in ids, (a, b)
missing_v = [k for k in V if k not in ids]
assert not missing_v, missing_v

# apply verdicts
for n in nodes:
    n['grade_explorer'] = n.get('evidence_grade'); n['confidence_explorer'] = n.get('confidence')
    if n['id'] in V:
        g, c, d, note = V[n['id']]
        n['evidence_grade'] = g; n['confidence'] = c; n['verify'] = {'status': 'two-sided', 'direction': d, 'note': note}
    elif n['explorer'].startswith('verifier'):
        n['verify'] = {'status': 'verifier-sourced', 'direction': 'new', 'note': 'promoted from verifier missed-list'}
    else:
        n['verify'] = {'status': 'not-sampled', 'direction': 'unchanged', 'note': 'verifier sampled other nodes; explorer grade kept'}
    n['first_seen_round'] = R; n['last_verified'] = DATE
    n['urls_canon'] = sorted({canon(u) for u in n.get('urls', []) if u})

# union-find same-as for singletons
par = {i: i for i in ids}
def find(x):
    while par[x] != x: par[x] = par[par[x]]; x = par[x]
    return x
same_edges = [(a, b) for a, b, _ in SAME_AS] + [(e['src'], e['dst']) for e in edges if e['type'] in ('same-as', 'same_as')]
for a, b in same_edges: par[find(a)] = find(b)
clusters = collections.defaultdict(list)
for i in ids: clusters[find(i)].append(i)
singletons = [c for c in clusters.values() if len({explorer_of[i][:3] for i in c}) == 1]
multi = [c for c in clusters.values() if len({explorer_of[i][:3] for i in c}) > 1]
canonical_of = {i: find(i) for i in ids}
for n in nodes:
    n['cluster'] = canonical_of[n['id']]
    n['merged_into'] = canonical_of[n['id']] if canonical_of[n['id']] != n['id'] else None

for a, b, note in SAME_AS: edges.append({'src': a, 'dst': b, 'type': 'same-as', 'note': note, 'evidence_url': '', 'origin': 'integrator', 'round': R})
for a, b in REFINES: edges.append({'src': a, 'dst': b, 'type': 'refines', 'note': 'integrator cross-explorer link', 'evidence_url': '', 'origin': 'integrator', 'round': R})
for a, b, note in CONTRADICTS: edges.append({'src': a, 'dst': b, 'type': 'contradicts', 'note': note, 'evidence_url': '', 'origin': 'integrator/verifier', 'round': R})
# dedup edges
seen_e, E2 = set(), []
for e in edges:
    k = (e['src'], e['dst'], e['type'])
    if k in seen_e: continue
    seen_e.add(k); E2.append(e)
edges = E2
dangling = [e for e in edges if e['src'] not in ids or e['dst'] not in ids]

# ---------------- write graph/edges ----------------
KEEP = None
os.makedirs(ST, exist_ok=True)
with open(ST + '/graph.jsonl', 'a') as f:
    for n in nodes: f.write(json.dumps(n, ensure_ascii=False) + '\n')
with open(ST + '/edges.jsonl', 'a') as f:
    for e in edges: f.write(json.dumps(e, ensure_ascii=False) + '\n')

# ---------------- seen.jsonl ----------------
urlmap = collections.defaultdict(lambda: {'explorers': set(), 'nodes': set(), 'raw': None})
for f in files:
    pre = os.path.basename(f)[:2]; acc = set(); walk_urls(json.load(open(f)), acc)
    for u in acc:
        c = canon(u); urlmap[c]['explorers'].add(pre); urlmap[c]['raw'] = urlmap[c]['raw'] or u
for n in nodes:
    for u in n.get('urls', []):
        c = canon(u); urlmap[c]['nodes'].add(n['id']); urlmap[c]['raw'] = urlmap[c]['raw'] or u
        if n['explorer'].startswith('verifier'): urlmap[c]['explorers'].add(n['explorer'])
VERIFIER_URLS = ['https://www.varnish.org/docs/security/vsv00017/','https://www.wiz.io/vulnerability-database/cve/cve-2026-42533','https://orca.security/resources/blog/cve-2026-42533-nginx-heap-buffer-overflow/',
 'https://helpnetsecurity.com/2026/03/24/mandiant-m-trends-2026-report/','https://www.vulncheck.com/blog/anthropic-glasswing-receipts','https://arxiv.org/pdf/2605.30106','https://nvd.nist.gov/vuln/detail/cve-2026-34971',
 'https://arxiv.org/pdf/2604.11669','https://arxiv.org/pdf/2509.11242','https://www.rfc-editor.org/rfc/rfc9954.json','https://crates.io/api/v1/crates/aws-lc-rs','https://crates.io/api/v1/crates/rustls/versions',
 'https://crates.io/api/v1/crates/h2/versions','https://crates.io/api/v1/crates/hyper/versions','https://github.com/quinn-rs/quinn/security/advisories?page=2','https://www.openssh.org/txt/release-10.6',
 'https://postquantum.com/industry-news/cloudflare-pqc-majority-traffic/','https://decrypt.co/378103/ai-agents-spending-money-research','https://wiki.postgresql.org/wiki/Fsync_Errors','https://lwn.net/Articles/752093',
 'https://arxiv.org/pdf/2605.30914','https://lilting.ch/en/articles/http3-qpack-header-amplification','https://dev.to/frankchu/i-built-foxios-54-kb-http3-accordion-by-hand-aioquics-decoder-unfolded-it-to-200-mb-4do7',
 'https://github.com/a2aproject/A2A/releases','https://github.com/open-policy-agent/opa/security/advisories','https://arxiv.org/abs/2403.04651','https://issues.redhat.com/browse/RHEL-95239']
for u in VERIFIER_URLS:
    c = canon(u); urlmap[c]['explorers'].add('verifier'); urlmap[c]['raw'] = urlmap[c]['raw'] or u
with open(ST + '/seen.jsonl', 'a') as f:
    for c in sorted(urlmap):
        d = urlmap[c]
        f.write(json.dumps({'url': d['raw'], 'canon': c, 'first_seen_round': R, 'last_seen_round': R, 'found_by': sorted(d['explorers']), 'nodes': sorted(d['nodes'])}) + '\n')

# ---------------- queries ----------------
def classify(q, axes, label):
    t = (q + ' ' + axes).lower()
    src = ('paper' if re.search(r'arxiv|paper|osdi|sosp|usenix|pldi|popl|ccs|ndss|icse|thesis|\bpdf\b', t) else
           'spec-rfc' if re.search(r'rfc|draft|spec|datatracker|ietf|w3c|nist|fips|standard|cnsa|sep-', t) else
           'repo-advisory' if re.search(r'ghsa|advisor|github|issue|repo|crate|release|changelog|rustsec|gh ', t) else
           'cve-incident' if re.search(r'cve|kev|incident|exploit|attack|breach|oss-security|compromis', t) else
           'benchmark' if re.search(r'bench|latency|throughput|rps|measure|own-experiment|perf', t) else
           'vendor-doc' if re.search(r'blog|vendor|docs|cloudflare|aws|google|microsoft|stripe', t) else
           'forum' if re.search(r'forum|reddit|hacker news|lobste|discussion|mailing', t) else 'web-other')
    stance = ('skeptic-negative' if re.search(r'contrarian|negative|skeptic|critique|fail|limit|overhype|bypass|pitfall|footgun|wrong|doesn.t|not ', t) else
              'attacker' if re.search(r'attack|exploit|offens|escape|smuggl|poison', t) else 'proponent')
    era = ('last-60d' if re.search(r'last.?60|recen|oct 2026|sep 2026|aug 2026|2026-(08|09|10)|october|september', t) else
           'historical' if re.search(r'histor|20(0|1)\d|legacy|foundational|retrospect|died|aolserver|cgi|erlang|caja|joe-e|waterken', t) else '2025-26')
    if label == 'recency-sweep-last-60-days': era = 'last-60d'
    elif label == 'historical-and-formal-web-foundations-why-they-died' and era == '2025-26' and not re.search(r'llm|agent|2025|2026', t): era = 'historical'
    return src, stance, era

LABEL2PILLAR = {'threat-cve-record-and-ai-exploit-speed': 'W-THREAT', 'gap-prior-art-servers-and-unserved-slot': 'W-GAP',
 'formal-proofs-in-production-and-llm-proof-synthesis': 'W-FORMAL', 'isolation-substrates-measured-and-escaped': 'W-ISOLATION',
 'authz-capabilities-with-formal-semantics': 'W-AUTHZ', 'transport-stacks-and-pqc-deployment-reality': 'W-TRANSPORT+W-PQC',
 'agent-protocols-primary-source-status': 'W-AGENT-PROTOCOL', 'supply-chain-provenance-and-deterministic-sim-ci': 'W-SUPPLY+W-ASSURE',
 'state-durability-and-db-gate-failure-modes': 'W-STATE+W-DATA-GATE', 'historical-and-formal-web-foundations-why-they-died': 'R+S',
 'recency-sweep-last-60-days': 'W-UNKNOWN', 'identifier-calibration-seed-and-prior-claims': 'K-CALIBRATION'}
Q = []
for line in open(RAW + '/_queries.log', errors='replace'):
    p = line.rstrip('\n').split('\t')
    if len(p) < 2 or not p[1].strip(): continue
    lab, q, axes = p[0], p[1], (p[2] if len(p) > 2 else '')
    src, stance, era = classify(q, axes, lab)
    Q.append({'round': R, 'label': lab, 'query': q, 'axes': axes, 'pillar': LABEL2PILLAR.get(lab, '?'), 'source_type': src, 'stance': stance, 'era': era,
              'cell': f"{LABEL2PILLAR.get(lab,'?')}|{src}|{stance}|{era}"})
# intra-round near-dups across explorers
tq = [toks(x['query']) for x in Q]
nd_pairs = []
for i in range(len(Q)):
    best = (0, None)
    for j in range(i):
        s = jac(tq[i], tq[j])
        if s > best[0]: best = (s, j)
    Q[i]['max_prior_jaccard'] = round(best[0], 2)
    Q[i]['near_dup_of'] = (Q[best[1]]['label'] + ': ' + Q[best[1]]['query']) if best[0] >= .5 else None
    if best[0] >= .5: nd_pairs.append((Q[i]['label'], Q[best[1]]['label'], round(best[0], 2), Q[i]['query'], Q[best[1]]['query']))
with open(ST + '/queries.jsonl', 'a') as f:
    for x in Q: f.write(json.dumps(x, ensure_ascii=False) + '\n')

cells = collections.Counter(x['cell'] for x in Q)
direction_diversity = len(cells) / len(Q)
# yield per explorer: new L4/L5 nodes (non-merged) per query
yl = {}
for lab in LABEL2PILLAR:
    nq = sum(1 for x in Q if x['label'] == lab)
    nn = [n for n in nodes if n['explorer'].endswith(lab)]
    l45 = sum(1 for n in nn if n.get('layer') in ('L4', 'L5') and not n['merged_into'])
    yl[lab] = (nq, len(nn), l45, (l45 / nq) if nq else None)
axis_counts = {k: collections.Counter(x[k] for x in Q) for k in ('source_type', 'stance', 'era', 'pillar')}
cross_nd = [p for p in nd_pairs if p[0] != p[1]]

# ---------------- frontier queue ----------------
MISSED = []  # filled from file passed in argv[1] (verifier missed lists)
if len(sys.argv) > 1:
    MISSED = json.load(open(sys.argv[1]))
DIRECTIVE_SEEDS = [
 ('Data-plane abstraction across backend families (relational, document, KV, wide-column, graph, vector, search, object, streams, upstream HTTP/gRPC): smallest uniform capability/operation IR that keeps per-backend safety; per-family injection/authz failure modes and Rust driver maturity', 'L2', 'W-DATA-GATE', .95, 'Directive §0b mandates a round-2+ target; round 1 covered only Postgres/SQLite/poolers'),
 ('Protocol-agnostic ingress + modularity/leanness: one normalization core vs per-protocol stacks; compile-time features vs Wasm components vs out-of-process capability-IPC plugins vs dynamic loading; measured binary size, dep count, unsafe LOC, idle RSS vs nginx/Caddy/Pingora/Envoy/HAProxy', 'L4', 'W-PERF+W-GAP', .95, 'Directive §0b mandates; no leanness measurements yet'),
 ('Verification toolchain footprint and per-component prover choice: disk/RAM of Lean 4 core (no Mathlib) + Aeneas/Charon, Verus + Z3, Kani/CBMC, F*/EverParse, TLA+/Apalache; which obligations need which; CI time', 'L4', 'W-FORMAL', .9, 'Directive §0c: Lean required in story, no local prover LLMs, smallest toolchain'),
 ('Golden extension contract: which core invariants survive arbitrary sandboxed/out-of-process third-party modules vs which assume golden modules; conformance-suite design', 'L5', 'W-ASSURE', .85, 'Directive §0c responsibility boundary'),
 ('W-ABUSE: GCRA/token buckets, adaptive concurrency (gradient/Vegas), CoDel/load shedding, Privacy Pass RFC 9576-9578 rate-limited tokens, PoW gates (Anubis measured effect), residential-proxy botnets, human fairness', 'L3', 'W-ABUSE', .85, 'Pillar has zero round-1 nodes'),
 ('W-OPS: single-binary ACME, config language + validation, secrets/key rotation, tamper-evident audit logs (Tessera/transparency logs), systemd hardening, FedRAMP/800-53/SSDF/CRA obligations for an OSS server', 'L3', 'W-OPS', .8, 'Pillar has one round-1 node (CRA)'),
 ('W-PERF: io_uring vs epoll and thread-per-core vs work-stealing measured on operator hardware; Wasm component canonical-ABI cost per call/KB; ML-KEM handshake cost on 1 vCPU; zero-downtime reload', 'L4', 'W-PERF', .8, 'Pillar thin; only vendor/old numbers'),
]
items = []
for s in seeds:
    items.append({'question': s['question'], 'layer': s.get('layer'), 'domain': s.get('domain'), 'expected_info_gain': float(s.get('expected_info_gain', .5)),
                  'reason': s.get('reason', ''), 'sources': [f"explorer-{s['from_explorer']}"], 'kind': 'seed'})
for m in MISSED:
    items.append({'question': m['text'], 'layer': m.get('layer', 'L4'), 'domain': m.get('domain', ''), 'expected_info_gain': float(m.get('eig', .45)),
                  'reason': 'verifier missed-list', 'sources': [f"verifier-{m['explorer']}"], 'kind': 'missed', 'absorbed_into': m.get('absorbed')})
for q, l, d, g, r in DIRECTIVE_SEEDS:
    items.append({'question': q, 'layer': l, 'domain': d, 'expected_info_gain': g, 'reason': r, 'sources': ['directive'], 'kind': 'directive'})
# dedup
merged = []
for it in items:
    t = toks(it['question'])
    hit = None
    for m in merged:
        if jac(t, m['_t']) >= .45: hit = m; break
    if hit:
        hit['expected_info_gain'] = max(hit['expected_info_gain'], it['expected_info_gain']); hit['sources'] += it['sources']
        hit['dup_questions'].append(it['question'])
        if it.get('absorbed_into'): hit['absorbed_into'] = it['absorbed_into']
    else:
        it['_t'] = t; it['dup_questions'] = []; merged.append(it)
# done/partial markers: (regex, status, by)
DONE = [
 (r'Wasmtime pooling.allocator', 'partial', 'wasmtime-pooling-local-bench + nanvix-same-hw-coldstart-2026 (core wasm only; fork+seccomp and component ABI still open)'),
 (r'Wasmtime.{0,3} 2026 advisory surge', 'partial', 'wasmtime-ghsa-record-2021-2026, wasmtime-llm-audit-sprint-2026-04, rec60-wasmtime-cranelift-crit-2026-10'),
 (r'rustls/aws-lc-rs.{0,10}proxies.*X25519MLKEM768', 'partial', 'crate-rustls-pq (default since 0.23.27); handshake cost on 1 vCPU still open'),
 (r'Does any gateway run Cedar/OPA/CEL', 'open', ''),
 (r'Test fsync-failure handling', 'partial', 'v.rebello-atc20-fsync-failures (2020 answer; redb/fjall untested)'),
 (r'Existing Kani/Verus proofs in hyper, h2, quinn, rustls, s2n-quic', 'partial', 'crate-s2n-quic (32 Kani files); gap.no-assurance-claims'),
 (r'Does any verified HTTP/1.1 or HTTP/2 framing parser exist', 'partial', 'v.coq-vst-http-kv-itp2021 (research), gap-verified-http1-parser'),
 (r'Primary-source check of Pingora HTTP/3', 'partial', 'gap.pingora (issue #95 open since 2024-03)'),
]
for m in merged:
    m['status'] = 'open'; m['resolved_by'] = ''
    for rx, st, by in DONE:
        if re.search(rx, m['question']) or any(re.search(rx, d) for d in m['dup_questions']):
            m['status'] = st; m['resolved_by'] = by
    if m.get('absorbed_into'):
        m['status'] = 'absorbed' if m['status'] == 'open' else m['status']; m['resolved_by'] = m['resolved_by'] or m['absorbed_into']
    bonus = .05 * (len(set(m['sources'])) - 1)
    pen = {'open': 1.0, 'partial': .6, 'absorbed': .3, 'done': 0}[m['status']]
    m['score'] = round(min(1.0, m['expected_info_gain'] + bonus) * pen, 3)
merged.sort(key=lambda m: -m['score'])
with open(ST + '/frontier_queue.jsonl', 'w') as f:
    for i, m in enumerate(merged):
        m.pop('_t', None); m['id'] = f'q1-{i+1:03d}'; m['added_round'] = R
        f.write(json.dumps(m, ensure_ascii=False) + '\n')

# ---------------- summary for report ----------------
by_layer = collections.Counter(n.get('layer') for n in nodes)
by_pl = collections.Counter((n['pillar'], n.get('layer')) for n in nodes)
grades = collections.Counter(n['evidence_grade'] for n in nodes)
dirs = collections.Counter(n['verify']['direction'] for n in nodes)
xlinked = set()
for e in edges:
    if e['origin'].startswith('integrator') or explorer_of.get(e['src'], 'a')[:3] != explorer_of.get(e['dst'], 'b')[:3]:
        xlinked.add(e['src']); xlinked.add(e['dst'])
strict_singletons = [c for c in singletons if not any(i in xlinked for i in c)]
summary = dict(strict_singletons=len(strict_singletons), nodes=len(nodes), explorer_nodes=len(nodes) - len(VNODES), verifier_nodes=len(VNODES), edges=len(edges), dangling=len(dangling),
               merged=sum(1 for n in nodes if n['merged_into']), clusters=len(clusters), singletons=len(singletons), multi_explorer_clusters=[sorted(c) for c in multi],
               by_layer=dict(by_layer), grades=dict(grades), verify_dirs=dict(dirs), urls=len(urlmap), queries=len(Q), cells=len(cells),
               direction_diversity=round(direction_diversity, 3), queue=len(merged), queue_open=sum(1 for m in merged if m['status'] == 'open'),
               cross_near_dups=cross_nd, yields=yl, axis_counts={k: dict(v) for k, v in axis_counts.items()},
               by_pillar_layer={f'{a}|{b}': c for (a, b), c in sorted(by_pl.items())}, top_cells=cells.most_common(15),
               sampled=sum(1 for n in nodes if n['verify']['status'] == 'two-sided'))
json.dump(summary, open('/tmp/claude-1000/-home-patrickd/b4045317-3a36-45b5-8cfe-a4b20991f0b0/scratchpad/r1_summary.json', 'w'), indent=1, default=list)
print(json.dumps({k: v for k, v in summary.items() if k not in ('cross_near_dups', 'by_pillar_layer', 'multi_explorer_clusters')}, indent=1, default=list))
print('cross-explorer near-dup queries:', len(cross_nd))
