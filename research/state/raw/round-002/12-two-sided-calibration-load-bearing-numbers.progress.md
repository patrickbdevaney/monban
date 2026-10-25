# Explorer 12 r2 — two-sided numeric calibration (progress)
Snapshot: CISA KEV catalogVersion 2026.10.23 (dateReleased 2026-10-23T19:30Z, count 1756), fetched 2026-10-24 23:37 EDT -> 12data/kev.json

## result-memory-safety-would-not-prevent-fraction (KEV part)
- KEV adds 2023-01-01..2026-10-23 = 890 (matches claim 890).
- Non-memory share: strict mem-CWE set 729/890 = 81.9%; broad set (adds int overflow, uninit, races) 703/890 = 79.0%; strict CWE + keyword 78.8%. Claimed 80.3% (715/890) sits inside [78.8, 81.9] -> HOLD; report as a band, not a point.
- Per year nonmem (strict): 2023 75.4%, 2024 83.3%, 2025 80.4%, 2026 YTD 86.8% — trend upward.
- 64/890 KEV adds have no CWE (7.2%) -> irreducible +-3.6pp.
- OSS middle-tier KEV entries 2023+: claim "5, 100% non-memory". Recount finds >=8: CVE-2023-44487 (IETF HTTP/2 Rapid Reset, CWE-400), CVE-2026-48710 (Starlette CWE-444 smuggling/host-path injection -> auth bypass, added 2026-09-02), CVE-2024-38475 httpd, CVE-2025-24813 / CVE-2026-34486 / CVE-2016-8735 Tomcat, CVE-2024-4577 PHP, CVE-2019-16278 nhttpd. Direction of conclusion holds (all non-memory) but count is UNDERSTATED, and the Starlette entry is a smuggling/canonicalization-to-authz case in KEV -> strengthens threat ranks (2)/(3).
- Kernel KEV: zero io_uring entries in KEV ever; but CVE-2025-39682 (kTLS receive path, zero-length record) added 2026-09-18 -> kTLS has an exploited-in-the-wild entry, io_uring does not.

## io-uring-security-record (NVD recompute 2026-10-24 23:40 EDT, keywordSearch, resultsPerPage=2000)
- io_uring total 161; 2022 10, 2023 15, 2024 38, 2025 40, 2026 54; >=7.0 (v3.1/v4 first metric) 2025 22 + 2026 22 = 44. EXACT MATCH all.
- epoll 2024/25/26 7/8/11 MATCH; kTLS 5/4/4 MATCH; XDP 37/48/67 MATCH.
- Skeptic: kernel CNA (since Feb 2024) files a CVE for most fixes: Jan-Apr 2025 alone 1,663 kernel-CNA CVEs in NVD => io_uring ~40/~5,000 = ~0.8% of 2025 kernel CVEs. Keyword counts inflated by CNA policy for ALL subsystems; XDP keyword dominated by NIC-driver fixes. Zero io_uring CVEs in CISA KEV (all-time) whereas kTLS CVE-2025-39682 IS in KEV (added 2026-09-18). CVE-2026-80713 verified (cveawg, published 2026-08-28, 'io_uring: preserve task restrictions across exec').
- Verdict: numbers HOLD (A for counts); interpretive claim "io_uring uniquely dangerous" should be stated as "local-attacker LPE surface; Google kCTF 2023 data", not in-the-wild exploitation. Grade B hold.

## std-rfc10024-ecdhe-mlkem / "PQ KA solved?"
- rfc-editor JSON: RFC10024, PROPOSED STANDARD, Aug 2026, from draft-ietf-tls-ecdhe-mlkem-05, defines X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024. MATCH.
- rustls 0.23.46 (2026-10-14, crate source read): aws-lc-rs provider ships X25519MLKEM768 (default, top priority), SECP256R1MLKEM768, MLKEM768, MLKEM1024. SecP384r1MLKEM1024 ABSENT (also absent on main 0.24.0-dev.2 @28ee6c6 2026-10-23). ring provider: no ML-KEM at all (main: rustls-ring DEFAULT = X25519,P256,P384).
- Counter-evidence (deployment): Ubuntu LXD restricted SimpleStreams to classical curves Mar 2025 because of middleboxes resetting split ClientHello; restoration announced 2026-07-03 (discourse.ubuntu.com/t/84803). rustls docs still say X25519MLKEM768 "pre-standardization" (stale doc string) and point to tldr.fail.
- Verdict: "solved" HOLDS for the server side of commodity hybrid (X25519MLKEM768 via aws-lc-rs). NOT solved: (a) CNSA-2.0-style P-384+ML-KEM-1024 hybrid in rustls; (b) PQ authentication; (c) client-side middlebox breakage (server cannot fix; only accept fragmented ClientHello). Keep A for the RFC fact; downgrade any derived "PQ confidentiality solved for our stack" claim to B with the two carve-outs.

## j-mcp-2026-07-28 / j-mcp-stateless-no-sessions (gh api 2026-10-24)
- Releases: 2026-07-28 published 2026-07-28T16:47:49Z (not prerelease); 2026-07-28-RC 2026-05-29T12:51:22Z; 2025-11-25 2025-11-25T21:17Z; RC 2025-11-15T06:06Z. EXACT MATCH. RC "May 21" alternative is unsupported by the release object -> resolve to 2026-05-29.
- No later release exists as of 2026-10-24 -> 2026-07-28 is latest. TS SDK tests reference a future '2026-09-01' protocolVersionPin mapped to era '2026-07-28' (test fixture, not a release).
- Changelog fetched: sessions/Mcp-Session-Id removed (SEP-2567), initialize removed (SEP-2575), SSE resumability removed. MATCH.
- Counter-evidence ("stateless" over-claim): (1) state did not vanish, it moved: subscriptions/listen is a long-lived POST stream, tasks extension keeps server-side task state, MRTR carries requestState, server-minted handles as tool args. (2) Dual era: TS SDK packages/core/src/constants.ts LATEST_PROTOCOL_VERSION='2025-11-25' with SUPPORTED list back to 2024-10-07, while a separate 2026-07-28 codec exists; rmcp 3.7.0 (2026-10-22) LATEST=V_2026_07_28 but keeps LATEST_WITH_INITIALIZE. A gateway must still implement session semantics for pre-2026 clients during the >=12-month deprecation window (SEP-2596).
- Verdict: date A HOLD; stateless node HOLD on spec text, add carve-out: 'stateless at protocol layer for 2026-07-28 peers only; legacy-session path mandatory until >=2027-07'.

## fail-verifier-soundness-bugs (gh api 2026-10-24/25)
- Verus label:soundness is:issue = 131 total / 41 open: EXACT MATCH (note: without is:issue search returns 154/43 because 23 PRs carry the label — a trap for future recounts).
- NEW numbers (underclaim): 94/131 filed in 2026, 81 in Oct 2026 alone (vs 8 in all of 2025); 12 since 2026-10-15. Filers: iainmcgin 26, remi-delmas-3000 20, tjhance 16, dschoepe 13 -> a systematic audit campaign, many 'proves false' via vstd specs (#3167 Ord::max/min/clamp, #3165 prophetic iterator axiom, #3212 crate named alloc gets vstd specs, #3216 ghost_block_wrapped runs exec without div-by-zero check, verified with --no-cheating). vstd is TCB.
- Issue states re-checked: #3252 closed, #3029 open, #3177 open, #2036 open, #3166 closed, #3180 closed. MATCH.
- Z3 #11295 (2026-10-24) now CLOSED; Z3 #10963 now CLOSED (node said 'still in 5.1.0' -> stale status). Dafny #6553 closed; F* #4534 closed. MATCH on existence/dates.
- Added: cvc5 #12926/#12927 'Unsoundness on Coverings solver' (2026-09-07, closed) — cvc5 is the solver cedar-policy-symcc trusts (nonlinear-arith module; Cedar SymCC encodes bitvectors/strings/sets, so likely not on Cedar's path, but the TCB claim must name cvc5 version).
- Verus latest rolling: release/rolling/0.2026.10.25.98699c5 (2026-10-25T03:07Z).
- Verdict: UP in confidence (0.9->0.95), A hold; the rate is higher than the node states — Verus proof TCB is in an active-defect discovery phase (81 soundness issues in one month).

## cedar-lean-proofs-2026-10 (independent recount, clone cedar-spec @301bdd2 2026-10-23, lean v4.35.0)
- 387 .lean files / 125,621 LOC: MATCH. Cedar/Thm 226 files / 96,228 LOC: MATCH.
- Theorem declarations: claim 3,912. Recount: declaration lines (incl @[..], private/protected/public) in Cedar/Thm = 3,776 (Cedar/ total 3,811). Raw token 'theorem ' across all .lean incl comments = 3,926 -> claim likely token count incl prose. Over by ~3.6%. Minor numeric over-claim.
- 0 sorry: MATCH. 'partial def': 1 in Cedar/ (SymCC/Decoder.lean:161) MATCH for Cedar/, BUT ~40 partial defs in CedarProto/ (protobuf decode used by the Lean FFI / DRT harness) -> the DRT channel itself runs through unproven partial Lean code.
- MISSED by node: 10 uses of native_decide (Cedar/Data/Int64.lean, Cedar/Thm/SymCC/Data/Ext.lean) -> TCB includes Lean compiler + Lean.ofReduceBool axiom, not just the kernel. No @[implemented_by]/@[extern] under Cedar/ (MATCH).
- Named theorems exist at stated files: forbid_trumps_permit, default_deny (Authorization.lean:64,92), validation_is_sound (Validation.lean:51), compile_is_sound (SymbolicCompilation.lean:71), isAuthorized_is_sound (:155), verifyNeverErrors_is_sound (Verification.lean:46). MATCH.
- What is proven vs the Rust evaluator: NOTHING is proven about cedar-policy (Rust) — the Lean model is the proof object; Rust<->Lean equivalence rests on DRT. 84 fuzz target files; cedar-drt README table: 18 DRT rows / 23 PBT rows. Public CI (build_and_test_drt_reusable.yml) only BUILDS and unit-tests the DRT harness (cargo build/test); no fuzz campaign runs in public CI -> DRT volume is an AWS-internal claim (blog/paper), unverifiable from the repo.
- Verdict: DOWN one notch on interpretation (A for counts; but any downstream claim 'verified evaluator' is B at best: verified MODEL + DRT-tested Rust). confidence 0.88->0.85.

## sdg-pgbouncer (NEWS.md snapshot, 1.26.1 head)
- 12 CVEs since 2025-04 (sort -u of CVE-2025/2026 ids in NEWS): EXACT MATCH. Dates 1.24.1 2025-04-16, 1.25.1 2025-12-03, 1.25.2 2026-05-08, 1.26.0 2026-09-23, 1.26.1 2026-10-14 MATCH.
- Minor mis-statement: CVE-2026-6669 is malicious-SERVER unbounded SCRAM iterations, not pre-auth client DoS; CVE-2026-6665 is malicious-backend stack overflow. Classification of the 12: memory-class (int overflow/stack overflow/null deref) = 6664, 6665, 6666, 6668, 107348 = 5/12 (42%); logic/authz/DoS = 7/12 incl. both CVSS>=8 ones (2025-2291 VALID UNTIL, 107350 SCRAM impersonation, 2025-12819 SQL via search_path).
- NEW (underclaim): 1.26.0 makes search_path tracked by default on PG18 -> the precondition of CVE-2025-12819 (track_extra_parameters includes search_path, previously "non-default") became DEFAULT; fixed code path but 1.26.1 itself says search_path-tracking bugs remain "to be addressed in a later release". Supports avoid-third-party-pooler.
- Verdict: HOLD A, conf 0.95.

## sdg-rls-plan-cache-family (cveawg 2026-10-24)
- CVE-2016-2193 pub 2016-04-11; CVE-2023-2455 pub 2023-06-09 fixed 15.3/14.8/13.11/12.15/11.20; CVE-2024-10976 pub 2024-11-14 CNA CVSS 4.2, fixed 17.1/16.5/15.9/14.14/13.17/12.21, CWE-1250; CVE-2026-14666 pub 2026-08-13 CVSS 4.2 AV:N/AC:H/PR:L, fixed 18.6/17.11/16.15/15.19/14.24, CWE-1250; CVE-2023-39418 MERGE 3.1. ALL MATCH. "CVSS ~4.2-5.4" -> CNA score is 4.2 for both; 5.4 only from NVD secondary.
- Nuance (prosecutor): CVE-2026-14666 trigger is ALTER ROLE/membership/ownership change during a live session, not SET ROLE per se -> long-lived pooled backends widen the stale window; any gateway that caches backends must invalidate on role DDL (or recycle conns). HOLD A 0.95.

## sdg-txn-pooling-session-leak (gh api 2026-10-24)
- PgDog #1850 open 2026-10-18 MATCH; #1341 open 2026-08-11 MATCH; #1407 open 2026-08-21 MATCH; fix PR #1444 OPEN (created 2026-08-27, unmerged ~2 months) -> SET ROLE leak still unfixed in PgDog v0.1.62 (2026-10-16).
- Supavisor PR #1113: node says "merged 2026-07-22" -> WRONG: created 2026-07-22, merged 2026-10-23T23:28Z; shipped only in v2.10.0-rc.0 (2026-10-24, release candidate). Default 'ignore' MATCH. Correct the date; feature is not yet in a stable Supavisor release.
- Verdict: class claim UP (all three poolers have open/just-landed leak issues); one date DOWN. Grade A hold w/ correction.

## sdg-rls-misconfig-empirical
- UpGuard (fetched): 16,326 DBs w/ publicly readable tables, ~300k candidate domains (BuiltWith + CrUX JS), pub 2026-10-14, ">half" PII indicators (no exact count), API-created tables lack RLS default. MATCH. Skeptic: "readable" = users-table query or table-name hint; PII judged from schemas not rows -> 16,326 is an upper bound on sensitive exposure; denominator is domains not DBs (share ~5.4% of domains is NOT a valid rate).
- CVE-2025-48757 pub 2025-05-30, CVSS 9.3 CWE-863, disputed: MATCH.
- Supabase changelog #45329 (PRIMARY, fetched): opt-in 2026-04-28; default new projects 2026-05-30 (gradual); existing projects 2026-10-30. MATCH (upgrade from "secondary report" to primary). UNDERCLAIM: existing tables keep their grants -> the 16,326 exposures are NOT remediated by the 10-30 switch; it controls grants not RLS.
- Verdict: UP to A for dates/counts, B for interpretation. conf 0.85.

## gap.insecure-defaults (gh api security-advisories 2026-10-24)
- All cited exist: ferron GHSA-vp46-fx86-chgc auth_to fail-open CRITICAL 2026-09-25; GHSA-3vvm-v3qp-7gmg DNS/ACL fail-open; docker/mcp-gateway CVE-2026-76092 unauth proxied tools CRITICAL, CVE-2026-76094 sig verification off by default HIGH (2026-07-09); pingora CVE-2026-2836 insecure-by-default cache key (2026-03-05), CVE-2026-105297 unbounded default header-list (2026-10-20); agentgateway GHSA-mvgg-jvj2-4frq session policy overwrite (2026-07-27). MATCH.
- Share (defender): across the 4 repos' 30 advisories, ~7 are default/fail-open class (~23%); parser/smuggling/canonicalization equal or larger (pingora 2 smuggling criticals, ferron encoded-slash, pingora :authority/Host mismatch CVE-2026-105298 2026-10-20). Insecure defaults are one co-equal class, not dominant. HOLD A.

## as.mutants-gate (re-verified, no re-run: memory budget)
- cargo-mutants v27.1.0 published 2026-06-02 MATCH; httparse a0fa552e 2026-06-30 MATCH; exit codes doc MATCH; arithmetic 88/261=33.7%, 58/231=25.1%, total 371 MATCH.
- OVERCLAIM FOUND: the cited "real test gap" (delete b'A'..=b'Z' arm of is_method_token, lib.rs:61) is an EQUIVALENT mutant — the fallthrough TOKEN_MAP[b] returns true for A-Z (tchar includes ALPHA), so deleting the fast-path arm cannot change behaviour; no test can kill it. Mis-labels equivalence as gap -> the 25.1% "true miss" rate is an upper bound; equivalent mutants must be triaged before using a threshold gate.
- Gate hazard: run had both misses and timeouts and exited 3 (not 2) -> a CI gate checking only exit==2 silently passes runs with misses. Gate must treat {2,3} as fail or parse mutants.out/outcomes.json.
- Verdict: numbers HOLD A; interpretive example DOWN; conf 0.8->0.75.

## as.fuzz-gate
- rustls build.yml job "Smoke-test fuzzing targets" (arm64) loop with -max_total_time=10 MATCH; cifuzz.yml on pull_request fuzz-seconds 150 MATCH.
- OSS-Fuzz (raw project.yaml probes): present rustls, httparse, tokio, wasmtime, ring, quiche; absent hyper, h2, quinn, pingora, http, s2n-quic, rustls-webpki, aws-lc. MATCH. TRAP: gh contents API on oss-fuzz/projects truncates at 1000 entries (falsely shows rustls absent) -> recounts must probe per-project.
- hyper has no fuzz dir MATCH; h2 fuzz last commit 2023-11-15 MATCH. Versions cargo-fuzz 0.13.2 (06-09), libfuzzer-sys 0.4.13, arbitrary 1.5.0, bolero 0.13.7, honggfuzz 0.5.62, afl 0.18.2 MATCH.
- Skeptic: 10 s/target is a compile+smoke check (rustls labels it so), not a campaign; the bug-finding is OSS-Fuzz continuous. A per-PR "fuzz gate" for our repo should be called smoke; real assurance = continuous corpus + coverage delta. HOLD A.

## as.dst-entropy-leak (local registry source read 2026-10-25)
- aws-lc-sys 0.46.0 urandom.c:189 syscall(__NR_getrandom,...) MATCH; getrandom 0.2.17 util_libc::getrandom_syscall via libc::SYS_getrandom MATCH; getrandom 0.3.4 dlsym(RTLD_DEFAULT,"getrandom") non-musl / static libc::getrandom on musl MATCH.
- UNDERCLAIM (stronger than node): aws-lc 0.46 default entropy source (entropy_sources.c) = Tree-DRBG seeded from CPU JITTER entropy (tree_drbg_jitter_entropy.c), plus RDRAND/RNDR for prediction resistance when CPU supports it (have_hw_rng_x86_64). RDRAND is a CPU instruction and jitter is timing-derived -> NOT interceptable by libc override, seccomp, or ptrace. So even a perfect getrandom interposer cannot make aws-lc deterministic. Only escape: DISABLE_CPU_JITTER_ENTROPY build flag still uses rdrand for personalization -> the only sound DST path is a deterministic test CryptoProvider (rustls CryptoProvider with seeded SecureRandom + non-aws-lc primitives) under sim, real provider in prod, and a canary asserting no getrandom/rdrand in sim (rdrand can be trapped only via CPUID masking in a VM).
- Verdict: UP confidence 0.85->0.92, A; strengthen claim from "not deterministic by default" to "cannot be made deterministic by syscall/libc interposition at all".

## fail-spec-fidelity-studies
- arXiv 2605.26457 (fetched): title is "Verus-SpecGym: An Agentic Environment for Evaluating Specification Autoformalization" (Agarwal, ..., Parno, Welleck; 2026-05-26); benchmark inside = Verus-SpecBench. Gemini 3.1 Pro 77.8% MATCH; other frontier 51.1-57.8% MATCH; OSS 21.5-25.5% (omitted by node); LLM-judge misses 26% of failures caught by executable evaluator MATCH.
- Skeptic on transfer: tasks are Codeforces problems with test+hack cases, not systems/protocol specs -> 77.8% is an upper bound for our HTTP/authz specs; no evidence of transfer.
- IronSpec OSDI'24 (usenix page via search): 10 spec bugs across all 6 real-world verified systems, 14 specs evaluated MATCH.
- Fonseca EuroSys'17: 16 bugs in IronFleet/Verdi/Chapar; none in verified protocols (8+ months searching) MATCH (via abstract + mailing list quote; PDF fetch blocked).
- Verdict: HOLD B->A- for numbers (all match); label title correction. conf 0.88.

## result-memory-safety-would-not-prevent-fraction (C/C++ part, vendor pages fetched 2026-10-25 00:02)
- nginx security_advisories.html: CVE-2024..2026 entries = 35 MATCH; non-memory (injection/spoofing/session/OCSP/SSL) = 8 -> 8/35 = 22.9% MATCH.
- httpd vulnerabilities_24.html: 2023+ unique CVEs = 77 MATCH; my keyword classification: memory 22, crash-ambiguous 5, logic 50 -> non-memory 50-55/77 = 65-71% vs claim 48/77 = 62% (claim conservative; HOLD as band 62-71%).
- MAJOR TIME-TREND (missed by node; underclaim for memory safety): 2026 YTD surge. httpd: 2026 = 44 CVEs (20 memory = 45%) vs 2023-2025 = 33 CVEs (2 memory = 6%). nginx: 2026 = 26 advisories (19 memory = 73%) vs 2024-2025 = 9. The pooled 2023-26 "61% logic" is dominated by a pre-2026 regime; in 2026 C servers are yielding memory bugs at 3-8x the earlier rate. A point estimate across the window hides a regime change.
- KEV part (from earlier): 78.8-81.9% band; KEV lags disclosure by months so the 2026 memory surge is not yet visible in KEV.
- Verdict: HOLD on the direction for KEV; DOWN on using the pooled C/C++ 61% as a stable rate — report per-year; grade B hold, conf 0.8->0.72 for the pooled figure.

## KEV edge-gateway + middle-tier (kev.json 2026.10.23)
- Edge-gateway recompute (my vendor+product filter: Citrix/F5/Fortinet/Ivanti/PAN/Juniper/SonicWall/Cisco/...; strict mem-CWE set): n=77 2023+, non-memory 57/77 = 74.0% vs claim 99/123 = 80.5%. Denominator is definition-sensitive (123 vs 77). Per-year memory share: 2023 2/13 (15%), 2024 2/17 (12%), 2025 8/22 (36%), 2026 8/25 (32%) -> memory share in edge-gateway KEV ~2.5x higher in 2025-26 (NetScaler CWE-119 x5 in 2026, F5 BIG-IP APM CVE-2026-94127 CWE-122, PAN-OS CVE-2026-0300 CWE-787). Same regime shift as C servers.
- nginx CVE-2026-42945 (AI-agent-found 18-year heap overflow, DepthFirst/F5, 2026-05-13, public PoC same day; CVSS4 9.2) is NOT in KEV as of 2026.10.23 -> KEV under-represents memory bugs in OSS servers that have public PoC but no confirmed ITW.
- Verdict: claim 80.5% DOWN to band 74-80%; trend direction contradicts any "memory safety matters less over time" reading.

## j-openapi-arazzo (gh api releases): OAS 3.0.4/3.1.1 2024-10-24, 3.1.2/3.2.0 2025-09-19, 3.2.1 2026-09-10; Arazzo 1.0.0 2024-09-25, 1.0.1 2025-01-20, 1.1.0 2026-05-18. ALL MATCH. HOLD A 0.95. (3.2.1 is a patch release: features date from 3.2.0.)

## sdg-embedded-store-selection
- SQLite wal.html (primary, updated 2026-08-25): WAL-reset bug found 2026-03-03, present 3.7.0 (2010-07-21) .. 3.51.2, fixed 3.51.3 (2026-03-13), backports 3.44.6, 3.50.7. MATCH except age: 15.6 years, not "14-year". Phil Eaton natural reproducer 2026-08-24.
- DEFENDER: trigger requires >=2 connections on the same file writing/checkpointing at the same instant -> a single-writer-connection architecture is immune; it is a concurrency bug, not a power-loss crash-consistency bug, so lumping it into "crash-consistency record" over-states SQLite's risk for our use.
- Version pin stale: latest SQLite 3.54.1 (2026-10-16), 3.54.0 (2026-10-09); node pin ">=3.53.0" ok as floor but say 3.54.1 current.
- redb: v4.3.0 (2026-09-15) fixes "crash shortly after a commit could silently roll that commit back during recovery IF check_integrity() had previously repaired the DB"; v4.4.0 (2026-10-13) fixes check_integrity() falsely reporting repair + Durability::None commits lost on clean close after caught panic. -> PROSECUTOR vs node's alternative ("redb + check_integrity on open"): the repair path itself was the bug locus twice in 2 months; use check_integrity as detect-only/fail-closed, never auto-repair.
- fjall #329 (power-loss partial batch, memtable flush w/o journal sync) opened 2026-10-01 closed 2026-10-02 MATCH; latest fjall 3.1.12 (2026-10-03).
- heed v0.23.0 2026-10-22 release notes: "no longer possible to produce undefined behaviors when opening or creating databases" MATCH.
- sled: crates.io max_stable 0.34.7 (2021), 1.0.0-alpha.124 -> "never left alpha" MATCH.
- Verdict: "all embedded stores flawed" HOLD as fact-pattern, but DOWN on SQLite-specific severity (avoidable trigger) and node's redb-mitigation inverted. B hold, conf 0.82.

## sdg-failed-request-no-mutation: Jepsen PG 12.3 (pub 2020-06-12) G2-item under SERIALIZABLE since SSI 2011 (9.1); fix scheduled for 2020-08-13 minor release MATCH. RDS PG 17.4 (2025-04-29, upd 05-03) Long Fork on Multi-AZ via read-only secondaries, violates SI ("Repeatable Read"); not in single-node PG MATCH. HOLD B 0.85 (invariant carve-outs are textbook-true; no counter-evidence).

## l5-authz-stack-recommendation (gh api 2026-10-25)
- OpenFGA GHSA: 29 advisories total; 2023-2026 decision-correctness (Authorization Bypass / Improper Policy Enforcement) = ~20 (8 in 2026 alone: Sep-28, Sep-08, 61709, 55170, 48096, 34972, 41131, 33729, 24851) -> "repeated fail-open decision bugs" STRONGLY MATCH for OpenFGA.
- SpiceDB GHSA: 18 total; decision bugs mostly FAIL-CLOSED ("no permission when expected": 49011, 46989, 38361) or partial lookups; fail-open only ~3-4 (CVE-2026-55866 unconditional permission w/ caveats, CVE-2026-46668 improper cache reuse, CVE-2022-21646 wildcard exclusions, CVE-2024-27101 int overflow). -> lumping SpiceDB with OpenFGA as "repeated fail-open" OVERCLAIMS; SpiceDB's record is predominantly fail-closed, low severity.
- Biscuit: biscuit-auth 6.0.0 last release 2025-07-16 (15 months), repo pushed 2026-10-08 -> "stale releases" MATCH, but not abandoned.
- osohq/oso archived=true MATCH. cedar 4.14.0 + cedar-policy-symcc 0.8.0 2026-10-17.
- Cedar delegation/token RFC: none (rfcs search: #88 JWT container closed 2024-11; #112 time-limited agentic policies open 2026-03 question) -> reversal condition unmet MATCH.
- Verdict: C -> B (facts verified), but conditional on cedar-lean caveat (verified MODEL, DRT-tested Rust, native_decide in TCB). SpiceDB characterization corrected. conf 0.7->0.75.

## PQ deployment numbers (defender for "solved")
- Cloudflare: >50% of human HTTPS traffic PQ key agreement since Oct 2025 (29%->52% jump attributed to iOS 26, secondary); still "more than half" Apr 2026 coverage; Year-in-Review 2025 52%. Radar live value not readable (no API token) -> ~half of clients, NOT all: ~48% of human clients still classical -> server must keep classical fallback; PQ confidentiality is per-connection opportunistic. Cloudflare PQ-auth target 2029 -> PQ authentication unsolved.

## threat-ledger-middle-tier-2023-2026
- KEV middle-tier OSS (2023+): HTTP/2 Rapid Reset CVE-2023-44487 (resource, 1); canonicalization/smuggling/authz: Starlette CVE-2026-48710 (Host header poisons request.url.path -> path-based security bypass; cveawg pub 2026-05-26, KEV 2026-09-02), httpd CVE-2024-38475 (CWE-116 mod_rewrite), Tomcat CVE-2025-24813 (path equivalence), nhttpd CVE-2019-16278 (traversal), PHP-CGI CVE-2024-4577 (arg injection via char mapping); Tomcat CVE-2026-34486 (EncryptInterceptor bypass from a regression fix, crypto-logic); Tomcat CVE-2016-8735. -> 5-6 of 8 are canonicalization/parser-differential/authz; 1 resource exhaustion.
- Verdict: by ITW exploitation (KEV), rank (2) canonicalization/fail-open > rank (1) H2/H3 exhaustion; rank (1) wins only on advisory VOLUME in Rust servers (ferron/pingora 2026: rapid-reset bypass, H3 SETTINGS O(n^2), unbounded default header list). Recommend tie or swap (1)<->(2) with explicit metric (likelihood=ITW vs disclosure volume). Rank (4) memory corruption: for C servers 2026 surge (above) makes it larger than the node implies, but for a Rust stack it is confined to FFI (aws-lc) -> keep rank 4 for OUR stack, flag stack-dependence. HOLD B, conf 0.75->0.7.

## Rust HTTP-stack OSV recompute (19 crates, osv querybatch 2026-10-25 -> 12data/osv_rust_http.json, 111 records)
- 2023+ unique incidents (RUSTSEC/GHSA pairs merged) ~51: resource exhaustion/panic/loop ~32 (63%); TLS/cert/DNSSEC validation logic ~9 (18%); smuggling/parser/path ~5 (10%: pingora x3, actix-http CL.TE 2026-04-22, warp traversal); unsoundness/memory ~5 (10%; only quiche FFI UAF GHSA-mh64-ph39-mrc9 is a real UAF, in C-ABI FFI functions). Supports threat-ledger rank (1) for Rust stacks by VOLUME; memory <=10% and FFI-confined (node said <=1% for memory-safe servers -> for Rust TLS/QUIC stack the unsound/FFI share is ~2-10% depending on whether tokio unsoundness counts).
- PQ "solved" COUNTER-EVIDENCE: RUSTSEC-2026-0349 / GHSA-w44r-93j7-qv28 (2026-10-14): rustls CLIENT cached server-selected group from unauthenticated ServerHello -> attacker forces later ClientHellos to X25519-only share -> classical-only handshake with no error, if the server accepts the share instead of HelloRetryRequest. All rustls < 0.23.46. Server-side lesson for us: when a client lists X25519MLKEM768 in supported_groups but sends only an X25519 key share, our server should HRR to the hybrid group (1 RTT cost) -> acceptance test. Also RUSTSEC-2026-0285 (TLS1.3 messages across encryption levels, 0.23.13-0.23.44), RUSTSEC-2026-0348 brotli 1GiB (feature-gated).
- => std-rfc10024 "PQ KA solved for our stack": DOWN to "solved only with rustls>=0.23.46 + server HRR-to-hybrid policy + aws-lc-rs provider"; downgrade resistance is NOT given by the RFC alone.
