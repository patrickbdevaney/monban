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
