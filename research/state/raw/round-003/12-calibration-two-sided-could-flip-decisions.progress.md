# Explorer 12 r3 — calibration two-sided could-flip decisions (started 2026-10-25 02:10 EDT)
Data dir: state/raw/round-003/12data

## C3 w02.handshake-pq-cost (local raw-log recompute, round-002/w02/out,out2)
- rustls(hellotls) logged trials: out 141.7->159.3us (+12.5%), out2 254.8->292.9 (+15.0%). The claimed best trial 123.4->145.0 (+17.5%) appears in NO raw log (grep over round-002): UNREPRODUCIBLE from artifacts.
- envoy: 170.8->211.9 (+24.0%), 121.1->151.7 (+25.3%). caddy (Go, not OpenSSL): 177.6->253.5 (+42.8%), 178.2->247.6 (+39.0%).
- nginx OpenSSL: 246.2->324.7 (+31.9%), 338.3->589.3 (+74.2%), nginx_auto 358.8->557.8 (+55.5%). haproxy: 257.4->335.4 (+30.3%), 258.0->331.7 (+28.6%), mc4096 553.9->728.8 (+31.6%).
- Abs X25519 cost: envoy BoringSSL (121.1 out2) is BELOW rustls in its best trial; rustls best 141.7 (logged). "rustls cheapest" not supported; rustls ~= envoy, both ~1.7x below OpenSSL servers (246/141=1.74x).
- Relative delta ordering holds (rustls 12-15% < envoy 24-25% < OpenSSL 29-74% < (Go 39-43%)). Abs delta: rustls +17.7..+38.1us; OpenSSL +74..+251us.
- Verdict DOWN (numbers) / unchanged decision: hybrid ML-KEM cost negligible at household scale either way.

## C8 threat-ledger 63% resource (recompute from round-002/12data/osv_rust_http.json; script 12data/ledger_recompute.py)
- 111 raw records -> 69 alias-clusters (union-find GHSA/RUSTSEC/CVE). 2023+: 51 after hand fixes (MadeYouReset double cluster merged; 6 regex misclasses fixed).
- resource 31/51 = 61% (Wilson 47-73%). per-year resource: 2023 8/10 (80%), 2024 7/7 (100%), 2025 2/6 (33%), 2026 14/28 (50%, CI 33-67%). TLS/cert logic: 2026 7/28 (25%).
- Scope sensitivity: drop tokio+hickory (not HTTP stack): 29/42 = 69%.
- Verdict: unchanged point (63 within band) but per-year trend DOWN; 2026 TLS-logic rise makes rank-6 under-ranked.

## C6 wasmtime per-year (round-002/07-data/classified.json; not re-pulled)
- Advisories/yr: 2021 4, 2022 8, 2023 4, 2024 4, 2025 4, 2026 57 (audit sprint).
- M0 exploitable ESC per year: 2021 2, 2022 5, 2023 4, 2024 0, 2025 0, 2026 1 (+2 knob-only non-exploitable). 2021-26 total 12/6y = 2.0/yr (Poisson 95% 1.03-3.49). 2024-26: 1 in 2.8y.
- Share framing (6/65=9%) driven by 2026 denominator explosion (57); share is the wrong instrument. M1 adds 2 (2026), M2 adds 2 more (2026).
- Verdict DOWN on "minimal config ~9%" as exposure measure; rate of M0 escapes long-run ~2/yr (core cranelift/reftypes/simd), recent quiet.

## C2 R-PQC-2 FIPS pin (CMVP primary, fetched 2026-10-25)
- Amazon Active certs (CMVP basic search): AWS-LC: #5429 dynamic 2026-07-20 (SP: bcm.o AWS-LC FIPS 2.0.0, sunset 2029-08-13, NO ML-KEM); #5314 static "AWS-LC 3" 2026-06-05 sunset 2031-06-04; #5298 dynamic "AWS-LC 3" 2026-06-03 sunset 2031-06-02 (SP v1.3: bcm.o AWS-LC FIPS 3.1.0, tested AL2023 Graviton4 r8g.metal-24xl + Xeon 8375C c6i.metal); #5146 dynamic 2026-01-26 sunset 2031-01-25; #4816 static 2024-10-01; #4631 2023-10-06.
- #5298/#5314 approved: ML-KEM KeyGen+EncapDecap (512/768/1024), EdDSA, KDA HKDF/OneStep, TLS1.2/1.3 KDF. NO ML-DSA, NO SLH-DSA. X25519 not in boundary (hybrid X25519MLKEM768: only ML-KEM half is module-approved).
- MIP 2026-10-25: AWS-LC 4 (dyn+static) Comment Resolution-Lab 10/22/2026; AWS-LC 5 Pending Review 10/5/2026. => No FIPS 4.0 cert. ML-DSA not approved in any AWS-LC cert.
- Crate mapping: aws-lc-fips-sys 0.13.11 (2026-01-14) vendors AWSLC_VERSION_NUMBER_STRING "3.1.0"; 6 sampled fipsmodule files byte-identical (sha256) to tag AWS-LC-FIPS-3.1.0; .cargo_vcs_info dirty=true, aws-lc-rs sha efaf569; NO git tag aws-lc-fips-sys/v0.13.11 exists in aws-lc-rs. 0.13.12 -> AWS-LC-FIPS-3.2.0 (e50a5f29); 0.13.13/14 -> 3.3.0 (83d85826); 0.13.15/16/17 -> commits ahead of 3.3.0 (+6/+12). 0.13.8-0.13.10 -> fcd86b84 (4 commits BEFORE 3.1.0 tag). 0.14.x (aws-lc-rs >=1.18) = FIPS 4.x source, uncertified.
- aws-lc-rs 1.15.2..1.17.0 all require aws-lc-fips-sys ^0.13.1: the aws-lc-rs pin is NOT what fixes module identity; the exact pin must be aws-lc-fips-sys "=0.13.11" (Cargo.lock), any aws-lc-rs <1.18.
- Verdict: claim UNCHANGED on cert numbers/dates; refined DOWN on "aws-lc-rs =1.15.3" being necessary (wrong lever) and UP on ML-KEM approved status (confirmed in cert). Decision unchanged: FIPS golden = aws-lc-fips-sys =0.13.11; ML-DSA cannot be FIPS-claimed in Oct 2026.

## C5 cedar-spec TCB (clone main == 301bdd22df13 2026-10-23, lean v4.35.0)
- native_decide: 10 in proof-path (Cedar/Data/Int64.lean x2: toInt_nonneg_of_ge_zero/toInt_neg_of_not_ge_zero via (0:Int64).toInt=0; Cedar/Thm/SymCC/Data/Ext.lean x8: msPerDay literal facts, tdiv bounds) + 16 in UnitTest (not proofs). All are closed numeric literal evaluations (replaceable by decide/simp/norm_num).
- Dependents of the Int64 native_decide lemmas: Thm/SymCC/{Decoder, Term/TypeOf, Data, Tactics, Concretizer/WF, Term/PE, Concretizer/Lit, Interpretation, Term/Interpret/Basic, Concretizer/Same} => SymCC soundness/completeness theorems very likely carry Lean.ofReduceBool (trust Lean compiler + runtime). Core authz theorems (Thm/Authorization) do not import these files by grep -> likely axiom-clean, UNVERIFIED (needs `#print axioms`; implementation-phase spike).
- cvc5: Cedar/SymCC/Solver.lean "Currently, we support only CVC5"; trusted for verify* verdicts (sound/complete theorems are about the encoding, not cvc5's answer). @[implemented_by safeSolve/safeTimedSolve] in CedarFFI.
- partial def: 1 in Cedar/ (SymCC/Decoder.lean), 40 in CedarProto/ (protobuf decode on DRT/FFI path), lakefile 1.
- DRT: fuzz_targets dir has 84 targets (32 with 'drt' in name, 12 'pbt'); README table stale: 41 rows (18 DRT / 23 PBT). Parsers (text/JSON->AST) are PBT round-trip only, never differential against Lean (outside model). Public CI builds fuzz crate and runs `cargo test`; no `cargo fuzz run` time budget in public workflows; no cron.
- Verdict: interpretation DOWN (TCB larger than 'Lean kernel + cvc5 + DRT': add Lean compiler for SymCC theorems; parser untrusted-but-untested-differentially); count UNCHANGED.

## C7 CRA + FedRAMP (primary)
- CRA OJ XHTML (publications.europa.eu/resource/celex/32024R2847; EUR-Lex HTML blocked/202): Art 71(2) "apply from 11 December 2027. However, Article 14 shall apply from 11 September 2026 and Chapter IV (Articles 35 to 51) shall apply from 11 June 2026." MATCH. Art 64(2) EUR 15,000,000 / 2.5% for Annex I + Art 13/14 MATCH; Art 64(3) 10M/2%. Art 3(14) steward = legal person MATCH; Art 24(1)-(2) MATCH. No amendment found postponing Art 14 (Digital Omnibus single-entry-point is a separate later track; delegated act on delaying dissemination applies to authorities). 
- FedRAMP/rules main pushed 2026-10-13, fedramp-consolidated-rules.json version 2026.10.13.01: 10 KSI groups, 46 KSIs (CNA 8, SVC 8, IAM 6, MLA 5, PIY 5, CMT 4, RPL 4, INR 3, SCR 2, CED 1). All 7 KSI ids cited in ops.compliance-map-800-53 exist; sc-13 in KSI-SVC-SIN and KSI-SVC-VRI; sc-8 in CNA-MAT; sc-12 in SVC-ASM; si-7/7.1/7.15 in SVC-VRI; cm-7 in CMT-RMV; au-2/au-12/au-10 in MLA-LET; AU-9(3) is in SVC-VRI not MLA-LET (minor misattribution); sa-11/sa-15 in SCR-MIT (sr-2/3/5 not in SCR-MIT list shown).
- Verdict: CRA UNCHANGED (now primary OJ, grade up B->A for dates); compliance map UNCHANGED (counts 10/46 now pinned).

## C4 CRS C1-C8 instance count (from r2 explorer 10 nodes) + third instances (cveawg/KEV/vendor)
- C1 Provenance: had GnuTLS CVE-2020-13777 + AWS ALB rotation (2). THIRD: Apache Superset CVE-2023-27524 (pub 2023-04-24) default SECRET_KEY -> forged server-issued session cookies; CISA KEV added 2024-01-08. -> 3 instances, one KEV.
- C2 Scope: >=4 (nginx CVE-2025-23419, Apache CVE-2025-23048, Fastly, Cloudflare mTLS; coalescing 421). Not two-instance.
- C3 Key completeness: >=3 (cache poisoning/deception multi-vendor, curl 16 reuse CVEs 2026, Next.js CVE-2026-44572).
- C4 Freshness: rests on RFC 8446 §8 / RFC 9001 §9.2 text + idempotency draft -08 §5 = 0 incident CVEs for 0-RTT replay found (search). Two-sided: clause is necessary-by-spec, not by incident -> keep, grade C for "observed". Adjacent incident: mbedTLS CVE-2026-73096 (advisory 2026-07-07; 3.6.0-3.6.6, 4.0.0-4.1.0; forged EndOfEarlyData in ClientHello record trailing bytes -> early data silently dropped) — integrity of early data, not replay.
- C5 Epoch: session fixation class + curl CVE-2016-5419 + Hebrok 2025. THIRD: PostgreSQL CVE-2026-14666 (pub 2026-08-13) cached RLS policy survives role-membership change until connection end.
- C6 Failure atomicity: had PyJWT CVE-2026-48524 (pub 2026-05-28; fix 2.13.0) [+ incomplete-fix CVE-2026-101917 2026-09-28, 2.14.0 = same codebase]. SECOND independent: RabbitMQ CVE-2026-67409 (pub 2026-09-25) JWKS fetch ignores HTTP status, non-200 destroys signing keys -> auth DoS (fixed 4.3.3/4.2.9/4.1.14/4.0.23/3.13.18). THIRD: libjwt commit 22a089aa "harden the cached source against HTTP errors and failing refreshes" (no CVE). Was effectively ONE-instance clause; now 3.
- C7 Authority ceiling: XFF (Litestar CVE-2025-59152, Lemmy CVE-2026-54738), JWKS kid, hashDoS. Plus client-side: rustls RUSTSEC-2026-0349 (unauth ServerHello cached group -> PQ downgrade of later connections) = unauth input crossing into security-relevant cross-connection state.
- C8 Shared-context partitioning: had HPACK/HEIST (research) + coalescing contamination draft (no CVE). THIRD/FOURTH: Tomcat CVE-2024-52317 (pub 2024-11-18, HTTP/2 request/response mix-up between users via incorrect recycling) and CVE-2026-101356 (pub 2026-10-20, async error path). => clause should name recycled request/response objects.
- GAP (counterexample to completeness): connection-level key-epoch transitions are not covered: rustls RUSTSEC-2026-0285/GHSA-2mjx-qc3c-rqvc (2026-09-14; handshake msgs accepted across encryption-level boundaries) + mbedTLS CVE-2026-73096. Proposed C5 extension: "at every key/epoch change, input buffers are empty or the connection aborts".

## C1 R-GAP-1 skeptic (web + gh search repos pushed>=2026-06, 7 queries)
- No 2026 project found combining PQ TLS + capability authz + machine-checked/DST + lean single binary middle-tier server.
- Nearest partial existence proof: coproduct-opensource/nucleus (MIT, created 2026-01-31, v2.7.0 2026-10-08, 22 stars): agent tool-proxy with IFC permission lattice "Lean 4 + Kani-backed verdicts" (195 .lean files at HEAD), SPIFFE identity, Firecracker pods, MCP; tokio-rustls 0.26. It is an agent sandbox runtime with >100 workspace crates, not a lean front-proxy/web tier; no PQ config found by code search.
- Rullst/Rullst (MIT, created 2026-05-25): full-stack Rust framework, Kani/Miri selected scopes, Verus pilot; TLS delegated to Caddy; "capability" = feature modules, not ocap. Not a match.
- agentgateway (Apache-2.0, v1.6.0 2026-10-02, v1.7.0-alpha.1 2026-10-21): aws-lc-rs 1.18 (rustls PQ default), CEL authz fork, MCP/A2A; code search: 0 hits cedar/kani/verus/turmoil/madsim.
- Verdict: gap UNCHANGED in conjunction; UP on underclaim (machine-checked authz lattices for agents now exist in OSS in 2026); decision unchanged.
- DONE: final JSON + nodes.jsonl written Sun Oct 25 02:21:56 AM EDT 2026
