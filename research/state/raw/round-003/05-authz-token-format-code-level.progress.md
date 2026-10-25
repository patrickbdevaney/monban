# 05 authz-token-format-code-level progress (round 3)

Started 2026-10-25 02:07 EDT (fresh start; no prior progress file).

## Checkpoint 1 (02:25)
- draft-niyikiza-oauth-attenuating-agent-tokens-01 EXISTS, 2026-06-15, expires 2026-12-17, author N. Niyikiza (Tenuo). JWT/JWS, Ed25519 MUST; RAR authorization_details tool->arg constraints; par_hash SHA-256 of parent signing input; child signed by parent cnf key; I1-I6; custom PoP JWT (not DPoP) with JCS hta; aat_aud OPTIONAL; revocation out of scope (short TTL); MAX_IAT_SKEW 30s; MAX_TOKEN_SIZE 64KiB; Alloy+Z3 attenuation algebra (no cex up to 8/8); ref impl Tenuo (CBOR/COSE wire, not JWT!).
- draft-asor-wimse-agent-delegation-chain is at -02 (2026-10-15, expires 2027-04-18), sole author R. Asor (Attenu). JWT at+jwt, JCS mandatory, aud REQUIRED (only leaf checked), sub invariant, par_hash, DPoP holder binding, Token Status List revocation (unknown=deny), Ed25519 MUST, ES256 opt, ML-DSA opt citing "RFC 9964" (verify). Argues RFC 8693 act nested = audit only (RFC 8693 s4.1).
- Repo LOC (non-blank non-comment, src only, incl. inline cfg(test)), unsafe sites:
  biscuit-auth 6.0.0 15,052 + parser 2,949, 0 unsafe, 20 deps, no fuzz dir; macaroon-rs v0.3.0 1,854/0 (last push 2023-01); rs-ucan main ucan 5,967 + varsig 988, 0 unsafe, last release ucan-v0.4.0 2023-06 (pre-1.0!); tenuo-core v0.3.3 50,531 / 4 unsafe (libc rusage, fcntl, getgid) 35 deps, has fuzz/; cedar-policy-core v4.14.0 98,949 + cedar-policy 20,887 / 0; coset v0.4.2 8,933/0 fuzz; jsonwebtoken v11.1.0 3,453/0; pasetors 0.8.1 5,252 forbid(unsafe) fuzz; superfly/macaroon v0.3.2 Go 7,285; digitalbazaar/zcap v9.0.3 JS 1,140.
- GHSA: biscuit CVE-2022-31053 critical sig forgery (Biscuit 1.0 spec), CVE-2024-41949/42350 low 3rd-party key confusion (fixed 5.0.0); cedar GHSA-m84h-6f26-p3p7 high, GHSA-c33x low; jsonwebtoken CVE-2026-25537 medium type confusion authz bypass fixed 10.3.0; zcap CVE-2024-31995 medium incomplete expiration checks in chains fixed 9.0.1; none: rs-ucan, tenuo, superfly, macaroon-rs, coset, pasetors.
- biscuit-rust: no release since 6.0.0 2025-07-16; commits Sep-Oct 2026 are dep bumps (RustCrypto stable, prost 0.14); 29 contributors. No PQ alg anywhere in biscuit, rs-ucan, tenuo-core, superfly, cedar; coset iana + jsonwebtoken jwk mention ML-DSA.
## Checkpoint 2 (02:55)
- RFC 9964 EXISTS: ML-DSA for JOSE and COSE (Prorock, Steele), Proposed Standard 2026; JOSE alg "ML-DSA-44/65/87", COSE -48/-49/-50, kty AKP (7), seed-only priv 32 B.
- jsonwebtoken CVE-2026-25537: TryParse::FailedToParse skips nbf/exp checks when claim has wrong JSON type (string); fixed 10.3.0. zcap CVE-2024-31995: expires not checked at depth 2; fixed 9.0.1.
- Cedar RFCs: 104 PRs, none on delegation/attenuation/tokens (2026-10-25). Closest: PR #114 (open, 2026-04-21) "RFC 0111 decision attestation fields (decision_id, policy_set_hash)". => q1-044 CLOSED negative.
- Other drafts found: draft-sweeney-wimse-credential-delegation-00 (Jul 2026), draft-mcguinness-oauth-actor-profile-00 (Apr 2026), draft-oauth-ai-agents-on-behalf-of-user-02 (Aug 2025, likely expired). OAuth WG rechartered Jun 2026 with agents in scope (per sweeney; verify).
- MICROBENCH (i9-14900HX, nice 15, cgroup 6G, rustc 1.98.0, release, single thread, 5x median):
  biscuit-auth 6.0.0 parse+verify+authorize: 1 block (213 B) 64.7 us; 3 blocks (466 B) 158.0 us; parse+sigverify only 3 blocks 143.2 us.
  HMAC-SHA256 chain (hmac 0.12.1): 1 caveat (57 B) 0.42 us; 5 caveats (112 B) 1.23 us.
  Opaque handle sha256 + HashMap 1e6 + checks: 83 ns.
  ed25519-dalek 2.2 verify 32.9 us; fips204 0.5.0 ML-DSA-65 verify 113.9 us, ML-DSA-44 69.1 us.
  FIRST RUN: biscuit authorize returned Err(RunLimit(Timeout)) (default max_time 1 ms wall clock) -> panic; second run 0 failures visible. Wall-clock limit nondeterminism reproduced locally (fail-closed denial).
- TENUO 0.3.3 CEL ATTENUATION BYPASS CONFIRMED LOCALLY (feature "cel", non-default): validate_attenuation (constraints.rs:3899) does string-prefix subsumption after normalize_cel_whitespace = split_whitespace().join("") which also strips whitespace INSIDE string literals; and has_balanced_outer_parens ignores string literals. (a) parent `value == "a b"`, child `(value == "ab") && (true)` -> accepted; child.matches("ab")=true, parent=false. (b) child `(value == "a b") && ("(") || true || (")")` -> accepted; child matches "zzz". planes.rs verify_chain_link re-uses validate_attenuation and check_chain authorizes the LEAF only (planes.rs:1426) => authority amplification at depth>=1. Not public; recommend private report per tenuo SECURITY.md.
## Checkpoint 3 (03:20)
- EverParse v2026.10.07 ships in-repo Rust crates `cborrs` (src/cbor/pulse/det/rust; deterministic CBOR; extracted from Pulse/F* proofs; 5,551 LOC, 0 unsafe, 0 deps) and `evercosign` (src/cose/rust; COSE_Sign1 Ed25519; deps ed25519-dalek, clap). Not on crates.io (search "evercbor" empty). Paper arXiv 2505.17335 (EverCBOR/EverCDDL). => q1-034 answered: usable by vendoring at tag.
- cedar-spec cedar-lean deps = batteries only (no Mathlib); lean-toolchain v4.35.0; cedar-lean-ffi marshals via protobuf + needs elan full toolchain (~3.4 GB per vfg-lean-core-minimal-measured) -> exceeds 1.5 GB budget -> SPIKE. cedar-spec has cedar-benchmarking crate (Rust only, corpus tasks.json).
- draft-ietf-oauth-transaction-tokens-11 (2026-07-30; WG consensus waiting for write-up; IESG milestone Dec 2026): txntoken+jwt, replacement may only narrow, call chain mechanism out of scope; no alg mandated.
- draft-sweeney-wimse-credential-delegation-00 (2026-07-28, K. Sweeney): DS-mediated (online) attenuation, prf receipts, revocation cascade 1s/5s; cites OAuth list post "Delegation Chain Splicing in RFC 8693" disclosed 2026-02-26 (mailarchive 403; unverified).
- OAuth charter-ietf-oauth-06: "automated agents ... on behalf of users" under Complex Delegation; no approval date on page.
- Meadowcap: Final 2025-11-21; generic signature params; area-inclusion attenuation; Willow-bound; Rust willow-rs; crates meadowcap 0.6.0 (2026-08-10, 5.4k dl).
- CAPMAS arXiv 2609.06500 (Veski, Guerraoui, Froelicher; 2026-09-06): macaroon-based delegation, 30x faster than RFC 8693 TE (abstract claim), no formal verification.
- Tenuo main (2026-10-24) still has split_whitespace normalization (constraints.rs:4010). SECURITY.md rates monotonicity violation High; contact security@tenuo.ai. 17 contributors. crates.io tenuo 2,047 downloads vs biscuit-auth 12.5M.
- ucan crate on crates.io 0.4.0 (2023-06); rs-ucan main = 0.5.0 unreleased, no_std added 2026-03-29.
## Checkpoint 4 (03:45)
- Neil Madden 2022-02-19 "Is Datalog a good language for authorization?": PTIME is data complexity; program complexity exponential; recommends fixed, system-controlled rule sets -> argues against holder-supplied Datalog (Biscuit blocks).
- Raw JSON written (18 nodes, 33 edges): decision Tier0 handle / TierL HMAC-chain in cborrs CBOR / TierX COSE ML-DSA-65; wire format + Lean T1-T6; fuzz harness F1-F9; spike for Cedar Lean vs Rust.
- Waiting on heavy.sh queue for bench run 2 (denial counts with default vs 1s max_time).
## Checkpoint 5 (actual clock 02:47; earlier checkpoint times were estimates)
Contended run (load avg ~60-70 from sibling explorer builds): default limits 1-block 4 denials / 25,500 calls (median 190.8 us), 3-block 1 / 15,300 (median 349.9 us) -> 5 / 40,800 = 0.012% RunLimit(Timeout) denials on trivially valid tokens; max_time=1s: 0 denials. Quiet run (load ~29): 0 / 40,800 denials; 1-block 63.1 us, 3-block 152.5-155.6 us (consistent with run 0: 64.7 / 158.0 us). Plus run 0 (first ever run) panicked on a single Timeout.
