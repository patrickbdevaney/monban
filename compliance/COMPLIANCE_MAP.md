# COMPLIANCE_MAP (AEGIS, Phase 6 instance, 2026-11-04)

Instantiated from `research/templates/COMPLIANCE_MAP.md` (template v4, 2026-10-25) by unit P6-compliance-001
(PLAN-6 D9, D11, D15–D17; PREFLIGHT D-P1 and the operator decision of 2026-11-04). It is an internal evidence map,
not a published compliance statement. `python3 -I ci/compliance.py check` (gate `compliance`) machine-checks it:
every §4 `gate_id` must be a gate in `gates/phase-6.toml`, every §4.1 theorem must be a frozen theorem in
`spec/STATEMENTS.sha256`, and the wording rules below are enforced on everything under `compliance/`.

Rungs (ARCHITECTURE §4.1): R4 = machine-checked proof of a model, R3 = types/capabilities, R2 = differential or
two-sided oracle, R1 = executed test harness, R0 = argued only. A proof covers its model, not the Rust code, unless a
gate log says otherwise. Grades A–E are the research evidence grades carried over from the template.

**Wording rules (enforced):**
- AEGIS makes no FedRAMP readiness or authorization claim. Authorization belongs to the deploying CSP.
- No NIAP PP exists for web servers or gateways (`ops.niap-no-pp` C). If Common Criteria is demanded: PP_APP + TLS
  package, or an EUCC/CC EAL4+ ST. EAL6/7 is a separately funded decision (~3.5 years, millions).
- No regulator credits machine-checked code proofs (`sc.regulator-2025-26-statements` B). The formal policy model
  maps to SA-17(1); test legs stay mandatory.
- CRA: admission control is described as rate limiting and resource budgeting only (Annex III class II risk,
  `ops.cra-annex3-waf-risk` C).
- SSDF 1.2 controls are labelled "draft" (IPD 2025-12-17); SSDF 1.1 is final.
- FIPS approved mode is claimed only on Amazon Linux 2023 (AL2023) with the cmvp lock; never on household
  Debian/Ubuntu/musl builds, and never for the floor lock.
- Laptop performance numbers are provisional. No threshold in this map is a performance number (PLAN-6 D11).

**Trusted, not verified** (SECURITY_CLAIMS.md "Not proven"). Every claim in this map assumes these and none of them
is described as proven: **hyper**, **h2**, **tokio**, **rustls**, **the AWS-LC C code**, and **the Rust compiler
(rustc/LLVM)**, plus SQLite C, the kernel, libc and the hardware; Phase 7 adds the kernel io_uring subsystem and io-uring 0.7.15 (opt-in `uring` front only)
and libcrux (spike only, never shipped). The R4 rows below are proofs about Lean models of
AEGIS logic; they say nothing about these components.

## 1. Dated obligations

| date | obligation | AEGIS response | grade |
|---|---|---|---|
| 2026-01-01 | CISA bad practices: memory-safety roadmap or MSL (voluntary) | Rust; the roadmap row lists the C residue (AWS-LC, SQLite, kernel) | A |
| 2026-06-22 | EO 14412: federal HVA/high-impact PQ key establishment by 2030-12-31, signatures by 2031-12-31; CBOM guidance in 270 days; FAR rule ~2026-12; NSS excluded | P-UNIVERSAL / P-PUBLIC-WEB; CBOM derivable from the lock and the release SBOM | A |
| 2026-09-11 | CRA Art 14 manufacturer reporting via ENISA SRP: early warning 24 h, notification 72 h, final report 14 d after fix (vulnerabilities) / 1 month (incidents) | binding on a monetized distributor; drafts only today: `compliance/cra/PSIRT-runbook.md`, CSAF/VEX templates (D-P1: not published, no contact channel) | A (`v2.cra-monetization-trigger` B) |
| 2026-09-21 | FIPS 140-2 certificates historical | only 140-3 modules; AWS-LC FIPS 3.1.0 is 140-3 (CMVP #5314 static, cited by the cmvp build; #5298 dynamic) | B |
| 2027-01-01 | CNSA 2.0: new NSS acquisitions CNSA-capable | P-CNSA opt-in, floor build only (D17) | C (NSA FAQ 403) |
| **2027-12-11** | CRA full application; open-source steward reporting Art 24(3) | steward file set drafted in `compliance/cra/`; publication is an operator step (PREFLIGHT §P4 item 1, "not now" on 2026-11-04) and must happen by this date regardless | A |
| 2030 | CNSA 2.0 software signing exclusive; ASD ISM: ECDH/ECDSA/RSA and ML-KEM-768/ML-DSA-65 not approved beyond 2030; NIST IR 8547 draft deprecates 112-bit | ML-DSA-87 release signature (test keys only today, D-P2); P-UNIVERSAL (0x11ED) | C / A (`r4e10.asd-ism-2026-09`) / B |
| 2033 | CNSA 2.0 browsers/servers/cloud exclusive | P-CNSA on NSS (floor build) | C |
| 2035 | IR 8547 draft disallows quantum-vulnerable PK; NSM-10 goal | profiles | B |

## 2. PQ profiles × jurisdictions

| profile | groups | signatures (floor) | signatures (cmvp) | jurisdictions | status, with rung |
|---|---|---|---|---|---|
| P-PUBLIC-WEB | 0x11EC, 0x11ED, 0x11EB, X25519, P-256 | ECDSA-P256 (WebPKI) | ECDSA-P256 | general | shipping; selection R1 (`tls-verdicts`) + Lean Select R4 model with R2 correspondence (`select-drt`) |
| P-UNIVERSAL | 0x11ED only | ML-DSA-87 / ECDSA-P384 | ECDSA-P384 only (D15) | the only group in the intersection of US-civil, EU (BSI/ANSSI), UK, AU, CA, JP post-2030 lists | active (P6-tls-001). 0x11ED is AEGIS-owned (rustls #3293 closed unmerged). KATs R1 (`kx-kat`); interop [A] measured with OpenSSL 3.5.3 and Go 1.27.3, both directions + HRR (`kx-interop`, P6-tls-002); Kani on share parsing only (`kani-kx`). The FIPS-boundary check for 0x11ED on cmvp is open (PLAN-6 open question 2), so 0x11ED is not listed under the FIPS profile |
| P-BSI-ALT | 0x11ED, 0x11EB | ECDSA-P384 + ML-DSA-87 | ECDSA-P384 only (D15) | DE | active; as above |
| P-CNSA | ML-KEM-1024 (0x0202) | ML-DSA-87 | **refused at boot on cmvp** (D17: ML-DSA-87 is not in AWS-LC 3.1.0) | US NSS (opt-in) | active on the floor build only. Pure ML-KEM is non-conformant in FR (ANSSI-PG-083 v3.00) and hybrid-only in BSI TR-02102 |
| FIPS (cmvp lock) | SECP256R1MLKEM768, P-256, P-384 | — | ECDSA (ML-DSA is not approved in AWS-LC 3.1.0) | US federal | AL2023 operating environments only |

All government profiles: TLS 1.3 only, AES-GCM only; no 0-RTT, X25519, Ed25519, ChaCha20 or TLS 1.2. On the cmvp
build every government profile that is served uses ECDSA-P384 certificates; P-CNSA is refused there with the D15
reason (gate `clienthello-cmvp` judges the refusal).

## 3. FIPS 140-3 path

Two locks:
- **floor**: rustls 0.23.46 + aws-lc-rs 1.18.x (AWS-LC FIPS 4.2.0 source, uncertified). No FIPS claim of any kind.
- **cmvp**: rustls =0.23.43 + aws-lc-rs =1.15.3 + aws-lc-fips-sys =0.13.11 = AWS-LC FIPS 3.1.0 (CMVP #5298 dynamic /
  #5314 static), built in the digest-pinned AL2023 image (`deploy/build/al2023.Containerfile`).

FIPS approved mode is claimed only for the cmvp build running on AL2023, and only while the gates below are green.
ML-KEM is approved in the 3.1.0 module; ML-DSA and SLH-DSA are not approved in AWS-LC 3.1.0 (aws-lc-rs 1.15.3
compiles ML-DSA out under `fips`); X25519 is outside the boundary. No ML-DSA CMVP certificate exists anywhere. As a
consequence (D15), on cmvp the audit ML-DSA-87 cosignature is absent and reported (`cosign = none`), tier-X token
verification denies (fail closed), and P-CNSA is refused (D17).

What was measured (P6-cmvp-002, kamrui, 2026-11-04):
- `aegis --fips-check` on the cmvp build: `module="AWS-LC FIPS 3.1.0" fips_mode=true config_fips=true`, read at
  runtime through aegis-iso (2 audited sites, 16/20 used, D16 amended); floor: `module=none`. R1.
- `fips-binary`: contiguous `AWS-LC FIPS 3.1.0`, sole identity, one fips-sys node. PASS with an absolute `--binary`;
  the gate's relative path is red at F4 until the oracle resolves the path (P6-cmvp-002 open item 5).
- `cmvp-client-policy`: ERROR at R0 on the real tree (relink not byte-identical; P6-cmvp-002 open item 6). Until it is
  green, the "rustls client compiled out" premise of the RUSTSEC-2026-0349/0382 ledger entries has no current gate log.
- `clienthello-cmvp`: PASS, diff=0, with no cmvp-module half skipped. `fips-lock` + `ci/cmvp-supply.sh`: PASS.

Evidence emitted per run: gate log, `/healthz` fips_status, audit event, binary string `AWS-LC FIPS 3.1.0`. Reversal:
an AWS-LC 4/5 certificate matching a fips-sys version, or rustls 0.24.

## 4. Control map (NIST 800-53 r5 5.2.0 ↔ FedRAMP 20x KSI v2026.10.13.01 ↔ SSDF ↔ CRA Annex I)

Row schema: `{control, ksi[], ssdf[], cra[], mechanism, evidence_kinds[≥2], evidence_artifact, gate_id, residual,
grade, last_verified}`. `evidence_kinds` is `;`-separated. `gate_id` lists one or more gates of
`gates/phase-6.toml`; the first is the primary gate. A gate listed here proves only what its own log says.

| control | ksi | ssdf | cra | mechanism | evidence_kinds | evidence_artifact | gate_id | residual | grade | last_verified |
|---|---|---|---|---|---|---|---|---|---|---|
| SC-13 | SVC-SIN | — | I(2)(e) | cmvp lock + FIPS-string gate + `aegis --fips-check` | gate log; runtime status (`--fips-check`, `/healthz`); binary string | `gates/out/logs/phase6-fips-binary-cmd.log` | `fips-binary`, `fips-lock` | AL2023 only; advisory ledger; gate relative-path defect open; R1 | B | 2026-11-04 (P6-cmvp-002) |
| SC-8/8(1) | SVC-SIN, CNA-MAT | — | I(2)(e) | TLS 1.3-only listeners per profile (F12 frozen verdicts) | ClientHello verdict matrix; interop transcripts; Lean Select DRT | `tls/verdicts.toml` + gate logs | `tls-verdicts`, `clienthello-cmvp`, `kx-interop`, `select-drt` | public listener is classical for X25519-first or classical-only clients; rustls trusted, not verified | A | 2026-11-04 (P6-tls-002, P6-spec-003) |
| SC-12 | SVC-ASM | — | I(2)(e) | ACME issuance/renewal with an atomic certificate swap; STEK ≤24 h | gate log (CERT-1..4); cert-expiry gauge | `oracles/acme-pebble` log | `acme-cert`, `crs-tls` | STEK rotation and STEK upgrade handover (UP-5) have no dedicated gate (R0); operator-held roots | B | 2026-11-04 |
| SI-7/7(1)/7(15) | SVC-VRI | PS.2.1, PS.3.2 | I(2)(f) | triple-signed release (Ed25519 + SLH-DSA-SHA2-128s + ML-DSA-87), TUF 3/5 root, SLSA provenance, reproducible build | attestation; TUF metadata; repro hashes | release directory (layout v1) | `release-verify`, `release-rebuild`, `repro` | throwaway test keys only (D-P2); second-runner rebuild depends on P6-release-002; self-digest at start not gated (R0) | B | 2026-11-04 (P6-release-001) |
| CM-7 | CMT-RMV | PW.9 | I(2)(a)(c) | default-deny config; boot fails closed without config; systemd exposure ≤2 | boot exit-code log; systemd-analyze log; unrestricted ledger | gate logs | `fail-closed-boot`, `systemd-hardening`, `unrestricted-ledger` | operator "Unrestricted" overrides (CI-gated) | A | 2026-11-04 |
| CM-2 | CMT-RMV | — | — | config hash at boot, carried in every audit event | frozen config/event schemas (F8, F9); config property test log | `interfaces/MANIFEST.sha256` | `interfaces-frozen`, `config-totality` | hash-in-every-event is enforced by schema, not by a dedicated runtime oracle | B | 2026-11-04 |
| AU-2/3/12 | MLA-LET | — | I(2)(l) | audit event schema F9 | frozen schema hash; independent tlog verifier log | `interfaces/F9-audit-event.schema.json` | `interfaces-frozen`, `audit-tlog` | module-authored content | B | 2026-11-04 |
| AU-9(3)/AU-10/SI-7(7) | SVC-VRI | — | I(2)(f)(l) | tlog-tiles + signed checkpoints (+ ML-DSA-87 cosign on the floor build) | consistency proofs (Go x/mod tlog, independent code); signed checkpoints | `oracles/tlog-verify` log | `audit-tlog` | needs an external witness; no ML-DSA-87 cosign on cmvp (D15) | A | 2026-11-04 |
| SA-11 | — | PW.7, PW.8 | I(2)(a) | gate stack (Phase 6: every gate has a red self-test) | CI logs per gate; conformance report (F13) | `gates/out/logs/` | `tests`, `proof`, `conformance` | spec fidelity | A | 2026-11-04 |
| SA-15(13) | — | PO.6.2 (draft) | — | logging syntax spec | frozen schema; manifest hash | `interfaces/F9-audit-event.schema.json` | `interfaces-frozen` | — | B | 2026-11-04 |
| SA-17(1) | — | — | — | Lean policy, token, lowering and group-selection models (§4.1) + DRT/oracle correspondence | proof gate log; theorem table (§4.1); DRT log | `spec/STATEMENTS.sha256` | `proof`, `select-drt` | no regulator credits code proofs; R4 model only, R2 correspondence where a DRT exists | B | 2026-11-04 (P6-spec-003) |
| SC-5 | — | — | I(2)(h) | admission control as rate limiting and resource budgets (GCRA, RST bucket, I1–I11) | admission oracle log; Kani log on `aegis-budget`; transport limit log | gate logs | `admission-props`, `kani-tbi`, `budget`, `transport-limits` | Kani covers only the listed `aegis-budget` properties (SECURITY_CLAIMS.md); thresholds are not performance numbers | B | 2026-11-04 |
| SR-2/3/5 | SCR-MIT | PO.1, PS.3 | I(2)(a), Art 13(5) | G1–G10 supply chain (vet, deny, advisories, cooldown, lock targets) + CycloneDX SBOM | SBOM; vet store; advisory ledger | `supply-chain/`, release `sbom.cdx.json` | `vet`, `deny`, `audit`, `lock-age`, `lock-targets`, `fips-lock` | xz-class windows; cmvp lock has a frozen vet baseline (DEVIATIONS X-16) | B | 2026-11-04 |
| SI-2 / RA-5 | INR | RV.1–3 | Art 14 | PSIRT 24 h/72 h/14 d; CSAF/VEX per release (drafts, D-P1) | exception ledger with evidence logs; advisory feed (CSAF/VEX templates) | `supply-chain/exceptions.toml`, `compliance/cra/csaf/` | `exception-ledger`, `repo-advisories`, `compliance` | reporter reachability: no contact channel exists yet (D-P1); nothing published | C | 2026-11-04 |
| PS.4.3 anti-rollback | — | PS.4.3 (draft) | I(2)(c) | TUF monotonic version | client test (rollback mutant refused); TUF metadata | `ci/release/verify.py` self-test | `release-verify` | built to the draft | B | 2026-11-04 |

### 4.1 SA-17(1) theorem table

Each theorem is a frozen entry of `spec/STATEMENTS.sha256` (kind `theorem`), checked by the `proof` gate (axioms at
most the allowlist {propext, Classical.choice, Quot.sound} of `ci/axiom_audit.py`; no sorry; the Select theorems use
only {propext, Quot.sound}). Rung R4 means: proved about the Lean model. None of them is
a statement about the Rust code or about the trusted components listed above.

| theorem | model | rung | states | does NOT cover |
|---|---|---|---|---|
| `AegisIR.Combine.combine_empty` | policy combiner | R4 model | the empty decision list combines to deny | the Rust combiner (covered separately by an exhaustive Rust test, R1); policy authoring |
| `AegisIR.Combine.combine_failclosed` | policy combiner | R4 model | allow implies no input decision is an error | evaluation of the individual policies that produce the decisions |
| `AegisIR.Combine.combine_allow_iff` | policy combiner | R4 model | allow iff the list is non-empty and every decision is allow | the Rust code; how decisions are gathered at runtime |
| `AegisIR.Token.attenuate_narrows` | capability token | R4 model | a request accepted by an attenuated token satisfies the parent's caveats | HMAC EUF-CMA (assumed), constant-time compare (assumed), the Rust codec |
| `AegisIR.Token.attenuation_mono` | capability token | R4 model | adding a caveat never widens the accepted requests | key management and revocation |
| `AegisIR.Token.aud_bound` | capability token | R4 model | an accepted request on a well-minted token has the minted audience | clock correctness; the Rust verifier |
| `AegisIR.Token.expiry_effective` | capability token | R4 model | an accepted request is strictly before the effective expiry | the system clock (trusted) |
| `AegisIR.Token.depthOk_bound` | capability token | R4 model | an accepted chain is at most 3 + depth caveats long | performance of verification |
| `AegisIR.Token.verify_iff` | capability token | R4 model | verify holds iff MAC chain matches, caveats hold and depth is ok | that the MAC function `H` is a secure MAC (parameter, assumed) |
| `AegisIR.Token.enc_injective` | capability token | R4 model | the caveat codec is injective | the Rust encoder (round-trip is an assumption on the Rust side) |
| `AegisIR.lower_sound_full` | data lowering | R4 model | on an exact backend, a defined SQL result of the lowered predicate equals the reference evaluation | non-exact backends; real SQL engines (oracle `lowering-read`, R2, covers SQLite/PG/Redis at pinned versions) |
| `AegisIR.lowerQ_sound_full` | data lowering | R4 model | a row kept by the lowered tenant-scoped query is permitted by the reference | write paths (W1–W7 are R2 oracle only) |
| `AegisIR.ThreeValued.lower_exact3` | data lowering, 3-valued | R4 model | on an exact backend, lowering preserves three-valued (NULL-aware) evaluation exactly | engine collation/type-coercion quirks outside the modelled backend |
| `AegisIR.ThreeValued.rows_exact3` | data lowering, 3-valued | R4 model | the rows kept by the lowered query are exactly the rows the reference permits | adapters written by third parties; paths that bypass AEGIS |
| `AegisIR.ThreeValued.eval3_sound` | data lowering, 3-valued | R4 model | a defined three-valued result agrees with two-valued evaluation | the SQL text generator in Rust |
| `AegisIR.Vacuity.combine_nonvacuous` | vacuity checks | R4 model | the combiner hypotheses are satisfiable (allow and deny both reachable) | anything beyond non-vacuity |
| `AegisIR.Vacuity.token_nonvacuous` | vacuity checks | R4 model | a well-minted, accepted, depth-ok token exists | anything beyond non-vacuity |
| `AegisIR.Select.select_in_profile` | TLS group selection | R4 model + R2 correspondence (`select-drt`, 8 profiles × 1e5 cases, 0 divergence) | a selected (ServerHello or HRR) group is in the profile and offered by the client | version (70) and sigalg (49) admission steps (not modelled); rustls itself (trusted) |
| `AegisIR.Select.pq_required_no_classical` | TLS group selection | R4 model + R2 correspondence | a profile without classical groups never selects one; an all-classical offer gets alert 40 | the key exchange implementation (AWS-LC C, trusted); 0x11ED KATs are R1 |
| `AegisIR.Select.hrr_only_if_no_share` | TLS group selection | R4 model + R2 correspondence | HRR is sent only for a group with no client key share | HRR transcript handling in rustls |
| `AegisIR.Select.alert_iff_empty_intersection` | TLS group selection | R4 model + R2 correspondence | alert 40 iff the offer and the profile share no group | out-of-domain ClientHellos (the DRT generator is in-domain only) |
| `AegisIR.Select.universal_only_11ED` | TLS group selection | R4 model + R2 correspondence | P-UNIVERSAL selects only 0x11ED | the 0x11ED wire format (R1 KATs + [A] interop) and the FIPS-boundary question on cmvp |

Kani (bounded model checking of the real Rust code) is a separate evidence leg and not part of this table: `kani-kx` covers 0x11ED
share parsing only (`split_share`); `kani-tbi` covers the listed `aegis-budget` properties.

### 4.2 Phase-7 TCB lines

One row per Phase-7 feature, each off by default (IMPLEMENTATION_PLAN §3 Phase 7). The `gate_id` column here names
gates of `gates/phase-7.toml`, not phase-6. The rows are the same as SECURITY_CLAIMS.md "Phase 7: one TCB line per
feature"; `python3 -I ci/tcb-lines.py` (gate `tcb-lines`) checks both copies, their gate ids and their rungs.

| feature | new surface | gate_id | rung | residuals |
|---|---|---|---|---|
| `proxy-protocol` | crates: `aegis-wire` (new, L2, no dependencies, `no_std`, no allocation, `forbid(unsafe_code)`; `proxy::parse_v2`) plus the aegis-bin `proxy-protocol` wiring (`front.rs`: before TLS, trust on the TCP peer only); third-party crates: none; C: none; kernel: none new (the same TCP accept path) | `proxy-l4`, `kani-wire`, `fuzz`, `default-graph` | parser: R2 (242/242 spec and hostile vectors, 0 of 135,958 differential mutants diverge from the oracle's reference parser, fuzz 1e7 execs) plus Kani bounded checks on the real Rust code within the bounds in the residuals (21 harnesses); PROXY-1..3 end to end: R2 on the `proxy-l4` corpus (399 checks, 13/13 e2e mutants), one host | Kani coverage is bounded: the UNIX address family is not covered in a whole parse; TLV regions over 10 bytes are covered only by vectors, the differential run and fuzz; the 8 KiB duplicate-extension bitmap (BitSet) is linked to the checked generic code only by an exhaustive unit test, not by Kani. Accepted only from configured trusted CIDRs, never auto-detected. `proxy-l4` limits: admission is observed only through the audit `peer` field; IPv4-mapped peers against v4 CIDRs are not exercised; the header deadline is bounded (≤ 20 s), not pinned |
| `l4` | crates: `aegis-wire` `tls_peek::client_hello` (one record of at most 16 KiB) plus the aegis-bin `l4` SNI routing and splice (`front.rs`); third-party crates: none; C: none; kernel: none new | `proxy-l4`, `kani-wire`, `fuzz`, `default-graph` | peek parser: R2 (84/84 ClientHello vectors, 0 differential divergences, fuzz 1e7 execs) plus Kani bounded checks on the real Rust code; L4-1/L4-2 SNI routing end to end: R2 on the `proxy-l4` corpus, one host | Kani does not cover ClientHello ext blocks over 12 bytes or whole-peek runs with symbolic hello-field lengths (each stage is checked alone); the 8 KiB duplicate-extension bitmap only by an exhaustive unit test; the splice idle timeout after routing (`limits.idle_timeout_ms`) is implemented but has no oracle; after routing the bytes are passed through uninspected (no HTTP parse, no policy), so the upstream receives the raw TLS stream |
| `uring` | crates: `aegis-uring` (new, L4, one driver thread per listener; 1 of at most 6 audited unsafe sites, DEVIATIONS X-19) on third-party `io-uring` 0.7.15; C: none (its build.rs compiles nothing without `bindgen`); kernel: **the Linux io_uring subsystem** (io_uring_setup, io_uring_enter, io_uring_register), denied by `deploy/aegis-hardened.service` and re-admitted only by the opt-in drop-in `deploy/uring.conf` | `front-equiv`, `unsafe-sites`, `vet`, `systemd-hardening`, `default-graph` | aegis-uring: R1 (19 crate tests on the desktop, kernel 6.11, including the injected-EPERM fail-closed path); FRONT-1 epoll/uring equivalence: R2 on the `front-equiv` corpus (120 checks, 12/12 mutants, including the hardened unit denying io_uring without the drop-in), one host; aegis-bin exits 69 with no epoll fallback when io_uring is unavailable; performance advisory only | widens the kernel attack surface to io_uring (at least 8 HIGH io_uring CVEs in 2026; Docker's default seccomp and Google production deny it), hence feature `uring` plus `--front uring` plus the drop-in, off in every shipped profile; the io-uring 0.7.15 vet audit is an agent review and needs an operator countersign or a human audit before production use (PREFLIGHT P5); X-19 unsafe: one `SubmissionQueue::push` site whose soundness is a buffer-ownership argument, not a proof; TCP_NODELAY through `IORING_OP_URING_CMD` needs kernel 6.7 or later (otherwise Nagle stays on); the double 400 on a bad chunk line (aegis-transport) is reproduced by both fronts, not fixed; `front-equiv` is one corpus on one host |
| `mtc` | crates: `aegis-tls` `select.rs` (feature `mtc`, compiled out under `cmvp`), which reads `trust_anchors` from the `aegis-wire` peek because rustls 0.23 does not expose it, plus the aegis-bin `tls.rs` boot wiring of `tls.credentials` (exit 78 on a credential that does not load or match); third-party crates: none; C: none; kernel: none | `cred-select`, `kani-wire`, `tls-verdicts` | selection logic: R2 against the `cred-select` decision table (10,021 cases, 0 divergence, 21/21 mutants), re-run on the merged tree (P7-bin-001), driven through tls-subject; selector through aegis-bin: R1 (one smoke run: an x509 credential served through the selector, a mismatched key refused with exit 78) | selection only: the MTC credential is an operator-supplied opaque blob that AEGIS neither issues, parses nor checks, so there is no MTC validity, issuance or transparency claim; the `trust_anchors` codepoint 0xCA34 is BoringSSL's experimental value (draft-ietf-tls-trust-anchor-ids-07 says TBD; no IANA entry) and may change; standalone and landmark MTCs are not distinguished (DEVIATIONS X-17); no gate drives `trust_anchors` through aegis-bin (`cred-select` uses tls-subject); rustls (certificate resolver hook) is trusted, not verified |
| `adapter-mariadb` | crates: `aegis-adapter-mysql` (new, L4: own MySQL wire client, q4-005 renderer, live schema gate) plus `mariadb-subject` (test only); the feature implies `native`; third-party crates: none new (aws-lc-rs legacy SHA-1 for mysql_native_password); C: none new in process (the AWS-LC C code is already listed); kernel: none new; external: the MariaDB 11.8.9 server, trusted, out of process | `lowering-read-mariadb`, `lowering-write-mariadb`, `schema-gate-mariadb`, `default-graph` | renderer and live schema gate: R2 (two-sided oracle at ENGINE_PIN mariadb 11.8.9 on kamrui: read 400,532 cases leak=0, write 18,022 cases W1/W2/W4/W6/W7 all 0, schema gate 25 cases); wire client: R1 (22 unit and fake-server tests); aegis-bin serving: none, a mariadb backend boots fail closed | **not servable**: aegis-bin connects, version-gates, pins the session and runs the live schema gate, then refuses the boot (exit 78), because aegis-data-ir has no EngineFamily::Mariadb with a MySQL denylist and apps/notes has no allowlist.notes-mariadb.lock (Phase 8, spec-author work); the Rust client is not live-tested on the write forms (begin/commit/rollback/run, ODKU, NOT EXISTS, RETURNING): the oracles execute the subject's SQL with their own client; no pool, no NC3 check-in and no cancel (no KILL QUERY path); loopback only and no TLS, so caching_sha2_password and non-loopback servers are refused; no RLS (MariaDB has none): isolation rests on the rendered tenant conjunct, the upsert guard and the schema gate; the oracles are single-connection (the NOT EXISTS upsert can raise a duplicate-key error under a race, which fails closed); the version floor is compiled in from engine-pins.toml (DEVIATIONS X-18) |
| `adapter-crdb` | crates: `aegis-adapter-pg` feature `crdb` (`Dialect::Crdb`, `crdb.rs` version gate and SERIALIZABLE retry, build.rs floors from engine-pins) plus `crdb-subject` (test only); the feature implies `native`; third-party crates: none new; C: none new; kernel: none new; external: CockroachDB 25.4.19, trusted, out of process | `lowering-read-crdb`, `lowering-write-crdb`, `schema-gate-crdb`, `pg-version-floor`, `default-graph` | renderer and live schema gate: R2 (ENGINE_PIN crdb 25.4.19, single node, in memory: read 300,526 cases leak=0, write 14,422 cases all 0, schema gate 20 cases); SQLSTATE 40001 retry: R1 (unit-tested against injected errors); aegis-bin wiring: R1 (one live test on kamrui: boot through the crdb version and schema gates, pool C8 reset and NC3 recovery statements accepted) | the SERIALIZABLE 40001 retry is only unit-tested and is not used by aegis-bin: the SDK host drives the scope op by op, so 40001 surfaces as a conflict (fail closed, no whole-transaction retry); no live contention test exists; no RLS on CockroachDB (no defence-in-depth policy; `schema-gate-crdb` does not require FORCE RLS); the CancelRequest (discard) path is untested; CockroachDB reuses the PostgreSQL F4 denylist and the notes PG allowlist lock (integrator to confirm that reading); single node only |
| `aegis-otlp` | crates: `aegis-otlp` (new, L5, a separate binary and not a dependency of aegis-bin; a hand-rolled OTLP/HTTP JSON encoder over the aegis-egress HTTP/1.1 exchange and aegis-canon JSON); third-party crates: none new in the lock (34-crate graph; tokio `signal` adds signal-hook-registry, already locked); no opentelemetry, prost or tonic; C: the AWS-LC C code through aegis-tls for https only (already listed); kernel: none new | `otlp-export`, `no-otel-in-bin` | R2 end to end against the mapping-checking OTLP/HTTP JSON collector (53/53 checks, desktop) | out of process by the spike verdict (DEVIATIONS X-3); the https endpoint, retry/backoff and drop-oldest under backpressure are not oracle-covered (the bounded reader and drop-oldest have unit tests only); there is no retry: a failed POST is counted in `aegis_otlp_failed_exports` and its log records are dropped; aegis emits no JSON logs and no histograms today, so those mappings are judged on synthetic fixtures; the laptop run of the gate was not done (disk floor) |
| `libcrux-spike` | crates: `spikes/libcrux-provider` with its own Cargo.lock (libcrux-* 0.0.x primitives, libcrux-aes 0.0.10 in place of libcrux-aesgcm; 115 crates), never in Cargo.lock or the cmvp lock, not shipped; C: 0 C/asm files compiled, against 395 (274 C, 121 asm) for the same server on aws-lc-rs; kernel: none (getrandom OS RNG) | `libcrux-spike` | C-surface count: R1 (measured, with a c-fixture negative control); KATs: R1 (490 checks); interop: R2 (24/24 cells against OpenSSL 3.5.3 and Go 1.27.3, kx-swap mutant red) | a spike, not a shipped provider and not FIPS; "smaller C surface" is a measured count, not "verified TLS": the provider glue is our own unreviewed code and upstream states libcrux is not verified side-channel resistant (no dudect run); handshake server CPU is 2.5-3× aws-lc-rs on kamrui (provisional); RUSTSEC-2026-0173 (proc-macro-error2, unmaintained, reached only through cfg(hax) edges and not compiled for any shipped target) is accepted in the spike-local ledger until 2027-02-06; upstream hax/F\* claims for parts of libcrux are upstream's and were not re-checked by us |

Every Phase-7 feature is off by default. `default-graph` shows the default and native aegis-bin graphs unchanged
(79 and 83 packages, no Phase-7 crate or feature). The stripped binaries are not byte-identical: against e235b75 the
default build is +8,576 B and the native build +9,088 B, with the same crate set (`budget` PASS), because the default
build now reads F8 `admission`, parses `--front`, and refuses (exit 78) every Phase-7 member it was not built with.

### 4.3 Phase-7 deferred and blocked items

| item | status | evidence | gate_id | re-check |
|---|---|---|---|---|
| HTTP/3 | deferred, preconditions not met (2026-11-06) | (a) hyperium/h3 PRs #366, #377 and #378 are all open and unmerged; the latest h3 0.0.8 (2025-05-06) has none of the fixes. (b) quinn: 9 HIGH and 1 MEDIUM advisories in 2026-05-06..2026-11-06 after de-duplication by alias (PREFLIGHT P1 counted 10 HIGH before de-duplication); last HIGH GHSA-53rm-773f-4q8c on 2026-09-30. Source: the `ci/h3-precondition.py` live run of 2026-11-06 (`NOT MET`). `no-quic` keeps every QUIC/HTTP/3 crate out of both locks and every aegis-bin graph | `no-quic` | 2027-03-30 (end of the 6-month clock if no further HIGH lands), or sooner if the PRs merge and a release ships; re-run `ci/h3-precondition.py`. If built: quinn-proto ≥ 0.11.19, quinn-udp ≥ 0.5.16, and our own frame/QPACK limits in front of h3 |
| WebTransport | deferred, blocked on HTTP/3 (2026-11-06) | every Rust implementation (wtransport 0.7.2, web-transport-quinn 0.13.6) is HTTP/3 over quinn; there is no Rust WebTransport over HTTP/2; draft-ietf-webtrans-http3-17 and -http2-16 are in WG Last Call (2026-11-02), not RFCs | `no-quic` | with HTTP/3: 2027-03-30 |
| 64-core scaling run | blocked on GCP quota (CPUS_ALL_REGIONS = 12, 2026-11-06) | `bench/scaling/run --gcp c2d-standard-64` refuses: `CPUS_ALL_REGIONS limit 12 (free 12) < 64 vCPUs`; it never creates a VM. The desktop harness runs 1..18 cores (disjoint cpusets on 24 threads) and, with F8 admission.per_ip and limits.max_streams_per_conn lifted in the bench config, passes with 0 errors; the numbers are provisional and plateau at about 31-42k req/s from 2 cores up because aegis-bin builds tokio with worker_threads(2), so they measure that cap, not core scaling (bench/scaling/INFEASIBLE_REPORT.md resolution; an F8 worker knob is a Phase 8 item) | `scaling` | after the operator raises CPUS_ALL_REGIONS to at least 64 (and C2D to at least 64 in us-central1), PREFLIGHT §P4 item 1 |

## 5. CRA steward / manufacturer file set

All drafts, headed `Status: DRAFT, not published` (PREFLIGHT D-P1). Nothing is at the repository root: no root
SECURITY.md, no LICENSE, no GitHub private vulnerability reporting, no contact channel. Publishing is an operator
step (PREFLIGHT §P4 item 1; operator decision 2026-11-04: "not now"); the CRA publication date is 2027-12-11.

| file | content |
|---|---|
| `compliance/cra/SECURITY.draft.md` | CVD policy; contact `<operator to supply>` |
| `compliance/cra/PSIRT-runbook.md` | T0 = "aware" stamped as a tlog event; T+24 h early warning via SRP (manufacturer distributors); T+72 h notification; final report ≤14 d after the fix |
| `compliance/cra/csaf/advisory-template.json` | CSAF 2.0 security advisory template, `tracking.status = draft` |
| `compliance/cra/csaf/vex-template.json` | CSAF 2.0 VEX template, one per release |
| `compliance/cra/schemas/csaf_json_schema.json` | the official CSAF 2.0 JSON schema, vendored (provenance in `schemas/SOURCES.txt`) |
| `compliance/cra/sbom-statement.draft.md` | points to the release pipeline's CycloneDX output (`sbom.cdx.json`, attested) |
| `compliance/cra/support-period.draft.md` | support period statement (period left to the operator) |
| `compliance/cra/eu-declaration-of-conformity.draft.md` | EU DoC, self-assessment route |
| `compliance/cra/steward-attestation.draft.md` | steward attestation, applicable only if a legal-person steward exists |

## 6. Government buyer route (R-OPS-10) [C]

Memory-safe language + FIPS 140-3 module (cmvp, AL2023) + EAL4+ ST only if demanded + formal policy model
(SA-17(1), §4.1) + this map's evidence bundle per release. Procurement scoring of these properties is unverified
(q4-003). Government profiles on the cmvp build use ECDSA-P384; P-CNSA is a floor-build profile only.

## 7. Export control [E: not researched in the map]

Standard, published algorithms only (TLS 1.3, ML-KEM, ML-DSA, SLH-DSA, AES-GCM, SHA-2). Record before commercial
binary distribution: US EAR classification for publicly available open-source encryption (EAR §734.3(b)(3) /
§742.15(b)) and any mass-market treatment for commercial builds; EU dual-use Annex I Cat. 5 Part 2 notes. Not legal
advice; obtain counsel before export to embargoed destinations.

## 8. Licenses

AEGIS itself has no license yet (operator decision 2026-11-04; PREFLIGHT D-P3); the `compliance` gate fails if a root
LICENSE appears before that decision changes. Dependencies: cargo-deny 11-SPDX allowlist (`deny.toml`, from
`sc3.deny-golden-duplicates`); GPL tools (HTTP Garden) run as external containers, never linked; vendored EverParse
output keeps its license header. The vendored CSAF schema is an OASIS work product (see `schemas/SOURCES.txt`).
