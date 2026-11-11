# Phase 8 preflight (integrator, 2026-11-06, base 92e753c)

There is no Phase 8 in IMPLEMENTATION_PLAN §3. The operator directive (2026-11-06) is "you can do the deferred phase 7
set, and maybe phase 8 and any others we cant think of?". Phase 8 is defined here as **residuals and hardening**. It
closes the claims that Phases 6 and 7 left narrower than their gate names, plus the BACKLOG items that block a
production claim. It adds no new feature surface.

The 2026-11-04 constraints still bind: no license, no CRA publication, no GitHub Actions, CI on kamrui, the GCP VM as
needed.

## P0. GO condition

Phase 7 GO (gates/phase-7.verdict.json) must exist before the Phase 8 GO run. Phase 8 units may start once their
Phase-7 inputs are on main, because they touch no Phase-7 gate's subject except where noted.

## P1. External evidence (probed 2026-11-06)

| question | source | finding | decision |
|---|---|---|---|
| Which certificate is AWS-LC FIPS 3.1.0 (aws-lc-fips-sys 0.13.11, static by default on Linux)? | csrc.nist.gov certificates 5314 / 5298; `aws-lc/include/openssl/base.h` in the .crate | **#5314** AWS-LC 3 (static) 3.1.0, active, sunset 2031-06-04; #5298 is the dynamic module. Security Policy 140sp5314.pdf v1.2 (2026-05-20). | The cmvp build cites #5314. #5298 only applies if the build is made dynamic. D-P8.1. |
| Is 0x11ED inside the boundary? | 140sp5314.pdf Table 5, Table 9, §2.7, §2.11; SP 800-227 §4.6.2 (final 2025-09); RFC 10024 | **Components yes, composite not stated.** ML-KEM-1024 EncapDecap/KeyGen is approved (FIPS 203). KAS-ECC-SSC P-384 is approved (IG D.F). KDA HKDF (SP 800-56Cr1) is approved. The "KDF TLS" CVL covers only v1.0/1.1/1.2, so the TLS 1.3 key schedule has no CAVP row. The policy says nothing about hybrids or combiners. §2.7: key establishment is assembled by the application. SP 800-227 §4.6.2: an SP 800-56C KDM over (S1‖S2) is an approved combiner when at least one secret comes from an approved method, and RFC 10024 places ECDHE first for 0x11ED. | D-P8.1: Monban may claim **"0x11ED built only from #5314-approved components (P-384 ECDH, ML-KEM-1024, HKDF); combiner per SP 800-227 §4.6.2 via the module's HKDF"**. It may **not** claim "0x11ED is FIPS-approved key establishment", because the TLS 1.3 KDF has no CAVP row. |
| Can a release build check the service indicator? | aws-lc-rs 1.15.3 `src/fips.rs`, `src/lib.rs`; aws-lc-fips-sys bindings | `FipsServiceStatus` and the indicator macros are `pub(crate)` and only built with `debug_assertions`. The public items are `fips_mode()`, `try_fips_mode()` and jitter entropy. The raw `FIPS_service_indicator_before_call/after_call` symbols are bound in aws-lc-fips-sys. | D-P8.2: the indicator check runs in a cmvp *test subject* through monban-iso (feature cmvp), using its spare audited unsafe sites (16/20 used). It is never in monban-bin. |
| rustls trust_anchors support | github.com/rustls/rustls/pull/3376 | Closed unmerged 2026-10-30. rustls plans its own MTC work (issue #3079 open). No TrustAnchorResolver in 0.23.46. | DEVIATIONS X-17 (our own peek) stays. ARCHITECTURE R-PQC-4's "adopt TrustAnchorResolver when #3376 lands" has no trigger now, so record it in the claims. |
| Kani version and async | github.com/model-checking/kani releases | kani-0.68.0 (2026-09-16): trait-method stubbing, `loop_decreases`. Async support is still unstable (`async-lib`, #1393 open), and there is no tokio support. | Kani proofs stay on synchronous cores. The client-path harnesses target the synchronous kx/share code in monban-tls. |

## P2. Inventory of residuals (sources)

| # | residual | from | Phase 8 unit |
|---|---|---|---|
| R1 | 0x11ED FIPS-boundary check not done | Phase 6 report; PLAN-6 open question 2 | P8-fips-001, P8-cmvp-002 |
| R2 | Kani does not cover the client complete path | Phase 6 report | P8-kani-001 |
| R3 | conformance C3 (differential vs Lean) and C4 (traceability) are reported, not gated; no config-pin gate | PLAN-6 D8 | P8-conformance-001 |
| R4 | MariaDB boots fail closed in monban-bin (no EngineFamily::Mariadb denylist, no notes-mariadb lock) | P7-bin-001 | P8-spec-001, P8-mariadb-001 |
| R5 | tokio `worker_threads(2)` hard-coded; scaling plateaus at about 31–42k req/s from 2 cores | bench/scaling 2026-11-06 | P8-spec-001, P8-bin-001 |
| R6 | one bad chunk line yields two 400s | P7-oracle-uring-001 | P8-transport-001 |
| R7 | no gate drives the MTC selector through monban-bin; the L4 idle timeout after routing has no oracle | P7-bin-001 | P8-oracle-001, P8-bin-001 |
| R8 | crdb: 40001 retry only unit-tested, CancelRequest untested | P7-adapter-crdb-001 | P8-oracle-001, P8-bin-001 |
| R9 | OTLP: https, retry and backpressure not oracle-covered | P7-otlp-001 | P8-oracle-001, P8-otlp-001 |
| R10 | ML-DSA-87 checkpoint cosignature verified only by Rust tests | BACKLOG Audit | P8-audit-001 |
| R11 | `monban_ops::acme::Faults` is public production API | BACKLOG ACME | P8-hardening-001 |
| R12 | idempotency keys never expire | BACKLOG Phase 4 | P8-spec-001, P8-hardening-001 |
| R13 | F8 route `path` can hold values canon rejects (dead routes) | BACKLOG Config | P8-spec-001, P8-hardening-001 |
| R14 | PG adapter: no fuzz target for the message parser, no Unix-socket connect timeout, SASLprep refused | BACKLOG Phase 4 | P8-hardening-001 |
| R15 | no end-to-end egress TLS handshake test | BACKLOG TLS | P8-hardening-001 |
| R16 | pg/valkey/redis engine pins carry laptop-style image Ids, so kamrui refuses them | P7-oracle-adapters-001 | P8-spec-002 |
| R17 | no long soak: leaks of fds, RSS or tasks over hours are unmeasured | (new) | P8-soak-001 |

Not in Phase 8, with reasons:
- HTTP/3 and WebTransport: re-check on or after 2027-03-30.
- The 64-core run: needs the operator's quota step.
- The Kani LRU/BTreeMap obligations: these need a data-structure redesign (BACKLOG Kani). They are tracked, not scheduled.
- CANON-8 per-upstream folding, and Redis D18 native mode: feature work, not residuals.
- The io-uring audit countersign: an operator step.

## P3. Decisions

**D-P8.1 0x11ED claim text.**
- Add `compliance/fips-boundary.toml`. It holds the certificate (#5314), the sha256 of 140sp5314.pdf, and for each
  0x11ED component: the policy table/row, the algorithm and the approval state. For the combiner it records the
  SP 800-227 §4.6.2 argument and the RFC 10024 ordering. For the TLS 1.3 KDF it records "no CAVP row, NOT CLAIMED".
- The checker (`ci/fips-boundary.py`) refuses any claim text in SECURITY_CLAIMS or COMPLIANCE_MAP that says 0x11ED is
  "FIPS-approved", "FIPS validated" or "inside the boundary" without the component qualifier.
- The PDF itself is not vendored. Only its sha256 and the cited excerpts are kept.

**D-P8.2 indicator check.**
- A cmvp-only test subject drives one 0x11ED handshake and one each of ECDH P-384, ML-KEM-1024 encap/decap and HKDF
  through aws-lc-rs.
- The subject wraps each call in `FIPS_service_indicator_before_call/after_call`, via ≤ 2 new audited monban-iso sites
  (feature cmvp), and requires Approved for the component primitives.
- The handshake as a whole is reported, not required to be Approved: the TLS 1.3 KDF has no row.
- This is debug-free. The indicator symbols exist in the 3.1.0 module in release builds; only aws-lc-rs's wrappers are
  debug-gated.
- If the symbols are absent from the release module, write an INFEASIBLE_REPORT and keep the documentation check.

**D-P8.3 worker threads.** F8 `runtime.worker_threads`, absent = 2, so every timing gate is unchanged. The scaling
bench sets it to the core count. The scaling gate stays advisory.

**D-P8.4 soak.** A 2-hour soak on the quiet VM, at moderate steady load (h2load at 50% of the measured 4-core
throughput), with PROXY, the selector, a crdb route and OTLP all on. The gate passes when:
- RSS slope ≤ 1 MiB/h after a 15-minute warm-up;
- open fds and tasks are back to baseline ±5 after load stops;
- there are 0 errors;
- the audit log verifies.

A 24-hour variant is available as `--hours 24`, record only.

**D-P8.5 C3/C4 gating.**
- **C3:** every DRT gate (select-drt, token-drt, lowering-read/write, pdp-dst) must have run in this run with
  0 divergence.
- **C4:** every F1 statement id in spec/STATEMENTS.sha256 maps to ≥ 1 gate id (a `spec/TRACE.toml`), and every mapped
  gate has a passing log in this run.
- **Config-pin:** the conformance report pins the config hash of every subject it judges, and refuses a report whose
  subject booted with a different effective-config hash.
