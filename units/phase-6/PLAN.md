# Phase 6 plan: profiles, compliance, release (draft, spec author, 2026-11-04, base d32c5ef)

**Scope** (IMPLEMENTATION_PLAN §3 Phase 6):
- P-UNIVERSAL, P-BSI-ALT and P-CNSA profiles;
- floor and cmvp locks;
- the FIPS-string gate and the cmvp client-policy gate;
- COMPLIANCE_MAP and SA-17(1);
- the CRA steward file set;
- the release pipeline (attest in a separate job, independent rebuild on a second runner image, TUF 3/5, and a
  triple signature Ed25519 + SLH-DSA-SHA2-128s + ML-DSA-87);
- the conformance suite.

**Read with:** `units/phase-6/PREFLIGHT.md`, which holds decisions D-P1..D-P6 and the operator decision of
2026-11-04: no license, no CRA publication, no GitHub Actions, CI on kamrui, the GCP VM as needed.

**Gate file:** `gates/phase-6.toml`, with 68 carried gates and 13 new ones. **Units:** 15 JSON files in this
directory.

## Starting point (inventory 2026-11-04)

**Already in place:**
- **0x11ED key exchange.** `crates/aegis-tls/src/kx.rs` builds it on aws-lc-rs: P-384 first, then ML-KEM-1024.
  - ACVP and RFC 5903 KATs, plus negative-share and order-mutant tests, are in `kx.rs` tests and `kat/`.
  - Spike evidence of interop with OpenSSL 3.5.9 and Go 1.26.10 is in `spikes/q4-026/interop/`. There is no interop
    gate.
- **Profiles** (`profile.rs`):
  - P-UNIVERSAL, P-BSI-ALT, P-CNSA and FIPS-CMVP are `Pending`, and `server_config` refuses them.
  - FIPS-FLOOR and FIPS-PQ-REQUIRED are `CmvpPending`.
  - `f8_name` wrongly returns None for FIPS-PQ-REQUIRED. F8 has that value.
- **F12** (`tls/verdicts.toml`): 12 frozen verdicts (PUB-T1..T6, FIPS-F1..F6) plus SUP-1..5. The three government
  profiles have `status = "pending"` and no verdicts.
- **`cargo xtask fips-lock --profile cmvp`:** checks `profiles/cmvp/Cargo.lock` text against `profiles/cmvp/pins.toml`.
  That lockfile does not exist yet, so the check is red by design. It is in no gate file.
- **Known gaps:** BACKLOG G1–G8 list what fips-lock still lacks.
- **FIPS status reporting.** `FipsStatus` already flows to the audit log, `/healthz` and the `aegis_fips_status`
  metric. The module identity is hard-coded to `None`.
- **Client-policy check.** `spikes/cmvp-client-policy/fips_client_policy.py` has 12/12 self-tests on the floor
  profile. It is not wired to any gate.
- **Exception ledger.** `supply-chain/exceptions.toml` has no RUSTSEC-2026-0349 entry and no validator, even though
  its line 2 claims one exists.
- **Reproducibility.** `ci/repro.sh` checks same-host reproducibility only.
- **Release pipeline:** absent (no SBOM, provenance, TUF or signing).
- **Conformance:**
  - The F13 schema exists, with a single `signature`.
  - The C0–C4 levels are defined only in `research/ARCHITECTURE-DRAFT.md:918`: C0 static, C1 behavioural, C2
    adversarial host, C3 differential vs Lean, C4 traceability.
  - There is no `conformance/` directory.
- **Compliance:** only the template `research/templates/COMPLIANCE_MAP.md` exists.
- **Lean:** five modules. The group-selection model exists only as text (SPEC_INVARIANTS §F `Select(model)`).
- **Kani:** `ci/kani.sh` hard-codes aegis-budget.

## Gate → unit (each new gate is in exactly one unit's acceptance)

| plan gate | gate in phase-6.toml | where | unit |
|---|---|---|---|
| `fips_lock_gate --profile cmvp`: exactly one fips-sys node, reachable from aws-lc-rs (lock half, G1–G5, G7) | fips-lock | laptop (light) | P6-spec-002 |
| … `AWS-LC FIPS 3.1.0` present in the binary, linked module (G2b, G6) | fips-binary | kamrui | P6-cmvp-001 |
| cmvp client-policy gate (0349 premise) | cmvp-client-policy | kamrui | P6-oracle-fips-001 |
| exception ledger valid (no expired entry; the 0349 entry cites the passing client-policy log) | exception-ledger | laptop | P6-oracle-ledger-001 |
| per-profile ClientHello matrix, floor half (all profiles, new rows UNI/BSI/CNSA) | tls-verdicts (carried, F12 re-frozen) | desktop | P6-oracle-hrr-001 |
| per-profile ClientHello matrix, cmvp half (`--require-cmvp`: module identity, `config.fips()`) | clienthello-cmvp | kamrui | P6-cmvp-001 |
| Lean group-selection model checked | proof (carried) + select-drt | laptop | P6-spec-003 |
| 0x11ED KATs | kx-kat | desktop | P6-tls-001 |
| 0x11ED interop: OpenSSL 3.5+, Go, BoringSSL per D-P4 | kx-interop | kamrui | P6-oracle-interop-001 |
| Kani share-parsing harness | kani-kx | kamrui | P6-kani-001 |
| second-runner hash = attested digest | release-rebuild | kamrui + quiet | P6-release-002 |
| (added) triple signature, TUF 3/5, test-key refusal, rollback/freeze | release-verify | kamrui | P6-release-001 |
| conformance C0–C2 100% | conformance | laptop (reads `gates/out/logs`; signs through kamrui OpenSSL) | P6-conformance-001 |
| (added) COMPLIANCE_MAP rows cite real gates; SA-17(1) theorem table; CRA set complete, DRAFT, unpublished | compliance | laptop | P6-compliance-001 |

**Self-tests.** Every new gate has a self-test that goes red on a mutant. Each unit's `oracles` field lists its
mutants.

**Carried gates.** All 68 Phase-5 gates are carried. `tls-verdicts` now judges F12 as re-frozen by P6-spec-001, and
`proof` now includes `AegisIR.Select`. Neither gate's command changes.

## Roles

- **Spec-author units.** Oracles, specs, Lean, the release verifier and the compliance checker are spec-author units.
  Each oracle goes red before its implementer starts (§2).
- **Integrator unit.** P6-spec-002 pre-wires every third-party edge and every tool pin. Implementers never touch
  Cargo.toml, Cargo.lock, `profiles/cmvp/Cargo.lock`, `ci/tools.lock` or `supply-chain/`.
- **Single writer.** `crates/aegis-tls` has one writer: P6-tls-001, then P6-cmvp-001 (sequential, not parallel).

## Unit graph and waves (→ = depends on)

```
W0  start now:  P6-spec-001 (F12 rows, F13 triple signature, F1 §F addendum)
                P6-spec-002 (cmvp lock + overlay build, tool pins, ledger 0349 entry, fips-lock G1-G5/G7)
                P6-spec-003 (Lean AegisIR.Select + select-drt harness)
                P6-oracle-interop-001  P6-oracle-ledger-001  P6-kani-001(harness+ci/kani.sh generalisation)
W0b spec-001 → P6-oracle-hrr-001 (hrr-verdicts: 0x11ED offers, new rows, --require-cmvp)
    spec-001 → P6-oracle-release-001 (release verifier + mutants: TUF 3/5, triple sig, test-key refusal)
    spec-002 → P6-oracle-fips-001 (client-policy oracle ported from the spike + FIPS-string/link oracle)
W1  P6-tls-001     → spec-001, oracle-hrr, oracle-interop    (activate UNI/BSI/CNSA; kx-kat; cfg-gate KAT ctor; f8_name)
W2  P6-cmvp-001    → tls-001, spec-002, oracle-fips          (AL2023 image, cmvp build, FipsStatus module identity)
    P6-release-001 → spec-002, oracle-release                 (build/SBOM/attest/sign/TUF jobs on kamrui)
W3  P6-release-002 → release-001, cmvp-001                    (second runner on aegis-quiet; release-rebuild)
    P6-conformance-001 → spec-001, tls-001                    (conformance/ runner, F13 reports C0-C2)
W4  P6-compliance-001 → every gate id above exists            (COMPLIANCE_MAP, SA-17(1), CRA drafts)
GO  python3 -I ci/run-gates.py --phase 6
```

## Placement (operator 2026-11-04: CI on kamrui, the GCP VM as needed)

- **kamrui**, via `remote = "kamrui"`: every new gate that needs docker, OpenSSL 3.5, Go or the FIPS module:
  - fips-binary, clienthello-cmvp, cmvp-client-policy, kx-interop, kani-kx, release-verify;
  - build A of release-rebuild.
- **Its toolchain:** Go 1.27.3 at `~/aegis-ci/go1.27.3`, and the rustup toolchain at `~/aegis-ci/rustup` (1.99.1 is
  present).
- **Limits:** kamrui has 4 cores. `ci/remote.sh` caps it at 9 GB and 4 jobs.
- **aegis-quiet** (GCP c2-standard-8): build B of release-rebuild only.
  - The gate starts the VM (`gcloud compute instances start`), runs, and stops it in a `finally`, so the VM never
    keeps running after the gate.
  - On first use, docker is installed on the VM, which is not an operator box.
- **Desktop** (`remote = true`): carried gates stay where they passed, plus kx-kat (build-heavy, no docker).
- **Laptop:** light gates only (fips-lock, exception-ledger, conformance, compliance, select-drt via ci/heavy.sh) and the
  proof gate. exception-ledger and conformance read `gates/out/logs`, which `ci/remote.sh` does not sync, so they run
  on the laptop.

## Interfaces (frozen F-files)

All amendments are in P6-spec-001, with a re-freeze in the same commit:

- **F12** `tls/verdicts.toml`:
  - P-UNIVERSAL, P-BSI-ALT and P-CNSA go from pending to active.
  - New frozen verdicts:
    - **UNI-T1..T5:**
      - 0x11ED offered → ServerHello 0x11ED;
      - only 0x11EB/0x11EC offered, with 0x11ED in supported_groups but not in key_share → HRR 0x11ED;
      - X25519-only → alert 40;
      - P-384-only (classical) → alert 40;
      - sigalgs without mldsa87 or ecdsa_secp384r1_sha384 → alert 40.
    - **BSI-T1..T4:**
      - 0x11EB first by the client → ServerHello 0x11EB (client order);
      - 0x11ED-only → ServerHello 0x11ED;
      - X25519MLKEM768-only → alert 40;
      - classical → alert 40.
    - **CNSA-T1..T4:**
      - MLKEM1024 → ServerHello 0x0202;
      - 0x11ED-only → alert 40 (pure only);
      - mldsa87 absent → alert 40;
      - TLS 1.2 → alert 70 or 40, per the oracle's existing version rule.
  - The research probe set gets a new offer set that includes mldsa87.
  - `kx_groups_target` of P-PUBLIC-WEB: 0x11ED goes from pending to active.
- **F13** `interfaces/F13-conformance-report.schema.json`: `signature` becomes `signatures`, an array of exactly 3
  with algs {ed25519, slh-dsa-sha2-128s, ml-dsa-87}, unique.
  - Plus an optional `test_keys: boolean`.
  - The `v` stays 1. Nothing outside the repo has consumed F13 yet, which `ci/interfaces.py` confirms (no consumer).
- **F1** SPEC_INVARIANTS §F addendum:
  - `Select(model)` stated as the Lean `AegisIR.Select.select` (D3).
  - REL-1..REL-5 (release, D6):
    - REL-1: an artifact is accepted only with all three signatures valid over the same digest.
    - REL-2: TUF root threshold 3 of 5, a version that rises monotonically, and expiry checked.
    - REL-3: the attested digest equals the sha256 of both independent rebuilds.
    - REL-4: test-key metadata is refused unless `--allow-test-keys` is passed.
    - REL-5: the SBOM in the artifact is the attested SBOM.
  - Re-freeze with `ci/statements.py freeze spec`.
- **F8** unchanged. Its profile enum already has all eight names.

## Decisions

- **D1 cmvp lock = overlay build, not a second workspace.** A crate can belong to only one cargo workspace, so the
  cmvp configuration is built as an overlay:
  - `profiles/cmvp/overlay.toml` holds the `[workspace.dependencies]` replacements: rustls =0.23.43 and aws-lc-rs
    =1.15.3 with `fips`.
  - `profiles/cmvp/Cargo.lock` is committed.
  - `profiles/cmvp/build.sh` copies the tree into a scratch dir, applies the overlay, and runs `cargo build --locked`
    with that lock, inside the AL2023 image.
  - The integrator regenerates the lock (P6-spec-002), and lock-age and vet apply to it as to the root lock.
  - `profiles/floor` is the root lock, renamed only in reports. G5 checks its lineage.
  - **Risk:** the code uses APIs newer than rustls 0.23.43 or aws-lc-rs 1.15.3 (for example ML-DSA, which is
    `unstable` in 1.15.3, in aegis-audit). P6-spec-002 measures this first. Any gap is closed behind a `cmvp` cfg in
    the owning crate, never by dropping a profile. The fallback for the audit ML-DSA cosignature on cmvp is "absent,
    reported", because ML-DSA is not FIPS-approved in 3.1.0 anyway.
- **D2 FipsStatus is real.** `fips_status()` reads the linked module's version string at runtime
  (`awslc_version_string` through aws-lc-rs on cmvp) and reports `module = Some("AWS-LC FIPS 3.1.0")` only on the cmvp
  build with `fips()` true.
  - fips-binary greps the release binary for the contiguous string. It also runs `aegis --fips-check`, which must
    print the same module string, and the `/healthz` field `module`.
  - If the bytes are not contiguous, that is an INFEASIBLE report, not a split match (PREFLIGHT P2).
- **D3 Lean Select.**
  - `AegisIR/Select.lean` defines `select : Profile → ClientHello → Outcome`. Outcome is ServerHello g, HRR g, or
    Alert 40. It is modelled on rustls 0.23.46 client-order selection plus the AEGIS profile filter.
  - Theorems:
    - `select_in_profile`: a negotiated group is in profile.kx and in the client's supported_groups.
    - `pq_required_no_classical`: P-PQ1.
    - `hrr_only_if_no_share`.
    - `alert_iff_empty_intersection`.
    - `universal_only_11ED`.
  - No Mathlib. The paranoid checkers apply.
  - select-drt: the Lean executable `select` (compiled with `lake exe select-drt`) and the Rust oracle selection must
    agree on 1e5 generated ClientHellos per profile, with 0 divergence. The mutant swaps one profile's order and must
    diverge.
  - This is the "cheapest R5-class claim". Rung: R4 model plus R2 correspondence. It is not a proof about rustls
    code.
- **D4 interop matrix** (from D-P4):
  - Peers: OpenSSL 3.5.3 (kamrui host), Go 1.27.3 crypto/tls (a peer program in `oracles/kx-interop/go/`), and
    BoringSSL from a pinned commit at least 7 days old, built in the AL2023 image.
  - Both directions where the peer has the group.
  - Each cell checks the negotiated group, completed handshake and application data echo. For 0x11ED it also checks
    HRR.
  - Mutant: the aegis-tls `order-mutant` feature (ML-KEM first) must fail every 0x11ED cell.
- **D5 Kani.**
  - `ci/kani.sh` takes `--crate` and `--neg`, defaulting to the current aegis-budget values, so `kani-tbi` is
    unchanged.
  - The harnesses in `aegis-tls/src/kani_proofs.rs` (`#[cfg(kani)]`) cover `split_share` and both `start_and_complete`
    / `complete` parse paths on symbolic bytes of any length up to SERVER_SHARE_LEN+1. They prove no panic and that
    any wrong length is an error.
  - aws-lc calls are stubbed, as share parsing is pure Rust.
  - Negative control: a harness over a deliberately indexing copy must fail.
- **D6 release pipeline** (`ci/release/`, Python run with `-I` plus shell, on kamrui).
  - **Jobs.** Each job is its own process, with its own scratch dir and key directory:
    1. **build A:** AL2023 image, `cargo auditable build --release --locked`, both floor and cmvp.
    2. **sbom:** CycloneDX via cargo-cyclonedx.
    3. **attest:** a separate job with a different key, which reads only build A's output digest and SBOM and signs an
       in-toto SLSA v1 statement.
    4. **sign:** Ed25519, SLH-DSA-SHA2-128s and ML-DSA-87 over the same digest, with the OpenSSL 3.5.3 CLI.
    5. **tuf:** root, targets, snapshot and timestamp, with root 3/5 Ed25519 using python-tuf `tuf.api.metadata`.
  - **Keys** are fresh test keys per run (D-P2), and the metadata carries `test_keys: true`.
  - **Tools** are pinned in `ci/tools.lock` by P6-spec-002: cargo-auditable, cargo-cyclonedx, and python-tuf plus
    securesystemslib as a hash-locked venv on kamrui (`#py:` rows).
  - **Verifier** (`ci/release/verify.py`, P6-oracle-release-001) uses OpenSSL for the signatures and python-tuf
    ngclient for TUF.
  - **A second ML-DSA verifier** is aws-lc-rs, already in the tree (BACKLOG :69). It is used in conformance report
    verification.
- **D7 second runner** (from D-P5). Build B runs on aegis-quiet:
  - pull the base image by digest;
  - rebuild the image from `deploy/build/al2023.Containerfile`;
  - mount the same pinned rustup and Go, rsynced from kamrui with their sha256 checked;
  - build both profiles.

  release-rebuild passes only if sha256(A) = sha256(B) = the attested subject digest, for both profiles.
  - Mutants:
    - B built with a different `SOURCE_DATE_EPOCH` must mismatch;
    - an attestation naming another digest must fail.
  - The VM is started and stopped by the gate. Cost is the VM's per-minute price only while the gate runs.
- **D8 conformance** (`conformance/`):
  - **C0 static:** the feature set, the linker import set (no client in cmvp), config pin, fips-lock, and budget.
  - **C1 behavioural:** h2-conformance, tls-verdicts, transport-limits and proxy-e2e results.
  - **C2 adversarial host:** the hostile-module corpus, mcp-corpus and ssrf-corpus.

  The runner reads each gate's log from this run, by sha256, and writes an F13 report per subject.
  - Subjects:
    - golden aegis-bin, floor;
    - golden aegis-bin, cmvp;
    - the p2-subject module.
  - The report is triple-signed with test keys.
  - The gate requires C0–C2 `passed == total` for each golden subject.
  - Mutant: a fork subject built with `tls-client` on in cmvp must fail C0.
  - C3 and C4 are reported, not gated. That matches the plan's "C0–C2 100%".
- **D9 compliance** (`compliance/`):
  - `COMPLIANCE_MAP.md` is instantiated from the template. Every §4 row carries `gate_id`, and the checker requires
    each `gate_id` to exist in `gates/phase-6.toml`.
  - The SA-17(1) section lists the Lean theorems by name, and the checker requires them in `spec/STATEMENTS.sha256`.
  - `compliance/cra/` holds the full steward set as DRAFT (D-P1).
  - The checker fails on:
    - a missing or non-DRAFT file;
    - a CSAF/VEX or CycloneDX schema error;
    - a root `SECURITY.md` or `LICENSE` existing (operator: not yet);
    - any of the forbidden words in the template's wording rules ("FedRAMP-ready", "WAF").
- **D10 ledger.**
  - `cargo xtask ledger-check` fails on an expired entry, or on a missing approver, reason or expiry.
  - It also fails on an `advisory-accepted` entry whose `evidence` file, or the sha256 of its gate log, is not from
    the current run. The 0349 entry's evidence is `gates/out/logs/phase6-cmvp-client-policy-cmd.log` with PASS
    compiled-out.
  - Ordering: exception-ledger runs after cmvp-client-policy in phase-6.toml.
  - The six wasmtime/pulley cooldown entries expire on 2026-11-12. P6-spec-002 removes them once their versions pass
    lock-age (2026-11-05 follow-up). It never extends them.
- **D11 thresholds and claims.**
  - No threshold here is a performance number.
  - Claims:
    - FIPS approved mode only on AL2023 with cmvp. COMPLIANCE_MAP says so.
    - Interop is [A] measured.
    - Lean Select is R4.
    - Kani covers share parsing only.
    - hyper, h2, tokio, rustls, the AWS-LC C code and rustc stay trusted, not verified.

## Open questions

1. Can rustls 0.23.43 + aws-lc-rs 1.15.3 build the current aegis-tls and aegis-audit code? P6-spec-002 measures
   this before any other W1 work (D1 risk).
2. Is the 0x11ED FIPS-boundary check (ARCHITECTURE §R-PQC: both components inside 3.1.0) a documentation check of the
   security policy for #5298, or a runtime indicator check (AWS-LC's service indicator)? Plan: both. The service
   indicator is asserted in fips-binary when it is available in 1.15.3. If it is not, that is documented as a
   residual.
3. Does BoringSSL's pinned commit build without Go? The plan gives it the mounted Go 1.27.3 anyway.
4. Is aegis-quiet's 10 GB boot disk enough for docker plus two builds? P6-release-002 checks this and resizes the
   disk if needed. That is a cost item for the operator's GCP project, reported.
