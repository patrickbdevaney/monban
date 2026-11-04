# Phase 6 preflight (integrator, 2026-11-04, base 657524f)

These are the preconditions and operator-level choices settled before the Phase 6 plan is written. The operator
directive was "settle the preflights as needed for phase 6". Every probe below was run on 2026-11-04. Each line names
the host it ran on and what it showed.

## P0. GO condition (q4-003, q1-009, velocity): met

1. **Phase 5 passed.** `gates/phase-5.verdict.json` records 129/129 steps, chain c0613bd8ecce, and was committed in
   657524f.
2. **q4-003 justifies most of Phase 6 directly.** `spikes/q4-003/verdict.json` is a flip, and its decision_effect (3)
   says: "FIPS/jurisdiction profiles, 0x11ED, reproducible signed release are procurement-gating for
   US-federal/DoD/NSS/Canada/EU and are justified by demand". The Lean selection-model gate is justified on safety
   grounds only, not by procurement.
3. **q1-009 is a keep.** No reverse condition fires.
4. **Velocity.** Phase 5 went from plan (2026-10-31) to GO (2026-11-04), against a 150–300 h [E] estimate. This is
   wall-clock, not agent-hours.

## P1. Operator constraints that bind Phase 6

**D-P1 (CRA steward file set): drafted, not published.** The operator said "don't set up vulnerability reporting or a
license yet". The full set is in COMPLIANCE_MAP §5: SECURITY.md, PSIRT runbook, CSAF/VEX, SBOM, support period, EU DoC,
and steward attestation. Phase 6 writes all of it under `compliance/cra/`, with every file headed
`Status: DRAFT, not published`.

What Phase 6 does not do:
- It adds no SECURITY.md at the repo root. GitHub and Forgejo would treat a root SECURITY.md as a live policy.
- It sets up no contact channel and no published address.
- It does not enable GitHub private vulnerability reporting.
- It adds no LICENSE.

The steward gate checks that the set is complete and well-formed (CSAF 2.0 schema, CycloneDX schema, and a support
period present). Publishing is an operator step listed in §P4.

The CRA date is 2027-12-11, when the set must be published regardless. That date is recorded in COMPLIANCE_MAP and is
not a Phase 6 deadline.

**D-P2 (signing keys): throwaway test keys only.** The pipeline does create, check and refuse signatures:
- TUF root 3/5, plus the triple signature Ed25519 + SLH-DSA-SHA2-128s + ML-DSA-87.
- Every run generates fresh keys in a temporary directory and destroys them after the run.
- No key is ever committed or kept.
- Release metadata signed by test keys carries `"test_keys": true`. The verifier refuses such metadata unless
  `--allow-test-keys` is passed.

Real key custody is an operator step (§P4). This covers the 5 TUF root holders, the hardware and the ceremony. The
agent never generates or holds a production key. The gates prove the pipeline logic, not the key ceremony: a
2-of-5 signed root must fail, and a single missing or bad signature of the three must fail.

**D-P3:** no license, no Docker image over 500 MB, no apt or sudo on operator boxes. These rules are unchanged.

## P2. Toolchain and environment probes

| need | probe (host) | result | decision |
|---|---|---|---|
| Go, a hard dependency of the AWS-LC FIPS build | `command -v go` on laptop, desktop and kamrui | missing everywhere | **Installed go1.27.3** to `kamrui:~/aegis-ci/go1.27.3`. Released 2026-10-19, so it is past the 7-day age rule. sha256 `65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40` was verified. Go is not installed on the laptop. |
| aws-lc-fips-sys =0.13.11 is AWS-LC FIPS 3.1.0 | .crate from static.crates.io (7.8 MB) | `AWSLC_VERSION_NUMBER_STRING "3.1.0"`, `AWSLC_MODE_STRING "AWS-LC FIPS "`; the upstream test asserts `"AWS-LC FIPS 3.1.0"`; `crypto/fipsmodule/ml_kem` is present; 0x11EB and 0x11EC are defined, 0x11ED is not | The FIPS-string gate greps the release binary for `AWS-LC FIPS 3.1.0`. If the bytes are not contiguous, that is an INFEASIBLE finding: the gate may not be weakened to match the two parts separately. |
| cmvp aws-lc-rs =1.15.3 can build 0x11ED | .crate source | `kem::ML_KEM_1024` (stable `pub mod kem`) and `agreement::ECDH_P384` are both present | P-UNIVERSAL on cmvp composes both from inside the 3.1.0 module. The FIPS-boundary claim for 0x11ED still needs the boundary check required by ARCHITECTURE §R-PQC. |
| AL2023 operational environment (the only tested OE) | kamrui docker, `amazonlinux@sha256:bb1c85fe…e3d3` | base is 55 MB. With gcc 11.5, g++, cmake 3.22, perl 5.32 and make, using tsflags=nodocs and no locale/man/doc, the rootfs is **450 MB**. With docs it is 528 MB. | The build image is `deploy/build/al2023.Containerfile`, built in a single RUN layer and asserted below 500 MB. Go and Rust are mounted read-only from `~/aegis-ci`, not baked in. The dnf `releasever` is pinned. |
| OpenSSL 3.5+ peer | kamrui `openssl version` | **3.5.3**. Groups include SecP384r1MLKEM1024, SecP256r1MLKEM768, X25519MLKEM768 and MLKEM1024. An `s_server`/`s_client` loopback negotiated **SecP384r1MLKEM1024**. ML-DSA-87 (4627 B), SLH-DSA-SHA2-128s (7856 B) and Ed25519 signatures all worked. | The interop peer and the triple-signature reference signer/verifier run on kamrui. The laptop has 3.0.15 and the desktop 3.3.1, so neither works as a peer. |
| BoringSSL peer for 0x11ED | `google/boringssl` main, `ssl/ssl_key_share.cc` and `include/openssl/ssl.h` | **BoringSSL does not implement 0x11ED or 0x11EB.** Its only PQ groups are `SSL_GROUP_X25519_MLKEM768 0x11ec` and `SSL_GROUP_MLKEM1024 0x0202`. | See D-P4. |
| a second independent 0x11ED implementation | `golang/go` master `crypto/tls/common.go` | `SecP384r1MLKEM1024 CurveID = 4589` (0x11ED). It has been in the default list since Go 1.26. | Go crypto/tls (go1.27.3) is the second 0x11ED peer. |
| Lean for the group-selection model | laptop `~/.elan/toolchains` | leanprover/lean4 v4.35.0, the version `ci/gate.sh` pins | The model is a new module under `spec/AegisIR/`, checked by the existing proof gate (paranoid checkers, no Mathlib). No new toolchain is needed. |
| Kani for share parsing | kamrui (ci/kani.sh) | already in use since Phase 3 | No change. |
| second runner for the independent rebuild | GitHub: `gh api …/actions/permissions` | Actions is **disabled** and the repo is **private**. GitHub artifact attestations need a public repo or Enterprise Cloud. | See D-P5. |
| laptop disk | `df -h /` | 17 GB free; the floor is 10 GB | Unchanged. Clear AEGIS's own target dirs before full runs. |

## P3. Decisions

**D-P4: BoringSSL interop is limited to the groups BoringSSL actually has. Go crypto/tls is added as the second 0x11ED
peer.** The plan text "0x11ED KATs + interop (OpenSSL 3.5+, BoringSSL)" cannot be met for 0x11ED, because BoringSSL
has no implementation of it. This is a strengthening, not a weakening. Every peer named in the plan stays in the gate:

- **0x11ED** (P-UNIVERSAL, P-BSI-ALT): interop with OpenSSL 3.5.3 **and** Go 1.27.3 crypto/tls. Both directions,
  HelloRetryRequest included.
- **0x11EB** (P-BSI-ALT, cmvp): OpenSSL 3.5.3 and Go.
- **0x0202 ML-KEM-1024** (P-CNSA): OpenSSL 3.5.3, BoringSSL, and Go.
- **0x11EC** (floor public listener): BoringSSL as a regression check.

BoringSSL is built from a commit at least 7 days old, inside the AL2023 image on kamrui (cmake plus g++; Go only for
its tests).

If BoringSSL adds 0x11ED, it joins the 0x11ED row. **This needs operator confirmation, because it changes the text of
a plan gate.** Until then the plan is written this way and the change is flagged in the Phase 6 report.

**D-P5: the second runner is an independently provisioned machine running the same pinned recipe, not GitHub.**
- Build A runs on kamrui (docker, AL2023 image).
- Build B runs on the dedicated GCP VM aegis-quiet, currently stopped. It installs docker on that VM, which is not an
  operator box, pulls the base image by digest, rebuilds the image from the Containerfile, and rebuilds the binary.
- The gate: sha256(B) = sha256(A) = the digest in the attestation.
- **Attestation runs as a separate job:** a different process and key that only reads A's output and signs an in-toto
  SLSA v1 provenance statement, using a test key (D-P2).
- Turning on GitHub Actions for a private repo spends the operator's minutes and gives no attestations. That stays an
  operator option (§P4) and is not assumed.
- Cost: the VM runs only during release-gate runs.

**D-P6: where Phase 6 heavy work runs.**
- **kamrui:** FIPS (cmvp) builds, OpenSSL/Go/BoringSSL interop, Kani, and the triple-signature reference.
- **desktop:** floor builds and the ClientHello matrix via ci/remote.sh, which needs no docker.
- **laptop:** light gates and the proof gate only.

## P4. Operator steps that are outside agent scope (listed, not done)

1. **Publish the CRA set.** This means a SECURITY.md contact, CVD policy, a support-period commitment, and the EU DoC
   signature. Required by 2027-12-11.
2. **Choose a license.**
3. **Real release keys:** the 5 TUF root holders and hardware, the ceremony, and production Ed25519, SLH-DSA and
   ML-DSA keys.
4. **Optional:** enable GitHub Actions, or make the repo public, if GitHub-hosted rebuilds and attestations are wanted.
5. **Confirm D-P4,** the change to the BoringSSL gate text.
6. **Decide whether to keep or delete the stopped aegis-quiet VM.** D-P5 uses it.
