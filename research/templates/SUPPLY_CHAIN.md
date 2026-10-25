# SUPPLY_CHAIN (template, v4, 2026-10-25)

Source: ARCHITECTURE.md v4 §3.14 and the process synthesis; R-SUP-1..6, R-PQC-2/5, R-DX-2. Gate G1–G10 have each executed in research; **never end to end** (`sc3.l5-ci-gate-list` A 0.75) — Phase 0 closes that.

## A. Dependency policy

- **Lean budget as CI gate** [A]: ≤6 MB stripped, ≤60 crates, non-crypto unsafe ≤5,000 lines, idle RSS ≤8 MB, 1k TLS ≤25 MB; per-feature deltas; growth without an approved bump fails.
- **Pins** [A]: caret + security floors in `Cargo.toml`; lock targets enforced by `xtask lock-targets`; `=` only in the cmvp profile. Floors: rustls ≥0.23.46, rustls-webpki ≥0.103.16, tokio ≥1.54.1 (x.y.0 blocked 14 days), hyper ≥1.12.0, h2 ≥0.4.20, wasmtime ≥49.0.4 (or 36.0.19), cedar ≥4.14.0, rmcp ≥3.7.0.
- **Lockfile discipline** [A]: `--locked` everywhere; updates only by bot PR; after any lock change `cargo audit --deny warnings` with advisory-db <24 h old; gates read `cargo metadata`, never grep or `cargo tree -i` (errors when two versions coexist, `r4tri.fips-sys-decoy-lock`).
- **Cooldown with audited bypass (G2)** [A executed / B policy]: 7-day window (7 days lands vulnerable webpki 0.103.15; 14 days lands 6 advisories incl. the rustls 0.23.45 PQ downgrade, `sc3.cooldown-executed-cargo-198`, `v4.cooldown-holds-vulnerable-webpki`). A cooldown-resolved lock intersecting an advisory with a published fix must take the fix through the bypass: label `security-advisory`, `CARGO_RESOLVER_INCOMPATIBLE_PUBLISH_AGE=allow cargo update -p <c> --precise <fixed>`, vet delta audit, second approver, 30-day expiry. **Toolchain note:** native `global-min-publish-age` is stable only from Rust 1.100 (cargo#17335); the golden pins 1.99.1, so enforce with `xtask lock-age --min 7d --allow-label security-advisory` + Dependabot `cooldown` until the bump. Limit: xz's window was 34 days; only tarball parity stops that class (`sc3.xz-window-cooldown-limit` A).
- **G1 lock intake** [A executed]: cargo-deny 0.20.2 (`yanked=deny`, `unmaintained=all`, `wildcards=deny`, `multiple-versions=deny` with skip = the 6 measured duplicates, 11-SPDX allowlist, crates.io only); cargo-audit 0.22.2 `--deny warnings`; cargo-vet 0.10.3 with six import sets from **zero exemptions** (`cargo vet init` auto-exempts: strip before any coverage claim; baseline 183/233 unaudited, 116/165 linux tree, 3.66M lines); exemptions only decrease; never `vet trust` build.rs/proc-macro publishers (arrayref typosquat build.rs, RUSTSEC-2026-0260); cargo-geiger 0.14.0 ceilings (hyper 123, h2 3, rustls/webpki/cedar 0).
- **First-party**: `#![forbid(unsafe_code)]` (except aegis-iso, ≤20 audited sites); deny `unwrap_used`, `expect_used`, `indexing_slicing` in ingest crates; bans per REPO_LAYOUT §5.
- **G5 new-crate intake for agent-added deps** [B; thresholds C]: pass only if vet-audited, or age ≥90 d ∧ recent downloads ≥100k ∧ owners unchanged 90 d; edit distance ≤2 to top-1000 fails unless allowlisted; build.rs/proc-macro <365 d fails; `cargo add` only via wrapper; agent sandbox has no crates.io token. Measured Rust hallucination rate 0.7–3%.
- **G10 repo-GHSA poll** [A 0.88]: 7 of 133 repo GHSAs across 15 golden repos invisible to OSV/RustSec/cargo-audit/cargo-deny/osv-scanner (cedar GHSA-m84h, quinn GHSA-53rm/wppq/6pp4, rmcp GHSA-4432). `xtask repo-advisories --lock Cargo.lock` on every PR and daily; retire after OSV ingests repo GHSAs within 7 d for 3 consecutive months.
- **Exception ledger** [A/B] (`supply-chain/exceptions.toml`): the only way "audit clean" and "frozen certified source" both hold. Each entry: advisory, crate@version, profile, reachability argument, owner, expiry tied to the next certificate. cmvp carries RUSTSEC-2026-0042/0043, 0349, 0285/0346/0348, webpki 0382. **0349 is client-side**: its entry is valid only if the cmvp client-policy gate passes (no reachable rustls client, or every client `kx_groups=[SECP256R1MLKEM768]` with no key-share-prediction store). The backported rustls PreferServerOrder patch (28ee6c68) is also ledgered.

```toml
[[exception]]
advisory     = "RUSTSEC-2026-0349"
crate        = "rustls@0.23.43"
profile      = "cmvp"
reachability = "client-side key-share prediction; cmvp gate fips_client_policy=PASS (mode: compiled-out | pq-only)"
owner        = "<handle>"
expires      = "on AWS-LC 4|5 CMVP cert or 2027-04-25, whichever first"
```

## B. Reproducible and bootstrapped builds

- **G3 double build** [A 0.78]: `rust-toolchain.toml` 1.99.1; `RUSTFLAGS="--remap-path-prefix=$PWD=/src --remap-path-prefix=$CARGO_HOME/registry/src=/cargo/registry --remap-path-prefix=$RUSTUP_HOME=/rustup"`; `cargo fetch --locked`; release `lto=true`, `codegen-units=1`, `panic=abort`; two dirs with different `CARGO_HOME` and `SOURCE_DATE_EPOCH`; pass = equal sha256 (identical at debug=0/2 on 1.98.0 and 1.99.1; 1.93.1 differs). Toolchain digest + `cargo auditable` mode are part of the attested build identity. Negative control: without registry remap, builds differ. Open: cross-host (q1-052); cargo trim-paths will replace the flags.
- **G4 tarball-vs-git parity** [A]: 13/15 sampled crates byte-identical; aws-lc-sys (1,964 vendored files) and ring (107 pregenerated asm) need submodule/regeneration checks (q3-025). The xz-catching gate.
- **Trusted-publishing ancestry** [A]: 30/233 golden versions trusted-published; sha = packaged commit for 24/30 → check git ancestry; falling back from trusted publishing to token publishing is a hard fail. Core pins (hyper, h2, rustls, tokio, aws-lc, ring, webpki) are token-published: residual.
- **Build substrate** [B / D]: pinned container + cargo + remap flags (35 s/build). Nix not adopted (no evidence advantage; Nix/Lix local root privesc 2026-10-13); Bazel too heavy solo. StageX stretch trial (`stagex/pallet-rust`, compare sha256).
- **Compiler trust** [B]: rustup component sha256 vs vendored manifest (day 1); `bootstrap-verify` stretch gate (mrustc → … chain, 16 steps; no Wheeler DDC report for rustc exists); Ferrocene 26.02.0 for safety regimes.

## C. Release chain

- **SLSA Build L3 + Source L2 + independent rebuild** [B]: build job has no `id-token`; separate `attest.yml` with `{id-token: write, attestations: write, contents: read}` runs `actions/attest@v4`; a second runner image rebuilds and must match the attested digest; protected `release` environment with required reviewer. Verify: `gh attestation verify ./aegis -R <org>/<repo> --signer-workflow <org>/<repo>/.github/workflows/attest.yml`. SLSA alone stopped 2/12 incidents (ordering only).
- **G6 workflow lint (first, non-dismissable)** [B]: `zizmor --pedantic`; 40-hex SHA pins on every `uses:`; top-level `permissions: {}`; no `pull_request_target` with PR-head checkout; no `github.event.*` in `run:`; no shared caches between untrusted and release workflows; CODEOWNER-approved suppressions; alerts on direct workflow pushes. 5/12 incidents 2024–26 were CI compromises, 3 via `pull_request_target`.
- **TUF** [B]: tuftool ≥0.15 authoring; tough =0.24.0 client (vet-audited; CVE-2026-6966/6967 duplicate-signature threshold bypass); root 3-of-5 offline, targets 2-of-3, snapshot/timestamp online; rollback rejected (signed monotonic version, SSDF 1.2 IPD PS.4.3); client negative test replaying GHSA-8m7c must reject. TUF stopped 0/12 incidents at intake (it protects distribution).
- **Release signatures (one rule everywhere)** [B decision / C jurisdiction fit]: three detached signatures, AND-verified per profile: **Ed25519** (ecosystem tooling; never sole), **SLH-DSA-SHA2-128s** (stateless hash-only hedge), **ML-DSA-87** (CNSA/ASD; SLH-DSA absent from both lists). Gov profiles drop Ed25519 from the required set. LMS/XMSS only with HSM-enforced state (RFC 10033).
- **Transparency** [B]: Sigstore keyless + Rekor v2 (needs RFC 3161 TSA); **cosign ≥3.1.0** (DSSE → Rekor v2; v3.1.4 current). PQ signatures carry long-lived authenticity; Sigstore is discoverability/audit.
- **Deploy artifact** [B]: OCI + cosign, pulled by digest; bare static binary + signed manifest for household; `.cwasm` only if compiled or MAC'd locally.
- **SBOM** [A]: `cargo auditable build --release --locked` (<4 kB embedded; trivy/grype/osv-scanner/syft read it); release check `cargo audit bin target/release/aegis --deny warnings` (or ledger); CycloneDX via cargo-cyclonedx 0.5.9, attested; feeds CRA steward file set and EO 14412 CBOM.

Release manifest:
```json
{"version":"1.0.0","monotonic":17,"artifact_sha256":"<…>","toolchain":"1.99.1@sha256:<…>",
 "auditable":true,"lock_profile":"floor|cmvp","lock_sha256":"<…>","fips_module":"AWS-LC FIPS 3.1.0|none",
 "proof_gate":{"lean":"v4.35.0@eb6cafb","theorems":45,"log_sha256":"<…>"},
 "slsa_provenance":"<attestation url>","sbom":"cyclonedx.json@sha256:<…>",
 "sigs":{"ed25519":"…","slh-dsa-sha2-128s":"…","ml-dsa-87":"…"}}
```

## D. CI gate stack (cheapest first; every gate has a negative-control PR that must fail; heavy stages 6 GB cap, 1 job/runner)

Tiers: PR (blocking), N nightly, R release, W weekly/cron.

| # | stage | tool | tier | pass criterion |
|---|---|---|---|---|
| 0 | workflow lint (G6) | zizmor --pedantic, SHA-pin check | PR | 0 findings |
| 1 | hygiene | rustfmt, clippy -D warnings, forbid(unsafe), disallowed-methods in sim crates | PR | 0 warnings |
| 2 | lock intake (G1) | deny, audit, vet, cargo-shear | PR | deny 0; audit 0 except ledger; vet 0 new unaudited, exemptions monotone down |
| 3 | cooldown + bypass (G2) | xtask lock-age (native after 1.100) | PR | no entry <7 d without label; no lock ∩ fixed advisory |
| 4 | repo GHSA (G10) | xtask repo-advisories | PR + daily | 0 matches or expiring ignore |
| 5 | new-crate intake (G5) | wrapper + crates.io API | PR | §A thresholds |
| 6 | unsafe ceilings (G7) | cargo-geiger 0.14.0 | PR | no growth |
| 7 | lean budget | xtask budget | PR | R-PERF-1 limits |
| 8 | FIPS lock + client policy | `fips_lock_gate.py --profile floor\|cmvp`; `fips_client_policy` | PR | one aws-lc-fips-sys node reachable from aws-lc-rs; cmvp =1.15.3 (window 1.15.2–1.17.1); binary contains `AWS-LC FIPS 3.1.0`; no reachable rustls client or all clients PQ-only |
| 9 | unit/feature | nextest 0.9.149, cargo-hack powerset | PR | green |
| 10 | property | proptest 1.12.0 | PR/N | 256/PR, 100k nightly |
| 11 | compile-fail SDK | trybuild 1.0.122 | PR | expected .stderr; 18.8 s cold |
| 12 | proof gate | ci/gate.sh + axiom_audit.py | PR / R paranoid | VERIFICATION_PLAN §3 |
| 13 | Kani | main ≥ #4910 | N | exit ∈ {0,10}; serial; 6 GB; OOM/timeout FAIL |
| 14 | DST | turmoil 0.7.2, deterministic CryptoProvider | PR ≥200 seeds × 60 sim-s; N ≥20k | trace hash equal; 0 getrandom/clock syscalls after init; 0 violations |
| 15 | oracle mutation | per-invariant bug patches | N | each invariant falsified within 1,000 seeds |
| 16 | fuzz | cargo-fuzz 0.13.2, CIFuzz, LibAFL 0.16.1 | PR 10 s/target + 150 s; N 1 h; W 12 h | 0 crashes/timeouts; coverage non-decreasing |
| 17 | config totality | Kani + fuzz | N | 1e7, 0 panics; 3× oversize serves LKG |
| 18 | differential | HTTP Garden (external GPL container); CANON-DIFF | N (G2 on PR) | 0 unclassified disagreements |
| 19 | data-plane oracles | read (two-sided), write | N + engine bump | leak=0 ∧ miss=0; W1/W2/W4 |
| 20 | agent corpus | 43 cases, both eras | PR | 100%; 0 handlers on rejects |
| 21 | TLS verdicts | `tls/verdicts.toml` (PUB-T1..T6, FIPS-F1..F6) + ClientHello matrix | PR on rustls/aws-lc bump | identical |
| 22 | memory model | Miri (seeds 0..16), ASan N, TSan W, loom/shuttle | N | 0 UB |
| 23 | mutation | cargo-mutants 27.1.0 `--in-diff` / full | PR/N | fail on exit {2,3}; ratchet |
| 24 | isolation faults | FI harness | N | per-class hard counts |
| 25 | upgrade | harness | N (3 green before release) | 0 refused/RST; naive REUSEPORT control fails |
| 26 | cert + outage | faketime +400 d; slow-upstream DST 10× | N | alarm + swap; unrelated p99 unchanged |
| 27 | systemd / pod | systemd-analyze --threshold=2; pod-restricted lint | PR | ≤2 (measured 1.4); CapEff NET_BIND_SERVICE only |
| 28 | conformance | BoGo, Wycheproof, duvet, C0–C4 | R | C0–C2 100% |
| 29 | AI red team | staging, canary sink, pinned model | N/W | **advisory**: 0 canary triggers recorded; ASR baselines set by first run |
| 30 | release | double build, parity, attest + rebuild, auditable, SBOM, TUF, triple signature | R | all equal/verified |
| 31 | watch | advisory-db, repo GHSAs, CMVP, rustls/aws-lc, Lean advisories | daily | re-check proofs ≤7 d after checker advisory |
| M | metrics | admin endpoint, golden counters, no feature flag | PR | 0 missing counters |

Ordering rule [C]: time/novelty gates (0, 2, 3, 5) before provenance gates (30); in the self-scored back-test vet + new-name + cooldown stopped 10/12 incidents, adding SHA pins, repro and parity covers 12/12 (`sc3.incident-gate-matrix` C, ordering only).

## E. Key management

| key | algorithm | storage | rotation | failure rule |
|---|---|---|---|---|
| STEK | AEAD per ticketer scope, scope in AAD | memory; handover by pipe | ≤24 h, 2-key window | refuse zero key; corrupt handover → fresh ring; no resumption on mTLS; 0-RTT off |
| public TLS leaf | ECDSA-P256; MTC later | `LoadCredential(Encrypted)` / k8s projected Secret | ACME + ARI | CERT-1..4; atomic swap |
| private hops | ML-DSA-44 (gov ML-DSA-87) | same | short-lived, one CA path | CERT-3 |
| capability tokens | Tier 0 / Tier L HMAC / Tier X ML-DSA-65 | credentials | epoch bump | CT compare at TCP-timestamp resolution |
| audit checkpoint | Ed25519 signed-note; **ML-DSA-87 cosignature mandatory in gov profiles** | credentials, separate from TLS | yearly / compromise | sign after tile fsync |
| release keys | Ed25519 + SLH-DSA-SHA2-128s + ML-DSA-87 | offline hardware token | on compromise; TUF root | AND per profile |
| TUF root/targets | 3-of-5 / 2-of-3 offline | offline holders | signed chain | rollback rejected; timestamp expiry ≤7 d [E] |
| FIPS module | AWS-LC FIPS 3.1.0, AL2023 only | n/a | new cert only | `--fips-check` nonzero unless fips() and version string match |

Secrets: systemd-creds (TPM2 where present) or k8s projected Secrets/CSI; rotation = new credential → reload → atomic swap → zeroize; each rotation audited (SC-12); no secrets in config, env or logs; optional KMS-backed `CredentialSource` for enterprise.

## F. Open supply-chain gaps (close by building)
End-to-end G1–G10 run with negative controls (phase 0) · cross-host repro and aws-lc-sys/ring parity · release drill (≤6 h target, E) · TUF negative test · cmvp client-policy gate · tlog writer vs Tessera.
