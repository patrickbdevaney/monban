# P6-spec-002 report (integrator, 2026-11-04, base a9b2d4f)

## 1. D1 risk measurement (cmvp overlay build): done first

**What was built.**
- `profiles/cmvp/overlay.toml` changes three `[workspace.dependencies]` lines:
  - rustls =0.23.43, with `fips` added;
  - rustls-webpki =0.103.13;
  - aws-lc-rs =1.15.3, with `fips`.
- The overlay also adds `[patch.crates-io] aws-lc-sys` pointing at an in-tree void crate. See DEVIATIONS X-15.
- `profiles/cmvp/overlay.py` applies the overlay, and fails closed when a key is missing or present twice.
- `profiles/cmvp/build.sh` has four modes: `--check` (the default), `--lock`, `--metadata` and `--vet`.
- `profiles/cmvp/Cargo.lock` is generated from the root lock with only the changes the overlay forces, plus
  `aws-lc-fips-sys --precise 0.13.11`. It differs from the root lock in these crates:
  - downgraded: rustls 0.23.43, rustls-webpki 0.103.13, aws-lc-rs 1.15.3;
  - added: aws-lc-fips-sys 0.13.11, and bindgen 0.72.1 with its build-time tree (cexpr, clang-sys, glob,
    itertools 0.13, libloading, minimal-lexical, nom, prettyplease, shlex 1.3);
  - aws-lc-sys is replaced by the void path crate 0.36.0;
  - dropped: getrandom 0.4.3, jobserver, r-efi 6.
- `deploy/build/al2023.Containerfile` has one RUN layer and is pinned by digest, with `--releasever=2023.12.20261102`.
  - That is the base image's own release, so the installed packages match its glibc. It is 2 days old. The 7-day rule
    covers crates and tools; the base digest was fixed in the PREFLIGHT, and an older releasever would mix repository
    snapshots.
  - `build.sh` asserts that the image is under 500 MB.

**Command:** `ci/remote.sh --host kamrui profiles/cmvp/build.sh --check`, run in the AL2023 image with the toolchain
and Go 1.27.3 mounted read-only. It runs `cargo build --locked --keep-going --release -p aegis-bin -p tls-subject
--features aegis-bin/cmvp,tls-subject/cmvp`.

**What compiled.** The AWS-LC FIPS 3.1.0 module (aws-lc-fips-sys 0.13.11, through cmake, Go and perl) built inside
AL2023. These crates compile unchanged against rustls 0.23.43 and aws-lc-rs 1.15.3 with fips:
- aegis-tls, aegis-transport, aegis-ops, aegis-egress, aegis-config, aegis-admission, aegis-metrics, aegis-data-ir;
- tokio-rustls 0.26.6.

**Gap list: the cfg(feature = "cmvp") work for P6-cmvp-001.** There are 3 compile errors, all ML-DSA:

| crate | site | error |
|---|---|---|
| aegis-audit | `src/note.rs:13` | `aws_lc_rs::signature::{ML_DSA_87, ML_DSA_87_SIGNING, PqdsaKeyPair}` unresolved (E0432). This is the ML-DSA-87 note cosignature. |
| aegis-token | `src/tier_x.rs:10` | `aws_lc_rs::signature::ML_DSA_65` unresolved (E0432). This is the tier-X token verification. |
| tls-subject | `src/main.rs:19`, `:77` | `PqdsaKeyPair` and `signature::ML_DSA_44_SIGNING` not found (E0432, E0425). This is the ML-DSA-44 test credential. |

The same gap also exists in a test file the build does not compile: `crates/aegis-tls/tests/profiles.rs:13,50,51`
(ML-DSA-44 and ML-DSA-65 keys).

**ML-DSA is not available at all on cmvp.** In aws-lc-rs 1.15.3, `src/unstable.rs` declares
`#[cfg(not(feature = "fips"))] pub mod signature;`.
- Probe 1 used the `unstable` feature plus `aws_lc_rs::unstable::signature`. It fails with "item configured out".
- So D1's fallback is the only option: the audit ML-DSA cosignature is "absent, reported" on cmvp, tier-X ML-DSA-65
  tokens must deny on cmvp, and ML-DSA test credentials must be skipped.

**What lies behind those gaps.** Probe 2 was measurement only and was never committed. It replaced the three ML-DSA
sites in a scratch copy with an error-returning stand-in.
- Every other crate compiled, including aegis-agent, aegis-state, aegis-adapter-host and the aegis-bin release link
  (fat LTO).
- So **there are no further API gaps in aegis-bin's default build**. The three sites above are the whole cmvp cfg list
  for aegis-bin and tls-subject.
- The probe binary was 5,315,424 B. `strings -a` found exactly one `AWS-LC FIPS 3.1.0`, as a contiguous string, and no
  other `AWS-LC FIPS x.y.z`. This bears on D2 and PREFLIGHT P2.
- The probe binary was deleted on kamrui so it cannot be mistaken for a cmvp artifact.
- These probes did not compile the `native` and `p2` features.

**Status:** `build.sh --check` is red until P6-cmvp-001 adds the cmvp cfgs. The lock half is green: see §2.

## 2. `cargo xtask fips-lock` (BACKLOG G1-G5, G7)

`xtask/src/main.rs` reads the resolve graph from `cargo metadata --locked`, parsed by `lock::parse_metadata` (G7). It
never reads Cargo.lock text.

**Inputs.**
- cmvp reads `profiles/cmvp/build.sh --metadata`.
- floor reads the root workspace. Per D1, `profiles/floor` is the root lock.

**Checks.**
- G1: at least one rustls node, and `prefer-post-quantum` on every rustls node.
- G2a: exactly one aws-lc-fips-sys node.
- G2b: every aws-lc-rs node has `fips` and links exactly the pinned fips-sys.
- G2c: aws-lc-sys may appear only as the void path crate (no build script) and only under aws-lc-rs. The void crate's
  `lib.rs` must contain no code.
- G3: every aws-lc-rs node is in [1.15.2, 1.17.1], and every node matches the pins in pins.toml.
- G4: rustls must be at least 0.23.46 and rustls-webpki at least 0.103.16.
  - On cmvp, a node below the floor is `REPORTED`, and passes only if a live advisory-accepted ledger entry exists for
    that crate, version and advisory.
  - On floor, a node below the floor fails.
- G5 (floor): any aws-lc-fips-sys must be at least 0.13.13.

**Other changes.**
- `lock-age` now also checks `profiles/cmvp/Cargo.lock`: 285 registry packages.
- `ledger-check` is dispatched as `ledger::run(&args)`. ledger.rs comes from main at 2b24d3f; the branch was rebased.
- `LockPkg.deps` was removed, because nothing reads lock text for dependencies any more.

**Self-test: 16 mutants, each of which must fail with its own check id, plus clean cmvp and floor baselines.**
- G2a: a decoy aws-lc-fips-sys 0.14.3.
- G2c: a registry aws-lc-sys present in cmvp.
- G2c: a crate other than aws-lc-rs depending on aws-lc-sys.
- G2b: aws-lc-rs without `fips`.
- G2b: aws-lc-rs linking fips-sys 0.14.3.
- G1: prefer-post-quantum missing, on cmvp and on floor.
- G1: no rustls node, on cmvp and on floor.
- G3: aws-lc-rs 1.17.2 with a pin edited to match.
- G3: aws-lc-rs 1.15.1 with a pin edited to match.
- G3: a second rustls node off the pin.
- G4: floor rustls 0.23.45.
- G4: floor webpki 0.103.15.
- G4: cmvp below the floor with no ledger entry.
- G5: floor lineage broken by aws-lc-fips-sys 0.13.11.

**Red on real inputs, then restored.**
- Change the 0349 entry's advisory id: `FIPS-LOCK (cmvp): FAIL (1 violations)`, from "G4: rustls 0.23.43 < floor
  0.23.46 ... no live advisory-accepted ledger entry".
- Change aws-lc-fips-sys to 0.13.12 in the cmvp lock: `FIPS-LOCK (cmvp): FAIL (G7: cargo metadata --locked ...)`.

**Not covered:** G2b's binary half and G6 (the module string) remain in BACKLOG for fips-binary (P6-cmvp-001).

## 3. Tool pins (`ci/tools.lock`; every pin was at least 7 days old on 2026-11-04)

- **cargo-auditable** v0.7.7 (2026-10-02) and **cargo-cyclonedx** 0.5.9 (2026-03-19): musl prebuilt archives. Each
  sha256 was checked by download and matches the GitHub asset digest.
- **`#go:`** go1.27.3, sha256 65efbc80….
- **`#boringssl:`** commit 3769c110eab4ddbc0c159fadb4f1d0d98b2cf0cc (2026-10-27). The sha256 column holds `git-commit`,
  because the commit hash is the content address.
  - It includes e651545 (2026-10-26), which makes server-preference curve selection BoringSSL's server default.
    P6-oracle-interop-001 should expect that.
- **`#py:`** tuf 7.0.1, securesystemslib 1.6.0, urllib3 2.8.0, cryptography 50.0.2 (cp311-abi3 manylinux_2_28),
  cffi 2.1.1 (cp313) and pycparser 3.12.
  - The wheel sha256 values come from the PyPI JSON API, for kamrui's Python 3.13.
  - cryptography, cffi and pycparser are added because securesystemslib needs them for Ed25519.
  - Install with `--no-deps --require-hashes`. No install script was written: ci/install-tools.sh skips `#` rows.

## 4. Exception ledger

- **Added `rustls@0.23.43 RUSTSEC-2026-0349`** (advisory-accepted), with:
  - approver "integrator (operator standing authorization 2026-11-04)", expiring 2027-05-04;
  - `evidence = "gates/out/logs/phase6-cmvp-client-policy-cmd.log"`;
  - `evidence_must = "CLIENT-POLICY: PASS (compiled-out)"`, a placeholder per the coordinator. P6-oracle-fips-001 sets
    the exact line.
- **Also added `rustls-webpki@0.103.13 RUSTSEC-2026-0382`**, with the same evidence. This was not in the brief, but
  fips-lock G4 needs it.
  - Reason: webpki 0.103.14 and later need aws-lc-rs ^1.18.
  - 0382 bites only where a certificate is verified. The tree builds no verifier: there is no
    WebPki{Server,Client}Verifier anywhere in crates/, and cmvp has no rustls client.
  - **Operator or reviewer, please confirm this one.**
- **Not ledgered.** The cmvp lock also carries rustls 0285/0346/0348 and fips-sys 0042/0043.
  - No gate scans the cmvp lock for advisories: repo-advisories, deny and audit read the root lock only.
  - Whether the ledger must cover these is for P6-oracle-fips-001 or P6-oracle-ledger-001 to decide.
- **block-buffer 0.10.4 (GHSA-qwgh) has no evidencing gate,** so it was left unchanged.
  - Its premise is that every release build is panic=abort and nothing catches the panic. No gate log prints that.
  - deny and audit print `advisories ok…` and an empty scan, but neither knows this GHSA. repo-advisories passes only
    *because* of the entry, which would be circular.
  - So `cargo xtask ledger-check` fails on this entry until such a gate exists (for example a budget or manifest check
    that prints `panic = "abort"` for the release profile).
- **wasmtime, pulley and cranelift cooldown entries: kept.** They were published on day 20755 (2026-10-29), so they are
  6 days old today and fail `lock-age --min-days 7` without the entries. They pass tomorrow, 2026-11-05, and can be
  removed then. They expire 2026-11-12.

## 5. Features (manifests outside the literal write_scope, per the coordinator's instruction)

- **aegis-tls:** `cmvp`, `kat` and `order-mutant`, all empty. Their effects belong to P6-tls-001 and P6-cmvp-001.
- **aegis-bin and tls-subject:** `cmvp = ["aegis-tls/cmvp"]`.

## 6. Acceptance

| command | result |
|---|---|
| `cargo xtask fips-lock --profile cmvp` | `FIPS-LOCK (cmvp): PASS` (G4 REPORTED rustls 0.23.43 / webpki 0.103.13, ledgered) |
| `cargo xtask fips-lock --profile floor` | `FIPS-LOCK (floor): PASS` |
| `cargo xtask fips-lock --self-test` | `FIPS-LOCK SELF-TEST: PASS (16/16 mutants caught; cmvp and floor baselines clean)` |
| `cargo xtask lock-age --min-days 7` | `LOCK-AGE: PASS` (285 packages, root + cmvp) |
| `cargo xtask lock-targets` | `LOCK-TARGETS: PASS` |
| `cargo deny check` | `advisories ok, bans ok, licenses ok, sources ok` |
| `cargo vet --locked` (root) | `Vetting Succeeded (50 fully audited, 26 partially audited, 195 exempted)` |
| also: `cargo xtask layering` | `LAYERING: PASS` |
| also: `python3 -I ci/vet-baseline.py --against HEAD` | `VET-BASELINE: PASS` |
| also: xtask clippy and tests (ci/heavy.sh) | clean; 7 passed |
| `ci/remote.sh --host kamrui profiles/cmvp/build.sh --check` | FAIL: the 3 ML-DSA gaps in §1, recorded as P6-cmvp-001 cfg work |

## 7. Open, needing a decision

1. **The cmvp lock is not vet-covered.** `profiles/cmvp/build.sh --vet` reports 12 unvetted crates:
   - aws-lc-fips-sys 0.13.11, about 1.66M lines;
   - aws-lc-rs 1.15.3, rustls 0.23.43;
   - bindgen, cexpr, clang-sys, glob 0.3.4, itertools 0.13.0, libloading 0.8.9, minimal-lexical, nom 7 and
     prettyplease.

   POLICY.md rule 3 forbids new exemptions for version changes of baseline crates (rustls, aws-lc-rs, glob, libloading,
   itertools). An agent cannot genuinely audit about 1.7M lines. So nothing was exempted or certified. The options are
   to intake the set into vet-baseline.txt (a spec-author or operator decision), or to have humans audit the deltas.
2. **The 0382 ledger entry** needs confirmation (§4).
3. **block-buffer evidence gate** (§4).
4. **The wasmtime/pulley/cranelift entries** can be removed on 2026-11-05.
