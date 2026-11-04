# P6-release-001 report (implementer, 2026-11-04, base main a3a870c)

## What was built

`ci/release/pipeline.sh --profile floor|cmvp --out DIR` runs on kamrui with the ci/remote.sh environment. It writes
release layout contract v1, which is defined in the `ci/release/verify.py` docstring.

**Stage 0 (the pipeline itself).**
- Exports the source with `git archive HEAD`. SOURCE_DATE_EPOCH is the commit time.
- A tree with no git metadata needs `AEGIS_RELEASE_COMMIT` and `AEGIS_RELEASE_EPOCH`, and is recorded as source kind
  `tree`. Otherwise it fails. An rsynced worktree on kamrui (`repo-<hash>`) has no usable `.git`, which is why this
  mode exists.
- cmvp applies `profiles/cmvp/overlay.toml` and `profiles/cmvp/Cargo.lock`.
- Runs `cargo fetch --locked`.
- Runs `deploy/build/image.sh`.

**Five jobs.** Each job is its own process, started with `env -i`, with its own scratch dir. The three keyed jobs
each get their own key dir: mode 0700, on tmpfs (`/dev/shm`). The pipeline refuses to finish while a key dir is not
empty, and its EXIT trap shreds any key dirs left over.

| # | job | what it does |
|---|---|---|
| 1 | `jobs/build.sh` | Runs `cargo auditable build --release --locked --offline -p aegis-bin` (cmvp adds `--features aegis-bin/cmvp`) inside `aegis-al2023-build:<sha12(Containerfile)>`, the same tag scheme as profiles/cmvp/build.sh.<br>Uses `--network none` with fixed in-container paths.<br>Mounted read-only: the source, the cargo registry, the Rust toolchain, Go and cargo-auditable. Only CARGO_HOME's lock/db files are writable, in scratch.<br>RUSTFLAGS remaps the paths as ci/repro.sh does.<br>Writes `build-info.json`: image name/id/base digest, Containerfile sha256, `rustc -vV`, `cargo -V`, `go version`, gcc, RUSTFLAGS, epoch, command, and the sha256 of Cargo.lock and cargo-auditable. |
| 2 | `jobs/sbom.sh` | Runs cargo-cyclonedx 0.5.9 (CycloneDX 1.5, SOURCE_DATE_EPOCH honoured) in the same image, with no network, on its own copy of the source.<br>Checks that Cargo.lock was not changed and that the BOM describes aegis-bin. |
| 3 | `jobs/attest.py` | Generates its own fresh Ed25519 key.<br>Reads only the artifact digest (`--subject`), build-info, source.json and the SBOM.<br>Writes a DSSE envelope with an in-toto Statement v1 and SLSA provenance v1.<br>Records commit, tree sha256, epoch, image id plus base digest plus Containerfile sha256, rustc -vV, Go and gcc versions, and RUSTFLAGS (for P6-release-002).<br>Checks its own signature, runs leakcheck against its key, then shreds the key. |
| 4 | `jobs/sign.sh` | Signs `aegis-release-v1 sha256:<sha256(SHA256SUMS)>\n` with Ed25519, SLH-DSA-SHA2-128s and ML-DSA-87, using `/usr/bin/openssl` 3.5.3. The check is for >= 3.5.<br>Verifies each signature with the shipped public key, runs leakcheck, then shreds the keys. |
| 5 | `jobs/tuf.py` | Runs in the py-tuf venv, with pins checked against the `#py:` rows of ci/tools.lock.<br>Root: 5 Ed25519 keys, threshold 3. One key each for targets, snapshot and timestamp. All roles are v1, with `test_keys: true` in every role's `signed`.<br>Self-checks: 5 of 5 root signatures, and each role verified by the root. Then leakcheck, then shredding of the 8 keys. |

**Other files.**
- `ci/release/jobs/leakcheck.py` (stdlib only) finds:
  - PEM `-----BEGIN … PRIVATE KEY-----` blocks;
  - PKCS#8 DER private key headers for Ed25519, ML-DSA-44/65/87 and SLH-DSA-SHA2-128s, raw and in base64 at every
    alignment, base64url and hex;
  - with `--keys`, the run's own keys exactly: DER, hex, base64, PEM lines, and the Ed25519 seed;
  - symlinks and special files.

  Public SPKI keys do not match. The pipeline runs it over the whole release before the hand-over.
- `deploy/build/image.sh` builds or reuses the image. It asserts that the **unpacked** rootfs (`du -sxk /` × 1024,
  as main f65893f does) and docker's content size are both under 500 MB.

The out dir is removed at start and replaced atomically at the end. A failed run therefore leaves no DIR that the
verifier could pass.

## Acceptance (kamrui, ci/remote.sh)

```
ci/remote.sh --host kamrui bash -c 'export AEGIS_RELEASE_COMMIT=8f734ed… AEGIS_RELEASE_EPOCH=1793800658;
  ci/release/pipeline.sh --profile floor --out target/release-out && ci/release/verify.py --allow-test-keys target/release-out'
```

The env vars were needed only because this worktree's rsynced copy has no `.git`. From `~/aegis-ci/repo` (main
checkout), the gate command as written uses the `git archive HEAD` path. That path was not exercised from this
worktree.

```
image: aegis-al2023-build:1f326d0afbea unpacked 470138880 B, content 167878066 B (< 500000000 B)
build: floor aegis-floor sha256 56ae5112ad4c1abf776ee90aa39d8acfc09ec1c69c4f1ff2c12a91ea7835fae7
sbom: CycloneDX 1.5, 83 components
attest: provenance for 1 subject(s), attest key c9b71976db5b308d (destroyed)
sign: ed25519 64 B / slh-dsa-sha2-128s 7856 B / ml-dsa-87 4627 B over sha256:fffa9fd5…
tuf: root v1 (3 of 5 Ed25519), targets/snapshot/timestamp v1, 15 targets, test_keys true; 8 keys destroyed
LEAKCHECK: PASS
RELEASE-PIPELINE: PASS (floor, artifacts/aegis-floor sha256 56ae5112…, 19 files, commit 8f734ed…, 3 key dirs (12 keys) destroyed)
RELEASE-VERIFY: PASS
```

The same release without `--allow-test-keys` gives `RELEASE-VERIFY: FAIL (REL-2 no-trust-anchor …)`, which is the
REL-4 / TOFU refusal.

**Reproducibility.** A second full pipeline run on the same commit, with fresh scratch, target and keys, gave the
same artifact sha256 `56ae5112…` and the same SBOM sha256 `5b2cf1d4…`. This is the same host and the same image id. The
cross-host comparison is P6-release-002 (D7).

**Private-key check (planted in a copy of target/release-out):**
- Planted PEM Ed25519 key `sigs/leaked.key.pem`:
  - `LEAKCHECK: FAIL (3 findings)`
  - `RELEASE-VERIFY: FAIL (D-P2 private-key-material: sigs/leaked.key.pem contains a PEM private key block)`
- Planted DER ML-DSA-87 private key, which verify.py's PEM scan does not see: `LEAKCHECK: FAIL (1 findings)`
  (`ML-DSA-87 PKCS#8 DER`).
- `leakcheck.py --self-test`: `LEAKCHECK SELF-TEST: PASS (clean tree passes; 13 planted-key mutants)`. Each mutant
  is caught:
  - PEM blocks for PKCS#8 Ed25519 and ML-DSA, and the ENCRYPTED and OPENSSH labels;
  - DER Ed25519 and SLH-DSA;
  - ML-DSA DER as base64 inside JSON;
  - base64 at offsets 1 and 2;
  - hex DER;
  - the raw seed and the hex seed (the known-key mode);
  - a symlink to a key.

  Clean public-key trees, PEM and DER, pass.

**cmvp:** `ci/release/pipeline.sh --profile cmvp` gives:
- `error[E0432]` at `crates/aegis-audit/src/note.rs:13`;
- `build: cmvp build FAILED. Known cause until P6-cmvp-001 lands (PLAN-6 D15) …`;
- `RELEASE-PIPELINE: FAIL (job build failed)`, exit 1, with no out dir.

**Cleanup checked after the runs:**
- `/dev/shm` holds no aegis key dirs;
- no `release-work.*` dirs are left;
- no aegis containers are left;
- docker images: only the pinned `aegis-al2023-build:1f326d0afbea` (90f85e49…).

My first run had created `aegis-build-al2023:1f326d0afbea` as a separate image id (68a83407…, not a cache hit). It was
removed (`docker rmi`, which deleted it) per the integrator's note.

## Notes and open items
- **Tools on kamrui.** `ci/install-tools.sh` was run on kamrui, putting `~/aegis-ci/tools/bin` at the tools.lock pins.
  The pipeline re-runs it when the cargo-auditable or cargo-cyclonedx stamp does not match the pin.
- **Container limits.** The docker containers run under dockerd, outside remote.sh's systemd scope. So the build and
  sbom containers have their own limits: `--memory 8g --memory-swap 9g --cpu-shares 256`, labelled, and removed by a
  trap.
- **Shredding.** Key dirs are on tmpfs, so `shred` is belt-and-braces there. TUF keys are also briefly held in process
  memory.
- **Builder id.** The provenance builder id is `urn:aegis:ci:kamrui:release-pipeline:v1`. P6-release-002 may want its
  own builder id for build B.
- **Rung.** REL-1..5 on a real pipeline release: R1 (executed: verify.py PASS on pipeline output). Reproducibility on one
  host: measured equal across 2 runs. Not yet cross-host.
