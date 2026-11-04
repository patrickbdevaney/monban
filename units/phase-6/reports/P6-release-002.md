# P6-release-002 report (implementer, 2026-11-04, base main c8c6937)

## What was built
- `ci/release/vm.sh start|stop|status|ssh|scp-opts` drives the GCP VM aegis-quiet (us-central1-a, c2-standard-8,
  Ubuntu 24.04, 120 GB pd-balanced) from the laptop.
  - The VM has no reserved address, so its IP changes on every start. vm.sh reads the new natIP and uses the alias
    `quiet` with `HostName=<ip>`.
  - The host key is not trusted on first use. It is pinned to the keys already in ~/.ssh/known_hosts for the alias's
    configured HostName (read only), with HostKeyAlias aegis-quiet and StrictHostKeyChecking=yes.
  - `stop` waits until `gcloud compute instances describe … --format='value(status)'` = TERMINATED, and exits 1
    otherwise.
- `ci/release/rebuild.sh --a kamrui --b quiet --profiles floor,cmvp` runs from the laptop.
  - **Build A:** `ci/remote.sh --host kamrui ci/release/pipeline.sh --profile P`. The pipeline output is streamed, so
    `RELEASE-PIPELINE: PASS (<profile>, artifacts/aegis-<profile> sha256 <hex> …` (and FAIL) reaches the gate's stdout
    for every profile, as conformance/run needs. The provenance, attest key, SHA256SUMS and artifact are then
    fetched.
  - **Build B:** the VM is started only if some A passed. EXIT/INT/TERM traps always run `vm.sh stop`. B is detached
    on the VM (setsid, log and rc file) and followed by polls.
  - **B provisioning, all fetched independently on the VM (none of it transferred from kamrui):**
    - docker.io from the VM's apt, first use only;
    - `docker pull` of the base by digest, with a RepoDigest check, then `deploy/build/image.sh` rebuilds the image
      from al2023.Containerfile (< 500 MB asserted);
    - rustc, cargo and rust-std for the channel in rust-toolchain.toml, from static.rust-lang.org. The channel
      manifest is checked against its published `.sha256`. Each component's sha256 is checked against that manifest
      **and** against the hashes in kamrui's rustup manifest. Then `install.sh --prefix`;
    - Go and cargo-auditable from their ci/tools.lock URLs, sha256 checked against ci/tools.lock;
    - a fresh CARGO_HOME filled by `cargo fetch --locked` from crates.io.
  - **B's source:** `git archive <commit>` from the laptop, exported the way A's provenance says A exported it. For
    source kind `tree` (a git-less worktree), B applies pipeline.sh's own rsync filter. cmvp gets the same overlay.
  - **B's build:** only `jobs/build.sh` from that source runs, with `CARGO_BUILD_JOBS=nproc` (8; A uses 4). B's builder
    id is `urn:aegis:ci:gcp-aegis-quiet:release-rebuild:v1`.
- **Gate, per profile (laptop check, python3 -I, stdlib):**
  - A's DSSE signature verifies with A's attest key;
  - there is exactly one subject, `artifacts/aegis-P`;
  - sha256(A) = sha256(B) = the attested digest, hashed on the laptop;
  - B's build record matches the attested recipe on 15 fields: profile, commit, tree sha256, SOURCE_DATE_EPOCH,
    command, RUSTFLAGS, base digest, Containerfile sha256, rustc -vV, cargo -V, go, gcc, paths, Cargo.lock sha256 and
    cargo-auditable sha256;
  - the builder ids differ;
  - then `ci/release/verify.py --allow-test-keys --expect-sha256 artifacts/aegis-P=<sha256(B)>` passes on A's release
    on kamrui (REL-1..5 plus the rebuild digest).
- Records are kept in `target/release-rebuild/<profile>/{A,B,PASS}`.

## Acceptance (run 2, commit 2cfd7af)
```
RELEASE-PIPELINE: PASS (floor, artifacts/aegis-floor sha256 56ae5112ad4c1abf776ee90aa39d8acfc09ec1c69c4f1ff2c12a91ea7835fae7, 19 files, commit 2cfd7af…, 3 key dirs (12 keys) destroyed)
RELEASE-PIPELINE: FAIL (job build failed)        <- cmvp, A: "cmvp build FAILED. Known cause until P6-cmvp-001 lands …"
rebuild: A's source kind is tree (commit 2cfd7af…)
B: rust rustc 2ff05ff9… / cargo 53f35219… / rust-std 109b0742… (manifest + kamrui agree)
B: go 65efbc80… ; B: cargo-auditable 76764433…
B: image aegis-al2023-build:1f326d0afbea sha256:f107e629… from base amazonlinux@sha256:bb1c85fe…   (kamrui's id is 90f85e49…: rebuilt image, different id, same binary)
B-RESULT: floor PASS sha256 56ae5112ad4c1abf776ee90aa39d8acfc09ec1c69c4f1ff2c12a91ea7835fae7 tree 7897f856…
VM: aegis-quiet TERMINATED (gcloud compute instances describe aegis-quiet --zone us-central1-a: status=TERMINATED)
rebuild: VM aegis-quiet TERMINATED after 237 s (~4 min)
REBUILD-CHECK: PASS (floor sha256 56ae5112…: A = B = attested; recipe matches (15 fields); builders urn:aegis:ci:kamrui:release-pipeline:v1 / urn:aegis:ci:gcp-aegis-quiet:release-rebuild:v1; image rebuilt, different id)
RELEASE-VERIFY: PASS
RELEASE-REBUILD: FAIL (cmvp: A: release pipeline failed (RELEASE-PIPELINE: FAIL (job build failed)); passed: floor sha256 56ae5112…; VM aegis-quiet TERMINATED after 237 s (~4 min))
```
- **floor:** passes everything. It is the same digest P6-release-001 measured on kamrui, now reproduced on an
  independently provisioned machine with independently fetched tools.
- **cmvp:** fails clearly in A until P6-cmvp-001 lands. B is not attempted for a profile whose A failed. So the gate
  as a whole is red, and goes green only when cmvp also gives A = B = attested.
- **Run 1** failed honestly on the source tree sha256. A's tree-mode export (this worktree has no git on kamrui) drops
  the tracked `research/state/raw/`, while B used the plain archive. The binaries were already equal. Fixed by having
  B mirror A's recorded source kind. The gate run from the main checkout uses git mode, where both sides are the
  plain `git archive`. I could not run that mode from a worktree.

## Self-test
`ci/release/rebuild.sh --self-test` gives `RELEASE-REBUILD SELF-TEST: PASS (10 cases; recorded runs replayed: floor)`.
- **Synthetic cases.** The provenance is real-format: made by `jobs/attest.py` itself with a throwaway key.
  - clean: PASS;
  - B SOURCE_DATE_EPOCH+1: FAIL;
  - a validly signed attestation naming another digest: FAIL;
  - a payload edited to another digest: FAIL (signature);
  - B binary differs: FAIL;
  - B reuses A's builder id: FAIL;
  - B built another tree: FAIL.
- **Replay of the recorded real floor run:** clean PASS, epoch+1 FAIL, swapped subject FAIL.
- **Red.** Self-test on checker mutants, from temporary copies that were then deleted:
  - epoch row removed: `SELF-TEST: FAIL (2 of 10 cases wrong)`;
  - digest/signature checks disabled: `FAIL (3 of 10 cases wrong)`.
- **Why the self-test does not use the VM.** The gate's decision is a pure function of four inputs: A's provenance and
  key, sha256(A), B's build record, and sha256(B). The binary does not depend on SOURCE_DATE_EPOCH. I measured this
  with a real mutant run:
  `rebuild.sh --profiles floor --mutant-b-epoch-offset 1` gave `B-RESULT: floor PASS sha256 56ae5112…` (identical
  binary), then `REBUILD-CHECK: FAIL (floor: recipe SOURCE_DATE_EPOCH: attested '1793803508' != B '1793803509')` and
  `RELEASE-REBUILD: FAIL`, with the VM TERMINATED after 211 s.
  - So the epoch mutant is caught by the recorded recipe, not by the digest, and an edited record is exactly what a
    real mutant B produces.

## VM usage and cost
| session | time |
|---|---|
| exploration and first-use docker install | ~2 min |
| run 1 | 266 s |
| run 2 | 237 s |
| mutant run | 211 s |
| **total** | **about 14 VM-minutes** |

- That is about $0.08 at the c2-standard-8 us-central1 on-demand rate (~$0.33/h), plus a little egress for two
  ~10 MB binaries.
- Disk: 106 GB free of 116, so no resize and no cost delta.
- The VM is TERMINATED now, checked with gcloud describe after every run.
- **Left on the VM:** docker.io; the AL2023 build image (~470 MB unpacked); a download cache in
  `~/aegis-ci/rebuild/dl` (Rust components, Go, cargo-auditable, about 300 MB), whose sha256 is re-checked on every
  run. Per-run dirs are deleted after a day.
- **Left on kamrui:** `target/release-rebuild/A-<profile>` under the worktree's target dir. remote.sh prunes it.

## Notes
- The fix that stops a stale `B-RESULT` line from an earlier run being read (b.log is truncated per run) was added
  after run 3. It was checked with the self-test only, not with another VM run.
- Rung: floor cross-host reproducibility is R1, executed. A on kamrui and B on aegis-quiet are byte-identical and equal
  the attested digest, but both use the same AL2023 image recipe and rustc. cmvp: not yet.
