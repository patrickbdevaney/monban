# P6-oracle-interop-001: kx-interop oracle

Built `oracles/kx-interop/` (gate `kx-interop`, PLAN-6 D4, PREFLIGHT D-P4). Details are in
`oracles/kx-interop/README.md`.

## Acceptance (2026-11-04, kamrui)

- `ci/remote.sh --host kamrui oracles/kx-interop/run` printed
  `KX-INTEROP: FAIL (20/20 cells failed: ED-OSSL-SRV, ... EC-BSSL-CLI)`, exit 1. This is the required red.
  - Every cell says `subject has no interop-server|interop-client mode`. tls-subject only has `describe|serve`.
- `ci/remote.sh --host kamrui oracles/kx-interop/run --self-test` printed
  `KX-INTEROP SELF-TEST: PASS (baseline 20/20 green; order 6/6 0x11ED cells red, 12 other cells green;
  x25519-fallback 2/2 refusal cells red; no-echo 18/18 cells red; hrr-precondition 4/4 HRR cells red;
  matrix-bssl-11ed refused; matrix-missing-cell refused; matrix-missing-refusal refused)`, exit 0.
- Self-test red/green history: the first self-test runs were red for real reasons. Each was fixed in the oracle
  harness, not by relaxing a check:
  - The OpenSSL group-name case differed.
  - BoringSSL's default verify list has no ML-DSA-87.
  - s_client read the `k`-prefixed nonce as a KeyUpdate command.
  - Client-direction HRR liveness needed a subject-side mutant.

## Matrix

| group | cells |
|---|---|
| 0x11ED | OpenSSL and Go, both directions, plus HRR (server direction) |
| X25519-only vs P-UNIVERSAL | OpenSSL and Go, refusal |
| 0x11EB | OpenSSL and Go, server direction, plus client direction with HRR |
| 0x0202 | OpenSSL, BoringSSL and Go, both directions |
| 0x11EC | BoringSSL, both directions |

Each cell checks the wire (ServerHello/HRR group parsed from plaintext records), the peer's report, an application
data round trip verified at the independent side, and the subject's report. The matrix is validated against a
runtime capability probe of each peer and against hard-coded required coverage before any cell runs.

## Peers

- OpenSSL 3.5.3, `/usr/bin/openssl` (the version is checked).
- Go 1.27.3, `go/` (stdlib crypto/tls only), built with `GOTOOLCHAIN=local GOFLAGS=-mod=mod GOPROXY=off`.
- BoringSSL `e651545da6e26e1f4420723a3b69a78ed1b9c51d` (committed 2026-10-26, 9 days old):
  - Tarball sha256 `8df88916...2013f`, recorded in `oracles/kx-interop/bssl/LOCK`.
  - Built in a throwaway `amazonlinux@sha256:bb1c85fe...` container.
  - Runtime image `aegis-bssl:e651545da6e2`, 267 MB, kept on kamrui.
  - No other images were created. Build containers are `--rm`; the source and build trees are deleted.

## Open items / dependencies

1. **P6-tls-001 must add the subject contract** (README "Subject contract"): `interop-server <PROFILE>` and
   `interop-client <PROFILE> <CA_PEM> <NONCE>` on stdio. `ref-subject/` is a working example.
2. **Outside every current write_scope:** `interop-client` needs `aegis_tls::client_config`, which needs
   `aegis-tls` feature `tls-client`.
   - `subjects/tls-subject/Cargo.toml` (not in P6-tls-001's scope, `subjects/tls-subject/src/**`) must set
     `aegis-tls = { workspace = true, features = ["tls-client"] }`.
   - Integrator action, or a scope change.
3. **Order mutant.** The aegis-tls `order-mutant` feature doesn't exist yet (P6-spec-002). Until it does, the
   self-test runs the same combiner swap on the reference subject.
   - Once the feature exists, a `run --subject <tls-subject built with --features aegis-tls/order-mutant>` must be
     red on all 6 0x11ED cells.
   - Whoever owns the gate selftest may want to add that run to `kx-interop`'s selftest command (gates/ is outside
     this scope).
4. **ci/oracles.sh placement.**
   - `needs` = `kamrui`, so `ci/oracles.sh --where local` (laptop) picks this oracle up.
   - `run` then re-runs itself through `ci/remote.sh --host kamrui`, which works from the laptop. That means the
     gate `oracles-local` runs it a second time.
   - If that's unwanted, ci/oracles.sh should skip `kamrui` needs for `--where local`. That is a ci/ change, outside
     this scope.
5. `ci/tools.lock` has no BoringSSL row. `bssl/LOCK` is the pin until P6-spec-002 (or whoever owns tools.lock) adds
   one.
   - `deploy/build/al2023.Containerfile` was absent in my base commit. It appears that another unit is creating it
     (image `aegis-al2023-build:1f326d0afbea` / `aegis-build-al2023` showed up on kamrui; not mine, left alone).
   - Once it lands, `bssl/build.sh` could build from it.
6. The 0x11ED client-direction HRR isn't reachable, because every profile lists 0x11ED first. It is covered on 0x11EB
   instead and documented in matrix.toml.
7. Oddity: the captured `run` log began with two `pipeline:`/`image:` lines from another job on kamrui
   (a release-pipeline build), interleaved by remote.sh's log follow. The oracle result is unaffected.

Disk: the remote `oracles/kx-interop/target` was 178 MB after a self-test and was deleted. Nothing is left on the
laptop beyond the source.
