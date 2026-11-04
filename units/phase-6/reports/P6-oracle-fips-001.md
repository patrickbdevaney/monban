# P6-oracle-fips-001 report (spec author, 2026-11-04, base a15e3a5)

## What was built

`oracles/cmvp-binary/` has two entry points. Both match the commands already in `gates/phase-6.toml`.

- **`run`** (fips-binary): `fips_binary.py`.
- **`client-policy`** (cmvp-client-policy): `client_policy.py`, a port of the spike gate plus the D13 check.
- **`selftest.py`:** the self-tests of both.
- **`lib/fixtures.sh`:** the heavy fixture build, which goes through ci/heavy.sh.
- **`fixtures/`:** its own workspace and lock, on the floor pins. It contains:
  - the spike's tlsbins, unchanged;
  - an mTLS member package;
  - 8 dependency-free `fips_*` stubs.
- **`README.md`:** the full check tables and limits.

Only files in `oracles/cmvp-binary/**` and this report were written.

## Contracts for P6-cmvp-001

**`aegis --fips-check`.** The oracle runs it with an empty environment, cwd `/`, stdin `/dev/null` and a 20 s timeout.
It must exit 0 and print exactly one stdout line, byte for byte:

```
cmvp:   FIPS-CHECK: module="AWS-LC FIPS 3.1.0" fips_mode=true config_fips=true
floor:  FIPS-CHECK: module=none fips_mode=false config_fips=false
```

The fields:
- `module`: `awslc_version_string()`, read at runtime, i.e. `FipsStatus.module`.
- `fips_mode`: `aws_lc_rs::try_fips_mode().is_ok()`.
- `config_fips`: `ServerConfig::fips()` of the default cmvp profile config.

It must not need a config file, sockets or certificates.

**Risk for P6-cmvp-001: reading the version string.** aws-lc-rs 1.15.3 has no safe API for the version string
(checked in its source). Reading it means calling `awslc_version_string` through FFI, which needs `unsafe`.
`unsafe_code` is forbidden outside aegis-iso. P6-cmvp-001 must find a sanctioned route, or report it.

**Client-policy PASS line.** It is exactly `CLIENT-POLICY: PASS (compiled-out)`, as the ledger's `evidence_must`
already says. `exceptions.toml` is unchanged.

## How the spike's strip=symbols problem is solved

The shipped aegis is stripped. The oracle relinks only the final crate, with `cargo rustc ... -- <extra>`, so the
dependency rlibs are reused. It does this twice:

1. `-C strip=none -C link-arg=-Wl,-Map=twin.map` gives the unstripped twin, read with `nm -C`.
2. `-C link-arg=-Wl,-Map=shipped.map` gives the shipped configuration plus its map.

**R0:** the second relink must be sha256-identical to the judged binary. If it is not, the result is ERROR. The
judged binary is restored and its hash re-checked.

**Measured on kamrui with the fixtures:**
- R0 holds for all 6 fixtures. `cargo build` and `cargo rustc` with `-Wl,-Map` give byte-identical output.
- The twin's `.text` and `.rodata` are identical to the shipped binary's.

So the symbol view is the shipped code, which is stronger than the spike, whose twin differed in `.text`.

**Real run.** The relink goes through docker in the AL2023 image, with the same mounts and environment as
`profiles/cmvp/build.sh --check`. This duplicates part of build.sh, which is outside my scope, so the two must be
kept in sync.

**Unverified until a real cmvp binary exists: R0 on the real tree.** build.sh links aegis-bin together with
tls-subject, while the relink builds `-p aegis-bin` alone. `cargo tree` shows identical features for every package
under aegis-bin either way.
- If R0 still fails on the real tree, the gate is ERROR (fail-closed).
- The fix would then be for build.sh to emit the map, passed in with `--map`/`--twin` (integrator scope).

## D13: what aegis-bin does today (real cmvp overlay graph, 65 packages)

**No WebPKI client-cert verification on cmvp listeners.**
- Nothing in any package's source builds a client-certificate verifier: rustls/webpki excluded, 0 hits for
  WebPkiClientVerifier, with_client_cert_verifier, AllowAny* or `impl ClientCertVerifier`.
- The listener builders use `with_no_client_auth()` only:
  - `crates/aegis-tls/src/profile.rs:280` and `:378`;
  - `crates/aegis-ops/src/acme/tls.rs:44`, which is the ACME ClientConfig and is feature-gated off in cmvp.

**The binary half** reports the linked `ClientCertVerifier` impls and the WebPkiClientVerifier symbol and map counts.
On the fixtures:
- srv_only links only `NoClientAuth`;
- srv_mtls links `WebPkiClientVerifier` (9 symbols, 19 map refs).

**C2 fails** on any WebPkiClientVerifier, any custom `ClientCertVerifier` impl, or a verifier that is installed but
not identifiable. The only exception is a live `[[mtls]]` entry in `oracles/cmvp-binary/mtls-justification.toml`
citing RUSTSEC-2026-0382. That file is absent: none is recorded.

## Acceptance

| command | result |
|---|---|
| `ci/remote.sh --host kamrui oracles/cmvp-binary/run --self-test` | `CMVP-BINARY SELF-TEST: PASS (20/20: 2 baselines PASS (cmvp fixture on the real cmvp graph, floor negative control), 18 mutants caught with the expected check id)` |
| `ci/remote.sh --host kamrui oracles/cmvp-binary/client-policy --self-test` | `CLIENT-POLICY SELF-TEST: PASS (31/31: spike's 12 ported (5 binaries + 7 mutants), cross-mode, map/twin/R0 mutants, D13 mTLS mutants, real cmvp graph M1 + D13 source baseline)` |
| real run (fips-binary, cmvp-client-policy) | red, see below |

**fips-binary mutants.** Each is caught with its own check id:
- no contiguous string, with the line assembled at runtime (F1);
- string present but runtime `module=none` (F4), and as floor (F1');
- string present but runtime `AWS-LC 4.2.0` (F4; F2 also fires);
- `--fips-check` mismatch, `fips_mode=false` (F4);
- `--fips-check` not implemented (F4);
- decoy `AWS-LC FIPS 2.0.0` (F2);
- non-FIPS `AWS-LC 5.11.0` bytes (F2);
- floor judged as cmvp (F1);
- good judged as floor (F1');
- missing binary (ERROR);
- 7 mutations of the real cmvp `cargo metadata`, each F3: no fips-sys, two fips-sys, registry aws-lc-sys, a void
  crate with a build script, aws-lc-rs without fips, fips-sys off the pin, aws-lc-rs unlinked.

The F3 baseline on the real cmvp graph is clean.

**client-policy cases.**
- The spike's 12, with the same verdicts. The spike's "neither mode" FAILs are judged in both modes.
- 2 cross-mode cases.
- B2, no-map and R0-tamper mutants.
- 5 D13 cases: mTLS (C2), justified (PASS), expired justification (C2), verifier only in the binary (C2), verifier
  only in the source (C2).
- Light cases on the real cmvp overlay:
  - M1 baseline: no client feature;
  - 3 M1 mutants (`aegis-tls/tls-client`, `aegis-egress/tls-client`, `aegis-ops/acme`), all caught;
  - D13 source baseline: n=0.

**The first client-policy run was red, 2/31 mismatches, both bugs I found and fixed:**
- The second-suppression mutant wrote an empty file, because the file was truncated before it was read.
- The justified-mTLS case flagged the `with_client_cert_verifier(...)` install site as an "other verifier". It now
  flags only an installed verifier whose construction cannot be identified.

**The third run was red too (5/31): a self-test artifact.** The cases that relink a fixture deleted the maps of the
shared views. The views now have their own work directories. The fourth run passed 31/31.

**The second run found a real hole in the relink, now closed.** Re-running with the same map paths made cargo treat
the final crate as fresh, so it skipped the link and no map was written. The case went ERROR, which is safe here.
But if a map had been left over from an earlier run, R0 would have compared the binary with itself.
- The fix: the map paths are now unique per run.
- Each map must exist after its relink, or the run is ERROR.

**Real runs.**
- `oracles/cmvp-binary/run --binary target/cmvp/release/aegis` (on kamrui): `CMVP-BINARY: FAIL (ERROR: 1 violations: binary not found: target/cmvp/release/aegis)`, exit 2
- `oracles/cmvp-binary/client-policy --mode compiled-out --binary target/cmvp/release/aegis` (on kamrui): `CLIENT-POLICY: ERROR (binary not found: target/cmvp/release/aegis)`, exit 2

Both are red because no cmvp binary exists. `profiles/cmvp/build.sh --check` still fails on the 3 ML-DSA sites
(P6-spec-002). They stay red until P6-cmvp-001.

## Open

1. **Version string needs unsafe.** P6-cmvp-001 must read the module version string without `unsafe` (see above).
2. **R0 on the real tree** is first measured when a cmvp binary exists.
3. **The source scan for custom `impl ClientCertVerifier` and "unidentified verifier"** has no fixture mutant. It
   would need another member package. The WebPki paths are covered in source and in the binary.
4. **`/healthz` `module`** (D2) is not judged here, because it needs a booted server. It is left to clienthello-cmvp
   or conformance.
5. **pq-only on the real binary** needs a clippy log and probe JSON that aegis does not emit. The cmvp gate uses
   compiled-out.
