# cmvp-binary: the fips-binary and cmvp-client-policy gates

This oracle judges the cmvp build of monban: `target/cmvp/release/monban`, built by `profiles/cmvp/build.sh` inside
the AL2023 image on kamrui. It has two entry points, both used by `gates/phase-6.toml`.

| entry point | gate | spec |
|---|---|---|
| `run --binary PATH [--expect cmvp\|floor] [--metadata FILE]` | fips-binary | PLAN-6 D2, PREFLIGHT P2, BACKLOG G2b (binary half) and G6 |
| `client-policy --mode compiled-out\|pq-only --binary PATH` | cmvp-client-policy | P-PQ6, PLAN-6 D13, the RUSTSEC-2026-0349 and 0382 ledger entries, spikes/cmvp-client-policy |

Each entry point also has `--self-test`, which is heavy. It builds `fixtures/` through `lib/fixtures.sh` into
`target/cmvp-binary-fixtures/`. Run it on kamrui:
`ci/remote.sh --host kamrui oracles/cmvp-binary/run --self-test` (and the same for `client-policy --self-test`).

**State.** There is no real cmvp monban binary until P6-cmvp-001: `build.sh --check` fails on the 3 ML-DSA sites.
Until then both gates are red on the real build, and the self-tests run on synthetic fixtures.

## `run` (fips-binary)

Without `--expect`, the binary is judged as cmvp. Checks F1, F2 and F4 read the binary; F3 reads the resolve graph.

- **F1.** The binary contains the contiguous bytes `AWS-LC FIPS 3.1.0` at least once.
  - Stripped binaries keep `.rodata`, so this works on the shipped artifact.
  - A split match is never accepted. If the bytes are not contiguous, that is an INFEASIBLE finding (PREFLIGHT P2).
  - P6-spec-002's probe link found exactly one contiguous occurrence.
- **F2.** No other module identity is in the binary:
  - no `AWS-LC FIPS x.y.z` with any other version;
  - no non-FIPS `AWS-LC x.y.z`. aws-lc-sys's `awslc_version_string` is `AWS-LC 5.11.0` in the floor's aws-lc-sys
    0.46.0.
- **F3.** `profiles/cmvp/build.sh --metadata` is the overlaid cmvp tree's `cargo metadata --locked`. In it:
  - exactly one aws-lc-fips-sys node, at the `profiles/cmvp/pins.toml` version;
  - every aws-lc-rs node has `fips` and depends on that node;
  - no registry aws-lc-sys. Only the void path crate may appear, and it has no build script.

  This check is independent of `cargo xtask fips-lock`, which checks more on the same graph.
- **F4.** Runtime module identity. See the contract below.

`--expect floor` is the negative control: a floor build must not look like cmvp. It requires:
- no `AWS-LC FIPS` bytes at all;
- `--fips-check` printing the floor line.

### The `--fips-check` contract (for P6-cmvp-001)

The oracle runs `monban --fips-check` with:
- an empty environment;
- cwd `/`;
- stdin `/dev/null`;
- a 20 s timeout.

It must exit 0 and print exactly one line on stdout, byte for byte, ending in `\n`. Nothing else may go to stdout;
stderr is ignored.

```
cmvp:   FIPS-CHECK: module="AWS-LC FIPS 3.1.0" fips_mode=true config_fips=true
floor:  FIPS-CHECK: module=none fips_mode=false config_fips=false
```

The fields:
- `module`: the linked module's `awslc_version_string()`, read at runtime and quoted, or `none` on the floor build.
  This is `FipsStatus.module` (D2).
- `fips_mode`: `aws_lc_rs::try_fips_mode().is_ok()`.
- `config_fips`: `ServerConfig::fips()` of the config the boot path would build for the default cmvp profile, with
  no config file needed. monban-tls `fips_status(&cfg).config_fips`.

`--fips-check` must not bind sockets, read a config, or need certificates.

## `client-policy` (cmvp-client-policy)

This is a port of `spikes/cmvp-client-policy/fips_client_policy.py`. With `--mode`, only that mode is judged. The PASS
line is exactly `CLIENT-POLICY: PASS (compiled-out)` or `CLIENT-POLICY: PASS (pq-only)`. The ledger entries for 0349
and 0382 cite the compiled-out line as their `evidence_must`.

**Real run.** The gate passes `--binary target/cmvp/release/monban` and nothing else. The oracle then:
- re-prepares `target/cmvp-src` with `build.sh --metadata`;
- judges `-p monban-bin --features monban-bin/cmvp`;
- relinks inside the AL2023 image, with the same mounts, environment and cargo flags (`--locked --release
  --no-default-features`, `DOCKER_CARGO_FLAGS`) as `build.sh --check`. Keep the two in sync; the client-policy
  self-test checks the flags against build.sh's `flags=(...)` line. Without `--no-default-features` cargo passes
  `--cfg feature="default"` to monban-bin, its `-C metadata` (symbol hashes) changes, and R0 is ERROR
  (P6-oracle-fips-002, measured with `cargo build -v` vs `cargo rustc -v`).

**How the spike's strip=symbols problem is solved.** The shipped binary has no symbols. So the oracle relinks only
the final crate with `cargo rustc`, twice, into `target/cmvp/oracle-cmvp-binary/`. The dependency rlibs are reused.

- **Twin:** `-- -C strip=none -C link-arg=-Wl,-Map=twin.map` gives the unstripped twin. It is read with
  `nm -C --defined-only`.
- **Map:** `-- -C link-arg=-Wl,-Map=shipped.map` gives the shipped configuration plus a linker map.
- **R0:** the second relink must be byte-identical (sha256) to the judged binary. If it is not, the map is not
  evidence of the shipped link, and the result is ERROR.
- Each run uses fresh map paths, so cargo cannot treat the final crate as up to date and skip the link. The map
  file must exist afterwards; otherwise the run is ERROR. Without this, a skipped link would compare the binary with
  itself, and R0 would hold trivially.
- The judged binary is restored, and its sha256 re-checked.
- On the fixtures, R0 holds: see Results.

This is stronger than the spike, which read the map of a separately built stripped binary.

**Graph source.** M1 uses `cargo tree` (the real feature resolver). The source scans use the source directories of
the packages that `cargo tree` reports.

| id | mode | check |
|---|---|---|
| M0 | both | rustls is in the graph, else ERROR |
| M1 | A | No first-party package has `tls-client` (monban-tls, monban-egress) or `acme` (monban-ops) on. |
| B0 | both | Positive control: the twin has `rustls::server` symbols and the map has `6rustls6server` refs. A blind view (stripped and no map, or the wrong artifact) is ERROR. |
| B1 | A | 0 `rustls::client::` symbols in the twin (or in the unstripped `--binary`). A compiled-out PASS needs a symbol view. |
| B2 | A | 0 `6rustls6client` refs in the shipped-config map. A compiled-out PASS needs the map. |
| S1 | B | The clippy log (disallowed-methods/types as in `fixtures/clippy.toml`) has 0 disallowed hits and no `error` line. |
| S2 | B | Exactly one `#[expect/allow(clippy::disallowed_*)]` in first-party source, directly on `--blessed-fn` (default `pq_only_client_config`). |
| M2 | B | No unallowlisted third-party crate in the graph builds a `ClientConfig`. This is a source grep and a backstop. |
| P1 | B | At least one probe JSON. Each must show `kx_groups == [secp256r1MLKEM768]`; NoClientSessionStorage and Disabled; both hellos `[0x11EB]/[0x11EB]`; negotiation of SECP256R1MLKEM768; and on hello 2, no PSK or early data and an unchanged share. |
| C1 | both | Informational line `CLIENT-CERT: ...` (D13), described below. |
| C2 | both | FAIL if a WebPkiClientVerifier, or any `ClientCertVerifier` other than rustls' `NoClientAuth`, is constructed in source or linked, unless a live justification covers it. |

**C1 contents.** The `CLIENT-CERT:` line lists:
- the listener client-auth sites in first-party source (`with_no_client_auth(` and `with_client_cert_verifier(`);
- any client-cert verifier construction in the source of any package in the graph, rustls and webpki excepted;
- the `ClientCertVerifier` impls linked into the twin;
- the WebPkiClientVerifier symbol and map counts.

**C2 justification.** A justification is a live `[[mtls]]` entry in `mtls-justification.toml`, which is absent today.
The entry needs these fields:
- `verifier`;
- `advisory = "RUSTSEC-2026-0382"`;
- `reason`;
- `approver`;
- `expires`, which must not be in the past.

Exit codes: 0 PASS, 1 FAIL, 2 ERROR. `--json` dumps the full record.

## Fixtures (`fixtures/`, own workspace and lock; floor pins rustls 0.23.46 and aws-lc-rs 1.18.2)

- **From the spike, unchanged:** the spike's `tlsbins` (`srv_only`, `dead_client`, `pq_client`, `bad_client`,
  `bad_resume`), its lib, probe and clippy.toml.
- **Lock:** the spike's lock, plus the two fixture packages.
- **`mtls/` (`srv_mtls`):** a server whose listener uses `WebPkiClientVerifier`. It is a separate package, so its
  source does not contaminate the scan of `cmvp-fixtures`.
- **fips-binary stubs (`fips_*`):** no dependencies. They embed or omit the module string, and they print contract,
  floor or mutant `--fips-check` lines.

## Self-tests

Every case names the check id that must produce its verdict.

**`run --self-test`: 20 cases.**
- Baselines:
  - `fips_good` on the real cmvp graph passes;
  - `fips_floor` passes with `--expect floor`.
- Mutants:
  - floor judged as cmvp (F1);
  - good judged as floor (F1');
  - no contiguous string, with the right line assembled at runtime (F1);
  - string present but runtime `module=none` (F4), and the same binary as floor (F1');
  - string present but runtime `AWS-LC 4.2.0` (F4);
  - `fips_mode=false` mismatch (F4);
  - `--fips-check` not implemented (F4);
  - decoy `AWS-LC FIPS 2.0.0` (F2);
  - non-FIPS `AWS-LC 5.11.0` bytes (F2);
  - missing binary (ERROR);
  - 7 mutations of the real cmvp `cargo metadata` (F3 each): no fips-sys, two fips-sys, registry aws-lc-sys, a
    void crate with a build script, aws-lc-rs without `fips`, fips-sys off the pin, aws-lc-rs not linking fips-sys.

**`client-policy --self-test`.**
- **The spike's 12**, with the same expected verdicts. Cases expected FAIL by the spike in "neither mode" are run in
  both modes.
- **Cross-mode:** srv_only judged as pq-only, and pq_client judged as compiled-out.
- **Map, twin and R0:** a client map with a clean twin (B2), no map (B2), and a tampered judged binary (R0 ERROR).
- **D13:**
  - srv_mtls (C2);
  - srv_mtls with a live justification (PASS);
  - srv_mtls with an expired justification (C2);
  - verifier only in the binary (C2);
  - verifier only in the source (C2).
- **Real cmvp overlay graph (light):**
  - the M1 baseline (`monban-bin/cmvp`, no client feature);
  - three feature mutants (`monban-tls/tls-client`, `monban-egress/tls-client`, `monban-ops/acme`), each caught;
  - the D13 source baseline over every package in the real cmvp graph: no verifier construction.

## Results

See `units/phase-6/reports/P6-oracle-fips-001.md`. It has the self-test transcripts and the real-run results, which
are red until P6-cmvp-001.

## Limits

- **The fixtures are floor-profile.** The same oracle code runs on the cmvp tree, but the cmvp relink path (docker)
  is first exercised for real when P6-cmvp-001 produces a binary. The fixtures exercise the host relink path.
- **Absence of symbols and map refs means "not linked".** That over-approximates reachability, which is the safe
  direction. The source scans are greps:
  - they skip `//` lines, `tests.rs`, `*_tests.rs` and `tests/` dirs;
  - they miss construction done through macros;
  - they flag cfg'd-out code. That is conservative.
- **The probe server is well-behaved**, not an active attacker (spike limit).
- **pq-only on the real binary** needs a clippy log and probe JSON that monban does not produce today. The cmvp gate
  runs compiled-out.
- **The `/healthz` `module` field (D2) is not checked here.** It needs a booted server; conformance and the cmvp
  ClientHello gate boot one.

## Placement

`needs` = `kamrui`: the oracle is run by its own gates (`fips-binary`, `cmvp-client-policy`, both
`remote = "kamrui"`, where Go, docker and the AL2023 image live). No `ci/oracles.sh` aggregate runs it.
