# P6-cmvp-001 report (implementer with integrator permissions, 2026-11-04, base ad34280)

**Status: partial.** D15, D12 and D13 are done. The D2 runtime module string is INFEASIBLE under forbid(unsafe_code);
see P6-cmvp-001-INFEASIBLE.md. As a result, `--fips-check` and the FIPS-F1..F6 module halves are red, and they fail
closed.

## D15: ML-DSA behind `cfg(feature = "cmvp")`

- **aegis-tls `profile.rs`**
  - On cmvp, P-CNSA's status is `Pending`, so `server_config` returns `ProfileError::Pending` with the reason "P-CNSA
    requires ML-DSA-87, which the cmvp build ... does not have (PLAN-6 D15)".
  - On cmvp, P-UNIVERSAL and P-BSI-ALT sigalgs are `[ECDSA_NISTP384_SHA384]`.
  - FIPS-CMVP is `Active` only on cmvp. `server_config(FipsCmvp)` asserts P-PQ5 (`cmvp_claim`), otherwise it returns
    `Assertion`. Clients refuse FIPS-CMVP as they refuse FIPS (P-PQ6).
  - Floor behaviour is unchanged.
  - kx.rs: the KAT helpers are now cfg'd out under cmvp, because they were dead code and failed `clippy --all-targets`.
- **aegis-audit `note.rs`**
  - On cmvp, `MlDsa87NoteSigner` is uninhabited, and `from_seed`/`generate` return the new `NoteError::Unavailable`.
  - `NoteVerifier::parse` refuses ML-DSA-87 vkeys.
  - `pub const MLDSA87_COSIGN` is false on cmvp.
- **aegis-token `tier_x.rs`:** on cmvp, `verify_x` always returns `Err(VerifyError::Denied)`. The test
  `tier_x_denied_on_cmvp` checks this with a validly signed token and a known key.
- **tls-subject:** no ML-DSA credentials on cmvp. P-UNIVERSAL and P-BSI-ALT get ECDSA-P384, PQ-REQUIRED gets
  ECDSA-P256, and P-CNSA has none (its builder refuses it).
- **`[features]` added:**
  - `cmvp = []` in aegis-audit and aegis-token;
  - aegis-bin `cmvp = ["aegis-tls/cmvp", "aegis-audit/cmvp", "aegis-token/cmvp"]`.

## D2: FipsStatus, `--fips-check`, /healthz

- **`aegis_tls::fips_check()` and `fips_status()`**
  - `module` is `Some` only on cmvp with `config_fips` true.
  - `cmvp_claim` requires cmvp, `config_fips`, `module_fips_mode`, and an exact `AWS-LC FIPS 3.1.0`.
  - The comparison uses numbers, so no contiguous module literal is in our code.
  - The module source is `linked_module()`, which returns `None` (INFEASIBLE: no safe API exists).
- **`aegis --fips-check`:** prints `FIPS-CHECK: module=<"..."|none> fips_mode=<bool>` and exits 0 only on
  `cmvp_claim`.
- **/healthz `fips`:** gains `module` (null or the string), `cosign: "none"` and
  `cosign_mldsa87: "available"|"compiled-out"`. The bin configures no cosigner on either build.
- **Audit:** the event's `fips_status` stays the existing enum (cmvp/floor/none from `cmvp_claim`). Putting the module
  string into audit detail needs `crates/aegis-bin/src/serve.rs` or `audit.rs`, which are outside the write_scope.
  Not done; flagged.

## D12: `ci/cmvp-supply.sh` (fips-lock gate), DEVIATIONS X-16

- **vet:** runs `cargo vet --locked --output-format json` on the overlay tree with the root store unchanged, then
  `ci/vet-baseline.py --frozen-failures`, a new mode with these rules:
  - every unvetted crate:version, with its criteria, must be in `profiles/cmvp/vet-baseline.txt` (12 entries);
  - no entry may be added or changed after the freeze;
  - stale entries must be removed.
- **advisories:** runs `cargo audit --json --file profiles/cmvp/Cargo.lock`. Each reported advisory needs a live
  `advisory-accepted` entry for that crate, version and id, with evidence. These fail: an unlisted advisory, a yanked
  or non-advisory warning, an empty DB, or an empty lock.
  - Reported today: 0042, 0043, 0285, 0346, 0348, 0349, 0382.
- **Five new ledger entries:**
  - fips-sys 0042 and 0043;
  - rustls 0285, 0346 and 0348.

  0346 cites the client-policy log. The others cite fixed `CMVP-PREMISE ...: PASS` lines in
  `phase6-fips-lock-cmd.log`, which cmvp-supply.sh checks on every run:
  - no Rust caller of AWS-LC X509 verify / CRL flags;
  - no caller of `EVP_aes_*_ccm`;
  - no client-certificate verifier in the graph;
  - rustls resolved without `brotli`.

  The 0382 entry's reason now records the D13 server half.
- **gates/phase-6.toml fips-lock:**
  - `cmd ... && ci/cmvp-supply.sh`;
  - `selftest ... && ci/cmvp-supply.sh --self-test`.

## D13

There is no client-certificate verification on any listener. Evidence:
- the only `ServerConfig` builder is `aegis_tls::server_config`, which uses `.with_no_client_auth()`;
- no `WebPkiClientVerifier`, `ClientCertVerifier`, `with_client_cert_verifier` or `WebPkiServerVerifier` exists in
  crates/, subjects/ or apps/;
- there is no direct webpki use;
- the cmvp build has no rustls client (tls-client is off, and tls-subject's client mode is cfg'd out).

So 0382's path-building code is unreachable on cmvp. The premise holds, and no INFEASIBLE note is needed for D13. The
client-auth premise scan (9,181 Rust files in the cmvp graph, 0 hits) keeps checking this on every run.

## Commands and results

| command | result |
|---|---|
| `ci/remote.sh --host kamrui ... profiles/cmvp/build.sh` | `cmvp: BUILD PASS (release; outputs in target/cmvp/release/)`. aegis is 5,315,488 B and tls-subject 3,391,720 B. Each contains exactly 1 `AWS-LC FIPS 3.1.0` string. An earlier build had 2 strings, because my P-CNSA reason text contained the module string; the text was fixed and the string removed. |
| `target/cmvp/release/aegis --fips-check` | `FIPS-CHECK: module=none fips_mode=true`, exit 1 (**FAIL vs acceptance**, per INFEASIBLE) |
| tls-subject describe on cmvp | `fips=true module=` for FIPS, FIPS-PQ-REQUIRED, P-UNIVERSAL and P-BSI-ALT. P-CNSA and FIPS-CMVP exit 1 with their reasons. |
| `oracles/hrr-verdicts/run --require-cmvp --file tls/verdicts.toml --subject "target/cmvp/release/tls-subject subject"` | `HRR-VERDICTS: FAIL (diff=25)`: 6 FIPS-F1..F6 module halves (module=None) plus 19 P-CNSA diffs. Every PUB, UNI, BSI and FIPS selection check passes on cmvp. |
| `ci/remote.sh cargo test --workspace --locked -q` (floor) | every result line `ok`, 0 failed |
| cmvp-feature unit tests on the floor lock (`-p aegis-tls -p aegis-audit -p aegis-token --lib --features ...cmvp`) | 21, 11 and 18 passed, including `cmvp_refuses_cnsa_and_drops_mldsa`, `cmvp_fips_cmvp_requires_module_identity`, `cmvp_mldsa87_cosign_absent` and `tier_x_denied_on_cmvp` |
| clippy `-D warnings --all-targets`, 5 crates, floor and with all cmvp features | `FLOOR-CLIPPY-OK`, `CMVP-CLIPPY-OK`; `cargo fmt --check` clean |
| `ci/cmvp-supply.sh` | `CMVP-SUPPLY: PASS`: `VET-FROZEN ... PASS (12 unvetted crates ...; intake)`, 7 advisories ledgered, 4 premise lines |
| `ci/cmvp-supply.sh --self-test` | `VET-BASELINE SELF-TEST: PASS (... frozen mode 9/9 cases)`; `CMVP-SUPPLY SELF-TEST: PASS (17/17 mutants caught; ...)` |
| red on real inputs | 0043 entry id changed: `FAIL ... RUSTSEC-2026-0043 ...: no ledger entry`. `nom` line removed from the baseline: `FAIL nom:7.1.3: unvetted and not in the frozen baseline`. Stale line added: `FAIL zzz:1.0.0: no longer a vet failure`. All restored afterwards. |
| `cargo xtask fips-lock --profile cmvp` | PASS (unchanged) |
| `cargo xtask ledger-check` | parses all 34 entries. It fails only on missing evidence logs, as expected outside a gate run. |

## Open (integrator or spec author)

1. **D2 module string.** See P6-cmvp-001-INFEASIBLE.md (options A, B, C). It blocks `--fips-check`, FIPS-F1..F6 and
   the healthz/audit `module` field.
2. **Conflict between D15 and clienthello-cmvp.** F12 has P-CNSA `status = "active"`, so hrr-verdicts must serve it
   on every subject. D15 refuses P-CNSA on cmvp, which gives 19 diffs. One of these needs to change: F12 or the oracle
   needs a "not on cmvp" notion, or D15 needs a revision. I did not touch the oracle or F12.
3. **Audit event module string:** needs a serve.rs or aegis-bin/audit.rs edit, outside the write_scope.
4. **Observation:** P-UNIVERSAL and P-BSI-ALT report `fips=true` on cmvp, because P6-tls-001's 0x11ED `fips()` returns
   `try_fips_mode()`. The aegis-bin `FipsStatus` comes from the first listener, so a Universal-first config would
   report `config_fips` true.
5. **cli.rs USAGE** does not list `--fips-check`. cli.rs is outside the write_scope; it is documented in main.rs.
6. **Extra files outside the literal write_scope**, written under the coordinator's instruction:
   - aegis-token src (tier_x.rs, tests.rs);
   - tls-subject main.rs;
   - three manifests (`[features]` only);
   - ci/vet-baseline.py, ci/cmvp-supply.sh, profiles/cmvp/vet-baseline.txt, supply-chain/exceptions.toml,
     gates/phase-6.toml and DEVIATIONS.md.
