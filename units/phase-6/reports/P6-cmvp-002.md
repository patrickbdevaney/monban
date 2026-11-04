# P6-cmvp-002 report (spec author + implementer, integrator permissions; 2026-11-04, base main 76a1394)

**Status: done, except for two oracle-side issues outside this unit.** D16 (runtime module string) and D17 (P-CNSA
refused on cmvp, F12 re-frozen) are both in. Every acceptance command PASSes, except these two (items 5 and 6):
- `oracles/cmvp-binary/run` PASSes only with an absolute `--binary`;
- `oracles/cmvp-binary/client-policy` is ERROR at R0 on the real tree, and the message is reported verbatim. One deviation from the letter of D16: the dependency edge is
`aws-lc-rs`, not `aws-lc-fips-sys`, because literal option B turns three root supply gates red. Evidence follows.

## D16: module string through aegis-iso

### Finding: literal option B changes the ROOT lock and turns three root gates red

I measured option B as written: `aws-lc-fips-sys = { version = "=0.13.11", ... }` in `[workspace.dependencies]`,
plus `aws-lc-fips-sys = { workspace = true, optional = true }` and `cmvp = ["dep:aws-lc-fips-sys"]` in aegis-iso.

- An optional dependency that the floor never enables **still enters Cargo.lock**: cargo resolves the lock with
  every feature of every workspace member.
- `cargo metadata` added 11 packages to the root lock: aws-lc-fips-sys 0.13.11, bindgen 0.72.1, cexpr, clang-sys,
  glob, itertools 0.13.0, libloading, minimal-lexical, nom 7.1.3, prettyplease and shlex. No existing version
  changed, so lock-targets and lock-age still PASS.
- Root gates on kamrui with that lock:
  - `cargo audit --deny warnings`: RUSTSEC-2026-0042 and RUSTSEC-2026-0043 (aws-lc-fips-sys 0.13.11), "error: 2
    vulnerabilities found!";
  - `cargo vet --locked`: "Vetting Failed! 10 unvetted dependencies" (aws-lc-fips-sys, bindgen, cexpr, clang-sys,
    glob, itertools, libloading, minimal-lexical, nom, prettyplease). The root vet baseline cannot grow.
  - `cargo deny check`: "advisories FAILED".
- The 0042/0043 ledger entries are "cmvp lock only" by design. Making the root gates pass again would mean
  ledgering advisories for a crate the floor never compiles, and baselining 10 crates. That weakens the gates, so
  I did not do it.

### What was built instead (option B', no root third-party change)

- **aegis-iso**
  - `cmvp = ["dep:aws-lc-rs"]`, with `aws-lc-rs = { workspace = true, optional = true }`. aws-lc-rs is already in
    both locks: on the floor it is 1.18.2, on cmvp it is 1.15.3 with `fips`, which links aws-lc-fips-sys 0.13.11.
    The edge puts that library after aegis-iso in the link order.
  - New module `crates/aegis-iso/src/fips.rs`, `pub fn awslc_version_string() -> Option<&'static str>`. It has
    **2 audited sites**, so aegis-iso goes from 14 to 16 of 20:
    1. `unsafe extern "C" { #[link_name = "aws_lc_fips_0_13_11_awslc_version_string"] safe fn ...() -> *const c_char; }`.
       The `safe` declaration is sound because the C function takes no arguments and returns a static literal.
    2. `CStr::from_ptr` on the non-null result.
  - The link name is exactly the one aws-lc-fips-sys 0.13.11's bindgen output uses (checked in its `src/*_crypto.rs`;
    C source is `service_indicator.c:10`). Any other module leaves the symbol undefined, so the link fails closed:
    a fips-sys pin change, the 0.14.x / FIPS 4.2.0 decoy, or the floor's aws-lc-sys.
- **Root Cargo.lock and profiles/cmvp/Cargo.lock** (`build.sh --lock`) change only by workspace-internal edges:
  `aegis-iso -> aws-lc-rs` and `tls-subject -> aegis-iso`. No third-party package or version changes. The root
  `Cargo.toml` is unchanged.
- **aegis-tls** (still no aegis-iso dependency; `cargo xtask layering` PASS)
  - `fips_status(cfg)` is replaced by `fips_status_with(cfg, linked)`, and `fips_check()` by `fips_check_with(linked)`.
  - New `server_config_with(profile, resolver, linked)`. `server_config` is that function with `None`, so FIPS-CMVP
    built through it is refused (P-PQ5 fails closed).
  - The `linked_module()` None seam is removed.
  - `module` is reported only on cmvp with `config_fips` true, as before.
  - `fips_check_with` now reports `config_fips` as `ServerConfig::fips()` of the FIPS-CMVP config. That is false
    when the config is refused: on the floor it is pending, and on cmvp P-PQ5 refuses it without the exact identity.
  - Tests:
    - the floor test checks that a passed string is ignored;
    - the cmvp test drives `None`, `4.2.0` and `3.1.0` through `server_config_with`.
- **aegis-bin**
  - `cmvp` feature adds `dep:aegis-iso` and `aegis-iso/cmvp`.
  - New `tls::linked_module()`: aegis-iso on cmvp, `None` on the floor. It is used by `Tls::build`
    (`server_config_with` + `fips_status_with`) and by `--fips-check`.
  - `--fips-check` follows the oracles/cmvp-binary F4 contract:
    - output is `FIPS-CHECK: module=<"..."|none> fips_mode=<try_fips_mode ok> config_fips=<bool>`;
    - it always exits 0;
    - it is listed in `cli::USAGE`.
  - `/healthz` already prints `fips.module`. It now carries the real string, because `Tls.fips` comes from
    `fips_status_with`.
  - Every audit event (admin and `p2.data_run`) gets detail `fips_module = <string>` when a module is reported, in
    `audit.rs` (`Auditor::module_detail`). There is no detail on the floor. serve.rs needed no change.
- **tls-subject**
  - `cmvp` feature adds `dep:aegis-iso` and `aegis-iso/cmvp`.
  - `build` uses `server_config_with` and `describe` uses `fips_status_with`, both with the aegis-iso string. P-CNSA
    is still refused with the D15 reason.
  - The `interop` feature from P6-tls-002 is untouched: default `interop`; cmvp is built `--no-default-features`.

## D17: F12 re-frozen, oracle

- **tls/verdicts.toml**
  - New amendment block in the header.
  - New section "Profile fields added by D17" defines `requires` (profile-level, only `"floor"`) and `cmvp` (only
    `"refused"`, and only together with `requires = "floor"`).
  - `[profiles.P-CNSA]` gets `requires = "floor"` and `cmvp = "refused"`. No `[[verdict]]` row changed.
  - Re-frozen with `python3 -I ci/interfaces.py freeze` in this commit (INTERFACES: PASS, 16 files).
- **oracles/hrr-verdicts**
  - Both fields load and are validated at load time.
  - Under `--require-cmvp`, a `cmvp = "refused"` profile gets one check, `PROFILE <p> cmvp refused`, which needs
    both of these:
    - `describe` fails with a reason (External now carries the subject's stderr);
    - a hello for the profile's first group gets neither a ServerHello nor an HRR.
  - That profile's verdict and supplementary rows are skipped with an `info ... judged on the floor build only` line.
  - Without the flag nothing changes. The floor gate is unchanged: 166 checks, 6 cmvp-module SKIPs as before.
- **Self-test**: 23 mutants become 27.
  - The positive control (cmvp identity) now also refuses P-CNSA. It is checked in process and through the external
    hook.
  - New mutants:
    - `require-cmvp:cmvp-serves-cnsa` and `external:require-cmvp:cmvp-serves-cnsa`: a cmvp-identity subject that
      still serves P-CNSA;
    - `verdict-file:P-CNSA-cmvp-refused-dropped`: 19 diffs against the refusing subject;
    - `verdict-file:P-CNSA-refused-without-requires-floor`: LOAD.
  - The README is updated.

## Acceptance (commands run; result lines)

| command | result |
|---|---|
| `ci/remote.sh --host kamrui bash -c 'profiles/cmvp/build.sh && target/cmvp/release/aegis --fips-check'` | `cmvp: BUILD PASS (release; outputs in target/cmvp/release/)`; `FIPS-CHECK: module="AWS-LC FIPS 3.1.0" fips_mode=true config_fips=true`, rc=0 |
| `... oracles/cmvp-binary/run --binary target/cmvp/release/aegis` | with the absolute path `--binary ~/aegis-ci/repo-1727f7b9e25b/target/cmvp/release/aegis`: `CMVP-BINARY: PASS (module "AWS-LC FIPS 3.1.0" contiguous, sole identity, one fips-sys node, --fips-check matches)`. **With the relative path from the brief or gate, FAIL**: F4 `cannot execute: [Errno 2] No such file or directory: 'target/cmvp/release/aegis'`. The oracle runs the binary with cwd `/` without absolutizing `--binary` (open item 5). F1 shows 1 contiguous `AWS-LC FIPS 3.1.0`, and F3 shows 0 violations. |
| `... oracles/cmvp-binary/client-policy --mode compiled-out --binary target/cmvp/release/aegis` | **ERROR** (oracle unchanged, as instructed): `CLIENT-POLICY: ERROR (R0: relink of the shipped configuration is not byte-identical to the judged binary (8bb3dc00d2084f53 != ba7e8c30aa358458): its map is not evidence)`. Before that line: `graph: rustls in graph True; client features on []`. Diagnosis in open item 6. |
| `... oracles/hrr-verdicts/run --require-cmvp --file tls/verdicts.toml --subject "target/cmvp/release/tls-subject subject"` | `ok   PROFILE P-CNSA cmvp refused (describe: ... exit status: 1: P-CNSA: profile P-CNSA is pending: P-CNSA requires ML-DSA-87, which the cmvp build ... does not have (PLAN-6 D15) ...; serve -> other:first record Some([]))`; `HRR-VERDICTS: PASS (25 verdicts selection-checked, diff=0; 152 checks; 0 cmvp-module halves SKIPPED: -)`. No SKIP lines, and FIPS-F1..F6 module halves are ok. |
| tls-subject cmvp `describe FIPS` / `FIPS-CMVP` / `P-CNSA` | `fips=true module=AWS-LC FIPS 3.1.0` (FIPS-CMVP now boots); P-CNSA exit 1 with the D15 reason |
| `strings`: contiguous `AWS-LC FIPS 3.1.0` in aegis and in tls-subject | 1 and 1 |
| `oracles/hrr-verdicts/run --self-test` (with and without `--require-cmvp`) | `HRR-VERDICTS SELF-TEST: PASS (27/27 mutants caught; baseline, external hook and --require-cmvp control clean)` |
| tls-verdicts floor gate (`--subject 'target/release/tls-subject subject'`) | `HRR-VERDICTS: PASS (25 verdicts selection-checked, diff=0; 166 checks; 6 cmvp-module halves SKIPPED: FIPS-F1,...,FIPS-F6)`, unchanged from before this unit |
| floor `target/release/aegis --fips-check` / `oracles/cmvp-binary/run --expect floor` | `FIPS-CHECK: module=none fips_mode=false config_fips=false`, rc=0; `CMVP-BINARY: PASS (floor negative control: no FIPS identity, --fips-check module=none)` with an absolute `--binary` |
| `ci/remote.sh cargo test --workspace --locked -q` (floor; rerun with `--no-fail-fast`) | 114 `test result: ok` lines, no FAILED. A first run hit a one-off failure of `aegis-ops drain::tests::accept_loop_stops_and_serves`; see open item 4. |
| clippy `-D warnings`: floor `--all-targets` (aegis-iso, aegis-tls, aegis-bin, tls-subject default, aegis-audit, aegis-token); cmvp features (`aegis-iso/cmvp,aegis-tls/cmvp` lib; tls-subject `--no-default-features --features cmvp`; aegis-bin `--features cmvp`) | `FLOOR-CLIPPY-OK`, `CMVP-LIB-CLIPPY-OK`, `SUBJ-CMVP-CLIPPY-OK`, `BIN-CMVP-CLIPPY-OK`; `aegis-tls --lib --features cmvp`: 11 passed |
| `cargo xtask unsafe-sites` | `aegis-iso 16/20 ... UNSAFE-SITES: PASS` |
| `cargo xtask layering` / `lock-targets` / `lock-age --min-days 7` / `fips-lock` / `fips-lock --profile cmvp` | all PASS |
| `ci/cmvp-supply.sh` / `--self-test` | `CMVP-SUPPLY: PASS ...`; `CMVP-SUPPLY SELF-TEST: PASS (17/17 mutants caught ...)` |
| root `cargo audit --deny warnings`, `cargo vet --locked` + `ci/vet-baseline.py`, `cargo deny check` (final tree, kamrui) | 0 vulnerabilities; `Vetting Succeeded`; `VET-BASELINE: PASS`; `advisories ok, bans ok, licenses ok, sources ok` |
| `cargo fmt --check`; `python3 -I ci/interfaces.py check` | clean; `INTERFACES: PASS` |

## Open / for the integrator

1. **D16 wording.** PLAN-6 D16 says "optional dependency on aws-lc-fips-sys". What shipped is an optional edge on
   aws-lc-rs plus a fixed 0.13.11 `link_name` (the evidence above shows why). The site count (2) and the data flow
   are as D16 describes. PLAN.md is not in my scope, so the amendment is yours. A reverse-if: if aws-lc-fips-sys ever
   enters the root lock legitimately, switch to `aws_lc_fips_sys::awslc_version_string`.
2. A cmvp-feature build of aegis-bin or tls-subject on the **floor** lock now fails to *link*, because the 0.13.11
   symbol is absent. That is by design (fail closed). Clippy and `--lib` tests on the floor lock are unaffected.
3. P6-cmvp-001 open item 4 still stands: `FipsStatus` in aegis-bin comes from the first listener.
4. A flake was seen once: `aegis-ops drain::tests::accept_loop_stops_and_serves` failed in one desktop workspace run.
   It passed 3/3 in isolation and in the full `--no-fail-fast` rerun. It is unrelated to this unit, since aegis-ops is
   untouched.
5. **oracles/cmvp-binary `--binary` relative path.** `run` executes the binary with cwd `/` and does not resolve
   `--binary` first. So the gate's own command, `oracles/cmvp-binary/run --binary target/cmvp/release/aegis`, is red
   at F4 ("No such file or directory"). The same happens for `--expect floor`. With an absolute path both PASS. The
   fix belongs in the oracle (resolve the path before the `cwd="/"` run, `fips_binary.py:96`). Not touched here.
6. **cmvp-client-policy R0 ERROR on the real tree** (exact message in the table).
   - The relink is deterministic: the same `8bb3dc00...` on two runs.
   - The judged binary is reproducible: the same `ba7e8c30...` from a combined aegis-bin + tls-subject build and from
     `CMVP_PACKAGES=aegis-bin profiles/cmvp/build.sh` alone. So the mismatch is **not** feature unification with
     tls-subject (or with this unit's tls-subject -> aegis-iso edge).
   - The cause is a difference between the oracle's `cargo rustc -p aegis-bin --bin aegis --features aegis-bin/cmvp
     -- -C link-arg=-Wl,-Map=...` relink and `build.sh`'s `cargo build --locked --keep-going --no-default-features
     -p aegis-bin --features aegis-bin/cmvp --release`.
   - Both `.text` and `.rodata` differ (`twin_sections_identical` false). The oracle's README says to keep the two in
     sync. Left for the oracle owner (P6-oracle-fips-001).
