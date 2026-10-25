# hrr-verdicts: TLS group-selection / HRR verdict oracle (F12)

Runs real in-memory rustls handshakes for every verdict in `tls/verdicts.toml` (frozen interface F12) and diffs
what it observes against what the file expects.

```
oracles/hrr-verdicts/run [--file tls/verdicts.toml] [--subject "CMD ARGS"] [--require-cmvp]
oracles/hrr-verdicts/run --self-test [--file tls/verdicts.toml]
```

Last line `HRR-VERDICTS: PASS (...)` iff diff == 0, exit 0 only on PASS. The default file is `<repo>/tls/verdicts.toml`;
a relative `--file` resolves against the caller's cwd (so both `run --file ../../tls/verdicts.toml` from here and the
phase gate's `oracles/hrr-verdicts/run --file tls/verdicts.toml` from the repo root work).
`run` builds through `ci/heavy.sh` (machine-wide lock, 6 GB cap) with `CARGO_TARGET_DIR=oracles/hrr-verdicts/target`,
then runs the binary directly (a run is a few hundred ms of in-memory handshakes). Delete `target/` after measuring.

## What is checked (spec/SPEC_INVARIANTS.md section F)

| check | clause | how |
|---|---|---|
| `MODEL` | Select(model) | every verdict and probe-supplementary expectation equals the spec's selection model applied to the profile's `kx_groups` and `selector` (client-order today). Subject-independent: catches a verdict file that contradicts the spec. |
| `VERDICT PUB-T1..T6, FIPS-F1..F6` | P-PQ1, P-PQ2, Select | hand-built TLS 1.3 ClientHello (exact groups, key shares and sigalgs from the row; real freshly-generated X25519 / P-256 / P-384 / ML-KEM public values) sent to the subject; the first server record is classified as HRR(group) / ServerHello(group) / alert(code) and compared. |
| `VERDICT FIPS-Fn cmvp-module` | P-PQ5 | needs the subject to report `fips=true` and `module=AWS-LC FIPS 3.1.0`. The floor build reports `fips=false`, so this half prints `SKIP ... (reason)` and is listed in the PASS line; with `--require-cmvp` a SKIP is a FAIL. Never silently passed. |
| `PROFILE <p> kx_groups / versions / early_data` | P-PQ2 (configured set = profile, order included because `kx_groups[0]` is a startup assertion), P-PQ4 | subject `describe` vs the profile row. |
| `PROFILE <p> P-PQ1 classical-only <g>` | P-PQ1 | for every profile whose list has no classical group: X25519-only, P-256-only, P-384-only hellos must all get alert 40. |
| `PROFILE <p> P-PQ2 group / certificate_verify` | P-PQ2 | full handshake with a real rustls client offering every sigalg in `[codepoints.sigalgs]`; the CertificateVerify scheme (observed client-side, signature verified) must be in the profile's `sigalgs`. |
| `SUP-1..5` | P-PQ1, P-PQ2, Select | supplementary rows (cited by id, not part of the 12): full handshakes with real clients (T7, T8, FIPS HS A) and two extra FIPS probes (X25519MLKEM768-only refused; P-256-first gap). |

Profiles with `status = "pending"` (P-UNIVERSAL, P-BSI-ALT, P-CNSA) are listed in F12 but not checked: 0x11ED is
AEGIS-owned Phase-6 code, and P-CNSA has no frozen verdicts yet.

## Self-test (`--self-test`)

Baseline (unmutated reference) must be clean, then each mutant must produce at least one diff:

| mutant | what it simulates | caught by |
|---|---|---|
| `pq-required-x25519-first` | PQ-REQUIRED configured `[X25519, X25519MLKEM768]` | PUB-T3, PUB-T4, P-PQ1 sweep, kx_groups, SUP-1 |
| `prefer-post-quantum-off` | P-PUBLIC-WEB built from `default_provider()` without the feature (`[X25519, P-256, P-384, X25519MLKEM768]`) | **only** the kx_groups static check (see limits) |
| `sigalg-not-in-profile` | PQ-REQUIRED served with an ML-DSA-65 certificate | P-PQ2 certificate_verify, SUP-1 |
| `pq-required-classical-fallback` | PQ-REQUIRED `[X25519MLKEM768, X25519]` | PUB-T3, PUB-T4, P-PQ1 sweep, kx_groups |
| `public-no-hybrid` | P-PUBLIC-WEB `[X25519, P-256]` | PUB-T1, T5, T6, kx_groups, P-PQ2 group |
| `fips-x25519mlkem768-added` | FIPS list with X25519MLKEM768 first | FIPS-F5, F6, SUP-3, kx_groups |
| `tls12-and-0rtt-on-pq-required` | TLS 1.2 + 0-RTT enabled on PQ-REQUIRED | versions, early_data (P-PQ4) |
| `verdict-file:PUB-T4-expect-server_hello` | a weakened verdict row | MODEL and VERDICT diff against a correct subject |
| `external:pq-required-classical-fallback` | the same mutant served through the `--subject` stdio hook | proves the hook path is not vacuous (a clean external run must also be diff 0) |
| `require-cmvp-on-floor-build` | `--require-cmvp` against the floor build | cmvp SKIPs become diffs |

## Subject interface (`--subject`)

Until `aegis-tls` exists the oracle uses a built-in reference profile builder whose lists are written in code from
ARCHITECTURE.md 3.2 (independently of the verdict file). The real builder plugs in as an external command, without
editing the oracle:

```
--subject "CMD ARGS..."      (split on whitespace, no shell)
CMD ARGS describe <PROFILE>  -> exit 0, stdout key=value lines:
     kx_groups=0x11ec,0x11eb,0x001d,0x0017   (configured order, hex codepoints)
     versions=TLS13                           (comma list: TLS13, TLS12)
     early_data=false                         (max_early_data_size > 0)
     fips=false                               (ServerConfig::fips())
     module=                                  (FIPS module string linked into the binary, e.g. AWS-LC FIPS 3.1.0)
CMD ARGS serve <PROFILE>     -> one TLS server connection for that profile over stdin (client->server bytes) and
                                stdout (server->client bytes), flushing after each read; exit on EOF or after a
                                fatal alert has been written. Diagnostics go to stderr.
```

Profiles that must be served: every `status = "active"` or `"cmvp-pending"` profile in the file (P-PUBLIC-WEB,
PQ-REQUIRED, FIPS, FIPS-PQ-REQUIRED). The expected implementation is a thin `aegis-tls` test binary
(e.g. `aegis-tls-subject`) wrapping `aegis_tls::profile::server_config(Profile, CredentialSelector) -> ServerConfig`;
it should report `kx_groups` from the built `CryptoProvider` (not from the profile constant) so that a builder bug is
visible. The oracle's own binary implements the protocol (`target/debug/hrr-verdicts subject [--mutate M] ...`) and
the self-test runs through it, so the hook is exercised on every self-test.

## Pass criterion

diff == 0 over all MODEL, PROFILE, VERDICT and SUP checks; the PASS line names every SKIPPED cmvp-module half.
Exit 0 only on PASS. Gate: `oracles/hrr-verdicts/run --file tls/verdicts.toml` (IMPLEMENTATION_PLAN §5 `verdicts`;
SUPPLY_CHAIN row 21: identical on every rustls / aws-lc bump).

## Versions (Cargo.toml / Cargo.lock in this directory)

rustls =0.23.46 (features aws_lc_rs, std, tls12, prefer-post-quantum), aws-lc-rs =1.18.2 (aws-lc-sys 0.46.0),
rcgen =0.14.10 (certificates generated at start-up: ECDSA-P256, ML-DSA-44, ML-DSA-65).
Substitutions for the 7-day publish cooldown on 2026-10-25: **rustls-webpki 0.103.15** instead of the 0.103.16 lock
target (published 2026-10-20; the oracle accepts any server chain on purpose, so RUSTSEC-2026-0382, fixed in .16, is
irrelevant here); build deps **cc 1.8.0** (1.10.0 published 2026-10-23) and **find-msvc-tools 0.1.14** (0.1.15,
2026-10-19). Every other locked crate was published on or before 2026-10-16.

## Provenance (research, untrusted; read, never executed in place)

| file under research/state/raw/ | sha256 | used for |
|---|---|---|
| round-003/03-work/hrr_acceptance_test.rs | ea483e10c2656eb04e34901507bda8c89a507adc9ffdd43315cebd13e02c14d9 | ClientHello shape, HRR classifier, PUB-T1..T5 bodies |
| round-003/03-work/run1.txt | d394ef36a0912962c13061a7acefcf13d085ab087a71c3a8f53370328b31ad78 | PUB-T1..T6 + T7/T8 observed results |
| round-003/03-work/pqauth/src/main.rs | 90fcb09a5f5cb5e37e8352f66f0db9c34634105caa19ef2f6434639e7c38dc9e | T1..T6 table (server "default" = default_provider, ECDSA-P256), real P-256 point |
| round-003/03-work/pqauth/Cargo.toml | 4355fff9b0b285f9864b1be3dcd08962e14eefaaf16bfc6d19aaace8f3fe85dd | research pins |
| round-003/03-work/main_config.rs, main_hs.rs | bc4ea38f…2002f, 860b25dc…dbdad | rustls main `KeyExchangeSelector` / `PreferServerOrder` (future `selector = "server-order"`) |
| round-003/03-pq-authentication-and-hrr-acceptance.json | 15dfb73919edab4d84df0204b435e7a3479f63986f4a0d94d1654123b9b6bb2d | node r3pq.hrr-acceptance-test |
| round-004/03-work/fips_probe_main.rs | 76f52bb81e5961448f3db60d72787e85ac1548af467bee9274988bd438e6c953 | FIPS probes 1..10, HS A..F |
| round-004/03-work-probe_fips_0.13.11.txt | 3aa9959d7ca9b3800f0d2b7ef6519a4d4967490013b38733d749acc72a8ba88a | FIPS-F1..F6 = PROBE 3, 4, 1, 2, 7, 8; SUP-3 = PROBE 6, SUP-4 = PROBE 5, SUP-5 = HS A |
| round-004/03-fips-golden-version-triangle-one-lock.json | f99fd09591f1f13036bb157403e08fed3ff267bf7d08e73c1f2d975c1cec20b2 | node r4tri.fips-handshake-verdicts |
| round-004/03-work/fips_lock_gate.py | f6d293fb2fb94b2aa33bbea5bc997ff5c29fa514e5a1594904227dbe01b714f6 | spec for `cargo xtask fips-lock` (below) |

Deviations from the research harness: the public server is the P-PUBLIC-WEB list `[0x11EC, 0x11EB, X25519, P-256]`
instead of `default_provider()` `[0x11EC, X25519, P-256, P-384]` (no verdict touches the difference); PQ-REQUIRED is
served with ML-DSA-44 instead of ECDSA-P256; key shares are real public values instead of `0x42` filler for
X25519 / ML-KEM; SNI is always sent. The research did not number the FIPS verdicts; the F1..F6 mapping above is
assigned in `tls/verdicts.toml` and frozen there.

## Re-run in repo

See the final section of this file (`Run log`), updated by the porter after each measured run.

## Known limits

- **Client-order selection makes server list order invisible to handshakes.** Under rustls 0.23.46 the server picks
  the first *client*-listed group it supports, so reordering a profile (e.g. `prefer-post-quantum` off) changes no
  verdict; only the static `kx_groups` check (subject self-report) catches it. Once the PreferServerOrder backport
  lands, `selector = "server-order"` makes the order behavioural (PUB-T2 flips: a deliberate verdict change).
- The static checks trust the subject's `describe`; the behavioural checks (verdicts, P-PQ1 sweep, sigalg handshake)
  do not.
- FIPS verdicts are selection-checked on the non-FIPS floor provider. The research reports identical verdicts on
  FIPS 3.1.0 and 4.2.0 builds; the module half (config.fips(), module identity) is SKIPPED until a cmvp build exists
  (needs Go + the FIPS module build, and Amazon Linux 2023 for approved mode).
- 0x11ED (P-UNIVERSAL, P-BSI-ALT, P-PUBLIC-WEB target list) cannot be exercised: not in rustls. Phase-6 gate.
- P-PQ3 (ticket scope), P-PQ6 (cmvp client policy) and 0-RTT behaviour are not exercised here.
- One host, in-memory transport; no network, no interop against other TLS stacks.

## Spec for `cargo xtask fips-lock` (ported from research fips_lock_gate.py)

The research gate runs over `cargo metadata --locked --format-version 1` (resolve graph with per-node features),
not over `Cargo.lock` text. Checks, each PASS/FAIL, exit 1 if any FAIL:

- **G1** every `rustls` node in the resolve graph has feature `prefer-post-quantum` (server and outbound clients);
  no rustls node at all is a FAIL. Both profiles.
- **G2a** (cmvp) exactly one `aws-lc-fips-sys` node (a second one is the decoy: per-version `links` keys let cargo
  resolve 0.13.11 and 0.14.3 side by side).
- **G2b** (cmvp) the set of `aws-lc-fips-sys` versions that `aws-lc-rs` actually depends on == {`CMVP_FIPS_SYS`
  = 0.13.11}.
- **G3** (cmvp) every `aws-lc-rs` node in [1.15.2, 1.17.1] (1.17.2 yanked and does not build with fips-sys <=0.13.15;
  1.17.3+ need fips-sys >=0.13.16).
- **G4a/G4b** (both) every rustls >= `RUSTLS_FLOOR` (0.23.46) and every rustls-webpki >= `WEBPKI_FLOOR` (0.103.16).
  In the cmvp profile this is *expected* to fail today (that is the triangle, `r4tri.no-co-resolvable-lock`); the
  gate reports it rather than hiding it, and the exception ledger must cite it.
- **G5** (floor) any `aws-lc-fips-sys` linked from aws-lc-rs must not be below 0.13.13 (0.13.11/.12 carry
  RUSTSEC-2026-0042/0043) -> "uncertified-lineage" report.
- **G6** (`--binary PATH`) the set of `AWS-LC FIPS x.y.z` strings in `strings -a` of the release binary is exactly
  {`CMVP_MODULE_VERSION` = 3.1.0} in cmvp (in floor: exactly one string).
- Constants overridable by env: CMVP_FIPS_SYS, CMVP_MODULE_VERSION, RUSTLS_FLOOR, WEBPKI_FLOOR.

### Checks in the research gate that `xtask fips-lock` (xtask/src/main.rs, 2026-10-25) does not implement

1. **G1 prefer-post-quantum on every rustls node**: absent from fips-lock and from every other xtask command (no
   occurrence of `prefer-post-quantum` in xtask). Cannot be done from `Cargo.lock` text, which has no features:
   needs `cargo metadata`.
2. **G2b version of the fips-sys node that aws-lc-rs links**: xtask checks only that *some* aws-lc-rs dep line
   starts with `aws-lc-fips-sys`, and that the (first) fips-sys node equals the pin. Equivalent today only because
   G2a (exactly one node) is also enforced; with multiple aws-lc-rs nodes it checks `any`, the research checks the
   set.
3. **G3 aws-lc-rs window [1.15.2, 1.17.1]**: replaced by the exact pin `aws-lc-rs = "1.15.3"` in
   `profiles/cmvp/pins.toml`; the window (and the 1.17.2-yanked rationale) is lost if the pin is edited. Also only
   the first aws-lc-rs node is compared to the pin (`find`), not every node.
4. **G4 rustls / webpki floors and the triangle report**: not in fips-lock (lock-targets checks equality for the
   golden lock only, not `>=` floors, and never the cmvp lock).
5. **G5 floor profile uncertified-lineage check**: no `floor` profile exists (`profiles/` has only `cmvp`).
6. **G6 binary module string `AWS-LC FIPS 3.1.0`**: no `--binary` option; module identity (P-PQ5) is unchecked.
7. Input source: xtask reads `profiles/cmvp/Cargo.lock` text and **passes vacuously-red only because pins are
   absent** when that lock does not exist yet; it does not run `cargo metadata --locked`, so it cannot see features
   or detect a lock that does not match the manifest.
8. Self-test has one mutant (decoy 0.14.3 appended); the research shape suggests also: rustls node without
   prefer-post-quantum (G1), aws-lc-rs 1.17.2 (G3), binary carrying `AWS-LC FIPS 4.2.0` (G6).

xtask has one check the research gate lacks: it rejects a non-FIPS `aws-lc-sys` node in the cmvp lock.

## Run log

2026-10-25, porter, laptop (i9-14900HX), via ci/heavy.sh; rustls 0.23.46, aws-lc-rs 1.18.2, aws-lc-sys 0.46.0,
rustls-webpki 0.103.15, rcgen 0.14.10 (cc 1.8.0, find-msvc-tools 0.1.14); verdict file sha256 prefix 564e8ab57983edb6.

- build: 13 s wall, peak RSS 0.39 GB; `target/` 110 MB (dev profile, debug = 0); deleted after the run.
- `run --file ../../tls/verdicts.toml` -> `HRR-VERDICTS: PASS (12 verdicts selection-checked, diff=0; 53 checks;
  6 cmvp-module halves SKIPPED: FIPS-F1,FIPS-F2,FIPS-F3,FIPS-F4,FIPS-F5,FIPS-F6)`. All 12 verdicts and SUP-1..5
  reproduce the research observations (run1.txt T1..T8; probe_fips_0.13.11.txt PROBE 1..8, HS A) on this lock.
- `run --subject "<target>/debug/hrr-verdicts subject"` (stdio hook) -> same PASS line.
- `run --self-test` -> `HRR-VERDICTS SELF-TEST: PASS (10/10 mutants caught; baseline and external hook clean)`;
  `prefer-post-quantum-off` caught by 1 diff only (PROFILE kx_groups), as expected under client-order selection.
