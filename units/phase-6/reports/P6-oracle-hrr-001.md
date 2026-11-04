# P6-oracle-hrr-001 report (spec author, 2026-11-04, base 875f42c)

## Built (oracles/hrr-verdicts only)
- **F12 vocabulary**
  - `offer_versions`: parsed, and written on the wire as `supported_versions`.
  - Profile field `sigalg_cover`.
  - Load-time rules: version names, non-empty, no duplicates; no row may negotiate TLS 1.2; sigalg_cover all-or-none.
- **MODEL** runs the three steps in order:
  1. version admission (alert 70);
  2. sigalg admission (alert 49);
  3. `select` (client- or server-order; alert 40, HRR or ServerHello).
- **0x11ED in the oracle** (`src/kx11ed.rs`): written from RFC 10024 §4, independent of aegis-tls.
  - The probes already sent real P-384 ‖ ML-KEM-1024 shares (97 + 1568 bytes).
  - The reference subject now serves 0x11ED, and the full-handshake client offers it.
- **Reference subject**
  - P-PUBLIC-WEB is `[0x11EC, 0x11ED, 0x11EB, X25519, P-256]`.
  - P-UNIVERSAL (ML-DSA-87 + ECDSA-P384), P-BSI-ALT (ECDSA-P384 + ML-DSA-87) and P-CNSA (ML-DSA-87).
  - A profile-filtered cert resolver: None, and so alert 49, when no offered scheme is both in the profile and signable.
- **New per-profile checks:**
  - `group-set <g>`: each codepoint group offered alone must get ServerHello iff it is in kx_groups, otherwise 40. This is a behavioural check of P-PQ2.
  - `sigalg-admission`: profiles with sigalg_cover get 49 when only out-of-profile sigalgs are offered.
  - `version-admission`: a TLS 1.2-only hello gets 70.
- **`--require-cmvp`**: FAIL unless the subject reports `fips=true` and `module=AWS-LC FIPS 3.1.0` exactly.
  - The self-test adds a positive control: a subject reporting 3.1.0 must pass with diff 0 and 0 SKIPs.
  - The self-test accepts `--require-cmvp`, as the clienthello-cmvp selftest calls it.
- **README** updated:
  - check table, the 25 verdict ids, the gov-profile subject requirements, the 23-mutant table and the run log;
  - a Phase-6 status note on the fips-lock G-list (items 1-8), naming the owner units and how `--require-cmvp` complements G6.

## Self-test: 23/23 mutants red, baseline clean
The 4 mutants from the unit file are all red:

| mutant | caught by |
|---|---|
| `universal-accepts-x25519` | UNI-T3, P-PQ1 sweep, group-set, kx_groups |
| `universal-picks-11eb` | UNI-T2 (got server_hello 0x11EB), group-set, kx_groups |
| `cnsa-accepts-11ed` | CNSA-T2, group-set, kx_groups |
| `require-cmvp:reports-fips-module-none` (and its external-hook variant) | 6 FIPS cmvp-module FAILs |

Also added:
- `cnsa-ecdsa-p384-unfiltered`, `cnsa-tls12-enabled`, `public-no-11ed`;
- `require-cmvp:reports-module-4.2.0`;
- the verdict-file mutants `UNI-T5-expect-alert-40` (MODEL), `UNI-T1-partial-sigalg-cover` (LOAD) and `CNSA-T4-against-tls12-profile` (LOAD);
- `external:universal-accepts-x25519`.

The original 10 mutants are still red.

## Commands run
- `ci/remote.sh bash -c "ci/heavy.sh cargo build --release --locked -q -p tls-subject && ci/heavy.sh oracles/hrr-verdicts/run --self-test; oracles/hrr-verdicts/run --self-test --require-cmvp; ci/heavy.sh oracles/hrr-verdicts/run --file tls/verdicts.toml --subject 'target/release/tls-subject subject'"` (desktop):
  - `HRR-VERDICTS SELF-TEST: PASS (23/23 mutants caught; baseline, external hook and --require-cmvp control clean)`, both with and without the flag.
  - Gate: `HRR-VERDICTS: FAIL (diff=60: ...)`, exit 1, which is the expected red:
    - 58 diffs on UNI/BSI/CNSA: tls-subject refuses them as Pending, so `describe` exits 1 and `serve` writes nothing.
    - 2 diffs on P-PUBLIC-WEB: 0x11ED is missing from kx_groups, and a 0x11ED-only hello gets 40.
    - PUB-T1..T6, FIPS-F1..F6 and SUP-1..5 are all ok.
- Laptop, built-in reference: `HRR-VERDICTS: PASS (25 verdicts selection-checked, diff=0; 166 checks; 6 cmvp-module halves SKIPPED: FIPS-F1,...,FIPS-F6)`.

## What P6-tls-001 must provide (tls-subject + aegis-tls)
There are no new CLI flags. The protocol stays `tls-subject [subject] describe|serve <PROFILE>`.

1. `Profile::Universal`, `BsiAlt` and `Cnsa` must not be Pending: `server_config` must build them.
2. `describe` must report `kx_groups` read from the built provider:
   - P-UNIVERSAL `0x11ed`
   - P-BSI-ALT `0x11ed,0x11eb`
   - P-CNSA `0x0202`
   - P-PUBLIC-WEB `0x11ec,0x11ed,0x11eb,0x001d,0x0017`

   All four also report `versions=TLS13` and `early_data=false`.
3. Credentials, which tls-subject currently generates only for ECDSA-P256 and ML-DSA-44:
   - P-UNIVERSAL and P-BSI-ALT: ML-DSA-87 or ECDSA-P384 (one is enough; both are allowed).
   - P-CNSA: ML-DSA-87 only.
   - This needs DER for ML-DSA-87 (OID 2.16.840.1.101.3.4.3.19) and ecdsa-with-SHA384 (1.2.840.10045.4.3.3) in tls-subject's mini X.509 writer.
4. ProfileCertResolver must return None when no offered scheme is in the profile and signable by the key; the expected verdicts are UNI-T5 and CNSA-T3 = 49. The oracle's sigalg-admission probe checks the same rule.
5. 0x11ED (`aegis_tls::kx::SECP384R1MLKEM1024`) must be in P-PUBLIC-WEB, P-UNIVERSAL and P-BSI-ALT. The oracle's client completes full handshakes over it, so the layout and the combiner must match RFC 10024.

## Open / notes
- `--require-cmvp` trusts the subject's self-report of the module. The binary-strings check is the fips-binary gate (P6-cmvp-001).
- Most of `src/main.rs` was left un-rustfmt'd: the file was already not rustfmt-clean at base (22 diffs), so I avoided the churn. The new `kx11ed.rs` is rustfmt-clean.
- `oracles/hrr-verdicts/target/` was deleted after the run.
