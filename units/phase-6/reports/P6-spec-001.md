# P6-spec-001 report (spec author, 2026-11-04, base 35125f0)

## Done
- **F12 `tls/verdicts.toml`**
  - P-UNIVERSAL, P-BSI-ALT and P-CNSA are `active`, each with `sigalg_cover = "all-or-none"` and a `credential`.
  - P-PUBLIC-WEB `kx_groups` = the former `kx_groups_target`, with 0x11ED second.
  - New frozen rows: UNI-T1..T5, BSI-T1..T4, CNSA-T1..T4 (`requires = "floor"`).
  - PUB-T1..T6, FIPS-F1..F6 and SUP-1..5 are byte-identical (`git diff` shows no `-` line inside any row).
  - New "gov probe set" = the research probe set plus `ecdsa_secp384r1_sha384` and `mldsa87`.
- **New row vocabulary**, defined in the file header for P6-oracle-hrr-001:
  - `offer_versions`: an optional array; it sets the `supported_versions` bytes. When absent it is `["TLS13"]`, so the old rows send the same bytes.
  - The profile field `sigalg_cover`, checked at load time.
  - The MODEL now runs in three steps: version admission (alert 70), then sigalg admission (alert 49), then Lean `select`.
- **F13**
  - `signature` is replaced by `signatures`: `prefixItems` in the order ed25519, slh-dsa-sha2-128s, ml-dsa-87, with `items: false` and min/max 3.
  - The signed message is defined as the canonical JSON of the report without `signatures`.
  - Optional `test_keys: boolean`. `v` stays 1.
- **F1 §F addendum:** Select stated as `AegisIR.Select.select`, with the five D3 theorem names and their statements, the rustls 0.23.46 client-order note (BACKLOG), the admission steps and the rung. REL-1..REL-5 added (R0).
- **Re-frozen:** `python3 -I ci/interfaces.py freeze` and `python3 -I ci/statements.py freeze spec`. STATEMENTS.sha256 is unchanged because no Lean file was touched.

## Deviation from the PLAN-6 draft (deliberate, justified in the F12 header)
UNI-T5 and CNSA-T3 freeze **alert 49**, not 40.

Reading rustls 0.23.46 `server/hs.rs` `with_certified_key`, the order of checks is:
1. version;
2. certificate resolver (`AccessDenied` when it returns None);
3. kx group / HRR.

The aegis-tls `ProfileCertResolver` returns None when no offered scheme is in the profile. Its doc comment already says 49.

The only "no common sigscheme → 40" path is in `tls13.rs` `emit_certificate_verify`, which runs after the ServerHello has been sent. So 40 can never be the first record, and freezing it would freeze a verdict no server can produce.

CNSA-T4 (TLS 1.2-only) freezes **70**, from rustls `Tls12NotOfferedOrEnabled`. The oracle had no per-row version vocabulary, so `offer_versions` was added for it.

## Checks run
- `python3 -I ci/interfaces.py check && python3 -I ci/statements.py check spec`
  - `INTERFACES: PASS (16 frozen files unchanged)`
  - `STATEMENT GATE: PASS (117 frozen declarations unchanged)`
- `python3 -I ci/interfaces.py self-test`: `INTERFACES SELF-TEST: PASS (mutated F6 detected)`. Before the freeze, `check` was red on F1, F12 and F13.
- Scratch probes (not committed):
  - **Python re-implementation of the new MODEL plus `sigalg_cover`:** `MODEL: PASS 27`.
    - Red on mutant UNI-T5 with `expect_alert` 40: `DIFF UNI-T5`.
    - Red on mutant UNI-T1 with partial sigalgs: `COVER UNI-T1`.
  - **The oracle's own strict `toml.rs`**, compiled standalone via `ci/heavy.sh rustc`: parses the file, 25 verdicts, the three profiles active.
  - **jsonschema Draft 2020-12 check of F13:**
    - Valid sample: accepted.
    - Refused: 2 or 4 signatures, a duplicate alg, swapped order, the old `signature`, an extra field, `test_keys` as a non-boolean.

## Expected red until downstream units land
- `tls-verdicts` goes red against the current oracle and subject until P6-oracle-hrr-001 (MODEL admission steps, `offer_versions`, `sigalg_cover`, serving the three profiles) and P6-tls-001 (0x11ED on P-PUBLIC-WEB, the Universal/BsiAlt/Cnsa profiles active) land. This is by design.
- **For P6-spec-003:** the Lean `select` covers group selection only (Outcome ∈ {SH, HRR, Alert 40}). The 70 and 49 admission steps sit outside it, so select-drt should compare against oracle step 3 only.
- **For P6-oracle-hrr-001:** the oracle subject must serve P-UNIVERSAL and P-BSI-ALT with an ML-DSA-87 or ECDSA-P384 credential, and P-CNSA with ML-DSA-87. The README's "12 frozen verdicts" wording is the oracle's to update.
