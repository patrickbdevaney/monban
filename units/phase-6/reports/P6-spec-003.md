# P6-spec-003 report: Lean Select(model) + select-drt

Rebased onto main 875f42c (P6-spec-001: F12 re-freeze, F1 §F addendum).

## Built
- `spec/AegisIR/Select.lean` (new lakefile root `AegisIR.Select`). It has
  `select : Profile → ClientHello → Outcome`, with `ClientHello = {groups, key_shares}` and
  `Outcome = serverHello g | hrr g | alert code`. `Profile = {selector, kx}`, and `select` emits only `alert 40`.
  The model covers group selection only, matching the §F addendum. The 70/49 admission steps are not modelled.
  - The table `ProfileId.profile` has eight F8 profiles. Their F12 rows: FIPS-FLOOR and FIPS-CMVP both use `FIPS`,
    and P-PQ-REQUIRED uses `PQ-REQUIRED`. P-PUBLIC-WEB now includes 0x11ED, per the re-frozen F12. Also
    P-UNIVERSAL [0x11ED], P-BSI-ALT [0x11ED,0x11EB], P-CNSA [0x0202].
  - The five frozen theorems use the addendum's wording: `select_in_profile`, `pq_required_no_classical`
    (classical = X25519, P-256, P-384; hypothesis "p.kx has no classical group"), `hrr_only_if_no_share`,
    `alert_iff_empty_intersection` and `universal_only_11ED` (stated on the P-UNIVERSAL table entry).
  - Extra corollaries: `sh_only_if_share`, `alert_code_40`, `pqRequired_table` (proved by `decide`: the
    pq-required list = the profiles with no classical group), `pqRequired_hyp` and `universal_offer_11ED`.
  - Axioms are at most {propext, Quot.sound}. No sorry, no native_decide, and the allowlist is unchanged.
    `STATEMENTS.sha256` was re-frozen with additions only (144 entries, none removed or changed).
- `oracles/select-drt/` (lakefile.toml, Main.lean, run, README.md, lake-manifest.json, lean-toolchain).
  - The Lean exe is `select-drt`.
  - The runner `run` (python3 -I) compares the exe against `fn model(p: &Profile, c: &ProbeCase) -> Outcome`, plus
    `enum Outcome`, `struct Profile` and `struct ProbeCase`. These are extracted verbatim from
    `oracles/hrr-verdicts/src/main.rs` (as on main) at run time and compiled with rustc. **This is the function
    called.** If P6-oracle-hrr-001 changes that signature or adds struct fields, select-drt goes red rather than
    silently comparing against something else.
  - Generated offers carry the profile's sigalgs and versions, so admission steps never fire. The comparison is
    group selection only.

## Acceptance (laptop, AEGIS_NO_SANDBOX=1)
`ci/heavy.sh ci/gate.sh && ci/heavy.sh oracles/select-drt/run --cases 100000 && ci/heavy.sh oracles/select-drt/run --self-test`
- `PROOF GATE: PASS` (AXIOM GATE: PASS; STATEMENT GATE: PASS (144 frozen declarations unchanged))
- `SELECT-DRT: PASS (8 profiles x 100000 cases = 800000, seed 1, 0 divergence; Lean table == F12; rung R4 model + R2 correspondence)`
- `SELECT-DRT SELF-TEST: PASS (7/7 mutants caught within 10000 cases per profile; baseline clean; equivalent mutant 0 divergence)`
- `ci/gate-selftest.sh`: `GATE SELFTEST: PASS`

## Self-test, red and green
- Green: the baseline has 0 divergence and 0 table problems.
- Red (all caught):
  - Lean selection-order swap on P-PUBLIC-WEB, P-BSI-ALT, FIPS-FLOOR and FIPS-CMVP: 2916, 1285, 2049 and 2063
    divergences.
  - Lean `share-ignored`: 21480.
  - A mutated copy of the oracle `fn model` (selector test negated): 8313.
  - A verdict-file table mismatch: 1 table problem and 5263 divergences.
- Before the rebase, the stale P-PUBLIC-WEB table (without 0x11ED) would have hit the table check, the same check
  the verdict-file mutant exercises.

## Interpretation note
The task says "one profile order swapped". Under client-order selection, permuting a profile's group list cannot
change any outcome (hrr-verdicts README, "Known limits"), so it cannot be a detectable mutant. I implemented the swap
as the profile's **selection order** (client-order to server-order). The list permutation is kept as an
*equivalent* mutant that must stay at 0 divergence, and it does.

## Open
- STATEMENTS.sha256 will conflict with other spec units on merge. My entries are only the `AegisIR.Select:*`
  lines.
- The generator is in-domain only (distinct groups, key_shares ⊆ groups). See the README limits.
- Build dirs `.lake/` and `target/` under oracles/select-drt were deleted after the run.
