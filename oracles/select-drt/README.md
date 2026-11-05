# select-drt: Lean Select(model) vs the hrr-verdicts selection model (PLAN-6 D3)

```
oracles/select-drt/run [--cases N] [--seed S] [--file tls/verdicts.toml]     (default N = 100000 per profile, S = 1)
oracles/select-drt/run --self-test [--cases N] [--seed S]                     (default N = 10000)
```

Last line `SELECT-DRT: PASS (...)` / `SELECT-DRT SELF-TEST: PASS (...)`. Exit 0 only on PASS. Run it through
`ci/heavy.sh`. A full 1e5-per-profile run takes about 5 s on the laptop.

## What is checked (spec/SPEC_INVARIANTS.md section F, 2026-11-04 addendum)

| check | how |
|---|---|
| Lean = oracle | For each of the eight F8 profiles, N seeded random ClientHellos (supported_groups = 0..6 distinct codepoints drawn from every F12 group plus P-521, X448, ffdhe2048, ML-KEM-512, GREASE 0x0A0A and 0x11EE; key_shares = a random subset of them, shuffled; half the hellos are biased toward the profile's own groups). Each one goes through both the compiled Lean `AegisIR.Select.select` and the oracle's `fn model`, and the outputs (`sh g` / `hrr g` / `alert 40`) must be byte-equal. The pass criterion is 0 divergence. |
| table | The Lean profile table (`select-drt profiles`) must equal tls/verdicts.toml (`selector` and ordered `kx_groups` of the mapped F12 row), and its names must equal the F8 `profile` enum in that order. Every F12 row must be modelled. |
| non-vacuity | Every profile must produce at least one server_hello, one hrr and one alert. |

The comparison is **group selection only** (step 3 of the F12 Select model). Generated offers carry the profile's own
sigalgs and versions, so the oracle's admission steps (alert 70, alert 49) cannot fire if the model contains them.

### Lean side
`lake exe select-drt` from this directory. `Main.lean` imports the spec module `AegisIR.Select` unchanged, through a
path `require` of `../../spec` (lakefile.toml only, no network, no Mathlib). The stdin protocol is documented in
`Main.lean`.

### Oracle side: the code called
At run time the runner extracts these items **verbatim** from `oracles/hrr-verdicts/src/main.rs`:
`enum Outcome`, `struct Profile`, `struct ProbeCase` and
`fn model(p: &Profile, c: &ProbeCase) -> Outcome`. It wraps them in a stdin/stdout harness, which is the only code
in this oracle, and compiles them with plain `rustc -O` (std only). Nothing in this directory is a copy of the model.
The sha256 of the extracted text is printed on each run. If the oracle renames or re-signs `fn model`, or adds a
field to `Profile` / `ProbeCase` that the harness does not fill, the build fails and the run is red. It never
silently compares against something else. If group selection later moves to its own function, point
`oracle_model_source()` at that function.

## Self-test (`--self-test`)

The baseline must have 0 divergence and 0 table problems. Then every mutant must diverge within N cases per profile:

| mutant | where | result (seed 1, N = 1e4) |
|---|---|---|
| `order:P-PUBLIC-WEB`, `order:P-BSI-ALT`, `order:FIPS-FLOOR`, `order:FIPS-CMVP` | Lean: one profile's selection order swapped (client-order to server-order) | 2916 / 1285 / 2049 / 2063 divergences |
| `share-ignored` | Lean: ServerHello even without a key share | 21480 |
| `oracle-copy branches-swapped` | a mutated copy of the oracle's `fn model` text (selector test negated) | 8313 |
| `verdict-file P-UNIVERSAL=[0x11EC]` | the F12 table differs from the Lean table | 1 table problem, 5263 divergences |

Equivalent mutant: `kx-reversed:P-PUBLIC-WEB` reverses a server list. Under client-order selection this is
invisible, as the hrr-verdicts README already notes, so it must stay at 0 divergence. If it ever diverged, one of
the two models would not be client-order.

A single-profile **list permutation** is not a usable mutant under client-order, because it is semantically
equivalent. The "swapped order" mutant is therefore the selection-order swap.

## Rung

R4 for the Lean model (theorems `select_in_profile`, `pq_required_no_classical`, `hrr_only_if_no_share`,
`alert_iff_empty_intersection`, `universal_only_11ED`, checked by the proof gate). R2 correspondence between the
compiled Lean `select` and the oracle's selection model. Neither is a claim about rustls code. rustls is trusted,
not verified, and the oracle's executed handshakes (hrr-verdicts, R1) are the link to it.

## Known limits

- Generated hellos are in-domain: groups are distinct and key_shares is a subset of groups. rustls rejects a
  key_share for an unlisted group (illegal_parameter), and neither model represents that case.
- The comparison is a random sample (8e5 cases), not exhaustive. The Lean theorems are the universal statements.
- The Lean table is a copy of F12, checked on every run. An F12 group-list change turns this oracle red until
  `spec/AegisIR/Select.lean` is updated and re-frozen.

## Run log

2026-11-04, laptop, via ci/heavy.sh, Lean 4.35.0, rustc 1.99.1, verdict file sha256 prefix f7507df8439e2a83 (main
875f42c):
- `run --cases 100000` -> `SELECT-DRT: PASS (8 profiles x 100000 cases = 800000, seed 1, 0 divergence; Lean table == F12; ...)`
- `run --self-test` -> `SELECT-DRT SELF-TEST: PASS (7/7 mutants caught within 10000 cases per profile; baseline clean; equivalent mutant 0 divergence)`
- Build output: `.lake/` 4.8 MB and `target/` 8.8 MB, both git-ignored and deleted after the run.

## Placement

`needs` = `lean`: it builds the Lean table with lake, so the aggregate runs it only in `oracles-local` (this laptop,
which has the pinned elan toolchain). The `select-drt` gate runs it again at 100000 cases per profile.
