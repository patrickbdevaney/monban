# P6-kani-001 report (spec author; gate kani-kx; PLAN-6 D5)

## Built
- `ci/kani.sh` takes `--crate C` and `--neg N`, with defaults aegis-budget and `negative_control_unclamped_refill`.
  `--expect-neg-only` runs only the negative control. `--self-test` is the same mode and is kept for kani-tbi.
  - The work dir for aegis-budget is still `~/aegis-ci/work/p2-kani`. Any other crate uses `kani-<crate>`.
  - Third-party `workspace = true` deps of the synced crates are copied verbatim from the root
    `[workspace.dependencies]`. A dep that is missing there is an error.
  - The root `Cargo.lock` is synced when the crate has third-party deps, so those deps resolve to the locked
    versions.
  - `-Z stubbing` is added only when the proofs file uses `kani::stub`. ssh flattens arguments, so this flag goes
    over the wire as one word.
  - With the default arguments, kani-tbi runs exactly as before: same dir, no lock sync, no extra flag.
- `crates/aegis-tls/src/kani_proofs.rs` has three harnesses in `kani_proofs::harnesses`. Each one runs on a
  symbolic `[u8; SERVER_SHARE_LEN+1]` with a symbolic length `0..=1666`.
  - `split_share_any_input` runs the **real private** `kx::split_share`. The harness calls a local placeholder
    with the same signature and replaces it with `crate::kx::split_share` through `kani::stub`. The placeholder
    always returns Err, so the cover on the Ok branch is satisfied only if the stub took effect. The log shows
    4/4 covers satisfied.
    - `pq_len` is picked from {EK_LEN (server), CT_LEN (client)}.
    - It proves no panic.
    - It proves Ok happens **iff** the length is exact and the point is uncompressed. On Ok, the two halves are
      the exact 97 / pq_len subslices of the input.
    - It proves every other input is `InvalidKeyShare`.
  - `server_start_and_complete_any_share` runs the real `SecP384r1MlKem1024::start_and_complete`, with
    `aws_lc_rs::kem::EncapsulationKey::new` stubbed.
    - It proves no panic before aws-lc, and that every input gives `InvalidKeyShare`.
    - Wrong lengths and bad prefixes never reach aws-lc.
    - An exact, uncompressed share reaches aws-lc with exactly 1568 bytes (asserted and covered in the stub).
    - All 43 aws-lc FFI sites are reported as unsupported constructs and are unreachable.
  - `negative_control_indexing_split` checks the same contract over `indexing_split`, a deliberately broken copy
    that slices and indexes without a length check. Kani reports two failed checks: the slice out-of-bounds
    panic in core `slice_index_fail`, and the "NEGATIVE CONTROL ...: Ok only for the exact length" assertion
    (1666 bytes accepted).
- `crates/aegis-tls/src/lib.rs` gets one line, `#[cfg(kani)] mod kani_proofs;`, outside this unit's
  write_scope. **Scope note:** the unit JSON says P6-tls-001 adds this line (single writer). The launching agent
  explicitly permitted it here, because the acceptance command cannot run without it. It is committed separately
  (the second commit), so the integrator can drop it if P6-tls-001 adds the same line.

## Acceptance (kamrui, Kani 9461e07a, a clean descendant of 16c774cf)
`ci/kani.sh --crate aegis-tls --neg negative_control_indexing_split`
```
RESULT split_share_any_input OK rc=0 wall=89.4s peak=470MB ** 4 of 4 cover properties satisfied
RESULT server_start_and_complete_any_share OK rc=0 wall=39.8s peak=457MB ** 3 of 3 cover properties satisfied
RESULT negative_control_indexing_split FAIL_AS_EXPECTED rc=1 wall=13.3s peak=313MB
KANI: PASS
KANI SELF-TEST: PASS
```
`ci/kani.sh --crate aegis-tls --neg negative_control_indexing_split --expect-neg-only`: `KANI SELF-TEST: PASS`.

kani-tbi with default arguments, `ci/kani.sh`: all 8 positive harnesses OK, then
`negative_control_unclamped_refill FAIL_AS_EXPECTED`, `KANI: PASS`, `KANI SELF-TEST: PASS`, exit 0.
`ci/kani.sh --self-test`: `KANI SELF-TEST: PASS`.

## Red/green (transient mutants, none committed; the files were restored)
| mutant | where | result |
|---|---|---|
| M1 `!=` -> `<` on the total-length check | kx.rs split_share | both positive harnesses FAIL, `KANI: FAIL` |
| M2 prefix check disabled | kx.rs split_share | split_share_any_input FAIL, `KANI: FAIL` |
| S1 length check added to the indexing copy | negative control | `NOT_RED`, `KANI SELF-TEST: FAIL`, exit 1 |

## Open / residual
- **`Active::complete` (client) is not executed by Kani.** Every `Active` constructor calls aws-lc C for key
  generation or import. Those are opaque handles, the crate forbids `unsafe`, and Kani has no FFI. The client's
  parse step is its first statement, `split_share(server_share, MLKEM1024_CT_LEN)?`. `split_share_any_input`
  verifies exactly that call. The link from that harness to `complete` is argued from the code, not checked.
  `complete_hybrid_component`'s inline point check is not covered, for the same reason.
- The harnesses are generic over the stubbed aws-lc boundary. aws-lc itself, rustls and rustc stay trusted.
- The drop of the symbolic `rustls::Error` / `CompletedKeyExchange` results is skipped (`mem::forget`). Their drop
  glue loops over Vec variants and does not unwind. This is harness scaffolding, not code under test.
