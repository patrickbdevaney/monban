# P7-oracle-sel-001 report (spec author, 2026-11-06, base b813a83)

The branch was fast-forwarded from 00ca246 to main b813a83 before work started. That brought in
oracles/proxy-l4/clienthello.py, the shared ClientHello builder this oracle must reuse, and P7-spec-002's
tls-subject `mtc` feature.

## What was built

`oracles/cred-select/` (stdlib Python, `python3 -I`):
- `run`: the entry point. It matches both gates/phase-7.toml commands for `cred-select`.
- `oracle.py` holds:
  - the seeded generator, which builds every ClientHello with `oracles/proxy-l4/clienthello.py`;
  - 21 directed cases;
  - the corpus checks (codepoint constant, size, peek consistency, row coverage, per-mutant kill counts);
  - the subject driver;
  - the self-test.
- `ref_selector.py`: the Python reference selector, i.e. the decision table. It also speaks the subject protocol,
  and it carries 14 selector mutants and 3 protocol mutants.
- `README.md`: the subject protocol, the decision table, the trust_anchors codepoint and its source, the generator,
  the checks, the mutants and the limits.

Only `oracles/cred-select/**` and this report were written. There is no `default-subject`: the aggregate
`ci/oracles.sh run` would hit a tls-subject built without `mtc`, so the gate `cred-select` owns the real run.

## Subject protocol (`tls-subject select`, for P7-mtc-001)

One process. Request lines go to stdin; stdin is closed after the last one. The subject writes one answer line per
request, in order, and exits 0.

```
request: <case> <profile> <listener> <ncred> <id,listener,kind,scheme4hex,ta_hex|-> ... <client_hello_hex>
answer:  <case> <credential id> | <case> handshake_failure      (unparseable request: <case> error <reason>)
```

- `profile` is an F8 name, FIPS-CMVP excluded.
- `kind` is `x509`, `mldsa` or `mtc`.
- The credential pool covers all listeners, in configured order.
- The format is plain tokens, so it needs no JSON crate (tls-subject's Cargo.toml is outside P7-mtc-001's scope).

## Decision table

| step | rule |
|---|---|
| R0 | shared peek refuses the bytes → handshake_failure |
| E0 | credential.listener == listener (SEL-3) |
| E1 | scheme ∈ F12 sigalgs of the profile (read from tls/verdicts.toml) |
| E2 | mldsa never on P-PUBLIC-WEB (SEL-2) |
| E3 | scheme ∈ client signature_algorithms |
| E4 | mtc: trust_anchor_id byte-equal to an ID in trust_anchors at 0xCA34 (SEL-1) |
| R1/R2/R3 | first eligible mtc, else mldsa, else x509, in configured order |
| R4 | nothing eligible → handshake_failure (SEL-3) |

trust_anchors codepoint:
- draft-ietf-tls-trust-anchor-ids-07 says `trust_anchors(TBD)`, and IANA has no entry.
- 0xCA34 is BoringSSL's experimental value, as recorded in the oracles/proxy-l4 README.
- It is one constant (`clienthello.TRUST_ANCHORS_EXT`), cross-checked by `constant.ta-codepoint`.

## Acceptance

`ci/remote.sh oracles/cred-select/run --self-test` (desktop):

```
CRED-SELECT: PASS (10021 cases, 0 divergence, rows {'R0': 407, 'R1': 1611, 'R2': 1422, 'R3': 3053, 'R4': 3507}, 66 checks ok)
...
CRED-SELECT SELF-TEST: PASS (reference PASS on 10000 cases; 21/21 mutants caught: 14 selector, 3 protocol, 4 corpus)
```

Every mutant the unit lists is red:

| unit oracle line | mutant | divergent cases |
|---|---|---|
| SEL-1 | sel1-ignore-trust-anchor | 2534 |
| SEL-1 | sel1-any-trust-anchor | 1080 |
| SEL-1 | sel1-prefix-match | 321 |
| SEL-2 | sel2-mldsa-public | 1002 |
| SEL-3 | sel3-other-listener | 2118 |
| SEL-3 | sel3-pool-wide | 4850 |
| wrong codepoint | ta-codepoint (the shared `ch-ta-codepoint`) | 1816 |
| wrong codepoint | ta-codepoint-lenient | 309 |

Other mutants:
- selector: peek-fail-open, tier-classical-first, tier-mldsa-over-mtc, client-sigalgs-ignored,
  profile-sigalgs-ignored, tiebreak-last;
- protocol: drop-first-line, case-off-by-one, exit-nonzero;
- corpus: no-decoy, no-mtc-match, no-hostile, small-n.

## Red today

Gate command (desktop): `ci/heavy.sh cargo build --release --locked -q -p tls-subject --features mtc &&
oracles/cred-select/run --n 10000 --subject 'target/release/tls-subject select'`

```
  FAIL subject.protocol exit 1, 0 answer lines for 10021 requests; stderr: usage: tls-subject [subject] describe|serve|interop-server PROFILE | tls-subject [subject] interop-client PROFILE CA_PEM NONCE
  FAIL subject.divergence 10021 of 10021 cases diverge from the decision table
CRED-SELECT: FAIL (23 checks failed: subject.protocol, subject.directed.sel1.match, ...; 10021 cases, 10021 divergence, ...)
```

## Notes for the integrator

- P7-spec-001 (the F8 and F1 SEL text) had not landed. The table follows PLAN-7 and D-P7.4. If the frozen text
  differs, the README records it, and only a tightening goes in without an INFEASIBLE_REPORT.
- Claim rung: selection logic R2 against this table, once P7-mtc-001 passes. There is no MTC validity claim.
