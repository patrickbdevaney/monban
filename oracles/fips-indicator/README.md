# fips-indicator: AWS-LC FIPS service-indicator verdicts (gate `fips-indicator`, unit P8-cmvp-002)

**Spec:** PREFLIGHT D-P8.2, D-P8.1. F1 FIPS-B1: a FIPS claim names only components the cited certificate approves.
**Closes:** residual R1, the indicator half. The documentation half is `fips-boundary`, P8-fips-001.
**Subject:** `target/cmvp/release/tls-subject indicator`. This is the cmvp tls-subject (features `cmvp,indicator`),
built by `profiles/cmvp/build.sh` in the AL2023 image on kamrui. It is never aegis-bin.

## What is checked

The oracle writes a random request plan to the subject's stdin and judges one answer line per request. The seed is
printed, and `--seed N` replays a plan. The randomness covers:
- the op order, with each op repeated;
- the HKDF salt, IKM, info and length;
- the invalid ECDH peer point.

Because of this, a recorded transcript does not pass (self-test `replay`).

| id | request | required answer |
|---|---|---|
| M | `module` | `module=AWS-LC FIPS 3.1.0` (CMVP #5314). The indicator that is read belongs to the certified module. |
| A1 | `ecdh-p384` | `indicator=approved ok=1 match=1` (KAS-ECC-SSC P-384) |
| A2 | `mlkem1024` | `encap=approved decap=approved match=1` (FIPS 203). `keygen` is reported, not judged. |
| A3 | `hkdf H SALT IKM INFO LEN`, salt and info non-empty | `indicator=approved`, and `okm` equals the oracle's own RFC 5869 HKDF (stdlib `hmac`) |
| C1 | `x25519` | `indicator=not-approved ok=1 match=1`. This is the control the acceptance names: the call ran, but it is not an approved service. |
| C2 | `ecdh-p384-peer HEX` (a random off-curve point) | `indicator=not-approved ok=0` |
| C3 | `hkdf` with salt `-` or info `-` (empty) | `indicator=not-approved`, and `okm` is still correct |
| C4 | `none` (empty closure) | `indicator=not-approved` |
| K | `kx-0x11ed` | `match=1` and a verdict for each of `client_start`, `server`, `client_complete`. **Reported, not required.** |
| H | `handshake P-UNIVERSAL` | `group=0x11ed version=0x0304 suite=0x130{1,2,3}` plus an `indicator` verdict. **The verdict is reported, not required.** |
| P | protocol | Exactly one answer per request, with the same id and op, in order. No `error` answers. Exit status 0. |

Notes on the rows:
- **C3.** This rule is AWS-LC 3.1.0's own, from `crypto/fipsmodule/service_indicator/service_indicator.c`
  `HKDF_verify_service_indicator`: `salt != NULL && salt_len == 0` or `info_len == 0` is not approved.
  aws-lc-rs 1.15.3 `Salt::extract` and `Okm::fill` call the one-shot `HKDF()`, and an empty `Box<[u8]>` salt is a
  non-null pointer. So the approved and not-approved expectations of A3 and C3 come from the module, not from a
  table the subject chooses. A3 and C3 run the same primitive and differ only in parameters.
- **K.** The AEGIS SecP384r1MLKEM1024 group (`aegis_tls::kx`) is run alone.
- **H.** The handshake is one in-memory TLS 1.3 handshake. The server is `aegis_tls::server_config_with`. The client
  is a subject-local rustls client restricted to 0x11ED. The verdict is not required because the TLS 1.3 key schedule
  has no CAVP row: PREFLIGHT D-P8.1 claims "built only from #5314-approved components", never "FIPS-approved key
  establishment". A single verdict over a handshake also only shows that *some* approved service ran inside it.

Pass criterion: every row holds. The last line is `FIPS-INDICATOR: PASS (...)` or `FIPS-INDICATOR: FAIL (...)`,
and the exit code is 0 only on PASS.

## Subject protocol

Requests arrive on stdin, one per line: `<id> <op> [args]`.

Answers go to stdout, one per request, in order: `<id> <op> key=value ...`, or `<id> <op> error <msg>`.

The subject exits 0 at EOF.

How the subject takes its readings:
- Every verdict is AWS-LC's `FIPS_service_indicator_before_call` / `_after_call` read around exactly one call, on the
  calling thread, through `aegis_iso::fips::with_indicator`. These are the aegis-iso audited sites, feature
  `indicator`.
- Key generation and the peer's side of each agreement run outside the window.

## Self-test (`run --self-test`, light, no build)

`fake_subject.py honest` models a correct subject and must PASS. It applies AWS-LC 3.1.0's indicator rule and runs a
real HKDF.

Each of the 20 mutant modes must be red **for its intended reason**: the FAIL summary must contain a
mutant-specific substring. A missing binary must also be red. The mutants cover:
- reporting Approved without calling the indicator (`always-approved`);
- X25519 reported Approved;
- an indicator that never moves;
- no verdict fields;
- the HKDF rule ignored;
- a wrong OKM;
- ML-KEM decap NotApproved, and an ML-KEM mismatch;
- an off-curve peer accepted;
- `none` Approved;
- the handshake missing, on the wrong group, or with no verdict;
- a 0x11ED kx mismatch;
- the uncertified module string `AWS-LC FIPS 4.2.0`;
- a dropped answer line, reordered answers, a non-zero exit, the compiled-out floor build, and a replayed transcript.

## In-repo runs

Recorded in units/phase-8 (unit report) and the gate logs. The self-test passed on the laptop with
`python3 -I` (21/21 red, model PASS). Before the subject mode existed, the oracle was red on the subject: the
indicator mode was compiled out or absent (`compiled-out` case), and on kamrui the floor tls-subject answers
`indicator ... compiled out` → FAIL.

## Known limits

- **The oracle judges what the subject reports.** A subject written to imitate AWS-LC's rule table, while also
  computing HKDF itself, would pass. `fake_subject.py honest` is exactly that, and it is the self-test's positive
  control. The binding to the real module rests on three things outside this oracle:
  - the subject source: every verdict comes from `aegis_iso::fips::with_indicator`, the only constructor of
    `aegis_iso::fips::Indicator`;
  - aegis-iso's `link_name` pin, `aws_lc_fips_0_13_11_…`: any other module, including the non-FIPS stubs that
    always return Approved, is a link error;
  - the `module` row.
- **The indicator is per thread.** The subject runs every op on its main thread. A verdict means some approved
  service completed inside the window.
- **Rung R2** (PREFLIGHT, PLAN "Claims"): one run of the real cmvp module on one host (kamrui, AL2023 image). It is
  not a CMVP validation of AEGIS. It is not an approval of the 0x11ED composite or of the TLS 1.3 KDF.
