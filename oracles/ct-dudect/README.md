# ct-dudect: constant-time tag compare in aegis-token (dudect)

Leakage detection on the Tier-L MAC check of `aegis-token` (unit P3-dudect-001; IMPLEMENTATION_PLAN §3 Phase 3,
"dudect on MAC compare, no leak"), following Reparaz, Balasch, Verbauwhede, *Dude, is my code constant time?*
(DATE 2017) and the reference `dudect.h`. Implemented in stdlib Python; no new dependencies.

## What is checked

The verifier must not leak, through its running time, how much of a presented tag matches the correct one (a
byte-at-a-time tag-guessing oracle). Three targets, all timed by the subject (`subjects/ct-subject`) one call per
measurement with `std::time::Instant` in-process:

- `cmp`: `aws_lc_rs::constant_time::verify_slices_are_equal(want, tag)`, the exact compare `mac_valid` calls
  (AWS-LC `CRYPTO_memcmp`), in isolation, so it is not masked by HMAC time.
- `mac`: `aegis_token::mac_valid` (HKDF K_aud + HMAC chain + compare) with the presented tag.
- `verify`: `aegis_token::verify` on encoded wire bytes carrying a forged tag (decode + MAC check + reject).

Classes (tag relative to the correct tag of the subject's fixed token): `equal`; `first` (differs only at byte 0);
`last` (differs only at byte 31, i.e. a 31-byte matching prefix); `random` (fresh random tag per measurement).
Tests: for `cmp` and `mac`: last-vs-random (fixed vs random), equal-vs-first, equal-vs-last, first-vs-last; for
`verify` (forged tags only, since an accepted token legitimately runs more code): last-vs-random, first-vs-last.

**Pass criterion:** every test has max |t| < 4.5 over ≥ 1e7 measurements (the default; `--measurements` lowers it
for quick runs only). Last line `CT-DUDECT: PASS (...)`. The 4.5 threshold is dudect's and is never raised.

## Method

- Per measurement the class is drawn from `os.urandom` (randomized interleaving). The oracle builds the inputs and
  sends them in batches of 100,000; the subject never sees class labels, and both classes are read from the same
  per-batch buffer, so memory access patterns do not depend on the class. The first batch is a discarded warm-up.
- The subject returns raw ns durations; all statistics are computed in the oracle (the subject cannot grade itself),
  from exact integer histograms per class.
- Welch's t-test on the uncropped data, on the data cropped at the 100 dudect percentiles
  `p_i = 1 - 0.5^(10 (i+1) / 100)` (here computed from the full pooled data rather than an initial batch), and the
  second-order test (t-test on `(x - class mean)^2`, uncropped). A test's statistic is max |t| over these, among
  crops with more than 10,000 measurements (dudect `max_test`).
- The subject is pinned to one CPU (`--cpu auto` = highest allowed CPU; `--cpu none` disables) to reduce noise.

## Self-test (`run --self-test`)

Default 2e6 measurements per test (`--measurements` to change).
1. Mutant: `ct-subject --mutant early-exit` replaces the compare (in all three targets) with a byte-by-byte
   early-exit loop. Each of cmp first-vs-last, cmp equal-vs-first, mac first-vs-last, verify first-vs-last must show
   max |t| > 10.
2. Negative control: the real subject with identical classes (cmp first-vs-first, mac last-vs-last, verify
   first-vs-first) must stay under 4.5, so noise alone does not trip the threshold.

## Subject protocol

Banner `CT-SUBJECT 1 tag=<64 hex>`; then per batch the oracle writes `<cmp|mac|verify> <n>\n` plus `n*32` tag bytes
and reads `n` little-endian u64 nanosecond durations. `quit` or EOF ends. See `subjects/ct-subject/src/main.rs`.

## Provenance

No research artifact was ported; the method is from the dudect paper and `dudect.h` (percentile formula, 10,000
measurement floor, second-order test), re-implemented here.

## Results in-repo

See below (appended per run).

## Known limits

- Timing is in-process `Instant` (clock_gettime, vDSO): about 20-30 ns overhead and coarse granularity on the
  build box; a sub-ns leak in `cmp` would need far more measurements to show. The early-exit mutant (≈ one cycle
  per matching byte) is detected at |t| in the hundreds to thousands, so byte-granular leaks are well within reach.
- A statistical test: absence of evidence over 1e7 measurements on one machine, compiler and CPU, not a proof.
  Constant-time behaviour of AWS-LC's `CRYPTO_memcmp` is trusted (SECURITY_CLAIMS.md), and this measures it, not
  verifies it. The run box (Ryzen 9 5900X) is shared; noise can raise |t| on both classes but cannot create a
  class-dependent difference, since classes are interleaved at random.
- Only the Tier-L tag compare is covered; the Tier-0 handle digest compare (`Tier0Table::lookup`) and Tier-X
  ML-DSA verify are not timed here.
- Timing of the HMAC itself depends only on the (public, fixed) caveats, not on the presented tag; it is in the
  `mac` and `verify` measurements but does not vary between classes.
