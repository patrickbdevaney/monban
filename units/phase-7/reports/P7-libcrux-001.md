# P7-libcrux-001 report (spec author; 2026-11-06, base 00ca246)

**Status: done, except one acceptance item that is infeasible: "OSV clean"** (see
`spikes/libcrux-provider/INFEASIBLE_REPORT.md`).

- `gate.sh --self-test`: **PASS**.
- `gate.sh`: **FAIL**, on that one supply line only. Every other step passes, and the gate runs all steps even after
  an earlier one fails.

Verdict, numbers and caveats: `spikes/libcrux-provider/VERDICT.md`.

## Acceptance (`ci/remote.sh --host kamrui spikes/libcrux-provider/gate.sh && ... --self-test`)

The `&&` stops after the gate fails, so I ran the self-test separately. Logs are `results/gate.log` and
`results/selftest.log`.

```
LIBCRUX-SPIKE: FAIL (supply: OSV: proc-macro-error2@2.0.1: RUSTSEC-2026-0173 (not compiled for any of
x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu, x86_64-unknown-linux-musl)) [passed: C files: libcrux 0 vs
aws-lc-rs 395; clippy clean; KAT 490 checks; interop 24/24 cells as expected; bench recorded (results/bench.txt)]

LIBCRUX-SPIKE SELF-TEST: PASS (gcm-notag: KAT red, 230 GCM checks failed; kx-swap: 8/8 X25519MLKEM768 cells red
(OpenSSL+Go), 16 other cells green; c-fixture: C files 0 -> 3 (cfixture/src/fixture.c counted); supply: OSV names a
planted h2 0.3.0, lock-age red as of 2026-10-08)
```

## Against the unit's `must`

| item | result |
|---|---|
| own Cargo.lock, not in either shipped lock | The spike has its own `[workspace]` table. The root `Cargo.toml` does not exclude `spikes/`, and I did not change it: that file is outside this unit's write scope. The gate checks that no libcrux/lcx/cfixture/hax-lib/core-models package is in `Cargo.lock` or `profiles/cmvp/Cargo.lock`, and that root `cargo metadata` doesn't list the spike packages. Root `git status` stays clean. |
| every crate >= 7 d | 115/115 (crates.io API, `User-Agent: aegis-ci`) |
| cargo-deny (root deny.toml) | advisories ok, bans ok, licenses ok, sources ok. aws-lc-rs uses `default-features = false, features = ["aws-lc-sys"]` as in the root; otherwise untrusted 0.7/0.9 is duplicated and bans fails. |
| OSV | **red**: RUSTSEC-2026-0173 (unmaintained), reached only through `cfg(hax)` edges and never compiled; no libcrux release avoids it. No acceptance ledgered (P6-cmvp-002 precedent). INFEASIBLE_REPORT.md lists three ways to close it. |
| CryptoProvider scope | kx X25519MLKEM768, X25519, secp256r1; AES-128/256-GCM, ChaCha20-Poly1305; SHA-256/384, HMAC, HKDF; ECDSA-P256 and Ed25519 signing. TLS 1.3 server only; no verification algorithms. |
| KATs | RFC 7748, NIST CAVP GCM, RFC 8439, RFC 5869, ACVP ML-KEM-768, plus RFC 4231, RFC 8032 and RFC 5903: 490/490 |
| interop | OpenSSL 3.5.3 s_client and Go 1.27.3: every kx × AEAD with an ECDSA-P256 leaf, plus every kx with an Ed25519 leaf: 24/24 |
| self-test mutants | gcm-notag → KAT red; kx-swap → OpenSSL (and Go) interop red on every X25519MLKEM768 cell; c-fixture → count larger. All three as listed in the unit. |
| VERDICT.md | C files: 0 (libcrux) vs 395 (aws-lc-rs: 274 C + 121 asm). Handshake server CPU 2.5–3.0× aws-lc-rs on kamrui (provisional). Rungs stated: C surface R1, KAT R1, interop R2. Upstream "not verified to be side-channel resistant" quoted verbatim. |

## Deviations and findings

1. **libcrux-aesgcm 0.0.8 cannot be co-resolved with libcrux-ml-kem 0.0.11.** The hax-lib requirements conflict
   (`=0.3.6` vs `^0.3.7`). PREFLIGHT's probe row lists aesgcm. I used **libcrux-aes 0.0.10** instead (same
   2026-10-07 train, upstream's AES-GCM crate). PREFLIGHT row P1 "libcrux CryptoProvider" should be corrected by the
   spec author; that file is outside this unit's write scope.
2. libcrux-sha2 exists, so no RustCrypto fallback was needed. getrandom 0.4.3 (OS RNG) and rand/rand_core 0.10 come
   from outside libcrux, and VERDICT.md lists them separately.
3. OpenSSL 3.5.3 `s_client` reports the negotiated group in two ways: "Negotiated TLS1.3 group" for KEM groups,
   "Peer Temp Key" for X25519/P-256. The interop driver matches each one exactly.
4. The gate's `build` step asserts **libcrux C files < aws-lc-rs C files** and **aws-lc-rs > 0**, so the counter
   cannot pass vacuously.

## Files

All under `spikes/libcrux-provider/`, plus this report: `Cargo.toml`, `Cargo.lock`, `provider/`, `baseline/`,
`bench/`, `cfixture/`, `kat/` (vectors and `gen.py`, sha256-pinned sources), `interop/`, `tools/`, `gate.sh`,
`README.md`, `VERDICT.md`, `INFEASIBLE_REPORT.md`, `results/`.
