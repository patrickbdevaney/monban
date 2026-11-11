# libcrux-provider: server-only rustls CryptoProvider on libcrux (P7-libcrux-001, PREFLIGHT D-P7.5)

Question: can Monban's non-FIPS P-PUBLIC-WEB server side run on a rustls `CryptoProvider` built from libcrux-*
primitives on crates.io, and does that shrink the C surface compared with aws-lc-rs? The verdict and numbers are in
`VERDICT.md`. This file covers layout, checks and how to reproduce.

FIPS stays on AWS-LC. Nothing here goes into the root lock or the cmvp lock.

## Layout

| path | what |
|---|---|
| `Cargo.toml`, `Cargo.lock` | **Standalone workspace with its own lock.** The root `Cargo.toml` does not exclude `spikes/`, so this manifest has its own `[workspace]` table and cargo treats the directory as a separate workspace. The gate checks that no spike crate shows up in `Cargo.lock` or `profiles/cmvp/Cargo.lock`, and that root `cargo metadata` doesn't list the spike packages. |
| `provider/src/lib.rs` | `lcx::provider()`: TLS 1.3 suites, kx groups, `Rng` (getrandom), empty verification-algorithm set |
| `provider/src/aead.rs` | AES-128/256-GCM (libcrux-aes), ChaCha20-Poly1305 (libcrux-chacha20poly1305), TLS 1.3 record protection. Self-test mutant `mutant-gcm-notag` lives here. |
| `provider/src/hash.rs` | SHA-256/384 (libcrux-sha2), HMAC (libcrux-hmac), TLS 1.3 HKDF straight on libcrux-hkdf extract/expand |
| `provider/src/kx.rs` | X25519 (libcrux-curve25519), secp256r1 (libcrux-p256), X25519MLKEM768 (libcrux-ml-kem + curve25519). Self-test mutant `mutant-kx-swap` lives here. |
| `provider/src/sign.rs` | ECDSA-P256-SHA256 (libcrux-ecdsa) and Ed25519 (libcrux-ed25519) signing keys, minimal PKCS#8/SEC1 DER reader |
| `provider/src/serve.rs` | interop server CLI, shared by `lcx-server` (this provider) and `baseline/` `awslc-server` (rustls aws-lc-rs) |
| `provider/src/bin/kat.rs` | `lcx-kat`: KATs, negative tests, group and record round trips |
| `bench/` | `lcx-bench`: in-memory handshake cost, libcrux server vs aws-lc-rs server |
| `cfixture/` | self-test fixture: one C file through `cc::Build`, linked only with `--features c-fixture` |
| `kat/` | vectors plus `gen.py`, which regenerates them from sha256-pinned public sources |
| `interop/` | `interop.py` (matrix driver) and `go/` (Go 1.27.3 stdlib client) |
| `tools/` | `cc-log` (C-compiler wrapper for the C-surface count), `c_surface.py`, `supply.py` (lock-age, OSV, isolation) |
| `INFEASIBLE_REPORT.md` | the one acceptance item that cannot be met: OSV is not clean on the full spike lock |
| `results/` | copied from the last kamrui gate run: C-surface JSON and logs, KAT, interop, bench, deny output |
| `gate.sh` | gate `libcrux-spike` and its `--self-test` |

The code follows workspace lints: `forbid(unsafe_code)` in every crate, and clippy denies unwrap/expect/panic/indexing.

## Provider scope

- **Protocol:** TLS 1.3 only, server only.
- **Key exchange:** X25519MLKEM768 (0x11EC: shares are ML-KEM first, then X25519; the secret is the ML-KEM ss
  followed by the X25519 ss), X25519, secp256r1.
- **Suites:** TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256. QUIC is `None`.
- **Server keys:** ECDSA-P256 with SHA-256, Ed25519.
- **Signature verification:** none. `signature_verification_algorithms` is empty, so client auth or client use fails
  closed.
- **Randomness:** `getrandom` 0.4.3 (OS). ECDSA nonces are random scalars from it, not RFC 6979.
- **Missing or substituted primitives:**
  - PREFLIGHT named `libcrux-aesgcm 0.0.8`. It pins `libcrux-intrinsics =0.0.7` / `hax-lib =0.3.6`, which cannot
    be resolved together with `libcrux-ml-kem 0.0.11` (cargo error: `hax-lib` 0.3.6 vs ^0.3.7). AES-GCM therefore
    comes from **`libcrux-aes 0.0.10`**, the same 2026-10-07 release train. Upstream's crate table lists
    libcrux-aes as the AES-GCM crate.
  - Every other primitive comes from a libcrux crate. libcrux-sha2 exists, so no RustCrypto fallback was needed.
    The non-libcrux crates in the provider's graph are rustls itself, getrandom, zeroize, rand/rand_core (pulled in
    by libcrux-ecdsa) and libc. VERDICT.md lists them.

## Gate

```
ci/remote.sh --host kamrui spikes/libcrux-provider/gate.sh            # supply build lint kat interop bench
ci/remote.sh --host kamrui spikes/libcrux-provider/gate.sh --self-test
ci/remote.sh --host kamrui spikes/libcrux-provider/gate.sh --only kat,interop
```

Run anywhere other than kamrui, `gate.sh` re-runs itself on kamrui. Build output goes to
`$CARGO_TARGET_DIR/libcrux-spike/` on the remote. `gate.sh`'s header comment describes every step and every
mutant.

**OSV scope.** OSV queries **every** package in the lock, not only the compiled graph, and there is no acceptance
list. That makes the gate red today on one advisory, RUSTSEC-2026-0173 (proc-macro-error2 2.0.1, unmaintained).
The crate reaches the lock only through `[target.'cfg(hax)']` edges: libcrux-intrinsics 0.0.9 → core-models 0.0.7
→ hax-lib 0.3.7 → hax-lib-macros 0.3.7. It is compiled for none of deny.toml's targets, and `tools/supply.py` checks
that and prints it. No libcrux release that is at least 7 days old avoids it.

I did not add an acceptance list, because the P6-cmvp-002 precedent says ledgering an advisory for a crate that is
never compiled weakens the gate. See `INFEASIBLE_REPORT.md`.

cargo-deny with the root `deny.toml` (`unmaintained = "all"`) passes, because it evaluates only the built graph.

## Reproduce the KAT files

```
python3 -I kat/gen.py <dir with rfc7748.txt rfc8439.txt rfc5869.txt rfc4231.txt rfc8032.txt rfc5903.txt
                       gcmtestvectors.zip mlkem-kg.json mlkem-ed.json>
```

`gen.py` pins the sha256 of each source and refuses a mismatch. The sources:

- RFCs: rfc-editor.org `.txt`.
- GCM: NIST CAVP `gcmtestvectors.zip`.
- ML-KEM: usnistgov ACVP-Server `gen-val/json-files/ML-KEM-{keyGen,encapDecap}-FIPS203/internalProjection.json`.
  The encapDecap sha256 a556952c…810f is the same file spikes/q4-026 used.
