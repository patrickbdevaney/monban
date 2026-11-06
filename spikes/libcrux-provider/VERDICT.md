# VERDICT: P7-libcrux-001 (PREFLIGHT D-P7.5), 2026-11-06, kamrui

**Verdict: the "smaller C surface" claim holds. The provider works at R2, but it is not a candidate for replacing
aws-lc-rs on P-PUBLIC-WEB yet. Gate status: FAIL on one supply item, OSV; see INFEASIBLE_REPORT.md.**

1. **C surface.**
   - The libcrux server build compiles **0** C/C++/assembly files and makes 0 C-compiler calls.
   - The same server on rustls' aws-lc-rs provider compiles **395** files: 274 C and 121 assembly. 381 of them are
     aws-lc-sys 0.46.0 sources; 14 are generated compiler probes in OUT_DIR.
   - Binary sizes are 2.31 MB (libcrux) vs 4.30 MB (aws-lc-rs).
   - The claim reaches **R1**: a measured count with a negative control. Under the `c-fixture` mutant (one extra
     `cc::Build`), the count goes 0 → 3 and names `cfixture/src/fixture.c`.
2. **Correctness.**
   - KATs: 490 checks, all pass.
   - Interop: 24/24 cells pass against OpenSSL 3.5.3 and Go 1.27.3.
   - The interop check can be turned red: the kx-swap mutant turns all 8 X25519MLKEM768 cells red against both
     peers and leaves the other 16 green.
   - The KAT can be turned red: the gcm-notag mutant fails 230 GCM checks and nothing else.
   - This is **R2**: executed against two independent TLS implementations, with oracle mutation.
3. **Cost: about 2.5–3× more server CPU per handshake than aws-lc-rs on kamrui.** The numbers are provisional (below).
4. **Assurance.** This is **not** a "verified TLS stack".
   - The provider is unverified glue.
   - Upstream libcrux states that its executables are **"*not* verified to be side-channel resistant"**.
   - Only specific libcrux modules carry upstream hax/F\* claims (below).
   - rustls stays trusted, not verified.

## C surface (gate step `build`, `results/c-surface*.json`)

Each build starts from an empty target dir. `$CC`, `$CXX`, `CC_x86_64_unknown_linux_gnu` and `HOST_CC` point at
`tools/cc-log`, which logs every C/C++/asm source argument as an absolute path and then calls the real compiler.

| build | C files | asm files | C++ | compiler calls | native libs linked | release binary |
|---|---|---|---|---|---|---|
| `lcx-server`: rustls 0.23.46 + this provider (libcrux) | **0** | **0** | 0 | 0 | none | 2,313,904 B |
| `awslc-server`: the same server on rustls aws-lc-rs 1.18.2 / aws-lc-sys 0.46.0 (the root-lock pins) | **274** | **121** | 0 | 422 | `aws_lc_0_46_0_crypto` (static) | 4,301,808 B |
| self-test `c-fixture`: lcx + one `cc::Build` | 3 (1 crate file + 2 cc flag probes) | 0 | 0 | 5 | `cfixture` | n/a |

What the count covers and what it does not:

- It counts C that the *build* compiles. It does not count C reached at run time: libc and the kernel are the same
  in both builds.
- The libcrux side replaces the C with Rust, and that Rust is not free of `unsafe`. A grep over the libcrux crates'
  `src/` finds about 270 lines mentioning `unsafe`; 192 of them are in libcrux-intrinsics (AVX2/AES-NI/NEON
  wrappers) and 50 in libcrux-ml-kem. This is a grep, not an audit.
- The provider crate itself is `#![forbid(unsafe_code)]`.

### Crates in the provider's build graph (x86_64-unknown-linux-gnu, normal + build edges)

- **libcrux (17):**
  - primitives: aes 0.0.10, chacha20poly1305 0.0.10, poly1305 0.0.7, curve25519 0.0.9, p256 0.0.9, ecdsa 0.0.9,
    ed25519 0.0.10, sha2 0.0.9, sha3 0.0.11, hmac 0.0.9, hkdf 0.0.9, ml-kem 0.0.11;
  - support: hacl-rs 0.0.6, intrinsics 0.0.9, platform 0.0.4, secrets 0.0.7, traits 0.0.9, plus libcrux-macros 0.0.4
    (proc-macro, build time).
- **Not libcrux, counted separately:**
  - rustls 0.23.46, rustls-pki-types 1.15.1, rustls-webpki 0.103.16 (no crypto backend features), untrusted 0.9.0,
    subtle, zeroize 1.9.1, once_cell;
  - **getrandom 0.4.3** (OS randomness) with libc and cfg-if;
  - rand 0.10.3 / rand_core 0.10.1, pulled in by libcrux-ecdsa's `rand` feature for the nonce RNG trait;
  - proc-macro2 / quote / syn 3 / unicode-ident (build time).
  - No RustCrypto primitive was needed. libcrux-sha2 exists, so there was no fallback.

### Deviation from PREFLIGHT's crate list

PREFLIGHT named `libcrux-aesgcm 0.0.8` (2026-05-13). It **cannot be resolved together with** libcrux-ml-kem
0.0.11:

- aesgcm pins `libcrux-intrinsics =0.0.7` → `hax-lib =0.3.6`;
- ml-kem's train needs core-models 0.0.7 → `hax-lib ^0.3.7`;
- cargo refuses: "failed to select a version for `hax-lib`".

AES-GCM therefore comes from **libcrux-aes 0.0.10** (2026-10-07, same train). The upstream crate table lists it as
the AES-GCM 128/256 crate.

## Correctness (gate steps `kat`, `interop`)

**KATs (`results/kat.txt`, 490 checks).** Every vector goes through the provider's own wrappers or its rustls trait
objects.

| suite | source | checks |
|---|---|---|
| X25519 | RFC 7748 5.2 (2 vectors), 1 and 1000 iterations, 6.1 DH. Negatives: all-zero output refused, short share refused | 10 |
| AES-128/256-GCM | NIST CAVP `gcmEncryptExtIV{128,256}` and `gcmDecrypt{128,256}`: IV 96, tag 128, PT 0/128/408, AAD 0/128/720; 108 vectors including 36 CAVP "FAIL" vectors. Negatives: tag, ciphertext and AAD tamper | 372 |
| ChaCha20-Poly1305 | RFC 8439 2.8.2 and A.5, plus tamper checks | 10 |
| HKDF-SHA-256 | RFC 5869 A.1–A.3: PRK, OKM, OKM through the rustls `Hkdf` trait with split `info` | 9 |
| HMAC-SHA-256/384 | RFC 4231 cases 1, 2, 3, 4, 6, 7, through rustls `Hmac`, including `sign_concat` | 18 |
| Ed25519 | RFC 8032 7.1 TEST 1–3 (public key and signature) | 6 |
| P-256 ECDH, ECDSA | RFC 5903 8.1 (both public keys and the shared x in both directions). Negatives: off-curve, compressed prefix, short. ECDSA-P256-SHA256 sign → libcrux verify, and a wrong-message reject | 8 |
| ML-KEM-768 | NIST ACVP-Server FIPS 203: keyGen ×10, encapsulation ×10, decapsulation ×10 (including implicit rejection), encapsulationKeyCheck ×10 (5 invalid refused) | 40 |
| other | SHA-256/384 "abc" one-shot, incremental and fork. Group round trips for all three groups (share and secret lengths, equal secrets), short-share refusal, ek coefficient ≥ q refused through the TLS server path. Record-layer round trip and tamper refusal for all three suites | 17 |

**Interop (`results/interop.txt`).** The libcrux server faces OpenSSL 3.5.3 `s_client` (`/usr/bin/openssl` on kamrui)
and Go 1.27.3 crypto/tls (stdlib client). Every cell passes:

| | AES-128-GCM | AES-256-GCM | ChaCha20-Poly1305 | ChaCha20-Poly1305, Ed25519 leaf |
|---|---|---|---|---|
| X25519MLKEM768 | OpenSSL ✓ Go ✓ | OpenSSL ✓ Go ✓ | OpenSSL ✓ Go ✓ | OpenSSL ✓ Go ✓ |
| X25519 | OpenSSL ✓ Go ✓ | OpenSSL ✓ Go ✓ | OpenSSL ✓ Go ✓ | OpenSSL ✓ Go ✓ |
| secp256r1 | OpenSSL ✓ Go ✓ | OpenSSL ✓ Go ✓ | OpenSSL ✓ Go ✓ | OpenSSL ✓ Go ✓ |

The first three columns use an ECDSA-P256 leaf. Each cell requires all of the following:

- the server reports the pinned group and suite;
- the peer reports the same group: OpenSSL "Negotiated TLS1.3 group" for the hybrid, "Peer Temp Key" for
  X25519/P-256; Go reports group and suite;
- the peer verified the chain against a fresh test CA (OpenSSL `-verify_return_error` → "Verify return code: 0 (ok)";
  Go `RootCAs`), so an independent stack checked the CertificateVerify that libcrux signed;
- a random nonce made the round trip.

**Mutants (`results/selftest.log`).**

- **kx-swap.** The server announces X25519MLKEM768 but answers with a 32-byte X25519 share. OpenSSL and Go both
  reject it: OpenSSL with an internal_error alert, Go with "tls: invalid server key share". All 16 other cells stay
  green.
- **gcm-notag.** The GCM tag is never checked. 230 KAT checks fail: the CAVP FAIL vectors, tag/AAD tamper, and the
  AES record-layer tamper. No non-GCM check fails.
- **supply.** OSV names an h2 0.3.0 planted into a copy of the lock, and lock-age evaluated as of 2026-10-08 is red.

## Handshake cost vs aws-lc-rs (gate step `bench`, `results/bench.txt`). PROVISIONAL

kamrui is an Intel N95 (4 cores, shared box, nice 15). The measurement:

- in-memory rustls 0.23.46 TLS 1.3 full handshakes, ECDSA-P256 leaf, AES-128-GCM;
- the same aws-lc-rs client for both servers;
- 400 handshakes after 40 warm-up, interleaved libcrux/aws-lc-rs;
- "server" = time inside the server's `read_tls`/`process_new_packets`/`write_tls` only, so it includes ECDSA
  signing and key exchange.

It is one run. Earlier runs the same day moved by about ±20% (e.g. libcrux hybrid p50 1014–1247 µs).

| group | server p50 libcrux | server p50 aws-lc-rs | ratio | full handshake p50 libcrux / aws-lc-rs |
|---|---|---|---|---|
| X25519MLKEM768 | 1059 µs (p90 1106) | 429 µs (p90 472) | 2.5× | 1971 / 1321 µs |
| X25519 | 922 µs (p90 976) | 355 µs (p90 392) | 2.6× | 1685 / 1102 µs |
| secp256r1 | 1387 µs (p90 1473) | 455 µs (p90 488) | 3.0× | 2265 / 1317 µs |

This was not profiled. The roughly 0.5–0.6 ms constant gap that shows up even for X25519 points at P-256 ECDSA
signing (libcrux-ecdsa over HACL\*-derived portable P-256) as the main cost; that is a guess, not a measurement.
The provider also copies each record once because the libcrux AEAD API is not in-place, but that is negligible for
a handshake. No throughput (bulk record) numbers were taken.

## Assurance: what is and is not claimed

- **Rungs reached.**
  - C surface: R1 (measured, with a negative control).
  - KATs: R1 (third-party vectors with negative controls and a mutant).
  - Interop: R2 (two independent implementations, with oracle mutation).
  - Nothing here is R3 or above.
- **Upstream caveat, verbatim.** libcrux README (crates.io `libcrux` 0.0.6 readme, fetched 2026-11-06): "executables
  compiled from the code in this repository are *not* verified to be side-channel resistant, although we try to
  enforce that the source code is secret-independent". libcrux-ml-kem's README adds that constant-time code is
  "best-effort, as there are no guarantees from the compiler".
- **Upstream verification claims.** These are upstream's claims for specific modules; none is re-checked here.
  - **libcrux-ml-kem:** "the portable and AVX2 code for field arithmetic, NTT polynomial arithmetic, serialization,
    and the generic code for high-level algorithms is formally verified using hax and F\*" (hax: panic freedom and
    functional correctness against a spec, where indicated).
  - **HACL\*-derived crates** (curve25519, p256, ed25519, sha2, hmac, hkdf, chacha20poly1305/poly1305 via
    libcrux-hacl-rs): upstream says the *F\* source in HACL\** is verified for memory safety, functional correctness
    and secret independence, and the Rust is extracted from it. Upstream also says "top-level Rust APIs in these
    crates accessing the code from HACL\* may not be verified".
  - **libcrux-aes:** carries upstream's **"pre-verification"** badge. No verification claim.
  - **libcrux-ecdsa** wraps hacl P-256. The nonce is a random scalar from the OS RNG (not RFC 6979), and the
    rejection sampling is libcrux code.
- **This spike's code** is unverified glue: DER key parsing, hybrid share split and concatenation, the record layer,
  HKDF wiring. It has KATs, negative tests and interop only. rustls (state machine, key schedule, codec) remains
  trusted, not verified.
- **No side-channel measurement** was done for this provider. `oracles/ct-dudect` was not run against it.

## Scope limits

- **Server only, TLS 1.3 only.** There are no signature verification algorithms (client auth or client use fails
  closed) and no QUIC.
- **No TLS 1.2**, so TLS 1.2 P-PUBLIC-WEB clients are not served.
- **No P-384 ECDSA and no RSA server keys.**
- **FIPS stays on AWS-LC.** Nothing here touches the root or cmvp lock; the gate checks this.
- **Not tested:** BoringSSL interop (kx-interop has an image; not wired here), HelloRetryRequest paths, resumption.
- **Secret hygiene.** Intermediate secrets are wrapped in `zeroize::Zeroizing`. libcrux's internal buffers are
  outside this crate's control.
- **Supply.** The full-lock OSV check is red on RUSTSEC-2026-0173: proc-macro-error2 is unmaintained, and it is in
  the lock only through `cfg(hax)` edges, never compiled. See INFEASIBLE_REPORT.md.
  - cargo-deny (root deny.toml) passes.
  - Lock-age passes: 115/115 packages are at least 7 days old; the youngest are the libcrux train of 2026-10-07.

## What this means for D-P7.5

The "smaller C surface" claim holds as stated: 0 vs 395 C/asm files compiled, at R1.

It is bought with:

- about 2.5–3× server handshake CPU on this box (provisional);
- unsafe SIMD Rust in place of C/asm;
- a library that is pre-1.0 and says it is not verified side-channel resistant.

A non-FIPS libcrux profile is technically workable for TLS 1.3 server-only P-PUBLIC-WEB. Making it a shipped option
needs:

1. the OSV item closed (upstream release or an owner decision);
2. a dudect/ct run on the libcrux paths;
3. desktop/quiet-VM performance numbers;
4. a decision on TLS 1.2 and on client-side verification algorithms.
