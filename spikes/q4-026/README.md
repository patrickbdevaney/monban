# q4-026: 0x11ED SecP384r1MLKEM1024 KxGroup, interop and FIPS boundary

Question (IMPLEMENTATION_PLAN Phase 1, q4-026): *0x11ED KxGroup interop + FIPS-boundary check. Interop fails ->
P-UNIVERSAL fallback (P-BSI-ALT minus 0x11ED + pure ML-KEM-1024).*

**Verdict: keep.** A ~250-line `SupportedKxGroup` on rustls 0.23.46's public API and aws-lc-rs 1.18.2 primitives
interoperates with OpenSSL 3.5.9 and Go crypto/tls (see the "Interop" table for each direction and the HRR
path). It passes a composite KAT built from public vectors, 15 negative handshake tests, 5 ACVP invalid-key
rejections and a 3000-input fuzz (malformed input gets an alert, never a panic). Both components are inside the AWS-LC FIPS 3.1.0 approved boundary (CMVP #5298/#5314), so a
FIPS claim for 0x11ED is possible on the cmvp lock, under the conditions in "FIPS boundary". The FIPS half was
checked against documents only; no build ran. 0x11ED stays Monban-owned code in monban-tls::kx.

## Code location (seed for `monban-tls::kx`)

| file | what |
|---|---|
| `src/kx.rs` | **the group**: `SecP384r1MlKem1024`, `SECP384R1MLKEM1024: &dyn SupportedKxGroup`, client `Active`. No unwrap/expect/panic/indexing, `forbid(unsafe_code)`. |
| `src/main.rs` | harness: `selftest` (KATs, rustls<->rustls, negative tests, fuzz, order mutant), `server`, `server-swapped` (mutant), `client` (TCP, for interop) |
| `kat/acvp-mlkem1024.txt` | 10 ML-KEM-1024 decapsulation + 10 encapsulation-key-check vectors extracted from NIST ACVP-Server `ML-KEM-encapDecap-FIPS203/internalProjection.json` (sha256 a556952c...810f) |
| `kat/rfc5903-p384.txt` | RFC 5903 section 8.2 P-384 ECDH vector |
| `interop/` | Dockerfiles (OpenSSL, Go) and raw transcripts |
| `refs/` | RFC 10024 and draft-05 text (sha256 below), CMVP Security Policy and SP 800-227 excerpts |
| `Cargo.toml`, `Cargo.lock` | own lock, copied from `oracles/hrr-verdicts` (all crates >=7 days old on 2026-10-25; only the root package name differs) |

## Spec: what the wire format is (and why the order matters)

draft-ietf-tls-ecdhe-mlkem was **published as RFC 10024 (August 2026)**. `refs/rfc10024.txt` (sha256 5efcfacef5...0dfe)
and `refs/draft-ietf-tls-ecdhe-mlkem-05.txt` (sha256 56e71ec9eb...a3c2; datatracker rev 05, 2026-08-10).

- **4.1 Client Share:** SecP384r1MLKEM1024 = secp384r1 uncompressed point (97 bytes, RFC 9846 4.3.8.2) **||**
  ML-KEM-1024 encapsulation key (1568) = **1665 bytes**.
- **4.2 Server Share:** server's secp384r1 point (97) **||** ML-KEM-1024 ciphertext (1568) = **1665 bytes**. The server
  MUST run the FIPS 203 sec 7.2 encapsulation-key check and send illegal_parameter if it fails. The client MUST
  check the ciphertext length (illegal_parameter). Both sides MUST run the ECDHE validity checks (illegal_parameter).
- **4.3 Shared Secret:** **ECDHE x-coordinate (48) || ML-KEM shared secret (32) = 80 bytes**.
- **The order differs from X25519MLKEM768.** For X25519MLKEM768 the ML-KEM part comes first in both the share and
  the secret (4.1 note: "the order of shares in the concatenation has been reversed ... for historical reasons";
  4.3). For SecP256r1MLKEM768 and SecP384r1MLKEM1024 the ECDHE part comes first. Section 5 gives the reason:
  SP 800-56Cr2 allows `Z' = Z || T` where the *first* secret is the approved one, so for the secp groups the ECDHE
  implementation is the one that needs certification.
- 7.3: value 4589 (0x11ED), DTLS-OK Y, Recommended N.

The code follows this layout (`split_share`, `combine` in `src/kx.rs`). Four checks confirm it: (a) the composite KAT
expects `girx || k` exactly; (b) the OpenSSL `-trace` shows both shares are 1665 bytes and start with `04` (the
point comes first); (c) OpenSSL and Go complete the handshake, so the Finished MACs over the derived secret match;
(d) the **order mutant** (`server-swapped`: ML-KEM secret first, as in X25519MLKEM768) fails against the rustls
client (R5-mutant), against OpenSSL and against Go. So the interop check can be made red, and the order is
pinned by an independent implementation.

## Results

Run on this laptop (i9-14900HX, Linux 6.17), 2026-10-25, loopback TCP / in-memory. Correctness only, no
performance numbers. Versions: rustls 0.23.46 (aws_lc_rs, prefer-post-quantum), aws-lc-rs 1.18.2 (aws-lc-sys 0.46.0,
non-FIPS), OpenSSL 3.5.9 (29 Sep 2026, alpine:3.22 apk), Go 1.26.10 crypto/tls.

### Interop (raw transcripts in `interop/`)

| # | server | client | groups offered / configured | result | transcript |
|---|---|---|---|---|---|
| A1 | **rustls+kx11ed** `[0x11ED]` | OpenSSL 3.5.9 s_client | `-groups SecP384r1MLKEM1024` | OK. Both sides report SecP384r1MLKEM1024, TLS_AES_256_GCM_SHA384, app data exchanged | A-openssl-client.txt, A-rustls-server.log |
| A2 | rustls+kx11ed | OpenSSL s_client | `-groups SecP384r1MLKEM1024:X25519MLKEM768` | OK, 0x11ED | same |
| B | rustls+kx11ed | OpenSSL s_client `-trace` | `-groups X25519:SecP384r1MLKEM1024` (share for X25519 only) | OK, via **HelloRetryRequest** to 0x11ED (HRR key_share length 2 = group 4589). Then the client share (1665 B, starts `04`) and server share (1665 B, starts `04`) | B-openssl-client-hrr.trace |
| C1 | OpenSSL 3.5.9 s_server `-groups SecP384r1MLKEM1024` | **rustls+kx11ed** `[0x11ED]` | | OK. s_server status page: "Shared groups: SecP384r1MLKEM1024", TLS_AES_256_GCM_SHA384 | C-openssl-server.txt |
| C2 | OpenSSL s_server `-groups X25519MLKEM768:SecP384r1MLKEM1024` | rustls+kx11ed | | OK, 0x11ED | C-openssl-server.txt |
| D | OpenSSL s_server `-trace` | rustls+kx11ed | | OK. Trace shows ClientHello key_share 4589 len 1665 (`04...`), ServerHello 4589 len 1665, close_notify | D-openssl-server.trace, D-rustls-client.txt |
| E1 | Go 1.26.10 `CurvePreferences=[SecP384r1MLKEM1024]` | rustls+kx11ed | | OK. Go reports CurveID 0x11ed, TLS_AES_128_GCM_SHA256 | E-go.txt |
| E2 | rustls+kx11ed | Go 1.26.10 | | OK, both sides 0x11ED | E-go.txt |
| M | **mutant** rustls server, ML-KEM secret first | OpenSSL 3.5.9; Go 1.26.10 | | **FAILS as it should.** OpenSSL: "decryption failed or bad record mac". Go: "tls: bad record MAC" | M-order-mutant.txt |

BoringSSL was **not tested**: no prebuilt image or binary was readily available, and building it needs cmake, Go
and about 1 GB. Go crypto/tls was used as the second independent implementation; it shares no code with OpenSSL or
AWS-LC.

### selftest (`selftest.txt`, 41/41 PASS)

- **KAT (K-dec-96..105, 10/10).** There is no published 0x11ED vector: RFC 10024 has no test-vector appendix, and a
  search found no public composite vector set. So a **composite KAT** was built from public component vectors.
  The client uses the RFC 5903 section 8.2 P-384 scalar `i` and an ACVP ML-KEM-1024 `dk`. It must emit
  `g^i || ek`. Given the server share `g^r || c`, it must derive exactly `girx || k` (80 bytes). All 10 ACVP
  decapsulation cases pass, including the 5 "modified ciphertext" implicit-rejection cases. This pins the layout,
  the split, the combiner order and the x-coordinate encoding against third-party numbers.
- **ACVP encapsulation-key check through the TLS path (K-ekc-156..165, 10/10).** The 5 invalid ek ("noisy linear
  system values too large") each get a server **alert 47 illegal_parameter**: the FIPS 203 sec 7.2 modulus check
  fires inside aws-lc `encapsulate`, as RFC 10024 4.2 requires. The 5 valid ek are accepted.
- **rustls<->rustls.** R1: direct 0x11ED. R2: HRR from X25519 to 0x11ED. R3: `hybrid_component` lets a client
  listing `[0x11ED, P-384]` complete against a P-384-only server without HRR. R4: no common group gives alert 40.
  R5-mutant: the order mutant fails (DecryptError).
- **Negative tests (15 handshake cases + fuzz), all alert or error, 0 panics:**

| id | input | observed |
|---|---|---|
| N-c-short1 / N-c-short-1568 / N-c-long1 | client share 1664 / 97 / 1666 bytes | server alert 47 |
| N-c-prefix02 / N-c-prefix00 | point prefix 0x02 / 0x00 at full length | server alert 47 |
| N-c-offcurve | Y lsb flipped (point not on curve) | server alert 47 |
| N-c-ek-coeff>q | ek first coefficient 0xFFF >= q | server alert 47 |
| N-c-empty | empty key_exchange in ClientHello (wire rewrite; rustls cannot send it) | server alert 50 decode_error (rustls codec, before the group) |
| N-s-ct-short1 / N-s-ct-short-all / N-s-ct-long1 | **wrong-length ciphertext** (1567, 0, 1569 bytes) | client alert 47 |
| N-s-prefix02 / N-s-offcurve | bad server point | client alert 47 |
| N-s-empty | empty key_exchange in ServerHello (wire rewrite) | client alert 50 |
| N-s-ct-bitflip | same-length ct with one bit flipped | implicit rejection, then client DecryptError at server Finished (encrypted alert). Never completes |
| F1 | 3000 random/edge-length inputs into `start_and_complete` and `complete` | 0 panics, 0 accepted |
| (lint) | `cargo clippy --lib` with unwrap/expect/panic/indexing denied | clean |

Build: 20 s, peak RSS 0.39 GB; `target/` 124 MB, deleted after measuring.

## FIPS boundary

**Answer: yes, 0x11ED can be FIPS-approved when it is built from the AWS-LC FIPS 3.1.0 module, on the cmvp lock
and in a tested operational environment.** Both components and the KDF are approved services of the certified
module, and SP 800-227 approves the combiner. This is a document-level answer (grade C). No FIPS build was run
here: aws-lc-fips-sys needs Go and cmake, which this laptop lacks, and approved mode needs AL2023.

Sources (excerpts with sha256 in `refs/fips/`):

1. **CMVP #5298** (AWS-LC 3 Cryptographic Module (dynamic), validated 2026-06-03, sunset 2031-06-02; Security
   Policy v1.3, module version **AWS-LC FIPS 3.1.0**) and **#5314** (static, same algorithm table with CAVP
   A6288..A6315). https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5298
   - Approved **ML-KEM KeyGen and EncapDecap, "Parameter Sets - ML-KEM-1024, ML-KEM-512, ML-KEM-768"**, FIPS 203
     (CAVP A6176..A6180, A6184, A6278, A6279). The service "Encapsulation/Decapsulation with ML-KEM" cites
     "FIPS 203: Section 7.2 and 7.3", so the sec 7.2 encapsulation-key input check is part of the approved service.
   - Approved **KAS-ECC-SSC SP800-56Ar3, "P-224, P-256, P-384, P-521", scheme ephemeralUnified, initiator and
     responder**. The SP 800-56Ar3 assurances are met (IG D.F scenario 2 path (1)) when ephemeral keys come from the
     module's key-pair generation and the module validates the peer key in SSC. This holds for aws-lc-rs
     `agreement::PrivateKey::generate` + `agree`.
   - Approved **KDA HKDF SP800-56Cr1**, "Shared Secret Length: 224-2048". Our Z' is 640 bits, inside that range.
     Section 2.11: "the module implements the TLS 1.2 and TLS 1.3 key derivation functions". rustls' TLS 1.3 key
     schedule runs on aws-lc-rs HKDF/HMAC, which is inside the module.
   - Non-approved: X25519 (that is why X25519MLKEM768 is excluded from the FIPS profile, FIPS-F5/F6). Neither
     component of 0x11ED is on that list.
   - Tested OEs: **Amazon Linux 2023 only** (Graviton4 r8g.metal-24xl, Xeon 8375C c6i.metal).
2. **NIST SP 800-227 (final, Sept 2025) section 4.6.2**, eq. (14): the SP 800-56C KDM key combiner
   `K <- KDM((S1, ..., St), OtherInput)` "is approved ... for any t > 1 if **at least one** shared secret ... is
   generated from the key-establishment methods in SP 800-56A ... or an approved KEM". For a two-step KDM,
   extraction must take all the shared secrets as input. The TLS 1.3 key schedule does `HKDF-Extract(salt, Z')`
   with `Z' = ecdh || mlkem`, so it qualifies. **Here both S1 (KAS-ECC-SSC P-384) and S2 (ML-KEM-1024) are approved,
   so position no longer matters for approval.** It would matter under the older SP 800-56Cr2 `Z || T` reading,
   where the first secret must be the approved one. Under that reading 0x11ED also qualifies, because ECDH is
   first (RFC 10024 section 5).
3. **RFC 10024 section 5** ("Regulatory Context"): the secp groups place ECDHE first so that "the ECDHE
   implementation must be certified, whereas the ML-KEM implementation does not require certification". It cites
   SP 800-227 4.6.1/4.6.2 for the combiner.

**What the cmvp profile implies** (`profiles/cmvp/pins.toml`: rustls =0.23.43, aws-lc-rs =1.15.3,
aws-lc-fips-sys =0.13.11 = AWS-LC FIPS 3.1.0):

- **API availability on the cmvp lock (source-checked, not compiled).** aws-lc-rs 1.15.3 has stable
  `kem::ML_KEM_1024` (a `pub const`; `&kem::ML_KEM_1024` still promotes to `'static`), `EncapsulationKey::new`,
  `encapsulate`, `decapsulate`, `agreement::PrivateKey::{generate, from_private_key}`, `agree` and
  `try_fips_mode`. rustls 0.23.43 has the same `SupportedKxGroup` / `ActiveKeyExchange` traits, including
  `hybrid_component`, and `rustls::ffdhe_groups`. **`kem::DecapsulationKey::new` (raw dk import) is absent in
  1.15.3.** Only the KAT constructor `Active::from_fixed_keys_for_kat` uses it, so it must be `cfg`-gated, or the KAT
  must run on the floor lock only. The live path compiles unchanged in principle. Verify in the Phase-6 cmvp build.
- `fips()` in `src/kx.rs` returns `aws_lc_rs::try_fips_mode().is_ok()`, the same policy as rustls' built-in
  SECP256R1MLKEM768. As verdicts.toml notes, `try_fips_mode()` cannot tell 3.1.0 from 4.2.0 (decoy lock), so a
  FIPS claim still needs P-PQ5: a single fips-sys node and the `AWS-LC FIPS 3.1.0` string in the binary. The group
  adds no new module code. It is glue (split, length checks, concatenation) in Rust outside the module, as rustls'
  own hybrids are.
- **Approved mode only on AL2023 hosts.** Debian, Ubuntu and musl builds may run 0x11ED but must not claim approved
  mode. This is unchanged from FIPS-F1..F6.
- Consequence for F12 (spec author's call, not applied here): 0x11ED could be added to the FIPS listener list
  (`[SECP256R1MLKEM768, SECP384R1MLKEM1024?, SECP256R1, SECP384R1]`). P-UNIVERSAL `[0x11ED]` can claim FIPS on the
  cmvp build. Both need new verdict rows and a cmvp-module half that stays SKIPPED until the cmvp build exists.

## Reproduce

```
cd spikes/q4-026
CARGO_TARGET_DIR=$PWD/target ../../ci/heavy.sh cargo build --offline     # 20 s, peak RSS 0.39 GB, target/ ~110 MB
./target/debug/kx11ed selftest                                          # -> SELFTEST: PASS (41 pass, 0 fail)

# OpenSSL 3.5.9 image (9 MB): alpine:3.22 + apk openssl
docker build -t monban-q4026-openssl -f interop/Dockerfile.openssl interop
# rustls server <- OpenSSL client (direct, HRR, multi-group)
./target/debug/kx11ed server 18443 3 &
printf 'GET / HTTP/1.0\r\n\r\n' | docker run --rm -i --network host monban-q4026-openssl \
   s_client -connect 127.0.0.1:18443 -tls1_3 -groups SecP384r1MLKEM1024 -ign_eof
#   ... -groups X25519:SecP384r1MLKEM1024 -trace      (HRR to 0x11ED)
#   ... -groups SecP384r1MLKEM1024:X25519MLKEM768
# OpenSSL server <- rustls client
docker run -d --name q4026srv --network host --entrypoint sh monban-q4026-openssl -c \
  "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -keyout /k.pem -out /c.pem -subj /CN=monban.test \
   && openssl s_server -accept 18444 -cert /c.pem -key /k.pem -tls1_3 -groups SecP384r1MLKEM1024 -www -naccept 1 -trace"
./target/debug/kx11ed client 127.0.0.1:18444
# Go 1.26 crypto/tls (multi-stage image; builder golang:1.26-alpine 241 MB, final ~16 MB)
ci/heavy.sh docker build -t monban-q4026-gotls interop/go
docker run --rm --network host monban-q4026-gotls server 127.0.0.1:18446 &  ./target/debug/kx11ed client 127.0.0.1:18446
./target/debug/kx11ed server 18447 1 &  docker run --rm --network host monban-q4026-gotls client 127.0.0.1:18447
# order mutant (must FAIL with every peer)
./target/debug/kx11ed server-swapped 18448 2 &  (OpenSSL s_client and Go client as above, port 18448)
rm -rf target
```

## Limits (honest)

- **Laptop, loopback, one run per case** (grade B ceiling per the contract; reached R2: executed against two
  independent implementations). The 0x11ED code is not yet in `monban-tls`; the Kani share-parsing harness
  (Phase-6 gate) is not written.
- **No published 0x11ED KAT exists.** The composite KAT uses third-party component vectors (ACVP ML-KEM-1024,
  RFC 5903 P-384). It covers only the client-side `complete`. Server-side `start_and_complete` uses fresh randomness
  and is covered by the round trip and by interop with OpenSSL and Go.
- **BoringSSL not tested** (no readily available build). Interop was with OpenSSL 3.5.9 and Go 1.26.10. Both pass
  in both directions.
- **Alert codes follow rustls, not exactly RFC 10024.** rustls 0.23.46 maps every `start_and_complete`/`complete`
  error to illegal_parameter (server/tls13.rs:541, client/tls13.rs:173). The RFC's "internal_error on other
  decapsulation failure" is unreachable: ML-KEM decapsulation of a correctly sized ciphertext cannot fail. An empty
  key_exchange is rejected by the rustls codec with decode_error (50) before the group runs.
- **FIPS half is a desk check.** No aws-lc-fips-sys build, no `config.fips()`, no module-string check, and the cmvp
  lock (rustls 0.23.43 / aws-lc-rs 1.15.3) was source-inspected, not compiled. Grade C for the FIPS answer.
- Secret hygiene: the 48-byte ECDH and 32-byte ML-KEM intermediates are plain `Vec`/`SharedSecret` and are not
  zeroized; the combined `SharedSecret` is zeroized. `monban-tls` should use `zeroize::Zeroizing`.
- The negative-test harness mutates shares through wrapper groups and one wire rewrite. It is not a full TLS
  fuzzer. F1 is a 3000-iteration xorshift fuzz of the two entry points, not coverage-guided.
- Docker images used: monban-q4026-openssl 9.15 MB, monban-q4026-gotls 15.6 MB, builder golang:1.26-alpine 241 MB
  (all under 500 MB). All three were removed after the run.
