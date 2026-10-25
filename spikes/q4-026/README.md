# q4-026: 0x11ED SecP384r1MLKEM1024 KxGroup, interop and FIPS boundary

Question (IMPLEMENTATION_PLAN Phase 1, q4-026): *0x11ED KxGroup interop + FIPS-boundary check. Interop fails ->
P-UNIVERSAL fallback (P-BSI-ALT minus 0x11ED + pure ML-KEM-1024).*

**Verdict: keep.** A ~250-line `SupportedKxGroup` on rustls 0.23.46's public API and aws-lc-rs 1.18.2 primitives
interoperates with OpenSSL 3.5.9 and Go crypto/tls (see the "Interop" table for each direction and the HRR
path). It passes a composite KAT built from public vectors and 21 negative tests (malformed input gets an alert,
never a panic). Both components are inside the AWS-LC FIPS 3.1.0 approved boundary (CMVP #5298/#5314), so a
FIPS claim for 0x11ED is possible on the cmvp lock, under the conditions in "FIPS boundary". The FIPS half was
checked against documents only; no build ran. 0x11ED stays AEGIS-owned code in aegis-tls::kx.

## Code location (seed for `aegis-tls::kx`)

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

RESULTS_PLACEHOLDER

## FIPS boundary

FIPS_PLACEHOLDER

## Reproduce

```
cd spikes/q4-026
CARGO_TARGET_DIR=$PWD/target ../../ci/heavy.sh cargo build --offline     # 20 s, peak RSS 0.39 GB, target/ ~110 MB
./target/debug/kx11ed selftest                                          # -> SELFTEST: PASS (41 pass, 0 fail)

# OpenSSL 3.5.9 image (9 MB): alpine:3.22 + apk openssl
docker build -t aegis-q4026-openssl -f interop/Dockerfile.openssl interop
# rustls server <- OpenSSL client (direct, HRR, multi-group)
./target/debug/kx11ed server 18443 3 &
printf 'GET / HTTP/1.0\r\n\r\n' | docker run --rm -i --network host aegis-q4026-openssl \
   s_client -connect 127.0.0.1:18443 -tls1_3 -groups SecP384r1MLKEM1024 -ign_eof
#   ... -groups X25519:SecP384r1MLKEM1024 -trace      (HRR to 0x11ED)
#   ... -groups SecP384r1MLKEM1024:X25519MLKEM768
# OpenSSL server <- rustls client
docker run -d --name q4026srv --network host --entrypoint sh aegis-q4026-openssl -c \
  "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -keyout /k.pem -out /c.pem -subj /CN=aegis.test \
   && openssl s_server -accept 18444 -cert /c.pem -key /k.pem -tls1_3 -groups SecP384r1MLKEM1024 -www -naccept 1 -trace"
./target/debug/kx11ed client 127.0.0.1:18444
# Go 1.26 crypto/tls (multi-stage image; builder golang:1.26-alpine 241 MB, final ~16 MB)
ci/heavy.sh docker build -t aegis-q4026-gotls interop/go
docker run --rm --network host aegis-q4026-gotls server 127.0.0.1:18446 &  ./target/debug/kx11ed client 127.0.0.1:18446
./target/debug/kx11ed server 18447 1 &  docker run --rm --network host aegis-q4026-gotls client 127.0.0.1:18447
# order mutant (must FAIL with every peer)
./target/debug/kx11ed server-swapped 18448 2 &  (OpenSSL s_client and Go client as above, port 18448)
rm -rf target
```

## Limits (honest)

LIMITS_PLACEHOLDER
