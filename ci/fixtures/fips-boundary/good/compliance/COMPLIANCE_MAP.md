# Fixture compliance map

| profile | groups | notes |
|---|---|---|
| P-UNIVERSAL | 0x11ED only | each component of 0x11ED is approved in #5314; 0x11ED as a whole is NOT CLAIMED |
| FIPS (cmvp lock) | SECP256R1MLKEM768, P-256, P-384 | AL2023 only |

- **cmvp**: aws-lc-fips-sys =0.13.11 = AWS-LC FIPS 3.1.0 (CMVP #5298 dynamic /
  #5314 static); the cmvp build is static.
- The TLS 1.2 KDF has a CVL row; the TLS 1.3 KDF has no CVL row and is not approved.
