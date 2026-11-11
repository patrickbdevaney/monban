# Security claims (fips-boundary fixture: every sentence here must stay green)

| component | trusted for | evidence | not claimed |
|---|---|---|---|
| **AWS-LC C code** | all cryptography | FIPS 140-3 validated module only in the cmvp profile (CMVP #5314 static; #5298 is the dynamic module and is not cited), AL2023 | memory safety |
| P-UNIVERSAL | 0x11ED only | 0x11ED built only from #5314-approved components (P-384 ECDH, ML-KEM-1024, HKDF); combiner per SP 800-227 §4.6.2 via the module's HKDF | 0x11ED is not FIPS-approved key establishment |

Monban may not claim that 0x11ED is FIPS-approved key establishment, because the TLS 1.3 KDF has no CAVP row.
The TLS 1.3 key schedule is NOT CLAIMED. The 0x11ED components are inside the #5314 boundary.
