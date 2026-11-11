# egress-tls: egress TLS end to end (P8-hardening-001; PREFLIGHT R15)

Gate `egress-tls-e2e` (gates/phase-8.toml). It closes BACKLOG TLS "no end-to-end egress TLS handshake test": until
Phase 8 the egress `tls-client` path was covered only by unit tests that never completed a handshake.

```
oracles/egress-tls/run --subject target/release/egress-subject [--only REGEX]   # built with --features tls-client
oracles/egress-tls/run --self-test
```

Last line `EGRESS-TLS: PASS (...)` / `EGRESS-TLS: FAIL (...)` (or `EGRESS-TLS SELF-TEST: ...`); exit 0 only on PASS.
Python stdlib only (`python3 -I`), no build of its own.

**Host:** the peer is OpenSSL `s_server` with the ML-KEM TLS groups, so OpenSSL >= 3.5 is needed. kamrui has
3.5.3 (`/usr/bin/openssl`). The desktop has 3.3.1, which has no ML-KEM groups, so `run` refuses there and `needs` is
`kamrui`. The gate's `remote = true` (desktop) has to become `remote = "kamrui"` (integrator; see
units/phase-8/patches/P8-hardening-001.patch). `EGRESS_TLS_OPENSSL` overrides the binary.

## What is checked

Spec: PREFLIGHT R15, PLAN-8 gate row "egress-tls-e2e: an egress-subject with `tls-client` does a real TLS 1.3
handshake to a local upstream for each client profile (PQ-first). It refuses resumption and early data, and refuses a
wrong-name or untrusted upstream." Client profile lists: F12 (`monban_tls::client_config`, P-PQ2, P-PQ6;
RUSTSEC-2026-0349 for resumption and early data off).

Per client profile (P-PUBLIC-WEB, PQ-REQUIRED, P-UNIVERSAL, P-BSI-ALT, P-CNSA, FIPS-PQ-REQUIRED) the oracle starts
three `openssl s_server -tls1_3 -WWW -alpn http/1.1 -early_data -num_tickets 2` upstreams with the profile's groups:

| upstream | leaf (ECDSA P-384, generated per run) |
|---|---|
| good | `egress.test`, issued by the case CA |
| untrusted | `egress.test`, issued by a second CA the subject is not given |
| wrong-name | `other.test`, issued by the case CA |

Each upstream sits behind the oracle's loopback relay, which parses every plaintext record in both directions
(ClientHello, ServerHello, HRR, plaintext alerts) and counts the encrypted records. Scripted DNS maps `egress.test`
to 127.0.0.1 (readmit 127.0.0.0/8 only, the relay port only). Five cases per profile, all through **one** client
(`tls.client` = the profile name, so the subject keeps one `NetConnector` and one injected config for all five):
`ok-1`, `ok-2` (the upstream has issued tickets with max_early_data by now), `untrusted`, `wrong-name`, `ok-3`.
The subject fetches `https://egress.test:PORT/<random>.txt`; the file holds a random nonce.

| id | check |
|---|---|
| E0 | one well-formed verdict per case with the right id; the subject stays up; OpenSSL has every needed group |
| E1 | ok cases: `connect`, status 200, `body_hex` = the nonce |
| E2 | every ClientHello: `supported_versions` = [0x0304]; `supported_groups` = the profile list exactly, in order; `key_share[0]` = the profile's first group, which is post-quantum (0x11EC/0x11ED/0x11EB/0x0202), and no share outside the list; SNI `egress.test`; ALPN offered exactly `[http/1.1]` |
| E3 | ok cases: exactly one ServerHello, no HRR, group = the profile's first group, version 0x0304 |
| E4 | untrusted and wrong-name: the subject rejects with code `tls`; the upstream never serves the nonce (`s_server` logs `FILE:<name>` per served file); the client sends at most one encrypted record (its alert under the handshake keys), never Finished plus a request; a connection did reach the upstream |
| E5 | no ClientHello carries `pre_shared_key` (41) or `early_data` (42), on any case |
| E6 | ok cases: the nonce served exactly once over exactly one connection; the subject dialled only the relay address |

Decryption is judged by the independent side: the nonce goes from the upstream's file to the subject's verdict, so a
wrong key schedule cannot pass E1.

## Self-test

`fake_subject.py` answers the same protocol with `openssl s_client` per case. The reference mode (`-verify_return_error
-verify_hostname egress.test -CAfile <ca>`, the profile's groups, ALPN http/1.1, no session file) must pass all 30
cases. Each mutant must go red with its id:

| mutant | breaks | red on |
|---|---|---|
| accept-untrusted | no `-verify_return_error`: continues past a failed chain | E4 (untrusted and wrong-name accepted) |
| no-hostname-check | chain checked, name not | E4 (wrong-name accepted) |
| resume | `-sess_out`/`-sess_in` per client | E5 (ok-2 offers pre_shared_key) |
| early-data | resume plus `-early_data` | E5 (pre_shared_key + early_data) |
| classical-first | x25519 first | E2 (supported_groups/key_share not PQ-first), E3 (HRR) |
| wrong-alpn | offers h2,http/1.1 | E2 |

The unit's oracle line "subject accepting an untrusted upstream -> red" is `accept-untrusted`.

## Subject contract (egress-subject `--features tls-client`)

ssrf-corpus JSON-lines (subjects/egress-subject/src/main.rs) plus, on a live case: `"tls": {"profile", "ca",
"client"}` (profile by F12 name; the subject builds `monban_tls::client_config(profile, roots from ca)` and injects it
with `monban_egress::TlsClient::from_config`; one `NetConnector::with_tls` per client id for the whole run) and
`"echo_body": true` (adds `"body_hex"`).

## Re-run in repo

2026-11-06, kamrui (OpenSSL 3.5.3):
- `run --self-test`: `EGRESS-TLS SELF-TEST: PASS (reference green; 6/6 mutants red)`.
- Red before code: the gate build (`cargo build -p egress-subject --features tls-client`) failed (no such feature),
  and the pre-Phase-8 subject (`--only P-UNIVERSAL`) was red: `EGRESS-TLS: FAIL (10 violations over 5 cases)` (E1, E4,
  E6: every https fetch failed closed with `tls-unavailable`).

## Provenance

Written from PREFLIGHT R15 / PLAN-8 and RFC 8446 (record and handshake layouts, the HRR random, extension numbers).
The record parser is the same approach as oracles/kx-interop (re-written here, not imported, so this oracle stays
self-contained). Nothing from `research/state/raw/` was used.

## Known limits

- One peer stack (OpenSSL). kx-interop covers Go and BoringSSL against the server side; the egress client is judged
  against OpenSSL only.
- Certificates are ECDSA P-384 only. The CertificateVerify algorithm set the client accepts is monban-tls's (the default
  provider's verification algorithms); an ML-DSA leaf is not tried.
- HRR in the client direction is not exercised: each upstream supports the profile's first group, so a correct client
  never sees an HRR (E3 requires none).
- Revocation, expiry and name constraints are rustls-webpki's and are not probed here (trusted, not verified).
