# bin-residuals: monban-bin's Phase-7 residuals end to end

Unit P8-oracle-001. Gate `bin-residuals` (gates/phase-8.toml, `remote = true`). Implementers P8-bin-001 (SEL through
the binary, L4 idle) and P8-transport-001 (R6). Closes PREFLIGHT R7 (no gate drove the MTC selector through
monban-bin; the L4 idle timeout after routing had no oracle) and carries R6 (one bad chunk line yields two 400s) into
the `mtc,l4` build.

```
oracles/bin-residuals/run --binary target/release/monban [-v] [--openssl PATH]   # monban --features mtc,l4 (the gate)
oracles/bin-residuals/run                                                       # the reference subject (ref_server.py)
oracles/bin-residuals/run --self-test                                           # reference PASS, 8 reference mutants FAIL
```

`run` execs `python3 -I oracle.py` from the repo root. Stdlib only. The last line is `BIN-RESIDUALS: PASS|FAIL (...)`
or `BIN-RESIDUALS SELF-TEST: PASS|FAIL (...)`, and the exit code is 0 only on PASS. `--subject` is an alias of
`--binary`. Needs the `openssl` CLI; for a real binary it must be **OpenSSL >= 3.5** (it mints the ML-DSA-44
credential, and the P-PQ-REQUIRED positive controls use `s_client` with X25519MLKEM768). kamrui has 3.5.3 (system);
elsewhere pass `--openssl` or `AEGIS_OPENSSL`. The reference runs with any openssl (an ML-DSA stand-in is used, see
"Material"). One run takes about 6 s, the self-test about 16 s. `needs` = `own-gate`: no aggregate runs it.

## Subject contract

The same CLI as oracles/proxy-l4 and oracles/proxy-e2e: `<binary> --config <f8.json> --cert <pem> --key <pem>
--audit-dir <dir>`; readiness `GET /healthz` = 200 on `admin.bind`; SIGTERM stops. The config the oracle writes
(ports fresh per run):

```json
{"v": 1,
 "listeners": [
  {"name": "pub",  "bind": "127.0.0.1:P1", "profile": "P-PUBLIC-WEB",  "alpn": ["http/1.1"]},
  {"name": "pub2", "bind": "127.0.0.1:P2", "profile": "P-PUBLIC-WEB",  "alpn": ["http/1.1"]},
  {"name": "pq",   "bind": "127.0.0.1:P3", "profile": "P-PQ-REQUIRED", "alpn": ["http/1.1"]},
  {"name": "web",  "bind": "127.0.0.1:P4", "profile": "P-PUBLIC-WEB",  "alpn": ["http/1.1"]},
  {"name": "l4",   "bind": "127.0.0.1:P5", "profile": "P-PUBLIC-WEB", "l4": [{"sni": "a.l4.test", "upstream": "127.0.0.1:U"}]}],
 "admin": {"bind": "127.0.0.1:PA"},
 "limits": {"idle_timeout_ms": 1500},
 "tls": {"credentials": [
  {"id": "pub-mtc",   "kind": "mtc",  "trust_anchor_id": "32473.1.7", "chain": "path:..", "key": "path:..", "listeners": ["pub"]},
  {"id": "pub-x509",  "kind": "x509", "chain": "path:..", "key": "path:..", "listeners": ["pub"]},
  {"id": "pub2-mtc",  "kind": "mtc",  "trust_anchor_id": "32473.2.7", "chain": "path:..", "key": "path:..", "listeners": ["pub2"]},
  {"id": "pq-x509",   "kind": "x509", "chain": "path:..", "key": "path:..", "listeners": ["pq"]},
  {"id": "any-mldsa", "kind": "mldsa", "chain": "path:..", "key": "path:.."}]},
 "vhosts": [{"host": "monban.test", "routes": [{"id": 1, "path": "/api/", "to": {"upstream": "127.0.0.1:C"}, "authz": "allow-all"}]}]}
```

- `any-mldsa` has no `listeners`, so it serves every HTTP listener, the P-PUBLIC-WEB ones included. That is legal F8
  (the load-time SEL-2 refusal is for a credential that *names* a P-PUBLIC-WEB listener) and is the SEL-2 bait:
  `TlsBlock::candidates` drops it on `pub`, `pub2` and `web` and keeps it on `pq`.
- `web` has no candidates, so it keeps the `--cert` acceptor (tls.rs `selectors`), as an operator's plain listener
  next to selector listeners would.
- MTC credentials are opaque operator blobs (D-P7.4). The oracle writes random bytes with a marker, never PEM, so the
  binary serves the whole file as the one certificate_list entry (tls.rs `load_credential`); their keys are P-256
  (scheme 0x0403).

## How selection is observed (tls13.py)

Python's ssl module cannot send trust_anchors (draft-ietf-tls-trust-anchor-ids-07, codepoint 0xCA34) or choose
signature_algorithms, and TLS 1.3 encrypts the Certificate message. `tls13.probe` builds the ClientHello with the
shared builder (oracles/proxy-l4/clienthello.py), offers X25519 and TLS_CHACHA20_POLY1305_SHA256 only, derives the
server handshake traffic key (RFC 8446 section 7.1) and decrypts the server's first flight up to Certificate. The
leaf entry is compared byte for byte with each configured credential (x509/mldsa: the DER of the PEM certificate;
mtc: the blob). It never sends Finished and never verifies CertificateVerify: selection is the claim, handshakes are
covered by the carried tls gates. The primitives are pure Python and checked at import against RFC 7748 section 6.1,
RFC 8439 sections 2.3.2, 2.5.2, 2.8.2 and RFC 5869 A.1; the probe was also checked against an OpenSSL 3.0 server
(certificate bytes equal) during development.

## What is checked (spec ids: spec/SPEC_INVARIANTS.md section F, F12 tls/verdicts.toml)

| check | expectation | clause |
|---|---|---|
| `sel1.match`, `sel1.second-in-list` | trust_anchors names 32473.1.7 (alone, or second) → `pub-mtc` | SEL-1 |
| `sel1.no-extension`, `.empty-list`, `.other-id`, `.prefix`, `.extended`, `.wrong-codepoint` (same bytes at 0xCA35), `.other-listeners-id` (pub2's id on pub) | `pub-x509` | SEL-1 (byte-exact, codepoint 0xCA34 only), SEL-3 |
| `sel2.mldsa-offered.pub` | client offers 0x0904..0x0906 then 0x0403 on `pub` → `pub-x509`, never `any-mldsa` | SEL-2 |
| `sel2.mldsa-offered.pub-with-ta`, `.pub2-own-ta` | the same offer with a matching trust anchor → that listener's mtc | SEL-1 + SEL-2 |
| `sel2.mldsa-only.pub.alert49` | only ML-DSA sigalgs: disjoint from P-PUBLIC-WEB's F12 sigalgs → alert 49 | F12 admission step 2 ("Select model as the oracle's MODEL check applies it") |
| `sel3.pub2-no-ta.alert40`, `.pub2-pubs-ta.alert40` (pub's id on pub2), `.pub2-mldsa-offered.alert40` | nothing among pub2's own credentials matches → **alert 40**, never pub's credential | SEL-3 ("→ handshake_failure (alert 40)") |
| `sel3.pub2-own-ta.control` | pub2's own id on pub2 → `pub2-mtc` | positive control |
| `pq.mldsa-control`, `pq.x509-control` | `openssl s_client -groups X25519MLKEM768 -sigalgs mldsa44` → `any-mldsa`; `-sigalgs ecdsa_secp256r1_sha256` → `pq-x509` (binary + OpenSSL >= 3.5 only) | positive controls: the mldsa credential is loaded and servable, so SEL-2 is not vacuous |
| `l4.silent.*` | ClientHello to `a.l4.test`, then silence: hello forwarded byte-exact; both the client and the upstream side are closed between idle − 0.25 s and idle + 1.25 s after the last byte | F8 `limits.idle_timeout_ms` on L4 after routing (front.rs splice contract: no byte either way) |
| `l4.client-active.*`, `l4.upstream-active.*` | one byte every 0.5 s for 4 s (> 2 × idle) in one direction keeps the splice open and every byte arrives; then silence closes both sides in the same window | idle, not absolute, timeout |
| `r6.chunk.bad-size.*`, `r6.chunk.bare-lf.*` | on `web`: exactly one response, a 400, then a close; the upstream sees nothing | R6, RFC 9112 section 7.1 / RFC 9110 one final response per request (oracles/proxy-e2e/oneresp.py) |
| `r6.chunk.valid.one-200` | a well-formed chunked POST gets exactly one 200 | positive control |

**PASS** iff every check passes (42 with the pq controls).

SEL-3 asks for alert 40 while rustls 0.23.46 sends 49 (access_denied) when the cert resolver returns nothing
(`server/hs.rs`, "no server certificate chain resolved"). The frozen F1 text wins: the subject has to send
handshake_failure itself (it already peeks the ClientHello before rustls sees it), or the spec author amends SEL-3.
Loosening the check here is not an option (CLAUDE.md).

## Self-test (negative controls)

`ref_server.py` follows the contract: on selector listeners it peeks the ClientHello, runs the cred-select decision
table (`oracles/cred-select/ref_selector.select`, the same table cred-select judges the selector against), applies
F12 admission step 2, and sends ServerHello + EncryptedExtensions + Certificate (`tls13.server_flight`) or the alert;
`web` is Python ssl with `oneresp.serve_h1`; `l4` peeks, routes by exact SNI and splices with the idle timeout. It
must PASS; then each mutant (env `AEGIS_BR_MUTANT`) must FAIL:

| mutant | planted bug | caught by (2026-11-06) |
|---|---|---|
| `sel1-any-trust-anchor` | mtc chosen whenever trust_anchors is non-empty | sel1.other-id, .prefix, .extended, .other-listeners-id, sel3.pub2-pubs-ta |
| `sel1-prefix-match` | an id matches its prefix or extension | sel1.prefix, sel1.extended |
| `sel2-mldsa-public` | ML-DSA exempt from the profile check on P-PUBLIC-WEB | sel2.mldsa-offered.pub, sel3.pub2-mldsa-offered |
| `sel3-other-listener` | nothing eligible → another listener's credential | sel3.pub2-no-ta, .pub2-pubs-ta, .pub2-mldsa-offered |
| `ta-codepoint-lenient` | trust_anchors also read at 0xCA33 / 0xCA35 | sel1.wrong-codepoint |
| `idle-ignored` | no idle timeout after routing | every `*.client-closed-at-idle` / `*.upstream-closed-at-idle` |
| `idle-absolute` | closes idle_timeout_ms after routing whatever the traffic | l4.client-active.stays-open, l4.upstream-active.stays-open, bytes-forwarded |
| `two-responses` | R6: two 400s for one malformed chunked request | r6.chunk.bad-size.one-response, r6.chunk.bare-lf.one-response |

The one-response judge has its own reference and mutants (two 400s, none, no close) in oracles/proxy-e2e's
self-test.

## Material

All certificates and keys are throwaway, minted per run into a 0700 temp dir that is removed afterwards: P-256 via
`openssl req -x509`, ML-DSA-44 via `openssl genpkey -algorithm ML-DSA-44` + `req -x509`. Without OpenSSL >= 3.5 a
real-binary run fails `harness` with that reason (never a silent skip). Reference runs then use a stand-in: a PKCS#8
block carrying the id-ml-dsa-44 OID (the reference reads only the OID, to know the scheme 0x0904) and a marker blob
as the certificate; it is never shown to a real binary.

## Recorded runs

- Laptop (2026-11-06): `run` → `BIN-RESIDUALS: PASS (40 checks; pq controls skipped (reference))`; `run --self-test`
  → `BIN-RESIDUALS SELF-TEST: PASS (reference green; 8/8 mutants caught: ...)`, 16 s.
- kamrui, **today's binary** (`ci/heavy.sh cargo build --release --locked -q -p monban-bin --features mtc,l4` at base
  0e27b11, run on kamrui instead of the desktop while the Phase-7 run holds the desktop): `BIN-RESIDUALS: FAIL (5
  failed: sel3.pub2-no-ta.alert40, sel3.pub2-pubs-ta.alert40, sel3.pub2-mldsa-offered.alert40,
  r6.chunk.bad-size.one-response, r6.chunk.bare-lf.one-response)`. 37 of 42 pass: SEL-1 and SEL-2 through the
  binary, both pq controls, and all 14 L4 idle checks. The reds are real residuals:
  - SEL-3: the binary answers `alert 49 access_denied` (rustls' unresolved-certificate alert), F1 says 40;
  - R6: `400 (with date) + 400 (without)`, byte for byte the P7-oracle-uring-001 finding 2.

## Known limits

- Rung: SEL-1..3 through monban-bin at R2 (black-box, directed cases on one config), on top of cred-select's R2 over
  the selector (>= 1e4 generated hellos). No MTC validity claim (D-P7.4).
- Only X25519 + ChaCha20-Poly1305 hellos are probed by the stdlib client; ML-KEM groups are reached only through
  `openssl s_client` on `pq`, and only as positive controls.
- The probe does not finish the handshake: a server that picks the right certificate but then fails to sign with it
  passes here (the tls and kx gates cover signing).
- L4 timing bounds are generous (the binary polls every 250 ms); a run on an overloaded host can still go red on
  them. The silent/active cases run in parallel.
- R6 is judged on h1 over TLS only; h2 has no chunked framing.
