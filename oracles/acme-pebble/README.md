# acme-pebble: ACME issuance and renewal against Pebble, CERT-1..4

This oracle checks the in-house ACME client in monban-ops (feature `acme`, DEVIATIONS X-6) and the certificate
lifecycle in `monban_ops::cert`. Both run black-box through `subjects/acme-subject`, against the Let's Encrypt
Pebble test CA. Unit: P2-acme-cert-001.

Clauses checked (`spec/SPEC_INVARIANTS.md` §G, ARCHITECTURE §3.11 "ACME and certs"):

- **ACME**: RFC 8555 issuance with HTTP-01, renewal driven by ARI (RFC 9773), and an atomic `ResolvesServerCert`
  swap.
- **CERT-1**: the `cert_seconds_to_expiry` gauge.
- **CERT-2**: alerts at 30/14/7/3 days, plus expired.
- **CERT-3**: preflight. A tampered chain is never served.
- **CERT-4**: +400 days on the injected clock, the in-process replacement for faketime.

## Usage

```
oracles/acme-pebble/run [--subject target/release/acme-subject]
oracles/acme-pebble/run --self-test
```

`run` builds `target/release/acme-subject` through `ci/heavy.sh` if it is missing. It then runs
`python3 -I oracle.py`, which uses only the stdlib. The last line is `ACME-PEBBLE: PASS|FAIL (...)` or
`ACME-PEBBLE SELF-TEST: PASS|FAIL (...)`, and the exit code is 0 only on PASS. The oracle is light: a full run takes
about 15 s and the self-test about 80 s.

### Infrastructure

Two containers run on the host network, bound to loopback, on random free ports. Both are removed on exit.

| image (pinned by digest) | size | role |
|---|---|---|
| `ghcr.io/letsencrypt/pebble@sha256:ddf23064…f78199` (rev b1e1ca4, 2026-04-20) | 8.0 MB | ACME CA, `-strict` |
| `ghcr.io/letsencrypt/pebble-challtestsrv@sha256:12ce2188…a1405b` | 7.1 MB | DNS only: every name resolves to 127.0.0.1, no AAAA |

- `docker.io/letsencrypt/pebble` no longer exists, so the images come from ghcr.io.
- Each image's size is checked to be under 500 MB before use.
- Pebble environment:
  - `PEBBLE_VA_NOSLEEP=1`
  - `PEBBLE_WFE_NONCEREJECT=0`: Pebble's random badNonce rejections are off, so a `badNonce` can only come from the
    replay mutation.
  - `PEBBLE_AUTHZREUSE=0`: every order runs a real HTTP-01 validation.
- Pebble config: `httpPort` is the subject's HTTP-01 port, `retryAfter` is 1 s, and certificates last 90 days.
- The trust anchor for the ACME server's TLS is `pebble.minica.pem`, copied out of the image. This is the test-only
  trust anchor: the subject's ACME `ClientConfig` trusts only roots passed in configuration.
- The issuing root comes from Pebble's management API (`/roots/0`) and is regenerated on every run.

## Subject protocol

```
<subject> --directory https://127.0.0.1:P/dir --acme-ca minica.pem --domain acme-subject.test
          --https-addr 127.0.0.1:H --http01-addr 127.0.0.1:C --ari-min-secs 0 --ari-max-secs 1
          --poll-min-secs 1 --poll-max-secs 2 --tick-ms 100 [--no-renew] [--mutate M]...
```

The subject writes JSON lines to stdout:

- `installed`, `ready`, `ari`, `renewing`, `swap` (`reason`: `ari` or `clock`), `status`
  (`cert_seconds_to_expiry`, `alert`, `serial`, `renewals`), `alert` (`level`)
- `bad_nonce_retry`, `preflight_rejected`, `error` (`stage`, `detail`)

It reads commands from stdin: `offset <secs>`, `advance <secs>`, `status`, `quit`. The HTTPS listener keeps
connections alive and answers every request with the store's current generation and serial.

The `--ari-max-secs 1` argument clamps Pebble's `Retry-After: 21600` so that ARI is re-fetched every second. This is
the client-side limit RFC 9773 §4.3 requires; the default limit is 1 day.

## What is checked (`run`)

1. **Issue.** The first certificate is installed. A TLS connection A made with Python's OpenSSL, `cafile` = the Pebble
   root and SNI `acme-subject.test`, verifies leaf → intermediate → Pebble root. The serial A serves equals the
   installed serial.
   - Negative control: the same chain must **not** verify against the minica root.
2. **CERT-1/2 on a fresh certificate.** 80 d < gauge ≤ 90 d, and the alert level is `ok`.
3. **ARI renewal.** The oracle moves the certificate's suggested window into the past through Pebble's
   `/set-renewal-info/`. The subject must re-fetch ARI and renew. Its newOrder carries `replaces` (RFC 9773 §5).
   - The subject must emit `swap` with reason `ari`.
   - A new connection B gets a new serial that verifies to the root.
   - Connection A, held across the swap, still answers, and reports the new store serial.
4. **Clock renewal.** `offset +62 d` puts the clock past the new certificate's window, so the subject must emit
   `swap` with reason `clock`. The offset is then reset.
   - A new connection C serves the newest serial.
   - A and B still answer.
5. **Sanity.** No `badNonce` and no `preflight_rejected` occur in the clean run.
6. **CERT-4.** A second subject runs with `--no-renew`. After `offset +400 d`, every CERT-2 alert fires exactly once
   and in order (`30d, 14d, 7d, 3d, expired`). The gauge is negative, the status is `expired`, and nothing is renewed.

**PASS** iff all of the above hold.

## Self-test (`--self-test`)

Every case must be caught.

| case | expected |
|---|---|
| `wrong-jws-key`: JWS signed by a key other than the one in the header | Pebble returns 400 `malformed` "JWS verification error"; the subject reports it and exits non-zero |
| `replay-nonce`: an already used nonce is sent once | Pebble returns `badNonce`; the subject retries with the fresh `Replay-Nonce` and still issues |
| `tamper-order`: the CSR names a different identifier than the order | Pebble returns 403 `unauthorized` "CSR is missing Order domain"; the subject reports it |
| `tamper-chain`: one byte of the leaf signature is flipped before install | the CERT-3 preflight rejects it (`BadSignature`); exit 3; nothing is served |
| `expired-no-renew`: +400 d with renewal disabled | all five alerts fire and the gauge is negative |
| control `tamper-chain` + `skip-preflight` | the main check FAILs because the served chain does not verify to the Pebble root (shows that check can go red) |
| control `--no-renew` | the main check FAILs because no ARI renewal happens |
| control `silence-alerts` | the CERT-4 check FAILs because no alerts fire |

The mutation hooks are `monban_ops::acme::Faults`, all off by default, plus the subject's `--mutate` flags.

## Results (in-repo, 2026-10-25)

```
issued 4bf325c3d5ca2d4f; ARI renewal -> 79ea7635158b495b; clock renewal -> 64b26a80a5598a35 (2 renewals); chain verified to Pebble root; held connection survived 2 swaps
+400 d: gauge -26784002 s, alerts ['30d', '14d', '7d', '3d', 'expired']
ACME-PEBBLE: PASS (issue + renew(ARI) + renew(clock) + ARI + atomic swap + CERT-1/2/4 alerts)
ACME-PEBBLE SELF-TEST: PASS (8/8 mutations caught: ...)
```

## Provenance

- This oracle is new in the repo. No research artifact was ported, so there is no `research/state/raw/` source.
- Pebble behaviour was read from the pinned revision's source (`wfe/wfe.go`, `core/types.go` at b1e1ca4):
  - the ARI window is 2/3 of the lifetime ± 1 d;
  - `Retry-After` is 21600 s;
  - `set-renewal-info` exists;
  - `replaces` is validated.
- RFC 9773's certID example (Appendix A) is a unit test in `monban_ops::acme::ari`.

## Known limits

- **Pebble is not a production CA.** Let's Encrypt staging interop has not been run here (that needs a public
  name).
- **TLS-ALPN-01 is not implemented.** The client fails closed if `http-01` is not offered. EAB is not implemented.
- **Pebble's PQ support was not verified.** The ACME client's TLS (floor, PQ-first `[X25519MLKEM768,
  SecP256r1MLKEM768, X25519, P-256]`, TLS 1.3 only, no resumption) negotiates whatever Pebble's Go TLS supports.
  The PQ preference is checked in a unit test, not against Pebble.
- **The held-connection check covers one connection per generation.** It is not a load test.
- **The clock renewal runs on an offset.** Pebble's clock is real, so the oracle resets the offset after the
  clock-driven swap; otherwise every new certificate would also be past its window.
