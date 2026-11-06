# Phase 7 plan: deferred modules (spec author, 2026-11-06, base e06550e)

**Scope** (IMPLEMENTATION_PLAN §3 Phase 7, "each off by default, own TCB line"):
- HTTP/3
- L4/PROXY
- WebTransport
- more adapters (F4 + two-sided oracle)
- an opt-in io_uring front
- the MTC CredentialSelector
- the libcrux non-FIPS CryptoProvider spike
- OTLP
- a 64-core scaling run

**Read with** `units/phase-7/PREFLIGHT.md`, which holds decisions D-P7.1..D-P7.8 and the probes they rest on.

**Gate file:** `gates/phase-7.toml`, with 82 carried gates and 17 new ones. **Units:** 17 JSON files in this
directory.

## What Phase 7 does with each item

| item | outcome | why (PREFLIGHT) | rung reachable |
|---|---|---|---|
| HTTP/3 | **deferred with evidence**; `ci/h3-precondition.py` + gate `no-quic` | both plan preconditions fail (D-P7.1) | n/a |
| WebTransport | **deferred**, blocked on HTTP/3 | every Rust implementation is HTTP/3 (D-P7.1) | n/a |
| PROXY v2 | built, feature `proxy-protocol`, trusted-CIDR only | D-P7.2 | R3 parser (Kani bounds + fuzz + spec vectors), R2 e2e |
| L4 SNI passthrough | built, feature `l4` | D-P7.2 | R2 e2e, R3 peek parser |
| more adapters | MariaDB (`adapter-mariadb`, new `aegis-adapter-mysql`) and CockroachDB (`adapter-crdb`, PG dialect) | D-P7.8, q4-005 | R2 two-sided oracle at ENGINE_PIN |
| io_uring front | built, feature `uring` + `--front uring`, off in every shipped profile | D-P7.3 | R2 behavioural equivalence with epoll; perf advisory |
| MTC CredentialSelector | built, feature `mtc`; selection only, MTC credential opaque | D-P7.4 | R2 decision-table oracle; no MTC validity claim |
| libcrux provider | spike in its own lock, server-only P-PUBLIC-WEB | D-P7.5 | spike verdict: KAT + interop R2; "smaller C surface" measured |
| OTLP | `aegis-otlp` exporter process, no OpenTelemetry crates | D-P7.6 | R2 e2e against a mapping-checking collector |
| 64-core scaling | harness + desktop run (≤24 cores); 64-core point blocked on GCP quota | D-P7.7 | advisory, provisional numbers |

## Gate → unit

| new gate | where | unit |
|---|---|---|
| `no-quic`: no quinn/h3/wtransport in either lock or any aegis-bin feature graph; plus the h3-precondition offline self-test | laptop | P7-spec-001 |
| `no-otel-in-bin`: no opentelemetry\*/prost/tonic in aegis-bin under any feature combination | laptop | P7-spec-001 |
| `default-graph`: default aegis-bin graph is unchanged by Phase 7 (no io-uring, no aegis-adapter-mysql, no PROXY/L4/MTC code) and the §6 budget still holds | desktop | P7-spec-002 |
| `proxy-l4`: PROXY v2 spec vectors + hostile corpus; trusted-CIDR refusal; L4 SNI routing e2e; PROXY over L4 | desktop | P7-oracle-proxy-001 → P7-wire-001, P7-bin-001 |
| `kani-wire`: Kani bounds on the PROXY v2 parser and the ClientHello peek (no panic, no read past the declared length, consumed ≤ input) | kamrui | P7-wire-001 |
| `fuzz` (carried, gains targets `proxy_v2`, `client_hello_peek`) | desktop | P7-wire-001 |
| `cred-select`: decision table (trust_anchors × sigalgs × listener kind → credential) over the selector, ≥ 1e4 generated ClientHellos, 0 divergence | desktop | P7-oracle-sel-001 → P7-mtc-001 |
| `lowering-read-mariadb`, `lowering-write-mariadb`, `schema-gate-mariadb` | kamrui (docker) | P7-oracle-adapters-001 → P7-adapter-mysql-001 |
| `lowering-read-crdb`, `lowering-write-crdb`, `schema-gate-crdb` | kamrui (docker) | P7-oracle-adapters-001 → P7-adapter-crdb-001 |
| `front-equiv`: the reverse-proxy-e2e corpus against `--front epoll` and `--front uring`, byte-identical responses and identical rejects; the hardened unit refuses io_uring unless the drop-in is installed | desktop | P7-oracle-uring-001 → P7-uring-001 |
| `otlp-export`: exporter vs a mapping-checking OTLP/HTTP JSON collector (metrics + logs), with mutants | laptop | P7-oracle-otlp-001 → P7-otlp-001 |
| `libcrux-spike`: own lock deny/lock-age/advisories, KATs, OpenSSL 3.5.3 + Go interop on X25519MLKEM768/X25519/P-256 × AES-GCM/ChaCha, C-surface count recorded | kamrui | P7-libcrux-001 |
| `scaling` (advisory, record_only): h2load at 1..24 cores, 0 errors, report written | desktop | P7-scaling-001 |
| `tcb-lines`: every Phase 7 feature has its own TCB line in SECURITY_CLAIMS.md and COMPLIANCE_MAP, names its new C/kernel/crate surface, and states its rung; deferred items carry their dated evidence | laptop | P7-compliance-001 |

Mixed MariaDB and CockroachDB placement: each engine gate is one cell, so adding an engine is one `--engine` flag on
the existing oracles. No new oracle family is created.

**Self-tests.** Every new gate has a self-test that goes red on a mutant. Each unit's `oracles` field lists its
mutants.

**Carried gates.** All 82 Phase-6 gates are carried unchanged. `fuzz` gains two targets. `budget` is unchanged,
because the default build must not move (`default-graph`).

## Roles and single writers

- **Spec-author units** (`P7-spec-*`, `P7-oracle-*`, P7-compliance-001). Each oracle goes red before its implementer
  starts.
- **Integrator unit** P7-spec-002. It pre-wires:
  - workspace members `crates/aegis-wire` (L2 pure parsers), `crates/aegis-adapter-mysql` (L4), `crates/aegis-uring`
    (L4) and `crates/aegis-otlp` (L5 binary, not a dependency of aegis-bin);
  - the features in aegis-bin and aegis-tls;
  - the io-uring 0.7.15 pin (vet + deny + lock-targets);
  - F8 additions.

  Implementers never touch Cargo.toml, Cargo.lock or supply-chain/.
- **Single writer per file:**
  - `crates/aegis-bin`: only P7-bin-001. It wires PROXY, L4, MTC, the front switch and the adapters after their
    crates land.
  - `crates/aegis-tls`: only P7-mtc-001.
  - `crates/aegis-adapter-pg`: only P7-adapter-crdb-001.

## Interfaces (frozen F-files): P7-spec-001

- **F8 config, additive.** Every field is optional, and an absent field means today's behaviour:
  - `listener.proxy_protocol = { trusted = [CIDR...] }`;
  - `listener.l4 = [{ sni = "...", upstream = "host:port" }]`, where a listener is either L4 or HTTP, never both;
  - `listener.front = "epoll" | "uring"`, default epoll;
  - `tls.credentials = [{ kind = "x509" | "mldsa" | "mtc", trust_anchor_id?, chain, key }]`;
  - adapter families `mariadb` and `crdb`.
- **F1 §F addendum:**
  - **PROXY-1:** a PROXY header from an untrusted source closes the connection before any byte is read as
    TLS or HTTP.
  - **PROXY-2:** the peer address used for admission, audit and rate limits is the PROXY source address only when
    PROXY-1 admitted it.
  - **PROXY-3:** a v1 header, a malformed v2 header, or a declared length over 536 → close.
  - **L4-1:** SNI routing reads at most one ClientHello record (≤ 16 KiB, with a stall deadline). An unknown SNI or
    no SNI → close, never a default upstream.
  - **L4-2:** L4 bytes are never parsed as HTTP.
  - **SEL-1:** the MTC credential is chosen only if the client's trust_anchors names its configured ID.
  - **SEL-2:** the ML-DSA credential is never chosen on a P-PUBLIC-WEB listener (the SC-106 withdrawal).
  - **SEL-3:** no matching credential → handshake_failure, never a different listener's credential.
  - **FRONT-1:** responses and rejects are a function of the request bytes, never of the front.
- Re-freeze both F8 and F1 in the same commit.

## Unit graph and waves

```
W0  P7-spec-001  (F8/F1 addendum, h3-precondition.py, no-quic, no-otel-in-bin)
    P7-spec-002  (members, features, io-uring pin, default-graph gate)
    P7-libcrux-001 (independent: own lock under spikes/)
    P7-scaling-001 (independent: bench/ harness; runs the default build)
W0b P7-oracle-proxy-001, P7-oracle-sel-001, P7-oracle-adapters-001, P7-oracle-uring-001, P7-oracle-otlp-001
W1  P7-wire-001          → spec-001, spec-002, oracle-proxy     (aegis-wire: PROXY v2 + ClientHello peek, Kani, fuzz)
    P7-adapter-mysql-001 → spec-002, oracle-adapters
    P7-adapter-crdb-001  → spec-002, oracle-adapters
    P7-uring-001         → spec-002, oracle-uring
    P7-otlp-001          → spec-002, oracle-otlp
W2  P7-mtc-001           → wire-001, oracle-sel                 (selector in aegis-tls, feature mtc)
W3  P7-bin-001           → wire-001, mtc-001, uring-001, adapter-mysql-001, adapter-crdb-001
W4  P7-compliance-001    → every gate id above exists
GO  python3 -I ci/run-gates.py --phase 7
```

## Placement

- **kamrui** (docker, OpenSSL 3.5.3, Go): adapters, libcrux-spike, kani-wire.
- **desktop:** proxy-l4, cred-select, front-equiv, scaling, default-graph. The desktop has io_uring enabled and 24
  threads.
- **laptop:** no-quic, no-otel-in-bin, otlp-export, tcb-lines.
- **The quiet VM** is used only by the carried release-rebuild and p2 gates.

## Residual claims to keep honest

- HTTP/3 and WebTransport are not built: "deferred, preconditions not met (2026-11-06)", not "unsupported by
  design".
- io_uring widens the kernel attack surface. The feature is opt-in and its TCB line says so.
- The libcrux spike claims "smaller C surface" only as a measured count. No side-channel claim (upstream disclaims
  it).
- The 64-core run is not done until the quota exists. Desktop scaling numbers are provisional.
