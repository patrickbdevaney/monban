# Phase 7 preflight (integrator, 2026-11-06, base e06550e)

Phase 7 is the deferred set (IMPLEMENTATION_PLAN §3): "each off by default, own TCB line". The operator directive
(2026-11-06) is "you can do the deferred phase 7 set, and maybe phase 8 and any others we cant think of?". The
2026-11-04 constraints still bind: no license, no CRA publication, no GitHub Actions, CI on kamrui, the GCP VM as
needed. Every probe below was run on 2026-11-06 and names its host or URL.

## P0. GO condition: met

- Phase 6 GO: `gates/phase-6.verdict.json`, 157/157 steps, chain af518b898fc9, head 7046005 (commit f354363).
- Ledger housekeeping before the plan: the wasmtime 50.0.1 cooldown-bypass entries were removed (e06550e). LOCK-AGE
  passes without them (285 packages, both locks).

## P1. Upstream preconditions (external probes)

| item | probe | result | decision |
|---|---|---|---|
| HTTP/3 precondition (a): h3 #366/#377/#378 | github.com/hyperium/h3/pull/366, /377, /378 | **All three are open, unmerged PRs** (frame-length bounds, decoded-header memory, QPACK "Header Accordions"). Latest h3 0.0.8 / h3-quinn 0.0.10 are from 2025-05-06, so no release has the fixes. | **not met** |
| HTTP/3 precondition (b): 6 months without a HIGH quinn advisory | github.com/quinn-rs/quinn/security/advisories, api.osv.dev | **10 HIGH + 1 MEDIUM in 2026-05-06..2026-11-06** (9 HIGH after de-duplication, per P7-spec-001 h3-precondition live run). The latest HIGH are GHSA-53rm-773f-4q8c, -wppq-2f6r-wfvm and -6pp4-4cxf-xf88, all on 2026-09-30. | **not met**. The earliest the clock can run out is 2027-03-30, if no further HIGH lands. |
| WebTransport | datatracker webtrans-http3-17 / -http2-16 (both 2026-11-02, WG Last Call); crates wtransport 0.7.2, web-transport-quinn 0.13.6 | Every Rust implementation is HTTP/3 (quinn). There is no Rust WebTransport over HTTP/2, and neither draft is an RFC. | blocked on HTTP/3 (D-P7.1) |
| PROXY protocol v2 | haproxy.org/download/3.2/doc/proxy-protocol.txt; crates ppp 2.3.0, proxy-header 0.1.3, no OSV advisories | The spec is stable and small. | own parser (D-P7.2) |
| MTC | draft-ietf-plants-merkle-tree-certs-08 (2026-11-02); draft-ietf-tls-trust-anchor-ids-07; Google blog 2026-02-27 | Negotiation is the `trust_anchors` extension, with no new SignatureScheme. Chrome is in a Phase 1 experiment with Cloudflare, X.509 fallback always present; Phase 3 is planned for Q3 2027. The Rust crates (`mtcs` 0.3.1, `synta-mtc` 0.5.1) are young and unaudited. | selector only, MTC credential opaque (D-P7.4) |
| libcrux CryptoProvider | celabshq/rustls-libcrux (crate `rustls-libcrux-provider` 0.0.1, **not on crates.io**, ChaCha20-Poly1305 only, no AES-GCM); `rustls-provider-libcrux-pq` 0.1.1 (single-author, 37 downloads, no P-384 ECDSA, no RSA PKCS#1 verify); neither in rustls PROVIDERS.md | Primitives on crates.io (2026-10-07 unless noted): libcrux-ml-kem 0.0.11, -curve25519 0.0.9, -p256 0.0.9, -chacha20poly1305 0.0.10, -aesgcm 0.0.8 (2026-05-13; does not co-resolve with ml-kem 0.0.11, so the spike uses libcrux-aes 0.0.10), -hmac/-hkdf/-ecdsa 0.0.9, -ed25519 0.0.10. ML-KEM arithmetic, NTT and serialization are hax/F\* verified. Upstream says it is **not verified side-channel resistant**. No C build dependency was found. | our own server-only provider on the primitives, as a spike (D-P7.5) |
| OTLP | spikes/otlp-footprint (verdict **flip**: in-process OTLP breaks the crate budget); opentelemetry-otlp 0.33.1 always pulls prost and opentelemetry_sdk | Already resolved: out of process. | hand-rolled OTLP/HTTP JSON exporter process (D-P7.6) |
| io_uring | crates io-uring 0.7.15 (2026-09-07), compio 0.19.2, tokio-uring 0.5.0 and monoio 0.2.4 (both stale since 2024); NVD keyword search shows ≥8 HIGH io_uring CVEs in 2026, the latest 2026-11-02; Docker's default seccomp drops io_uring (moby #46762); Google restricts it in production (2023 kCTF post) | A real attack surface that default container runtimes deny. | opt-in feature only, on io-uring 0.7.15 directly (D-P7.3) |

## P2. Local probes

| need | probe (host) | result | decision |
|---|---|---|---|
| io_uring available | `/proc/sys/kernel/io_uring_disabled` (laptop 6.17.0-14, desktop 6.11.0-29, kamrui 6.17.0-41) | 0 on all three | Tests run on the desktop. The hardened unit's `SystemCallFilter=@system-service` is checked by the unit for whether it admits io_uring_*. |
| 64-core scaling run | `gcloud compute project-info describe`, `regions describe us-central1` | **CPUS_ALL_REGIONS limit = 12**, C2 = 8, C2D = 100, N2 = 200 regional | **A 64-vCPU VM cannot start.** See D-P7.7. |
| MariaDB and CockroachDB images | spikes/q4-005 (measured 2026-10) | mariadb:11.8 334.5 MB, cockroach v25.4 464.3 MB unpacked; MySQL 8.4 829 MB | Both are under 500 MB, so they run on kamrui. MySQL stays out. |
| laptop disk | `df -h /` | 8.7 GB free, under the 10 GB floor. AEGIS `target/` is 2.4 GB; the rest is not AEGIS's. | Clear `target/` before full runs. Leftover agent worktrees were removed (branches kept). Remote per-worktree dirs on desktop and kamrui were deleted. |
| AL2023 build image size | kamrui `docker image inspect` | 168 MB compressed; `image.sh` asserts unpacked < 500 MB | unchanged |

## P3. Decisions

**D-P7.1 HTTP/3 and WebTransport are deferred with evidence.** This is not a weakening: the plan line makes both
preconditions mandatory, and both fail. Phase 7 delivers instead:
- `ci/h3-precondition.py`. It re-runs the two probes (GitHub PR state for #366/#377/#378, and the OSV and GitHub
  advisory list for quinn, quinn-proto and quinn-udp). It prints `H3-PRECONDITION: MET` or `NOT MET (…)` with dates.
  It is a manual check, not a gate, because gates do not depend on the network. Its offline self-test runs on recorded
  fixtures.
- Gate `no-quic`: no quinn\*, h3\* or wtransport crate in either lock or in any aegis-bin feature graph, so H3 cannot
  arrive by accident.
- Re-check date: 2027-03-30, or sooner if the PRs merge and a release ships. If HTTP/3 is built later, it needs our own
  frame/QPACK limits in front of h3, and quinn-proto ≥ 0.11.19 / quinn-udp ≥ 0.5.16 as floors.

**D-P7.2 PROXY v2 and L4 use our own parsers.** The PROXY v2 header and a minimal TLS ClientHello peek (SNI,
supported_versions, ALPN, trust_anchors) are each about 300 lines. That is less TCB than a dependency, and it suits
Kani (bounded, no allocation) and the fuzz gate. PROXY is accepted only from configured trusted source CIDRs. From
anyone else it is refused. It is never auto-detected.

**D-P7.3 io_uring is an opt-in front, in its own process mode, off in every shipped profile.** Feature `uring` plus
`--front uring` at runtime. It is not in the hardened unit by default; a separate unit drop-in is needed. It is built
on io-uring 0.7.15, not on a stale runtime crate. Its TCB line names the kernel io_uring surface explicitly. The perf
claim is advisory; the gate is behavioural equivalence with the epoll front.

**D-P7.4 MTC: CredentialSelector only.** A selector picks a credential per ClientHello: an MTC credential when the
client's `trust_anchors` names a configured MTC trust anchor ID, else ML-DSA for private hops, else the classical
chain. The MTC credential is an operator-supplied opaque blob. AEGIS neither issues nor verifies MTCs (rung: selection
logic R2 against a decision-table oracle; no MTC validity claim). Feature `mtc`, off by default. Because rustls 0.23
does not expose `trust_anchors`, the selector reads it from the same ClientHello peek as D-P7.2.

**D-P7.5 libcrux: our own server-only provider, as a spike, in its own lock.**
- Scope: P-PUBLIC-WEB server side only.
  - Key exchange: X25519MLKEM768, X25519 and P-256.
  - AEADs: AES-128/256-GCM and ChaCha20-Poly1305.
  - SHA-2, HMAC and HKDF.
  - Signing: ECDSA-P256 or Ed25519 server keys.
  - No client verification. FIPS stays on AWS-LC.
- It lives in `spikes/libcrux-provider/` with its own Cargo.lock, so it never enters either shipped lock. Gate
  `libcrux-spike` runs on that lock, on kamrui:
  - deny, lock-age and an advisories check;
  - KATs;
  - OpenSSL 3.5.3 and Go interop handshakes;
  - a C-surface count (C source files compiled by the build, before and after), plus handshake cost versus aws-lc-rs,
    recorded.
- Its verdict says whether the "smaller C surface" claim holds, at which rung, and with the upstream caveat that
  side-channel resistance is not verified.

**D-P7.6 OTLP: `aegis-otlp`, a separate binary with no OpenTelemetry crates.**
- What it does:
  - scrapes the admin listener's OpenMetrics text;
  - reads aegis JSON logs on stdin;
  - POSTs OTLP/HTTP JSON (`/v1/metrics`, `/v1/logs`).
- How it is built: a hand-rolled encoder on hyper (already in the graph).
- Gates:
  - `no-otel-in-bin`: no opentelemetry\* or prost in the aegis-bin graph.
  - `otlp-export`: exporter end-to-end against a dummy collector that checks the OTLP JSON mapping, with mutants.

**D-P7.7 The 64-core scaling run is blocked by GCP quota; the harness is built and run on the desktop.**
- `bench/scaling` drives aegis with h2load (the approved public tool) at 1, 2, 4, 8, 16 and 24 cores on the desktop
  (24 threads). It records req/s and p99 per core count. Gate `scaling` is **advisory, record_only**: it passes when
  every point ran with 0 errors and the report was written.
- The 64-core point needs CPUS_ALL_REGIONS ≥ 64. The planned shape is c2d-standard-64 in us-central1, about an hour.
  The quota increase request is an operator step (§P4).
- Laptop and desktop numbers are provisional by CLAUDE.md.

**D-P7.8 More adapters: MariaDB and CockroachDB, golden only after a two-sided oracle at 0 leaks.**
- From q4-005: both engines are 0 leaks in 10 800 cases per engine, with the engine-specific mandated forms and the
  amended W3 schema gate.
- CockroachDB rides the PG wire (`aegis-adapter-pg` with a `crdb` dialect: upsert guard fix, SERIALIZABLE retry).
- MariaDB needs a new `aegis-adapter-mysql` with our own wire client:
  - mysql_native_password and caching_sha2 refused at first;
  - binary prepared statements only;
  - loopback or TLS.
- Two-sided means both read (lowering-read) and write (lowering-write) oracles run against the live engine, plus the
  schema gate.
- Each has its own feature: `adapter-mariadb` and `adapter-crdb`.

## P4. Operator steps outside agent scope (listed, not done)

1. **GCP quota:** raise CPUS_ALL_REGIONS from 12 to at least 64 (plus C2D ≥ 64 in us-central1) for the 64-core
   scaling run. The request is made in the Cloud console under IAM & Admin → Quotas. After that the run is one command
   (`bench/scaling --gcp c2d-standard-64`) and costs about an hour of VM time.
2. Unchanged from Phase 6: license, CRA publication, real release keys, D-P4 BoringSSL text.
3. HTTP/3 re-check on or after 2027-03-30 (`ci/h3-precondition.py`).

## P5. Added during the phase

- **io-uring 0.7.15 vet audit** (P7-spec-002): no import set covered it at safe-to-deploy, so the zero-exemption rule
  forced an own audit (all ~5.9k hand-written lines, ~87 unsafe sites read). Its `who` records an agent review: the
  operator should countersign or replace it with a human audit before the `uring` feature is used in production.
- **aegis-uring unsafe budget** (DEVIATIONS X-15): io-uring's submission API is `unsafe fn`, so aegis-uring may hold
  ≤ 6 audited sites; `cargo xtask unsafe-sites` enforces it.
- **F8 admission.per_ip** (P7-spec-001, wired by P7-bin-001): the S1 per-IP GCRA (1000/s, burst 2000) was hard-coded;
  the scaling bench from one source IP was all 429s. Absent = today's values.
