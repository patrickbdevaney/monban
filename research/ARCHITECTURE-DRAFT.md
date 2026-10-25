# AEGIS ARCHITECTURE-DRAFT (running; integrator-maintained)

Status: **after round 3 (2026-10-25)**. This is the running protocol of directive §9, built only from the independent map (`state/graph.jsonl`, 756 node ids) under the §0a blind-research rule. It is not reconciled with the prior treatments; that happens only at Synthesize/Critique/Final. Every rule carries an evidence grade, node ids and a reversal condition. Rule diffs per round are in §R.

Grade convention:
- A/B/C/D/E as in META §3.
- A rule's grade is the weakest link among its load-bearing evidence. A decision we inferred from graded inputs is marked E (design) or C (decision with independent support).
- §0b applies: every database and protocol rule is an **adapter or front-end** rule inside a backend-agnostic data plane (§3 "Data plane") and a protocol-agnostic ingress (§3 "Ingress"). Postgres and SQLite are examples only.
- §0c applies: proofs are build-time artifacts only; the production image ships zero prover binaries.

---

## 1. Positioning and the unserved gap

- **R-GAP-1** [C] The gap is integration plus assurance, not a missing primitive.
  - No surveyed system (~45 repos) combines all of: a memory-safe single binary, per-request isolation, capability authz, native agent protocols, PQ-TLS, and machine-checked claims.
  - Round 2 adds a measurable leanness column: hyper+rustls core 4.21 MB stripped / 40 crates vs nginx 8.05 MB with libs, Pingora 7.24 MB / 174 crates, Caddy 52 MB, Envoy 107 MB (`w02.size-deps-table` [A]).
  - Nodes: `gap.unserved-combination`, `gap.no-assurance-claims`, `gap.agentgateway`, `gap.spin`, `gap.pingora`, `w02.size-deps-table`.
  - Reverse if a project or closed product is found holding ≥4 of the 6 columns.
  - Diff r3 (verdict unchanged, C): closest 2026 prior art is coproduct-opensource/nucleus (MIT, v2.7.0 2026-10-08): an agent tool-proxy with an IFC permission lattice checked in Lean 4 (195 .lean files) plus Kani, SPIFFE identity and Firecracker pods; >100 crates and not a front proxy. agentgateway v1.6.0 / v1.7.0-alpha.1 gets PQ through aws-lc-rs 1.18 and authorizes with CEL (no formal-methods or DST hits). Rullst has selected Kani/Miri scopes and delegates TLS to Caddy. All three were pushed 2026-10-24, so recheck at final synthesis. Node: `gap.unserved-combination` (r3 revision).
- **R-GAP-2** [A] Fail-closed default configuration is a positioning requirement, enforced by a CI gate that tests the shipped default config.
  - Round 2 generalizes it to **fail-closed construction** (see R-DB-3, R-AUTHZ-5): across 2025-26, empty or absent policy defaults to allow-all in NATS, Kafka, FDB, Hasura, Turso, Apache Syncope (CVE-2026-73579) and DBHub. A KEV-listed MCP auth bypass (LiteLLM CVE-2026-59822, KEV 2026-09-02) mapped an auth error to an empty principal.
  - Nodes: `gap.insecure-defaults`, `dpf-empty-means-all-pattern`, `r2e11.litellm-failopen`, `v2.docker-mcp-gateway-advisories-r2`.
  - Reverse: never; this is a hygiene floor.
- **R-GAP-3** [A] Choose bases and dependencies by governance: multi-maintainer or foundation, and a release within 24 months. Round 2 adds: pin every dependency with a lockfile and run a post-bump smoke request, because a fresh Pingora 0.9.0 build with tokio ≥1.54 panics on the first connection (`w02.pingora-tokio-panic` [A], cloudflare/pingora#1059, PR #1060 unmerged).
  - Nodes: `gap.dormancy-churn`, `hist-urweb-adoption-bus-factor`, `w02.pingora-tokio-panic`.

## 2. Threat model (ranked, likelihood × impact)

- **R-THR-1** [B] Rank threats in this order:
  1. H2/H3/QUIC protocol-state resource exhaustion [A], now including H3→H1 translation amplification (CDN Tsunami: QPACK expansion 36-350×, `r2e11.cdn-tsunami` [B]) and stalled flow control (CERT VU#885548, `r2e11.h2-stalled-flowcontrol` [A])
  2. Path/host canonicalization and fail-open authz logic [A/B]
  3. Request smuggling and parser differentials [A], including the H3→H1 seam (HAProxy CVE-2026-33555) and opportunistic-TLS desync (Opossum, CVE-2025-49812)
  4. Memory corruption in C/C++ components, the RCE tail [A]
  5. Agent/MCP origin binding, session-principal binding, token audience, and parser differentials in gateway policy [A/B]
  6. Cross-request state scope violations (tickets, pools, caches, idempotency, JWKS) [A] (new in round 2: `crs-verdict-matrix`)
  7. TLS validation logic, including PQ downgrade [B]
  8. Data-plane injection/authz bypass per backend family, incl. agent DB tools [A] (new: `dpf-family-matrix`, `dpf-agent-db-tool-bypass-cluster`)
  9. Decompression and algorithmic complexity [B]
  10. Supply chain: account takeover and slopsquatting [A incident / B rates]
  - **Diff r2 (metric made explicit):** the order depends on the metric. By in-the-wild exploitation (KEV), canonicalization and authz lead (5-6 of 8 OSS middle-tier KEV entries). By advisory volume in the Rust HTTP stack (OSV 2023+, ~51 incidents), resource exhaustion leads (~63%). Both orders are kept (`threat-ledger-middle-tier-2023-2026` r2 revision).
  - Reverse if a year of KEV and advisory data reorders the top three under both metrics.
  - **Diff r3:** the Rust-stack advisory share was recomputed with GHSA/RUSTSEC alias dedupe (111 records → 69 clusters, 51 since 2023): resource exhaustion 61% (CI 47-73%), falling to 50% in 2026 while TLS validation logic rose to 25%. For 2026 Rust stacks, rank TLS logic above memory corruption (`threat-ledger-middle-tier-2023-2026` r3 revision, B). New class: async cancellation (R-THR-5). Four classes recurred independently across Go, Traefik, Fastify, undici, Caddy, Apache and wasi-http in 6 weeks (Sep-Oct 2026): trailers, H3→H1 bridging, validator/handler divergence, unbounded sizes (`r3e11.cross-stack-bug-classes-sep-oct-2026`, B).
- **R-THR-2** [B] Assume AI-accelerated discovery. Every TCB component needs a rebuild-and-release path measured in hours, plus runtime feature kill-switches. Round 2 evidence: Lean kernel soundness bug found with AI models (`vfg-lean-kernel-soundness-bugs-2026`), HAProxy H3 desync reportedly LLM-found, HTTP/2 Bomb found with Codex.
  - Diff r3: OpenSSH 10.6 (2026-10-06) says AI-surfaced bugs are being independently rediscovered and moves to more frequent releases; Apache Thrift 0.25.0 fixed 61 CVEs in one announcement (2026-10-04) (`r3e11.ai-found-bug-flood-vendor-posture`, A). Golden: security patch release SLA ≤7 days, with the in-place upgrade path (R-OPS-7) exercised weekly in CI.
- **R-THR-3** [B] Memory safety is required (it removes the RCE tail) but insufficient. Mitigation effort goes first to logic and resource classes.
  - **Diff r2:** the pooled 2023-26 KEV non-memory share (78.8-81.9%) hides a 2026 regime shift: memory bugs surged in C servers (httpd 20 of 44 advisories in 2026 vs 2 of 33 in 2023-25; nginx 19 of 26). This raises the value of memory safety for anything still in C (aws-lc, libsql, librdkafka, libfdb_c). Node: `result-memory-safety-would-not-prevent-fraction` (B, revised down).
- **R-THR-4** [A] (new) Remote timing: TCP timestamps expose server processing time without network jitter (NDSS'26 / BH USA'26). Any constant-time claim (token MAC compare, crypto) must hold at TCP-timestamp resolution, and the network-noise argument for non-constant-time code is dead. Node: `r2e11.tcp-timestamp-timing`.
- **R-THR-5** [A instances / B class] (new r3) **Async cancellation is a threat class.** Dropping a future at an await, after the wire send but before the cleanup owner exists, leaves a resource mid-protocol, and a pool or runtime then reuses it.
  - 15 verified instances in 5 ecosystems, 6 from 2026: sqlx #4393 (a cancelled `Pool::begin` leaves the connection in a txn; fix f1e94ec main-only), diesel_async #304 (the next borrower reads the cancelled MySQL result; fix #305 unreleased), rust-postgres PR #1374 (named server objects stranded; open), redis-py CVE-2023-28858 (cross-user replies, ChatGPT 2023-03-20; NVD CVSS 3.7 underrates it), Go CVE-2025-47907 (another query's rows), Wasmtime CVE-2026-27195 and GHSA-3r89 (host panics), oneshot RUSTSEC-2026-0005 (use-after-free), omicron/dropshot #695 (mutex state corrupted on disconnect), futurelock (omicron #9259).
  - The attacker chooses the instant: hyper drops the service future on h2 RST_STREAM and h1 close, and tower-http `Timeout` drops the inner future on expiry.
  - "One txn per request + outbox" closes only about 5 of 15 (not pooled protocol state, ambiguous commit, tokio-Mutex state, accounting, Wasm instances, liveness).
  - Mitigation: R-STATE-6/7. Nodes: `ac.root-cause-drop-at-await` (A 0.82), `ac.attacker-chosen-cancel-instant` (B; the MadeYouReset advisory RUSTSEC-2025-0070 is pingora-core), `ac.counter-hypothesis-one-txn-outbox` (B).
  - Reverse if a cancellation-deferral mechanism (AsyncDrop, linear futures) becomes stable in Rust and is adopted by hyper and the drivers.

## 3. Reference architecture (component picks; each one candidate among alternatives)

### Ingress, modularity and leanness (§0b)
- **R-ING-1** [C] (new) One protocol-normalization core plus feature-gated front ends.
  - Core: http-types request/response, a single admission layer, one canonical request form consumed by routing and authz.
  - WebSocket, SSE and WebTransport are stream modes of the core. gRPC, GraphQL, MCP and webhooks are handler layers. TCP/UDP stream proxying is a separate L4 path.
  - Translation seams (H3→H1, H2→H1) are the documented failure site: a downgrade must check FIN/length consistency, buffer the full request before opening a backend connection, and apply a decoded-bytes budget before translation (`r2e11.haproxy-cve-2026-33555` [B], `r2e11.cdn-tsunami` [B]).
  - Evidence is indirect: the fixed cost of h1+h2+TLS+PQ is 4.21 MB / 39 deps; each extra codec adds ~23 crates; normalization copy cost is unmeasured. Nodes: `w02.ingress-design-verdict` (C), `w02.feature-cost-unused` (A).
  - Reverse if the normalization copy cost (q2-016) exceeds 10% of per-request CPU for 10 MB bodies, or a per-protocol stack shows fewer seam bugs.
  - **Diff r3:**
    - Copy cost is measured (q2-016 closed). Zero-copy `Bytes` through `http::Request<Body>` makes 0 userspace copies and costs 30 µs user CPU per 10 MB. An owned decode+encode codec adds 0.58-0.72 ms (+28-34% wall at 1 core; kernel copies dominate). The reversal is not met for the zero-copy design (`w02.norm-copy-cost-measured`, A 0.75).
    - The core object is an **Exchange** with a message stream (per-message and per-lifetime budgets), not a Request.
    - Normalization is non-destructive: raw bytes are retained, which webhook signatures need.
    - Authz consumes only the core-canonicalized route identity (grpc-go CVE-2026-33186, critical: interceptors matched a raw `:path`).
    - TCP/UDP stream proxying and PROXY protocol are a separate L4 module (R-ING-3).
    - WebTransport is deferred from golden v1 (draft-16 in WGLC, quinn 11 GHSAs in 2026, h3-webtransport stale since 2025-05). So is permessage-deflate.
    - New reversal: if any front end needs more than 2 core hooks, per-protocol stacks win.
    - Nodes: `r3e09.ring1-verdict-amendment` (C), `r3e09.core-vs-per-frontend-matrix` (C), `w02.ingress-design-verdict-measured-update` (B).
- **R-ING-2** [A classes / C numbers] (new r3) **Front-end defect-class rules**, held once in the core where possible:
  - **WebSocket.** A typed Origin (absent | null | opaque | parsed) is checked against a per-route allowlist; `null` is denied unless listed. Rust WS crates do no Origin check (fastwebsockets, tungstenite). 2025-26 CSWSH CVEs: Vitest, Mailpit, Next.js dev server (Low), nginx-ui, Spring for GraphQL.
    - Leave framed mode only after a validated 101 (status, Connection/Upgrade tokens, Sec-WebSocket-Accept); bytes before the 101 are buffered or rejected. Pingora CVE-2026-2833 (critical, ≤0.7.0), Netty CVE-2026-59898, Envoy CVE-2024-23326.
    - No permessage-deflate in the golden (2026 size-check-ordering CVEs: undici, websocket-driver, Autobahn).
    - max_message 1 MiB, max_frame 64 KiB, write buffer ≤4× message (tungstenite defaults: 64 MiB / 16 MiB / `usize::MAX`).
  - **gRPC/Connect.** Authorization on the canonical route only. h2 ≥0.4.16 (RUSTSEC-2026-0258, 1-byte DATA fragmentation).
    - Set `max_concurrent_streams`, header list size, decode size (1 MiB) and timeout explicitly: tonic 0.14.6 stores `None` and passes it to hyper, overriding hyper's 200 (static read; runtime check q3-032).
  - **GraphQL** sits behind the core: Content-Type allowlist (415 on text/plain), no mutation over GET (405), body cap 64 KiB, explicit depth/complexity/alias/directive/batch limits. async-graphql 7.2.1 defaults are all `None`, and validator quadratics (graphql-php CVE-2026-40476) are not caught by depth caps.
    - IBM static cost produces one scalar charged to the core per-principal budget.
  - **Webhooks.** The signature is verified over the RAW bytes with a constant-time compare (`subtle`). Replay store TTL ≥ max(tolerance, retry horizon), because Stripe retries for 3 days with fresh signatures. Tolerance 0 is rejected at config load; ≥2 secrets for rotation.
    - Outbound delivery and callback registration go through the egress guard: connect to the pinned validated IP, apply a redirect policy, handle NAT64/6to4. SSRF-at-delivery was the highest-count 2026 webhook class (PraisonAI, Firefly III, Plane fix-of-fix, Gogs, Postiz).
  - **SSE.** ≤8 streams per principal, keepalive 15 s, replay window 1,000, jittered `retry` ≥3,000 ms, slow-reader disconnect.
  - **Fail-closed config:** CI boots the default config and fails if any effective limit is `None`/unbounded (asserted via h2 SETTINGS, WS 1009, GraphQL 4xx, webhook replay reject).
  - Nodes: `r3e09.ws-cswsh-origin`, `r3e09.ws-upgrade-smuggling`, `r3e09.ws-deflate-and-frame-dos` (B), `r3e09.grpc-defect-classes`, `r3e09.tonic-connect-crate-scorecard` (B), `r3e09.graphql-defect-classes` (B), `r3e09.async-graphql-defaults-audit` (C), `r3e09.webhook-defect-classes`, `r3e09.sse-defect-classes` (B), `r3e09.L5-per-frontend-budget-table` (C), `r3e09.L5-ingress-conformance-harness` (C).
  - Own fuzz/differential harnesses are required: OSS-Fuzz covers only hyperium/http and httparse among these crates (`r3e09.ossfuzz-negative`). Every cited CVE gets a named regression test.
  - Reverse a numeric limit when golden agent traffic measurably hits it.
- **R-ING-3** [B] (new r3) **The L4 stream proxy and PROXY protocol are a separate feature crate below the HTTP core**, off by default, with their own TCB line.
  - PROXY headers are accepted only from explicit trusted CIDRs, once per connection, never guessed; v1 ≤107 bytes; ≥3 s header timeout. 2026 spoofing CVEs: Puma, Netty codec, ProxySQL (default trust `*`).
  - UDP gets a 3× anti-amplification budget (Netty QUIC CVE-2026-44894, OpenSSL QUIC CVE-2026-35191).
  - Envoy itself only hardens tcp_proxy/udp_proxy against an untrusted downstream.
  - Node: `r3e09.l4-proxy-protocol-udp` (B).
- **R-TLS-8** [A] (new) One TLS mode per port. Never implement RFC 2817 `Upgrade: TLS` or opportunistic TLS; reject the header in the core. Node: `r2e11.opossum` (USENIX Sec'26, CVE-2025-49812; Apache removed RFC 2817).
- **R-MOD-1** [B] (new) Modularity mechanism: Cargo features.
  - Defaults are h1, h2, tls, pq only. A feature that is off adds zero code (measured: h3 referenced-only +15 KB; features off add nothing).
  - No native `dlopen` plugins: loaded code is invisible to audit, there is no stable Rust ABI, and nginx needs signature checks because internal structs change with configure options.
  - Compiler-bearing modules (Wasmtime with Cranelift: +8.94 MB, +57 crates, +12.1k unsafe lines) run out of process behind capability IPC, or use the precompiled `.cwasm` no-compiler runtime (+393 KB). Precompiled artifacts are MACed and keyed locally; never `Module::deserialize` untrusted bytes (runwasi CVE-2026-47218, CVSS4 9.3).
  - CI commits a per-feature size/crate/unsafe delta; `cargo hack --each-feature`; a features-off build must contain none of the feature's crates (`cargo tree -i`).
  - Nodes: `w02.L5-feature-gate-rule`, `w02.feature-cost-unused`, `r2e11.runwasi-cve-2026-47218`.
  - Reverse if measured out-of-process IPC cost (q2-001) exceeds 2× the in-process cost for typical handler calls; then Wasm components in process with a host-enforced boundary become the default module form.
  - **Diff r3 (direction narrowed; the reversal condition fired for cheap ops):**
    - Measured on one pinned laptop core: UDS+postcard noop 4.8 µs (p99 5.7), futex shm ring 2.1 µs, in-process 0.02-0.05 µs. A SigV4-presign-shaped op costs 1.34 µs in process vs 6.93 µs over UDS (5.2×); a redis-GET-shaped op is about 100×.
    - Out-of-process is now used only for modules with a C/C++ binding, more than 15 unsafe sites, third-party provenance or a compiler, and only within a hop budget: rate × 4.8 µs ≤ 10% of a core (≈20k calls/s/core).
    - 20k-100k calls/s needs batching or replacing the C dependency.
    - Hot pure-Rust paths (>50k/s or op <10 µs) stay in process.
    - Third-party Wasm-compilable modules above the hop budget run as in-process Wasm components inside an OS-sandboxed worker (R-ISO-1).
    - The thresholds are policy derived from one laptop (C) and must be re-baselined on a 1-vCPU VPS (q3-002).
    - Nodes: `w02.ipc-hop-cost-1core` (A), `w02.redis-presign-shaped-ops` (A), `w02.spin-ring-negative-result` (A), `w02.L5-adapter-oop-threshold-table` (C), `w02.L5-feature-gate-rule-amendment` (B).
- **R-PERF-1** [B] (new) Lean budget for the core (CI-enforced):
  - Stripped binary ≤6.0 MB (measured 4.21); full build without in-process Wasm JIT ≤9 MB.
  - ≤60 crates (40); non-crypto unsafe lines ≤5,000 (3,325); own crates `forbid(unsafe_code)`; aws-lc-sys is a separate TCB line (11.3k unsafe binding lines, 1.5M bundled C/asm LOC).
  - Idle RSS ≤8 MB (3.4-5.9); 1k idle TLS connections ≤25 MB (17.2).
  - X25519MLKEM768 handshake ≤1.3× X25519 server CPU and ≤2.4 KB extra wire bytes. Measured: +12.5-15.0% over two logged trial pairs and +1.1/+1.2 KB. Diff r3: the earlier +17.5% "best trial" appears in no log (`w02.handshake-pq-cost` r3 revision, B).
  - Static h1 ≥0.5× nginx in the same run.
  - Measured comparisons [A]: idle RSS nginx 12.7 MB, Pingora 6.9, Caddy 45, Envoy 63, HAProxy 45-78 (maxconn-dependent). rustls/aws-lc is ~2× cheaper per X25519 handshake than OpenSSL-based servers.
  - Budgets are derived from a hello-world baseline, so they are a floor, not a forecast (verifier). Nodes: `w02.L5-lean-budget`, `w02.size-deps-table`, `w02.idle-rss-table`, `w02.handshake-pq-cost`.
- **R-PERF-2** [B] (new) Benchmark protocol: isolated cpuset core plus a `--cpus=1` run, 512 MB, ≥3 trials with loadavg logged, cgroup `cpu.stat` µs/request as the primary metric, lockfile pinned, unique high ports. Quote rankings only outside 2× variance. Nodes: `w02.L5-bench-plan`, `w02.throughput-h1-h2` (B; 2.8× trial variance on a contended host).
  - Diff r3: report bands from interleaved ABBA trials (≥5 reps, isolated cores with an idle SMT sibling, per-run loadavg recorded), never a single best trial. CI gates derived from laptop numbers are provisional until re-run on the target VPS class (`w02.L5-bench-harness-spec`, A).
- **R-PERF-3** [B] (new r3) **IPC wire rules** for every out-of-process boundary:
  - postcard 1.1.3 or raw frames. bincode is forbidden by policy (RUSTSEC-2025-0141, unmaintained).
  - Byte fields use `serde_bytes`. A 64 KB echo is 4.9× slower without it; CI runs a 64 KB echo perf test per schema.
  - Bodies cross the boundary as fd/stream frames, never inside a serialized message.
  - No shared-memory ring in the default build. No spin-waiting when `available_parallelism ≤ 2`: a spin-then-futex ring costs 638 µs per call on one core.
  - CI streams 10 MB through the core and asserts allocator bytes < 1% of the body and 0 explicit copies.
  - Nodes: `w02.serde-bytes-pitfall`, `w02.spin-ring-negative-result`, `w02.bincode-unmaintained-use-postcard`, `w02.L5-feature-gate-rule-amendment` (B).
  - Reverse rule 8 if a 2-vCPU target makes spin rings pay (195 ns on 2 dedicated cores).

### Transport / parser
- **R-TLS-1** [A] Front protocols: HTTP/1.1 and HTTP/2 over TCP, using hyper `=1.12.0` and h2 `=0.4.20`, with the golden config pins and an AEGIS wrapper:
  - hyper pins: max_concurrent_streams 100; max_header_list_size 16384; header_table_size 4096; max_pending_accept_reset_streams 20; max_local_error_reset_streams 256; stream window 256 KiB; connection window 1 MiB; max_frame 16384; send buffer 400 KiB; keepalive interval and timeout 20 s. Never raw h2 defaults (unbounded streams, 16 MiB MHLS).
  - Wrapper (for gaps hyper/h2 do not cover, grep-verified): header field count ≤128 including cookie crumbs; handler semaphore 100 with a 4× queue then GOAWAY ENHANCE_YOUR_CALM; RST bucket 100 burst / 33 per s; max total streams 10k; per-stream stall deadline 10 s regardless of WINDOW_UPDATE/PING; connection idle 30 s; `Counts` assert paths unreachable.
  - Nodes: `l5-config-pin-table-transport`, `l4-h2-budget-mechanics-0.4.20`, `crate-hyper-h2`.
  - Diff r2: pins and wrapper added. Reverse if hyper/h2 ship a field-count cap and stall timer (`pred-hyper-h2-stall-or-count-cap`), letting the wrapper shrink.
- **R-TLS-7** [B] (new) The **Transport Budget Invariant TBI-1..9** is a named SPEC_INVARIANT:
  - TBI-1 header list bytes (32+n+v) ≤16384 and fields ≤128, counted before merge; TBI-2 decoded bytes per block ≤4×MHLS and work ≤K1·wire + K2·decoded; TBI-3 HPACK table ≤4096, QPACK capacity 0 and blocked streams 0; TBI-4 live handlers ≤100, queued ≤400, permit acquired before spawn and released on drop; TBI-5 RST bucket, error resets ≤256 per lifetime, total streams ≤10k; TBI-6 buffered body ≤ connection window; TBI-7 live allocation ≤ S·(F·C_FIELD + MHLS) + window + send buffer (~6.3 MiB, C_FIELD ≤256 B to be measured); TBI-8 stall deadline; TBI-9 no reachable panic.
  - Live handlers are bounded, not open streams (the MadeYouReset lesson; Go x/net's 4× queue rule, HAProxy glitch counter, nghttp2 RST bucket).
  - Tools: Kani on pure counter/window structs (h2 `FlowControl`, `Budget`, our RST bucket; Firecracker's token-bucket harness is the precedent); Verus for our unbounded ledgers; a Lean core composition lemma; fuzz with a resource-ratio oracle; DST with paused time for TBI-8.
  - Not provable over h2 as written: TBI-4 (hyper-spawned tasks outlive h2's protocol counts), TBI-8 (no timer exists), TBI-7's C_FIELD (allocator-dependent), TBI-1's field count. These need the wrapper.
  - Nodes: `l5-transport-budget-invariant-tbi`, `l5-tbi-tool-assignment`, `l5-kani-harness-spec-tbi`, `l5-fuzz-oracle-tbi`, `l5-ci-gate-tbi` (C), `l4-handler-bounded-designs`, `l4-temporal-stall-liveness`, `l4-firecracker-kani-token-bucket`, `r2e11.h2-stalled-flowcontrol`.
  - Reverse if a measured C_FIELD makes TBI-7 exceed 16 MiB per connection at the pinned limits (then lower the stream cap).
- **R-TLS-2** [A/B] HTTP/3 stays opt-in, and **off in the golden** until hyperium/h3 #366/#377/#378 land (h3 0.0.8: `max_field_section_size = VarInt::MAX`). If enabled: quinn 0.11.19 with `receive_window` 4 MiB (default VarInt::MAX ≈ 250 MB/conn), stream window 256 KiB, 100 bidi / 8 uni streams, 30 s idle; or quiche with its 24 MiB connection window lowered; s2n-quic defaults are acceptable (3.75 MB window).
  - Use the NDSS'26 MerCuriuzz logical-vulnerability categories as the QUIC state-machine test checklist.
  - Nodes: `l4-quic-stack-window-defaults`, `crate-quinn`, `crate-h3`, `r2e11.mercuriuzz-quic-logic`, `l5-config-pin-table-transport`.
  - Reverse after h3 merges finite defaults (`pred-h3-qpack-limit`) and 6 months with no HIGH quinn advisory.
  - Diff r3:
    - quinn-proto 0.11.18 fixed three remote-peer panics (RUSTSEC-2026-0338/0340/0343; 0338 only in unordered-read mode). Pin ≥0.11.19 and keep ACK_FREQUENCY and datagrams off unless needed (`r3e11.quinn-proto-0.11.18-19`, A).
    - A zero-drop H3 upgrade needs CID routing (nginx 1.31.7 `quic_bpf`, Proxygen packet forwarding, QUIC-LB draft-22); golden v1 accepts H3 resets on upgrade.
    - The QUIC listener authenticates with ECDSA/Ed25519 until MTC: every ML-DSA chain is ≥10.5 KB and exceeds the 3× pre-validation amplification budget (`r3pq.quic-amp-budget-mldsa`, B; modelled).
- **R-TLS-3** [B] Upstream framing is HTTP/2 or a framed Unix socket by default. Any HTTP/1.1 upstream regenerates framing. Strict H1 grammar as round 1. Nodes: `threat-request-smuggling-desync`, `rec60-ai-desync-http-terminator`.
- **R-TLS-4** [A] TLS uses rustls `=0.23.46` + aws-lc-rs, and rustls-webpki `>=0.103.16`. rustls 0.23.46 default features (aws_lc_rs, prefer-post-quantum) also give every rustls-based DB driver PQ-hybrid offers with no driver change; C-TLS drivers (rdkafka, foundationdb) do not inherit it (`dpf-rustls-pq-driver-inheritance` [A]). Server-side PQ support of DB servers is unverified (q2-014).
  - Diff r3:
    - Every rustls in Cargo.lock must enable `prefer-post-quantum`. With `default-features=false` DEFAULT_KX_GROUPS becomes [X25519, P256, P384, X25519MLKEM768] (measured 319 B vs 1,539 B ClientHello, classical).
    - The server asserts at startup that `kx_groups[0]` is X25519MLKEM768 (MLKEM1024 in the gov profile) (`r3pq.prefer-pq-feature-pitfall`, A).
    - Security floors: rustls ≥0.23.46, rustls-webpki ≥0.103.16, tokio ≥1.54.1 (R-SUP-3).
    - Outbound clients get a config switch to omit ML-DSA sigalgs behind TLS-inspecting middleboxes. Go #81199 resets were triggered by `signature_algorithms_cert` only, and rustls exposure is unproven (`v3.go81199-sigalgs-cert-trigger`, B).
- **R-TLS-5** [B] Default to epoll; io_uring opt-in for the trusted front only. Round 2: io_uring has 0 CISA KEV entries ever; the "uniquely dangerous" case rests on local LPE/kCTF data (`io-uring-security-record` r2 revision). No change in direction.
- **R-TLS-6** [B] Verify binary framings with generated verified parsers (EverParse/3D, Vest). Round 2: no verified HPACK/QPACK or H2 frame decoder exists in any prover; Vest/EverParse cannot express the dynamic table, so the HPACK table and budgets need hand-written Kani/Verus (`l4-no-verified-hpack-qpack-decoder` [B]). A Vest H2 frame-header parser is weeks-scale work.

### PQC
- **R-PQC-1** [A] Key exchange prefers X25519MLKEM768. The server sends HRR to the PQ group whenever the client lists it, even if the client sent only an X25519 share. Pre-standard Kyber codepoints are rejected.
  - Diff r2: "PQ key agreement solved" now carries carve-outs: it needs rustls ≥0.23.46 (RUSTSEC-2026-0349 client downgrade via cached group, CVSS 3.7, mitigated by server HRR), aws-lc-rs, and the server HRR policy. About half of human HTTPS clients still offer classical only. An acceptance test is mandatory (q2-002).
  - Nodes: `std-rfc10024-ecdhe-mlkem` (A, revised), `rec60-rustls-0.23.46-downgrade` (= `adv-rustls-pq-downgrade-2026-0349`).
  - **Diff r3 (direction narrowed):** the acceptance test was executed (q2-002 closed). The rustls 0.23.46 server picks the **first client-listed** group it supports and sends HRR only when that group's share is missing:
    - [X25519MLKEM768, X25519] with only an X25519 share → HRR 0x11EC
    - X25519 listed first → classical X25519 ServerHello
    - pq-required (`kx_groups=[X25519MLKEM768]`) → HRR for hybrid-listing clients, alert 40 for X25519-only clients
  - So "HRR whenever the client lists it" cannot be built on 0.23.x defaults. Golden per listener:
    - Agent/API/internal listeners: pq-required.
    - The public human-browser listener: client order, accepting classical from X25519-first clients until rustls ships `ServerConfig.kx_selector` with `PreferServerOrder` (main 28ee6c68, unreleased; reversal R2).
  - CI freezes the five HRR verdicts; any change blocks a rustls bump.
  - Nodes: `r3pq.hrr-acceptance-test` (A 0.93), `r3pq.rustls-kx-client-order` (A).
- **R-PQC-2** [B] (r3: C → B, resolved) FIPS profile: AWS-LC FIPS 3.1.0 via aws-lc-rs with the `fips` feature. Pin `aws-lc-fips-sys = "=0.13.11"` (with its checksum), aws-lc-rs **1.15.2-1.17.2**, approved mode on a listed operational environment, default group SecP256r1MLKEM768.
  - **Diff r3:**
    - CMVP #5298 (dynamic, issued 2026-06-03) and #5314 (static, 2026-06-05) cover AWS-LC FIPS 3.1.0. ML-KEM 512/768/1024, EdDSA, HKDF and the TLS 1.3 KDF are approved; ML-DSA and SLH-DSA are not, and X25519 is outside the boundary, so only the ML-KEM half of a hybrid group is approved. #5429 is AWS-LC FIPS 2.0.0 (no ML-KEM).
    - aws-lc-fips-sys 0.13.11 vendors 3.1.0 (6 of 6 sampled fipsmodule files byte-identical to tag AWS-LC-FIPS-3.1.0; crate built from a dirty tree). 0.13.12-0.13.17 vendor later uncertified sources.
    - Only aws-lc-rs 1.15.2-1.17.2 accept ^0.13.1: 1.17.3 needs ≥0.13.16, 1.17.4 ≥0.13.17, and 1.18.x needs 0.14.x (verifier). So `fips()==true` cannot distinguish the certified build.
    - The executed golden lock resolved aws-lc-rs 1.18.2, so **the FIPS golden is a separate lock** (frontier q3-004 checks that it still satisfies the rustls 0.23.46 floor).
    - ML-DSA is disabled in the FIPS build.
    - Nodes: `ops.fips-module-boundary-pin` (r3 revision, B 0.82), `v3.aws-lc-rs-fips-sys-range` (A), `ops.rustls-fipsstatus-gate` (A).
  - Diff r2: which version that is remains **unresolved**. Explorer 05 says aws-lc-rs `=1.15.3` / aws-lc-fips-sys `=0.13.11`. Round 1 used `=1.17.4`, which uses fips-sys 0.13.17 on v3.6.0 source. The README maps 3.0.x → aws-lc-rs <1.18.0 and tracks "the latest module that completed testing". CMVP #5429 (AWS-LC dynamic, 2026-07-20) is a further candidate. AWS-LC FIPS 4.0 is in MIP (Comment Resolution, 2026-10-22).
  - Gate: on rustls main, `ServerConfig::fips()` must return `FipsStatus::Certified{certificate}` naming the pinned cert; `aegis --fips-check` exits nonzero otherwise; on 0.23.x the bool must be true; the cert id goes to the audit log and `/healthz` (`ops.rustls-fipsstatus-gate`).
  - Nodes: `ops.fips-module-boundary-pin`, `crate-aws-lc-rs` (= `v2.awslc-rs-fips-crate-map`), `fips-cmvp-mlkem-modules`, `v.rhel-fips-hybrid-groups`.
  - Reverse: move to aws-lc-fips-sys 0.14.x / aws-lc-rs 1.18 only when an AWS-LC 4 certificate issues (Comment Resolution since 2026-10-22; `pred-awslc-fips-v4-cmvp`, `pred-awslc4-cmvp-2027q1`). Before then, any lock drift off 0.13.11 fails CI.
- **R-PQC-3** [B mechanics / C compliance] CNSA 2.0 profile.
  - Diff r2: SecP384r1MLKEM1024 is absent from rustls 0.23.46 and 0.24.0-dev.2.
  - **Diff r3 (direction changed):** the CNSA 2.0 TLS profile draft (draft-becker-cnsa2-tls-profile-05, 2026-10-22; individual draft) is **pure** ML-KEM-1024 (0x0202) plus ML-DSA-87 (0x0906) only, with no hybrids. rustls 0.23.46 already serves it: ClientHello 1,849 B, server flight 21,331 B (one extra RTT), 19 QUIC datagrams, ~270-283 µs server CPU. The hybrid-group blocker is therefore moot for this profile.
  - The new blocker: ML-DSA is not approved in AWS-LC FIPS 3.1.0, so a profile cannot be both FIPS-validated and CNSA-ML-DSA today.
  - Nodes: `r3pq.cnsa2-tls-profile` (B), `r3pq.mldsa-handshake-measured` (A).
  - Reverse if NSA guidance requires hybrids, or when an ML-DSA-approved FIPS module ships.
- **R-PQC-4** [B] Public WebPKI certificates stay ECDSA-P256 until Merkle Tree Certificates.
  - **Diff r3 (amended):**
    - ML-DSA in publicly trusted X.509 is blocked: SC-106 (cabforum/servercert PR #679) was withdrawn by its author on 2026-10-21 and moved toward a ClientAuth/NonBrowser WG; the Baseline Requirements do not permit ML-DSA.
    - Chrome's Quantum-resistant Root Program is testing MTC -07/-05 in Chrome 152 Canary: ML-DSA-44 cosigners, ≥2 cosignatures for standalone certificates, MTC-only draft policy with ACME ARI + profiles mandatory; Phase 2 Q1 2027, Phase 3 Q3 2027.
    - The certificate layer is a **CredentialSelector** over X.509, standalone MTC and landmark-relative MTC, chosen per connection from the client's `trust_anchors` signal. It adopts the rustls TrustAnchorResolver when PR #3376 (open, experimental codepoint 0xca34) lands. The ACME client must support ARI, profiles and optional alternates.
    - **Private hops use ML-DSA-44 now:** Cloudflare origin pulls (AOP/COTS, seed-only keys, origin TLS 1.3) and internal mTLS. rustls 0.23.46 serves and verifies ML-DSA-44.
    - Measured flights: ECDSA 2.1 KB; ML-DSA-44 11.7 KB (fits initcwnd 10; about +90 µs server CPU; faster client verify than ECDSA); ML-DSA-65 15.6 KB (one extra RTT); ML-DSA-87 20.9 KB.
  - Reversals:
    - R1: Chrome Stable ships MTC and rustls merges #3376/#3079 → add MTC credentials.
    - R3: a CA/B ballot permits ML-DSA → consider dual chains.
    - R4: Let's Encrypt MTC in production.
    - R6: CRQC estimates move inside 2030 → ML-DSA MTC leaf immediately.
    - Predictions: `pred-chrome-mtc-default-2027` p = 0.55; `pred-cab-mldsa-ballot-2027` p = 0.2.
  - Nodes: `r3pq.pq-auth-posture-decision` (B), `r3pq.cab-sc106-withdrawn` (A), `r3pq.chrome-cqrp-testing` (A), `r3pq.mtc-server-obligations` (A), `r3pq.cloudflare-origin-mldsa` (B), `r3pq.mldsa-handshake-measured` (A), `r3pq.apple-mtc-policy-absent` (B).
- **R-PQC-5** [B] Release signing is dual Ed25519 + SLH-DSA-SHA2-128s. Diff r3: RFC 10033 (stateful hash-based signatures: state and backup management) catalogs the state-discipline hazards of LMS/XMSS, which supports stateless SLH-DSA for a solo-operator release key unless an HSM enforces state (`r3e11.rfcs-published-in-window`, A).
- **R-PQC-6** [A/B] (new) Session tickets and 0-RTT (CRS C1, C2, C4):
  - One ticketer per (cert-chain hash, client verifier, ALPN, config epoch), with that scope in the ticket AAD through a wrapping `ProducesTickets`. rustls leaves ticketer sharing across `ServerConfig`s to the caller (`crs-rustls-ticketer-policy`, C).
  - Resumption off on mTLS listeners (cost ~4% of handshakes saved per Hebrok 2023, unverified here).
  - STEK: CSPRNG keys, rotation ≤24 h with a 2-key window, refuse an all-zero key at startup (GnuTLS CVE-2020-13777 class).
  - 0-RTT off by default; when enabled, only on replay-safe routes with a per-instance anti-replay set, `Early-Data: 1` forwarded, 425 on unsafe routes.
  - Resumed sessions keep PQ forward secrecy only under psk_dhe_ke; confirm rustls's mode (q2-004, q2-012).
  - Evidence: cross-vhost ticket resumption bypassed mTLS in nginx (CVE-2025-23419), Apache (CVE-2025-23048), LiteSpeed, Caddy, and enabled server-auth bypass across six provider clusters (Hebrok USENIX Sec'25).
  - Nodes: `crs-ce-tls-ticket-cross-vhost`, `crs-ce-stek-lifecycle`, `crs-ce-0rtt-replay`, `v2.hebrok25-server-auth-bypass`, `v2.curl-0rtt-early-data-2026-9545`.
  - Diff r3: during an in-place upgrade the STEK ring crosses processes **by pipe only, never via disk**. Encrypt with the newest key for L_enc and accept for ≤ L_enc + L_dec ≤ 24 h; a corrupt handover yields a fresh ring (UP-5, injected-clock tests). Lifetime evidence: Springall IMC 2016 found 10% of the top 1M reusing a STEK for ≥30 days. Whether nginx USR2 keeps ticket keys is unverified (`zd.l4-stek-continuity`, B).
- **R-PQC-7** [A] (new r3) **PQ-signed tokens and headers.** Default limits:
  - Header limits: nginx `large_client_header_buffers 4 8k` (one header > 8 KB fails); hyper h2 `max_header_list_size` 16 KiB; Node 16 KiB; Envoy 60 KiB; Cloudflare 128 KB total.
  - Multi-KB tokens are never HPACK/QPACK-indexed by default (4096 B table, QPACK capacity 0, h2 skips entries over 75% of the table), so they are resent on every request.
  - So a 5 KB token works everywhere and a 16 KB token fails on default nginx, hyper h2 and Node.
  - PQ-signed tokens go in the body or behind a by-reference handle. If one is sent as a header, raise the h2 limit only on token routes and enforce an explicit maximum.
  - Nodes: `r3pq.header-limit-table` (A), `r3pq.hpack-large-token-literal` (A), `r3e05.rfc9964-mldsa-jose-cose` (A; one base64 ML-DSA-65 hop ≈7 KB).

### Isolation
- **R-ISO-1** [E design; A inputs] Isolation is keyed by code provenance (P1 first-party native Rust; P2 agent-generated in hardened Wasmtime inside a sandboxed worker; P3 multi-tenant third party in per-cordon processes or microVM; P4 arbitrary native code in microVM/gVisor).
  - Diff r2: inputs measured on one machine [A]: native handler 0.38 µs (105 B JSON); core Wasm 1.06 µs; component 1.24 µs (canonical-ABI floor ~85 ns; ABI 2-7% of cost; Wasm codegen ~2× is the driver); fresh pooled component instance with WASI 20 µs p50 / 30 µs p99, 52 KB; fork from an 8 MB zygote 124 µs (+400 µs exit/wait), 64 MB 0.68 ms, 256 MB 1.5 ms; seccomp+Landlock install in the child +135 µs.
  - Advisory exposure: on the minimal M0 config (x86_64, Cranelift, core Wasm), 6 of 65 2024-26 advisories are guest-triggerable and 1 is an exploitable escape (GHSA-897f, default config, any arch); M1 (sync P2 components, non-fs WASI, wasi-http) 25 of 65; M2 (+wasi-fs) 31 of 65.
  - Consequence: Wasm alone is not a sufficient boundary for hostile code; P2/P3 always add an OS sandbox around the Wasm worker. A process sandbox per request costs 6-80× a pooled Store, so process sandboxes are per worker or tier, not per request. No flip.
  - Nodes: `isolation-decision-table-by-provenance`, `isolation-decision-inputs-table`, `canonical-abi-cost-measured`, `zygote-sandbox-recipe-measured`, `wasmtime-advisory-share-by-config`, `rec60-wasmtime-cranelift-crit-2026-10`.
  - Reverse as round 1, plus: if an M0-class escape recurs within 6 months (`pred-wasmtime-m0-escape`), P2 moves to per-tenant processes.
  - Diff r3 (direction unchanged): the advisory row is restated as an escape rate. M0 had 12 exploitable escapes in 2021-2026 (2.0/yr, 95% CI 1.0-3.5) and 1 since 2024 (0.36/yr); M1 adds 2 and M2 adds 4, all in 2026. The 6/65 share was a denominator artifact of the 2026 audit sprint (57 of 81 advisories). Wasm is never the only boundary for third-party code (`wasmtime-advisory-share-by-config`, `isolation-decision-inputs-table` r3 revisions, C).
- **R-ISO-2** [B] Wasmtime config pin:
  - Version exactly `>=36.0.19` on the 36 line or `>=43` (37-42 have no backport for GHSA-897f, CVSS 9.9).
  - `default-features=false`; features cranelift, pooling-allocator, runtime, std (+component-model if P2). No component-model-async, gc, threads, winch, or wasi-fs preopens.
  - Config: `wasm_memory64(false)` and `wasm_gc(false)` set explicitly (memory64 was default-on in 39..<45.0.1; gc defaults true); signals-based traps on (disabling them also disables Spectre mitigations); epoch interruption + ResourceLimiter; fresh Store per request dropped on trap.
  - **Never density-tune guards**: keep the default 4 GiB reservation and 32 MiB guard. Guard 0 with reservation == max_memory_size < 4 GiB re-opens GHSA-6wgr (CVE-2026-34988) and turns GHSA-394w (CVE-2026-35195) from abort into host corruption.
  - wasmtime-wasi: set TCP/UDP policy explicitly (the docs are inconsistent on defaults); linker allowlist plus a static import check.
  - A Cranelift JIT worker cannot run under `MemoryDenyWriteExecute=yes`: give it its own systemd unit, or use precompiled `.cwasm` with a local MAC.
  - Nodes: `wasmtime-minimal-config-pin`, `skeptic-small-reservation-pooling-recipe`, `vfg-wasi-default-grants`, `ops.systemd-baseline-score`, `r2e11.runwasi-cve-2026-47218`.
  - Diff r3:
    - Pin ≥36.0.19 on the 36 line (it carries both wasi-http fixes) or ≥49.0.4 / 50.0.0.
    - GHSA-3r89 (dropping a queued call panics the host; 46-<48.0.6, 49-<49.0.3) and CVE-2026-27195 (drop after an async hostcall; component-model-async, default since 39) are cancel-on-drop advisories. Keep component-model-async off and discard the Store after any dropped `call_async`.
    - RUSTSEC-2026-0350/0376 (wasi-http forwards absolute-form requests to other hosts and accepts conflicting content-lengths; patched 36.0.18-19 / 48.0.6-7 / 49.0.3-4) show the host shims mis-implementing HTTP framing. **Never use wasmtime-wasi-http for egress.** Use a narrow outgoing-fetch host function with an allowlist, host-rebuilt CL/TE and trailers dropped, differential-tested against hyper.
    - Nodes: `ac.i07-wasmtime-cancel-advisories` (A), `r3e11.wasi-http-host-side-framing-batch` (A 0.80; CVE-2026-58494 is a June advisory).
- **R-ISO-3** [A] ISO invariants (Store/arena never reused after trap; no ambient filesystem; epoch deadline + wall-clock watchdog; fuel never the DoS bound). Unchanged.
- **R-ISO-4** [A] (new) OS sandbox recipe: in a zygote or long-lived worker, set no_new_privs, open fds, apply Landlock then seccomp **once** before serving requests (saves ~135 µs per request); keep hot-path syscalls argument-free so they stay on the 5.11+ seccomp bitmap cache (+18-30 ns vs +41-450 ns for argument-checking filters). Fork in a multithreaded process is unsafe: fork from a single-threaded zygote. Nodes: `zygote-sandbox-recipe-measured`, `seccomp-per-syscall-overhead-measured`.

### Authn / authz
- **R-AUTHZ-1** [C decision; A/B inputs] PDP: Cedar `4.14.x` + cedar-policy-symcc `0.8.x`, validated and SMT-checked at deploy time; error in a `forbid` yields Deny.
  - Diff r2 (wording, no flip): the claim reads "verified Lean model (3,776 declarations, 0 sorry) + DRT-tested Rust evaluator". The TCB includes the Lean compiler (10 `native_decide` uses) and cvc5 for SymCC (cvc5 #12926/#12927 unsoundness, 2026-09). Nothing is proven about the Rust evaluator. SpiceDB is mostly fail-closed (lumping it with OpenFGA overclaimed); Biscuit's last release is 2025-07-16; Oso archived.
  - Nodes: `l5-authz-stack-recommendation` (B, up), `cedar-lean-proofs-2026-10` (A, revised), `fail-verifier-soundness-bugs`, `vfg-native-axiom-tcb`.
  - Diff r3 (no flip):
    - At main 301bdd2 (Lean v4.35.0), the 10 `native_decide` uses sit in Data/Int64.lean (×2, imported by 10 Thm/SymCC files) and Thm/SymCC/Data/Ext.lean (×8). The SymCC soundness theorems very likely depend on `Lean.ofReduceBool`; the core authz theorems likely do not (grep inference; spike: `#print axioms`).
    - cedar-drt has 84 fuzz targets (32 DRT); public CI runs `cargo test` only.
    - No Cedar delegation/attenuation RFC exists (104 PRs checked).
    - Cedar TPE (v4.14.0) has Lean-proved residual soundness but no residual→native lowering (issue #592). That is the gap R-DB-7's theorem fills.
    - Nodes: `cedar-lean-proofs-2026-10` (r3 revision, B), `r3e05.cedar-no-delegation-rfc` (A), `irl-cedar-tpe-no-native-lowering` (A).
- **R-AUTHZ-2** [B] (r3: E → B) Capability token:
  - Round 2: avoid JWT as the token format (NDSS'26 Token Time Bomb: 31 new vulns, 20 CVEs across 43 JWT implementations; `r2e11.token-time-bomb-jwt` [A]). If any JWT verifier is unavoidable (DBSC proofs, OAuth), run JWTFuzz against it and reject `alg: none`.
  - **Diff r3 (decided, three tiers):**
    - **Tier 0 (default):** an opaque handle plus a server capability table (verify 83 ns; instant revocation by row).
    - **Tier L:** an HMAC-SHA256 macaroon chain in verified deterministic CBOR, for offline holder attenuation (5 caveats 1.2 µs). Format: `[1, kid, nonce, caveats[1..64], tag]` over a closed caveat set (aud, exp, nbf, ops mask, res_prefix, cnf_jkt, tenant, tool + argcon, depth_left). K_aud = HKDF(K, 'aegis-cap-v1'‖aud‖kid). Mint requires aud and exp ≤900 s; maximum 4 KiB.
    - **Tier X:** COSE_Sign1 ML-DSA-65 (RFC 9964, COSE -49) only at trust-domain crossings (≥114 µs and ~7 KB per hop).
    - External OAuth / AAT (draft-niyikiza-01) / DT (draft-asor-wimse-02) tokens terminate at ingress and are exchanged. RFC 8693 `act` is informational only.
    - Rejected: Biscuit (3 blocks 158 µs; no PQ; a 1 ms wall-clock Datalog limit gives nondeterministic denials), UCAN (crates.io 0.4.0, 2023), ZCAP.
    - Parser: EverParse deterministic-CBOR Rust (v2026.10.07, vendored at a tag; the crate is named `cbordet*` in the tree, so record the real crate name).
  - Nodes: `r3e05.l5-token-decision` (B), `r3e05.l5-token-wire-format-lean` (C), `r3e05.token-verify-microbench` (B), `r3e05.code-level-token-verifier-table` (A), `r3e05.everparse-cborrs-2026-10` (B), `r3e05.draft-niyikiza-aat-01`, `r3e05.draft-asor-wimse-dt-02`, `r3e05.attack-matrix-token-candidates` (B).
  - Reversals:
    - R1: third parties must verify offline without a shared secret → promote Tier X.
    - R2: AAT or DT adopted by a WG with COSE + ML-DSA → use it as the Tier X format.
    - R3: Biscuit ships PQ, deterministic fuel and a scoping model → reconsider.
    - R4: Tier 0 p99 > 5 µs at depth 8 or table replication infeasible → Tier L becomes the default.
    - R5: a Cedar delegation RFC lands.
- **R-AUTHZ-3** [B] Capability widening is a machine-computed set diff; approval signs a canonical effect digest; provenance labels travel on the wire. Unchanged.
- **R-AUTHZ-4** [B] Agent endpoints by default: Origin allowlist, RFC 9728 PRM, RFC 8707 audience binding, RFC 9207 iss, CIMD. Extended by R-AGENT-4.
- **R-AUTHZ-5** [A/B] (new) **Fail-closed tri-state decisions.** Every policy evaluation returns Allow, Deny or Error; Error, timeout or crash means Deny, enforced at one host combiner and proven in Lean core (`combine ds = allow → ∀ d ∈ ds, d ≠ error`). A `Principal` cannot be default-constructed, so no error path can produce an empty principal. The differential fuzzer emits obs-text and invalid UTF-8.
  - Evidence: Envoy RBAC fail-open on obs-text, ext_authz failure_mode_allow bypass, LiteLLM KEV, Syncope empty realm filter.
  - Nodes: `vfg-policy-tristate-failclosed-invariant`, `vfg-extension-boundary-cves`, `r2e11.litellm-failopen`, `dpf-empty-means-all-pattern`.
- **R-AUTHZ-6** [A] (new r3) **Attenuation is the conjunction of every caveat in the chain**, evaluated by one verifier.
  - Never use "subsumption check + evaluate the leaf only". Tenuo 0.3.3 (non-default `cel` feature) accepts widening children because its check is syntactic (whitespace inside literals, literal parentheses) and only the leaf authorizes. Confirmed locally and unfixed on main 2026-10-24. Tenuo's SECURITY.md rates monotonicity violations High: the **operator should report privately to security@tenuo.ai; the PoC is not published here**. The AAT draft (I4) uses the same leaf-only design.
  - Verifiers take `now` as a parameter. No wall-clock run limits in authz paths; use deterministic step/fuel bounds. Biscuit's default `max_time` = 1 ms produced 5 / 40,800 Timeout denials under contention.
  - Audience comes from HKDF key separation plus a required `aud` caveat. `exp` is required at mint with a MAX_TTL. The closed schema makes absent or type-confused exp/aud a parse failure (the zcap CVE-2024-31995 and jsonwebtoken CVE-2026-25537 classes).
  - Lean statements T1-T5: monotonicity is `List.all_append`, plus aud binding, expiry min, depth_left non-increasing, verify ⟺ MAC chain ∧ denotation (HMAC opaque). T6 parse canonicality is cited from EverParse. All unchecked.
  - Fuzz targets F1-F9; 1e8 execs per target per release.
  - Nodes: `r3e05.tenuo-cel-attenuation-bypass` (A), `r3e05.biscuit-wallclock-limit-observed` (B), `r3e05.l5-token-wire-format-lean` (C), `r3e05.l5-token-verifier-fuzz-harness` (C), `inv-attenuation-monotonicity` (r3 revision).
  - Reverse: never for the conjunction rule. Reconsider the clock rule only if replay determinism stops mattering.

### State / WAL / idempotency
- **R-STATE-1** [B] Failed request ⇒ no committed mutation, by construction. Diff r3: "failed" includes cancellation (disconnect, RST, timeout, shutdown, trap). The bare statement is replaced by INV-NOMUT-C (R-STATE-6); security accounting is exempt and must be pre-debited.
- **R-STATE-2** [A spec / E design] Idempotency per draft-08 + Stripe semantics. Diff r2: the principal is a MUST in the key, not just "scoped" (`crs-ce-idempotency-key-scope`).
- **R-STATE-3** [B] Effect classes declared; exactly-once claimed nowhere. Unchanged.
- **R-STATE-4** [A pins / C store choice] Any store-of-record must pass our crash harness, now **measured on ~130k crash images** with positive and negative controls:
  - PASS (0 acked loss outside the creation window): SQLite WAL + `synchronous=FULL`/EXTRA (0/4010) and TRUNCATE+FULL; redb 4.4.0 2PC + Durability::Immediate; fjall 3.1.12 SyncAll/SyncData (0/12030); canopydb 0.2.5 `commit_with(true)` (0/12030); LMDB/heed 0.23.0 default flags.
  - FAIL: redb Durability::None (6000/6160 lost, even on SIGKILL); fjall default Buffer (6658/12030 lost); canopydb `commit()` (10600/12030; default_commit_sync=false and no background WAL sync by default); SQLite WAL+NORMAL (lost acks in 85% of images, up to the last checkpoint); LMDB NO_SYNC (corruption, reader SIGSEGV/SIGBUS) and NO_META_SYNC (loses 1 commit).
  - The dominant cause is acks before fsync and a missing parent-directory fsync, not torn writes.
  - **Bootstrap rule:** create directory and file, fsync the file, fsync the parent directory, then serve. Every passing store needed it.
  - Default candidate: SQLite WAL FULL, single writer connection, `>=3.51.3` (WAL-reset bug 3.7.0-3.51.2 needs ≥2 writer connections; current 3.54.1). Alternative: redb 2PC + Immediate; `check_integrity` is detect-only, fail closed, never auto-repair (4.3.0/4.4.0 fixed bugs in the repair path).
  - Harness must be interposer-independent: an LD_PRELOAD shim is blind to rustix raw syscalls (the first fjall run was 100% false positives). The harness still lacks crash-during-recovery and fsync-EIO stages (redb's real 2026 bugs were double faults).
  - Nodes: `cc.harness-method`, `cc.ranking-negative`, `cc.l5-config-pin`, `cc.l5-store-acceptance-gate` (C), `cc.neg-ldpreload-rustix`, `cc.result-*`, `sdg-embedded-store-selection`.
  - Reverse on double-fault/EIO results (q2-007), real-kernel arbitration (q2-022) or commit-latency measurements that price the safe configs out.
- **R-STATE-5** [B] (new) **Cross-request state scope invariant CRS (C1-C8)**, replacing round 1's bridge "no unauthenticated cross-request state" (false as stated: STEK-sealed tickets are authenticated yet unscoped; too strong: QUIC tokens and rate counters are legitimately unauthenticated).
  - Definition: cross-request state outlives its request (connection, process, fleet or client-held). "Authenticated" means verified at use under a current non-default key and epoch, bound to σ = (issuer cert-chain hash, authority, principal|PUBLIC, auth context {trust store, method, privilege}, config epoch).
  - C1 provenance (AEAD, CSPRNG key, rotation, refuse zero keys). C2 scope: use only if σ(S) = σ(R), with σ(R) computed per request (covers H2/H3 coalescing: 421 + ORIGIN frame). C3 key completeness: every response- or authz-determining input is keyed or stripped by the same parser. C4 freshness (single-use or idempotent; 0-RTT rules). C5 epoch revocation on any auth/config change. C6 failure atomicity: no insert on failed validation, no eviction on failed refresh. C7 authority ceiling: unauthenticated-influenced state only affects budgets and address validation, capped and keyed with SipHash. C8 no shared compression contexts, upstream connections or response queues across principals; close on framing error.
  - Keying table: upstream pool key = `derive(Hash, Eq)` over the whole `UpstreamConnConfig` with annotated `#[pool_key(skip, reason)]` opt-outs (hyper-util's `(Scheme, Authority)` key is insufficient; curl's 2026 cluster of ~18-20 reuse/state CVEs came from hand-enumerated keys); response cache key includes canonical path, Vary values, principal|PUBLIC and epoch, with the internal header namespace stripped at ingress; JWKS keyed (issuer, kid) with ≤1 fetch per 5 min and a negative cache; limiter keyed on the socket peer or a validated trusted-proxy hop; DNS connects to the pinned validated IP and rechecks on redirect.
  - Oracles: two-scope differential for every state type; the nginx CVE-2025-23419 replica as a permanent regression; a cache-key completeness fuzzer; oracle mutation (removing the epoch from the pool key must turn C5 red).
  - Nodes: `crs-l5-invariant-text`, `crs-l5-keying-table`, `crs-l5-test-oracles`, `crs-verdict-matrix`, `crs-ce-pool-reuse-incomplete-key` (A, up), `v2.curl-2026-auth-state-cluster`, `r2e11.h3-proxy-qpack-sidechannel`.
  - Reverse if a store/cache class is found where σ cannot be computed per request at acceptable cost.
  - Diff r3 (calibration, B):
    - C1 gains Superset CVE-2023-27524 (default SECRET_KEY, CISA KEV 2024-01-08).
    - C5 gains PostgreSQL CVE-2026-14666, worded as "cached authorization decisions are invalidated on any principal/role change".
    - C6 gains RabbitMQ CVE-2026-67409 (a JWKS fetch ignored the HTTP status and destroyed keys; an availability/fail-closed case, CWE-252, weaker than token forgery).
    - C7 gains a client-side instance, rustls RUSTSEC-2026-0349.
    - **New C5b:** at every key or encryption-level change, buffered input is empty or the connection aborts (rustls RUSTSEC-2026-0285 accepted handshake messages across levels; mbedTLS CVE-2026-73096 forged EndOfEarlyData).
    - **C8 amended:** recycled request/response objects are reset and never carry data across principals (Tomcat CVE-2024-52317 and CVE-2026-101356, published 2026-10-20 for HTTP/2 async servlets).
    - C4 rests on RFC text only (no 0-RTT replay CVE).
    - New oracles: the RabbitMQ JWKS-500 replay, refusal to start with known default secrets, and a Tomcat-style mix-up test.
    - Nodes: `crs-l5-invariant-text` (r3 revision, B).
- **R-STATE-6** [B] (new r3) **INV-NOMUT-C** replaces the bare "failed request ⇒ no mutation":
  - NC1: every termination before the commit point (CP) is a failure (disconnect, RST, timeout, abort, shutdown, trap, crash).
  - NC2: commit-point latch. After CP, commit + idempotency outcome + outbox flush run in a must-complete task, and the status derives only from the commit result. A timer firing after CP yields 202 Pending (idempotency retrieval), never 408/5xx (tower-http `Timeout` returns 408 while dropping the inner future).
  - NC3: discard-on-cancel. A connection returns to the pool only if ReadyForQuery ∧ txn status `I` ∧ no outstanding replies ∧ all server objects closed. Never reuse a connection after a CancelRequest (PG CancelRequest targets a backend, not a statement, and gets no reply). Discard the Wasm Store after a dropped call; close upstream connections that hold unread bytes. NC3 is a precondition for INV-NONEMPTY, since a leaked txn carries the previous request's SET LOCAL tenant.
  - NC4: security accounting is debited atomically before the work, never refunded, and cancellations are charged. It is exempt from NC1 (the INCR-then-EXPIRE TTL loss in gitlab#285352 shows post-hoc debits get lost).
  - NC5: a cancelled or timed-out authz/limiter stage evaluates to Error ⇒ Deny.
  - NC6: no effect capability before CP; effects go through the outbox with deterministic keys.
  - NC7: output gate. Write-dependent body bytes are sent only after CP, and no txn is held open across client I/O.
  - NC8: no started future holding a resource is left unpolled; everything drains within T_drain (futurelock: spawn the future and select on its JoinHandle).
  - Host-enforced, surviving malicious modules: NC1, NC3, NC4, NC5, NC8. SDK-mediated only: NC2, NC6, NC7.
  - Proof rung: a TLA+/P state machine with cancellation as a nondeterministic action, plus Kani/Lean lemmas for NC4/NC5.
  - Nodes: `ac.l5-inv-nomut-c` (B), `ac.observed-vs-actual-outcome` (A), `ac.principle-cancel-equals-crash` (B), `ac.i06-pg-cancelrequest-untargeted` (A), `ac.i09-omicron-3140-disconnect-mutex` (A).
  - Reverse NC3 (unconditional discard) if PG 18 reconnect p50 exceeds 20 ms or a 1-vCPU box saturates below 200 cancels/s (spike q3-008); then use state-tracked reuse.
- **R-STATE-7** [B] (new r3) **Cancel-correct coding rules and the cancel-sweep gate.**
  - CR1-CR9 enforced in `clippy.toml`:
    - `disallowed-types` tokio Mutex/RwLock in core
    - `await-holding-invalid-types` (tokio guards, RawConn, StoreGuard)
    - deny `await_holding_lock` / `let_underscore_future` / `unused_must_use`
    - `select!`/`try_join!` only where listed in `cancel-audit.toml`, each with a CANCEL-SAFETY comment
    - no `write_all`/`read_exact`/`tokio::time::timeout` in core; use a CP-aware deadline instead
    - commit only via `spawn_must_complete`
    - arm a drop guard right after any wire send that creates server state
    - the golden owns the pool checkin predicate
    - a "# Cancel safety" rustdoc section
  - **Driver pins (2026-10-25):**
    - sqlx: a git rev ≥ f1e94ec (0.9.0 on crates.io has #4393), or avoid it.
    - diesel_async: ≥ PR #305 (v0.9.2 lacks it).
    - tokio-postgres 0.7.18: patched with sfackler/rust-postgres PR #1374 (open); also watch #1394 (prepare drops a trailing 57014 ErrorResponse).
    - wasmtime ≥49.0.4 (R-ISO-2); oneshot ≥0.1.12.
  - **Cancel sweep:** a `CancelAt<N>` wrapper drops the top-level future at its Nth Pending. Every sim I/O shim returns Pending once, so every I/O await is a cancellation point. Coverage gate: every site gets cancelled.
    - 8 modes: drop, abort, h2 RST, h1 FIN, tower timeout, shutdown deadline, Wasm epoch trap, kill -9 (must equal drop).
    - 8 oracles: DB snapshot vs CP; next principal on pool size 1 gets its own results with zero idle-in-txn; one debit; cancelled authz denies; no effect without CP; liveness within T_drain; Store discarded; no permanent 409 on retry.
    - PR gate: all handlers × all sites × {drop, RST, timeout} + 200 seeds. Nightly: 8 modes × 20k seeds against real PG 18.
    - Regression corpus: sqlx#4393, diesel_async#304, rust-postgres#1374, the redis-py#2624 shape on redis-rs, the Go 47907 shape, Wasmtime 27195/0354, omicron #3140/#9259.
    - Oracle self-test: a checkin predicate mutated to "always reusable" must fail within 100 seeds.
  - Nodes: `ac.l5-cancel-sweep-harness` (B), `ac.l5-coding-rule-lint-gate` (B), `ac.rust-cancel-tooling-landscape` (A: clippy has no cancel-safety lint; AsyncDrop is still nightly).

### Data plane (§0b; backend-agnostic)
- **R-DB-2** [B decision / C design] (was open) **Typed operation-capability IR with per-adapter lowering** ("generate, don't parse"):
  - `Op{tenant: TenantId from the verified session only; cap: CapId registered at build time; budget{rows ≤10k, bytes ≤8 MiB, ms ≤5000}; kind}`. `OpKind` = Get | Query{pred, proj, order, limit} | Put | Delete | Append | Subscribe | BlobGet | BlobPut{max_len, mime} | Presign{ttl ≤900} | Call{svc, method} | VectorSearch{k ≤100, pred} | Named{stmt_id, params}. `Pred` = And | Or | Not | Cmp{FieldId enum, op, typed Scalar}.
  - The adapter is the DB client: it builds wire requests from the IR. Native DB protocols are never exposed downstream (Envoy marks every DB wire-protocol filter `requires_trusted_downstream_and_upstream`).
  - Tenant binding per family: RLS families use a session variable; PEP-only families get a mandatory conjunct; namespace families get an adapter-built `t/<tenant>/` prefix and raw keys are rejected; DynamoDB uses PK + STS session tags.
  - WIT (`aegis:data@0.1.0`) is only the encoding for out-of-process/sandboxed adapters, with `tenant-handle` a host-owned resource a guest cannot forge.
  - Alternatives rejected: WIT-first (no standardized relational/document WIT; wasi-keyvalue Phase 2 unchanged since 2024-03), per-family traits (tenant binding reimplemented 17 times; the failure mode of the 2026 MCP DB-tool CVEs). Existence proof of a cross-backend IR with capability flags: Hasura NDC v0.2.14. Policy-to-filter compilers exist (Oso list filtering, Enterprise OPA compile API, Cedar 4.14 experimental tpe).
  - Nodes: `dpf-uniform-abstraction-comparison`, `dpf-l5-op-capability-ir` (C), `dpf-envoy-db-filters-untrusted` (A), `dpf-agent-db-tool-bypass-cluster` (A), `dpf-family-matrix` (B).
  - Reverse if the `Named` escape hatch exceeds ~20% of golden ops (the IR's expressiveness ceiling for graph/stream workloads is unmeasured), or a standardized data WIT appears.
  - Diff r3:
    - IR semantics are fixed: And([]) = TRUE, Or([]) = FALSE (both tested nested inside conjunctions), Kleene 3VL for NULL, a mandatory tenant conjunct.
    - Query builders that drop empty sub-expressions are banned from the lowering path: SQLAlchemy 2.1.6 `or_()` drops the FALSE conjunct with only a DeprecationWarning; go-sqlbuilder `Cond.Or()` returns ''; ucast-prisma maps an empty `or` to {}. Hasura ndc-test tests empty OR.
    - Policy-to-SQL compilers are currently unsound for some dialects: OPA v1.21.4 compiles `startswith` to LIKE without ESCAPE (SQL Server `[` stays a live wildcard), has no collation awareness, and still interpolates literals inline. So the golden lowers its own IR rather than adopting a compiler.
    - Assurance plan: R-DB-7.
    - Nodes: `irl-empty-or-widening-family` (A), `irl-opa-compile-sql-lowering-defects` (A).
- **R-DB-3** [A/B] (new) **INV-NONEMPTY**: the tenant binding is checked structurally after lowering; an empty capability set denies; "Unrestricted" must be explicit, justified and CI-gated (CODEOWNERS). Nodes: `dpf-empty-means-all-pattern` (A), `dpf-l5-allowlist-generation`.
- **R-DB-4** [C] (new) **Build-time allowlist lock per adapter.** An xtask lowers each CapId template through its adapter and normalizes it per family (pg_query fingerprint, sqlparser AST hash, canonical CQL, Mongo canonical extended JSON, RESP command + key template, Cypher AST, canonical JSON for search/vector, topic/subject templates, method + canonical path for HTTP/S3) into a committed `allowlist.<adapter>.lock`.
  - The build fails on INV-NONEMPTY failure, any family denylist item (Redis EVAL/FUNCTION/MODULE/KEYS/FLUSH*/SWAPDB/CONFIG; Mongo `$where`/`$function`/`$accumulator`/JS in `$expr`/zlib; Cypher CALL/APOC; CQL UDF/system keyspaces; Kafka admin/ACL/config APIs and client `sasl.*`/`config.providers`; NATS `>`/`$JS.API`/`$SYS`; SQL Server CDC functions; DynamoDB Scan; S3 TTL >900 s/admin; Qdrant snapshots), or an unbounded budget. Each denylist entry traces to a dated CVE or vendor-documented bypass.
  - At runtime the adapter refuses any op not in the lock; an empty lock denies everything.
  - Tests: 100k-case proptest per adapter for INV-NONEMPTY; differential fuzz of each normalizer against the backend's own parser. Regex/text-level read-only validators are rejected (the 2026 MCP DB-tool bypasses, e.g. mcp-neo4j-cypher CVE-2026-35402, were fixed by EXPLAIN-based analysis).
  - Nodes: `dpf-l5-allowlist-generation` (C), `dpf-redis-valkey`, `dpf-mongodb`, `dpf-graph-neo4j`, `dpf-kafka`, `dpf-nats`.
- **R-DB-5** [B] (new) **Native enforcement with per-tenant credentials minted by the core, wherever the family has it** (RLS role/session, STS session policy with `dynamodb:LeadingKeys`, a Redis ACL user per tenant, a Kafka PREFIXED principal, a NATS account, an FDB tenant JWT). Only these invariants survive a malicious third-party adapter; for PEP-only families (MySQL/MariaDB, TiDB, libSQL, MongoDB, Cassandra/Scylla, Neo4j Community, Qdrant, Meilisearch documents API, Tantivy, InfluxDB/QuestDB, upstream HTTP), the adapter is inside the trust boundary and the extension contract says so.
  - Every native mechanism documents bypasses (CRDB RLS skipped by FK cascades, TRUNCATE, CDC, backup/restore, LDR/PCR and ON CONFLICT DO NOTHING; SQL Server RLS error side channel; DynamoDB Scan; Redis FLUSHALL/SWAPDB; SurrealDB's in-engine permissions produced 79 GHSAs in 2023-26), so native enforcement is necessary, not sufficient: the IR check stays.
  - **Never share a backend connection across tenants** (Valkey CVE-2025-67733 response-stream injection; SQL Server SESSION_CONTEXT with pooling) = CRS C8.
  - Do not assume a patched backend: disable wire compression from the adapter side and gate on server version at connect (MongoBleed CVE-2025-14847 exploited in the wild; 3.6/4.0/4.2 unpatched).
  - Nodes: `dpf-family-matrix`, `dpf-redis-valkey`, `dpf-dynamodb` (B, down: Scan/global-table claims unconfirmed), `v2.crdb-rls-on-conflict-gap`, `v2.mongobleed-itw`, `dpf-surrealdb-inline-perms-negative`.
- **R-DB-6** [B] (new) **Adapter isolation by provenance and driver type.** In process (a Cargo feature) only for first-party adapters on pure-Rust drivers with ≲15 unsafe sites and no C client: tokio-postgres 1, mysql_async 4, redis 6, scylla 3, async-nats 9, mongodb 14, tiberius 6, rskafka 0, object_store 2, rust-s3 0, qdrant-client 0 (regex counts; verifier did not recheck). Out of process (seccomp+Landlock worker, WIT-encoded IPC) for C-binding drivers (libsql 831 sites + ~1.43M C/C++ LOC; foundationdb + libfdb_c; rdkafka + librdkafka; questdb-rs 1508 sites + C) and for every third-party adapter. Cost: an in-process adapter adds its driver's full LOC to the core TCB; out of process adds an IPC codec and unmeasured latency.
  - Nodes: `dpf-l5-adapter-isolation`, `w02.feature-cost-unused`, `zygote-sandbox-recipe-measured`.
  - Reverse on the IPC spike (q2-001).
  - Diff r3: the IPC spike ran on a laptop (q2-001 closed): 4.8 µs per UDS hop, ~5 µs added to a redis-GET-shaped op (about one loopback RTT; ~2.5% of a remote-store RTT). An idle exec helper costs 2.5 MB RSS / 0.56 MB private and 544 µs to first reply; fork from a zygote 250-615 µs (minimal helper, a floor). Out-of-process adapters within the hop budget (R-MOD-1) make cancel = crash cheap: kill the helper and every piece of driver state resets. Nodes: `w02.helper-process-rss-spawn` (A 0.75), `w02.L5-adapter-oop-threshold-table` (C).
- **R-DB-7** [A executed (SQLite/PG/Redis) / B doc-derived (MySQL/SQL Server/Mongo) / E theorem] (new r3) **Adapter refinement contract.** A golden DB adapter is accepted only if it ships three things:
  - (1) the Lean `Backend.Refines` claim it relies on (whenever the backend's eq/range/prefix returns true, the reference returns true);
  - (2) a `check_schema()` run against the live catalog at startup;
  - (3) an executed differential-oracle report with leak_cases = 0 over ≥100k cases at the pinned engine version, re-run on every engine bump (including PG 17→18), with the 78-case counterexample corpus as unit tests.
  - **Lean model:** `AegisIR/Lowering.lean`, 232 LOC, core Lean only, toolchain v4.35.0. T1 `lower_sound_pos` (soundness given Refines), T2 tenant conjunct, T3 `refines_necessary`, T5 empty And/Or by rfl. T4 `lower_sound_full` (with NOT, under Backend.Exact) is `sorry`. **Unchecked**: no Lean toolchain was installed within the research budget (spike SPK-LEAN-IR-1, projected <5 s / <0.7 GB).
  - **Schema gate:** SQLite PRAGMA table_xinfo (STRICT, declared type = IR type, no NOCASE/RTRIM); PG attcollation C/POSIX or deterministic with COLLATE "C" emitted, no citext; MySQL PAD_ATTRIBUTE = 'NO PAD' with a binary collation; SQL Server *_BIN2; Mongo collation absent or simple, tenant constrained to a string by $jsonSchema. Refuse to start on a version mismatch.
  - **Unsound-lowering denylist** (each item traced to an executed counterexample or a primary doc):
    - SQLite: no LIKE/GLOB for Prefix (ASCII case folding, `_`/`%` wildcards, NUL terminator: `'acme\0evil' LIKE 'acme'` = 1); no NOCASE; a literal's class must equal the column affinity; use a typeof guard + COLLATE BINARY + substr; strip affinity with unary + (the hardened form leaked via `'' >= 10` on a NUMERIC column).
    - PG: no nondeterministic ICU collations or citext (distinct tenant ids collide; NFC == NFD); no LIKE for Prefix (an error on 17 became a leak on 19rc1 because PG 18 added LIKE for nondeterministic collations); COLLATE "C" on every text comparison and Range (glibc en_US: `'A' BETWEEN 'a' AND 'b'`); `= ANY($1)` for IN.
    - MySQL: no *_ci and no PAD SPACE (utf8mb4_bin is PAD SPACE); use utf8mb4_0900_bin and an explicit ESCAPE. LIKE treats trailing spaces as significant, so the PAD hazard is =/IN/range only.
    - SQL Server: no LIKE without ESCAPE (`[` is a live wildcard); BIN2 collations; fixed-format tenant ids (trailing blanks are ignored).
    - Redis/Valkey: never raw tenant text in MATCH/KEYS/ACL patterns; use `t:{hex(tenant)}:suffix`, which also pins SCAN to one slot. The naive encoding leaked for 10/19 tenants and escaped globs for 3/19, because tenant `acme` matches `acme:x` keys.
    - Mongo: explicit `$eq`, plus `{tenant: {$not: {$type: 'array'}}}`; pin the exact numeric `$type`; collation `simple`; never a NULL literal; never `$where`/`$expr` from request data (`{tenant: 'acme'}` matches `['acme', 'evil']`).
  - Result-set soundness is assured; timing/scoring channels from Range/Prefix are on the NOT-proven list (arXiv 2608.11730, 2026-08-12) until spike q3-015. Write-path soundness (UPDATE/DELETE/upsert) is open (q3-006).
  - Engine logic bugs (NoREC: 159 bugs in mature DBMSs) put the engine in the lowering TCB: pin the engine and run SQLancer nightly.
  - Nodes: `irl-l5-lean-lowering-theorems` (E), `irl-l5-differential-oracle-harness` (A 0.85), `irl-l5-unsound-lowering-denylist` (A 0.80), `irl-l5-backend-refinement-contract` (E), `irl-sqlite-affinity-collation-cex` (A), `irl-pg-collation-cex` (A), `irl-redis-glob-key-prefix-cex` (A), `irl-mongo-filter-semantics-cex` (B), `irl-ndc-equal-syntactic-equality` (A; precedent: NDC `equal` must be syntactic), `irl-engine-logic-bugs-tcb` (B), `irl-post-filter-side-channel-2026` (B), `irl-sql-mechanized-semantics-landscape` (B: no mechanized SQL semantics models collation or affinity).
  - Reverse to proven per-adapter refinement if a mechanized semantics of collation/affinity appears for the pinned engine; reverse the denylist item by item on a new executed counterexample.
- **R-DB-1** [A/B] Postgres adapter (one family instance of R-DB-2..6): Parse fingerprints in the lock; Bind parameters only; BEGIN..COMMIT with SET LOCAL ROLE; session state banned; RLS defence-in-depth; PG `>=18.6/17.11`; pooler on a private socket (PgBouncer `>=1.26.1`).
  - Diff r2: recycle pooled backend connections on any role DDL (CVE-2026-14666 triggers on role DDL during a live session). PgDog's session-leak fix (PR #1444) is unmerged; Supavisor's SET handling (PR #1113, merged 2026-10-23) is only in v2.10.0-rc.0. PgBouncer 1.26.0 tracks search_path by default on PG18 and 1.26.1 says search_path bugs remain.
  - Nodes: `sdg-l5-db-gate-invariants`, `sdg-rls-plan-cache-family`, `sdg-txn-pooling-session-leak`, `sdg-pgbouncer`. Reverse on the q1-012 reproducer.
  - Diff r3: the q1-012 reproducer ran (PG 17.11 and 19rc1; plan_cache_mode auto, force_generic and force_custom):
    - Alternating SET LOCAL ROLE per txn with a reused named prepared statement was always correct.
    - Revoking membership or BYPASSRLS while a plan was cached was honoured on patched minors. `set_config(..., true)` was correct; the session-level `set_config` positive control leaked in every mode.
    - Golden: SET LOCAL ROLE + statement caching allowed; tenant GUCs only with `is_local=true` (session-level forbidden). The PG minor floor 17.11/18.6 is checked at startup **and pooled connections are recycled after the upgrade and after any role DDL**, because the advisory says stale policies persist until the session ends.
    - The CVE-2026-14666 fix (1974acf23, +63/-2) has no regression test, so q1012 S2/S3 becomes our regression test.
    - Nodes: `irl-l5-q1012-role-plan-cache-gate` (A 0.85), `irl-cve-2026-14666-fix-anatomy` (A), `v3.cve-2026-14666-session-persistence` (A).

### Agent-protocol projection
- **R-AGENT-1** [A] MCP 2026-07-28 is the primary target, with the 2025-11-25 path mandatory until at least 2027-07 (≥12-month deprecation, SEP-2596; the TS SDK's LATEST is still 2025-11-25).
  - Diff r2: **statelessness is not a security property by itself.** It removes the session-confusion class but not Origin, parser, audience or SSRF classes, and it adds client-held `requestState` (attacker-controlled; the spec says MUST integrity-protect). Seal all state handles by default (default-on in the Python SDK via PR #3032; opt-in in rmcp's `request-state` feature, so we enable it or own it). rmcp 3.7.0 licence is Apache-2.0 per crates.io; it keeps the initialize path; 7 GHSAs plus 4 found by the verifier, 5 in 2026-06..10: pin and re-audit on every bump.
  - Nodes: `j-mcp-2026-07-28`, `fin.stateless-not-sufficient`, `j-rmcp-sdk` (= `fin.rmcp-3.7.0`), `v2.rmcp-more-advisories`.
- **R-AGENT-2** [C] One handler IR (JSON Schema 2020-12) projects to OpenAPI 3.2, MCP tools, WebMCP and Server Card. Unchanged (OAS 3.2.1 2026-09-10, Arazzo 1.1.0 2026-05-18 re-verified).
- **R-AGENT-3** [A/B] Web Bot Auth / RFC 9421 verifier; identified agents form a separate budgeted class (R-ABUSE-1). Signature verification runs only after cheap pre-auth limits, because its cost is attacker-triggerable (`abuse-wba-interplay`, C).
- **R-AGENT-4** [B] (new) **Listener gate as a type**, so every route and every future protocol revision inherits it:
  - Host/:authority allowlist; Origin allowlist with absent Origin allowed only under a bearer or mTLS credential, never with ambient auth (the 2026-07-28 spec leaves absent Origin unspecified); Content-Type `application/json` on POST (no text/plain no-preflight); no ACAO wildcard; mandatory token `aud`.
  - All state handles sealed with (principal, route, backend, policy version, ttl).
  - One strict JSON parse shared by policy and handler: reject duplicate keys, case-variant keys, BOM, NUL and out-of-range numbers (ToolHive's 2026 bypasses: GHSA-hxx3, 9v4w, vpfq, g7gq).
  - Egress on the resolved, validated address with cross-origin redirect header stripping (invariant 1 in the advisory ranking: 18 of 58 advisories).
  - Canonical case-folded tool namespace per backend (Docker mcp-gateway tool shadowing and case-variant reserved names).
  - Typed explicit opt-out instead of default-off security (the Go SDK reverted its secure default after browser-client breakage; opt-in protection was filed as the same bug in six SDKs within five months).
  - Nodes: `l5.origin-audience-session-rules`, `l5.invariant-list`, `fin.same-bug-n-sdks` (A, up), `fin.spec-absent-origin` (B, down), `fin.toolhive-policy-bypass`, `fin.sdk-default-tension`, `v2.docker-mcp-gateway-advisories-r2`.
- **R-AGENT-5** [B] (new) **Advisory-derived conformance corpus.** 33 case ids, each traced to source advisories with an expected behaviour (e.g. `host-allowlist-required` → 403 with no handler call; `reject-text-plain-post` → 415/403; `session-principal-binding` → 404; `token-wrong-audience-401`; `redirect-strip-headers`; `json-dup-nul-reject`; `ssrf-resolved-address`; `body-cap-413`; `openapi-traversal` → upstream receives 0 requests). Every advisory row maps to a case; fix-twice classes get ≥5 variants; rejected requests invoke zero handlers (counter assertion). Check overlap with the official conformance repo's http-standard-headers/session-lifecycle/stateless scenarios before claiming novelty. Nodes: `l5.conformance-manifest`, `l5.ci-gate` (C), `adv.corpus-r2-09`, `fin.conformance-gap` (B, down).
- **R-AGENT-6** [B] (new) **Control-plane attachment invariant**: a policy or route from tenant A never binds to tenant B's backends without an explicit grant (agentgateway GHSA-g7j8, GHSA-jwm2 cross-namespace ReferenceGrant advisories). Node: `v2.agentgateway-referencegrant`.

### Admission and abuse control (W-ABUSE, new in round 2)
- **R-ABUSE-1** [D numbers (r3: E → D) / B mechanisms] Admission pipeline for 1 vCPU, in order (round-2 text kept below; r3 replacements follow it):
  - S0 listener: 2,048 connections, 32 per IP prefix, 10 s header deadline, TLS handshake semaphore 8.
  - S1 pre-auth GCRA (governor 0.10.4): key /32 or /64 in a 65,536-key LRU, overflow to a global bucket; 5 req/s burst 20; /24-/48 aggregate 50/s burst 200.
  - S2 classify: Web Bot Auth verified (after S1), session, Privacy Pass, anonymous.
  - S3 cost classes 1/5/20/100 units; per-identity units/min: anonymous 60 (burst 120), session 600, verified agent 1,200.
  - S4 load-keyed challenge ladder (meta-refresh → PoW d4 → d6), only when queue sojourn > target for 100 ms, only for anonymous traffic, always with an accessible alternative.
  - S5 adaptive concurrency (Gradient2/Vegas, start 16, min 4, max 64) with work-conserving partitions (verified .30 / session .50 / anonymous .20), per-class queue 32, CoDel at 2× handler p50, LIFO only in the anonymous queue. Envoy warns minRTT probing raises 503s and can be manipulated adversarially: pin min_concurrency probes and retry internally.
  - S6 fuel/250 ms deadline, DB timeout 2 s, post-hoc cost debit.
  - Rejects: 429 + Retry-After (TAT-derived) per identity; 503 with jittered 1-5 s globally; **never HTTP 200 for a reject or challenge** (Anubis returns 200).
  - All numbers are grade E proposals pending the swarm simulation. Nodes: `abuse-L5-admission-pipeline-1vcpu`, `abuse-rate-limit-algos-crates` (A), `abuse-adaptive-concurrency` (B), `abuse-codel-lifo` (B), `abuse-cost-weighted-budgets` (A; GitHub's multi-dimensional budgets as existence proof).
  - **Diff r3 (numbers replaced from a deterministic simulator, grade D; mechanisms kept):**
    - The round-2 defaults **collapse** under a 10k-IP solver swarm: human failure 99.1%, human p99 3,793 ms, verified success 59.7%. Across 178 sweep points no single-parameter change rescued them.
    - Causes:
      - PoW-minted cookies share the human session class (I3 violated).
      - No concurrency cap on the expensive tier.
      - Per-identity budgets never bind across 10k identities (10k IPs × 0.1 req/s × 100 units = 10 units/s per identity).
    - Tuned table:
      - **New S0.5 handshake reservation:** full TLS handshakes use ≤50% of each 5 ms accept window (1.0 → 7.9% human failure; ≤0.6 → 0.9%).
      - S1 10 req/s burst 50 (≤2 throttles verified agents to 20-40% and NAT users to 46-74%), O(1) eviction.
      - **Fresh-session class** (cookie < 60 s; shares verified 0.30 / established 0.40 / fresh 0.10 / anon 0.20).
      - **Aggregate expensive-tier budgets**, independent of identity count: A_f = 300 units/s (fresh + anon) and A_e = 400 (established), charged at S5 admission.
      - Step-up 16-bit PoW for anonymous cost ≥100 at any load.
      - **Drop the CPU-keyed challenge trigger** (it raised human failure 12% → 23%); PoW rungs {16, 18} bits, never 24 (112 s in a browser); accessible lane required (no-JS failure 33% → 10%).
      - Gradient2 bounds min 4 / initial 8 / max 32, not the Netflix library defaults (20 / 20 / 200); qmax 32.
      - CoDel 20 ms on the cheap queue, 250 ms on the expensive one.
    - The adaptive limiter and the load-keyed ladder had no measurable effect once aggregate caps existed. Keep them as backstops.
    - Machine-readable: `state/raw/round-003/07-work/tuned.json`.
    - Nodes: `r3e07-L5-tuned-default-table` (D), `r3e07-r2-defaults-collapse` (D), `r3e07-tls-handshake-floor` (D), `r3e07-netflix-defaults-vs-1vcpu` (A), `r3e07-limiter-dormant` (D), `r3e07-verified-agent-s1-collision` (D).
    - Reverse on the calibrated rerun: a measured 1-vCPU handshake cost (q3-001), pre-TLS resumed-handshake classification (q3-003; the S0.5 fix assumes PSK identity is visible before crypto, unverified in any stack), and sim v2 (q3-005).
- **R-ABUSE-2** [B] PoW is a load-keyed speed bump, not a defence. Headless Chrome scrapers computed Anubis PoW (#978, maintainer "not a bug"); d4 is 2^16 SHA-256 ≈ 17-28 ms native; cost per session is <1 cent/month until millions of sites (Ormandy); a double-spend bug also existed. What held in 2025-26 incidents: making expensive endpoints cheap or cached (Forgejo swap: CPU 100% → 10%), a global load-keyed shed, and identity-bound budgets. Nodes: `abuse-anubis-bypass-evidence` (B, up), `abuse-pow-economics-calc` (D), `abuse-pillar-admission-economics` (C), `abuse-incident-ledger-2025-26` (C).
  - Diff r3: measured asymmetry replaces the round-2 calculation. Native SHA-256 runs 62-89 MH/s single-thread (1.1-3.4 GH/s multi-thread) vs ~150 kH/s in a browser: 430-860× single-thread and far more for a farm. A 16-bit solve takes 0.44 s on desktop (≈2.2 s on a phone, assumed); 24-bit takes 112 s. Cap human-facing PoW at about 18 bits and never rely on it for attacker cost. Anubis v1.28 ships opt-in WASM Argon2id/HashX modes with no perf numbers (q3-011). Nodes: `r3e07-pow-asymmetry-measured` (C, up), `r3e07-pow-ladder-negative` (D), `abuse-pow-economics-calc` (r3 revision: superseded).
- **R-ABUSE-3** [D derivation / B incident shape] Per-IP limiters cannot see low-rate distributed swarms (N IPs × ~1 request each; SourceHut, KDE, GNOME). Aggregate controls (global concurrency, queue delay, cost classes, cheap reject paths) are required; ASN/subnet-keyed limits are an unmeasured middle ground (open seed). Node: `abuse-per-ip-limits-fail-swarm`, `abuse-residential-proxy-scale` (C).
  - Diff r3 (executed in the simulator): per-IP-only limiting gives 74% human failure at 0.01 req/s/IP and 98% at 0.1 req/s/IP (p99 63 s); the swarm takes the whole CPU. A 2026 campaign shape (DataDome, secondary: 1.2M IPs, 16,402 ASNs, ~1 request per 9 s per IP, ~136k rps average) matches it. Nodes: `r3e07-per-ip-collapse` (D), `r3e07-swarm-shape-datadome-2026` (C).
- **R-ABUSE-4** [E] Budget invariants I1-I7: I1 admitted cost in any window ≤ b + r·W; I2 one identity never alters another's TAT; I3 a class within its share is admitted regardless of others; I4 limiter memory ≤ M and an evicted key restarts at the anonymous burst, never minting a verified budget; I5 post-hoc debit with TAT ≤ now + 10 min; I6 human liveness via PoW or an accessible lane (5% reserved); I7 no fail-open (stage error ⇒ reject). I1/I2/I5/I7 are property-testable; I3/I4/I6 need a TLA+ model of the feedback loop. Acceptance via the swarm DST spec (50,000-IP residential swarm, PoW-solving headless swarm, native-solver swarm, greedy identified agent, key-churn attacker): human success ≥99% (CG-NAT ≥95%, accessible path 100% within 60 s), verified agents ≥99% unaffected, CPU ≤85% and sojourn p99 ≤100 ms at ≥20× offered load, reject path ≤20 µs p99, zero unmetered admits under fault injection. Nodes: `abuse-L5-budget-invariants`, `abuse-L5-swarm-sim-spec`.
  - Privacy Pass: redeem tokens from a trusted issuer only; no RFC rate-limited token exists (rate-limit-tokens-06 expired); ARC is undeployed and private-verify only. Nodes: `abuse-privacy-pass-rfcs` (A), `abuse-arc-act` (B).
  - Diff r3:
    - New invariants:
      - **I8** expensive-tier aggregate: admitted cost from {fresh, anon} ≤ A_f·W + burst and from {established} ≤ A_e·W + burst, regardless of identity count. GCRA algebra, tractable for Kani/Verus.
      - **I9** class non-contamination: completing a challenge never places an identity in the established class until a behaviour- and cost-based promotion rule holds (age-only promotion is bypassed by a slow farming swarm).
      - **I10** handshake reservation: full TLS handshakes consume ≤50% of any accept window.
      - **I11** per-identity budgets are non-binding when N ≥ B/b and must not be cited as a swarm defence.
      - I9/I10 need a TLA+ controller/accept model.
    - **Acceptance criteria C1-C12** (10 seeds × 10 scenarios):

      | criterion | r2 defaults | tuned |
      |---|---|---|
      | C1 human failure ≤2% | 99.1% | 0.9% mean / 1.3% worst |
      | C2 human p99 ≤140 ms | — | 82-92 ms |
      | C3 verified agents ≥99% | 59.7% | 100% |
      | C4 attacker expensive units/s ≤667 | — | 366 (aged-cookie 510) |
      | C5 NAT / no-JS humans ≤5% | — | pass, except a **50-user NAT flash crowd at 21%/26%: FAIL** (known gap) |
      | C6 cheap flood ≤2% | 75.5% | 0% |
      | C7 aged-cookie swarm | — | 2.5% / 510 units |
      | C8 single heavy hitter | — | 0% |
      | C9 baseline humans ≤1% | — | 0% |
      | C10 accept-window overhead | — | 0.27-0.45 |
      | C11 no fail-open / key-churn memory bound | untested | untested |
      | C12 | PoW-minted sessions are 100% of fresh-class admits under the solver swarm, so budgets carry the PoW layer | |

    - CI: fixed seeds 1..10 plus nightly random seeds; fail on any worst-seed breach.
    - Nodes: `r3e07-L5-budget-invariants-additions` (E), `r3e07-L5-swarm-acceptance-criteria` (D), `r3e07-sim-harness` (D), `r3e07-aged-cookie-farming` (D).
- **R-ABUSE-5** [D economics / B classifier lesson] (new r3) **Make expensive endpoints cheap or cached before tuning limiters.**
  - Attacker cost to saturate one vCPU's unprotected cost-100 endpoint: $1.7-5.2/hour. Saturating the TLS floor costs $60-200/hour (residential proxy $2-6/GB, ~7.4 KB per rejected attempt; Turnstile solves $1.45/1k; LLM-driven steps cost far more than scripted ones).
  - A rejected request after a full TLS handshake costs the defender ~1.7e-9 USD. Capacity, not money, is the binding constraint, and limiter micro-optimisation is worthless next to TLS (<0.1 µs vs 424-848 µs).
  - Behaviour-derived scores may only weight budgets. A hard deny requires a cryptographic identity signal: server-side behavioural classifiers keep a 4-6% false-positive rate even on tight signals (XGuardian, USENIX Sec'26: 88.9% accuracy).
  - Prices are dated 2026-10-25 and go stale by 2027-Q1 (`r3e07-L5-cost-model-sheet`).
  - Nodes: `r3e07-price-sheet-2026-10` (B), `r3e07-cost-per-1m-by-attack-class` (D), `r3e07-defender-stage-cost-table` (D), `r3e07-L5-cost-model-sheet` (D), `r3e11.xguardian-server-side-anticheat` (B).

### Observability / ops / compliance
- **R-OPS-1** [A] EU CRA reporting live since 2026-09-11 (runbook, PSIRT, VEX/CSAF, tamper-evident awareness timestamp). Diff r3: confirmed from the Official Journal text via the Publications Office cellar: Art 71(2) application 2027-12-11, Art 14 from 2026-09-11, Chapter IV from 2026-06-11; Art 64(2) EUR 15M / 2.5%, Art 64(3) EUR 10M / 2%; no postponing amendment found (`ops.cra-obligation-split` r3 revision, A).
- **R-OPS-2** [A] (new) systemd hardening baseline: `systemd-analyze security --offline --threshold=2` as a CI gate (measured: minimal unit 9.4 UNSAFE, upstream Caddy unit 8.8 EXPOSED, aegis-hardened.service 1.4), paired with a runtime test (writes to /etc and /usr blocked, CapEff only CAP_NET_BIND_SERVICE, RWX mmap denied). Key directives: DynamicUser, ProtectSystem=strict, NoNewPrivileges, CapabilityBoundingSet=CAP_NET_BIND_SERVICE, RestrictAddressFamilies, SystemCallFilter=@system-service ~@privileged @resources, MemoryDenyWriteExecute, ProtectProc=invisible, WatchdogSec=30. Node: `ops.systemd-baseline-score`.
- **R-OPS-3** [B] (new) CRA posture: as an open-source project we publish the steward-grade file set (SECURITY.md, CVD policy, CycloneDX/SPDX SBOM per release, signed provenance), because downstream manufacturers must demand it (Art 13(5)). Any monetized offering around the golden (support, hosting) makes the distributor a manufacturer (Art 14 reporting since 2026-09-11; remaining obligations 2027-12-11; 15M EUR / 2.5% fines). Class placement follows primary function (Art 7; Implementing Regulation (EU) 2025/2392): frame admission control as rate limiting and publish technical documentation to keep the Art 32(5) route. Nodes: `ops.cra-obligation-split`, `v2.cra-monetization-trigger`, `v2.cra-implementing-reg-2025-2392`, `ops.cra-annex3-waf-risk` (C).
- **R-OPS-4** [B] (new) COMPLIANCE_MAP: the binary supplies mechanisms and machine-readable evidence for NIST 800-53 r5 (5.2.0) controls mapped to FedRAMP 20x KSIs (10 groups / 46 KSIs in rules v2026.10.13.01; r3): SC-13 (FIPS pin + FipsStatus gate), SC-8/8(1) TLS 1.3-only listeners, SC-12 credential rotation, SI-7/7(1)/7(15) signed releases + SLSA + self-digest, CM-7 default-deny + systemd score, CM-2 config hash at boot, AU-2/3/12 event schema, AU-9(3) (maps to KSI-SVC-VRI, not KSI-MLA-LET; r3 fix)/AU-10/SI-7(7) Merkle tile log, SA-15(13) logging syntax, SA-11/SR-2/3/5 supply-chain gates. Never claim "FedRAMP-ready"; authorization belongs to the deploying CSP. There is no NIAP protection profile for web servers or gateways, so the government path is FIPS 140-3 module use plus 800-53 inheritance (PP_APP + TLS package if CC is demanded). SSDF 1.2 IPD gates (incl. PS.4.3 anti-rollback via signed monotonic versions) are built to the draft and labelled as such. Nodes: `ops.compliance-map-800-53` (B, down), `ops.fedramp-20x-ksi-mapping` (A), `v2.fedramp-class-tiers` (C), `ops.niap-no-pp` (C), `ops.ssdf-12-ci-gates`.
- **R-OPS-5** [B] (new) Audit log = C2SP tlog-tiles: JSON-lines events (ts, seq, actor, action, object, outcome, req_id, config_hash, fips_status) hashed as RFC 6962 leaves; single writer; checkpoint signed only after tile fsync; invariants I1 append-only consistent checkpoints, I2 gapless seq = leaf index, I3 full tiles immutable, I4 fsync order, I5 independent verification, I6 typed redaction, I7 explicit failure policy (fail-closed for admin actions); optional witness cosignatures. Tamper evidence needs an external witness. No production Rust writer exists (tlog_tiles 0.2.0, 4.2k downloads): we build it and use Go Tessera (v1.0.4; avoid 1.0.3) as the conformance oracle. Node: `ops.audit-log-spec`.
- **R-OPS-6** [A/B] (new) Operability: ACME via instant-acme `=0.8.5` with the `fips` feature, ARI renewal, Pebble in CI, hot cert swap through `ResolvesServerCert` (B; 8 months without a release). Config: typed Rust parse with `deny_unknown_fields`, emitted JSON Schema, `aegis check-config` (pure, nonzero exit) in ExecStartPre (C). Secrets: systemd `LoadCredential(Encrypted)`. **Generated config is untrusted input**: validate limits at build/load, fail soft to last-known-good, keep a global kill switch, and deny `clippy::unwrap_used`/`expect_used` in the core (Cloudflare 2025-11-18: an oversized generated feature file hit a Rust `unwrap()` and took down the proxy; `r2e11.cloudflare-2025-11-18` [A]). Error and log text containing attacker bytes is untrusted input to operators' debugging agents: escape it (`r2e11.waf-log-injection-agents`, C).
  - Diff r3: the Cloudflare outage node is merged with `zd.l4-config-push-outage`. The root cause was a ClickHouse permission change that doubled the generated feature file (limit 200, ~60 used), regenerated every 5 minutes, so the outage flapped. Lessons added: canary pushes and parse-validate-swap with last-known-good on every reload (R-OPS-7 UP-7).
- **R-OPS-7** [C protocol / A mechanisms] (new r3) **In-place upgrade protocol, invariants UP-1..UP-7.**
  - Mechanism: parent-spawns-child fd inheritance (shellflip-style, in-tree on `nix` 0.31.x + `sd-notify` 0.5.0, no custom unsafe), with the systemd fd store (`FileDescriptorStoreMax`, `FDSTORE=1`) as the crash net.
  - **Never a second-process SO_REUSEPORT bind:** it creates a separate accept queue whose close RSTs queued connections (HAProxy measured 2-3 per million per reload on 4.9). `tcp_migrate_req` (5.14+) is opt-in and was hit by CVE-2026-46015.
  - A spawns B after `check-config` and a signature check of B against the attested digest. B validates and claims its fds and signals ACCEPTING. A sends MAINPID, does a two-phase GOAWAY (2^31-1 first, the real id ≥1 RTT later), drains to deadline D, zeroizes its STEK and exits. A rollback window applies if B dies.
  - Invariants:
    - **UP-1** a listener socket is always open in a live process, and no non-empty queue is closed unpolled.
    - **UP-2** no unclaimed REUSEPORT fd: each received fd is validated (SO_TYPE, SO_ACCEPTCONN, getsockname) and then claimed or closed (Pingora `close_unclaimed`; Proxygen black-holing).
    - **UP-3** GOAWAY last_stream_id is correct.
    - **UP-4** exit ≤ D, with forced closes counted (zero drop only before D).
    - **UP-5** STEK by pipe (R-PQC-6).
    - **UP-6** CLOEXEC hygiene (MSG_CMSG_CLOEXEC).
    - **UP-7** a failing B never degrades A, and the handover parser never panics.
  - Handover socket: SO_PEERCRED, a 0700 directory, length caps, fuzzed. nginx trusts an env fd list unchecked, and Envoy hot-restart IPC is unauthenticated AF_UNIX (issue #45872 reports a length overflow).
  - QUIC: out of scope for v1.
  - Harness gate: 200 consecutive upgrades at 5/s under 2k new conn/s (H1/H2/TLS-resume), 0 refused/RST; fault injection (SIGKILL B, hang, bad config, oversized message, wrong uid, stray fd, concurrent upgrade); a naive REUSEPORT negative control must fail; 3 green nightlies. TLA+ model.
  - Nodes: `zd.l5-upgrade-protocol` (C), `zd.l5-upgrade-harness-gate` (C), `zd.l2-same-socket-vs-reuseport` (B), `zd.l3-pingora-graceful` (A), `zd.l3-systemd-fdstore` (A), `zd.l4-orphan-socket-blackhole` (A), `zd.l4-h2-goaway-two-phase` (A), `zd.l4-reload-attack-surface` (B), `zd.l4-rust-fd-crates` (A), `zd.l4-reuseport-kernel-migration` (A).
  - Reverse to a REUSEPORT-migration design if spike q3-033 shows zero queue loss with `tcp_migrate_req` on the target kernel.
- **R-OPS-8** [B] (new r3) **Scale-out state sits behind traits with in-memory single-node implementations first:**
  - `TicketKeyRing`: per node, or a shared ring from storage (HKDF-epoch derivation is our own sketch with no production example).
  - `RateLimitStore`: local-only multiplies limits by replicas; consistent-hash per site; gossip (Raghavan 2007: 2.88 kbps per limiter); or Redis Lua. Cloudflare measured 0.003% wrong decisions with per-PoP counters.
  - `IdempotencyStore`: linearizable create-if-absent via a single owner by hash or a DB unique constraint; draft-08 is silent on multi-node.
  - `AuditSequencer`: one sequencer per log (Tessera).
  - The single-node golden needs none of these.
  - Nodes: `zd.l3-scaleout-state-matrix` (B), `zd.l4-ratelimit-measured-cost` (B).

### Developer and coding-agent surface (W-DX, new in round 3)
- **R-DX-1** [C decision / B experiment] (new r3) **First-party handlers are native Rust against a separate-crate, capability-typed SDK.**
  - SDK shape:
    - `Ctx<'r, E: Effect>` is built only by the router, with a non-optional, non-Default `Principal` with private fields, so a missing authn check cannot be written.
    - `TenantDb`/`TenantCache` are request-lifetime and non-Clone.
    - `Tx<Open> → Committed` typestate gates effects (aligns with R-STATE-6 NC2/NC6).
    - `Html`, `Url` and `Secret` are newtypes; delete-style operations take `Granted<Cap>` proofs.
    - No raw SQL or HTML API; the app crate is `forbid(unsafe_code)`.
    - Agent edits to `sdk/**` are denied, because in-crate privacy errors print "help: consider making the field publicly accessible" (a CI grep forbids that text in reject logs).
    - The handler Ctx exposes raw request bytes only as a verified-before-parse capability (webhooks, R-ING-2).
  - Evidence: a toy experiment (n = 16 single-edit mutants) rejected 13/16 at compile time against the capability shape vs 1/16 for an axum-like shape. 5 of the 13 were absent-API rejects (API minimalism). Semantic classes (same-tenant ownership, archived visibility) slipped through both shapes, so those go to Cedar plus oracle tests.
  - Opt-in guards (axum extractors, Rocket guards, Leptos server fns, Convex identity) fail by omission.
  - Prior art to evaluate before building: policy-core (axum, typed `Ctx<Unauthed>/Ctx<Authed>`), typesec-agent, capsec.
  - CI gate: a compile-fail mutant corpus of ≥30 with ≥90% of structural-class mutants rejected.
  - Benchmarks do not show Rust as an agent handicap: SWE-bench Multilingual Rust 58.1% (best language), Claw-SWE-Bench Rust best for 7 of 11 models. But both draw on one task pool (n = 43, likely contaminated). The one-shot Rust gap is about 3 pp for stronger models (PROBE).
  - Nodes: `dx.l5-decision-sdk-shape` (C), `dx.exp-handler-sdk-mutants` (B), `dx.exp-error-signal` (B), `dx.omission-problem` (B), `dx.sdk-design-space-matrix` (C), `v3.typed-authz-ctx-prior-art` (C), `dx.swebench-multilingual-rust` (B), `dx.claw-swe-rust-agentic` (C), `v3.claw-swe-shared-task-pool` (B), `dx.fpeval-probe-corrections` (B).
  - Reverse if async/tokio lifetimes break non-`'static` handles in real axum (spike q3-012), or an LLM trial shows >2× repair iterations with no defect drop (q3-031).
- **R-DX-2** [B] (new r3) **The deploy artifact is OCI + cosign, digest-pinned** (Spin v3 `registry push` and `up -f <ref>@sha256`, cosign ≥2.0). A single-vendor git-push PaaS is a sustainability risk: Shuttle stopped Pro projects on 2026-01-16. The compiler does not catch hallucinated dependencies, so pair this with the intake gate (R-SUP-4). Nodes: `dx.deploy-prior-art` (B), `dx.compiler-feedback-ablations` (C).

## 4. Assurance case (threat → mitigation → mechanism → residual)

| threat | mitigation | assurance mechanism | residual |
|---|---|---|---|
| H2/H3 resource exhaustion (incl. stall, translation amplification) | golden pins + wrapper; TBI-1..9; H3 off; request-complete before backend conn | Kani H1-H5 (Kani ≥#4910); Verus twin for ledgers; Lean composition lemma; fuzz resource-ratio oracle O1-O6 over corpus (Rapid Reset, MadeYouReset, CONTINUATION, HTTP/2 Bomb, Header Accordions, VU#885548); DST stall replay | TBI-4/7/8 rest on our wrapper over h2; C_FIELD unmeasured; new variants yearly |
| smuggling / parser differential (incl. H3→H1, Upgrade: TLS) | strict H1; H2/framed upstream; regenerate framing; one TLS mode per port | HTTP Garden differential; Lean HTTP/1.1 grammar model + differential testing (Lean `Std.Http` as candidate oracle); EverParse/Vest for binary framings | H1 Rust parser not proven equivalent to the model |
| canonicalization / authz bypass | single canonical form; Cedar PDP; tri-state combiner | Cedar Lean model + DRT; Lean `combine_failclosed`; obs-text/UTF-8 fuzz | Cedar Rust evaluator; Lean compiler (native_decide) and cvc5 in TCB |
| fail-open construction (empty policy, error → principal) | INV-NONEMPTY; non-default-constructible Principal; error ⇒ Deny | build-time lock check; 100k proptest; default-config gate | operator "Unrestricted" overrides (CI-gated) |
| data-plane injection / authz per family | typed op IR; generate-don't-parse; per-adapter lock with denylists; native per-tenant creds; binary collations; unsound-lowering denylist (r3) | lock generation in CI; normalizer differential fuzz; INV-NONEMPTY proptest; **executed lowering oracle leak_cases=0 at ENGINE_PIN + live schema gate + Lean Refines model (r3)** | native RLS bypasses; Lean model unchecked (T4 sorry); refinement tested not proven; write path; timing channels; PEP-only adapters inside trust boundary |
| cross-request state scope | CRS C1-C8; keying table; whole-config pool keys | two-scope differential oracles; nginx CVE-2025-23419 replica; key-completeness fuzzer; oracle mutation | classes not yet enumerated |
| agent origin/session/audience/parser | listener-gate type; sealed handles; strict shared JSON parse; resolved-address egress | advisory-derived corpus (33 cases, ≥5 variants for fix-twice classes); zero-handler counter | absent-Origin interop untested |
| admission swarms | pipeline S0-S6; cost budgets; load-keyed ladder | swarm DST spec; I1/I2/I5/I7 property tests; TLA+ for I3/I4/I6 | all numbers E; JA4 separation unmeasured |
| memory corruption | Rust; forbid(unsafe); C drivers out of process | Miri; sanitizers; geiger ceilings; lean-budget unsafe gate | aws-lc C (1.5M LOC), tokio unsafe, rustc |
| sandbox escape (Wasm/KVM) | provenance table; OS sandbox around every Wasm worker; exact pin; default guards | config + feature-set CI assertion; 72 h patch SLO | M0 residual (1 escape in 65 advisories); KVM core |
| extension-boundary decoding | host parses first and re-serializes module output; no Proxy-Wasm-style shared KV/context switch | conformance C2 hostile-module corpus | host decoder correctness |
| durability loss | ack ⇒ fsynced; bootstrap dir fsync; pinned durability options | crash harness (≥10k images/cell, 3 seeds, controls); DST disk model | double faults and EIO untested; real-kernel arbitration pending |
| TLS logic / PQ downgrade | rustls ≥0.23.46; HRR policy; scoped ticketers; 0-RTT off | HRR acceptance test; downgrade harness; BoGo; Wycheproof | WebPKI PQ auth absent until MTC |
| remote timing | constant-time compares at TCP-timestamp resolution | dudect/ctgrind with pinned compiler; ts-based timing harness | compiler-induced timing (Clangover class) |
| supply chain | locked, cooldown, vet, no-network build.rs, SLSA L3, TUF 3/5; lockfile smoke on bump | repro double-build; attestation verify; zizmor | maintainer takeover (xz class) |
| config-plane failure | validated generated config; last-known-good; kill switch; no unwrap | clippy deny; config fuzz | — |
| async cancellation (r3) | INV-NOMUT-C NC1-NC8; discard-on-cancel checkin predicate; commit-point latch; pre-debit + charge cancels; pinned driver fixes | cancel sweep (CancelAt<N>, 8 modes × 8 oracles, named regression corpus) as PR gate; clippy CR1-CR9; TLA+/P model | only executed paths swept; unreleased upstream fixes; reconnect cost unmeasured |
| front-end defect classes (r3) | typed Origin; validated-101 gate; no deflate; canonical route authz; GraphQL/webhook/SSE rules; fail-closed effective limits | ingress conformance harness (CSWSH matrix, upgrade desync differential vs hyper/Pingora, :path variants, 1-byte DATA, GraphQL 415/405, webhook replay, PROXY cases); CVE→test traceability | tonic/async-graphql defaults verified by source read only |
| reload / upgrade (r3) | fd inheritance + FDSTORE; claim-or-close fds; two-phase GOAWAY; drain deadline; STEK by pipe; authenticated handover | upgrade harness (200 upgrades under load, fault injection, REUSEPORT negative control); fuzz handover parser; TLA+ | forced closes after D; H3 resets |
| PQ downgrade at the server (r3) | pq-required kx_groups on agent/API listeners; prefer-post-quantum asserted on every rustls; HRR verdicts frozen | 5-verdict HRR acceptance test per rustls bump; lockfile feature audit | public listener classical for X25519-first clients until PreferServerOrder ships |

### TCB ledger (round 3; sizes where measured)
- **rustc + LLVM + std.** Unchanged (166 open I-unsound in r1).
- **tokio.** 155k LOC. Note tokio 1.54 rejects zero-capacity buffers (breaks Pingora 0.9.0).
- **hyper/h2/httparse.** 16.7k / 15.2k / 3k LOC.
- **AEGIS transport wrapper** (TBI-1/4/5/8 enforcement): ours, to be Kani/Verus-checked.
- **rustls.** 45.7k LOC, 6 unsafe sites.
- **aws-lc-rs / aws-lc-sys.** 11,271 unsafe binding lines, 1.5M bundled C/asm LOC (measured on the hello build). FIPS boundary when pinned.
- **Data-plane adapters in process.** Each adds its driver's full LOC (e.g. mongodb 91.7k LOC / 14 unsafe sites; scylla 93.9k / 3; redis 49.3k / 6). C-binding drivers are out of process and outside the core TCB but inside their worker's.
- **Linux kernel.** seccomp-bpf, Landlock, cgroups, systemd sandboxing. KVM if microVMs are used.
- **Wasmtime + Cranelift.** P2/P3 only, inside an OS sandbox; M0 residual 6 of 65 advisories.
- **Host decoders of module output** (extension boundary): in the verified TCB by contract.
- **Cedar Rust evaluator.** 15.7k LOC, DRT only. Lean kernel, Lean compiler (native_decide) and cvc5 trusted for the analyses.
- **Audit-log tlog writer.** Ours; Go Tessera as oracle.
- **Proof checkers (build time only).** Lean 4.35 kernel plus the bundled independent checkers (nanoda, lean4lean) under `lake check --paranoid`; Verus + Z3 (131 soundness-labelled issues, 41 open; 81 filed in Oct 2026, check for bulk batch); Kani/CBMC pinned at ≥ #4910; TLC. Specs are TCB.
- **Embedded store** (SQLite or redb), gated by the harness. **Postgres** server/planner (RLS defence-in-depth only).
- **CI/release.** GitHub runners, Sigstore/Rekor, TUF keys.
- **Added in round 3:**
  - The **pool checkin predicate** and drop guards (ours; NC3).
  - **Per-adapter `Backend.Refines` facts plus the engine's collation/affinity semantics**: tested by oracle, not proven, and engine logic bugs are in scope.
  - The **token verifier** (ours) plus **EverParse deterministic-CBOR Rust** (vendored, verified parser; tree hash recorded).
  - The **upgrade handover parser** (ours; fuzzed).
  - **DB drivers pinned at git revisions** (sqlx, diesel_async, patched tokio-postgres).
  - **AWS-LC FIPS 3.1.0** as the FIPS boundary when the FIPS lock is used (ML-KEM approved; X25519 and ML-DSA outside the boundary).
- **Measured supply-chain mass of the golden lock (233 crates, 2026-10-25):** 116 of 165 linux-tree crates unaudited by any imported cargo-vet set, 3.66M lines (aws-lc-sys 2.09M, tokio 155k, libc 136k, cedar-policy-core 134k). cargo-geiger: 24,928 used unsafe items over 80 crates. Protocol logic is unsafe-free (rustls, webpki, cedar 0; h2 3; hyper 123); the unsafe mass is runtime/allocator (tokio 2,527; memchr 2,138; hashbrown ~1.5k ×3; aws-lc-rs 1,052).

### NOT proven (explicit)
- The Cedar Rust evaluator (DRT only).
- HTTP/1.1 text framing in Rust (only a Lean model + differential testing is planned).
- TBI-4/7/8 over hyper/h2 as written (they rely on our wrapper; C_FIELD is measured, not proved).
- The tokio/hyper I/O shell and async liveness (SOSP'26 Lion shows a Verus liveness contract for a Tokio-API runtime exists; not adopted).
- Wasmtime runtime, WASI, component glue and the x86_64 Cranelift lowering; KVM.
- aws-lc C outside its verified parts.
- Soundness of IR lowering (Pred → SQL/Mongo/OpenSearch filters returns a subset of permitted rows). r3: a core-Lean model with refinement-parameterised theorems is drafted but unchecked (T4 `sorry`); per-adapter refinement is tested by oracle, not proven; the write path, projection/order/cursor/error leaks, OpenSearch, and timing/scoring channels (arXiv 2608.11730) are out of scope.
- Cancel safety beyond the executed paths the cancel sweep enumerates; unreleased upstream driver fixes.
- Token theorems T1-T6 and the upgrade invariants UP-1..UP-7 (statements and specs only).
- The admission tuned table's numbers (uncalibrated simulator; C5 NAT flash crowd fails; C11 untested).
- Native DB enforcement (documented bypasses) and normalizer-vs-backend-parser equivalence.
- Microarchitectural tenant isolation inside a shared process; module-authored audit content.
- Admission-controller invariants I3/I4/I6 (model only).
- Embedded-store crash consistency beyond single crashes on one kernel (no double fault, no EIO, logical replay model).
- Noninterference of arbitrary handlers; DST fidelity (kernel, entropy, disk).
- Spec fidelity of every proved component (Verus-SpecGym: 77.8% upper bound on spec correctness for LLM-written specs).

## 5. Formal properties (named; rung)

| invariant | statement source | tool / rung (proposed) |
|---|---|---|
| no_ambient_authority | `inv-no-ambient-authority`; golden contract I1 | Lean induction over step relation; sealed `Cap<O>`; linker allowlist + static import check (survives arbitrary modules) |
| attenuation_monotonicity | `inv-attenuation-monotonicity`, `r3e05.l5-token-wire-format-lean` | r3: conjunction-of-all-caveats evaluation, so monotonicity = `List.all_append` (core Lean T1); aud binding T2, expiry T3, depth T4, verify⟺MAC∧denote T5 (HMAC opaque); F1-F9 fuzz + DRT to Rust |
| decision_failclosed (tri-state) | `vfg-policy-tristate-failclosed-invariant` | Lean `combine_failclosed`; host combiner (survives arbitrary modules, I7) |
| INV-NONEMPTY | `dpf-empty-means-all-pattern`, `dpf-l5-allowlist-generation` | structural check after lowering at build time; proptest 100k/adapter |
| failed_request_no_mutation | `sdg-failed-request-no-mutation`; golden I3 | by construction + DST; survives modules only for host-staged effects |
| transport budgets TBI-1..9 | `l5-transport-budget-invariant-tbi` | Kani (pure structs), Verus (ledgers), Lean (composition), fuzz + DST (CPU, stall) |
| admission budgets I1-I7 | `abuse-L5-budget-invariants` | property tests (I1/I2/I5/I7); TLA+ (I3/I4/I6); swarm DST |
| cross-request scope CRS C1-C8 | `crs-l5-invariant-text` | per-clause differential oracles + oracle mutation; C3 as an information-flow property (Kani/proptest feasibility open, q-seed) |
| parser_canonicality / no_desync | `http1-desync-2025`; golden I5 | Lean grammar model (unambiguity, round-trip) + differential vs Rust parser; EverParse for binary; survives modules if host parses first and re-serializes |
| audit append-only / completeness | `ops.audit-log-spec`; golden I6 | Kani/proptest for I1-I3; Tessera oracle; log-vs-effect diff test |
| tenant isolation | golden I4 | logical: survives (host-owned tenant handle, native creds); microarchitectural: assumes golden modules unless per-tenant process |
| store_never_reused_after_trap | `crash-isolation-semantics` | type/API boundary + test |
| pq_no_downgrade | `rec60-rustls-0.23.46-downgrade` | HRR acceptance test |
| ack_implies_durable | `cc.l5-crash-harness-spec` | crash harness + DST |
| INV-NOMUT-C NC1-NC8 (r3) | `ac.l5-inv-nomut-c` | TLA+/P with cancellation as a nondeterministic action; Kani/Lean for NC4/NC5; cancel sweep (host-enforced NC1/3/4/5/8 survive modules) |
| lowering_sound (r3) | `irl-l5-lean-lowering-theorems` | core Lean T1-T5 parameterised by `Backend.Refines` (unchecked; T4 sorry) + executed oracle + schema gate |
| upgrade UP-1..UP-7 (r3) | `zd.l5-upgrade-protocol` | TLA+ + upgrade harness + handover fuzz |
| admission I8-I11 (r3) | `r3e07-L5-budget-invariants-additions` | I8 GCRA algebra (Kani/Verus); I9/I10 TLA+; swarm acceptance C1-C12 |

- **R-FORMAL-1** [B/E] Proof pipeline rules (pinned verifier/solver; TRUSTED ledger; no admitted modules; spec/proof by separate agents; executable specs vs vectors; spec mutation). Unchanged.
- **R-FORMAL-2** [B] (diff r2: made concrete) Prover per obligation, smallest toolchain first:
  - **Required on the laptop: Lean 4.35 core (no Mathlib; Batteries at most) + TLC, about 1.1 GB.** Lean core measured: Init-only subset 676 MB, Init+Std 1.0 GB, toy check 0.24 s / 514 MB RSS. TLC: 2.67M states in 4.4 s / 362 MB.
  - CI only: Verus 0.2026.10.18 + rustc 1.99.1 (3.16 GB), Kani 0.68.0 + nightly (~2 GB; but see R-FORMAL-3), F* (694 MB), EverParse (973 MB), Apalache (4 GB default heap).
  - Mathlib is avoidable: Cedar's Lean proofs need only Batteries. **Aeneas is out of the required path** because it requires Mathlib (5.8 GB, 9.9 GB RAM / 32 min to re-check).
  - Lean carries spec/model obligations (policy, attenuation, HTTP/1.1 grammar, budget composition, effect mediator), tied to Rust by differential testing. Kani carries unsafe glue and pure counter structs (never async/Arc<Mutex>/slab state machines: memory explodes). Verus carries unbounded ledgers. TLA+/TLC or DST carries liveness.
  - The production image ships zero prover binaries; toolchain digests go into the release attestation.
  - LLM proof synthesis is an optional cloud accelerator only (CryptoProver: Verus proofs of curve25519-dalek + chacha20 in 11.4 h for $467).
  - Nodes: `vfg-toolchain-pin-footprint-table` (A), `vfg-lean-core-minimal-measured` (A), `vfg-mathlib-avoided-cost-and-aeneas-dependency` (A), `vfg-obligation-to-tool-map` (C), `vfg-verus-footprint` (B), `l4-negative-kani-memory-explosion` (A), `rec60-cryptoprover-symcrypt`.
  - Reverse if a golden obligation needs Mathlib, or Verus peak RAM on the first 10 obligations exceeds 16 GB (spike q2-013).
  - Diff r3: two more Lean obligations are drafted in core Lean (no Mathlib, no Batteries): data-plane lowering (`AegisIR/Lowering.lean`, 232 LOC, R-DB-7) and token T1-T6 (R-AUTHZ-6). Neither has been checked: no Lean toolchain was installed within the research disk budget. Spikes SPK-LEAN-IR-1 / q3-020 (projected <5 s, <0.7 GB from `vfg-lean-core-minimal-measured`). If they check as projected, the Lean-core laptop toolchain carries spec obligations for the policy, attenuation, lowering and budget composition.
- **R-FORMAL-3** [A] (new) **Proof gate hardening** (a false PASS is the worst failure):
  - Diff r3: Cedar's 10 `native_decide` uses sit in the SymCC path (Int64 and Ext lemmas). Either replace those closed literal facts (trivial) before using SymCC in the golden gate, or list the Lean compiler as TCB for the analysis only, never for the authorizer (`cedar-lean-proofs-2026-10` r3 revision).
  - Lean: `lake build`, then `lake check --paranoid` (accepts only if every bundled kernel checker accepts; #15145, 2026-09-14; nanoda re-checked 59,400 declarations in 49.7 s / 362 MB); axiom allowlist exactly {propext, Classical.choice, Quot.sound}; ban `native_decide` and `bv_decide` (each adds a per-proof axiom trusting the Lean compiler); toolchain must include the 2026 kernel soundness fixes (#14807 is_prop, #14577 nested inductives, #14498 opaque fvars). The conjunction is not independent against shared-spec bugs: nanoda also accepted the #14807 exploit.
  - Kani: pin a main commit at or after PR #4910 (no release contains it; 0.68.0 reported VERIFICATION SUCCESSFUL when CBMC ran out of memory, #4905), fail on any CBMC exit code other than 0 or 10, run harnesses serially or with an instruction budget (parallel runs changed 30 of 220 verdicts, #5043), cap each at 6 GB, treat OOM or timeout as FAIL.
  - Mutation gate: fail on cargo-mutants exit codes {2, 3}; triage equivalent mutants before setting thresholds (the cited httparse "test gap" was an equivalent mutant).
  - Nodes: `vfg-proof-ci-gate-spec`, `vfg-lean-multikernel-paranoid-check` (A, down), `vfg-lean-kernel-soundness-bugs-2026`, `vfg-native-axiom-tcb`, `vfg-kani-footprint-and-gate-failures` (A, up), `as.mutants-gate` (A, revised).
- **R-FORMAL-4** [B] (new) **Golden extension contract** (§0c responsibility boundary). An invariant survives a malicious module only if it is enforced at a host choke point the module cannot bypass and that host code is in the verified TCB:
  - SURVIVES: I1 no ambient authority (handles only, linker allowlist, seccomp/Landlock); I2 bounded resources if host-enforced (epoch, memory limiter, I/O and host-call quotas, cgroups; fuel is not a bound); I5 parser canonicality if the host parses first and re-serializes all module output; I6 audit completeness for host-mediated effects; I7 fail-closed authz via the tri-state combiner.
  - ASSUMES GOLDEN MODULES: I3 no-mutation-on-failure for adapters with external side effects; I4 microarchitectural tenant isolation unless each tenant has its own process; module-authored audit content; PEP-only data adapters (R-DB-5).
  - PARTIAL: I8 availability.
  - Do not copy Proxy-Wasm ABI v0.2.1: resource limits are only SHOULD, plugins can switch effective context to other requests, and plugins share KV/queues. Out-of-process boundaries still break hosts through their decoders (Envoy ext_proc CVE-2026-47207 UAF/DoS from a malicious server).
  - Nodes: `vfg-invariant-survival-table`, `vfg-proxywasm-abi-not-capability-safe` (B, down), `vfg-extension-boundary-cves`, `vfg-wasi-default-grants`, `dpf-l5-adapter-isolation`.

## 6. Performance model (round 2: first measured core numbers)

- Core (hyper 1.12 + rustls 0.23.46 + aws-lc-rs, fat LTO, panic=abort, 1 core, 512 MB): 4.21 MB stripped, 40 crates, idle RSS 3.4-5.9 MB, 1k idle plain conns 9.0 MB, 1k idle TLS 17.2 MB [A].
- Static h1/h2: hyper+rustls is in the nginx/HAProxy/Pingora class and 2-5× above Caddy/Envoy on a static body; rankings within that class are noise (2.8× trial variance at loadavg ~41) [B].
- TLS 1.3 handshake server CPU, X25519 → X25519MLKEM768 (r3: bands recomputed from raw logs; the r2 "best trial" 123.4 µs is in no log): rustls +12.5% (141.7 → 159.3 µs) and +15.0% (254.8 → 292.9); Envoy +24-25%; Caddy +39-43%; nginx +32-74%; HAProxy +29-32%. Trial spread up to 1.8× on a contended host; only the ordering rustls < Envoy < OpenSSL servers is robust [B]. Wire bytes server→client 731 → 1819 B, client→server 351 → 1535 B. One core saturates at 3-8k new handshakes/s [A; corroborated in direction by public OpenSSL 3.5 data].
- Isolation per request: native 0.38 µs; pooled component 1.24 µs warm, 20 µs fresh instance; fork 124 µs-1.5 ms by zygote size [A].
- seccomp: +18-30 ns per cacheable syscall [A].
- Round 3 measured [A unless noted]:
  - Out-of-process hop on one laptop core: UDS 4.8 µs, futex ring 2.1 µs, in-process 0.02-0.05 µs; throughput 214k/s (UDS) and 465k/s (ring) vs 21.8M/s in process.
  - Zero-copy normalization: 30 µs user CPU per 10 MB; the owned codec adds 0.58-0.72 ms.
  - Exec helper: 2.5 MB RSS / 0.56 MB private; 544 µs to first reply.
  - ML-DSA-44 auth: 11.7 KB server flight, ~+90 µs server CPU. ML-DSA-65: 15.6 KB (one extra RTT). CNSA ML-DSA-87: 21.3 KB.
  - Token verify: handle 83 ns, HMAC chain with 5 caveats 1.2 µs, Biscuit with 3 blocks 158 µs, ML-DSA-65 114 µs [B].
  - Lowering oracle: ~5.7k queries/s on SQLite, 2.6k/s on PG.
  - Defender capacity model on a $5 vCPU [D]: ~1,131 req/s of 429-after-full-TLS (941 with hybrid ML-KEM), ~32 req/s of cost-100 handler work.
- Still unmeasured: $5-VPS end-to-end (incl. the IPC hop and handshake cost on a real 1-vCPU guest), 64-core scaling, io_uring vs epoll on our workload, h3 server cost, commit latency of the safe store configs, C_FIELD, PG reconnect cost under discard-on-cancel.

## 7. Decision record (contested choices, both sides)

- **Wasm vs native handlers.** Unchanged direction (R-ISO-1). Round 2 numbers: Wasm codegen costs ~2× native for serde-class handlers; the component ABI is not the cost driver; Wasm alone is insufficient for hostile code.
- **Data-plane abstraction.** Typed op IR (chosen) vs WIT-first vs per-family traits (R-DB-2). WIT survives as the encoding for out-of-process adapters.
- **Modularity mechanism.** Cargo features + out-of-process capability IPC vs in-process Wasm components vs dlopen (rejected) (R-MOD-1). r3: IPC measured at 4.8 µs per hop; out-of-process is narrowed to C-binding/third-party/compiler-bearing modules within a hop budget, and hot pure-Rust paths stay in process.
- **Ingress structure.** One normalization core (chosen, C) vs per-protocol stacks (R-ING-1).
- **io_uring vs epoll.** epoll (R-TLS-5).
- **Cedar vs Biscuit vs both.** Cedar PDP + own token: Tier 0 opaque handle (default), Tier L HMAC chain in verified CBOR, Tier X COSE ML-DSA-65 at crossings; Biscuit/UCAN/ZCAP rejected on measured cost, determinism and PQ (R-AUTHZ-1/2/6, r3).
- **QUIC now vs later.** Off in the golden until h3 limits land (R-TLS-2).
- **MCP version.** 2026-07-28 + mandatory 2025-11-25 path; stateless is not sufficient (R-AGENT-1).
- **Store-of-record.** SQLite WAL FULL default; redb 2PC alternative; both need the bootstrap rule (R-STATE-4).
- **PoW gates.** Speed bump only, behind cost budgets (R-ABUSE-2).
- **Prover set.** Lean core + TLC required; Verus/Kani CI-only; Aeneas not required (R-FORMAL-2).
- **PQ key exchange at the server (r3).** pq-required on agent/API listeners vs client order on the public browser listener, until `PreferServerOrder` ships (R-PQC-1).
- **PQ authentication (r3).** ECDSA WebPKI + ML-DSA-44 private hops + MTC CredentialSelector, vs pure ML-DSA public X.509 (blocked), composite (long-lived signatures only), AuthKEM/KEMTLS (rejected for TLS), dual chains (R-PQC-4).
- **FIPS lock (r3).** A separate FIPS lock (aws-lc-rs ≤1.17.2 + fips-sys =0.13.11) vs the main golden lock (aws-lc-rs 1.18.x) (R-PQC-2; q3-004).
- **Dependency freshness vs cooldown (r3).** 7-day cooldown + audited security bypass vs a blanket 14-day window, which lands known advisories (R-SUP-3).
- **Cancellation (r3).** Discard-on-cancel (pgx-style) vs state-tracked reuse: discard by default until the reconnect-cost spike (R-STATE-6).
- **Upgrade (r3).** fd inheritance + FDSTORE vs second-process SO_REUSEPORT (rejected) vs tcp_migrate_req (opt-in, recent CVE) (R-OPS-7).
- **Handler SDK (r3).** Capability-typed separate-crate SDK vs plain axum + lints vs WIT component handlers vs Ur/Web-style languages vs Encore-style codegen (R-DX-1; C).

## 8. Supply chain and process gates (feeds templates/)

- **R-SUP-1** [A] `--locked`; cargo vet with an exemptions ratchet and a hard fail on new unaudited crates; cargo-deny/audit; CODEOWNERS on supply-chain/CI files.
  - **Diff r3 (executed on the 233-crate golden lock, 2026-10-25):**
    - cargo-audit 0.22.2 (1,352 advisories): 0 vulnerabilities.
    - cargo-deny 0.20.2: advisories, sources and licences pass (an 11-SPDX allowlist; the default empty allowlist fails 100+ crates). Bans fail on 6 duplicates (getrandom, hashbrown ×3, itertools, r-efi, syn, unicode-width), which become the skip list; CI fails on any new duplicate.
    - cargo-vet 0.10.3 with **zero exemptions** (`cargo vet init` auto-exempts every crate, so strip exemptions before any coverage claim) and all six import sets: 183/233 unaudited, of which 116/165 are on the linux tree (3.66M lines).
    - Per-crate cargo-geiger 0.14.0 ceilings; new unsafe crates or ceiling growth fail.
    - `cargo auditable` build + `cargo audit bin`.
  - The gate list G1-G9 runs cheapest first (G6 workflow lint, G1 deny/audit/vet, G5 new-crate intake, G4 tarball parity, G7 geiger, G3 repro, G8 attest+rebuild, G9 auditable). Each gate has a negative-control PR.
  - Nodes: `sc3.golden-lock-gate-run` (A), `sc3.vet-zero-exemption-baseline` (A), `sc3.geiger-014-golden-unsafe` (A), `sc3.deny-golden-duplicates` (A), `sc3.l5-ci-gate-list` (A 0.80).
- **R-SUP-2** [A] Unsafe budget (forbid in first-party; geiger ceilings). Round 2 gives the measured budget numbers (R-PERF-1).
- **R-SUP-3** [A executed / B policy] Cooldown via cargo min-publish-age + Dependabot cooldown. Round 2 adds: every dependency bump runs a smoke request against the built binary (Pingora/tokio 1.54 panic).
  - **Diff r3 (executed on cargo 1.98.0 `-Zmin-publish-age`):**
    - A 7-day window downgrades 6 crates and lands RUSTSEC-2026-0382 (webpki).
    - A 14-day window downgrades 26 crates, hard-errors on the exact pin `cedar =4.14.0`, and lands 6 advisories: rustls 0.23.45 RUSTSEC-2026-0346..0349, including the silent classical-KX downgrade; webpki 0382; tokio 1.53.2 0386.
  - Policy:
    - `[registry] global-min-publish-age = "7 days"` (stable from 1.100.0: PR #17335 merged 2026-08-28; RFC 3923 merged 2026-05-18).
    - Updates only via bot PR. After any lock change, `cargo audit --deny warnings`.
    - An advisory whose patched version is younger than the window takes the label `security-advisory` and `CARGO_RESOLVER_INCOMPATIBLE_PUBLISH_AGE=allow cargo update -p <crate> --precise <patched>`, a vet delta audit or trusted publisher, a second approval and a 30-day expiry.
    - CI fails any lock entry younger than 7 days without the label.
    - **No exact `=` pins for crates under cooldown**: use caret ranges + lock + security floors (rustls ≥0.23.46, rustls-webpki ≥0.103.16, tokio ≥1.54.1).
    - tokio on a backport line, with x.y.0 releases younger than 14 days blocked (1.54.0 was yanked; RUSTSEC-2026-0384).
  - Golden lock age 2026-10-25: 6 crates < 7 d, 25 < 14 d, median 188 d.
  - Nodes: `sc3.cooldown-executed-cargo-198` (A), `sc3.cooldown-blocked-counts-golden` (A), `sc3.l5-cooldown-security-bypass` (B), `sc3.rustls-advisory-batch-2026-10` (A), `r3e11.tokio-1.54-regression-and-asyncfd` (A).
  - Reverse to 14 days only if the advisory bypass proves unworkable in practice.
- **R-SUP-4** [A/B] Reproducible double build; SLSA L3; TUF 3/5; zizmor; SHA-pinned actions.
  - **Diff r3:**
    - **Repro gate with exact flags:** `rust-toolchain.toml` 1.99.1; `RUSTFLAGS="--remap-path-prefix=$PWD=/src --remap-path-prefix=$CARGO_HOME/registry/src=/cargo/registry --remap-path-prefix=$RUSTUP_HOME=/rustup"`; `cargo fetch --locked`; release with lto = true, codegen-units = 1, panic = abort; build in two directories with different CARGO_HOME and SOURCE_DATE_EPOCH; pass = equal sha256.
      - Measured identical at debug = 0 and debug = 2 on 1.98.0 and 1.99.1; 1.93.1 differs; `cargo auditable` changes the hash. **Toolchain digest and auditable mode are part of the attested build identity.**
      - Negative control: without the registry remap the build must differ.
      - Cross-host reproducibility is open (q1-052); trim-paths (cargo #17488, m1.101.0) will replace the flags.
    - **Tarball-vs-git parity:** 13/15 sampled crates are byte-identical to their recorded commit. aws-lc-sys (1,964 vendored files) and ring (107 pregenerated asm files) are the exceptions and need a submodule/regeneration check (q3-025).
    - **Trusted-publishing provenance:** 30/233 golden versions are trusted-published. Their sha equals the packaged commit for only 24/30, so use git ancestry, not equality. A crate that switches from trusted publishing back to a token-published version is a hard fail. The core pins (hyper, h2, rustls, tokio, aws-lc, ring, webpki) are still token-published.
    - **Release** = provenance (`actions/attest`, separate signing job) + an independent rebuild on a second runner image whose hash equals the attested digest + branch protection (SLSA Build L3 + Source L2). SLSA alone excludes malicious producers and dependencies.
    - **Non-dismissable workflow lint** (zizmor --pedantic, 40-hex SHA pins, top-level `permissions: {}`, no `pull_request_target` with a PR-head checkout, no `github.event.*` in `run:`, no caches shared between untrusted and release workflows, CODEOWNER-approved suppressions, atomic credential rotation). Add audit-log retention and alerts on direct workflow-file pushes (the PostHog attacker deleted the workflow run).
    - **New-crate intake gate** for agent-added dependencies: pass only if vet-audited, or age ≥90 d ∧ recent downloads ≥100k ∧ owners unchanged for 90 d. Fail on edit distance ≤2 to the top 1000 unless allowlisted. Fail for build.rs/proc-macro crates younger than 365 d. `cargo add` goes through a wrapper; the agent sandbox has no crates.io write token.
      - Rust hallucination risk: 0.7-3% of samples; the 22% headline counts std items.
      - Never `cargo vet trust` crates reached by build scripts or proc-macros (arrayref was delivered via a typosquat proc-macro1 build.rs).
  - Nodes: `sc3.repro-ablation-golden` (A 0.78), `sc3.l5-repro-double-build` (A), `sc3.tarball-git-parity-golden` (A), `sc3.trustpub-sha-gate` (A), `sc3.l5-release-attest-rebuild` (B), `sc3.slsa-scope-limit` (B), `sc3.l5-workflow-lint` (B), `sc3.l5-new-crate-intake` (B), `sc3.slopsquat-rust-study-2606` (B), `sc.arrayref-incident` (= `sc3.arrayref-trust-model-gap`).
- **R-SUP-5** [C] (new r3) **Gate ordering from an incident back-test.**
  - 12 incidents, 2024-26: xz, ultralytics, tj-actions, faster_log, evm-units, Nx, chalk/debug, Shai-Hulud 1 and 2.0, the Polymarket typosquats, Trivy/TeamPCP, arrayref.
  - Single gates: vet + new-name + 14-day cooldown stop 10/12; SLSA L3 verification alone 2/12; TUF alone 0/12 at intake; adding SHA pins + repro + tarball parity covers 12/12.
  - The largest class is CI/build-pipeline compromise (5/12, 3 of them via `pull_request_target`), which a seconds-long lint addresses. xz's 34-day window defeats any cooldown under 30 days; only tarball parity was decisive there.
  - The cells are self-scored counterfactuals (n = 12, chosen by prominence), so only the ordering is used: time and novelty gates beat provenance gates.
  - Nodes: `sc3.incident-gate-matrix` (C), `sc3.incident-class-fractions` (B), `sc3.xz-window-cooldown-limit` (A).
- **R-ASSURE-1** [B/A] DST on a sans-IO core with turmoil and injected Rng/Clock; oracle mutation; mutants ratchet; fuzz smoke + nightly; HTTP Garden.
  - Diff r2: aws-lc's default entropy is a Tree-DRBG seeded by CPU jitter plus RDRAND/RNDR, which no libc/seccomp/ptrace interposition can make deterministic: **under simulation, replace the rustls CryptoProvider** with a deterministic one (`as.dst-entropy-leak`, A, up). Any interposition-based harness must strace-audit its shim (rustix raw syscalls bypass LD_PRELOAD; `cc.neg-ldpreload-rustix`).
  - Diff r3: **run the existing art.** Executed oracles found bugs in code written to be safe: the explorer's own hardened SQLite lowering, 3 unreleased driver fixes, and OPA's SQL Server lowering. Released binaries, pip/npm packages and paper artifacts (the figshare artifact exposed the Rust hallucination metric counting std items) are run, not read, before a load-bearing number is accepted (`irl-l5-differential-oracle-harness`, `sc3.slopsquat-rust-study-2606`).
- **R-ASSURE-2** [B] (new) **Conformance suite third parties can run**: C0 static (feature set, linker imports, config pin), C1 behavioural, C2 adversarial host (hostile-module corpus: loops, memory bombs, I/O amplification, forged or stale handles, effective-context switch, double responses, non-canonical output, obs-text, crash loops, trap after partial commit; oracle = invariant monitors + audit-vs-effect diff), C3 differential vs the Lean models, C4 traceability (duvet-style). Produces a signed JSON report; C0-C2 must pass 100% to claim conformance. Modelled on wasi-testsuite, k8s-conformance and Cedar DRT. Node: `vfg-conformance-suite-outline`.

## 9. Hard gates

- Offensive tooling only as test harnesses against our own server (staging, no egress). Unchanged.
- r3: the Tenuo CEL attenuation bypass is a third-party vulnerability. Its PoC strings are not published in the map; the operator decides on a private report to security@tenuo.ai. No crate names were registered during the slopsquat study.
- r3 naming: RFC 10032 (AEGIS AEAD, CFRG) collides with the working name "Aegis". Rename the project before any public release.
- Licences: HTTP Garden GPL-3.0 (external container only); AFL++ AGPL (avoid); Sozu AGPL (not a base). New: the modelcontextprotocol/conformance repo licence field is NOASSERTION, so check before vendoring cases.
- Export control: standard crypto (TLS, ML-KEM, ML-DSA); note still to be written in COMPLIANCE_MAP. Korea (KpqC: NTRU+, SMAUG-T, HAETAE, AIMer) and Japan (NCO: government PQC by 2035, hybrid + agility) motivate a pluggable KEM-group interface for those markets (`r2e11.kpqc-korea-japan`, C).

---

## R. Rule diff log

- **Round 1 (2026-10-24):** created 41 rules (R-GAP-1..3, R-THR-1..3, R-TLS-1..6, R-PQC-1..5, R-ISO-1..3, R-AUTHZ-1..4, R-STATE-1..4, R-DB-1..2, R-AGENT-1..3, R-OPS-1, R-FORMAL-1..2, R-SUP-1..4, R-ASSURE-1).
- **Round 2 (2026-10-25): 30 new rules, 27 round-1 rules changed (24 amended in text, 1 open → decided, 2 grade/blocker changes), 0 deleted, 0 reversed in direction. Total 71.**
  - New: R-THR-4; R-ING-1; R-TLS-7, R-TLS-8; R-MOD-1; R-PERF-1, R-PERF-2; R-PQC-6; R-ISO-4; R-AUTHZ-5; R-STATE-5; R-DB-3, R-DB-4, R-DB-5, R-DB-6; R-AGENT-4, R-AGENT-5, R-AGENT-6; R-ABUSE-1..4; R-OPS-2..6; R-FORMAL-3, R-FORMAL-4; R-ASSURE-2.
  - **Open → decided:** R-DB-2 (backend-agnostic data plane: typed op-capability IR) [B decision / C design].
  - **Grade moved down:** R-PQC-2 B → C (byte-identical FIPS pin unresolved: 1.15.3/0.13.11 vs 1.17.x; CMVP #5429 unaddressed). R-PQC-3 stays C with a new blocker (no SecP384r1MLKEM1024 in rustls).
  - **Amended (direction unchanged):** R-GAP-1 (lean column), R-GAP-2 (fail-closed construction), R-GAP-3 (lockfile smoke), R-THR-1 (metric made explicit; new classes 6 and 8), R-THR-2, R-THR-3 (2026 C-server memory surge), R-TLS-1 (golden pins + wrapper), R-TLS-2 (H3 off in golden; quinn window pin), R-TLS-4 (driver PQ inheritance), R-TLS-5 (0 KEV), R-TLS-6 (no verified HPACK decoder anywhere), R-PQC-1 (carve-outs; HRR test mandatory), R-ISO-1 (measured inputs; OS sandbox always around Wasm), R-ISO-2 (exact pin; no density tuning; MDWX), R-AUTHZ-1 (TCB wording), R-AUTHZ-2 (no JWT), R-STATE-2 (principal MUST), R-STATE-4 (measured pass/fail table; bootstrap rule; interposer-independent harness), R-DB-1 (role-DDL recycle), R-AGENT-1 (stateless insufficient; sealed requestState), R-AGENT-3, R-FORMAL-2 (concrete toolchain; Aeneas out), R-SUP-3, R-ASSURE-1 (CryptoProvider replacement).
  - **Superseded bridge:** round 1's candidate invariant "no unauthenticated cross-request state" is replaced by CRS C1-C8 (R-STATE-5): false as stated (authenticated-but-unscoped tickets) and too strong (QUIC tokens).
  - **Decision stability (for the saturation judge):** of the 40 round-1 rules that had a decision, 40 kept their direction (1.00); R-DB-2 went from open to decided. 14 of 41 kept their text materially unchanged (0.34); 27 were changed by new evidence, mostly by adding measured parameters, pins or carve-outs. Load-bearing E/C decisions still open: R-ISO-1 (E design), R-AUTHZ-2 (E), R-ING-1 (C), R-DB-2/4 (C design), R-ABUSE-1/4 (E numbers), R-PQC-2 (C), R-GAP-1 (C).
- **Anchoring audit:** not performed at this stage by design (§0a). The integrator did not read the prior treatments or the seed conversation. Every rule cites only independent map nodes; the Synthesize stage must name any rule whose pick equals a prior-treatment pick and give its independent evidence.
- **Round 3 (2026-10-25): 15 new rules, 37 amended, 3 with a direction change, 0 deleted. Total 86.**
  - **New:** R-THR-5; R-ING-2, R-ING-3; R-PERF-3; R-PQC-7; R-AUTHZ-6; R-STATE-6, R-STATE-7; R-DB-7; R-ABUSE-5; R-OPS-7, R-OPS-8; R-SUP-5; R-DX-1, R-DX-2.
  - **Direction changed (3 of 71):**
    - R-PQC-1, narrowed per listener: the rustls 0.23.x server follows client order, so "HRR whenever listed" is unimplementable on defaults.
    - R-MOD-1: its reversal condition fired for cheap ops (IPC 5-100× in-process), so out-of-process is narrowed to C-binding/third-party/compiler-bearing modules within a hop budget.
    - R-PQC-3: the CNSA profile is pure ML-KEM-1024 + ML-DSA-87 per draft-becker-05, and the new blocker is that ML-DSA is not FIPS-approved.
  - **Grade moved:**
    - R-PQC-2 C → B (FIPS pin resolved: fips-sys =0.13.11 = AWS-LC 3.1.0; aws-lc-rs 1.15.2-1.17.2).
    - R-AUTHZ-2 E → B (three-tier token decided with measured costs).
    - R-ABUSE-1 E → D (simulated numbers).
    - R-OPS-1 B → A (Official Journal).
    - R-SUP-3 B → A/B (executed).
  - **Amended (direction unchanged):** R-GAP-1, R-THR-1, R-THR-2, R-ING-1, R-PERF-1, R-PERF-2, R-TLS-2, R-TLS-4, R-PQC-4, R-PQC-5, R-PQC-6, R-ISO-1, R-ISO-2, R-AUTHZ-1, R-STATE-1, R-STATE-5, R-DB-1, R-DB-2, R-DB-6, R-ABUSE-2, R-ABUSE-3, R-ABUSE-4, R-OPS-4, R-OPS-6, R-FORMAL-2, R-FORMAL-3, R-SUP-1, R-SUP-4, R-ASSURE-1 (plus the 5 grade moves above, 2 of which also changed text).
  - **Decision stability (for the saturation judge):** 68 of 71 round-2 rules kept direction (**0.958**). Load-bearing decisions still at E/C or open: R-ISO-1 (E design), R-ING-1 (C), R-DX-1 (C), R-DB-2/7 (Lean unchecked, write path open), R-ABUSE-1 (D), R-PQC-2 (FIPS lock triangle, q3-004), R-GAP-1 (C, short shelf life). Saturation is not met: mechanical novelty 0.881.
  - **Anchoring audit:** still not performed by design (§0a). The round-3 integrator did not read the prior treatments or the seed conversation.
