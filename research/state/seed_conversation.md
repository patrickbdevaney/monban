# Seed conversation: hypotheses (DATA, not priors)

Condensed from the operator's pasted conversation with another assistant, 2026-10-24. Every line is a **hypothesis to
verify or refute**. None of it is evidence. Several items look wrong or invented (flagged ⚠). Grade each one as you meet it.
OPERATOR STEER (AEGIS_QUESTION.md §0a): do NOT anchor on this list or on the prior treatments. Search the alternative space
independently first; prior picks earn no preference.

## The thesis arc the operator built
1. PHP won the 1990s middle tier because of its execution lifecycle: shared-nothing, per-request teardown, FTP deploy, and
   density on shared hosts. Its language design was not the reason. The alternatives the conversation named:
   - Tcl + AOLserver (threaded, pooled DB, in-memory)
   - Ada 95 / AWS
   - Erlang/OTP
   - OCaml
   - Java servlets
2. AI coding agents invert the old ergonomics tradeoff. Strict compilers, proofs and capability schemas become
   guardrails instead of friction.
3. Target: a single-binary middle-tier server, the successor to nginx + PHP-FPM / Node / FastAPI / Go REST. It should have
   PHP's crash isolation, hot deploy and density, native speed, and containment between untrusted agents and the database.
   It serves human UI, REST/API agents and MCP/browser-driving agents. **The DB (Postgres/SQLite), the CDN/edge and the
   physical network are external boundaries, out of scope to rewrite** (operator confirmed). The scope is software,
   servers, VPS and networking, with maximal formal security.

## Concrete component hypotheses from the conversation
- Transport:
  - io_uring thread-per-core (monoio/glommio, Zig)
  - QUIC/HTTP3 with connection migration
  - hybrid PQC X25519MLKEM768 + ML-DSA-65 (+ Ed25519); SLH-DSA for roots/firmware
  - Merkle Tree Certificates and cert compression for MTU
  - stateless retry for amplification
  - DANE/DNSSEC and CT
  - self-certifying agent addresses
- Isolation:
  - Wasmtime Component Model with fuel + epoch, pooling allocator, MPK, guard pages
  - Landlock + seccomp self-sandbox
  - seL4 or hardened Linux
  - SEV-SNP/TDX
  - SMT disabled
- State:
  - per-request CoW arena
  - session WAL with idempotency keys / step nonces
  - deterministic journaled replay of side effects (durable execution)
  - redb/LMDB
  - Merkle/BLAKE3 tamper-evident log
- Authz:
  - zero ambient authority
  - Biscuit/Macaroons attenuated capabilities (PQC-signed)
  - Datalog policies
  - taint/IFC labels on untrusted LLM input
- Serialization: Cap'n Proto / WIT / FlatBuffers. Untyped JSON is banned at the core.
- DB gate ("Iron Gate"):
  - compile-time extracted, prepared-statement-only queries with IDs
  - no raw SQL from workers
  - Postgres RLS via SET LOCAL principal/tenant
- Agent ingress:
  - one handler definition projected to HTML/JSON/MCP tool schema
  - machine-cadence detection
  - MCP sessions with idempotency
- Abuse economics:
  - x402 HTTP 402 micropayments, state channels, fuel-per-payment
  - PoW (Equihash/Argon2)
  - Privacy Pass
  - cost-weighted budgets rather than RPM
- Verification:
  - Verus/Kani/Creusot proofs of core state machines
  - HACL*/libcrux/Jasmin constant-time crypto
  - CompCert / verified Cranelift (VeriISLE)
  - FoundationDB-style deterministic simulation
  - Nix/Bazel reproducible builds
  - threshold-signed releases
  - proof-carrying cartridges
- Ops: a single ~25 MB static binary, hot-swap signed .wasm "cartridges", runs on a $5 VPS through to bare metal.

## Claims that need checking (⚠ = suspicious)
- ⚠ "0 ns serialization" for Cap'n Proto. Validation and bounds traversal still cost.
- ⚠ "Wasm cold start <10 µs, <2 MB/instance". The real numbers depend on the pooling allocator and AOT.
- ⚠ "Mathematically absolute isolation". Spectre, wasmtime CVEs and TCB size all argue against it.
- ⚠ "PQC causes optical amplifier saturation". Nonsense physics. Ignore.
- ⚠ "RFC 9680 = Merkle Tree Certificates". Verify the number and status. MTC was an IETF draft (Chrome/Cloudflare experiment).
- ⚠ "Rowhammer from fuel-metered Wasm flips capability tokens". Plausible class, overstated as a routine threat.
- ⚠ "Formally verified compiler backend for Wasmtime". Cranelift ISLE lowering-rule verification (Crocus/VeriISLE/Arrival)
  covers a subset of rules, not the whole compiler.
- "TLS termination at the AWS ALB is classical-only". Verify the current ALB/CloudFront/Cloudflare PQC status as of 2026.

## Prior deep-research treatments (DEDUP AGAINST THESE; explore different directions)
- `prior_treatments/PDF1-agentic-web-server-architecture-plan.txt` ("Aegis", a Gemini-style report).
  - Crates: verified-core (Verus), crypto (rustls + aws-lc-rs + biscuit 6 + "AIP"), ingress ("spargio" + quinn + hyper +
    x402-rs), sandbox (wasmtime 49+ pooling + MPK + fuel/epoch), wal (redb group commit), db-gate (pgwire 0.41 +
    pg_query.rs + tokio-postgres + rusqlite, SimpleQuery disabled), compiler (KVerus loop), sim (madsim).
  - ⚠ Items to verify, possibly fabricated or misdescribed:
    - "MCP Streamable HTTP 2026-07-28 spec" with Mcp-Method/Mcp-Name/Mcp-Param-* headers and MRTR/InputRequiredResult
    - "spargio" (an io_uring runtime)
    - "KVerus arXiv 2605.03822"
    - "AIP Agent Identity Protocol arXiv 2603.24775" with its µs numbers
    - wasmtime issue #13467
    - "x402 165M transactions"
    - tokio-uring 370k vs monoio 270k RPS
    - pgwire 0.41.1
    - the KVerus/LLM proof loop inside a build tool as a trusted step
  - Its weak points:
    - It has no threat-model→proof-obligation mapping and no TCB accounting.
    - It has no supply-chain or bootstrap story, no compliance mapping (FIPS 140-3/CNSA 2.0/FedRAMP/EU CRA), and no
      HTTP-parser or request-smuggling hardening.
    - It has no ops/upgrade/key-rotation story, no observability, and no multi-node scale-out.
    - Its comparison with real prior art (Pingora, Envoy, Spin, wasmCloud, workerd, NGINX Unit, Caddy) is thin.
    - It doesn't say what is NOT provable.
- `prior_treatments/PDF2-executive-summary.txt`: a generic ChatGPT-style report recommending Kubernetes microservices +
  zero-trust + ML-model threats (poisoning, extraction). Low specificity. Mostly about hosting models, not the request
  server. Useful only as the "conventional baseline" this track must beat or justify departing from.
