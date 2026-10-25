# progress checkpoint 1 (2026-10-24)
Method: GitHub API (repo meta, latest release, contributors, published GHSA counts) for ~45 repos + web search. Data in /tmp/claude-1000/w/{meta,rel}.tsv (scratch).
KEY FACTS (A-grade, fetched from GitHub API 2026-10-24/25):
pingora Rust Apache 27.7k* 119 contrib v0.9.0 2026-09-09; 8 GHSA (CVE-2025-4366, CVE-2025-8671 MadeYouReset, CVE-2026-2833/2835 critical smuggling, 2836 cache-poison, 3 more 2026-10-20 incl. h2 memory exhaustion)
river: Rust, 2.35k*, last push 2024-09-06, v0.5.0 2024-08-30, "no expectation of stability" -> dormant 14mo
envoy C++ 29k*, 1776 contrib, v1.40.1 2026-10-23, >=100 GHSA (43 since 2025-10)
nginx C BSD-2 32k*, 1.31.8 2026-10-21; nginx.org lists 26 CVEs by ID-year 2026 (incl HTTP/3 request body injection CVE-2026-95101, TLS ticket session forgery CVE-2026-97629)
nginx/unit ARCHIVED 2025-10-08, last rel 1.35.0 2025-09-11; fork freeunit v1.37.0 2026-10-04 70*
caddy Go Apache 78k* v2.11.7 2026-10-03 18 GHSA; traefik Go MIT 65k* v3.7.16 >=89 GHSA; haproxy C 3.4.7 LTS (to 2031Q2) QUIC CVE-2026-26080/81
ferron Rust MIT 2.2k* 23 contrib; 7 GHSA all 2026-09-25 (rapid reset, h3 SETTINGS O(n^2), auth_to fail-open critical)
sozu Rust AGPL-3.0 3.7k* 22 issues 64 contrib 2.3.3 2026-10-19 0 GHSA
spin v4.2.5 (Akamai acquired Fermyon 2025-12-01, CNCF) 2 GHSA; wasmCloud 2.11.0; WasmEdge 0.18.1 1 GHSA; wasmer 7.5.0 9 GHSA; workerd v1.20261025.1 2 GHSA(old); wasmtime v50.0.0 81 GHSA (7 crit,6 high,45 med,23 low; 60 since 2025-10); Viceroy 0.21.1
hyperlight (hyperlight-dev, CNCF sandbox 2025-02) v0.18.0 2026-10-14 1 GHSA; firecracker v1.17.0 2026-09-10 2 GHSA 37.6k*; unikraft RELEASE-0.21.0 2026-05-20 license NOASSERTION; Unikraft Cloud seed $6M 2025-10-09
lunatic: last release v0.13.2 2023-05-03, last push 2025-03-29 -> dormant
deno MIT v2.9.8 40 GHSA; bun v1.4.4 2026-10-22 (Rust rewrite merged 2026-05-14 per bun.com/blog/bun-in-rust; Anthropic acquired Bun Dec 2025) 3 GHSA; encore MPL-2.0 v1.58.8 6 GHSA; convex-backend FSL-Apache (NOASSERTION) 1 GHSA; postgrest MIT Haskell v16.5 0 GHSA; hasura v2.51.2 4 GHSA
MCP layer: docker/mcp-gateway MIT Go v0.44.2 10 GHSA (2 crit 2026-07: unauthenticated tool access container mode, config bind mount; sig verification OFF by default; tool-name shadowing); agentgateway (LF, Solo.io) Rust v1.6.0 280 contrib 5 GHSA (stateful MCP sessions cross routes overwrite authz policy high); IBM mcp-context-forge Py v1.1.0 19 GHSA; pomerium v0.33.4 13 GHSA; envoy ai-gateway RENAMED Agent Router (theagentrouter/agent-router, AAIF) v1.2.0; lasso mcp-gateway 395* last 2026-01 5 contrib; invariant guardrails no release, scanner -> snyk/agent-scan; microsoft/mcp-gateway C# 896*, no release
Cloudflare MCP Server Portals: hosted, beta, Aug 2025 (Access-bound), not self-hostable.
# checkpoint 2
- New entrants (GitHub search 2026-10): pingoo (Rust MIT 1.0k*, LB+WAF+PQ-TLS, no release tag, no GHSA, commercial support model); aralez (Pingora-based Rust Apache 804* v0.95.2, 7 contrib); nono (nolabs-ai Rust Apache 4.7k* v0.80.0 agent sandbox, 12 GHSA); pipelock (Go Apache 959* v3.7.1 agent firewall, signed action receipts, 5 GHSA); toolhive (stacklok Go Apache 2.3k* v0.56.0 43 GHSA, MCP in containers); bifrost (maxim Go Apache 9k* 3 GHSA); octelium (Go AGPL 4.1k* zero-trust, MCP gateway); ThinkWatch (Rust 819* license NOASSERTION, 3 contrib); mcpdef (Rust WASM sandbox, docker hub only, unverified)
- Wasmtime 2026-04-09: 12 advisories (2 crit CVE-2026-34987 Winch, CVE-2026-34971 Cranelift aarch64), 11/12 found by LLM multi-agent harness (primary: bytecodealliance.org/articles/wasmtime-security-advisories). fuzzing doesn't cover aarch64 Cranelift/Winch.
- workerd README: "not a hardened sandbox" (must run inside VM)
- nginx/unit README: unsupported, archived; ingress-nginx retired 2026-03 (kubernetes.io blog 2025-11-11, 2026-01-29 statement), InGate dropped.
- Kong: MCP proxy plugin in 3.12 (Oct 2025), governance paywalled enterprise (3rd-party claims; unverified).
- Stacklok survey (Jul 2026, n=100): 41% MCP in some production, 5% governed enterprise-wide; WorkOS: only 18% implement tool scoping (secondary).
- Pingora GHSA 2026-10-20 trio incl h2 memory exhaustion default header-list -> default-insecure.
# checkpoint 3: final JSON written
