# progress 12 (checked 2026-10-24)
## crates.io API (all checked via /api/v1/crates/<c>[/versions])
pgwire max0.42.1(2026-10-21); 0.41.1 EXISTS pub 2026-09-29 not yanked; 0.41.0 2026-09-04; 0.18.0 exists 2023-12-23
wasmtime max 50.0.0 (2026-10-20); 49.0.0 EXISTS 2026-09-21 not yanked; wasmtime-wasi/-wasi-http 50.0.0 exist
spargio EXISTS crate+GitHub soumyarupsarkar/spargio: 0.5.13 pub 2026-03-18, first 2026-02-27, 23 vers, dl 1373, MIT, 5 stars, last push 2026-03-18 (stale ~7mo)
biscuit-auth 6.0.0 EXISTS 2025-07-16 (latest). redb 4.4.0 latest 2026-10-13. rusqlite 0.41.0 2026-10-24. pg_query 6.2.1 2026-09-30. madsim 0.2.34 2025-10-11. x402-rs 0.12.5 2026-01-21 (x402-rs/x402-rs). x402 crate 0.1.0 2025-02-20 stub
rustls latest 0.23.46 (0.24.0-dev.2 pre). rustls-post-quantum 0.3.0-dev.2 (0.2.0 stable 2024-12). aws-lc-rs 1.18.2. quinn 0.11.12. hyper 1.12.0. tokio-uring 0.5.0 (2024-05-27, stale). monoio 0.2.4 (2024-08-20). glommio 0.9.0 (2024-03).
NOT FOUND: kverus, builtin, builtin_macros, cranelift-isle-veri (crates)
'aip' crate EXISTS but = Google AIP-160/193 Rust impl (aip-rs), NOT Agent Identity Protocol.
## GitHub
wasmtime #13467 EXISTS: ISSUE (not PR) 'How to limit guest code execution rate?' by matthew-a-thomas, opened 2026-05-23, closed 2026-08-25, 8 comments; a user question about fuel vs epoch rate limiting
## arXiv
2605.03822 EXISTS: 'KVerus: Scalable and Resilient Formal Verification Proof Generation for Rust Code' Liu,Wan,Wang,Wang,Huang,Wei; submitted 2026-05-05, v2 2026-08-02; Accepted ASE 2026; cs.SE. Is a research system (Verus), no crate/tool release verified yet.
2603.24775 EXISTS: 'AIP: Agent Identity Protocol for Verifiable Delegation Across MCP and A2A' Sunil Prakash, 2026-03-25, only v1, cs.CR. Compact 0.049ms Rust/0.189 Py MATCH; 0.22ms MATCH; 340-380B/block MATCH; X-AIP-Token header MATCH; max_depth 3 default MATCH. DIFFER: '135us 3-hop, 324us 6-hop' NOT in paper; paper Rust chained verify depth3=0.516ms depth5=0.745ms, Python depth3=0.315 depth5=0.447; max depth tested 5. Apple M3 Max. Single author, preprint, unreviewed; github.com/sunilp/aip
## MCP spec (github.com/modelcontextprotocol/modelcontextprotocol)
2026-07-28 EXISTS: GA release tag published 2026-07-28T16:47:49Z (RC 2026-05-29); dirs docs/specification/2026-07-28, schema/2026-07-28. Prior revs: 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25. Headers Mcp-Method (all requests), Mcp-Name (tools/call,resources/read,prompts/get), Mcp-Param-{Name} via x-mcp-header (primitive int/string/bool) EXIST, REQUIRED (SEP-2243). MRTR/InputRequiredResult(resultType input_required, inputRequests/inputResponses) EXIST (SEP-2322). Origin validation MUST->403 EXISTS. Closing SSE response stream = cancellation EXISTS.
DIFFERS: (a) x-mcp-header CR/LF prohibition applies to the annotation NAME in inputSchema; header VALUES with control chars are base64-sentinel encoded (=?base64?..?=), not rejected. (b) 2026-07-28 REMOVES Mcp-Session-Id/protocol sessions (SEP-2567), initialize handshake (SEP-2575), SSE resumability/Last-Event-ID; so 'session nonce' MCP session semantics are not in this rev. (c) HTTP+SSE deprecated in 2025-03-26 (Streamable HTTP intro) CORRECT; 'stateless refinement in 2026-07-28' CORRECT.
DONE json written
