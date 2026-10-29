# mcp-corpus: MCP listener/gateway corpus oracle (Phase-3 gate)

## What is checked

The clause ids are from `spec/SPEC_INVARIANTS.md` and ARCHITECTURE §3.9:
- INV-FAILCLOSED (F3): a reject never reaches a handler, a parse/policy error denies, and there is no fail-open.
- Admission I7: a reject is never HTTP 200.
- INV-CONFUSED-DEPUTY-NI (F10) surface: audience, session/handle binding, token passthrough, redirect credentials.
- CANON-2 on JSON-RPC bodies: duplicate/NUL/case-variant names, BOM, non-finite numbers.
- CANON-6 analogue on the listener: Host and Origin allowlists.
- The MCP 2026-07-28 header/body consistency rules (-32020, -32022).

`corpus.json` holds 44 cases:

| set | n | content |
|---|---|---|
| `advisory-33` | 33 | the r2 manifest `l5.conformance-manifest`, each with its GHSA ids |
| `spec-2026-07-28` | 10 | N01–N10 |
| `extra` | 1 | `token-passthrough`: executed in research but missing from the 43 |

Together the first two sets are the "43-case corpus". The "33 advisory cases" of the Phase-3 gate are taken to be the `advisory-33` set: it is the only 33-element set in the research.

Each case has an `executable` field:
- `yes`: 26 cases.
- `needs --subject-url2 / --subject-redir-url / --subject-multi-url / --subject-pid`: 5 cases.
- `no: <reason>`: 13 cases (client-side OAuth, Inspector-only, launcher-only, tasks extension, SSRF egress, OpenAPI backend, and h2c `:authority`, which needs an HTTP/2 client that stdlib does not have).

The research also could not execute 14 of the 33.

Every reject case asserts **HTTP 4xx AND zero upstream handler invocations**. The mock upstream counts every request it receives, whatever the method. Where the spec mandates exact values, the case checks them:
- invalid Origin → 403;
- N01–N03 → 400/-32020;
- N04 → 400/-32022 listing the supported versions;
- N06/N08 → 404/-32601;
- bad tokens → 401;
- 64 MiB body → 413.

A per-era baseline (legitimate tools/call → 200, reaches the handler) must pass, so a gateway that rejects everything fails.

## Gateway profile the subject must be configured with (`corpus.json` → `profile`)

| item | value |
|---|---|
| eras | 2025-11-25 (initialize, sessions bound to principal and route) and 2026-07-28 (stateless; `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` and `_meta` protocolVersion must agree) |
| auth | Bearer JWT HS256, test secret `aegis-oracle-test-secret-NOT-FOR-PRODUCTION`, `iss=https://issuer.oracle.test`, `aud` = the full route URL (RFC 8707) |
| Host allowlist | `127.0.0.1:PORT`, `localhost:PORT` |
| Origin allowlist | `http://127.0.0.1:PORT`, `http://localhost:PORT` |
| upstream | the oracle's mock: tool `echo(x)`; `/redir` answers 307 to a second origin; `/a` and `/b` for multiplexing |

## Usage

    oracles/mcp-corpus/run                       # no subject: in-process strict toy gateway = reference model
    oracles/mcp-corpus/run --subject http://127.0.0.1:P/mcp --upstream-port U \
        [--subject-url2 URL] [--subject-redir-url URL] [--subject-multi-url URL] [--subject-pid PID] \
        [--counter-url URL] [--flood-n N] [--wait S] [--json-out F]
    oracles/mcp-corpus/run --self-test [--verbose]

- The oracle binds its mock upstream on `--upstream-port` (127.0.0.1), and the gateway under test must forward there.
- For a server with internal handlers, use `--counter-url` instead: a GET to it must return `{"count": n}`.
- Every target must be loopback; anything else is refused.
- The last line is `MCP-CORPUS: PASS|FAIL (...)` and the exit code is 0 only on PASS.

## Subject wiring: the AEGIS agent listener (P3-agent-001)

The shipped binary serves this profile with `aegis agent --config <agent.json>` (crates/aegis-agent, wired in
crates/aegis-bin/src/agent.rs). `crates/aegis-agent/subject/mcp-gate.sh run` does the whole wiring: it starts
`aegis-pdp serve` (Cedar, out of process; policy `crates/aegis-agent/subject/mcp.cedar`) on a SOCK_SEQPACKET socket,
writes an agent config with routes `/mcp`, `/mcp2`, `/mcp-redir`, `/mcp-multi` pointing at the mock upstream port,
starts `target/release/aegis agent`, and runs this oracle with `--subject`, `--subject-url2`, `--subject-redir-url`,
`--subject-multi-url` and `--subject-pid`. `mcp-gate.sh self-test` swaps in a deny-all Cedar policy and requires the
run to fail on the baselines. Build first: `cargo build --release --locked -p aegis-bin -p aegis-pdp`.

## Pass criterion

- Both baselines pass.
- No case FAILs in any era.
- Every `executable: yes` case actually executed (not NA).

`needs-*` and `no:` cases are reported as NA with their reason. `--self-test` exits 0 only if all of these hold:
- the strict toy gateway (`toy_gateway.py`, no flaws) passes;
- the lenient toy (`no-audience-check` + `wildcard-origin` + `pass-unknown-version`) fails;
- each of the 19 single-flaw toys fails on the case expected to catch that flaw.

## Re-run in-repo (2026-10-25; about 22 s for the self-test, 10 s for the out-of-process run, so `ci/heavy.sh` was not needed)

    $ oracles/mcp-corpus/run
    MCP-CORPUS: PASS (subject=strict-toy-reference cases=44 executed=29 pass=29 fail=0 na=15 advisory-33 executed=18 pass=18 baseline=ok)

    # out of process: toy_gateway.py run standalone, oracle given --subject URL, --subject-pid, --flood-n 3000
    MCP-CORPUS: PASS (subject=http://127.0.0.1:35065/mcp cases=44 executed=31 pass=31 fail=0 na=13 advisory-33 executed=20 pass=20 baseline=ok)
    # same, standalone lenient toy (--flaws no-audience-check,wildcard-origin,pass-unknown-version), exit 1:
    MCP-CORPUS: FAIL (... executed=26 pass=21 fail=5 ... failing=['N04-unsupported-protocol-version', 'absent-origin-fail-closed', 'host-allowlist-required', 'no-wildcard-cors', 'token-wrong-audience-401'] ...)

    $ oracles/mcp-corpus/run --self-test
      strict toy gateway (must PASS)            ok  executed=29 pass=29 fail=0 na=15 fails=[] required_na=[]
      lenient toy gateway ... (must FAIL)       ok  failing=['N04-...', 'absent-origin-fail-closed', 'host-allowlist-required', 'no-wildcard-cors', 'token-wrong-audience-401']
      flaw no-audience-check                    ok  expected token-wrong-audience-401; failing=['token-wrong-audience-401']
      ... (19 single flaws, each caught by its expected case; reject-everything caught by BASELINE)
    MCP-CORPUS SELF-TEST: PASS (21/21: strict toy passes; lenient toy and 19 single-flaw toys each fail on the expected case)

## Research provenance (untrusted input: read and reviewed, nothing executed in place)

| path under `research/state/raw/` | sha256 | use |
|---|---|---|
| round-004/06-corpus/mcp_lc_corpus.py | 4ed6f2ad6839c286b6333b763d33e60d9973c2e3f2c847b9c7f1859351990919 | case logic ported (httpx → http.client) |
| round-004/06-corpus/corpus_ext.py | 07328392a225c2c081890e27d669532b3d30e83dad72c7b466b40870c0ea382e | auth/forwarding cases ported (pyjwt/RS256 → stdlib HS256) |
| round-004/06-corpus/corpus_expected.json | 26b7511053289a4c4960c212c6d874b3e271838d45ffb618695ab0b3046f6148 | the 43 case ids, bases and expected verdicts → `corpus.json` |
| round-004/06-corpus/mock_upstream.py | 4fd98b9743e27c1a7eacdcd0b054ba9fbec94a566eb2548e96fa05634432754a | ported to the in-process `mock_upstream.py` with an exact counter |
| round-004/06-corpus/gen_matrix.py | 95a234f7d121beec9ec5342161b9f2073eec037eceff5ec2eeb5e42d2692de53 | read |
| round-004/06-corpus/targets.json | e459dcafc97bc6ba948e87bae0fe8c74f52e5bbd60e4827eb19de093d7984101 | read |
| round-004/06-corpus/targets_ag.json | 008a3b2c79f9bd8fbbcd84569f0bc784fdbd64cb667f5fc3efd6faad0f29c4ba | read |
| round-004/06-corpus/targets_docker.json | 65405c768822a65c11b411f1d236ca888840fa2292472b9ecc6a5e6c21fbb71a | read |
| round-004/06-corpus/targets_docs.json | d0209f82f57dd18fc12cae67a81ff45b30ecbf776687233903827b306049ca1d | read |
| round-004/06-corpus/targets_drp.json | 7433dc52dc9ea31a321554b537f8d73a38eefdad4628f69eb81587d11c167c93 | read |
| round-004/06-corpus/targets_extra.json | 69ca5a7b864ea6fb0608b1f24fecdc4a771f2900411c3db7ef4d2455c407c627 | read |
| round-004/06-corpus/matrix.md | d5a1453d2527fd811d9be03b90b01a81b9ab54269ea4ce35cee40b60da1c42c0 | read (implementation × case matrix) |
| round-004/06-corpus/all_results.json | 6a959a62d5b63b84dc4569437d9601c352ad6336b774d9135b663bb8818075b5 | read |
| round-004/06-corpus/pass_rate_summary.json | 22961a0c109891b51da405ca79db1f3aa6e1a1ad00fcbd8f77661c56042a1fc1 | read |
| round-004/06-mcp-gateway-conformance-corpus-executed.json | 15fd23b64089fb659d8c86e547d7ce7542d7085c2f2044838174f6b4d341158c | report: 43 = r2 33 + 10 N |
| round-002/09-agent-gateway-cves-to-invariants.json | 63ca6e7eaea8b56a8b87538684adad0f953d5def476c8d6e80a27b4e83c084c0 | `l5.conformance-manifest` (33 cases with GHSA ids) |

`corpus.json` was generated once from `corpus_expected.json` and the r2 manifest (read-only), plus the porter's executability and era mapping.

## Discrepancies with the research claims

- **43 cases, confirmed with a caveat.** `corpus_expected.json` lists exactly 43 = 33 (r2 manifest) + 10 (N01–N10).
  - The research runner registers a slightly different 43: it has `token-passthrough` but not `openapi-traversal`. The union is 44, and all 44 are carried here.
  - The research runner also needs `httpx`, `h2`, `pyjwt` and `cryptography`.
- **"Executed against 5 implementations"**: the matrix covers 5 projects in 14 configurations / 24 target×era columns:
  - python-sdk 2.3.0/1.30.0
  - typescript server 2.4.0 / sdk 1.32.2
  - rmcp 3.7.0
  - agentgateway 1.6.0
  - docker mcp-gateway 0.44.2

  Only 19 of the 33 advisory cases executed on at least one target.
- **"33 advisory cases" (Phase-3 gate)**: the research never defines this set. It is interpreted here as the 33 r2 manifest cases. Of those, 15 execute with a bare `--subject`, 18 with `--subject-url2/--subject-redir-url/--subject-multi-url` (as in the reference run), and 20 with `--subject-pid` as well. The other 13 are not black-box testable at a gateway.
- **The expected statuses are partly research proposals, not spec text.** The r2 manifest's own overclaim note says only Origin→403 and -32020/400 are spec-mandated. N01 and N04 accept the same alternative codes the research accepted (-32001, -32004).
- **The token profile is weaker than research.** Research used RS256 plus an HS256-with-public-key alg-confusion token. Stdlib has no RSA signing, so the alg-confusion row is replaced by `alg=HS512`, `wrong-key`, `alg=none` and tampered-signature rows.

## Known limits

- **`host-allowlist-required;h2-authority` is not executed.** It needs an h2c client. Pending: a Rust probe under this dir via `ci/heavy.sh`, or a hand-rolled HPACK client.
- **`session-table-bound` and `cache-bound` are crude.** They use RSS growth (< 15 MB, the research threshold), only with `--subject-pid`. They do not run in the in-process self-test, but they were exercised out-of-process with N=3000. 25 of 3000 flood requests got client-side connection errors under 50-way concurrency; that does not affect the verdict.
- **The toy gateway exists only to show the oracle is satisfiable and red-able.** It is not AEGIS and not evidence about any product.
- The official MCP conformance suite is not used: research `l4.conformance-suite-gap-origin-only` shows it is not evidence.
