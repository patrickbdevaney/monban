# P7-oracle-proxy-001 report (spec author, 2026-11-06, base 00ca246)

**Status: done.** `oracles/proxy-l4` exists:
- Its self-test is green: 13/13 e2e mutants and 6/6 vector mutants are caught, and the reference subject PASSes.
- It is red on today's tree: aegis-bin has no `proxy-protocol` or `l4` feature, and the default binary refuses the
  F8 additions with exit 78.

## Deliverables

| path | what |
|---|---|
| `oracles/proxy-l4/run`, `oracle.py` | Gate entry point: `run --binary target/release/aegis` and `run --self-test`. |
| `oracles/proxy-l4/proxyv2.py` | PROXY v2 encoder, CRC32C, and the reference parser for the receiver rules in the README. |
| `oracles/proxy-l4/clienthello.py` | The shared ClientHello builder, with trust_anchors per draft-07 at 0xCA34, plus the reference peek parser. oracles/cred-select imports it via `sys.path.insert(0, "<repo>/oracles/proxy-l4")`. |
| `oracles/proxy-l4/vectors/proxy_v2.json` | 242 vectors: 34 spec, 3 trailing, 4 policy, 201 hostile. |
| `oracles/proxy-l4/vectors/client_hello.json` | 84 vectors: 23 valid, 61 hostile. |
| `oracles/proxy-l4/gen_vectors.py`, `vectors_check.py` | Deterministic generator (`--check` detects drift), and the reference parsers run over the vectors. |
| `oracles/proxy-l4/ref_server.py`, `tlsbio.py` | Reference subject and its 13 planted mutants; MemoryBIO TLS helper. |
| `oracles/proxy-l4/README.md` | The exact F8 config, the configs that must be refused (exit 78), the audit event contract, the receiver rules, the checks, the vector schema mapped to aegis_wire, and provenance. |

## Contract decisions P7-bin-001 must meet

Each is written down in the README. They follow PLAN-7 and D-P7.2; where the spec leaves a choice, I picked the
fail-closed option.

1. **A trusted source must send a header** (never auto-detected). An untrusted source whose first bytes could begin
   a PROXY header is closed with no bytes sent back. An untrusted source without a header is served directly.
2. **Audit events `proxy.accept`** (detail `peer`, `via`) and **`l4.route`** (detail `sni`, `upstream`, `peer`), each
   with outcome allow and object = the listener name.
   - `proxy.accept` is emitted when the header is admitted, even if the L4 layer refuses later.
   - This is how "admission/audit see the PROXY source address" is observed.
3. **Policy refusals:** DGRAM families are refused on a stream listener. UNIX, UNSPEC and LOCAL use the TCP peer.
   LOCAL discards its block unparsed. Invalid family or protocol nibbles are refused even with LOCAL.
4. **Peek and routing:**
   - The ClientHello must sit in exactly one record, with nothing trailing inside that record.
   - SNI must be one host_name and a valid LDH name.
   - Duplicate extensions are refused.
   - SNI matching is case-insensitive and exact.
5. **Deadlines:** the read deadline for the PROXY header and for the ClientHello runs from accept, not per read.
   The bound checked is ≤ 20 s.
6. **Configs refused with exit 78:**
   - CIDR `/33`;
   - a non-IP CIDR;
   - an L4 SNI that is a case-insensitive duplicate;
   - an upstream without a port;
   - `l4` together with `alpn`.
7. **`profile` stays on L4 listeners** because F8 v1 requires it. If P7-spec-001 forbids it there, the oracle needs
   a one-line config edit, which is not a weakening.

## Runs (desktop, ci/remote.sh)

- `ci/remote.sh oracles/proxy-l4/run --self-test` → `PROXY-L4 SELF-TEST: PASS (13/13 e2e mutants, 6/6 vector mutants
  caught; reference PASS)`. The reference scored `PROXY-L4: PASS (399 checks; 242 PROXY vectors incl. 205 hostile, 84
  ClientHello vectors)`.
- Red evidence:
  - `ci/heavy.sh cargo build --release --locked -q -p aegis-bin --features proxy-protocol,l4` exits 101 with
    `error: the package 'aegis-bin' does not contain these features: l4, proxy-protocol`.
  - On the default release build, `oracles/proxy-l4/run --binary target/release/aegis` gives
    `PROXY-L4: FAIL (1 failed, 0 passed: harness: subject exited 78 at start: ... config error at
    "/listeners/0/proxy_protocol": UnknownField ...)`.

## Limits

These are listed in full in the README:
- admission is observed only through the audit `peer` field;
- the deadline value is bounded, not pinned;
- IPv4-mapped peers against v4 CIDRs are not exercised;
- the splice idle timeout after routing is not exercised;
- reject classes are informational for the Rust parser.
