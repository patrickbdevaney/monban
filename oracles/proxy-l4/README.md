# proxy-l4: PROXY v2 + L4 SNI passthrough oracle (unit P7-oracle-proxy-001)

Black-box oracle for the Phase 7 `proxy-protocol` and `l4` features of `aegis` (gate `proxy-l4`, implementers
P7-wire-001 and P7-bin-001). It checks F1 PROXY-1..3 and L4-1..2 (PLAN-7 "Interfaces", PREFLIGHT D-P7.2) end to end
against stdlib-Python upstreams. It also ships the parser-level vector sets and the shared ClientHello builder.

```
oracles/proxy-l4/run --binary target/release/aegis [-v|-vv]   # binary built with --features proxy-protocol,l4
oracles/proxy-l4/run --self-test [--jobs 4]
```

`run` execs `python3 -I oracle.py` from the repo root. The last line is `PROXY-L4: PASS (...)` or
`PROXY-L4: FAIL (...)`, and the exit code is 0 only on PASS. Self-test prints `PROXY-L4 SELF-TEST: PASS|FAIL (...)`.
`--subject` is an alias of `--binary`; `default-subject` is `target/release/aegis`. Needs: python3 ≥ 3.10, the
`openssl` CLI (mints three throwaway ECDSA P-256 certificates and runs one `s_client`), and Linux loopback, where
any 127.0.0.0/8 address can be a source. `::1` is optional: without it the IPv6 checks are skipped and the PASS
line says so. The oracle runs on the desktop (`ci/remote.sh`). One run takes about 30 s, the self-test about 2 min.
It only signals explicit child PIDs.

## Subject contract

Same as oracles/proxy-e2e:
- `<binary> --config <file.json> --cert <pem> --key <pem> --audit-dir <dir>`
- readiness: `GET /healthz` = 200 on `admin.bind`
- stop: SIGTERM. Audit events must be on disk (tlog-tiles entry bundles under `<audit-dir>/**/tile/entries/`) once
  the process has exited.
- exit 78 on a config it refuses, without ever accepting a connection.

### The exact F8 config the binary must accept

These are the PLAN-7 F8 additions `listener.proxy_protocol = { trusted = [CIDR...] }` and
`listener.l4 = [{ sni, upstream }]`. Ports are fresh per run (`P_*`). The config is written as JSON, which the F8
loader already reads:

```json
{
 "v": 1,
 "listeners": [
  {"name": "pub",   "bind": "127.0.0.1:P_PUB",   "profile": "P-PUBLIC-WEB", "alpn": ["http/1.1"],
   "proxy_protocol": {"trusted": ["127.0.0.2/32", "127.0.1.0/24"]}},
  {"name": "plain", "bind": "127.0.0.1:P_PLAIN", "profile": "P-PUBLIC-WEB", "alpn": ["http/1.1"]},
  {"name": "l4",    "bind": "127.0.0.1:P_L4",    "profile": "P-PUBLIC-WEB",
   "l4": [{"sni": "a.l4.test", "upstream": "127.0.0.1:P_UA"}, {"sni": "b.l4.test", "upstream": "127.0.0.1:P_UB"}]},
  {"name": "l4p",   "bind": "127.0.0.1:P_L4P",   "profile": "P-PUBLIC-WEB",
   "proxy_protocol": {"trusted": ["127.0.0.2/32"]},
   "l4": [{"sni": "a.l4.test", "upstream": "127.0.0.1:P_UA"}, {"sni": "b.l4.test", "upstream": "127.0.0.1:P_UB"}]},
  {"name": "pub6",  "bind": "[::1]:P_PUB6",      "profile": "P-PUBLIC-WEB", "alpn": ["http/1.1"],
   "proxy_protocol": {"trusted": ["::1/128"]}}
 ],
 "admin": {"bind": "127.0.0.1:P_ADMIN"},
 "vhosts": [{"host": "aegis.test", "routes": [
   {"id": 1, "path": "/api/", "to": {"upstream": "127.0.0.1:P_REC"}, "authz": "allow-all"}]}]
}
```

- `pub6` is present only when the host has `::1`.
- L4 listeners carry `profile` because F8 v1 makes it required. An L4 listener terminates no TLS, so it ignores the
  profile. If P7-spec-001 freezes `profile` as forbidden on L4 listeners, the two `l4` entries in `Run.config` lose
  that key: a one-line change, not a weakening.
- `listener.front` and `tls.credentials` are not used here (front-equiv, cred-select).

Configs the binary must **refuse with exit 78**, each the config above with one change and never accepting a
connection:

| variant | change |
|---|---|
| `cidr-prefix-33` | `trusted = ["127.0.0.0/33"]` |
| `cidr-garbage` | `trusted = ["localhost"]` |
| `l4-duplicate-sni` | the second l4 route's sni = `A.L4.TEST`, a case-insensitive duplicate of `a.l4.test` |
| `l4-bad-upstream` | upstream `no-port` |
| `l4-and-alpn` | `alpn` on an L4 listener ("a listener is either L4 or HTTP, never both") |

### Audit events (how admission and audit "see the PROXY source address")

Each event is an F9 event with `outcome = "allow"`. Other actions are ignored. The oracle compares the multiset of
these events with what it caused, exactly:

| action | when | `object` | `detail` |
|---|---|---|---|
| `proxy.accept` | once per connection whose PROXY header was admitted (PROXY-1 passed, header valid), when it is admitted, whatever happens next | listener name | `peer` = the address used for admission, audit and rate limits (PROXY-2); `via` = the TCP peer address |
| `l4.route` | once per L4 connection forwarded to an upstream | listener name | `sni` (compared case-insensitively), `upstream` = the configured `host:port`, `peer` (as above) |

IP strings are compared after `ipaddress` normalisation, so Rust's `Display` of `IpAddr` matches. No `proxy.accept`
and no `l4.route` may exist for a refused connection. Refusals themselves are not required in the audit log: they
can be driven by an attacker.

## Receiver rules this oracle encodes

### PROXY v2 acceptance rules

Source: haproxy proxy-protocol.txt §2.2, plus the PLAN-7 limits. Where the spec leaves a choice, the rule below is
the fail-closed one.

1. **Trust (PROXY-1):** a listener with `proxy_protocol` decides trust on the TCP peer address only, never on
   anything in the header.
   - From an **untrusted** source, a first byte sequence that could begin a PROXY header (a prefix of the v2
     signature, or of `PROXY`) → close, with no byte sent back, before any byte is read as TLS or HTTP. Anything
     else is served directly, with peer = TCP peer.
   - From a **trusted** source, the header is **required**. Without it → close ("never auto-detected", spec §1:
     the receiver "MUST not try to guess").
2. **v1 is refused (PROXY-3):** `PROXY ...` → close.
3. **Version, command and family:** version nibble ≠ 2 → close. Command ∉ {LOCAL 0, PROXY 1} → close. Family nibble
   > 3 or protocol nibble > 2 → close. This applies to LOCAL too.
4. **Declared length (PROXY-3):** `len` > 536 → close, without waiting for the bytes.
5. **Partial header:** a partial header that never completes (EOF, or the read deadline) → close. Consumed =
   exactly 16 + `len`. Bytes after that belong to TLS or L4 and are never re-parsed, even if they look like a
   signature.
6. **LOCAL:** accepted. Peer = TCP peer. The whole block (address family, addresses, TLVs) is discarded unparsed
   (spec: "discard the protocol block including the family").
7. **PROXY with an UNSPEC family or protocol:** accepted. Peer = TCP peer. The block is skipped.
8. **PROXY with INET (12 bytes), INET6 (36) or UNIX (216):** `len` below the address size → close.
   - TCP4/TCP6: peer = the source address.
   - UNIX stream: accepted, peer = TCP peer.
   - DGRAM (UDP4, UDP6, UNIX dgram) announced on a stream listener → close (policy).
9. **TLVs after the address block:** they must tile the rest exactly, else close.
   - `CRC32C` (0x03): length must be 4. It must appear at most once. It must match the CRC32c of the whole header
     with the field zeroed (RFC 4960 App. B).
   - `UNIQUE_ID` (0x05): ≤ 128 bytes.
   - `AUTHORITY` (0x02): valid UTF-8.
   - `SSL` (0x20): at least 5 bytes (client u8, verify u32), and its sub-TLVs must tile the rest exactly.
   - `ALPN`, `NOOP`, `NETNS`, the custom, experimental and future ranges, and unassigned types: ignored.
10. **Deadline:** the header must arrive within the read deadline (bound checked: ≤ 20 s), or close.

### ClientHello peek rules

L4-1 and L4-2. These are also the peek that cred-select reads `trust_anchors` from (D-P7.4).

1. The first record must be a handshake record (type 0x16) with record version 0x0301, 0x0302 or 0x0303, and length
   1..16384. Anything else → close. A request line (`GET `, `CONNECT `, the h2 preface) fails here, so L4 bytes
   are never parsed as HTTP (L4-2): no HTTP response and no upstream connection.
2. Exactly one record holds exactly one complete ClientHello (handshake type 1).
   - A ClientHello that continues into a second record → close (L4-1: at most one record).
   - Bytes after the hello inside its record → close.
   - Records after the first are not parsed; they are forwarded.
3. The hello body is checked in this order:
   - legacy_version, random;
   - session_id ≤ 32;
   - cipher_suites even and non-empty;
   - compression non-empty;
   - extensions exactly fill the body. A missing extensions block is allowed.
4. Extensions:
   - A duplicate extension type → close.
   - `server_name`: a non-empty list. Exactly one entry, of name_type 0 (host_name), as a valid LDH DNS name: no
     trailing dot, labels ≤ 63, total ≤ 253, ASCII only. Anything else → close.
   - `alpn`, `supported_versions`, `signature_algorithms`, `supported_groups` and `trust_anchors` must be
     well-formed per their RFCs.
   - `trust_anchors` (draft-ietf-tls-trust-anchor-ids-07 §5.1) is a `RequestedTrustAnchorList<0..2^16-1>` of
     `TrustAnchorID<1..32>`, at codepoint **0xCA34** (see "ClientHello builder" below). The same bytes at any other
     codepoint are an unknown extension and are ignored.
5. Routing: the SNI is matched against the configured `l4[].sni` case-insensitively and exactly (no suffix or
   wildcard). An unknown SNI or no SNI → close, never a default upstream (L4-1).
6. Forwarding: the upstream receives the client's bytes byte-exact, starting with the ClientHello record. A PROXY
   header in front is never forwarded.
7. Deadline: the whole record must arrive within the stall deadline, counted from accept, not per read: a dribbling
   client is closed too. The bound checked is ≤ 20 s.

## What is checked

| check (name prefix) | clause | how |
|---|---|---|
| `vectors.generated` | – | `gen_vectors.py --check`: the committed vector files equal the generator output. |
| `vectors.reference-*` | – | the reference parsers agree with every vector (0 divergences). |
| `vectors.hostile-count` | acceptance | at least 200 hostile PROXY headers. There are 205: 201 malformed + 4 policy. |
| `proxy.vector.<id>` (spec, trailing, policy) | PROXY-2/3 | Every §2.2 vector is sent from trusted 127.0.0.2, coalesced in one send with a real TLS ClientHello (python ssl over MemoryBIO), followed by `GET /api/v/<id>`. The vectors cover TCP4, TCP6, UNIX, LOCAL, UNSPEC, every registered TLV, CRC32C (first and last position), SSL with every subtype, NETNS, the custom/experimental/future ranges, and len = 536. Expected: 200 + the upstream saw the request + `proxy.accept` with the right `peer`. DGRAM vectors must close. |
| `proxy.hostile.<id>` (201) | PROXY-3 | Each malformed header, followed by a ClientHello so that a lenient parser would answer it (incomplete ones are half-closed instead). Expected: closed, 0 bytes back. Covers: signature flips; v1 forms; version, command, family and protocol nibbles; len 537/538/600/1024/4096/65535; short address blocks for every family; partial headers; truncated TLVs; bad, unzeroed, wrong-length and duplicate CRC32C; UNIQUE_ID > 128; short SSL and bad SSL sub-TLVs; non-UTF-8 AUTHORITY; a bare TLS or HTTP first flight. |
| `matrix.<src>.*` | PROXY-1, PROXY-2 | Sources 127.0.0.1, .0.2, .0.3, 127.0.1.1, 127.0.1.254, 127.0.2.1 and 127.1.0.1 against `trusted = [127.0.0.2/32, 127.0.1.0/24]`. **Trusted:** a header → 200 and `peer` = header source; no header → closed, 0 bytes. **Untrusted:** a header → closed, 0 bytes, upstream untouched; no header → 200; a header claiming a trusted address (127.0.0.2) → closed; LOCAL → closed; v1 → closed. |
| `plain.*` | F8 "absent = today" | A listener without `proxy_protocol` does not interpret a header (no successful exchange); direct TLS → 200. |
| `v6.*` | PROXY-1/2 | `[::1]` listener trusting `::1/128`: TCP6 and TCP4 headers → `peer` = header source, `via` = `::1`. |
| `l4.python.{a,b,case}.*` | L4 routing | python ssl client, SNI a / b / `A.L4.TEST`, verifying the upstream's own certificate. The tagged echo proves which upstream answered; the upstream's raw byte stream equals the client's (`byte-exact`). |
| `l4.openssl.b.routed` | L4 routing | `openssl s_client -servername b.l4.test -verify_return_error` → `B:` echo. |
| `l4.{unknown,no,suffix}-sni.closed` | L4-1 | SNI `c.l4.test`, no SNI, and `x.a.l4.test` → 0 bytes back. |
| `l4.{http-get,http-connect,h2-preface}.*` | L4-2 | request lines, half-closed and held open → closed, 0 bytes, no upstream. |
| `l4.vector.<id>` (84) | L4-1, L4-2, peek rules | Each ClientHello vector sent raw. Routed ones must reach the right upstream byte-exact (the 16384-byte record, an ML-KEM share, trust_anchors, mixed-case SNI, a trailing second record). Hostile ones must close with 0 bytes: fragmented across records, record > 16384, wrong content type or version, bad SNI forms, duplicate extensions, malformed trust_anchors, ... |
| `l4p.*` | PROXY over L4 | Trusted header (with CRC32C) + TLS SNI a → `A:` echo. The upstream receives exactly the TLS bytes, header stripped. Events: `proxy.accept` and `l4.route` with `peer` = header source. Also: trusted LOCAL → routed, peer = TCP peer; untrusted header → closed and no upstream; untrusted direct → routed with peer = TCP peer; trusted with no header → closed; trusted header + HTTP, + unknown SNI, or v1 → closed; refusals reach no upstream. |
| `stall.*` | L4-1 deadline, rule 10 | A partial record held open; a record dribbled 1 byte / 0.5 s; a partial PROXY signature; a header followed by a partial record. Each must close with 0 bytes within 20 s of the first byte. |
| `upstream.{a,b}.connections` | L4-1 | Each upstream's connection count equals the number of routed connections exactly, so refused traffic reached no upstream. |
| `audit.*` | PROXY-2, audit | The audit multiset equals the expected one (see "Audit events"). |
| `boot.<variant>.exit-78` | fail-closed config | the five refused configs above. |

**PASS** iff every check passes.

## Vector sets (for P7-wire-001 at parser level)

- `vectors/proxy_v2.json`: 242 vectors (34 spec, 3 trailing, 4 policy, 201 hostile).
- `vectors/client_hello.json`: 84 vectors (23 valid, 61 hostile).
- Both are generated by `gen_vectors.py`, which is deterministic. Expectations are written by construction, not by
  running a parser. One JSON object per line.

PROXY vector fields:
- `id`, `group`, `hex`;
- `expect` ∈ `ok` | `reject` | `incomplete`;
- `class`, the reject reason (informational for Rust; the reference must match it);
- for `ok` vectors: `consumed`, `command` (local/proxy), `family` (unspec/inet/inet6/unix), `proto`
  (unspec/stream/dgram), `src`/`dst` (IP text, or hex for UNIX paths), `src_port`/`dst_port`, `peer` (`src` |
  `transport`), `stream_accept`, and `tlvs` (`[[type, value-hex], ...]`, top level, in order);
- `listener` (`accept` | `close`).

Mapping to `aegis_wire::proxy::parse_v2(&[u8]) -> Result<(Header, consumed)>`:
- `ok` → Ok, with these fields and `consumed`.
- `incomplete` → the need-more-bytes result.
- `reject` → Err.
- `stream_accept=false` (DGRAM) parses Ok. The refusal is policy, in aegis-bin.

ClientHello vector fields:
- `expect`, `class`;
- for `ok` vectors: `sni` (as sent; null if absent), `alpn` (hex list), `versions`, `sigalgs`, `groups`,
  `trust_anchors` (null = extension absent, [] = empty list, else hex IDs), `consumed` (= 5 + record length);
- `route` (`a` | `b` | `close`, for the routes `a.l4.test` / `b.l4.test`).

These map onto `aegis_wire::tls_peek::client_hello` in the same way. A Rust test reads the JSON (for example with
`include_str!` in a test-only module); the data is not code. `python3 -I oracles/proxy-l4/vectors_check.py` runs
the reference parsers over both files.

## ClientHello builder (shared with oracles/cred-select)

The builder lives in `oracles/proxy-l4/clienthello.py`, stdlib only:
- `build(sni, alpn, versions, sigalgs, groups, key_shares, trust_anchors, ta_codepoint, extra, order, padding_to,
  raw_exts, seed, ...)` returns a ClientHello handshake message.
- `record()` and `records()` frame it as one record, or fragment it across several.
- `peek()` is the reference peek parser, and `PeekError` / `PeekIncomplete` are its errors.
- `TRUST_ANCHORS_EXT = 0xCA34`.

Usage:
```python
sys.path.insert(0, os.path.join(REPO, "oracles", "proxy-l4"))   # python3 -I does not add the script dir
import clienthello as ch
rec = ch.record(ch.build(sni="mtc.example", sigalgs=[0x0403], trust_anchors=[bytes.fromhex("81fd5901")]))
```

**trust_anchors codepoint:**
- draft-ietf-tls-trust-anchor-ids-07 §5.1 / §12.1 says `trust_anchors(TBD)`.
- The IANA TLS ExtensionType registry has no entry (tls-extensiontype-values-1.csv, checked 2026-11-06).
- The deployed experimental value is **0xCA34**: BoringSSL `include/openssl/tls1.h` `#define
  TLSEXT_TYPE_trust_anchors 0xca34` ("not an IANA defined extension number", crbug 398275713); boringssl main
  b69a6175, file sha256 56615a88...cc1.
- The value is one constant here and a parameter (`ta_codepoint=`) of `build()`.

## Self-test (negative controls)

`--self-test` runs four kinds of check.

1. **Reference parsers vs the vector sets:** 0 divergences.
2. **Vector mutants:** each must diverge.

   | mutant | defect | divergences |
   |---|---|---|
   | `proxy-v1-accept` | v1 parsed | 5 |
   | `proxy-len-537` | limit raised to 1024 | 6 |
   | `proxy-crc-skip` | CRC32C not verified | 10 |
   | `proxy-tlv-lenient` | truncated TLVs ignored | 16 |
   | `proxy-local-header-peer` | LOCAL uses the header address | 2 |
   | `ch-ta-codepoint` | trust_anchors read from 0xCA35 | 10 |

3. **Reference subject:** `ref_server.py` must PASS the full e2e run. It is a stdlib server implementing the
   contract above with the same reference parsers.
4. **e2e mutants:** each is planted in `ref_server.py` with `AEGIS_PROXY_L4_REF_MUTANT`, runs in a child process
   (4 in parallel), and must FAIL.

   | mutant | defect | clause | caught by (2026-11-06 run) |
   |---|---|---|---|
   | `proxy-untrusted-accept` | an untrusted source's header is accepted | PROXY-1 | 16 checks: `matrix.*.proxy-refused`, `l4p.untrusted-header.refused`, audit |
   | `proxy-trust-by-header` | trust decided on the header source, not the TCP peer | PROXY-2 | 5 checks: `matrix.*.trusted-src-claim-refused` |
   | `proxy-local-header-peer` | LOCAL takes the peer from the address block | PROXY-2 | `audit.proxy-and-l4-events` |
   | `proxy-v1-accept` | v1 accepted | PROXY-3 | 7 checks: `proxy.hostile.h-v1-*`, `l4p.trusted-v1` |
   | `proxy-len-537` | declared length up to 1024 accepted | PROXY-3 | 6 checks: `proxy.hostile.h-len-537-full`, ... |
   | `proxy-crc-skip` | CRC32C not verified | PROXY-3 | 11 checks: `proxy.hostile.h-crc-*` |
   | `proxy-tlv-lenient` | truncated TLV area ignored | PROXY-3 | 17 checks: `proxy.hostile.h-tlv-*` |
   | `proxy-autodetect` | a trusted source without a header is served directly | D-P7.2 "never auto-detected" | 7 checks: `matrix.*.no-header-refused`, `l4p.trusted-no-header.refused` |
   | `l4-default-upstream` | unknown or no SNI goes to the first upstream | L4-1 | 11 checks: `l4.unknown-sni.closed`, `l4.no-sni.closed`, ... |
   | `l4-http-parse` | a request line on an L4 listener gets `HTTP/1.1 400` | L4-2 | 8 checks: `l4.http-get.not-http`, ... |
   | `l4-multi-record` | a ClientHello reassembled across records | L4-1 | `l4.vector.ch-h-fragmented-50`, upstream count, audit |
   | `l4-no-stall-deadline` | no deadline on the ClientHello read | L4-1 | `stall.l4.partial-record`, `stall.l4.dribble`, `stall.l4p.after-header` |
   | `l4-forward-proxy-header` | the PROXY header is forwarded to the L4 upstream | PROXY over L4 | `l4p.trusted.routed`, `l4p.trusted-local.routed`, upstream counts |

## Provenance

The oracle was written for this unit. No research artifact was ported. Sources were fetched 2026-11-06 with
`User-Agent: aegis-ci`:
- `https://www.haproxy.org/download/3.2/doc/proxy-protocol.txt`, sha256
  `66be61883fcad0dafc27af8c73c5c4d9aba6e43039ffe35fd72cf4d07266c98d` (§2.2, §2.2.1-§2.2.8).
- `https://www.ietf.org/archive/id/draft-ietf-tls-trust-anchor-ids-07.txt`, sha256
  `624df5bf7afc1c950fc0c5489c5bc5ffdef8c30488efb108c6c9d10b434caaaf` (§4, §5.1).
- `https://raw.githubusercontent.com/google/boringssl/main/include/openssl/tls1.h`, sha256
  `56615a8877a7af97a6411a55555664c9589baf907747bedaf03a1d49b8b90cc1` (the 0xCA34 codepoint).
- IANA `tls-extensiontype-values-1.csv`: no trust_anchors entry.

The CRC32C implementation is checked at import against the RFC 3720 check value (`123456789` → `0xE3069283`).

## In-repo runs (2026-11-06, desktop via ci/remote.sh)

- `run --self-test` → `PROXY-L4 SELF-TEST: PASS (13/13 e2e mutants, 6/6 vector mutants caught; reference PASS)`.
  The reference subject scored `PROXY-L4: PASS (399 checks; 242 PROXY vectors incl. 205 hostile, 84 ClientHello
  vectors)`.
- Red today:
  - The gate command's build step fails: `error: the package 'aegis-bin' does not contain these features: l4,
    proxy-protocol`.
  - The oracle against today's default release build gives `PROXY-L4: FAIL (1 failed, 0 passed: harness: subject
    exited 78 at start: ... config error at "/listeners/0/proxy_protocol": UnknownField ...)`.

## Known limits

- **Admission:** it is observed only through the audit `peer` field. The provisional admission limits (burst 2000
  per IP) are far above what a test client can reach without flooding, so a reject keyed on the PROXY source is not
  driven.
- **The deadline is bounded, not pinned:** any value ≤ 20 s passes. PLAN-7 fixes no number.
- **IPv4-mapped sources and trusted CIDRs:** whether a `::ffff:a.b.c.d` TCP peer matches a v4 CIDR is not
  exercised. The listeners bind one family each.
- **Live L4 sessions:** the splice idle timeout on an established L4 session is not exercised (P7-bin-001's
  acceptance names it; this oracle covers only the pre-routing deadline).
- **UNIX vectors:** UNIX-family PROXY headers are checked at the parser level and e2e (peer = TCP peer). There is
  no UNIX-socket listener.
- **Reject classes:** they are informational for the Rust parser. Only ok, reject and incomplete, plus the fields,
  bind it.
