# ssrf-corpus: SSRF-CORPUS oracle for the egress guard (unit P3-egress-001)

## What is checked

`spec/SPEC_INVARIANTS.md` has no egress clause yet. The spec references come from the unit and from ARCHITECTURE:
§3.3 (webhooks "egress guard"), §3.6 (narrow fetch host function, never wasi-http), and §3.9 / R-AGENT-4..7
("resolved-address egress"). The oracle also exercises `INV-FAILCLOSED` in the egress sense: if any check fails,
the fetch is refused. It is never repaired.

The subject is given a URL, scripted DNS answers and an allowlist policy. It must vet the request and report what
it would connect to. It never opens a real socket, except in live cases, where it fetches from a loopback server
that the harness starts. **PASS** requires all of the following:
1. **No forbidden connects.** No connect goes to an address the independent judge (`netclass.py`, written from the
   IANA special-purpose registries) forbids for that case. Re-admission is allowed only for loopback, RFC 1918,
   CGNAT and ULA prefixes, and only those the case's `readmit` lists.
2. **Every connect is derivable.** Each connect address is either a first-query DNS answer for some case host, or a
   strict literal (canonical dotted quad, or bracketed IPv6) appearing in the case URL or one of its redirect
   `Location`s. This catches lenient IPv4 parsers (`010.010.010.010` → 8.8.8.8) and dialers that re-resolve the
   name.
3. **At most one DNS query per hop:** total queries ≤ connects, or connects + 1 when the fetch ended in a reject.
   The rebinding cases answer the second query with a private address. A subject that asks twice gets caught here,
   and also by check 1 when it dials that answer.
4. **Expected decisions.** Every `connect` case (the 47 positive controls) connects, to `expect_addr` where one is
   given. Every `reject` case does not connect.
5. **Live cases.** The loopback server saw exactly `server_hits` requests, and the `Host` header was the original
   name (for example `svc.test:PORT`), not the dialled IP.

Corpus (`corpus.py`, 273 cases; `run --list` prints them):
- Forbidden answers via DNS: 33 IPv4 and 40 IPv6. The IPv4 set covers this-network, RFC 1918, CGNAT, loopback,
  link-local, metadata (169.254.169.254, 169.254.170.2, 100.100.100.200), IETF, documentation, benchmarking,
  6to4-relay, multicast, reserved and broadcast. The IPv6 set covers unspecified, loopback, IPv4-mapped,
  IPv4-compatible, NAT64 `64:ff9b::/96` with a forbidden embedded address, local-use NAT64 `64:ff9b:1::/48`, 6to4
  `2002::/16` with a forbidden embedded address, Teredo, documentation (`2001:db8::/32`, `3fff::/20`),
  benchmarking, ORCHID, discard, ULA, `fd00:ec2::254`, link-local, site-local, multicast, SRv6 and non-`2000::/3`.
- Literals:
  - 13 IPv4 and 10 IPv6 forbidden literals, each allowlisted by its literal text.
  - 4 zone-id forms.
  - 23 non-canonical IPv4 forms (22 plus one 5-label form): octal, hex, decimal, short and leading-zero.
- DNS rebinding: 7 cases where the first answer is public and the second is private or metadata. Also 6 mixed answer
  sets, where every answer must be vetted, plus NXDOMAIN and an empty answer.
- Redirects: 27 cases to forbidden or invalid targets, including 301/302/303/307/308 to private and metadata
  targets, scheme-relative, `file:`, `gopher:`, `javascript:`, userinfo, port, and `http:evil` locations. The rest
  cover:
  - same-origin and relative redirects;
  - cross-origin, denied and allowed;
  - chains;
  - the hop limit (3 hops pass with max 3, 4 fail), loops and max 0;
  - https→http downgrade (refused) and http→https upgrade;
  - a redirect to a rebinding host.
- Authority tricks: userinfo, `%40`, backslash, `?@`, `#@`. Hosts: trailing dots, empty labels, `_`, `%2e`,
  non-ASCII, leading `-`, bracketed names, and uppercase forms.
- Ports: default, allowlisted and not allowlisted, plus `0`, `65536`, `080`, `+80`, `80:80`, empty, `-1`, `99999`,
  `8o`, `0x50` and space.
- Allowlist: exact and suffix rules, apex, lookalike, and a private answer behind an allowed suffix. Schemes:
  `ftp`, `file`, `gopher`, `dict`, `ldap`, `javascript`, `data`, `ws`, `jar`, and http when it is not allowed.
- Positive controls: public IPv4 and IPv6, edge-of-range public addresses, NAT64 and 6to4 embedding a public
  address, and public literals. Readmit cases: private with a matching prefix connects; the wrong prefix,
  metadata, an IPv4-mapped address and link-local are never re-admitted.
- Live (10 cases): an OK fetch, an uppercase host, an IP literal, rebinding, a same-origin redirect, redirects to a
  private address and to metadata, no readmit (0 server hits), a size cap (`max_bytes` 1000 against a 200 kB body)
  and a deadline (300 ms against a 2 s handler).

## Subject protocol (JSON lines over stdin/stdout)

Case → subject (fields the subject does not know are ignored):

    {"id", "url", "dns": {host: [[addr, ...], ...]}, "allow_hosts": ["a.test", "*.wild.test", "8.8.8.8"],
     "allow_ports": [..], "allow_http": true, "readmit": ["127.0.0.1/32"], "max_redirects": 3,
     "cross_origin": false, "redirects": {"<hop url>": [302, "<location>"]}, "live": false,
     "deadline_ms": n, "max_bytes": n}

- The i-th query for a host gets the i-th answer set; the last set repeats.
- Hop URLs are serialized as `scheme://host[:port]path?query`: lowercase, IPv6 bracketed, default port omitted,
  fragment dropped.
- A hop with no `redirects` entry answers 200.

Subject → harness:

    {"id", "decision": "connect", "addr": "ip:port", "status": 200, "connects": [..], "queries": {host: n}}
    {"id", "reject": "<code>", "detail": "...", "connects": [..], "queries": {host: n}}

Reject codes are informational. Only the decision is judged.

## Subjects

- `default-subject`: `target/release/egress-subject` (`subjects/egress-subject`, monban-egress built without
  `tls-client`). In simulated cases its scripted connector records the vetted address egress hands it and does not
  dial. In live cases it uses the real `NetConnector` and reports every vetted address passed to it as a connect,
  before dialling.
- With no `--subject`, the oracle runs `ref_subject.py`, the Python reference.

## Self-test (`run --self-test`)

The reference must PASS and each mutant (`ref_subject.py --mutant X`) must FAIL:

| mutant | broken rule | caught by |
|---|---|---|
| `hostname` | connects by hostname (re-resolves at dial time) | forbidden + non-derivable connects, 2 queries per hop |
| `no-mapped` | IPv4-mapped/compatible treated as public | forbidden connect (`::ffff:127.0.0.1`, ...) |
| `redirect-no-revet` | follows redirects without vetting the new hop | forbidden connect (10.0.0.1, 169.254.169.254) |
| `octal` | `inet_aton` IPv4 literals | non-derivable connect (`010.010.010.010` → 8.8.8.8) |
| `first-only` | vets only the first DNS answer | mixed-answer cases connect |
| `no-embedded` | NAT64/6to4/Teredo not unwrapped | forbidden connect (`64:ff9b::7f00:1`, ...) |
| `downgrade` | allows https→http | `redirect-downgrade` connects |

## Provenance

The corpus, the judge and the reference were written in this repository for P3-egress-001. They are not ported
from `research/state/raw/`, so there is nothing to hash. The address tables follow the IANA IPv4/IPv6
special-purpose registries, RFC 6052/8215 (NAT64), RFC 3056/7526 (6to4), RFC 4380 (Teredo) and RFC 9637
(`3fff::/20`). The cloud metadata endpoints are AWS/GCP/Azure 169.254.169.254, AWS ECS 169.254.170.2, Alibaba
100.100.100.200 and AWS IPv6 `fd00:ec2::254`.

## Re-run in repo

```
oracles/ssrf-corpus/run --self-test
ci/remote.sh bash -c 'cargo build --release -p egress-subject && oracles/ssrf-corpus/run --subject target/release/egress-subject'
```

## Known limits

- **Simulated responses.** Redirects come from the case table. HTTP framing is exercised only in the live cases and
  in monban-egress's unit tests.
- **No TLS.** The subject has no TLS (`tls-client` off). https cases use the scripted connector, so SNI is not
  observed here. In monban-egress, SNI comes from the same `Url::host()` as `Host`.
- **Reasons are not judged.** The decision is judged, not the reason code. A subject that rejects for the wrong
  reason still passes check 4.
- **Derivability is per case.** If one hop dials another host's first answer, the address still counts as
  derivable. Classification (check 1) still applies to that connect.
- **Local-use NAT64 is refused outright** (`64:ff9b:1::/48`). Its embedding position is network-specific, so no
  positive control exists for it.
