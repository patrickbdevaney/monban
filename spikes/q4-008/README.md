# q4-008: CANON-2 false-reject rate on real request lines

**Question.** Does the reject-don't-repair reference (`oracles/canon-diff/canon_ref.py`) reject more than 0.1% of benign
real request lines for any one clause? If so, that clause flips to 308 or repair (IMPLEMENTATION_PLAN q4-008; ARCHITECTURE
§3.3 "Reverse"; D-9).

**Verdict: flip, for some clauses.** The three keys already in F8 `canon` stay `reject`. Four clause families measured
above 0.1% on 2024–2026 traffic:
- percent-encoded non-ASCII path octets
- empty path segments
- the existing trailing-slash 308
- the strict query grammar

`verdict.json` has the exact values. Measurement grade B.

## Sources and licenses

| source | era | what | lines used | license |
|---|---|---|---|---|
| Common Crawl `CC-MAIN-2026-43` URL index (cdx) | Oct 2026 | 1000 random blocks out of 886,601, every 3rd line. That gives 989,955 URLs (913,268 distinct targets) across many sites. Statuses: 2xx 825,747, 3xx 100,921, 4xx 60,924, 5xx 2,360 | 989,955 | Common Crawl Terms of Use (research use permitted). Only counts and ≤6 truncated examples per clause are kept |
| SecRepo `self.logs`, www.secrepo.com (Mike Sconzo), Apache combined format | 2024-01-01 … 2026-10-22, 1021 daily files | real access log of a small static security-dataset site | 2,279,367 | CC BY 4.0 |
| same, comparison only | 2017–2023, 2508 files | | 3,646,443 | CC BY 4.0 |
| NASA-HTTP (Internet Traffic Archive), KSC WWW server, comparison only | Jul+Aug 1995 | 3,461,612 log lines, of which 3,459,784 are HTTP request lines | 3,459,784 | "The traces may be freely redistributed" |

Total: 3.27M request lines from 2024–2026 (these decide the verdict) and 10.4M lines overall.

Sources that were tried and not used:
- The Harvard Dataverse "Online Shopping Store – Web Server Logs" (zanbil.ir 2019, CC0 metadata). The file is restricted (HTTP 403, "contact author").
- CSIC 2010. It is synthetic.

Downloads were kept outside the repo in the session scratchpad and deleted after counting. Peak disk use was about 250 MB.

sha256 of the downloads:
- `NASA_access_log_Jul95.gz` 199109ed…7488
- `NASA_access_log_Aug95.gz` 14995aed…b788
- CC `cluster.idx` 5be2d435…3fb (deleted after sampling)
- `cc_urls.tsv.gz` (sample, seed 8) 970f3542…a9a9
- sha256 over the sorted sha256 list of SecRepo 2024–2026: 6af36b7d…c640
- the same for SecRepo 2017–2023: 872d6a81…f161

## Method

- `analyze.py` parses each log line:
  - It undoes Apache `%r` escaping (`\xHH`, `\"`, `\\`), so the target is the byte string the server received.
  - It splits the request line into method, target and version. Non-HTTP lines (TLS bytes, junk) are excluded entirely: 1,828 lines, all in NASA.
  - It splits the target at the first `?`.
  - The path goes to `canon_ref.canon_path`, the query to `canon_ref.canon_query`. For CC only, the URL authority goes to `canon_ref.canon_authority` as a stand-in for Host. `canon_ref.py` is imported unmodified (`-I -B`, no pycache written).
- **Per-clause attribution.** `canon_ref` returns only the first reason it hits. So 50 independent detectors (19 path, 20 query, 11 host) mirror each of its rejecting rules without exiting early, and a line can count against several clauses.
  - *any-hit*: the clause is violated on the line.
  - *sole*: it is the only violated clause, so flipping it alone would accept the line.
  - A consistency counter checks that the detectors and the reference agree on reject vs accept for every path, query and host. It was **0 on all 10.4M lines**.
- **Decision rule** (`summarize.py`): a rejecting clause flips if its benign any-hit rate is above 0.1% in at least one of the two 2024–2026 sources. SecRepo 2017–2023 and NASA 1995 are reported only.
- `utf8_check.py` checks whether the CC paths with `%80–%FF` decode to strict UTF-8 and NFC.

### Benign classification heuristic (attack traffic is supposed to be rejected)

A line is an attack/scanner line if any of the following holds:
1. The request line is not HTTP/1.x with a standard method (GET HEAD POST PUT DELETE OPTIONS PATCH), or the target is absolute-form or `*`. Absolute-form here means proxy probes; h1 absolute-form is rejected anyway by `canon_request`.
2. The raw target, or its once- or twice-percent-decoded form, matches a signature list (`SIG_TARGET` in `analyze.py`):
   - traversal: two or more `../`, `..\`, `..;`, `%2e%2e`, `%252e`, overlong `%c0%ae`
   - sensitive files: `/etc/passwd`, `.env`, `.git/`, `wp-config`, `id_rsa`, …
   - well-known probe paths: `wp-login.php`, `xmlrpc.php`, `/wp-includes`, `phpmyadmin`, `/actuator`, `/boaform`, `/hnap1`, Exchange/VPN paths, …
   - injection tokens: SQLi `union select`, `<script`, `${jndi`, shellshock `() {`, `/bin/sh`, `wget `, `php://`, `%00`, …
3. For SecRepo only (`--static-site`), any `.php`, `.asp`, `.aspx`, `.jsp`, `.cgi`, `.pl`, `.do`, `.action` or `.cfm` path. The site serves only static files.
4. The User-Agent matches a scanner list: nikto, sqlmap, zgrab, masscan, nuclei, censys, expanse, l9explore, ….
5. **Scanner session:** the client IP sent any line matching rules 1–4 in the same source.

A single `/../`, `/./`, `//` or `%2F` is **not** a signature, so the heuristic does not decide the clauses under test by construction.

Exclusions:
- SecRepo 2024–2026: 624,673 lines (27.4%) excluded.
  - target signature 443,456
  - scanner-session IP 167,788 (18,920 IPs)
  - absolute-form 10,224
  - scanner UA 3,198
  - other method 7
- CC: 1,197 lines excluded (0.12%; spam or redirect URLs that carry signatures).
- NASA: 95,550 lines excluded, mostly by scanner-session propagation from HTTP/0.9 or malformed lines.

Known misses, which inflate benign rates slightly and never changed a decision:
- ThinkPHP `invokefunction` RCE probes
- GBK-encoded "新建文件夹.rar"-style backup-archive probes (most of SecRepo's 0.099% `p.raw_nonascii`)

## Results (percent of lines; raw / benign (benign sole-cause))

| clause | SecRepo 2024–26 | CC 2026-43 | SecRepo 2017–23 | NASA 1995 | decision |
|---|---|---|---|---|---|
| p.enc_slash `%2F` | 0.0031 / 0.0001 (0.0001) | 0.0479 / 0.0479 (0.0469) | 0.0007 / 0.0006 | 0 / 0 | keep reject |
| p.dot_segment | 0.0026 / 0.0002 (0.0002) | 0 / 0 | 0.0008 / 0.0006 | 0.0045 / 0.0042 | keep reject |
| h.non_ascii (Host) | n/a | 0 / 0 | n/a | n/a | keep reject |
| p.enc_backslash `%5C` | 0.0035 / 0.0035 | 0.0004 / 0.0004 | 0.0234 / 0.0256 | 0 / 0 | keep reject |
| p.backslash | 0.0011 / 0 | 0 / 0 | 0.0001 / 0.0001 | 0.0009 / 0.0009 | keep reject |
| p.semicolon (`;` matrix) | 0.0046 / 0.0005 | 0.0855 / 0.0856 (0.0850) | 0.0342 / 0.0025 | 0.0002 / 0.0002 | keep reject (closest) |
| p.enc_semicolon `%3B` | 0.0002 / 0 | 0.0035 / 0.0035 | 0.0002 / 0.0002 | 0 / 0 | keep reject |
| p.enc_nul `%00` | 0.0165 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | keep reject |
| p.enc_ctrl | 0.0007 / 0.0001 | 0.0008 / 0.0008 | 0.0091 / 0.0057 | 0.0001 / 0.0001 | keep reject |
| p.enc_pct `%25` | 0.0113 / 0.0095 | 0.0104 / 0.0097 | 0.0092 / 0.0092 | 0.0009 / 0.0010 | keep reject |
| p.raw_nonascii | 0.0788 / 0.0987 | 0 / 0 | 0.0115 / 0.0120 | 0.0002 / 0.0001 | keep reject |
| p.bad_pct, forbidden ASCII, space, `#`, ctrl | ≤0.0053 / ≤0.0018 | 0 / 0 | ≤0.0516 / ≤0.0594 | ≤0.0574 / ≤0.0548 | keep reject |
| **p.enc_nonascii `%80–%FF`** | 0.0332 / 0.0299 | **2.8509 / 2.8540 (2.8314)** | 0.0622 / 0.0699 | 0 / 0 | **flip: accept opaque** |
| **p.empty_segment `//`** | 0.9900 / **0.5453 (0.5434)** | 0.0112 / 0.0112 | 1.8252 / 0.2596 | 0.0364 / 0.0367 | **flip: 308 merge** |
| **p.trailing_slash (canon_ref: 308)** | 4.2785 / 2.2863 | **40.34 / 40.38** | 3.5205 / 3.5179 | 4.8854 / 4.8933 | **flip: accept** |
| **q.no_eq** `?token` | 0.1357 / 0.0074 | 0.4752 / **0.4756** (0.4513) | 0.0913 / 0.0100 | 2.1352 / 2.1399 | flip (query opaque) |
| **q.multi_eq** `a=b=c` | 0.7824 / **1.0245** (0) | 0.2009 / 0.2005 (0.0930) | 1.6652 / 1.8607 | 0 / 0 | flip (query opaque) |
| **q.enc_amp_eq** `%26 %3D` | 0.2367 / 0.2304 | 0.5742 / **0.5724** (0.2367) | 0.1241 / 0.1245 | 0.0003 / 0.0003 | flip (query opaque) |
| **q.enc_semicolon** `%3B` | 0.1476 / **0.1667** | 0.0114 / 0.0114 | 0.1210 / 0.1344 | 0 / 0 | flip (query opaque) |
| **q.enc_pct** `%25` | 0.0143 / 0 | 0.3604 / **0.3597** (0.0720) | 0.0036 / 0.0006 | 0 / 0 | flip (query opaque) |
| **q.enc_nonascii** | 0.0084 / 0 | 0.3290 / **0.3294** (0.2160) | 0.0044 / 0.0016 | 0 / 0 | flip (query opaque) |
| **q.plus** `+` | 0.0250 / 0.0126 | 0.4446 / **0.4438** (0.3092) | 0.0247 / 0.0090 | 0.0654 / 0.0649 | flip (query opaque) |
| **q.semicolon** `;` separator | 0.8481 / **1.0879** | 0.1274 / 0.1259 (0.0168) | 1.7001 / 1.8407 | 0 / 0 | flip (query opaque) |
| **q.dup_name** | 0.0064 / 0.0001 | 0.1767 / **0.1769** (0.1304) | 0.0751 / 0.0003 | 0 / 0 | flip (query opaque) |
| q.empty_pair `&&` | 0.0006 / 0.0004 | 0.0873 / 0.0868 | 0.0049 / 0.0003 | 0 / 0 | keep reject |
| q.enc_plus `%2B` | 0.0024 / 0.0001 | 0.0686 / 0.0686 | 0.0080 / 0.0018 | 0.0001 / 0.0001 | keep reject |
| q.empty_name, bad_pct, enc_nul_ctrl, raw non-ASCII, space, forbidden ASCII | ≤0.0348 / 0 | ≤0.0029 / ≤0.0029 | ≤0.0925 / ≤0.0056 | ≤0.0008 / ≤0.0008 | keep reject |
| h.underscore (only host clause seen) | n/a | 0.0019 / 0.0019 | n/a | n/a | keep reject |

Line-level totals for benign lines (any CANON reject, then 308):
- CC: 5.242% reject; 308 38.27%
- SecRepo 2024–26: 1.960% reject; 308 1.09%
- SecRepo 2017–23: 2.437% reject
- NASA: 2.248% reject

Path family / query family, benign:
- CC: 3.01% / 2.25%
- SecRepo 2024–26: 0.69% / 1.28%

Full numbers, unique-target rates and examples are in `results/*.json`, `results/summary.json` and `results/table.md`.

### What the flipping lines are (examples from `results/*.json`)

- **p.enc_nonascii.** Internationalized slugs such as `/ru/%D1%83%D0%BC…/` and `/ar/%D8%A7…`. These are 3.1% of distinct CC targets.
  - Of the 28,223 such CC paths, only 1 is invalid UTF-8 and 190 (0.019% of lines) are valid but not NFC (`results/cc_utf8_check.txt`).
  - The octets have exactly one reading. Ambiguity appears only if something decodes and Unicode-normalizes them. So the right flip is "accept as opaque uppercase-hex octets, never decode". Strict-UTF-8 and NFC rejects stay, since both are under 0.1%.
- **p.empty_segment.** SecRepo: bingbot fetching `//self.logs/access.log.….gz`, and the site's own broken `href`s (`/honeypot//%22http…`). CC: `/privacy-policy//`, `//robots.txt`. The rate is driven by one crawler on one site; CC shows 0.011%. A 308 to the merged path is safe because nothing non-canonical is forwarded, so this is a 308 flip, not a repair.
- **p.trailing_slash.** canon_ref answers `/a/` with a 308 to `/a`, following the research owner table. On CC, 40% of URLs end in `/` (WordPress-style permalinks). Redirecting them costs a round trip each, and it would loop on any upstream whose own canonical form is `/a/`. RFC 3986 treats `/a/` and `/a` as different resources, which is one reading each, not an ambiguity. So the recommendation is accept.
- **Query.** These are search forms (`?s=Logbuch+der+gegenwart`), correctly encoded nested URLs in values (`redirect_url=http%3A%2F%2F…%3Frefer%3D…`, `%252C`), base64 tokens (`?YWN0…==`), cache busters (`?1709465443916`), PHP arrays (`availabilities%5B%5D=…` repeated), SMF forums (`board=15.0;wap2`) and Apache autoindex sort links (`?C=M;O=A`).
  - Most of these have a single reading: an escaped `%26`/`%3D`/`%25` inside a value is the correct encoding, not an ambiguity.
  - The ones that really are ambiguous (`+`, `;` as separator, duplicate names) only matter if Monban itself interprets the query. CANON-5 keys authz on the route id, not on query parameters.
  - Hence `query: "opaque"`: byte-exact forwarding after §6.2.2.1/2, and strict per-parameter rules only on routes that declare typed parameters.

## Reproduction

    DL=/path/outside/repo   # with nasa/, secrepo/, cc/cluster.idx as listed in verdict.json "reproduce"
    DL=$DL spikes/q4-008/run.sh

`run.sh` runs `cc_sample.py`, then `analyze.py` once per source, then `summarize.py` and `utf8_check.py`. Every long step goes through
`ci/heavy.sh`. The analysis takes about 19 CPU-minutes in total; the CC sampling took about 25 minutes of network time.

The CC fetch on this run used `HEAVY_TIMEOUT=3000` for the network-bound sampler. Its User-Agent was `monban-q4-008-research/1.0`, with no personal data; it is now `aegis-ci`, per CLAUDE.md.

## Limits (honest)

- **Site type.** SecRepo is one static security-dataset site:
  - Its autoindex sort links (`?C=M;O=A`) alone push q.semicolon and q.multi_eq above 0.1%.
  - It sees heavy scanner load (27% of lines excluded).
  - The CC sample covers many sites, but its URLs come from links, not from browsers.
  - Neither source has API, SPA/XHR, mobile-app or gRPC-web traffic, or POST bodies. For a JSON-API-only deployment the query flips matter less.
- **Crawler normalization.** CC's crawler resolves dot segments (0 of 989,955 URLs), percent-encodes raw non-ASCII, and stores A-label hosts.
  - So CC cannot measure p.dot_segment, p.raw_nonascii or h.non_ascii. Those keeps rest on SecRepo and on how browsers behave: WHATWG URL parsing resolves dot segments, percent-encodes non-ASCII and sends A-labels.
  - The access logs have no Host header, so the host clauses come from CC authorities only.
- **Era.** NASA 1995 differs: imagemap and isindex queries (`?99,176`) give q.no_eq 2.1%. It never decided anything.
- **Heuristic.** The benign/attack split is signature-based. Its misses (see above) bias the benign rates upward slightly. None of the keep-reject clauses would cross 0.1% with a perfect classifier, and no flip depends on an attack line.
- **Threshold use.** The decision uses the any-hit rate. Sole-cause rates are smaller for the query clauses because they co-occur. The flip is proposed as one family (`query: "opaque"`), so the family total (CC 2.25%) is the relevant number.
- **Spec ownership.** The verdict proposes four new F8 keys plus matching changes to canon_ref and the golden. Those belong to the spec author (re-freeze); this spike edits nothing outside `spikes/q4-008/`.
