# Explorer 07 r4 — bridge: canonical identity, one owner (progress)
Started 2026-10-25 03:30 EDT. Reused ids: threat-path-canonicalization-authz-bypass, r3e09.grpc-defect-classes, r3e09.L5-ingress-conformance-harness, r3e09.ring1-verdict-amendment, crs-l5-keying-table, crs-ce-cache-poison-deception, irl-pg-collation-cex, w02.ingress-design-verdict, dpf-upstream-http-grpc.
## Plan
1. queries (needle) per instance class; 2. executed differential harness (Rust: url vs http::Uri vs fluent-uri/iri; idna; serde_json vs simd-json/sonic; cookie crates; Python stdlib urllib/http.cookies too); 3. L5s.
## Findings
### Sources 1-12 (verified via OSV API 2026-10-25, read)
- idna GHSA-h97m-ww89-6jmq / CVE-2024-12224 / RUSTSEC-2024-0421 pub 2024-12-09: xn--example- == example after decode; fixed idna 1.0.0 (rec 1.0.3 / url 2.5.4). Go twin CVE-2026-39821 (GO-2026-5026, 2026-05-22) x/net/idna.
- Heimdall IAP CVE-2026-42272 (GHSA-43jv-5j4x-qv67, 2026-05-08): case-sensitive %2F vs %2f check -> authz/upstream path differ; fixed 0.17.14.
- Quarkus CVE-2026-50559 (GHSA-qcxp-gm7m-4j5v, 2026-07-29): %3B/%2F/%5C not decoded by security layer normalizedPath(), decoded downstream; fixed 3.20.6.2/3.27.4.1; follow-on to CVE-2026-39852 (incomplete fix lineage).
- @fastify/middie CVE-2026-14198 (GHSA-2v46-jxjm-7q3v, 2026-07-01): middie decodes %2F before matching, router preserves.
- s3-proxy CVE-2026-42882 (GHSA-rfgq-wgg8-662p, 2026-05-11): authz on RequestURI() vs action on URL.Path.
- Hono CVE-2026-39410 (GHSA-r5rp-j6wh-rvv4, 2026-04-08): JS trim() strips U+00A0 in cookie names, browsers keep it -> __Host-/__Secure- prefix bypass; 4.12.12.
- Werkzeug CVE-2023-23934 (2023-02-14) nameless cookie => __Host- bypass; PHP CVE-2020-7070 url-decoded cookie names => __Host- forge.
- Fastify CVE-2022-41919 (2022-11-22) Content-Type essence parsing => CSRF without preflight.
- grpc-go CVE-2026-33186 GHSA-p77j-4mvh-x3m3 (OSV published 2026-03-18; fixed 1.79.3) confirmed (reuse r3e09.grpc-defect-classes).
- OSV crates.io (read): url 0 advisories ever; idna 1; http 4 (2019-21, memory); cookie 2 (2017/2021); serde_json 0; sonic-rs 0; simd-json 2 (2019/21 memory); tower-http/warp Windows path traversal 2022.
- Bishop Fox JSON interop (49 parsers) + Bitcoin Core #20949 duplicate-key JSON-RPC proxy; Orange Tsai BH17 lineage; WHATWG URL #893 (Jan 2026) maintainer: Tsai premise known earlier.
### EXECUTED differential (2026-10-25, i9 laptop, rustc 1.88, heavy.sh; crate versions url 2.5.8, http 1.5.0, idna 1.1.0, fluent-uri 0.3.2, serde_json 1.0.154, simd-json 0.15.1 (MSRV-resolved; latest 0.18.1 has same code), sonic-rs 0.5.10, cookie 0.18.2, mime 0.3.17, matchit 0.8.6, httparse 1.10.1; Python 3.12.9 stdlib) — recomputed
- WPT urltestdata @c48d5874 (2026-09-19): 896 cases; url 2.5.8 passes 831 (65 fail: ~40 file:, 8 ASCII xn-- passthrough (whatwg/url PR #914 merged 2026-06-25), 2 caret (fixed on main #1141 2026-07-08), 7 '///x' vs special base, 3 backslash in non-special -> url makes '\\/a' authority 'a').
- IdnaTestV2 (WPT, 2674 usable): url host 1916 pass, idna::domain_to_ascii 1917; all 758 misses = expected ASCII passthrough of invalid xn-- labels after PR #914. rust-url #1135 open (hsivonen, 2026-06-24) 'won't have time before August'. Python IDNA2003 codec agrees 1463/2676.
- paths (49 targets): admin-decision disagreement pairs: http_raw vs url_whatwg 14, raw vs decode_then_dot 17, raw vs python normpath(unquote) 19, matchit_on_raw vs matchit_on_url 15; only 2 pairs <=2 (url vs matchit_on_url 2; decode_then_dot vs python 2).
- JSON dup keys: serde_json Value LAST wins; serde derive struct REJECTS dup field; simd-json get() FIRST; sonic-rs get() FIRST; Python last. simd-json 0.15.1..0.18.1 decodes lone '\ud800' to U+0000 (simd-lite/simd-json #481 open 2026-09-22, fix PR #482 open). serde_json Value rejects 1e400 but serde derive (ignored field) accepts; simd-json rejects big ints >u64 w/o feature.
- cookie 0.18.2 (and master) uses str::trim(): ' __Host-sid=evil' read as '__Host-sid' == Hono CVE-2026-39410 class, unfixed. cookie crate keeps all dups (first/last choice left to app); Python SimpleCookie last-wins and drops NBSP-prefixed name.
- Content-Type: mime crate rejects 13/25 that Python email accepts; 'application/json, text/plain' -> python text/plain, naive 'application/json, text/plain'.
- Origin: 'https://example.com\\@evil.com' -> url crate origin example.com, Python urlsplit evil.com (Tsai 2017 class alive in CPython 3.12.9). fullwidth host -> url example.com, python raw.
- headers: httparse 1.10.1 accepts duplicate Host, duplicate differing Content-Length (5/6), conflicting TE; HeaderMap::get returns FIRST.
### Sources batch 2 (OSV-verified, read)
- Traefik CVE-2026-53622 (GHSA-9cr8-q42q-g8m7, 2026-06-23) HTTP/3 exact case-sensitive SNI TLSOptions lookup -> mTLS bypass; CVE-2026-48491 (GHSA-5r4w-85f3-pw66, 2026-06-23) SNICheck ignores wildcard -> domain-fronted mTLS bypass. Fixed 3.7.3.
- opa-envoy-plugin CVE-2026-26205 (GHSA-9f29-v6mm-pw6w, 2026-02-19) double-slash parsed_path authz bypass; mitigation merge_slashes or read raw path.
- Envoy CVE-2021-29492 (2021-05-28) %2F/%5C not decoded -> path_with_escaped_slashes_action (REJECT_REQUEST/UNESCAPE_AND_REDIRECT/KEEP/UNESCAPE_AND_FORWARD); edge best practices doc.
- Cloudflare URL normalization: incoming ON by default, 'normalize to origin' OFF by default => rules and origin see different paths by default (vendor doc, last updated ~2026-04).
- CouchDB CVE-2017-12635 (Erlang vs JS JSON dup 'roles'; fix: Erlang made last-wins like JS) — canonical historical instance.
- Case/collation identity: Snipe-IT CVE-2026-86770 (GHSA-w3vv-5wxh-xg4h, 2026-09-09, SAML username collation), Logto CVE-2026-15617 (2026-07-23, CVSS 9.1), prompts.chat CVE-2026-22665 (2026-04-03).
- grpc-go CVE-2026-84303 (GHSA-qc2q-p7wx-3px3, OSV 2026-09-01) xDS RBAC mixed-case header match.
- Contrarian: paivana (GNU Taler) proxy commit 4f469917 rejects non-normal request targets (libcurl normalizes after whitelist check); lighttpd maintainer (#2985) argues normalize-then-forward; DISA web server SRG V-264364 normalize else reject+close.
- libsoup CVE-2025-14523 (AlmaLinux patch) rejects duplicate Host per RFC 9112 §3.2; IETF HTTP WG Jul 2025 thread: duplicate Host in h2/h3 unspecified; HAProxy rejects Host != :authority.
- Claroty Team82 + Snyk 'Exploiting URL Parsing Confusion' (Jan 2022): 16 parsers, 5 confusion classes, 8 CVEs.
### Sources batch 3 (read)
- :authority vs Host: Jetty CVE-2026-6790 (GHSA-7p3p-8qv8-m2vh, 2026-07-14; h1/h2/h3 no authority==Host check); Netty CVE-2026-59900 (GHSA-c69g-56f8-xwqj, 2026-07-29, h2->h1 translation no Host dedup); Pingora CVE-2026-105298 (OSV 2026-10-20, fixed 0.9.0, cache poisoning + host ACL bypass). RFC 9113 §8.3.1: server SHOULD treat Host!=:authority as malformed; non-origin servers MUST scheme-normalize both before comparing.
- RFC 6265bis-22 (datatracker rev 22, 2026-10-19): UAs MUST match prefixes case-insensitively (§5.4); parse algorithm strips leading/trailing WSP only (SP/HTAB) -> cookie-rs str::trim() (Unicode White_Space incl U+00A0) diverges.
- PRECIS RFC 8264/8265 (UsernameCaseMapped) and I-JSON RFC 7493 (no dup names; IEEE754 double range) exist (datatracker).
- Trail of Bits 2025-06-17 'Unexpected security footguns in Go's parsers': encoding/json v1 dup last-wins + case-insensitive field match; json/v2 rejects dup, case-sensitive.
- axum #2678 (2024-03-25, open) / #2729 (open): routing before percent-decoding; matches executed result (matchit_on_raw admin=7 vs url 18).
- Cookie Crumbles (Squarcina et al., USENIX Sec 2023): 9/13 frameworks session-integrity vulns, 12 CVEs; LangSec parse-tree differential (Sassaman et al. 2011 TR) and ParDiff (static differential analysis of protocol parsers, 2024).
### Batch 4 + executed canonicalizer (recomputed)
- CORS: jupyter-server CVE-2026-40110 (GHSA-24qx-w28j-9m6p, 2026-05-05, unanchored re.match); Litestar CVE-2026-25478 (GHSA-2p2x-hpg8-cqp2, 2026-02-09, unescaped '.'). curl CVE-2026-8924 (2026-07-03) trailing-dot super cookie; curl CVE-2022-30115 HSTS trailing dot.
- Content-Type params: Rack CVE-2026-26961 (GHSA-vgpv-f759-9wx3, 2026-04-02) dup boundary last-wins vs WAF first; ModSecurity CVE-2026-52747 (2026-07-10); python-multipart CVE-2026-53538 (2026-06-22) ';' separator. EXECUTED: mime 0.3.17 accepts dup boundary/charset, get_param returns FIRST; Python email FIRST -> Rack-class differential vs any last-wins consumer.
- JSON: Cpanel::JSON::XS CVE-2026-9334 (2026-06-03) dup-key type confusion; Python CVE-2023-24329 urlsplit leading blanks.
- hyper 1.12.0 h1 role.rs: no Host check at all (no dup/missing Host 400, RFC 9112 §3.2 unenforced); h2 0.4.20 server.rs: :authority -> uri authority, Host header untouched, never compared (Pingora CVE-2026-105298 class lives in AEGIS's own stack unless core owns it). (source read)
- EXECUTED strict reference canonicalizer canon_ref.py (reject-don't-repair): accepted paths 10/49, hosts 7/36, cookies 9/20, json 9/25, tenant slugs 5/26. Re-feeding accepted canonical forms to all parsers: pairwise disagreement sum 0 (paths, 9 interpreters), 0 (hosts, 7), 0 (json, 5) vs 331/331/69 before. The differential caught a bug in MY canonicalizer first (0x7f.0.0.1 accepted as LDH; fixed with WHATWG 'ends in a number' rule) => canonicalizer itself must sit under the differential CI gate.
- Residual not removable at the edge: '/ADMIN' and '/admin.' — upstream-specific folding (case-insensitive FS, Rails format suffix, Windows trailing dot) => per-upstream profile, not per-front-end code.
### DONE 2026-10-25: raw JSON written (17 nodes, 31 edges, 71 sources); nodes/edges jsonl written; diffh/target deleted.
