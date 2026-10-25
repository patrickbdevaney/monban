# canon-diff: CANON-DIFF G1–G4 differential oracle

## What is checked

The clause ids are from `spec/SPEC_INVARIANTS.md` §D, plus `INV-FAILCLOSED` in the sense that every input gets a total verdict.

| clause | how |
|---|---|
| CANON-1 (one `canon_K` per kind) | one reference function per kind in `canon_ref.py`: `path query query_typed host origin cookie ctype json tenant headers request`. The subject is asked about each kind separately. |
| CANON-2 (reject, don't repair) | the reference rejects every input with more than one plausible reading. The repairs it allows are listed at the top of `canon_ref.py`: RFC 3986 §6.2.2.1–2, lowercase scheme/host, default port stripped (§6.2.3), and lowercasing of case-insensitive tokens. A G1 property checks that an accepted path or opaque query differs from its raw form only by §6.2.2.1–2 and that an accepted host differs only by ASCII lowercasing. |
| CANON-2 per-clause outcomes (spike q4-008, F8 `canon` block) | `empty_segments = redirect_308`: `//` anywhere in a path is a reject whose reason is `308 path: empty segment, redirect to <slash-merged path>`; the subject must answer 308 (not 400, not accept) with the same target. `trailing_slash = accept`: `/a/` is accepted as `/a/`. `encoded_non_ascii_path = accept_opaque`: `%80–%FF` kept as uppercase-hex octets; rejected (400) if the percent-decoded path is not strict UTF-8 or not NFC. `query = opaque` (kind `query`): §6.2.2.1–2 only, otherwise byte-exact, never split or reordered; `+ ; %26 %3D %25 %80–%FF`, name-only tokens and duplicate names accepted; still rejected: bad escape, raw non-ASCII, raw space/forbidden ASCII/`#`, `%00–%1F`/`%7F`, `%2B`, empty pair (`&&`, leading/trailing `&`), empty name, length > 8192. `query = typed` (kind `query_typed`): the old strict per-parameter rules. Unchanged: dot segments, encoded `/ \ ; NUL ctrl %25`, raw `\ ;`, raw non-ASCII, host and header rules. |
| CANON-6 (SNI, :authority/Host and Origin bind one vhost, else 421; userinfo rejected) | `request` kind. 13,023 grid cases plus G1 random requests, covering h1/h2, duplicate Host, Host ≠ :authority, userinfo, SNI mismatch and Origin binding. The subject's reject status code must match. |
| CANON-7 (idempotence) | `canon(serialize(canon(x))) == canon(x)`. Checked on the reference over G2 and G1, and on the subject: each canonical it accepts is fed back to it. |
| H1(c) | `headers` kind: duplicate singleton fields, CL+TE, TE ≠ exactly `chunked`, obs-fold, obs-text, whitespace before the colon. |
| Host rule | ASCII-lowercase exact A-label match, no IDNA and no WHATWG parsing on ingress. `xn--` labels only get an RFC 3492 structural check, never a mapping. |

Gate parts (ARCHITECTURE §3.3; research node `r4e07.ci-gate-canon-property`):
- **G1**: property run, `--g1 N` cases (default 100,000), seeded attacker-operator grammar. On the reference it checks totality, that every reject reason carries a status code, CANON-7, safe-set-only repair and output shape. With a subject it checks subject-vs-reference agreement plus subject CANON-7.
- **G2**: pinned differential over 17,113 deduplicated inputs. Sources: the research corpus, WPT `urltestdata.json` @c48d5874, `IdnaTestV2.json` (same WPT pin), and `corpus/extra.json` (its `paths_q4008`/`queries_q4008` lists and a `query_typed` copy of every query input are appended last, so earlier case ids are unchanged). Without a subject, the reference is compared to the frozen golden `expected.json`. A `research-pin` check also compares the reference to research `canon_map.json`, allowing only the reviewed `deviations.json`.
- **G3**: `ledger.json`, 63 rows: one per item named in `r4e07.instance-ledger`, 2 hyper/h2 regressions, and 12 q4-008 rows (11 `q4008-*` plus the opaque twin of CVE-2026-53538). Expectations are hand-written from the spec, not generated, so this check is not circular.
- **G4**: lockfile bans on `../../Cargo.lock`: `simd-json`, `sonic-rs`, and more than one URL parser.

Kind sizes in G2: path 320, host 3073, origin 384, query 83, query_typed 83, json 36, cookie 32, ctype 30, tenant 31, headers 18, request 13023.

## Subject protocol (line-oriented JSON over stdin/stdout)

`./run --subject "<cmd>"` starts `<cmd>` (split with shlex, no shell, cwd = this dir). It writes one ASCII JSON object per line:

    {"id": 17, "kind": "path", "input": "/a%2Fb"}

The subject answers with one line per request, in any order, matched by `id`:

    {"id": 17, "accept": "<canonical>"}      or      {"id": 17, "reject": "<status> <reason>"}

- `input` is a string for every kind except `headers` (a list of raw field lines without CRLF) and `request`.
- `request` input is `{proto: "h1"|"h2", scheme, sni, authority, host: [..all Host lines..], origin, vhosts: {canonical-authority: [allowed serialized origins]}}`, and it is accepted as `{"vhost": "<key>"}`.
- Accepted canonical forms: strings for every kind except `headers` (`[[lowercased-name, value], ...]`) and `request`.
- `json` is accepted as the canonical serialization: sorted keys, `,`/`:` separators, UTF-8, no escapes beyond JSON's.
- A reject reason must start with the HTTP status. The status is compared for `request` (400/403/404/421, in the check order frozen in `canon_request`'s docstring) and for `path` (308 redirect vs 400/414 reject). A 308 reason must end in `, redirect to <path>`, and the target must equal the reference's.
- `query` is the opaque mode (F8 default); `query_typed` is the same input under a route that declares typed parameters.
- The subject process is started several times per run (corpus, ledger, G1, idempotence batches). It must read until EOF.

Cells reported per kind (any nonzero cell fails the run):
- `ref_reject_subj_accept`: the subject is lenient (the dangerous one).
- `ref_accept_subj_reject`: a false reject.
- `canonical_mismatch`
- `reject_code_mismatch`
- `not_idempotent`
- `protocol_error`: malformed, missing or timed-out answers, and stale golden.

## Pass criterion

`./run [--subject CMD] [--g1 N] [--g2 pinned|skip] [--g3 ledger|skip] [--g4 lock|skip]` prints a per-section table. The last line is `CANON-DIFF: PASS (...)` only if every cell in every section is 0. The exit code is 0 only on PASS. `--self-test` exits 0 only if every check below is caught.

`./run --regen-golden` rewrites `expected.json` from `canon_ref.py`. Run it only after a reviewed change to the reference, and say why in the commit.

## Re-run in-repo (2026-10-25, after the q4-008 update; this laptop, python 3.12; under 30 s, so `ci/heavy.sh` was not needed)

    $ oracles/canon-diff/run
    [G2 reference-vs-golden] cases=17113 nonzero_cells=0
    [CANON-7 reference properties (G2 corpus)] cases=17113 nonzero_cells=0
    [research-pin] canon_map entries=85 listed_deviations=3 mismatches=0
    [G3 ledger (reference)] cases=63 nonzero_cells=0
    [G1 reference properties (totality, CANON-7, safe-set-only)] cases=100000 nonzero_cells=0
    [G4 lock bans] .../Cargo.lock packages=25 violations=0
    CANON-DIFF: PASS (subject=reference-vs-golden g2=17113 g3=63 g1=100000 g4=ok nonzero_cells=0 3.9s)

    $ oracles/canon-diff/run --subject "python3 -I -B $PWD/oracles/canon-diff/canon_diff.py --serve"   # reference as a subject
    CANON-DIFF: PASS (subject=... g2=17113 g3=63 g1=100000 g4=ok nonzero_cells=0 3.1s)

    $ oracles/canon-diff/run --self-test
      reference-as-subject (must pass)             caught/ok  (nonzero_cells=0)
      mutant decode-%2F                            caught/ok  (nonzero_cells=43 ref_reject_subj_accept>0=True)
      mutant backslash-to-slash                    caught/ok  (nonzero_cells=19 ...)
      mutant accept-duplicate-Host                 caught/ok  (nonzero_cells=1851 ...)
      mutant accept-userinfo                       caught/ok  (nonzero_cells=2045 ...)
      mutant lowercase-non-ASCII                   caught/ok  (nonzero_cells=394 ...)
      mutant repair-dot-segments                   caught/ok  (nonzero_cells=118 ...)
      mutant json-last-wins                        caught/ok  (nonzero_cells=31 ...)
      mutant cookie-unicode-trim                   caught/ok  (nonzero_cells=26 ...)
      mutant double-decode-%25 (CANON-7)           caught/ok  (nonzero_cells=16 not_idempotent>0=True)
      mutant ignore-SNI-binding (CANON-6)          caught/ok  (nonzero_cells=629 ...)
      mutant ignore-Origin-binding (CANON-6)       caught/ok  (nonzero_cells=390 ...)
      mutant strip-trailing-dot                    caught/ok  (nonzero_cells=557 ...)
      mutant 308-trailing-slash (q4-008)           caught/ok  (nonzero_cells=32 ref_accept_subj_reject>0=True)
      mutant reject-encoded-non-ASCII-path (q4-008) caught/ok  (nonzero_cells=20 ref_accept_subj_reject>0=True)
      mutant split-reorder-opaque-query (q4-008)   caught/ok  (nonzero_cells=65 canonical_mismatch>0=True)
      mutant forward-//-instead-of-308 (q4-008)    caught/ok  (nonzero_cells=56 ref_reject_subj_accept>0=True)
      mutant 400-instead-of-308-for-// (q4-008)    caught/ok  (nonzero_cells=56 reject_code_mismatch>0=True)
      tampered golden entry                        caught/ok  (nonzero_cells=1)
      G4 synthetic lock (simd-json, 2 URL parsers) caught/ok  (violations=2)
    CANON-DIFF SELF-TEST: PASS (20/20 checks: 17 mutants caught (lenient, false-reject and q4-008 outcome), reference subject passes, golden tamper and G4 ban caught)

The mutants run as real subprocess subjects over the protocol. The self-test runs G1 with 3,000 cases (`--self-test-g1`).
The five q4-008 mutants: a subject that 308-redirects trailing slashes (false reject), one that rejects every `%80–%FF`
path escape (false reject), one that splits the opaque query on `&` and re-joins it sorted (canonical mismatch), one that
forwards `//` paths instead of answering 308 (lenient), and one that answers `//` with 400 instead of 308 (code mismatch).

## Research provenance (untrusted input: read and reviewed, nothing executed in place)

| path under `research/state/raw/` | sha256 | use |
|---|---|---|
| round-004/07-work/canon_ref.py | aaa048aebe6fe637ba49e647c919b5c30325af96a5147a0e319f722dc745a1b0 | logic ported and reviewed into `canon_ref.py`; deviations below |
| round-004/07-work/mkcorpus.py | 0d16bde861dcbbb91c3d7cd8cdfaef94cb9bdfd737cfd67f83135343c9068704 | read (it generated the research corpus) |
| round-004/07-work/corpus/corpus.json | 526cfe1bf2272983c36840b9a089b3b163c651dcc2269acda6e38ddcf0afbede | copied as `corpus/research_corpus.json` |
| round-004/07-work/corpus/urltestdata.json | 81e85fd3c199c08ef9c34cf651b3580eeedd080316493bfaf277a6b5ff8cf652 | copied as `corpus/urltestdata.json` (WPT @c48d5874 per the report) |
| round-004/07-work/corpus/IdnaTestV2.json | 84de621e5239676e59e5a3e68ef3e2b1acde9da5480a633d2ef446ef03238b76 | copied as `corpus/IdnaTestV2.json` |
| round-004/07-work/corpus/IdnaTestV2.clean.json | e09bdea96b8250715b6a46100c68c99e1d422c640f66ad53ef2ffdbfd817b371 | read; not used (the original WPT file is filtered in code instead) |
| round-004/07-work/canon_map.json | ec0b2cc99c30594c89f462ec2064e0bc502be4714d8e8d7ccab531cb56088fe5 | copied as `research/canon_map.json` (research-pin check) |
| round-004/07-work/results.json | bc49d76218e126ad7858f255aab538c29462c910d77b885dc5b850bf0de1f563 | read: before-canonicalization disagreement sums |
| round-004/07-work/results_canon.json | 4183d1479471991f93399479d2dde0390b4ac4876855ae83e2efefa73c5317b6 | read: after-canonicalization sums (0/0/0) |
| round-004/07-work/rust_out_canon.json | d7033ff0c3dcbf0f7a01e7d46e499161cc7463ca0c33bb4e81d437bdfed41b3e | read (per-parser outputs on canonical inputs) |
| round-004/07-work/analyze.py | 9a0ac9eaa892fc33387b0bc798d005771cbb42a7858d262473365d1516b6d9b2 | read (defines the pairwise sums) |
| round-004/07-work/corpus_canon/corpus.json | 28d0277fdeded4003e11d3e4ebb9ee194cab3d69ca3a929f4e3cebe95b826a2f | read |
| round-004/07-bridge-canonical-identity-one-owner.json | 952d31b52ab60f6352ea375722b8a4f780a79c90b1fc597fd0e9da251eecc3c2 | CANON-1..8 text, owner table, G1–G5 definition, instance ledger |
| round-003/02-bench/src/norm.rs | bf865702f2b22b6ac4aa380b5192cbf4eb068e5221379fa66812fb26e0e3c139 | read: a zero-copy cost benchmark with no canonicalization logic; nothing ported |

## Discrepancies with the research claims (stated plainly)

- **"331/331/69 → 0/0/0 (paths/hosts/JSON)" is misreported for paths.** I recomputed from `results.json` using `analyze.py`'s definition (summed pairwise disagreement over interpreter pairs):
  - paths = **444** (9 interpreters, 36 pairs, "is /admin" decision);
  - hosts = **331** (7 interpreters, 21 pairs, value);
  - JSON = **69** (5 parsers, 10 pairs).

  The "after" figure (0/0/0 in `results_canon.json`) is confirmed. So the claim should read 444/331/69 → 0/0/0. The 0 is over tiny accepted sets: 6 paths, 6 hosts, 9 JSON docs.
- **The research reference used IDNA on ingress.** `canon_ref.py` validated `xn--` labels with Python's IDNA2003 codec, which contradicts the "no IDNA on ingress" rule. It also wrongly rejected `xn--fa-hia.de` (faß.de), which the research's own vhost example lists. Fixed here (see `deviations.json`).
- **`/admin/`**: research accepted it as `/admin`. Its own owner table says "308 to the dotless form", so until q4-008 it was a reject whose reason started with `308`. Since q4-008 it is accepted as `/admin/` (its own form); still a listed deviation.
- **`/%ef%bc%a1dmin`** (fullwidth A): research rejected it; since q4-008 it is accepted as opaque octets `/%EF%BC%A1dmin` (strict UTF-8, NFC), byte-distinct from `/admin`. Listed deviation.
- **The reference here is stricter than research elsewhere.** Research acceptance counts vs here:

  | kind | research | here |
  |---|---|---|
  | cookies | 9/20 | 3/20 |
  | JSON | 9/25 | 5/25 |
  | paths | 10/49 | 9/49 |
  | hosts | 7/36 | 8/36 |

  The added rejects:
  - JSON: NUL in strings, `-0`, underflow, more than 17 significant digits, names that collide under ASCII case-folding (Go encoding/json, ledger row `tob-go-json-2025`).
  - cookie: whitespace around `=`, quoted values, `$`/`%` names, case-insensitive duplicates.
  - host: R-LDH `??--` labels other than `xn--`.

  New kinds: `query`, `ctype`, `origin`, `headers`, `request` (research had no reference function for these).
- **G3 "34 dated instances"**: the ledger node names 47 items in 11 classes. The 34-id list could not be reconstructed, so every named item got a row. Ledger inputs are **reconstructed from one-line mechanism descriptions, not the original PoCs**.
- **G2 "every Rust parser in the lock"** is not done here. The research ran 12 Rust crates via its `diffh` harness. This oracle differentials the subject (the future `aegis-canon` through a protocol adapter) against the reference; there is no multi-crate Rust harness yet. The main `Cargo.lock` currently has 25 packages and none of them is an identity parser.

## Known limits

- The reference is spec-by-code and was reviewed by one porter. It is not mechanized (CANON rung stays R2 executed). A wrong rule in it propagates into the golden; G3 and the research pin are the independent checks.
- G1 samples a grammar of known operators. New Unicode or spec changes can escape it.
- IPv6 literals are rejected (not served). `query_typed` has no route-declared list parameters (F8 exempts declared list parameters from the duplicate-name rule; the oracle has no way to declare them yet). `headers` treats every field not in a small list allowlist as a singleton, which may false-reject real traffic (q4-008 did not measure headers).
- Opaque `%80–%FF` path octets are only checked for strict UTF-8 and NFC, as F8 specifies. So zero-width (`%E2%80%8B`), bidi overrides (`%E2%80%AE`), BOM (`%EF%BB%BF`), noncharacters (`%EF%BF%BF`) and NFKC-foldable forms (fullwidth letters) are accepted. Routing matches the octets byte-exactly, so none of them aliases an ASCII route inside AEGIS; they matter only behind an upstream that decodes and folds paths (CANON-8, not checked).
- CANON-8 (per-upstream folding profile) is not checked. `/ADMIN` and `/admin.` stay canonical.
- G4 inspects the whole lockfile, not the ingress crate subgraph.

## q4-008 golden regeneration (2026-10-25): reviewed verdict changes

`expected.json` was regenerated with `--regen-golden` after the q4-008 change to `canon_ref.py` (F8 `canon` block frozen
in commit 7396972; CANON-2 amended). Before regenerating, the previous reference (the committed `canon_ref.py`, which
reproduced the old golden exactly on all 16,985 old cases) was compared with the new one on the same case ids.

- Old cases: 16,985. **Changed: 107**, all in the `path` and `query` kinds; no host, origin, cookie, ctype, JSON,
  tenant, headers or request verdict changed.
  - 400 → 308 (empty segment now redirects to the slash-merged path): 36 paths
  - 308 → accept (trailing slash is its own form): 20 paths
  - 400 → accept: 9 paths (opaque `%80–%FF` octets that are strict UTF-8 and NFC) and 33 queries (opaque mode)
  - 400 → 400 with a different reason (same status, still rejected): 1 path, 8 queries
- New cases: 128 (23 `paths_q4008`: 6 accept, 17 reject; 22 `queries_q4008`: 14 accept, 8 reject; 83 `query_typed`
  copies of every query input: 18 accept, 65 reject). Total 17,113.
- Every change was checked against the F8 semantics in `spikes/q4-008/verdict.json` (`decision_effect`). No change
  turns a dot segment, encoded `/ \ ; NUL ctrl %25`, raw non-ASCII or host case into an accept.

| case id | kind | input | old | new |
|---|---|---|---|---|
| `research:path:1` | path | `/admin/` | 308 path: trailing slash, redirect to /admin | accept "/admin/" |
| `research:path:5` | path | `//admin` | 400 path: empty segment | 308 path: empty segment, redirect to /admin |
| `research:path:30` | path | `/%ef%bc%a1dmin` | 400 path: ambiguous percent-escape %EF | accept "/%EF%BC%A1dmin" |
| `research:path:34` | path | `/admin//x` | 400 path: empty segment | 308 path: empty segment, redirect to /admin/x |
| `research:path:35` | path | `///admin` | 400 path: empty segment | 308 path: empty segment, redirect to /admin |
| `wpt:query:219` | query | `b` | 400 query: pair must be exactly name=value | accept "b" |
| `wpt:query:234` | query | `%20d%20` | 400 query: pair must be exactly name=value | accept "%20d%20" |
| `wpt:path:260` | path | `/foo/:foo.com/` | 308 path: trailing slash, redirect to /foo/:foo.com | accept "/foo/:foo.com/" |
| `wpt:path:263` | path | `/foo/:/` | 308 path: trailing slash, redirect to /foo/: | accept "/foo/:/" |
| `wpt:path:293` | path | `//@` | 400 path: empty segment | 308 path: empty segment, redirect to /@ |
| `wpt:path:297` | path | `/b:c/d@foo.com/` | 308 path: trailing slash, redirect to /b:c/d@foo.com | accept "/b:c/d@foo.com/" |
| `wpt:path:306` | path | `/bar.com/` | 308 path: trailing slash, redirect to /bar.com | accept "/bar.com/" |
| `wpt:path:307` | path | `///////` | 400 path: empty segment | 308 path: empty segment, redirect to / |
| `wpt:path:308` | path | `///////bar.com/` | 400 path: empty segment | 308 path: empty segment, redirect to /bar.com/ |
| `wpt:path:309` | path | `//://///` | 400 path: empty segment | 308 path: empty segment, redirect to /:/ |
| `wpt-raw:path:313` | path | `//foo/bar` | 400 path: empty segment | 308 path: empty segment, redirect to /foo/bar |
| `wpt:query:315` | query | `?e` | 400 query: pair must be exactly name=value | accept "?e" |
| `wpt:query:317` | query | `efgh?ijkl` | 400 query: pair must be exactly name=value | accept "efgh?ijkl" |
| `wpt:path:342` | path | `/example.com/` | 308 path: trailing slash, redirect to /example.com | accept "/example.com/" |
| `wpt:path:346` | path | `/foo/example.com/` | 308 path: trailing slash, redirect to /foo/example.com | accept "/foo/example.com/" |
| `wpt:path:354` | path | `/c:////foo/bar.html` | 400 path: empty segment | 308 path: empty segment, redirect to /c:/foo/bar.html |
| `wpt-raw:path:360` | path | `//server/file` | 400 path: empty segment | 308 path: empty segment, redirect to /server/file |
| `wpt-raw:path:364` | path | `//` | 400 path: empty segment | 308 path: empty segment, redirect to / |
| `wpt-raw:path:365` | path | `///` | 400 path: empty segment | 308 path: empty segment, redirect to / |
| `wpt-raw:path:367` | path | `///test` | 400 path: empty segment | 308 path: empty segment, redirect to /test |
| `wpt:path:372` | path | `/C:/m/` | 308 path: trailing slash, redirect to /C:/m | accept "/C:/m/" |
| `wpt:path:377` | path | `/foo/` | 308 path: trailing slash, redirect to /foo | accept "/foo/" |
| `wpt:path:396` | path | `/foo/bar/` | 308 path: trailing slash, redirect to /foo/bar | accept "/foo/bar/" |
| `wpt:path:405` | path | `/foo%C2%91%91` | 400 path: ambiguous percent-escape %C2 | 400 path: encoded octets are not valid UTF-8 |
| `wpt:path:412` | path | `//foo//bar` | 400 path: empty segment | 308 path: empty segment, redirect to /foo/bar |
| `wpt:path:415` | path | `/%E4%BD%A0%E5%A5%BD%E4%BD%A0%E5%A5%BD` | 400 path: ambiguous percent-escape %E4 | accept "/%E4%BD%A0%E5%A5%BD%E4%BD%A0%E5%A5%BD" |
| `wpt:path:417` | path | `/%E2%80%A5/foo` | 400 path: ambiguous percent-escape %E2 | accept "/%E2%80%A5/foo" |
| `wpt:path:419` | path | `/%EF%BB%BF/foo` | 400 path: ambiguous percent-escape %EF | accept "/%EF%BB%BF/foo" |
| `wpt:path:421` | path | `/%E2%80%AE/foo/%E2%80%AD/bar` | 400 path: ambiguous percent-escape %E2 | accept "/%E2%80%AE/foo/%E2%80%AD/bar" |
| `wpt:path:466` | path | `/aaa/` | 308 path: trailing slash, redirect to /aaa | accept "/aaa/" |
| `wpt:query:467` | query | `query` | 400 query: pair must be exactly name=value | accept "query" |
| `wpt:path:498` | path | `/%E4%B8%AD/test.txt` | 400 path: ambiguous percent-escape %E4 | accept "/%E4%B8%AD/test.txt" |
| `wpt-raw:path:501` | path | `//www.example2.com` | 400 path: empty segment | 308 path: empty segment, redirect to /www.example2.com |
| `wpt:query:519` | query | `hi` | 400 query: pair must be exactly name=value | accept "hi" |
| `wpt:path:532` | path | `/%EF%BF%BD` | 400 path: ambiguous percent-escape %EF | accept "/%EF%BF%BD" |
| `wpt:query:534` | query | `%EF%BF%BD` | 400 query: pair must be exactly name=value | accept "%EF%BF%BD" |
| `wpt:query:625` | query | `q=%F0%9F%94%A5` | 400 query: ambiguous percent-escape %F0 | accept "q=%F0%9F%94%A5" |
| `wpt:query:626` | query | `test` | 400 query: pair must be exactly name=value | accept "test" |
| `wpt:query:637` | query | `` `{} `` | 400 query: pair must be exactly name=value | 400 query: forbidden character U+0060 |
| `wpt:query:641` | query | `%27` | 400 query: pair must be exactly name=value | accept "%27" |
| `wpt:query:642` | query | `'` | 400 query: pair must be exactly name=value | accept "'" |
| `wpt:query:650` | query | `i` | 400 query: pair must be exactly name=value | accept "i" |
| `wpt:query:860` | query | `qux` | 400 query: pair must be exactly name=value | accept "qux" |
| `wpt:path:922` | path | `/C%3A/` | 308 path: trailing slash, redirect to /C%3A | accept "/C%3A/" |
| `wpt:path:923` | path | `/C%7C/` | 308 path: trailing slash, redirect to /C%7C | accept "/C%7C/" |
| `wpt:path:927` | path | `/C:/` | 308 path: trailing slash, redirect to /C: | accept "/C:/" |
| `wpt-raw:path:929` | path | `//d:` | 400 path: empty segment | 308 path: empty segment, redirect to /d: |
| `wpt:path:930` | path | `/d:/` | 308 path: trailing slash, redirect to /d: | accept "/d:/" |
| `wpt:query:932` | query | `x` | 400 query: pair must be exactly name=value | accept "x" |
| `wpt:query:933` | query | `fox` | 400 query: pair must be exactly name=value | accept "fox" |
| `wpt:path:935` | path | `/localhost//cat` | 400 path: empty segment | 308 path: empty segment, redirect to /localhost/cat |
| `wpt:path:936` | path | `//localhost//cat` | 400 path: empty segment | 308 path: empty segment, redirect to /localhost/cat |
| `wpt:path:937` | path | `///mouse` | 400 path: empty segment | 308 path: empty segment, redirect to /mouse |
| `wpt-raw:path:938` | path | `/////mouse` | 400 path: empty segment | 308 path: empty segment, redirect to /mouse |
| `wpt:path:940` | path | `//pig` | 400 path: empty segment | 308 path: empty segment, redirect to /pig |
| `wpt-raw:path:941` | path | `//localhost//pig` | 400 path: empty segment | 308 path: empty segment, redirect to /localhost/pig |
| `wpt:query:946` | query | `chai` | 400 query: pair must be exactly name=value | accept "chai" |
| `wpt:path:952` | path | `/y/z/` | 308 path: trailing slash, redirect to /y/z | accept "/y/z/" |
| `wpt-raw:path:955` | path | `//C:/` | 400 path: empty segment | 308 path: empty segment, redirect to /C:/ |
| `wpt-raw:path:956` | path | `///C:/` | 400 path: empty segment | 308 path: empty segment, redirect to /C:/ |
| `wpt:path:959` | path | `/Y:/` | 308 path: trailing slash, redirect to /Y: | accept "/Y:/" |
| `wpt:path:962` | path | `/y:/` | 308 path: trailing slash, redirect to /y: | accept "/y:/" |
| `wpt:path:964` | path | `///foo` | 400 path: empty segment | 308 path: empty segment, redirect to /foo |
| `wpt:path:965` | path | `////foo` | 400 path: empty segment | 308 path: empty segment, redirect to /foo |
| `wpt:path:966` | path | `//foo` | 400 path: empty segment | 308 path: empty segment, redirect to /foo |
| `wpt:path:968` | path | `//one/two` | 400 path: empty segment | 308 path: empty segment, redirect to /one/two |
| `wpt-raw:path:971` | path | `///one/two` | 400 path: empty segment | 308 path: empty segment, redirect to /one/two |
| `wpt-raw:path:972` | path | `////one/two` | 400 path: empty segment | 308 path: empty segment, redirect to /one/two |
| `wpt:path:973` | path | `//p` | 400 path: empty segment | 308 path: empty segment, redirect to /p |
| `wpt-raw:path:1006` | path | `////` | 400 path: empty segment | 308 path: empty segment, redirect to / |
| `wpt:path:1007` | path | `//x/` | 400 path: empty segment | 308 path: empty segment, redirect to /x/ |
| `wpt-raw:path:1008` | path | `////x/` | 400 path: empty segment | 308 path: empty segment, redirect to /x/ |
| `wpt:query:1020` | query | `passwd` | 400 query: pair must be exactly name=value | accept "passwd" |
| `wpt:path:1025` | path | `//path` | 400 path: empty segment | 308 path: empty segment, redirect to /path |
| `wpt:query:1043` | query | `%22` | 400 query: pair must be exactly name=value | accept "%22" |
| `wpt:query:1044` | query | `%3C` | 400 query: pair must be exactly name=value | accept "%3C" |
| `wpt:query:1045` | query | `%3E` | 400 query: pair must be exactly name=value | accept "%3E" |
| `wpt:query:1046` | query | `%E2%8C%A3` | 400 query: pair must be exactly name=value | accept "%E2%8C%A3" |
| `wpt:query:1047` | query | `%23%23` | 400 query: pair must be exactly name=value | accept "%23%23" |
| `wpt:query:1048` | query | `%GH` | 400 query: pair must be exactly name=value | 400 query: bad percent-escape |
| `wpt:query:1049` | query | `a` | 400 query: pair must be exactly name=value | accept "a" |
| `wpt:query:1062` | query | `query%27%7F=query` | 400 query: ambiguous percent-escape %7F | 400 query: rejected percent-escape %7F |
| `wpt:path:1076` | path | `/dir/` | 308 path: trailing slash, redirect to /dir | accept "/dir/" |
| `wpt:query:1077` | query | `` %20!%22$%&'()*+,-./:;%3C=%3E?@[\\]^_`{\|}~ `` | 400 query: pair must be exactly name=value | 400 query: bad percent-escape |
| `wpt:query:1078` | query | `` %20!%22$%&%27()*+,-./:;%3C=%3E?@[\\]^_`{\|}~ `` | 400 query: pair must be exactly name=value | 400 query: bad percent-escape |
| `wpt:query:1144` | query | `%00y` | 400 query: pair must be exactly name=value | 400 query: rejected percent-escape %00 |
| `wpt:path:1147` | path | `/%EF%BF%BFy` | 400 path: ambiguous percent-escape %EF | accept "/%EF%BF%BFy" |
| `wpt:query:1149` | query | `%EF%BF%BFy` | 400 query: pair must be exactly name=value | accept "%EF%BF%BFy" |
| `wpt:query:1163` | query | `search` | 400 query: pair must be exactly name=value | accept "search" |
| `wpt-raw:path:1166` | path | `///example.org/path` | 400 path: empty segment | 308 path: empty segment, redirect to /example.org/path |
| `extra:path:3860` | path | `/a/b/` | 308 path: trailing slash, redirect to /a/b | accept "/a/b/" |
| `extra:path:3863` | path | `/%e2%80%8b` | 400 path: ambiguous percent-escape %E2 | accept "/%E2%80%8B" |
| `extra:query:3913` | query | `a=1;b=2` | 400 query: pair must be exactly name=value | accept "a=1;b=2" |
| `extra:query:3914` | query | `a=1&a=2` | 400 query: duplicate name | accept "a=1&a=2" |
| `extra:query:3915` | query | `a=1&%61=2` | 400 query: duplicate name | accept "a=1&a=2" |
| `extra:query:3916` | query | `a+b=1` | 400 query: forbidden character U+002B | accept "a+b=1" |
| `extra:query:3917` | query | `a=1+2` | 400 query: forbidden character U+002B | accept "a=1+2" |
| `extra:query:3919` | query | `a=%2B` | 400 query: ambiguous percent-escape %2B | 400 query: rejected percent-escape %2B |
| `extra:query:3920` | query | `a=%26b=2` | 400 query: pair must be exactly name=value | accept "a=%26b=2" |
| `extra:query:3921` | query | `a=%3D` | 400 query: ambiguous percent-escape %3D | accept "a=%3D" |
| `extra:query:3926` | query | `a=%00` | 400 query: ambiguous percent-escape %00 | 400 query: rejected percent-escape %00 |
| `extra:query:3929` | query | `a=%C3%A9` | 400 query: ambiguous percent-escape %C3 | accept "a=%C3%A9" |
