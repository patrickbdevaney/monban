# canon-diff: CANON-DIFF G1–G4 differential oracle

## What is checked

The clause ids are from `spec/SPEC_INVARIANTS.md` §D, plus `INV-FAILCLOSED` in the sense that every input gets a total verdict.

| clause | how |
|---|---|
| CANON-1 (one `canon_K` per kind) | one reference function per kind in `canon_ref.py`: `path query host origin cookie ctype json tenant headers request`. The subject is asked about each kind separately. |
| CANON-2 (reject, don't repair) | the reference rejects every input with more than one plausible reading. The repairs it allows are listed at the top of `canon_ref.py`: RFC 3986 §6.2.2.1–2, lowercase scheme/host, default port stripped (§6.2.3), and lowercasing of case-insensitive tokens. A G1 property checks that an accepted path differs from its raw form only by §6.2.2.1–2 and that an accepted host differs only by ASCII lowercasing. |
| CANON-6 (SNI, :authority/Host and Origin bind one vhost, else 421; userinfo rejected) | `request` kind. 13,023 grid cases plus G1 random requests, covering h1/h2, duplicate Host, Host ≠ :authority, userinfo, SNI mismatch and Origin binding. The subject's reject status code must match. |
| CANON-7 (idempotence) | `canon(serialize(canon(x))) == canon(x)`. Checked on the reference over G2 and G1, and on the subject: each canonical it accepts is fed back to it. |
| H1(c) | `headers` kind: duplicate singleton fields, CL+TE, TE ≠ exactly `chunked`, obs-fold, obs-text, whitespace before the colon. |
| Host rule | ASCII-lowercase exact A-label match, no IDNA and no WHATWG parsing on ingress. `xn--` labels only get an RFC 3492 structural check, never a mapping. |

Gate parts (ARCHITECTURE §3.3; research node `r4e07.ci-gate-canon-property`):
- **G1**: property run, `--g1 N` cases (default 100,000), seeded attacker-operator grammar. On the reference it checks totality, that every reject reason carries a status code, CANON-7, safe-set-only repair and output shape. With a subject it checks subject-vs-reference agreement plus subject CANON-7.
- **G2**: pinned differential over 16,985 deduplicated inputs. Sources: the research corpus, WPT `urltestdata.json` @c48d5874, `IdnaTestV2.json` (same WPT pin), and `corpus/extra.json`. Without a subject, the reference is compared to the frozen golden `expected.json`. A `research-pin` check also compares the reference to research `canon_map.json`, allowing only the reviewed `deviations.json`.
- **G3**: `ledger.json`, 51 rows, one per item named in `r4e07.instance-ledger` plus 2 hyper/h2 regressions. Expectations are hand-written from the spec, not generated, so this check is not circular.
- **G4**: lockfile bans on `../../Cargo.lock`: `simd-json`, `sonic-rs`, and more than one URL parser.

Kind sizes in G2: path 297, host 3073, origin 384, query 61, json 36, cookie 32, ctype 30, tenant 31, headers 18, request 13023.

## Subject protocol (line-oriented JSON over stdin/stdout)

`./run --subject "<cmd>"` starts `<cmd>` (split with shlex, no shell, cwd = this dir). It writes one ASCII JSON object per line:

    {"id": 17, "kind": "path", "input": "/a%2Fb"}

The subject answers with one line per request, in any order, matched by `id`:

    {"id": 17, "accept": "<canonical>"}      or      {"id": 17, "reject": "<status> <reason>"}

- `input` is a string for every kind except `headers` (a list of raw field lines without CRLF) and `request`.
- `request` input is `{proto: "h1"|"h2", scheme, sni, authority, host: [..all Host lines..], origin, vhosts: {canonical-authority: [allowed serialized origins]}}`, and it is accepted as `{"vhost": "<key>"}`.
- Accepted canonical forms: strings for every kind except `headers` (`[[lowercased-name, value], ...]`) and `request`.
- `json` is accepted as the canonical serialization: sorted keys, `,`/`:` separators, UTF-8, no escapes beyond JSON's.
- A reject reason must start with the HTTP status. Only for `request` is the status compared (400/403/404/421, in the check order frozen in `canon_request`'s docstring).
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

## Re-run in-repo (2026-10-25, this laptop, python 3.12.9; under 15 s total, so `ci/heavy.sh` was not needed)

    $ oracles/canon-diff/run
    [G2 reference-vs-golden] cases=16985 nonzero_cells=0
    [CANON-7 reference properties (G2 corpus)] cases=16985 nonzero_cells=0
    [research-pin] canon_map entries=85 listed_deviations=2 mismatches=0
    [G3 ledger (reference)] cases=51 nonzero_cells=0
    [G1 reference properties (totality, CANON-7, safe-set-only)] cases=100000 nonzero_cells=0
    [G4 lock bans] .../Cargo.lock packages=25 violations=0
    CANON-DIFF: PASS (subject=reference-vs-golden g2=16985 g3=51 g1=100000 g4=ok nonzero_cells=0 1.4s)

    $ oracles/canon-diff/run --subject "python3 -I -B $PWD/oracles/canon-diff/canon_diff.py --serve"   # reference as a subject
    CANON-DIFF: PASS (subject=... g2=16985 g3=51 g1=100000 g4=ok nonzero_cells=0 3.2s)

    $ oracles/canon-diff/run --self-test
      reference-as-subject (must pass)             caught/ok  (nonzero_cells=0)
      mutant decode-%2F                            caught/ok  (nonzero_cells=19 ref_reject_subj_accept>0=True)
      mutant backslash-to-slash                    caught/ok  (nonzero_cells=6 ...)
      mutant accept-duplicate-Host                 caught/ok  (nonzero_cells=1851 ...)
      mutant accept-userinfo                       caught/ok  (nonzero_cells=2056 ...)
      mutant lowercase-non-ASCII                   caught/ok  (nonzero_cells=395 ...)
      mutant repair-dot-segments                   caught/ok  (nonzero_cells=151 ...)
      mutant json-last-wins                        caught/ok  (nonzero_cells=47 ...)
      mutant cookie-unicode-trim                   caught/ok  (nonzero_cells=25 ...)
      mutant double-decode-%25 (CANON-7)           caught/ok  (nonzero_cells=26 not_idempotent>0=True)
      mutant ignore-SNI-binding (CANON-6)          caught/ok  (nonzero_cells=632 ...)
      mutant ignore-Origin-binding (CANON-6)       caught/ok  (nonzero_cells=384 ...)
      mutant strip-trailing-dot                    caught/ok  (nonzero_cells=551 ...)
      tampered golden entry                        caught/ok  (nonzero_cells=1)
      G4 synthetic lock (simd-json, 2 URL parsers) caught/ok  (violations=2)
    CANON-DIFF SELF-TEST: PASS (15/15 checks: 12 lenient mutants caught, reference subject passes, golden tamper and G4 ban caught)

The mutants run as real subprocess subjects over the protocol. The self-test runs G1 with 3,000 cases (`--self-test-g1`).

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
- **`/admin/`**: research accepted it as `/admin`. Its own owner table says "308 to the dotless form", so here it is a reject whose reason starts with `308`.
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
- IPv6 literals are rejected (not served). `query` has no route-declared list parameters. `headers` treats every field not in a small list allowlist as a singleton, which may false-reject real traffic (q4-008 false-reject spike still open).
- CANON-8 (per-upstream folding profile) is not checked. `/ADMIN` and `/admin.` stay canonical.
- G4 inspects the whole lockfile, not the ingress crate subgraph.
