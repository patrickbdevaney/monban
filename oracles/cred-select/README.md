# cred-select: MTC CredentialSelector decision-table oracle (unit P7-oracle-sel-001)

Black-box oracle for the Phase 7 MTC CredentialSelector (gate `cred-select`, implementer P7-mtc-001). It checks
F1 SEL-1..3 (PLAN-7 "Interfaces", F1 §F addendum) and PREFLIGHT D-P7.4 against a Python reference selector built
from the decision table below. It runs ≥ 1e4 generated ClientHellos plus 21 directed cases, and requires 0
divergences.

```
oracles/cred-select/run --n 10000 --subject 'target/release/tls-subject select'   # the gate (tls-subject --features mtc)
oracles/cred-select/run [--n N] [--seed S] [-v]                                    # subject = the Python reference
oracles/cred-select/run --self-test [--n N]
```

`run` execs `python3 -I oracle.py` from the repo root. Stdlib only (Python ≥ 3.11, for `tomllib`). The last line is
`CRED-SELECT: PASS (...)` or `CRED-SELECT: FAIL (...)`, and the exit code is 0 only on PASS. Self-test prints
`CRED-SELECT SELF-TEST: PASS|FAIL (...)`. `--n` below 10000 fails `corpus.size`. The default seed is fixed (0xC5E1),
so a run is reproducible. Without `--subject` the oracle drives `ref_selector.py` over the same pipe, as
oracles/README.md asks. There is deliberately no `default-subject`: the aggregate `ci/oracles.sh run` builds
tls-subject without `mtc`, so the gate `cred-select` owns the real run. A run takes about 25 s and the self-test
about 100 s on the laptop. It runs on the desktop (`ci/remote.sh`). It starts one subject process per drive and
signals nothing.

## Subject protocol: `tls-subject select` (for P7-mtc-001)

The oracle starts the subject once (`shlex.split` of `--subject`, cwd = repo root). It writes every request line
to the subject's stdin and then closes it. It reads stdout until the subject exits, with a 900 s timeout. The
subject must answer **every request line with exactly one line, in order**, and exit 0 at EOF. Diagnostics go to
stderr only. A line-at-a-time subject is fine because the oracle feeds stdin and drains stdout concurrently. The
format is plain ASCII tokens separated by single spaces, so the subject needs no JSON crate (tls-subject's
manifest is outside P7-mtc-001's write scope).

**Request line:**

```
<case> <profile> <listener> <ncred> <cred_1> ... <cred_ncred> <client_hello_hex>
```

| token | meaning |
|---|---|
| `case` | decimal case number. It is echoed in the answer. |
| `profile` | the listener's F8 profile name: one of `P-PUBLIC-WEB`, `P-PQ-REQUIRED`, `P-UNIVERSAL`, `P-BSI-ALT`, `P-CNSA`, `FIPS-FLOOR`, `FIPS-PQ-REQUIRED`. `FIPS-CMVP` is never sent: it has no floor-build config, and `mtc` is never in the cmvp build. |
| `listener` | name of the listener the connection arrived on, `[A-Za-z0-9._-]{1,32}`. |
| `ncred` | decimal count of credential tokens that follow, possibly 0. |
| `cred_i` | `id,listener,kind,scheme,trust_anchor_id`. These are the F8 `tls.credentials` entries of **all** listeners, in configured order. `id` is unique, `[A-Za-z0-9._-]{1,32}`, never `handshake_failure`. `listener` is the owning listener. `kind` is `x509`, `mldsa` or `mtc`. `scheme` is the 4-hex-digit TLS SignatureScheme the credential's key signs CertificateVerify with. `trust_anchor_id` is the hex TrustAnchorID (1..32 bytes) when kind = `mtc`, otherwise `-`. |
| `client_hello_hex` | the hex of the raw bytes the client sent first: normally one TLS record holding the ClientHello. |

**Answer line:** `<case> <credential id>` or `<case> handshake_failure`. A request line the subject cannot parse
is answered with `<case> error <reason>`, and the oracle counts it as a divergence. The oracle never sends one.

Schemes used: x509 ∈ {0403, 0503, 0807}, mldsa ∈ {0904, 0905, 0906}, mtc ∈ {0403, 0503, 0904, 0906}. The subject
builds each credential with a fresh key of that scheme:
- x509 and mldsa: a self-signed chain, as tls-subject already does;
- mtc: the chain is any opaque bytes, because AEGIS neither issues nor verifies MTCs (D-P7.4).

Only the id is compared. The subject may build a fresh `CredentialSelector` per line.

How the subject must decide:
- It must run the aegis-tls `CredentialSelector` (feature `mtc`) on `aegis_wire::tls_peek::client_hello` of the
  bytes. Driving it through a rustls `ServerConnection` with the selector as `ResolvesServerCert` is allowed, but
  the answer must equal the table.
- A rustls refusal before the resolver runs does not excuse a divergence. The generated hellos are kept close to
  real ones to make that path workable: TLS 1.3, suites 1301..1303, groups [X25519, X25519MLKEM768, P-256, P-384,
  SecP256r1MLKEM768, ML-KEM-1024], one X25519 share. The selection itself is defined on the peek.
- A credential set that aegis-bin's config loader would refuse (for example an mldsa credential on a P-PUBLIC-WEB
  listener) is still a valid request here. The selector must just never choose such a credential.

## Decision table (the reference: `ref_selector.select`)

Input: profile P, listener L, credential pool C (in configured order), ClientHello bytes B.

| step | rule | clause |
|---|---|---|
| R0 | `peek(B)` is refused → `handshake_failure`. Refused means anything the shared peek rejects (oracles/proxy-l4 README "ClientHello peek rules"): not exactly one handshake record ≤ 16384 holding exactly one ClientHello, trailing bytes, a duplicate extension, a malformed `trust_anchors` (empty or > 32-byte ID, overrun, trailing bytes), an invalid SNI, and so on. | D-P7.2/D-P7.4 fail closed |
| E0 | keep only credentials with `listener == L` | SEL-3 |
| E1 | the credential's `scheme` ∈ F12 `sigalgs` of P (read from `tls/verdicts.toml` at run time; the schemes the listener may produce, P-PQ2) | F12 |
| E2 | kind `mldsa` is never eligible on `P-PUBLIC-WEB` (holds even if F12 ever lists an ML-DSA scheme there) | SEL-2 |
| E3 | the credential's `scheme` ∈ the client's `signature_algorithms`, as the peek reads it. A missing extension = empty list. | TLS 1.3 §4.2.3 |
| E4 | kind `mtc`: its `trust_anchor_id` equals, byte for byte, one TrustAnchorID in the client's `trust_anchors` extension at codepoint **0xCA34**. A missing extension or an empty list matches nothing. Prefixes, extensions and IDs at any other codepoint do not match. | SEL-1 |
| R1 | eligible (E0..E4) `mtc` credentials exist → the **first** one in configured order | D-P7.4 "MTC when trust_anchors names it" |
| R2 | else eligible `mldsa` exist → the first one (only reachable on private-hop profiles, by E2) | D-P7.4 "else ML-DSA for private hops" |
| R3 | else eligible `x509` exist → the first one | D-P7.4 "else the classical chain" |
| R4 | else `handshake_failure`. Never a credential of another listener, never a scheme the client did not offer or the profile does not allow. | SEL-3 |

F12 sigalgs as loaded: P-PUBLIC-WEB [0403]; P-PQ-REQUIRED [0403, 0904]; P-UNIVERSAL and P-BSI-ALT [0906, 0503];
P-CNSA [0906]; FIPS-FLOOR and FIPS-PQ-REQUIRED [0403, 0503].

Order within a tier is the configured order, so the operator controls it. The client's order of trust anchors or
sigalgs does not matter, and neither do SNI, ALPN or supported_versions.

**trust_anchors codepoint:**
- draft-ietf-tls-trust-anchor-ids-07 §5.1 says `trust_anchors(TBD)`, and IANA has no entry (checked 2026-11-06,
  oracles/proxy-l4 README).
- The value used is **0xCA34**, BoringSSL's experimental `TLSEXT_TYPE_trust_anchors` (include/openssl/tls1.h,
  "not an IANA defined extension number"), as deployed in Chrome's MTC experiment.
- It is one constant: `clienthello.TRUST_ANCHORS_EXT` in oracles/proxy-l4, mirrored as `TA_CODEPOINT` in
  oracle.py. Check `constant.ta-codepoint` fails if the two differ. When IANA assigns the value, both lines change
  together, and so does aegis-wire.
- Extension body: `TrustAnchorID RequestedTrustAnchorList<0..2^16-1>`, with `opaque TrustAnchorID<1..32>`.

## Generator

Seeded `random.Random`. All ClientHellos come from the shared builder `oracles/proxy-l4/clienthello.py` (`build`,
`record`, `records`, `trust_anchors_ext`). The peek is that file's `peek`. Per case:
- **Profile:** weighted towards P-PUBLIC-WEB (30 %).
- **Listeners:** 2..4 names, the target first.
- **Credentials:** 0..5 per listener, of kind x509 / mldsa / mtc in the ratio 4:3:3. A scheme allowed by the
  profile is picked 70 % of the time. In 6 % of cases the target listener has no credentials. The pool is shuffled,
  so configured order interleaves listeners.
- **signature_algorithms:** absent 4 %. Otherwise a random subset of 14 schemes, plus each pool credential's scheme
  with p = 0.55.
- **trust_anchors at 0xCA34:** absent 25 %, empty list 5 %. Otherwise 1..4 IDs drawn from:
  - the target's MTC IDs (p 0.40);
  - other listeners' MTC IDs (0.15), which is SEL-3 bait;
  - near misses (0.25): a prefix, a one-byte extension, a one-bit flip, or the reversed bytes;
  - random IDs.
- **Decoys (15 %):** a well-formed `trust_anchors` body naming pool MTC IDs at 0xCA35, 0xCA33 or 0x1A1A (GREASE).
  60 % of the time the real extension is then dropped. Sometimes the decoy comes first in the extension order.
- **Hostile (4 %, row R0):**
  - duplicate trust_anchors;
  - an empty TrustAnchorID;
  - a 33-byte ID;
  - trailing bytes in the extension, or a list length overrun;
  - the ClientHello fragmented over two records;
  - record type 0x17, or record version 0x0304;
  - trailing bytes in the record;
  - an invalid SNI;
  - duplicate signature_algorithms.
- **SNI and ALPN:** random, and irrelevant to the table.

## What is checked

| check | how |
|---|---|
| `constant.ta-codepoint` | the shared builder's codepoint is 0xCA34 |
| `corpus.size` | ≥ 10000 generated cases (`--n`) |
| `directed.reference.<name>` | the reference gives the hand-written expected answer on 21 directed cases: SEL-1 match / no extension / empty list / other ID / prefix / extension / second in list / scheme not offered; decoy at 0xCA35 / 0xCA33 / real + decoy; SEL-2 ML-DSA offered on public / ML-DSA only; tier ML-DSA / MTC / x509 on P-PQ-REQUIRED; SEL-3 other listener's ID / other listener's scheme / listener with no credentials; duplicate trust_anchors; no sigalgs |
| `corpus.peek-consistent` | the shared peek reads back exactly the sigalgs, trust_anchors and SNI the generator built, and refuses every hostile hello |
| `coverage.R0..R4` | each table row is taken at least 150 / 800 / 500 / 800 / 800 times per 1e4 cases |
| `coverage.kills.<mutant>` | every selector mutant below changes the answer on ≥ 100 generated cases per 1e4 (the corpus can tell each planted bug apart, without the directed cases) |
| `subject.protocol` | exit 0 and exactly one answer line per request |
| `subject.directed.<name>` | the subject's answer on each directed case |
| `subject.divergence` | 0 cases where `<case> <answer>` differs from the reference, over all 10021 cases. The first 10 divergences are printed with the profile, listener, peek fields and credential pool. |

**PASS** iff every check passes.

## Self-test (negative controls)

1. The reference (`python3 -I ref_selector.py`, over the same pipe) must PASS the full run.
2. Each **selector mutant** (`ref_selector.py --mutant M`, a one-rule change to the reference) must be red:

| mutant | planted bug | unit oracle line |
|---|---|---|
| `sel1-any-trust-anchor` | MTC chosen whenever the client sent a non-empty trust_anchors list | SEL-1 |
| `sel1-ignore-trust-anchor` | MTC chosen without trust_anchors at all | SEL-1 ("MTC chosen without a matching trust anchor id") |
| `sel1-prefix-match` | an ID matches if one is a prefix of the other | SEL-1 |
| `sel2-mldsa-public` | ML-DSA exempt from the profile checks on P-PUBLIC-WEB | SEL-2 ("ML-DSA credential on a P-PUBLIC-WEB listener") |
| `sel3-other-listener` | nothing eligible → another listener's eligible credential | SEL-3 ("fallback to another listener's credential") |
| `sel3-pool-wide` | the listener filter dropped | SEL-3 |
| `ta-codepoint` | trust_anchors read from 0xCA35 (the shared `clienthello` mutant `ch-ta-codepoint`) | "parsed from the wrong extension codepoint" |
| `ta-codepoint-lenient` | trust_anchors also accepted from 0xCA33 / 0xCA35 | "wrong extension codepoint" |
| `peek-fail-open` | a refused peek falls back to the first x509 credential | fail closed |
| `tier-classical-first` | x509 before ML-DSA | D-P7.4 order |
| `tier-mldsa-over-mtc` | ML-DSA before a matching MTC | D-P7.4 order |
| `client-sigalgs-ignored` | the client's sigalgs not checked | E3 |
| `profile-sigalgs-ignored` | F12 profile sigalgs not checked | E1 |
| `tiebreak-last` | the last instead of the first in a tier | tie-break |

3. Each **protocol mutant** must be red: `drop-first-line` (one answer missing, every line shifted),
   `case-off-by-one` (one echoed case number wrong), `exit-nonzero` (all answers right, exit 3).
4. Each **corpus mutant** must make the corpus checks red:
   - `no-decoy` (decoy probability 0): `coverage.kills.ta-codepoint-lenient` goes red;
   - `no-mtc-match` (own MTC IDs never offered): `coverage.R1` goes red;
   - `no-hostile`: `coverage.R0` goes red;
   - `small-n` (9999 cases): `corpus.size` goes red.

Recorded self-test (laptop, 2026-11-06): 21/21 mutants caught. The selector mutants diverge on 243..4850 of 10021
cases. The reference shows 0 divergence. Rows: R0 407, R1 1611, R2 1422, R3 3053, R4 3507.

## Provenance and limits

- Sources: PREFLIGHT D-P7.4; PLAN-7 F8 (`tls.credentials = [{kind, trust_anchor_id?, chain, key}]`) and F1 SEL-1..3;
  F12 `tls/verdicts.toml` (profile sigalgs, scheme codepoints); draft-ietf-tls-trust-anchor-ids-07 §5.1;
  draft-ietf-plants-merkle-tree-certs-08 (negotiation is trust_anchors only, with no new SignatureScheme, so an
  MTC credential's key signs with an ordinary scheme). No research artifact was ported or run.
- P7-spec-001 had not landed when this was written. If its frozen F8 puts `tls.credentials` under each listener,
  the `listener` field of a credential token is just that listener's name. If the F1 text tightens a rule, the
  table follows the frozen text and this README records the change. Loosening a rule needs INFEASIBLE_REPORT.md.
- Rung: the selector logic reaches R2 against this decision table (differential, ≥ 1e4 cases). There is no claim
  about MTC validity, issuance or transparency: the credential is opaque (D-P7.4).
- The oracle judges selection only. A full handshake with the chosen credential is not checked here; the carried
  tls gates cover handshakes.
- Red until P7-mtc-001: today `tls-subject` has no `select` mode, so it prints a usage error, exits 1 and gives 0
  answers. See units/phase-7/reports/P7-oracle-sel-001.md.
