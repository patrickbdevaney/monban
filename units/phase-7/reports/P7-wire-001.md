# P7-wire-001 report (implementer, 2026-11-06, base 4789bce)

aegis-wire now has its real parsers in place of the P7-spec-002 fail-closed stubs:
- the PROXY protocol v2 header parser (F1 PROXY-1..3, PREFLIGHT D-P7.2);
- the bounded TLS ClientHello peek (F1 L4-1, and the `trust_anchors` input of D-P7.4).

It also has the vector tests, the Kani harnesses for gate kani-wire, and the full fuzz properties and seeds for
`proxy_v2` and `client_hello_peek`. The receiver rules are the proxy-l4 oracle's (`oracles/proxy-l4/README.md`).
Nothing outside write_scope was edited.

## 1. Public API (final)

`aegis_wire` is L2 with no dependencies. It is `#![forbid(unsafe_code)]` and `no_std` (`cfg_attr(not(kani),
no_std)`), with no allocation anywhere. Every borrowed field is a sub-slice of the input.

**`aegis_wire::proxy`**
- `parse_v2(&[u8]) -> Result<(Header<'_>, usize), ProxyError>`. The `usize` is consumed, which is exactly
  `16 + declared len`, at most `MAX_HEADER_LEN` = 552.
- `looks_like_proxy(&[u8]) -> bool`: a non-empty prefix of the v2 signature or of `PROXY`. This is for the PROXY-1
  refusal on untrusted sources.
- consts: `SIGNATURE`, `MAX_DECLARED_LEN` = 536, `FIXED_LEN` = 16, `MAX_HEADER_LEN`, and the
  `tlv::{ALPN, AUTHORITY, CRC32C, NOOP, UNIQUE_ID, SSL, NETNS}` type codes.
- `Header<'a> { pub command: Command, pub family: Family, pub transport: Transport, pub addresses: Addresses<'a>, /* validated TLV region, private */ }`, with three methods:
  - `source() -> Option<SocketAddr>`: `Some` only for PROXY over TCP4/TCP6. `None` means use the TCP peer.
  - `stream_accept() -> bool`: false for PROXY + DGRAM with addresses, which aegis-bin refuses by policy.
  - `tlvs() -> Tlvs<'a>`: an iterator of `Tlv { kind: u8, value: &[u8] }`.
- `Command { Local, Proxy }`, `Family { Unspec, Inet, Inet6, Unix }`, `Transport { Unspec, Stream, Dgram }`.
- `Addresses<'a>`:
  - `Unspec`;
  - `Inet { src: SocketAddr, dst: SocketAddr }`, used for v4 and v6;
  - `Unix { src: &[u8], dst: &[u8] }`, the raw 108-byte fields.
- `ProxyError { Incomplete, V1Refused, TooLong, Malformed }`. Only `Incomplete` means "read more". It turns into a
  close at EOF or the deadline.

**`aegis_wire::tls_peek`**
- `client_hello(&[u8]) -> Result<Peek<'_>, PeekError>`. It reads one record of at most `MAX_RECORD` = 16384 body
  bytes.
- `Peek<'a> { pub sni, pub alpn, pub versions, pub sigalgs, pub groups, pub trust_anchors: Option<&'a [u8]>, pub consumed: usize }`.
  - Fields:
    - `sni` is the host_name bytes, case as sent;
    - the others are validated list bodies;
    - `consumed` = 5 + record length.
  - Iterators:
    - `alpn_protocols()` and `trust_anchor_ids()` yield `&[u8]`;
    - `version_list()`, `sigalg_list()` and `group_list()` yield `u16`.
- consts: `MAX_RECORD`, `RECORD_HEADER` = 5, `EXT_SERVER_NAME`, `EXT_SUPPORTED_GROUPS`,
  `EXT_SIGNATURE_ALGORITHMS`, `EXT_ALPN`, `EXT_SUPPORTED_VERSIONS`, `EXT_TRUST_ANCHORS` = 0xCA34.
- `PeekError { Incomplete, TooLong, NotClientHello, Malformed }`.

**Changes against the P7-spec-002 stub shapes.** No crate used the stubs: aegis-tls and aegis-bin only declare the
optional dependency.
- The `Unimplemented` variants are removed.
- `Header` gains a lifetime and `family`, `transport` and TLV access.
- `Addresses::Unix` carries the paths.
- `Peek` gains `groups` and `consumed`.

## 2. Implementation notes

- **Reader.** All reads go through `rd::Rd`, a bounds-checked cursor built on `split_at_checked`, `split_first` and
  `get`. There is no indexing. The parser only ever hands it the declared region: `input.get(..16 + n)`, or
  `input.get(..5 + n)`.
- **Two stages.** The PROXY parse is the fixed part and the address block, then `check_tlvs`. The peek is
  `record`, then `hello_body`, then `extensions`.
- **Flat state machines.** `check_tlvs` and `extensions` are one byte-at-a-time pass over their region, with no
  nested loop:
  - the TLV framing, the AUTHORITY UTF-8 DFA and the SSL sub-TLV framing are state machines fed the same byte;
  - the same holds for the extension framing and each extension's inner format.

  The first versions were nested reader loops, and Kani could not bound them (§4). The vector, differential and
  fuzz results below were all re-run on the flat versions.
- **CRC32C and UTF-8.** CRC32C is bitwise (RFC 4960 App. B; tested against the RFC 3720 check value). It runs as
  one pass over the declared header, with the field zeroed by position. UTF-8 is our own Table 3-7 DFA. A unit test
  checks it against `core::str::from_utf8` on every 1-, 2- and 3-byte input and on 1.18 M 4-byte inputs. It replaces
  `from_utf8`, whose word-at-a-time path Kani could not bound.
- **Duplicate extensions.** The duplicate check is a 65 536-bit `BitSet` (8 KiB on the stack). That keeps the check
  linear on a hostile 16 KiB block of up to 4096 extensions. A rescan would be about 8 M compares per hello. The
  check sits behind a crate-private `TypeSet` trait (see §4).
- **Fixed rejections.** A v1 header, or any prefix of `PROXY`, is `V1Refused`. A declared length over 536 is
  `TooLong` as soon as the 16-byte fixed part is in. A record length over 16384 is `TooLong` from the 5-byte header.

## 3. Tests (`ci/remote.sh cargo test -p aegis-wire --locked`): 9 passed

- **Vector tests.** `vector_tests::proxy_v2_vectors` covers 242/242 vectors (41 ok, 189 reject, 12 incomplete).
  `client_hello_vectors` covers 84/84 (23 ok, 59 reject, 2 incomplete).
  - The JSON is read with `include_str!("../../../oracles/proxy-l4/vectors/*.json")` and a minimal test-only JSON
    parser, since the crate has no dependencies.
  - For every ok vector, every field the reference compares is checked:
    - PROXY: consumed, command, family, proto, src/dst (IP, or the hex of the NUL-stripped UNIX path), ports, peer,
      stream_accept, tlvs;
    - ClientHello: sni, alpn, versions, sigalgs, groups, trust_anchors (null vs [] vs ids), consumed.
  - Every borrowed slice is checked to lie inside the consumed bytes.
  - Reject classes are not compared, since the README makes them informational for Rust.
- **Other tests.**
  - `prefixes_of_accepted_vectors_are_incomplete`: every proper prefix of every ok vector is `Incomplete`.
  - `trailing_bytes_do_not_change_the_result`.
  - `v1_and_its_prefixes_are_refused`.
  - `crc32c_check_value`, including the zeroed form.
  - `valid_utf8_matches_core`.
  - `valid_host_matches_spec`: the one-pass LDH machine against the split-based definition, on every string of
    length ≤ 7 over a 7-character alphabet, plus label and host length edges.
  - `bitset_is_an_exact_set`: all 65 536 values, injective, and re-insert refused.
- **Mutation check (manual, reverted).** Each test was made to fail by a planted bug:
  - skipping the AUTHORITY UTF-8 check gives 8 PROXY divergences;
  - skipping the duplicate-extension check gives 3 ClientHello divergences.
- **Differential run (one-off, not committed).** `gen_mutants.py` (scratchpad) made 135 958 single-byte and
  truncation mutants of every vector:
  - 62 534 PROXY mutants, of which 6 914 ok, 53 788 reject and 1 832 incomplete;
  - 73 424 ClientHello mutants, of which 17 402 ok, 54 728 reject and 1 294 incomplete.

  Each was labelled by the oracle's own reference parsers (`proxyv2.parse`, `clienthello.peek`). Through the same
  Rust comparison there were **0 divergences**, fields included, on the final flat-state-machine code.

clippy: `ci/remote.sh cargo clippy -p aegis-wire --all-targets --locked -- -D warnings` is clean. `cargo fmt` is
clean.

## 4. Kani (gate kani-wire): what is proven, and the bound

`ci/kani.sh --serial --mem 6G -p aegis-wire`, run from the laptop to kamrui (Kani checkout 9461e07, a descendant of
16c774cf). Result: `KANI: PASS`, `KANI SELF-TEST: PASS`, with 21/21 positive harnesses OK and the negative control
FAIL_AS_EXPECTED.

| harness | wall | peak |
|---|---|---|
| proxy_exact_16 | 45 s | 1.3 G |
| proxy_exact_28 | 73 s | 2.2 G |
| proxy_exact_32 | 267 s | 3.1 G |
| proxy_exact_35 | 383 s | 3.6 G |
| proxy_exact_52_inet6 | 160 s | 3.7 G |
| proxy_tlvs_total | 219 s | 3.5 G |
| proxy_tlvs_10 | 40 s | 0.8 G |
| proxy_short_total | 619 s | 3.0 G |
| proxy_not_all_there_never_ok | 23 s | 0.5 G |
| proxy_declared_length_cap | 11 s | 0.3 G |
| peek_record_prefix_determined | 12 s | 0.4 G |
| peek_exact_50 | 37 s | 0.8 G |
| peek_exact_56 | 43 s | 1.0 G |
| peek_exact_62 | 230 s | 2.2 G |
| peek_body_total | 39 s | 0.7 G |
| peek_iterators_total | 65 s | 1.2 G |
| peek_ext_total | 127 s | 2.1 G |
| peek_ext_10 | 101 s | 1.4 G |
| peek_ext_12 | 85 s | 1.0 G |
| peek_not_all_there_never_ok | 12 s | 0.3 G |
| peek_record_length_cap | 4 s | 0.1 G |
| negative_control_planted_oob | FAIL_AS_EXPECTED (its own NEGATIVE CONTROL assertion) | |

The total is about 43 min.

**Rung.** This is R2 on the Rust code, bounded. It proves no panic (overflow, bounds, unwrap),
`consumed <= input`, consumed = the declared size, and borrowed fields inside the declared bytes. For PROXY it also
proves that the result on the input equals the result on the declared prefix. For the ClientHello the same holds at
the record stage, which is the only stage that sees the raw input.

**Harness shape.** The shape is dictated by what CBMC can finish within the kani.sh limits (6 G, 1800 s). These
were each tried and failed first:
- A symbolic input or declared length did not finish in 1800 s. Neither did a `for len in ..` loop, whose counter
  is merged into a symbolic value. So every harness fixes the lengths as concrete bytes or literals, and every other
  byte is symbolic.
- Nested loops over symbolic sizes did not finish in 900–1200 s: the TLV × UTF-8 loops, the extension ×
  host/ALPN/trust-anchor loops, and ListSet's `contains` inside the extension loop. Hence the flat state machines.
- Buffers over 64 bytes exceed CBMC's field-sensitivity limit. The concrete length bytes then stop propagating, so
  the 232-byte UNIX whole parse did not finish in 900 s.
- The 8 KiB `BitSet` ran out of the 6 G cap inside a parse. Even three symbolic inserts into it alone did not
  finish in 1200 s.

**Composition.** So the proofs are compositional:
- `proxy_exact_{16,28,32,35}`: the whole PROXY parse with family/protocol symbolic. At L = 35 it reaches CRC32C.
- `proxy_exact_52_inet6`: the whole parse with that byte concrete.
- `proxy_tlvs_total` (regions of 0..=8 bytes) and `proxy_tlvs_10`: `check_tlvs` alone, fully symbolic. They reach
  CRC32C, AUTHORITY, UNIQUE_ID, SSL and its sub-TLVs, and a duplicate CRC32C.
- `peek_exact_{50,56,62}`: the whole peek with the hello-field lengths concrete.
- `peek_body_total` (bodies of 44..=64 bytes) and `peek_ext_total` / `peek_ext_10` / `peek_ext_12` (blocks of
  0..=12 bytes): the stages alone, fully symbolic.
- `peek_record_prefix_determined`, `peek_iterators_total`.
- The short-input, not-all-there and cap harnesses for both parsers. These call the shipped `parse_v2` /
  `client_hello` with symbolic header bytes.

**Not covered by Kani** (covered by the vectors, the differential run and fuzz instead):
- the UNIX address branch in a whole parse (it is two checked splits);
- TLV regions over 10 bytes and extension blocks over 12 bytes;
- whole-peek runs with symbolic hello-field lengths (each stage is covered alone).

**The BitSet link is a test.** The ClientHello stage harnesses run the generic `extensions`/`client_hello_with`
code with `ListSet`, an exact list-backed set in kani_proofs.rs, not with `BitSet`. The link "BitSet is an exact
set" is the exhaustive unit test, not a Kani proof.

The negative control `negative_control_planted_oob` fails on its own NEGATIVE CONTROL assertion (FAIL_AS_EXPECTED).

## 5. Fuzz

**Targets.** Both targets now assert the full property set.

`proxy_v2`:
- consumed = 16 + declared, ≤ input, ≤ 552;
- every TLV and UNIX path inside the header;
- the result on the declared prefix equals the result on the whole input;
- a declared length over 536 is refused from the fixed part;
- v1 or any `PROXY` prefix is `V1Refused`;
- proper prefixes of an accepted header are `Incomplete`.

`client_hello_peek`:
- a handshake record of 1..=16384 bytes, with consumed = 5 + length ≤ input;
- every field inside the record body;
- the result on the declared prefix equals the result on the whole input;
- an over-cap record is refused;
- the SNI is LDH, ALPN names are non-empty, TrustAnchorIDs are 1..=32;
- the iterators walk;
- proper prefixes are `Incomplete`.

The planted `selftest!` lines are unchanged.

**Seeds.** `fuzz/corpus/proxy_v2/` has 242 files and `fuzz/corpus/client_hello_peek/` has 84: one per oracle
vector, named by vector id. The self-test still starts from `examples/seeds.rs`, as before.

**Runs.**
- `ci/remote.sh ci/fuzz.sh run --execs 10000000 --targets proxy_v2,client_hello_peek` gives
  `FUZZ: PASS (2/2 targets reached 10000000 execs, 0 crashes/timeouts/OOMs; skipped: none)`. That is about 370k and
  303k exec/s on the desktop.
- `ci/remote.sh ci/fuzz.sh self-test --targets proxy_v2,client_hello_peek` gives
  `FUZZ: PASS (self-test: 2/2 planted panics found within 1e6 execs …)`.

## 6. Acceptance

**The unit's `acceptance.cmd`, run literally: FAIL at step 2, without running any harness.** The cause is §7.1.

| step | tail |
|---|---|
| `ci/remote.sh cargo test -p aegis-wire --locked` | `test result: ok. 9 passed; 0 failed` |
| `ci/remote.sh --host kamrui ci/kani.sh --serial --mem 6G -p aegis-wire` | `ssh: Could not resolve hostname kamrui` / `kani.sh: ssh kamrui failed` / `KANI: FAIL` / `KANI SELF-TEST: FAIL` |

**The same command, with step 2 run the way kani.sh works (from the laptop, which reaches kamrui over ssh): PASS.**

| step | tail |
|---|---|
| `ci/remote.sh cargo test -p aegis-wire --locked` | `test result: ok. 9 passed; 0 failed; 0 ignored` |
| `ci/kani.sh --serial --mem 6G -p aegis-wire` (runs on kamrui) | `KANI: PASS` / `KANI SELF-TEST: PASS` (exit 0) |
| `ci/remote.sh ci/fuzz.sh run --execs 10000000 --targets proxy_v2,client_hello_peek` | `FUZZ: PASS (2/2 targets reached 10000000 execs, 0 crashes/timeouts/OOMs; skipped: none)` |

The `must` clauses:
- PASS;
- aegis-wire is L2, no_std, with no allocation anywhere and `forbid(unsafe)`;
- `proxy::parse_v2(&[u8]) -> Result<(Header, consumed)>`, with v1 refused and len ≤ 536;
- `tls_peek::client_hello(&[u8]) -> Result<Peek{sni, alpn, versions, sigalgs, trust_anchors, …}>`, reading one
  record of at most 16 KiB;
- Kani shows no panic, consumed ≤ input, and no read past the declared length, within the bounds in §4;
- the oracle vectors pass at the parser level, 242/242 and 84/84.

## 7. Outside write_scope: needs the integrator

1. **The acceptance command cannot pass as written.**
   - `ci/remote.sh --host kamrui ci/kani.sh …` runs kani.sh *on* kamrui. kani.sh then does `ssh kamrui`, which fails
     there: `ssh: Could not resolve hostname kamrui`, so `KANI: FAIL` with no harness run.
   - kani.sh is built to run from the laptop and reach the prover over ssh, which is how P7-spec-002 ran it.
   - Suggested fix in `units/phase-7/P7-wire-001.json`: `ci/kani.sh --serial --mem 6G -p aegis-wire`, without the
     `ci/remote.sh --host kamrui` prefix.
   - I ran the acceptance with exactly that substitution (§6).
   - **The gate has the same defect.** In `gates/phase-7.toml`, gate `kani-wire` has `remote = "kamrui"`. run-gates.py
     line 73 turns that into `ci/remote.sh --host kamrui bash -c 'ci/kani.sh …'`, which reproduces the failure.
   - The carried gates `kani-tbi` and `kani-kx` have no `remote` key and run kani.sh from the laptop. Suggested fix:
     drop `remote = "kamrui"` from kani-wire.
2. **Runtime.** The full kani-wire suite takes about 43 min on kamrui. That is serial, the
   longest single harness is about 11 min, and every harness is under the 1800 s default timeout and the 6 G cap.
