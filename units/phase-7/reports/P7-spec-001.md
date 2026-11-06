# P7-spec-001 report (spec author, 2026-11-06)

Gates owned: `no-quic`, `no-otel-in-bin`. Interfaces: F8 additive amendment, F1 §F addendum, both re-frozen in
the same commit.

## Delivered

- **`ci/no-quic.py`** (gate `no-quic`). It fails if any QUIC, HTTP/3 or WebTransport crate shows up in either of
  two places:
  - the shipped locks: Cargo.lock, profiles/cmvp/Cargo.lock, and fuzz/Cargo.lock when present;
  - the aegis-bin graph (`cargo tree --offline -e normal,build --target all`), with default features and with
    `--all-features`.

  The banned names are quinn\*, h3 / h3-\*, wtransport\*, web-transport\*, quiche, tokio-quiche, s2n-quic\*, neqo-\*,
  msquic and tquic. `h3` matches only exactly or with a `-` suffix, so `h3o` is not flagged.

  `--self-test` must go red on 8 mutants: the mandatory fixture lock with quinn-proto 0.11.19, the mandatory
  `--all-features` tree with h3, and one tree each for h3-quinn, wtransport, web-transport-quinn, quinn-udp,
  s2n-quic and quiche. It must stay green on a clean lock and a clean tree; the clean tree includes the look-alike
  names h3o, h2 and quickcheck.
- **`--self-test-otel`** (selftest of gate `no-otel-in-bin`). It reads the gate's own cmd from gates/phase-7.toml
  and runs its exact `grep -qE` filter on fixture trees. The filter must go red on prost, opentelemetry\* and tonic,
  and stay green on the clean tree. The self-test also goes red if the gate cmd stops being a
  `cargo tree -p aegis-bin --all-features --prefix none -e normal,build` pipeline.
- **`ci/h3-precondition.py`**. This is a manual check, never a gate.
  - Live mode makes these requests, all with `User-Agent: aegis-ci`:
    - GitHub REST for hyperium/h3 pulls 366/377/378 (state, merged_at);
    - crates.io for the h3 release dates (yanked releases ignored);
    - the GitHub repository advisories of quinn-rs/quinn, plus OSV querybatch for quinn, quinn-proto and quinn-udp
      and OSV vulns/{id}. Advisories are deduplicated by id and alias, and withdrawn ones are ignored.
  - Severity comes from the GitHub `severity`, else OSV `database_specific.severity`, else the CVSS 3.x base score.
    An unrated advisory counts as HIGH (fail closed).
  - (a) is met only when all three PRs are merged and an h3 release was published after the last merge. (b) is met
    on or after last HIGH + 6 calendar months.
  - `--record FILE` saves the trimmed live responses. `--offline-selftest` replays them through the live code path
    on ci/fixtures/h3-precondition/\*.json. There are 15 fixtures, including the three mandatory ones:
    - `met.json` → MET;
    - `snapshot-2026-11-06.json` (recorded live today) → NOT MET;
    - `high-day-179.json` → NOT MET.

    The other fixtures cover the 6-month boundary (exact day / day before), merged with no release, a release
    before the last merge, a yanked release, a PR still open, a MEDIUM, a withdrawn HIGH, a CRITICAL on quinn-udp,
    an unrated OSV advisory, and CVSS 7.5 and 5.3 vectors.

    Live verdict 2026-11-06: `NOT MET (a: PR #366 open, #377 open, #378 open; latest h3 0.0.8 2025-05-06; b: 9
    HIGH + 1 lower in 2026-05-06..2026-11-06; last HIGH GHSA-53rm-773f-4q8c 2026-09-30, clock ends 2027-03-30)`.
- **F8 (`interfaces/F8-config.schema.json`)**. Every addition is optional. A config without them means what it
  meant before Phase 7 and has the same effective form and config_hash: defaults are not printed in the hashed form,
  and the `--print-effective` dump shows them.
  - `listeners[].proxy_protocol = {trusted: [CIDR]}`, 1..64 entries, unique. Each entry must be canonical text,
    with host bits zero, no /0 and no IPv4-mapped IPv6 prefix.
  - `listeners[].l4 = [{sni, upstream}]`, 1..1024 entries. SNI must be an exact A-label and unique; upstream is
    `host:port` or `[v6]:port`. An L4 listener with `alpn` is refused (`Forbidden`).
  - `listeners[].front = epoll | uring`, default epoll.
  - Root `tls.credentials` (1..64): `{id, kind x509|mldsa|mtc, trust_anchor_id, chain, key, listeners?}`.
    - `trust_anchor_id` is required for mtc and forbidden otherwise.
    - `chain` and `key` are `cred:` or `path:` references, never inline.
    - Ids are unique, and mtc trust_anchor_ids are unique.
    - `listeners` must name declared listeners that are not L4.
    - An mldsa credential scoped to a P-PUBLIC-WEB listener is refused (`CredentialScope`).
  - Backend engines `mariadb` and `crdb`. Each pin must have the same `kind` as the engine.
  - **Integrator addition (coordinator message): root `admission`.**
    - Members: `per_ip {rate_per_s 1..1e6, burst 1..1e7, burst >= rate}`, `per_ip_store 1024..1048576`,
      `max_conns`, `per_prefix_conns` and `concurrency` (each 1..1048576).
    - The defaults are exactly the constants hard-coded in aegis-bin `shared.rs admission_config()`:
      `Gcra::new(1_000_000, 2_000)`, s1_store 65536, max_conns 16384, prefix_cap 4096, limit 4096.
    - `RateLimit::emission_interval_ns()` = floor(1e9 / rate); for 1000/s it gives 1_000_000, today's value.
    - A block equal to the defaults is not hashed. A burst below the rate is refused (`BurstBelowRate`).
- **F1 §F addendum**: PROXY-1..3, L4-1..2, SEL-1..3 and FRONT-1. Every clause is at R0 (statement only) until its
  gate passes: proxy-l4/kani-wire, cred-select or front-equiv. The addendum also records the HTTP/3 deferral and its
  evidence. It is prose only, so the Lean statement ledger was re-frozen unchanged (144 declarations).
- **aegis-config parses all of it**:
  - new `p7` module: `Front`, `Cidr`, `ProxyProtocol`, `L4Route`, `TlsBlock`, `Credential`, `CredentialKind`,
    `SecretRef`, `TrustAnchorId` with `wire()`, `Admission`, `RateLimit`, and `TlsBlock::candidates` with the SEL-2
    and L4 exclusions;
  - new ErrorKinds: Forbidden, DuplicateSni, DuplicateCredential, DuplicateTrustAnchor, UnknownListener,
    CredentialScope, BurstBelowRate;
  - tests: tests/p7.rs (schema mirror plus accept/reject corpus), unit tests for adapter families against injected
    pins, and a sixth totality seed with Phase-7 tokens and `p7_invariants`.

## Design note: mariadb/crdb are `AdapterFamily`, not new `Engine` variants

aegis-bin `native/mod.rs` matches `aegis_config::Engine` exhaustively. Adding variants would have broken the
`native` build, and aegis-bin is outside this unit's scope (single writer P7-bin-001). So the new families are a
separate type:
- `DataBlock::adapters()` holds them, and `backends()` keeps exactly the Phase-4 view. Ids are unique across both,
  and document order is kept in the effective form.
- `SchemaProvider::adapter_field` has a default that refuses (`Unavailable`). An assembly that predates the
  families therefore fails the boot on any endowment naming one, instead of resolving it as another engine.
- Pins: `adapter_pins()` / `adapter_pin()`. A pin entry whose `kind` is mariadb or crdb is parsed into a separate
  list.

## Acceptance (acceptance.cmd, run in the worktree)

```
NO-QUIC: PASS (no QUIC/HTTP3/WebTransport crate; Cargo.lock 319 pkgs; profiles/cmvp/Cargo.lock 327 pkgs; fuzz/Cargo.lock 74 pkgs; aegis-bin default 79 nodes; aegis-bin all-features 84 nodes)
NO-QUIC SELF-TEST: PASS (8 mutants rejected, 2 clean controls accepted)
NO-OTEL SELF-TEST: PASS (gate filter "grep -qE '^(opentelemetry[a-z_-]*|prost|tonic) '": red on prost/opentelemetry/tonic trees, green on clean)
H3-PRECONDITION SELF-TEST: PASS (15 fixtures: 5 MET, 10 NOT MET, each as expected)
INTERFACES: PASS (16 frozen files unchanged)
STATEMENT GATE: PASS (144 frozen declarations unchanged)
```

Also run:
- The no-otel-in-bin gate cmd passes on the real tree.
- config-totality (desktop, `ci/remote.sh`, `AEGIS_CONFIG_ITERS=1000000 cargo test --release -p aegis-config`):
  `totality: 1000000 inputs, 23975 accepted (2887 with p2, 3526 with phase-7 members), 976025 rejected (14955 in p2,
  11536 in phase-7 members)`, PASS. The full aegis-config debug suite passes (560 tests).
- clippy `-D warnings` passes on aegis-config (all targets), on aegis-bin `--all-features --all-targets`, and on
  aegis-ops, host-subject and transport-subject.
- `ci/interfaces.py self-test`, `ci/unrestricted.py --self-test` and `cargo xtask layering` all PASS.

## Discrepancy noted

PREFLIGHT P1 says "10 HIGH + 1 MEDIUM" for quinn in 2026-05-06..2026-11-06. The live count, after deduplicating
GitHub and OSV records by alias, is 9 HIGH + 1 MEDIUM: three HIGH on 2026-09-30, three on 2026-09-14, two on
2026-08-17 and one on 2026-06-22, plus the MEDIUM GHSA-hmxj on 2026-08-17. GHSA-6xvm (2026-03-09) is outside the
window. The verdict and the clock end date are unchanged.

## Infeasible

Nothing.

## Follow-ups for other units

- **P7-bin-001**:
  - Wire `Config::admission()` into `admission_config()`: `s1` / anon / session / verified =
    `Gcra::new(per_ip.emission_interval_ns(), per_ip.burst)`, `s1_store`, `max_conns`,
    `prefix_cap = per_prefix_conns`, `limit = concurrency`.
  - Refuse at boot (exit 78) when a member's feature is absent: `proxy_protocol`, `l4`, `front: uring`, a `tls`
    block, and adapter-family backends.
  - Use `ProxyProtocol::admits` for PROXY-1. It matches an IPv4-mapped peer as IPv4.
  - Use `limits.stall_timeout_ms` as the L4-1 deadline.
  - Implement `SchemaProvider::adapter_field` for the families it wires.
- **P7-mtc-001 / P7-oracle-sel-001**:
  - `TrustAnchorId::wire()` encodes the DER RELATIVE-OID contents octets; please confirm against
    draft-ietf-tls-trust-anchor-ids-07 when recording the codepoint.
  - `TlsBlock::candidates(cfg, listener)` gives the scoped candidate list (SEL-2 and L4 already excluded).
- **P7-oracle-adapters-001**: engine-pins.toml entries must use `kind = "mariadb"` / `kind = "crdb"`, or
  aegis-config refuses the backends (`UnknownPin` / `PinEngineMismatch`). ci/engines.sh and the aegis-adapter-pg
  build.rs floor parser must accept those kinds.
- **Integrator (gates file, not in this scope)**: the `no-otel-in-bin` cmd has no `--target all`, so
  platform-specific deps outside the host target are not seen. no-quic.py does use `--target all`. Consider adding
  it; the otel self-test would keep passing.
