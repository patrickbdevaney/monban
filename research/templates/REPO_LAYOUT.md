# REPO_LAYOUT (template, v4, 2026-10-25)

Source: ARCHITECTURE.md v4 §3, §8. Grades per META §3; **[E]** = no evidence node. "Monban"/`monban-` is a placeholder name (RFC 10032 collision; rename before public release).

## 1. Toolchain and pin table (re-verified 2026-10-25)

**Pin rule (one rule everywhere).** `Cargo.toml` uses caret ranges + security floors. The versions in the "lock target" column are what the **golden `Cargo.lock`** must resolve to, enforced by `xtask lock-targets` over `cargo metadata`. `=` pins appear only in the **cmvp** FIPS profile (`profiles/cmvp/Cargo.toml`), because certification needs module byte identity.

| item | floor (Cargo.toml) | lock target | grade | note |
|---|---|---|---|---|
| rustc/cargo | `rust-toolchain.toml` = 1.99.1 | 1.99.1 (58cf8f9c3) | A | repro identical on 1.98/1.99.1, differs on 1.93.1. Native `global-min-publish-age` only from 1.100 → `xtask lock-age` until bump |
| hyper / h2 | ≥1.12.0 / ≥0.4.20 | 1.12.0 / 0.4.20 | A | + Monban wrapper (R-TLS-1) |
| rustls | ≥0.23.46, `prefer-post-quantum` on every instance | 0.23.46 (+ backported 28ee6c68 PreferServerOrder patch, ledgered) | A | no 0x11ED upstream (#3293 closed unmerged) → `monban-tls::kx::SecP384r1MlKem1024` is ours |
| rustls-webpki | ≥0.103.16 | 0.103.16 | A | cooldown bypass mandatory (7-day window lands 0.103.15) |
| aws-lc-rs | floor profile ≥1.18.2 | 1.18.2 | A | AWS-LC FIPS 4.2.0 source, uncertified |
| cmvp profile | rustls `=0.23.43`, aws-lc-rs `=1.15.3`, aws-lc-fips-sys `=0.13.11` | same | A | CMVP #5298/#5314; AL2023 OEs only; fips-sys 0.14.3 is the decoy |
| tokio | ≥1.54.1; x.y.0 blocked 14 days | 1.54.1 | A | |
| wasmtime (feature `p2`) | ≥49.0.4 (or 36.0.19 LTS) | 50.0.0 | A | `default-features=false` |
| cedar-policy / symcc | ≥4.14.0 / 0.8 | 4.14.0 | A | G10 watches GHSA-m84h |
| rmcp | ≥3.7.0 | 3.7.0 | A | re-audit per bump |
| quinn-proto (feature `h3`, off) | ≥0.11.19 | — | A | phase 7 |
| serde_json | 1.0.154 + dup-rejecting visitor | 1.0.154 | A | simd-json, sonic-rs banned |
| postcard / serde_bytes | 1.1.3 | 1.1.3 | A | bincode banned |
| governor | 0.10.4 | 0.10.4 | A | |
| redb (alt store) / rusqlite | 4.4.0 / SQLite ≥3.51.3 | — | A | |
| instant-acme | 0.8.5 `fips` | 0.8.5 | B | 8 months without release: watch; alt rustls-acme |
| Lean 4 | v4.35.0 @eb6cafb, Init-only, `lakefile.toml` zero `require` | — | A | 712 MB carve; re-verify carve on each pin |
| Verus | release/0.2026.10.18.7d82994 | — | A | CI only, 3.16 GB |
| Kani | main commit ≥ PR #4910 (not release 0.68.0) | — | A | 0.68.0 false-PASSes on CBMC OOM (#4905) |
| TLC | tla2tools.jar by sha256 | — | B | 362 MB / 2.67M states |
| gate tools | cargo-deny 0.20.2, cargo-audit 0.22.2, cargo-vet 0.10.3, cargo-geiger 0.14.0, cargo-mutants 27.1.0, cargo-fuzz 0.13.2, cargo-auditable 0.7.7, cargo-cyclonedx 0.5.9, nextest 0.9.149, trybuild 1.0.122, proptest 1.12.0, turmoil 0.7.2, zizmor (pedantic), **cosign ≥3.1.0** (DSSE → Rekor v2), tuftool ≥0.15, tough =0.24.0 | — | A | |

Laptop-required toolchain: Lean 712 MB + elan 13 MB + TLC + Rust. Verus, Kani, EverParse, F*, Apalache are CI only. No prover binary ships in the image; toolchain sha256 values go into the release attestation.

## 2. Workspace tree

```
monban/
  rust-toolchain.toml            # 1.99.1
  Cargo.toml                     # workspace; caret + floors; features h1,h2,tls,pq default
  Cargo.lock                     # integrator/bot only
  profiles/cmvp/                 # FIPS cmvp lock (=pins), its own Cargo.lock + checksum gate
  supply-chain/                  # cargo-vet store, exceptions.toml (expiring ledger), deny.toml
  spec/                          # L0 Lean package + SPEC_INVARIANTS.md (hashed, CODEOWNERS)
    AegisIR/Lowering.lean Token.lean Combine.lean Vacuity.lean
    Canon/ Budget/ Write/ Select/   # new in plan: grammar, TBI composition, W1–W6, kx selection
  interfaces/                    # F2–F13 frozen artifacts (hashed)
  crates/
    monban-types/  monban-canon/  monban-budget/  monban-token/  monban-authz/
    monban-data-ir/  monban-config/  monban-admission/
    monban-tls/  monban-transport/  monban-agent/  monban-egress/  monban-audit/  monban-metrics/
    monban-state/  monban-iso/  monban-ops/  monban-wasm/
    monban-adapter-pg/  monban-adapter-sqlite/  monban-adapter-redis/  monban-adapter-host/
    monban-bin/
  sdk/monban-sdk/                 # separate trust zone; agents may not edit
  oracles/                       # never linked into the binary
    lowering-read/ lowering-write/ canon-diff/ mcp-corpus/ hrr-verdicts/ cancel-sweep/
    isolation-fi/ crash-harness/ swarm-sim/ upgrade-harness/ ipcbench/ known-false-proofs/
  conformance/                   # C0–C4 suite, signed JSON report
  tls/verdicts.toml              # F12: PUB-T1..T6 + FIPS-F1..F6
  ci/  gate.sh axiom_audit.py kani.sh heavy.sh
  gates/phase-0.yaml … phase-7.yaml
  units/                         # unit JSONs (IMPLEMENTATION_PLAN §6)
  xtask/                         # layering, lock-age, lock-targets, repo-advisories, fips_lock_gate,
                                 # allowlist-lock, draft-tag lint, feature-delta, budget
  bench/                         # BENCH_PLAN harness, baseline configs
  deploy/  monban-hardened.service  monban.socket  k8s/
```

## 3. Layering rule (machine-checked by `xtask layering`)

```
L0 spec (Lean, not linked)     spec/
L1 pure types                  monban-types
L2 pure logic (sans-IO)        monban-canon, monban-budget, monban-token, monban-authz, monban-data-ir, monban-config, monban-admission
L3 protocol shells             monban-tls, monban-transport, monban-agent, monban-egress, monban-audit, monban-metrics
L4 effects / OS                monban-state, monban-iso, monban-ops, monban-adapter-*, monban-wasm (feature p2)
L5 assembly                    monban-bin
SDK                            monban-sdk -> L1, L2 only; app crates -> monban-sdk only (no tokio/axum deps)
tools                          xtask, oracles/*, conformance/, bench/  (never linked)
```
A crate depends only on lower layers. Negative control: a PR adding `monban-transport → monban-adapter-pg` must fail.

## 4. Crate table

| crate | role | allowed deps | first-party unsafe | assurance |
|---|---|---|---|---|
| spec/ | Lowering, Token, Combine (checked); Canon grammar, TBI composition, GCRA I1/I2/I8, Write W1–W6, kx selection (planned) | none (Init only) | n/a; native_decide/bv_decide banned; axioms ⊆ {propext, Classical.choice, Quot.sound} | `ci/gate.sh`; `lake check --paranoid` 6 checkers (CI) |
| monban-types | sealed newtypes: Principal (no Default), TenantId, RouteId, CapId, Decision, Canon<K>, RawFor<Signature> | core/alloc | forbid | DRT to Lean Decision |
| monban-canon | sole identity canonicalizer CANON-1..8 | http 1.5, percent-encoding 2.3, serde_json (url/idna banned here) | forbid | CANON-DIFF G1–G4, Kani totality |
| monban-budget | sans-IO RST bucket, GCRA, window/stream ledgers, request resource ledger | none | forbid | Kani structs, Verus ledgers, Lean composition |
| monban-transport | hyper/h2 wrapper TBI-1..9, strict H1, H1 upstream framing regeneration, Exchange, validated-101, 421 binding | hyper, h2, monban-budget, monban-canon | forbid | fuzz resource-ratio, HTTP Garden, DST stall, h2spec |
| monban-tls | profiles (P-PUBLIC-WEB, P-UNIVERSAL, P-BSI-ALT, P-CNSA, FIPS), 0x11ED KxGroup (ours), ticketer per scope, STEK ring, FipsStatus, CredentialSelector stub | rustls, aws-lc-rs, rustls-webpki | forbid | verdicts.toml, ClientHello matrix, 0x11ED KATs + interop + Kani |
| monban-admission | S0–S6 | monban-budget | forbid | property I1/I2/I5/I7, TLA+ I3/I4/I6/I9/I10, swarm sim (advisory) |
| monban-authz | tri-state combiner, Cedar adapter | cedar-policy | forbid | Lean Combine, Cedar DRT |
| monban-token | Tier 0 table, Tier L HMAC chain (det-CBOR), Tier X COSE ML-DSA-65 verify | EverParse det-CBOR (vendored at tag), aws-lc-rs, subtle | forbid | Lean T1–T5, DRT, fuzz F1–F9, dudect |
| monban-data-ir | Op, Pred, OpKind, Adapter trait, check_schema, allowlist-lock format | monban-types | forbid | Lean Lowering; renderer DRT 1e7 Preds; INV-NONEMPTY proptest |
| monban-adapter-pg/-sqlite/-redis | lowering + driver + NC3 checkin + per-tenant creds | tokio-postgres 0.7.18 + PR #1374; rusqlite (C, own TCB line); redis-rs | forbid in ours | two-sided read oracle, write oracle, schema gate, cancel sweep, SQLancer nightly |
| monban-adapter-host | out-of-process module/adapter protocol (WIT `monban:data@0.1.0` encoding, postcard, fds) | postcard, serde_bytes | forbid | frame fuzz, 64 KB perf test, hostile-module corpus |
| monban-agent | listener-gate type, both MCP eras, sealed requestState, projection IR | rmcp or owned transport; JSON via monban-canon | forbid | 43-case corpus, zero-handler counter |
| monban-egress | resolved-address connect, redirect policy, NAT64/6to4, fetch host fn (never wasi-http) | url/idna (egress only) | forbid | SSRF corpus |
| monban-audit | C2SP tlog-tiles writer, single sequencer, Ed25519 + ML-DSA-87 (gov) checkpoints | aws-lc-rs sha2, monban-state | forbid | Kani/proptest I1–I3, Tessera v1.0.4 oracle |
| monban-metrics | OpenMetrics endpoint on admin listener (always compiled); OTLP behind feature `otlp` | minimal | forbid | golden-counter presence test (Phase-2 gate) |
| monban-config | typed config, JSON Schema, check-config, last-known-good, CFG-1..4 | serde | forbid; deny unwrap/expect/indexing | Kani totality + fuzz 1e7 |
| monban-state | idempotency, outbox, commit-point latch, store trait (SQLite FULL default / redb 2PC) | rusqlite or redb | forbid | crash harness, DST, cancel sweep |
| monban-iso | supervisor, exec-spawned zygote, Landlock→seccomp once, clone filter, dumpable=0, crash budgets, fork+Wasm and cordon modes | rustix, landlock, seccompiler, nix 0.31 | ≤20 audited call sites, each `// SAFETY:` [E] | FI gate, negative syscall tests |
| monban-wasm (feature p2) | fresh Store per request, fuel, epoch watchdog, linker allowlist, local-MAC .cwasm, MPK density option behind assertions | wasmtime | forbid | FI gate, hostile-module corpus, config assertions |
| monban-ops | ACME (instant-acme), CERT-1..4, upgrade UP-1..7, sd-notify | instant-acme, sd-notify 0.5 | forbid | Pebble, faketime +400 d, upgrade harness, TLA+ UP |
| monban-sdk | B2 scoped adapter: ScopedHandler<'r,E>, Ctx<'r,E>, TenantDb<'r>, Tx<Open>→Committed, Detached, Granted<Cap> | monban-types, monban-data-ir, monban-authz traits | forbid | trybuild (≥25/32; residual exactly {M15, M16, N9, N14}) |
| monban-bin | assembly; startup assertions (kx_groups[0], fips(), PG minor floor, no unbounded limit, cmvp client policy) | per feature | forbid | budget gate, systemd ≤2, fail-closed default boot |
| xtask | gates | cargo_metadata, reqwest (tooling only) | n/a | negative-control PR per gate |

## 5. Dependency policy (summary; full in SUPPLY_CHAIN.md)

- `--locked` everywhere; lock changes only from the bot through cooldown + intake gates.
- cargo-vet from zero exemptions; exemptions only decrease; new crates audited or imported, never exempted; never `vet trust` publishers of build.rs/proc-macro crates.
- Banned: fancy-regex, pcre2, onig (data plane), simd-json, sonic-rs, bincode, wasmtime-wasi-http (egress), url/idna on ingress.
- C in process only: aws-lc (crypto), SQLite (default store; redb is the pure-Rust option). All other C-binding drivers and any C normalizer (e.g. libpg_query) run out of process or at build time only.
- First-party: `#![forbid(unsafe_code)]` except `monban-iso`.

## 6. Binary budget gates (R-PERF-1 [B]; floors from a hello-world build)

Stripped ≤6.0 MB default (≤9 MB everything except in-process JIT) · ≤60 crates default · non-crypto unsafe ≤5,100 lines (5,000 until 2026-11-10; raised by operator decision for the RUSTSEC-2026-0459 rusqlite 0.41.1 bump, DEVIATIONS X-10) · idle RSS ≤8 MB · 1k idle TLS ≤25 MB · hybrid handshake ≤1.3× X25519 CPU. Every feature PR commits a size/crate/unsafe delta; `cargo hack --each-feature`; a features-off build contains none of the feature's crates (`cargo metadata`).
