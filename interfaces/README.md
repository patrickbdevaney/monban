# Frozen interfaces (F1–F13)

Written by the spec-author role before implementation (IMPLEMENTATION_PLAN §1). Implementer agents may not edit
them; `ci/interfaces.py check` fails on any change. A change goes through a spec-change PR that re-freezes
`MANIFEST.sha256` and re-runs every dependent gate.

| id | artifact | status | ratified at freeze |
|---|---|---|---|
| F1 | `spec/SPEC_INVARIANTS.md` + `spec/STATEMENTS.sha256` (Lean statements) | frozen | statement hashes; proof PRs cannot touch them (`ci/statements.py`) |
| F2 | `crates/aegis-types/src/lib.rs` | frozen | `Principal` mintable only via `authn_path` (owner aegis-token); `Canon<K>` via `canon_owner` (aegis-canon); `RawFor<S>` via `raw_owner` (aegis-transport); enforced by `cargo xtask layering` |
| F3 | `crates/aegis-transport/src/exchange.rs` | frozen | Exchange + 2 front-end hooks (`on_head`, `on_message`); R-ING-1 reverses if a front end needs a third |
| F4 | `crates/aegis-data-ir/src/ir.rs` | provisional: q4-004 → resolved; additive re-freeze P4-spec-001 | three-valued policy semantics (ThreeValued.lean); `Not` only on `Fidelity::Exact`; binary no-pad tenant/key collations; upsert needs a sole full-length (tenant, key) unique index (q4-005); P4-spec-001 (D1, D4): `CapSet` (no empty constructor, explicit `Unrestricted`) + `authorize`, tenant encoding = 16 lower-case hex digits (`tenant_text`, Redis `t:{hex}:`), KV mapping rule `kv_plan`, `EnginePin`, per-family `denylist`, allowlist lock format (`lock_body` + sha256 trailer); Op/Pred/Schema layout unchanged |
| F5 | `interfaces/F5-token.cddl` | frozen | D1 segment prefix, D2 op-mask subset, D3 depth at verify, D4 missing arg denies, mint-shape check |
| F6 | `crates/aegis-authz/src/combine.rs` | frozen | tri-state; Error/timeout/crash ⇒ Deny; `combine` = Combine.lean `combine` |
| F7 | `sdk/aegis-sdk/src/surface.rs` | frozen | request-scoped surface |
| F7b | `sdk/aegis-sdk/src/streaming.rs` | frozen | host-driven streaming/SSE/WS/detached jobs (q4-001 D2) |
| F8 | `interfaces/F8-config.schema.json` | frozen (q4-008 resolved); data block P4-spec-001 | every limit bounded; canon block per q4-008 (empty segments 308, trailing slash accepted, encoded non-ASCII opaque, opaque query); optional `data.backends[]` {id, engine, dsn_ref, pin, max_conns, op_budget_ms} and `routes[].data` = non-empty cap list or the literal `"unrestricted"` (absent = no data capability) |
| F9 | `interfaces/F9-audit-event.schema.json` | frozen | tlog-tiles leaf fields |
| F10 | `interfaces/F10-module-wire.cddl` | frozen | out-of-process module wire; host decoders in the verified TCB; P4-spec-001 adds normative comments only (kind↔OpMask bit, D4 tenant encoding) |
| F11 | `interfaces/F11-upgrade-handover.cddl` | frozen | UP-1..7 handover messages |
| F12 | `tls/verdicts.toml` | provisional: q4-026 | PUB-T1..T6, FIPS-F1..F6; 0x11ED from our own KxGroup (Phase 6) |
| F13 | `interfaces/F13-conformance-report.schema.json` | frozen | C0–C4 report |

"Provisional" means frozen now, with a named Phase-1 spike that may force one re-freeze before Phase 2.
