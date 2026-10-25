# Backlog found while building the verify wall (not yet units)

## xtask fips-lock gaps (from the oracles/hrr-verdicts port, 2026-10-25). Phase 6 gate.
1. G1 prefer-post-quantum on every rustls node (needs `cargo metadata`, not Cargo.lock text).
2. G2b which aws-lc-fips-sys version aws-lc-rs actually links.
3. G3 aws-lc-rs window [1.15.2, 1.17.1] instead of a single exact pin compare.
4. G4 floors rustls ≥0.23.46 / webpki ≥0.103.16 and the report that cmvp cannot meet them (ledger entries).
5. G5 floor-profile lineage (aws-lc-fips-sys ≥0.13.13) once profiles/floor exists.
6. G6 `AWS-LC FIPS 3.1.0` string present in the binary (P-PQ5 module identity).
7. Read `cargo metadata --locked` rather than Cargo.lock text.
8. Add self-test mutants for G1, G3, G6.

## TLS
- rustls 0.23.46 selects by client order: server list order never changes the outcome until the PreferServerOrder
  backport; PUB-T2 flips deliberately then (re-freeze F12).
- P-PQ3 ticket scope, P-PQ6 cmvp client policy, 0-RTT: no verdicts yet. P-CNSA: no frozen verdicts.

## Canon / MCP (from the oracle ports, 2026-10-25)
- Research claim "331/331/69 → 0/0/0" corrected: before-counts are 444/331/69 (paths/hosts/JSON); the 0/0/0 holds
  over only 6/6/9 accepted values. ARCHITECTURE §3.3 cites the wrong path number.
- The research canon_ref.py used Python IDNA2003 for xn-- labels, which violates its own no-IDNA-on-ingress rule; the
  oracle now uses a structural Punycode check only.
- G3 "34 dated instances" is not reconstructible; 47 ledger rows reconstructed from one-line descriptions.
- Pending: G2 through every Rust identity parser in the lock; h2c :authority case; CANON-8 folding; q4-008.
- MCP corpus: 44 cases (union of two research lists); 13 not black-box executable; only 19/33 advisory cases had
  ever run on any target. Several expected statuses are research proposals, not spec text: ratify at Phase 3 freeze.

## Data plane (from the lowering oracle ports, 2026-10-25)
- Spec §E corrected (equality → subset; UNKNOWN gap is a miss, never a leak); F4 gained `Collation` + key flag and
  rejects non-binary tenant/key collations (W3 no-op on NOCASE/ICU: 51/1200 cases).
- Lean comment on `inList []` says FALSE; the definition yields UNKNOWN on a NULL column. Fix the comment in a
  spec-change PR (comments are stripped from the statement ledger, so no hash change).
- Research hardened SQLite filter was two-valued on NULL (wrong under NOT); prefix check misses on NUL (fails safe).
- Pending oracle coverage: W5 (triggers, data-modifying CTEs, FK actions), W6, MERGE, native PG RLS; PG 19rc1;
  SQLite at the adapter pin (≥3.51.3, not Python's 3.45.3); Redis ACL hostile-command corpus; MySQL/Cockroach (q4-005).

## State (from crash-harness / cancel-sweep ports, 2026-10-25)
- NEW: SQLite 3.53.2 silently falls back from WAL to rollback-journal if the first fsync fails during WAL
  conversion (PRAGMA had already returned "wal"); acked writes are then lost. aegis-state MUST re-read
  journal_mode and synchronous after the first write and refuse to serve otherwise (INV-DURABLE).
- redb 2PC passes only with the bootstrap parent-directory fsync (research's 1,176/8,020 losses reproduce without it).
- Store creation must be temp file + rename + dir fsync so a crash inside create is retryable.
- Full-size crash run (~170k images) is a CI/VPS job. Rust subjects need `--cfg rustix_use_libc` for the tracer.
- Cancel-sweep pending: real-driver regression cases, task abort / h1 FIN / shutdown deadline / Wasm trap modes, NC6–NC8.
- Admission: I3/I6/I9/I10 need TLA+; governor is not LRU, so the I4 check needs a declared eviction policy.

## Process
- Phase-1 commits swept in unfinished spike files (incl. a throwaway self-signed loopback key in spikes/q3-008,
  since removed from the tree; still in history, no real secret). Commit only finished spike dirs by path.

## Oracle follow-ups (2026-10-25)
- NC3 widened: every resource a cancelled request touched is quarantined (closes the gap where a cancelled connection
  passing the checkin predicate carried `SET` state). Update oracles/cancel-sweep model + add mutant "cancelled
  connection with session state checked in without DISCARD ALL" (spec-author unit).
- C8: pools shared across principals must reset on recycle (DISCARD ALL) regardless of cancellation — make explicit in
  the PG adapter unit acceptance.
- canon-diff: opaque path octets that pass UTF-8+NFC (zero-width, bidi overrides, BOM, fullwidth) are accepted; only
  dangerous behind path-folding upstreams (CANON-8 per-upstream folding profile must reject them for such upstreams).
- lowering-read: PG/Redis engines not re-run after the refQ3 switch.

## Config (from P2-config-001)
- F8 route `path` pattern admits `..`, `//`, `;` which aegis-canon rejects at request time → such routes are dead.
  Add a check-config cross-check: route path must itself pass `canon_path` unchanged (spec-author decision; reject).
- Route id capped at 2^53−1 (I-JSON safe range); empty `authz` ⇒ Deny; 1 MiB cap also applies to the effective form.
- aegis-config carries its own SHA-256 (FIPS 180-4 vectors); aegis-audit uses aws-lc-rs — consolidate on aws-lc-rs
  if aegis-config may take that dependency (it is L2 pure; keep in-crate unless the TCB ledger prefers one impl).

## Audit (from P2-audit-001)
- ML-DSA-87 checkpoint cosignature verified only by Rust tests (Go 1.26 has ML-DSA internal-only): add an
  independent verifier (e.g. OpenSSL 3.5 `pkeyutl -verify` with ML-DSA-87) to oracles/tlog-verify.
- Cosignature uses signed-note escape type 0xff + "aegis-mldsa87-note-v1" without a timestamp: not interoperable
  with C2SP witnesses (timestamped ML-DSA-44). Revisit when a witness standard for ML-DSA-87 exists.
- Log restart from existing tiles (resume at size N) belongs to aegis-state; in-memory hash store grows ~64 B/entry.
- Admin path: a checkpoint failure leaves the event in the log (published later) — log may record an attempted but
  unapplied action, never the reverse. Document in the audit-failure policy.

## Upgrade (from P2-upgrade-001)
- F11 SCM_RIGHTS transport: RESOLVED by P2-upgrade-002 (rustix safe sendmsg/recvmsg, OwnedFd, MSG_CTRUNC ⇒ close
  all + abort; ≤64 listeners per handover; stdio inheritance removed).
- Not done: FDSTORE, UP-3 (h2 GOAWAY, needs transport), ACME/CERT-1..4 (P2-ops-cert-001).
- Child crash after READY and after the parent closed its copies loses the listeners (documented in handover.rs):
  FDSTORE closes this.

## ACME (from P2-acme-cert-001)
- `aegis_ops::acme::Faults` (oracle fault hooks) is public production API, off by default: move behind a
  `test-faults` feature so release builds cannot enable it.
- Not done: TLS-ALPN-01, EAB; Let's Encrypt staging interop (needs a public name); PQ group negotiation with Pebble
  unverified (only a unit test checks the PQ-first preference). ACME uses blocking std sockets + rustls (no tokio).

## Transport (from P2-transport-001, 2026-10-25)
- h2spec: RESOLVED by P2-transport-002 (145/146 stable; failures were a subject vhost misconfig). Two h2 0.4.20
  deviations remain (crates/aegis-transport/INFEASIBLE_REPORT.md): GOAWAY(PROTOCOL_ERROR) instead of STREAM_CLOSED
  for HEADERS on a client-reset stream; pseudo-headers in END_STREAM trailers accepted. Strict tests #[ignore]d.
- Resource-limit oracle (stall / reset / header-block budgets measured against the running server) NOT built:
  generating that client tripped a content safety stop during this session. Coverage today: aegis-transport e2e
  tests (window-0 stall reset, 431 on 129 cookie crumbs, idle close, strict H1 rejects) and spike q2-009's
  measurements. Operator decision needed on how to provide this gate (e.g. an established public HTTP/2 test tool).
- h2spec v2.6.0 cannot negotiate TLS 1.3, so conformance runs over h2c; TLS-path conformance needs a newer client.
- panic = "abort": a handler panic aborts the process (supervisor restarts it) rather than becoming a per-request
  Error → Deny; fine for fail-closed, but the INV-FAILCLOSED host mapping is per-process here, not per-request.
