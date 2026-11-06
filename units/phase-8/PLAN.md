# Phase 8 plan: residuals and hardening (spec author, 2026-11-06, base 92e753c)

**Scope:** close residuals R1–R17 from PREFLIGHT §P2. No new feature surface. Every new or carried feature keeps its
TCB line, and claims are narrowed wherever evidence stops (D-P8.1).

**Read with:** units/phase-8/PREFLIGHT.md (D-P8.1..D-P8.5).

**Gate file:** gates/phase-8.toml. It carries every Phase-7 gate and adds 12 new ones.

**Units:** 15 JSON files in this directory. Dispatch waits for the Phase-7 GO, so they don't compete with the GO run
for the desktop or kamrui.

## Gate → unit

| new gate | where | closes | unit |
|---|---|---|---|
| `fips-boundary`: compliance/fips-boundary.toml cites #5314 rows (policy sha256 pinned). It refuses unqualified "0x11ED FIPS-approved/validated/inside the boundary" claim text, and refuses a TLS 1.3 KDF approval claim. | laptop | R1 | P8-fips-001 |
| `fips-indicator`: in the cmvp tls-subject, `indicator` mode reads AWS-LC's FIPS service indicator, which reports whether each crypto call ran in approved mode. ECDH P-384, ML-KEM-1024 encap/decap and HKDF must each report Approved. The 0x11ED handshake is reported. | kamrui | R1 | P8-cmvp-002 |
| `kani-kx-client`: Kani harnesses on the client side of 0x11ED/0x11EB share handling (client keygen share encoding, server-share parse + decapsulation input bounds, no panic) | laptop (drives kamrui) | R2 | P8-kani-001 |
| `conformance-full`: C0–C4 all 100%. C3 requires every DRT gate's log from this run at 0 divergence. C4 requires spec/TRACE.toml to map every F1 statement to ≥1 gate with a passing log. Config-pin requires that each judged subject booted with the effective-config hash the report pins. | laptop | R3 | P8-conformance-001 |
| `native-e2e-mariadb`: the notes app on a MariaDB backend end to end (reads, writes, tenant isolation, schema refusal). | kamrui | R4 | P8-oracle-001 → P8-mariadb-001 |
| `bin-residuals`: through aegis-bin (features mtc,l4): <br>• MTC/ML-DSA/x509 credential chosen per ClientHello (SEL-1..3 end to end) <br>• L4 idle timeout after routing <br>• one response per request on malformed chunked input (R6) | desktop | R6, R7 | P8-oracle-001 → P8-bin-001, P8-transport-001 |
| `crdb-live`: aegis-bin with adapter-crdb on CockroachDB: <br>• a contention workload produces 40001s and is never answered wrong <br>• CancelRequest on a slow query returns within its deadline and the pooled connection is reset or retired | kamrui | R8 | P8-oracle-001 → P8-bin-001 |
| `tlog-mldsa-openssl`: OpenSSL 3.5.3 `pkeyutl -verify` independently verifies the ML-DSA-87 checkpoint cosignatures of a log written by aegis-bin | kamrui | R10 | P8-audit-001 |
| `no-test-faults`: aegis-ops `Faults` exists only under feature `test-faults`. No release graph (default, native, all shipped profiles, cmvp) enables it. | laptop | R11 | P8-hardening-001 |
| `egress-tls-e2e`: an egress-subject with `tls-client` does a real TLS 1.3 handshake to a local upstream for each client profile (PQ-first). It refuses resumption and early data, and refuses a wrong-name or untrusted upstream. | desktop | R15 | P8-hardening-001 |
| `engine-pins-kamrui`: `ci/engines.sh check` plus a pg17/pg18/valkey start on kamrui. Every pin carries a host-independent `config_digest`. | kamrui | R16 | P8-spec-002 |
| `soak` (D-P8.4): 2 h on aegis-quiet. RSS slope ≤ 1 MiB/h, fds and tasks back to baseline ±5, 0 errors, audit log verifies. | quiet | R17 | P8-soak-001 |

**Carried gates that gain cases** (each with a new mutant):
- `otlp-export`: an https endpoint and retry-then-drop under a failing collector (R9, P8-oracle-001 → P8-otlp-001).
- `state-props`: idempotency retention expiry, INV-IDEMP within the window (R12, P8-hardening-001).
- `config-totality`: a route `path` that fails `canon_path` is refused at load (R13, P8-spec-001 → P8-hardening-001).
- `fuzz`: new target `pg_message` (R14, P8-spec-002 registers it, P8-hardening-001 fills it).
- `scaling`: F8 `runtime.worker_threads` = core count (R5, P8-bin-001).
- `reverse-proxy-e2e`: the one-response case (R6).

## Interfaces: P8-spec-001

**F8, additive** (absent = today's behaviour):
- `runtime.worker_threads`, range 1..=1024, default 2;
- `state.idempotency_retention_s`, range 60..=2,592,000; absent = today's "never expire" (kept so no stored key
  changes meaning);
- a load-time refusal of route `path` values that don't pass `canon_path` unchanged. This makes the F8 doc rule
  explicit. The value is already dead at request time, so refusing it changes no served behaviour.

**F4/F10:** `EngineFamily::Mariadb` and its denylist (MySQL forms):
- REPLACE, INSERT IGNORE, ON DUPLICATE KEY without the guard, LOAD DATA, SELECT … INTO OUTFILE/DUMPFILE;
- user variables (`@x :=`), multi-statements;
- `HANDLER`, `DO`, `CALL`.

**F1 §F addendum:**
- **FIPS-B1:** a FIPS claim names only components the cited certificate approves.
- **SOAK-1:** resources return to baseline after load.

Both re-frozen.

## Roles and single writers

- **Integrator (P8-spec-002):**
  - aegis-ops feature `test-faults`, plus its use by acme-subject;
  - tls-subject feature `indicator` (cmvp only), plus the aegis-iso cmvp indicator sites (≤ 2, cap 20 kept);
  - fuzz target registration `pg_message`;
  - engine pin `config_digest`s.
- **Single writers:**
  - aegis-bin: P8-bin-001
  - aegis-tls: P8-kani-001 (harness module only)
  - aegis-transport: P8-transport-001
  - aegis-data-ir: P8-mariadb-001
  - apps/notes: P8-mariadb-001
  - aegis-ops, aegis-state, aegis-config, aegis-adapter-pg, aegis-egress: P8-hardening-001, after P8-spec-001 for
    aegis-config

## Waves

```
W0  P8-spec-001, P8-spec-002, P8-fips-001, P8-kani-001, P8-audit-001, P8-soak-001 (harness)
W0b P8-oracle-001 (bin-residuals, crdb-live, native-e2e-mariadb, otlp-export + proxy-e2e cases), P8-conformance-001
W1  P8-cmvp-002 → spec-002 ; P8-transport-001 → oracle-001 ; P8-mariadb-001 → spec-001, oracle-001
    P8-otlp-001 → oracle-001 ; P8-hardening-001 → spec-001, spec-002
W2  P8-bin-001 → spec-001, oracle-001, mariadb-001
W3  P8-compliance-001 → all (claims: D-P8.1 text, TCB lines updated, residual table closed or carried)
GO  python3 -I ci/run-gates.py --phase 8
```

## Claims Phase 8 may make at GO (rungs)

| claim | rung |
|---|---|
| 0x11ED built only from #5314-approved components; combiner per SP 800-227 §4.6.2. **Not** "FIPS-approved key establishment". | R1 documentation + R2 indicator run |
| Kani on the client share path | R2, bounded, on the Rust code |
| Conformance C0–C4 | 100%, gated |
| MariaDB servable through aegis-bin | R2 end to end |
| Soak | 2 h, one host; provisional for long-run claims |
