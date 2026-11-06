# P7-compliance-001 report (spec author, 2026-11-06, base 479ee82, main 3b74452 merged)

Gate owned: `tcb-lines`. The worktree was reset to main 479ee82. P7-bin-001 landed during the unit (f2af60c, 0dfd06d,
plus the scaling commit 3b74452), and main was merged in before the lines were finalised. Its residuals are filled in.
No `PENDING(` marker is left, and the gate refuses one.

## Delivered

| path | what |
|---|---|
| `ci/tcb-lines.py` | Gate `tcb-lines`: check, `--root DIR` and `--self-test`. Stdlib only, in the style of ci/compliance.py. |
| `ci/fixtures/tcb-lines/good/` | Minimal fixture tree: SECURITY_CLAIMS.md, compliance/COMPLIANCE_MAP.md, and a gates/phase-7.toml with only the cited names. It must PASS, and every mutant also runs on it. |
| `SECURITY_CLAIMS.md` | Two new "Not proven" rows: the Linux io_uring subsystem + io-uring 0.7.15, and libcrux (spike). New section "Phase 7: one TCB line per feature" (8 rows plus a default-build note). New subsection "Phase 7: deferred and blocked" (HTTP/3, WebTransport, 64-core run). |
| `compliance/COMPLIANCE_MAP.md` | The **Trusted, not verified** paragraph names io_uring/io-uring and libcrux. New §4.2 (the same 8 TCB rows; gate ids here are phase-7 gates) and §4.3 (deferred/blocked). §1–§8 are unchanged, so `compliance` stays green. |
| `DEVIATIONS.md` | X-17 (MTC: trust_anchors read from our own peek, not rustls; one opaque `mtc` kind, standalone/landmark not told apart). X-18 (owned MySQL wire client, as X-10). A numbering note: X-15 is used twice (cmvp overlay in Phase 6, aegis-uring unsafe budget in Phase 7). Both are kept because code and reports cite each one, so read X-15 by context. OTLP out of process is X-3 as decided, not a new entry. |

## TCB lines written (each in both files)

1. **proxy-protocol**
   - Surface: aegis-wire `parse_v2` and the aegis-bin `front.rs` wiring. C: none. Kernel: none new.
   - Gates: `proxy-l4`, `kani-wire`, `fuzz`, `default-graph`.
   - Rungs: the parser is R2, plus Kani bounded checks. PROXY-1..3 end to end are R2 on the proxy-l4 corpus, one host.
   - Residuals: the Kani bounds (UNIX family, TLV regions over 10 bytes, the 8 KiB bitmap linked only by an exhaustive unit test); trusted CIDR only; the proxy-l4 limits.
2. **l4**
   - Surface: the aegis-wire peek, plus SNI routing and splice.
   - Gates: same as proxy-protocol.
   - Rungs: the peek is R2, plus Kani. L4-1/L4-2 are R2.
   - Residuals: ext blocks over 12 bytes are not Kani-covered; the bitmap is checked only by a unit test; the idle timeout after routing has no oracle; bytes are passed through uninspected.
3. **uring**
   - Surface: aegis-uring (1 of 6 unsafe sites) on io-uring 0.7.15. Kernel: the io_uring subsystem, denied by the hardened unit and re-admitted only by `deploy/uring.conf`.
   - Gates: `front-equiv`, `unsafe-sites`, `vet`, `systemd-hardening`, `default-graph`.
   - Rungs: the crate is R1; FRONT-1 is R2, one host.
   - Residuals: the kernel attack surface; the agent-only vet audit needs an operator countersign; the X-15 unsafe site rests on an argument, not a proof; TCP_NODELAY needs kernel 6.7 or later; the double-400 is reproduced, not fixed.
4. **mtc**
   - Surface: aegis-tls `select.rs` (compiled out under cmvp), the aegis-wire peek, and the aegis-bin `tls.rs` wiring.
   - Gates: `cred-select`, `kani-wire`, `tls-verdicts`.
   - Rungs: selection is R2 (re-run on the merged tree, through tls-subject); the selector through aegis-bin is R1 (smoke run only).
   - Residuals: selection only, no MTC validity claim; 0xCA34 is an experimental codepoint; no gate drives the selector through aegis-bin.
5. **adapter-mariadb**
   - Surface: aegis-adapter-mysql. External: MariaDB 11.8.9.
   - Gates: `lowering-read/write-mariadb`, `schema-gate-mariadb`, `default-graph`.
   - Rungs: the renderer and schema gate are R2; the client is R1; there is no serving.
   - Residuals:
     - **not servable**: aegis-bin boots it fail closed with exit 78 until an EngineFamily::Mariadb denylist and a notes-mariadb lock exist (Phase 8);
     - the Rust client is not live-tested on the write forms;
     - no pool and no cancel;
     - loopback only, no TLS;
     - no RLS;
     - single-connection oracles.
6. **adapter-crdb**
   - Surface: aegis-adapter-pg `crdb`. External: CockroachDB 25.4.19.
   - Gates: the three crdb gates, `pg-version-floor`, `default-graph`.
   - Rungs: the renderer and schema gate are R2; the 40001 retry is R1 (unit tests); the aegis-bin wiring is R1 (one live test, pool reset accepted).
   - Residuals: the 40001 retry is only unit-tested, and aegis-bin surfaces 40001 as a conflict (no whole-transaction retry through the SDK host); CancelRequest is untested; the PG denylist and lock are reused (integrator to confirm); no RLS; single node.
7. **aegis-otlp**
   - Surface: a separate L5 binary with no new locked crate and no opentelemetry/prost/tonic.
   - Gates: `otlp-export`, `no-otel-in-bin`.
   - Rung: R2, 53/53.
   - Residuals: https, retry/backoff and drop-oldest under backpressure are not oracle-covered; there is no retry at all; JSON logs and histograms are tested only on synthetic fixtures; the gate has no laptop run.
8. **libcrux-spike**
   - Surface: its own lock, never shipped. C: 0 files, against 395 for aws-lc-rs.
   - Gate: `libcrux-spike`.
   - Rungs: the C count and the KATs are R1; interop is R2.
   - Residuals: handshakes are 2.5-3× slower (provisional); it is not verified side-channel resistant; the glue is ours and unreviewed; RUSTSEC-2026-0173 (cfg(hax) only) is accepted until 2027-02-06; upstream hax/F\* claims were not re-checked.

**Deferred and blocked (both files):**
- **HTTP/3:** deferred, preconditions not met (2026-11-06).
  - Evidence: h3 #366/#377/#378 are still open; quinn had 9 HIGH and 1 MEDIUM advisories, the last HIGH on 2026-09-30.
  - Gate: `no-quic`.
  - Re-check: 2027-03-30.
- **WebTransport:** deferred, blocked on HTTP/3 (2026-11-06). Re-check 2027-03-30.
- **64-core run:** blocked on GCP quota (CPUS_ALL_REGIONS = 12).
  - The desktop harness now passes with 0 errors.
  - The req/s plateau at about 31-42k from 2 cores up comes from `worker_threads(2)`, not from scaling.

A note under the TCB table records the default build at +8,576 B and the native build at +9,088 B against e235b75.
The crate set is identical and `budget` passes.

## Gate checks (tags)

- Structure and coverage: `structure`, `feature-missing`, `feature-dup`, `surface` (the row must name `crates:`, `C:` and `kernel:`).
- Gate ids: `gate-id` (backticked names only, each a gate in gates/phase-7.toml).
- Rung and residuals: `rung` (R0..R4), `residual` (a per-feature list of residuals the row must keep).
- Consistency: `mismatch` (gate ids or rungs differ between the two files).
- Deferred and blocked: `deferred` (dated deferral, re-check 2027-03-30, the h3 PRs named, nothing "unsupported by design" anywhere) and `blocked` (quota row).
- Trust list and wording: `trusted-list`, and `proven`. `proven` looks at each table cell or sentence that names hyper, h2, tokio, rustls, AWS-LC, rustc/LLVM, io_uring/io-uring, libcrux or the kernel, and flags proven/proved/verified unless a negation comes before it.
- Markers: `pending` (no `PENDING(` marker left).

## Acceptance (`python3 -I ci/tcb-lines.py && python3 -I ci/tcb-lines.py --self-test`, laptop)

```
TCB-LINES: PASS (8 Phase-7 features x 2 files (SECURITY_CLAIMS.md, compliance/COMPLIANCE_MAP.md), each naming crates/C/kernel surface, rung and residuals; 22 gate ids, all in gates/phase-7.toml; HTTP/3 + WebTransport deferred (2026-11-06, re-check 2027-03-30); 64-core run blocked on quota; no trusted component called proven)
TCB-LINES SELF-TEST: PASS (repo and fixture baselines clean; 92/92 mutant runs red with the exact expected tag (46 mutants x repo, fixture))
COMPLIANCE: PASS (15 control rows, 32 gate ids in gates/phase-6.toml, 22 SA-17(1) theorems frozen in spec/STATEMENTS.sha256, 8 CRA drafts unpublished, 2 CSAF 2.0 documents schema-valid (validator: builtin+jsonschema), 0 CycloneDX; no root SECURITY.md, no LICENSE)
COMPLIANCE SELF-TEST: PASS (baseline clean; 31/31 mutants red with the exact expected tag)
```

The unit's mutants are all among the 46, each run on the real files and on the fixture:
- a feature without a line: `no-uring-line-sc`, `no-libcrux-line-cm`;
- a line without a rung: `mtc-no-rung`;
- HTTP/3 "unsupported by design": `h3-by-design-status`, `h3-by-design-prose`;
- io-uring, hyper or AWS-LC called proven: `io-uring-verified`, `hyper-proven`, `aws-lc-proved`, plus libcrux and rustc;
- a gate id that does not exist (from the brief): `gate-id-unknown`, and `gate-removed-from-toml`, which renames `kani-wire` in the toml copy.

## Notes for the integrator

- The rows quote counts from the unit reports and commit messages. No gate log for Phase 7 exists yet under
  gates/out/logs. The Phase-7 GO run is what records them.
- The `compliance` gate still reads gates/phase-6.toml for its §4 ids. §4.2/§4.3 are judged by `tcb-lines` against
  phase-7.toml, and the map says so in §4.2.
- The duplicate X-15 numbering is now written down in DEVIATIONS.md. It was not renumbered, because both numbers are
  cited.

## Infeasible

Nothing.
