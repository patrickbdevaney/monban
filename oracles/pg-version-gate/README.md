# pg-version-gate: PostgreSQL minor floor and PG19 block

Checks that a PostgreSQL client admits a server only if `supply-chain/engine-pins.toml` admits its version, and
re-checks the version when a pooled connection is re-established. Backs gates **pg-version-floor** (offline, fake
servers) and **pg19-blocked** (live engines), both owned by P4-pg-001. Unit: P4-oracle-pgver-001.

Spec: ARCHITECTURE §3.8 **R-DB-1** (PG ≥ 18.6 / 17.11, CVE-2026-14666; recycle pooled connections after minor
upgrades) and **R-DB-8** (PG19 gated on the ON CONFLICT WHERE-before-RLS fix, `wpo-pg-onconflict-where-peek` A 0.86;
units/phase-4/PLAN.md: every 19.x refused until a spec change names the fixed minor). Neither is a numbered clause in
`spec/SPEC_INVARIANTS.md`. The closest clause is F7 tenant isolation, which assumes the engine is not one with a known
RLS bug. Admission semantics mirror `monban-data-ir` `EnginePin::admit` (crates/monban-data-ir/src/ir.rs).

## Run

```
oracles/pg-version-gate/run                                  # reference subject, offline (~0.5 s)
oracles/pg-version-gate/run --subject '<cmd>'                # e.g. 'target/release/pg-subject connect'
oracles/pg-version-gate/run --self-test                      # reference clean + 9 mutants red (~30 s)
ci/engines.sh with pg19rc1,pg17 -- oracles/pg-version-gate/run --live [--subject '<cmd>'] --refuse @pg19rc1 --accept @pg17
ci/engines.sh with pg19rc1,pg17 -- oracles/pg-version-gate/run --self-test --live --refuse @pg19rc1 --accept @pg17
```

`--refuse` and `--accept` can be repeated (for example `--accept @pg18` as well). `--pins FILE` overrides the pins
file. The last line is `PG-VERSION-GATE: PASS|FAIL (...)` or `PG-VERSION-GATE SELF-TEST: PASS|FAIL (...)`, and the
exit code is 0 only on PASS. The subject is started with the repo root as its working directory.

## Truth (from engine-pins.toml, read at run time, never hand-copied)

- Floors: `floor` of every `kind = "postgres"`, `policy = "allow"` pin (today 17.11 and 18.6). Blocked majors: the
  major of every `policy = "blocked"` postgres pin (today 19).
- Version = leading token of the `server_version` ParameterStatus (text before the first ASCII space).
  `server_version_num` is ignored: real 17/18/19 servers do not send it at startup (checked live), and the pins file
  names `server_version`.
- Accept iff the token is ASCII `major.minor` with both parts ≤ u32::MAX, the major is not blocked, the major has a
  floor, and `(major, minor) >= floor`, compared **numerically** (17.9 < 17.11 and 18.10 > 18.6).
- Refuse: blocked major (every 19.x, including 19.0 GA and later minors), a major with no floor (14/15/16/20 even when
  fixed upstream, because the pins list no floor for them), below floor, any pre-release (`NNbetaN`, `NNrcN`,
  `NNdevel`, `NNalphaN`), a missing `server_version`, and anything unparseable (empty, `v18.6`, `17.x`, full-width
  digits, `17.11garbage`, three-part `9.6.24`, u32 overflow such as `17.4294967307`).

## What is checked

**Offline (45 matrix + 7 reconnect cases).** One fake PG v3 server per case (stdlib, 127.0.0.1, random port). It
answers SSLRequest/GSSENCRequest with `N` and the startup with AuthenticationOk, a realistic ParameterStatus set,
BackendKeyData and ReadyForQuery. The matrix covers 14.24, 15.19, 16.4, 16.15, 17.0, 17.9, 17.10, 17.11, 17.12, 17.20,
Debian/Ubuntu-suffixed 17.10/17.11/18.6, 18.0, 18.5, 18.6, 18.7, 18.10, 18beta1, 18rc1, 18devel, 19beta3, 19rc1, 19.0,
19.1, 19.12, 20.0, 9.6.24, garbage forms, `server_version` missing (with and without `server_version_num`),
`server_version_num` omitted, and decoys where `server_version_num` disagrees with `server_version`.
The PASS criterion: every verdict equals the truth. An accept must also echo `server_version` equal to the leading
token the server sent, and the subject must have actually opened a startup on that server.

Reconnect (R-DB-1): the subject connects (accepted, pooled). The fake then "restarts" as a minor upgrade does: it sends
FATAL 57P01 to every open connection, closes them, and reports version B. The subject connects twice more. Expected:
the second connect is **refused** if B ≠ A (the pooled connection is recycled, and the subject must have re-read the
startup: a verdict with no new startup is a failure), and otherwise follows truth(B). The third connect follows
truth(B) (a fresh admission). Scenarios: 17.11→17.10, 17.11→17.12, 18.6→19.0, 17.11→18.6, 17.11→17.11, 18.6→18.5,
18.6→(no server_version).

**Live (`--live`).** For each target, the oracle first probes the server with its own client (SCRAM-SHA-256) and
requires that the pins verdict on the reported version equals the flag (`--refuse`/`--accept`). A run with swapped
flags therefore fails as misconfigured instead of passing. Then the subject must refuse each `--refuse` target, and
must accept each `--accept` target twice (the second connect reuses the pool), echoing the server's leading token.
Measured: postgres:19rc1 reports `19rc1 (Debian 19~rc1-1.pgdg13+1)`, postgres:17-alpine `17.11`, postgres:18-alpine
`18.6`. No target reports `server_version_num`.

## Subject protocol

`--subject '<cmd>'` starts `<cmd>` once (shlex-split, no shell). The oracle writes one JSON object per line to its
stdin and reads one JSON object per line from its stdout, with a 20 s timeout per reply.

```json
{"v":1,"id":7,"op":"connect","dsn":"postgresql://postgres:secret@127.0.0.1:5432/postgres"}
{"id":7,"ok":true,"server_version":"17.11"}
{"id":7,"refuse":"major 19 blocked (R-DB-8)"}
```

`server_version` in an accept is the leading token (`17.11`, not `17.11 (Debian ...)`). Reasons are free text and are
not judged. The subject keeps a pool keyed by DSN for its lifetime. While the pooled connection is alive it may reuse
it. Once the connection is dead it must open a new startup, compare the reported token with the one it admitted, and
refuse (and drop the pool entry) if they differ. The DSN is the only input. Auth is trust (fake servers) or
SCRAM-SHA-256 (live engines), and SSL is not used on loopback. A subject may answer `{"op":"hello"}`. The reference
is `python3 -I pgver.py serve [--mutant NAME]`. It uses the in-file v3 client, which is ported from the in-repo
`ci/engines.sh` probe (trust/SCRAM only; cleartext and MD5 refused). No third-party drivers.

## Self-test

The truth function is first checked against the pins, relative to each floor: floor-1 refused; floor, floor+1 and
floor+10 accepted; rc refused; every listed form of a blocked major refused. It also checks that the matrix still
contains the plan's required versions and a string-versus-numeric disagreement. Then the unmutated reference must be
clean **through the process protocol** (positive control), and every mutant must go red offline:

| mutant | what it breaks | first catch |
|---|---|---|
| string-compare-version | `'17.9' >= '17.11'` as strings | 17.9 accepted, 18.10 refused |
| no-floor | floor ignored for known majors | 17.0 / 17.10 / 18.5 accepted |
| pg19-allowed | 19 not blocked; any 19 (incl. rc/beta) admitted | 19beta3, 19rc1 accepted |
| pg19-ga-allowed | 19 refusal broken at GA: pre-releases refused, 19.0+ admitted | 19.0 accepted |
| wrong-field | version taken from `server_version_num` | `server_version` missing (num 170011) accepted |
| no-recheck-on-reconnect | version cached at first connect | 17.11→17.10 reconnect accepted |
| unknown-major-allowed | major without floor admitted | 14.24 / 16.x / 20.0 accepted |
| missing-version-accepted | missing/unparseable version admitted (fail open) | 9.6.24, garbage accepted |
| u32-wrap | u32 wrap-around parse | 17.4294967307 accepted as 17.11 |

With `--live`, the reference must also be clean live, and every mutant is run live. When a `--refuse` target has a
blocked major, `pg19-allowed` must be red live. Measured on 19rc1 + 17.11: pg19-allowed and wrong-field red. The
others cannot be told apart on those two versions; the offline run covers them.

## Provenance and in-repo runs

No research artifact was ported or executed. The oracle is new code. The PG v3 SCRAM client is adapted from
`ci/engines.sh` (`probe_pg`, P4-engines-001). Floors and advisories come from `supply-chain/engine-pins.toml` (sources
cited there: the CVE-2026-14666 page and the 2026-08-13 release announcement).

Re-run in-repo on 2026-10-30 (laptop):
- `run`: PASS, 52 cases.
- `run --self-test`: PASS, 9/9 mutants red.
- `ci/engines.sh with pg19rc1,pg17 -- run --self-test --live --refuse @pg19rc1 --accept @pg17`: PASS.
- `ci/engines.sh with pg17,pg18,pg19rc1 -- run --live --refuse @pg19rc1 --accept @pg17 --accept @pg18`: PASS.
- Negative controls: the live run with the pg19-allowed mutant as `--subject` FAILs (19rc1 accepted); swapped flags
  FAIL as misconfigured; an unsubstituted `@pg19rc1` FAILs.

## Known limits

- Live reconnect is not exercised: the oracle does not restart the real containers. Pool recycling is checked only
  against the fake server's simulated restart. Role-DDL-triggered recycling (also R-DB-1) is not checked here.
- A pooled connection that stays alive across a server-side version change cannot happen with real PG, because a minor
  upgrade restarts the postmaster. The protocol therefore only requires re-checking on reconnect, not periodic polling.
- Lifting the PG19 block is a spec change (a fixed 19.x minor named in the pins plus a passing lowering-write RLS ON
  CONFLICT family). The self-test fails if the pins stop blocking 19, so the oracle is revisited at that point.
- Only the startup ParameterStatus is judged. A `SELECT version()` cross-check and a `server_version` re-reported after
  startup are out of scope.
- 14/15/16 are refused because the pins list no floor for them, even though upstream fixed CVE-2026-14666 in
  16.15/15.19/14.24. Adding a floor to the pins changes the truth automatically.
