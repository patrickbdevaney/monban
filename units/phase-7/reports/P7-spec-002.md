# P7-spec-002 report (integrator, 2026-11-06, base 00ca246)

The unit pre-wires the Phase 7 workspace members, features, the io-uring pin, and fuzz/Kani registration. It also adds
the `default-graph` gate. Every new crate is a stub that compiles and fails closed (`Err` or exit 2). None uses
`todo!()`.

## 1. Names other units must use

| what | name | layer / kind | consumer unit |
|---|---|---|---|
| crate | `aegis-wire` (`crates/aegis-wire`) | L2, no dependencies | P7-wire-001 |
| crate | `aegis-adapter-mysql` (`crates/aegis-adapter-mysql`) | L4: aegis-types, aegis-data-ir, aws-lc-rs, rustix(time) | P7-adapter-mysql-001 |
| crate | `aegis-uring` (`crates/aegis-uring`) | L4: io-uring, tokio(rt, net, io-util, sync) | P7-uring-001 |
| binary | `aegis-otlp` (`crates/aegis-otlp`, bin `aegis-otlp`) | L5: aegis-types, aegis-canon, aegis-egress[tls-client], aegis-tls[tls-client], tokio, rustls, http, hyper | P7-otlp-001 |
| subject | `mariadb-subject` (`subjects/mariadb-subject`) | tool, depends on aegis-adapter-mysql | P7-adapter-mysql-001 |
| subject | `crdb-subject` (`subjects/crdb-subject`) | tool, depends on aegis-adapter-pg with `crdb` | P7-adapter-crdb-001 |
| aegis-bin features | `proxy-protocol` = [dep:aegis-wire]; `l4` = [dep:aegis-wire]; `mtc` = [aegis-tls/mtc, dep:aegis-wire]; `uring` = [dep:aegis-uring]; `adapter-mariadb` = [native, dep:aegis-adapter-mysql]; `adapter-crdb` = [native, aegis-adapter-pg/crdb] | all off by default | P7-bin-001 |
| aegis-tls feature | `mtc` = [dep:aegis-wire] | off by default | P7-mtc-001 |
| aegis-adapter-pg feature | `crdb` = [] (gates the `Dialect::Crdb` code) | off by default | P7-adapter-crdb-001 |
| fuzz targets | `proxy_v2`, `client_hello_peek` (in `ci/fuzz.sh` TARGETS_ALL) | fuzz workspace | P7-wire-001 |
| Kani | `ci/kani.sh [--serial] [--mem 6G] -p aegis-wire`; default negative control `negative_control_planted_oob` in `crates/aegis-wire/src/kani_proofs.rs` | kamrui | P7-wire-001 |

**Stub API shapes.** P7-wire-001 owns `src/**` and may refine these.
- `aegis_wire::proxy::parse_v2(&[u8]) -> Result<(Header, usize), ProxyError>`. It comes with `SIGNATURE` and
  `MAX_DECLARED_LEN = 536`.
- `aegis_wire::tls_peek::client_hello(&[u8]) -> Result<Peek<'_>, PeekError>`. It comes with `MAX_RECORD = 16384`.
  - `Peek` borrows raw extension bodies, so the peek needs no allocation: `sni`, `alpn`, `versions`, `sigalgs` and
    `trust_anchors`, each an `Option<&[u8]>`.
- `aegis_uring::UringFront::bind(SocketAddr, u32) -> Result<_, UringError>`.
- `aegis_adapter_mysql::connect(&ConnectConfig) -> Result<Connection, MysqlError>`.
- Every stub returns its `Unimplemented` variant. The subjects and aegis-otlp exit 2 with a message on stderr and
  write nothing to stdout.

**Layer registration.** Layers are read from `[package.metadata.aegis] layer`. `cargo xtask layering` also gains two
checks:
- `PINNED_LAYERS`: aegis-wire 2, aegis-adapter-mysql 4, aegis-uring 4, aegis-otlp 5. A crate that moves off its layer
  fails.
- `SEPARATE_BINARIES`: aegis-pdp, aegis-p2, aegis-otlp. A dependency of any kind on one of them fails.

The layering self-test gains three mutants, and each is rejected:
- aegis-bin -> aegis-otlp, rejected twice (separate binary, and an L5 -> L5 edge);
- aegis-wire -> aegis-adapter-mysql (L2 -> L4);
- aegis-uring moved to L3.

## 2. io-uring =0.7.15

- **Root pin.** `io-uring = { version = "=0.7.15", default-features = false }`, so no `bindgen` and no
  `direct-syscall`. The comment on the root pin rule names this exception (PREFLIGHT D-P7.3).
- **Lock.** Adds exactly one registry crate. Checksum `ed3bd0ec…f2bb`, which matches the sha256 of the downloaded
  .crate. Its dependencies bitflags 2.13.2, cfg-if and libc are already locked.
- **Lock target.** `io-uring = "0.7.15"` in `supply-chain/lock-targets.toml`.
- **lock-age.** Published 2026-09-07, 60 days ago. `LOCK-AGE: PASS` over 286 packages, which is 285 + io-uring.
- **deny.** `advisories ok, bans ok, licenses ok, sources ok` (MIT OR Apache-2.0, no duplicate versions).
- **vet: zero exemptions.** None of the 6 configured import sets covers io-uring at safe-to-deploy. Neither does any
  set in the cargo-vet registry: the only audit found is google's safe-to-run for 0.5.13. So
  `supply-chain/audits.toml` now carries an **own `safe-to-deploy` audit of 0.7.15**.
  - I read all the hand-written code, about 5.9k lines, including the ~87 unsafe sites. The bindgen `sys_*.rs` files
    were spot-checked. The build.rs does nothing without `bindgen`.
  - The notes record two caveats, neither reachable from an accept/recv/send front:
    - `register_ifq` is a safe fn that passes raw addresses to the kernel;
    - `cq_off.flags` is 0 on kernels older than 5.8.
  - Result: `Vetting Succeeded (51 fully audited, 26 partially audited, 195 exempted)`; Phase 6 had 50 fully audited.
  - `vet-baseline.py`: PASS, 218 exemptions, unchanged.
  - **Red:** with the audit removed, `cargo vet --locked` gives `Vetting Failed! io-uring:0.7.15 missing
    ["safe-to-deploy"]`.
  - **This audit is an agent review.** Its `who` field says so. The operator should countersign it, or replace it
    with a human audit.

## 3. Gate default-graph (`ci/default-graph.py`)

**Baseline.** `ci/fixtures/default-graph/baseline.txt` holds 79 packages. It was generated from a `git archive` of
e06550e with `cargo tree -p aegis-bin -e normal,build --target all --locked`, and is identical to the current tree's
default graph.

**Checks.**
- **G1:** the default package set equals the baseline exactly.
- **G2:** none of io-uring, aegis-wire, aegis-uring, aegis-adapter-mysql or aegis-otlp is in the default graph or the
  `--features native` graph.
- **G3:** every Phase 7 feature exists, and none can be reached from its crate's `default` feature (closure over that
  crate's own `[features]` table).
- **G4:** cargo's real feature resolver shows no Phase 7 feature enabled on aegis-bin, aegis-tls or aegis-adapter-pg,
  in either the default or the native graph. This catches another crate switching a feature on.

**Self-test.** The fixtures are generated from real cargo output with the path suffixes dropped. The two clean
controls pass. Each mutant fails with exactly the expected check ids:
- `mutant-io-uring.tree`: aegis-bin default pulls io-uring. Fails G1, G2 (io-uring, aegis-uring) and G4.
- `mutant-adapter-mysql.tree`: fails G1 and G2.
- `mutant-changed-set.tree`: tokio re-versioned and want added, with no Phase 7 crate. Fails G1 only.
- `native-mutant-crdb.tree`: fails G4.
- Four feature-table mutants built from `features-clean.json`. Each fails G3:
  - `default = ["uring"]`;
  - default → native → l4;
  - aegis-tls `default = ["mtc"]`;
  - adapter-crdb missing.
- Three live mutants run the real resolver with `--features uring`, `adapter-mariadb` and `mtc`. Each fails G2 on
  io-uring, aegis-adapter-mysql and aegis-wire respectively.

**Red on the real input.** Setting `default = ["uring"]` in aegis-bin gives `DEFAULT-GRAPH: FAIL (9 violations)`: G1,
G2 default and native, G3, G4 default and native. Restoring it gives PASS.

**What it does not cover.** The gate is cargo tree and metadata only, with no build. The §6 numbers (size, crate count,
unsafe lines) stay with the carried `budget` gate, which is run below.

## 4. Fuzz and Kani registration

**Fuzz.**
- `fuzz/Cargo.toml` gains the aegis-wire path dependency and two `[[bin]]` entries. `fuzz/Cargo.lock` gains only
  aegis-wire.
- The stub targets assert properties that hold for both the stub and the real parser:
  - `consumed <= input`, `consumed <= 16 + 536`, and v1 never accepted;
  - a handshake record, the declared length ≤ MAX_RECORD, and every field a sub-slice of the input.
- Each target has a planted `selftest!` panic.

**Kani.**
- `ci/kani.sh` gains `-p` (an alias for `--crate`), `--mem M` (validated, sets MemoryMax) and `--serial` (a no-op,
  since harnesses already run serially).
- When `--neg` is not given, the negative control is chosen per crate. The aegis-budget, aegis-tls and other existing
  invocations are unchanged.
- `crates/aegis-wire/src/kani_proofs.rs` has two stub harnesses (every input refused) and the planted-OOB negative
  control.

| command | result |
|---|---|
| `ci/remote.sh ci/fuzz.sh self-test --targets proxy_v2,client_hello_peek` | `FUZZ: PASS (self-test: 2/2 planted panics found within 1e6 execs …)`, after about 380 and 557 execs |
| `ci/remote.sh ci/fuzz.sh run --execs 100000 --targets proxy_v2,client_hello_peek` | `FUZZ: PASS (2/2 targets reached 100000 execs, 0 crashes/timeouts/OOMs; skipped: none)` |
| `ci/kani.sh --serial --mem 6G -p aegis-wire` (kamrui) | `KANI: PASS`, `KANI SELF-TEST: PASS` (2 OK, negative control FAIL_AS_EXPECTED) |

## 5. Other checks run

| command | result |
|---|---|
| `ci/remote.sh cargo clippy --workspace --all-targets --locked -- -D warnings` | clean |
| clippy and build of `-p aegis-bin --features proxy-protocol,l4,mtc,uring,adapter-mariadb,adapter-crdb`; build of `-p aegis-tls --features mtc` | clean |
| `cargo test -p` on the 6 new packages | ok (0 tests) |
| `cargo run -p aegis-otlp` | `aegis-otlp: exporter not built (P7-otlp-001); refusing to start`, exit 2 |
| `cargo fmt --all --check`, and the same for fuzz | clean |
| `cargo xtask layering --self-test` | PASS (the new mutants are listed in §1) |
| `cargo xtask unsafe-sites` | PASS (54 packages) |
| `cargo xtask fips-lock --profile floor` | PASS |
| `cargo xtask allowlist-lock --check` | PASS |
| `python3 -I ci/interfaces.py check` | PASS (16 frozen files unchanged) |
| `python3 -I ci/panic-abort.py` | PASS |
| `python3 -I ci/compliance.py check` | PASS |

## 6. Acceptance

`python3 -I ci/default-graph.py && python3 -I ci/default-graph.py --self-test && cargo xtask layering && cargo xtask
lock-age --min-days 7 && cargo xtask lock-targets && ci/remote.sh cargo xtask budget`

Exit 0. Tail lines:

| step | result |
|---|---|
| `ci/default-graph.py` | `DEFAULT-GRAPH: PASS (default graph = e06550e baseline, 79 packages; native graph 83 packages; no Phase 7 crate or feature in either)` |
| `ci/default-graph.py --self-test` | `DEFAULT-GRAPH SELF-TEST: PASS` (3 clean, 8 fixture/table mutants, 3 live mutants) |
| `cargo xtask layering` | `LAYERING: PASS` |
| `cargo xtask lock-age --min-days 7` | `LOCK-AGE: PASS` (286 packages, root + cmvp) |
| `cargo xtask lock-targets` | `LOCK-TARGETS: PASS` (13/17 present) |
| `ci/remote.sh cargo xtask budget` | `BUDGET: PASS (default: size 5373664 B (<= 6000000), 45 third-party + 19 workspace crates, non-crypto unsafe 4948 lines …; native: size 7070208 B …; p2-worker: size 9722912 B …)` |

The default (5,373,664 B) and native (7,070,208 B) sizes and crate counts are byte-identical to the Phase 6 budget log
(`gates/out/logs/phase6-budget*.log`). The default build did not move.

## 7. Outside write_scope: needs the coordinator

1. **`profiles/cmvp/Cargo.lock` must gain the new members. Without that, the carried cmvp gates go red.**
   - `profiles/cmvp/build.sh --metadata` runs `cargo metadata --locked` on a copy of the whole workspace. With six new
     path members and io-uring, it now fails with "cannot update the lock file … because --locked was passed".
   - This breaks `fips-lock --profile cmvp`, cmvp-supply and the cmvp builds.
   - The fix is purely additive: 65 lines, the six members plus io-uring, with no version change. To produce it,
     copy the current cmvp lock into `target/cmvp-src/` (after `build.sh --metadata` has prepared it), run a
     non-locked `cargo metadata --manifest-path target/cmvp-src/Cargo.toml`, and copy the lock back to `profiles/cmvp/`.
   - I produced and checked that lock: `cargo metadata --locked` then succeeds. But `profiles/**` is not in this unit's
     scope, so I did not write it.
   - The lock is at
     `/tmp/claude-1000/-home-patrickd/b4045317-3a36-45b5-8cfe-a4b20991f0b0/scratchpad/cmvp-Cargo.lock.proposed`
     (diff: `…/cmvp-Cargo.lock.diff`).
   - After it lands, `build.sh --vet` will need the io-uring audit too. The audit is in the shared supply-chain store,
     so it already covers that.
2. **`subjects/tls-subject/Cargo.toml` needs `mtc = ["aegis-tls/mtc"]`.** P7-mtc-001's acceptance builds
   `-p tls-subject --features mtc`, and that manifest is in neither P7-mtc-001's write_scope nor this one's.

## 8. Notes for downstream units

- **P7-uring-001.** Pushing SQEs needs `unsafe`: io-uring's `SubmissionQueue::push` is `unsafe fn`, because the caller
  must keep the buffers alive until completion, and the crate has no safe submission API. With
  `#![forbid(unsafe_code)]` in aegis-uring, the unit's own escape hatch applies: an INFEASIBLE_REPORT proposing
  aegis-iso audited sites. Do not call `register_ifq`.
- **P7-otlp-001.** hyper's client features need want, futures-channel and smallvec, none of which is in the lock, so
  they were not added (they would be a new intake). For POST, aegis-egress's hand-written HTTP/1.1 exchange
  (`http1::exchange`, `Method::Post`) and its `tls-client` handshake are wired in instead.
- **P7-bin-001.** `adapter-mariadb` and `adapter-crdb` imply `native`. `default-graph` also guards the native graph
  (G2, G4), so crdb or mariadb code that leaks into plain `native` fails.
