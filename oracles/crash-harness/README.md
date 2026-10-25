# crash-harness: oracle for INV-DURABLE

Gates `spec/SPEC_INVARIANTS.md` §B **INV-DURABLE**: *ack(w) ⇒ w survives any single crash (SQLite WAL FULL single
writer / redb 2PC Immediate); bootstrap fsyncs file and parent directory before serving.* This oracle also closes the
plan's open items **double fault** (a crash during recovery) and **fsync EIO** (q2-007; IMPLEMENTATION_PLAN §2 row
"crash harness").

## Usage

```
oracles/crash-harness/run                       # reduced run, ~3 min on the laptop, ~20k crash images
oracles/crash-harness/run --self-test           # 6 mutations, all must be caught (~15 s)
oracles/crash-harness/run --full                # research-size run: CI/VPS job (see "Full size")
oracles/crash-harness/run --subject '<cmd> {dir}'   # plug in the aegis-state store (see "Subject protocol")
  options: --txns N --cuts N --seeds 1,2,3 --eio N --double N --double-cuts N --jobs N --keep --keep-build
```

`run` re-executes itself under `ci/heavy.sh`, so the build and the simulation both hold the machine-wide heavy-job
lock. It builds `rust/` (`cargo build --release --locked`), runs `python3 -I crashsim.py`, and **deletes
`rust/target/` on exit** unless you pass `--keep-build`. The last line is `CRASH-HARNESS: PASS|FAIL (...)` and the exit
code is 0 only on PASS. `.work/last-run.json` keeps the per-subject tallies.

## What is checked

The oracle owns the workload: txn *i* writes 5 rows across 2 tables (`ctr`, `a{i%50}`, `g{i}`, `b{i%50}`; values of
64 to 1,864 B; identical to research `wl::ops`). It records the subject's trace with an LD_PRELOAD tracer (Rust cdylib
`rust/shim` plus `open_shim.c` for the variadic `open*`). The trace covers write/pwrite/writev, fsync/fdatasync,
O_DSYNC, truncate/fallocate, open/O_TRUNC, rename/unlink/mkdir/rmdir, and the ack markers. The oracle then
reconstructs crash images under the persistence model and reopens each image with the subject.

An image is **ok** only if all of these hold: the store opens; the dump is readable; `ctr` agrees across both tables
(atomicity); the state equals exactly the first *c* transactions; *c* ≥ the acked count at the crash point; and the
store's integrity check passes (SQLite `PRAGMA integrity_check`, redb `check_integrity()`; redb's `false`, meaning it
repaired something, counts as a failure). The failure classes are `open_fail`, `read_fail`, `atomicity`,
`state_mismatch`, `lost_ack`, `integrity_fail`, `corrupt_ctr`, `crash_*` and `timeout`. Failures at crash points before
the subject's first `BEGUN` are bootstrap-window failures (`init_*`): nothing has been served yet, so they are reported
but not counted, as in the research.

**Crash points:** every post-ack instant (the op right after each ack marker, where ack-before-durable bugs live), a
seeded random sample, and the end of the trace. **Images per crash point:** 10, from the
policy × namespace-regime matrix ported from research:

| data policy | namespace regimes |
|---|---|
| dropall (all unsynced data lost) | journal, fsfile, strict |
| all (SIGKILL: page cache survives) | full |
| subset (each 4 KiB page of each unsynced write survives w.p. ½, any order) | journal, fsfile, strict |
| prefix (random prefix in issue order, last write torn at 512 B) | journal, fsfile, strict |

`strict` = POSIX (an entry is durable only after its parent directory is fsynced); `fsfile` = ext4/xfs practice;
`journal` = ext4 data=ordered-like.

The run has three stages per subject:

1. **main.** The workload runs under the tracer, followed by a coverage audit. The audit **fails closed** on any
   unmodelled op (link, symlink, exchange-rename, copy_file_range, a writable shared mmap other than SQLite's
   non-durable `-shm`), on ack markers ≠ acks, or on a trace with no O/W/S records (the interposer was bypassed).
2. **eio.** The k-th fsync returns EIO, for k ∈ {1 (bootstrap), the first commit fsync, a mid-run commit fsync, the
   last fsync}. The model follows fsyncgate: that file's unsynced writes become *limbo*. Each image either has them or
   not, and a later successful fsync does **not** promote them. The rule: **once an fsync has failed, no ack may
   follow** (the store must fail-stop). Crash images are taken from the EIO point onward.
3. **double.** N first-crash images (spread over the post-ack cuts, rotating dropall/strict, prefix/journal,
   subset/fsfile, dropall/journal) are reopened under the tracer, and that recovery is traced. Every crash point of the
   recovery (sampled down to `--double-cuts`) is replayed with the first image as the durable base. The result is
   checked against the **first** crash's ack count.

Reference subjects (`rust/refstore`): `sqlite:wal-full` (golden default), `redb:2pc` (passing alternative), `wal:crc`
(own CRC-framed log with fdatasync per commit, the expected shape of aegis-state). All of them do the INV-DURABLE
bootstrap: fsync every file, then the directory, before `READY`.

## Pass criterion

`PASS` iff every subject and seed has zero counted violations across all three stages, and the coverage audit is
clean. `--self-test` passes iff every mutation is caught:

| mutation | subject | expected catch |
|---|---|---|
| SQLite WAL `synchronous=NORMAL` instead of FULL (dropall model) | sqlite:wal-normal | `lost_ack` |
| ack before fsync (`--ack-early`: `OK` sent before the commit) | sqlite:wal-full | `lost_ack` |
| skip the parent-directory fsync at bootstrap (`--no-dirsync`) | redb:2pc | `lost_ack` (strict regime) |
| fsync EIO treated as success (tracer `AEGIS_EIO_SWALLOW=1`) | wal:crc | `ack_after_eio` (+ `lost_ack`) |
| extra: redb `Durability::None` | redb:none | `lost_ack` |
| extra: own log without fsync | wal:naive | `lost_ack` |

With `--subject`, the self-test also runs the EIO-swallow mutation against the subject, plus `--ack-early` /
`--no-dirsync` if the subject advertises them in its READY line (`mutations=ack-early,no-dirsync`).

## Subject protocol (for the future aegis-state store)

The subject is any executable; `{dir}` in `--subject` is replaced by the store directory (or appended). It speaks
newline-terminated text over stdin/stdout:

```
start                 -> open/create the store in {dir}; bootstrap (fsync files, then the dir); print
                         "READY <free text> [mutations=ack-early,no-dirsync]"   or   "ERR open <msg>" and exit != 0
BEGIN <i>             -> "BEGUN <i>"
PUT <t> <khex> <vhex> -> (no reply) buffer a put into table t ∈ {0,1}
COMMIT <i>            -> "OK <i>" only once the txn is durable;  "ERR <i> <msg>" otherwise. After any ERR the store
                         must fail-stop (every later COMMIT gets ERR): never retry an fsync and ack.
DUMP                  -> "KV <t> <khex> <vhex>" per row, then "END"   (or "ERR dump <msg>")
CHECK                 -> "INTEGRITY ok <msg>" | "INTEGRITY fail <msg>"   (detect only; never silently repair)
QUIT / EOF            -> clean close, exit 0
```

Requirements, all checked:
- each reply line goes out in **one write(2)** on fd 1 (the tracer turns `OK <i>` / `BEGUN <i>` into ack markers;
  `AEGIS_PROTO_FD` overrides the fd);
- the subject is dynamically linked against glibc and does its I/O through libc. Raw syscalls (rustix `linux_raw`,
  io_uring, static binaries) bypass LD_PRELOAD; the audit catches a missing O/W/S trace but cannot see partial
  bypass, so build Rust subjects with `RUSTFLAGS='--cfg rustix_use_libc'` (research lesson from fjall);
- no writable shared mmap of durable files.

The trait the aegis-state crate should expose, so its CLI wrapper is ~40 lines:

```rust
pub trait CrashSubject {
    fn open_bootstrap(dir: &Path) -> Result<Self, Error> where Self: Sized; // fsync files + dir before Ok
    fn commit(&mut self, puts: &[(u8, Vec<u8>, Vec<u8>)]) -> Result<(), Error>; // Ok only once durable; Err poisons
    fn dump(&mut self) -> Result<BTreeMap<(u8, Vec<u8>), Vec<u8>>, Error>;
    fn check(&mut self) -> Result<(), Error>; // detect-only integrity check
}
```

## Pins and build

`rust/` is its own workspace with its own `Cargo.lock`, excluded from the main workspace by `exclude = ["oracles"]`.
- `rusqlite =0.40.2` (bundled `libsqlite3-sys 0.38.2` = **SQLite 3.53.2**; the golden floor is ≥3.51.3, and refstore
  refuses to start below it). rusqlite 0.41.0 was published 2026-10-24, under 7 days before this port, so the previous
  release is pinned.
- `redb =4.4.0` (2026-10-13), `libc =0.2.191` (2026-10-16), `cc =1.8.0` (build-only).
- Lock-age audit on 2026-10-25: three transitive crates were under 7 days old and were moved to their previous
  releases (`cc` 1.10.0 → 1.8.0, because 1.9.0 is also 6 days old; `find-msvc-tools` 0.1.15 → 0.1.14; `smallvec`
  1.16.4 → 1.16.3). Every locked crate is now ≥9 days old.
- Build: ~30 s, 59 MB `rust/target/`. The oracle directory without `target/` is ~150 KB. Peak `.work/` usage during a
  run is the in-flight images (≤ 4 × jobs images at a time, a few MB each).

## Full size (CI/VPS job)

`--full` = 300 txns, 400 random cuts plus every post-ack cut, seeds 1–3, 4 EIO positions, 20 double-fault bases × 60
recovery cuts, 3 subjects, roughly 170k images. Extrapolated from the reduced run at ~115 images/s on 8 workers, that
is ~30–45 min on this laptop. That exceeds the 10-minute budget and the default 30-minute `ci/heavy.sh` timeout, so it
runs as a CI/VPS job:

```
HEAVY_TIMEOUT=7200 oracles/crash-harness/run --full --jobs 16
```

## Provenance (research artifacts are untrusted input: read and ported, never executed in place)

| file (research/state/raw/) | sha256 |
|---|---|
| round-002/08-state-crash-consistency-experiment.harness/crashsim.py | 229f2f8855e14b78677b727abe4f89f8451e788014e9cb52479a66ec5c50b846 |
| round-002/08-state-crash-consistency-experiment.harness/main.rs (= work/wl/src/main.rs) | cae5f568b23f0bba6085c5a840ad8a4ee231b0a5a915a5b6f9a8d6c2d2adfb97 |
| round-002/08-state-crash-consistency-experiment.harness/shim.c | 103a4c4aee8a21259f25b31f501ffa04ec838126b7a5c94adfe739d226e9e884 |
| round-002/08-state-crash-consistency-experiment.harness/final.py | ed58d4e8643fc1bbe44661ef15cc8dc5408abcfd141c67dab16cdcd5f9661e11 |
| round-002/08-state-crash-consistency-experiment.harness/one.sh | 1bae84e42802d10aee043564562cbba4ed5d3d0b2761b209557f2df704ee0316 |
| round-002/work/wl/Cargo.toml | 56aaf514dbcdbf5da8aa38567baa5af8ef04a4b87f19f3519c268e7b49584937 |
| round-002/work/runall.sh | a9e148b0d45424574074de07a57087a229400481bae754a4e58069199e18679c |
| round-002/work/mkjobs.py / mkjobs2.py | edf580c29c093639901b0ef630ff8236650f541d7a3ced15bbac72c276f30fc6 / 58cf3883948b640b5f13a41fa80a5915a68daf223d08b0df15e33794a9514970 |
| round-002/work/patch1.py | 7073b227e3c64c32568a6dfcaccd124eb20d33081c7041378fc5c30965b9bff0 |
| round-002/work/summ.py | 98b5a8ee3a79216dff608a127f0d1867ad88cbf948eec33a7f98e001012d2131 |
| round-002/08-state-crash-consistency-experiment.final_table.json | 56d065581587ebde1693760764e308eb715bb8d3bf1720a195072aa7dfff7857 |
| round-002/08-state-crash-consistency-experiment.results.jsonl | 09c5829692ba376c29fcd6a1f635c0e17d45d4930b20800de9420dbb818264a6 |
| round-002/08-state-crash-consistency-experiment.json | fbd1968d2c89ab0e6a0f7ee8d76e7fe26666333ed551f915267b9df2a5e04fe2 |
| round-002/08-state-crash-consistency-experiment.progress.md | 6dedc7996dcfb1b59ddc1ad273c172d89d1424a2f6b1b3ef459d6c011e810229 |

What changed from research: the C shim became a Rust cdylib (only the variadic `open*` remain in C); the workload
moved into the driver behind a subject protocol; post-ack cuts are enumerated instead of only sampled; EIO and
double-fault stages were added; the coverage audit fails closed; the stores are reduced to the golden floor (SQLite,
redb) plus the own-log controls (fjall/heed/canopydb/sled dropped).

## Re-run in repo (2026-10-25, laptop, rustc 1.99.1, SQLite 3.53.2, redb 4.4.0)

`./run`: `CRASH-HARNESS: PASS (images=19860 [main=9790 eio=710 double=9360], subjects=3, seeds=1, 188s)`

| subject | main | eio | double | violations | bootstrap-window (not counted) |
|---|---|---|---|---|---|
| sqlite:wal-full | 3,430 | 630 | 5,560 | 0 | init_open_fail 6 |
| redb:2pc | 3,410 | 40 | 3,200 | 0 | init_open_fail 2 |
| wal:crc | 2,950 | 40 | 600 | 0 | 0 |

`./run --self-test`: `CRASH-HARNESS SELF-TEST: PASS (6/6 mutations caught; images=5630)`. SQLite WAL+NORMAL lost an
acked txn in 624 of 790 images (79%; research reported 85% = 3,391/4,010 over 3 seeds at 300 txns). ack-early: 680
of 800. no-dirsync on redb: 111 of 780 (strict regime only). EIO swallowed: `ack_after_eio` on 4 of 4 EIO positions,
plus lost acks.

Comparison with research: SQLite WAL FULL is 0 violations, as in research (0 of 4,010). redb 2PC is 0 violations
here, while research saw 1,176 of 8,020 `lost_ack`, all in the strict regime. Research's workload never fsynced the
parent directory; ours does the INV-DURABLE bootstrap, and removing it (`--no-dirsync`) brings the strict-regime
losses back. That reproduces the research cause. One research number is off: the round-002 tables sum to ~146k
states over 19 configurations, not "~130k".

**New finding (EIO stage, first run).** With EIO on the first fsync, which hits `s.db-journal` while converting a
fresh file to WAL, SQLite 3.53.2 silently fell back to the rollback journal. `PRAGMA journal_mode=WAL` had already
returned `wal` and no error surfaced. The store then served in DELETE mode and lost acked writes (research's `wl`
has the same unchecked PRAGMA). refstore now re-reads `journal_mode` and `synchronous` after the schema write and
refuses to start otherwise. **aegis-state must do the same.**

## Known limits

- This is a logical-op replay (ALICE-style), not a block device. It does not model sub-sector tearing, bit rot,
  misdirected writes, the device write cache, or `O_DSYNC` reopen anomalies (LKML 2602.2/03173).
- LD_PRELOAD cannot see raw syscalls or io_uring (see "Subject protocol"). mmap stores are flagged and fail, not
  modelled.
- EIO model: a single injected EIO per run; the failed fsync is not issued to the kernel; limbo pages are
  all-or-nothing per policy (page-wise for subset). It does not model ENOSPC, or EIO surfacing on a later fsync of a
  different fd (errseq semantics).
- Double fault: one level (a crash during the first recovery). Recovery = open + DUMP + CHECK + clean close, which
  covers SQLite's WAL recovery/checkpoint/WAL delete on close and redb's repair inside `check_integrity`.
- `init_*` (crash during first-time creation, before READY) is reported, not gated. redb leaves an unopenable file
  ("magic number mismatch") when killed inside `Database::create`. aegis-state should create via temp file + rename
  + dir fsync, so that a crash during bootstrap can be retried.
