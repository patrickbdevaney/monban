# P7-oracle-uring-001 report (spec author, 2026-11-06, base 00ca246)

**Status: done.**
- Oracle `oracles/front-equiv/` and drop-in `deploy/uring.conf` are written.
- The self-test is green on the desktop (12/12 mutants caught).
- The oracle is red today, for two independent reasons:
  1. aegis has no `--front` flag and no `listeners[].front` field;
  2. **the hardened unit admits io_uring today**, a finding outside this unit's write scope (see below).

Nothing is infeasible, and no check was weakened.

## What was delivered

| path | what |
|---|---|
| `oracles/front-equiv/run`, `equiv.py` | the oracle (`--binary`, `--binary-from-build`, `--self-test`) |
| `oracles/front-equiv/unitcheck.py` | systemd half: offline SystemCallFilter algebra plus a `systemd-run --user` runtime probe |
| `oracles/front-equiv/front_ref.py`, `aegis-front-ref`, `uring.py`, `noring_exec.py` | self-test reference front (a real io_uring ring through ctypes + mmap), its 8 front mutants, and the seccomp io_uring-EPERM exec wrapper |
| `oracles/front-equiv/h2load.lock` | h2load 1.69.0 as pinned Alpine 3.22 packages (sha256). The desktop has no Docker and no h2load, so the oracle fetches and unpacks them into `$AEGIS_TOOLS/h2load-1.69.0` with no apt or sudo. |
| `oracles/front-equiv/needs` | `kamrui` (see "Follow-ups") |
| `deploy/uring.conf` | drop-in that re-admits only `io_uring_setup io_uring_enter io_uring_register` |

## The interface P7-uring-001 / P7-bin-001 must provide

It is fixed in `oracles/front-equiv/README.md` ("The interface the implementer must provide"). In short:

- **Flag.** `aegis --config <f> ... --front epoll|uring` is a serve option like `--cert`, not a subcommand.
- **Config field.** F8 `listeners[].front = "epoll"|"uring"`; absent means epoll. The CLI flag overrides the field.
- **Refusals.** `--front <other>` exits 64. A bad `front` in the config exits 78. Nothing is bound in either case.
- **Identity under uring**, same pid, read from /proc:
  - at least one `anon_inode:[io_uring]` fd;
  - CqTail advances by at least 1 per client connection;
  - client connection sockets and the listener are not registered in any epoll instance.
- **Identity under epoll:** no io_uring fd, and the connection socket is registered in epoll.
- **Fails closed.** If io_uring_setup fails, `--front uring` exits non-zero within 8 s, prints a message containing
  `io_uring`, and never accepts a connection. It never falls back to epoll. `--front epoll` keeps working under the
  same filter.
- **FRONT-1:** byte-identical normalized responses, close behaviour and upstream view across the whole corpus,
  including h2load and the zero-window stall run.

## Acceptance

`ci/remote.sh oracles/front-equiv/run --self-test` (desktop):

```
  baseline (reference front, fixture unit): PASS (120 checks; zero-window stall wall epoll 10.1 s / uring 10.1 s)
  mutant drop-last-chunk: caught by equiv.body.big-1m, equiv.body.big-chunked-upstream, equiv.body.big-then-small, equiv.pipeline.mixed
  mutant reorder-pipelined: caught by equiv.pipeline.3, equiv.pipeline.mixed, equiv.reject.bad-chunk-size, equiv.reject.bare-lf-chunk-line
  mutant close-after-response: caught by equiv.get.canonical, equiv.post.chunked, equiv.post.length, equiv.post.large-256k, equiv.response.hop-by-hop, equiv.slash.exact ...
  mutant normalize-bare-lf: caught by equiv.post.large-256k, equiv.fragmented.1-byte-writes, equiv.reject.bare-lf, equiv.reject.bare-lf-chunk-line, equiv.reject.after-good-on-same-conn
  mutant no-ring: caught by uring.identity.has-io_uring, uring.identity.cq-moves-with-traffic
  mutant socket-in-epoll: caught by uring.identity.conn-not-in-epoll
  mutant silent-fallback: caught by fallback.uring-refuses-without-io_uring, fallback.nothing-listened, fallback.message-names-io_uring
  mutant config-front-ignored: caught by cli.config-front-uring.identity.has-io_uring, cli.config-front-uring.identity.cq-moves-with-traffic, cli.config-front-uring.identity.conn-not-in-epoll
  mutant unit-admits: caught by unit.denies-io_uring, runtime.unit-denies
  mutant dropin-broad: caught by dropin.only-io_uring
  mutant dropin-incomplete: caught by dropin.admits-io_uring, runtime.dropin-admits
  mutant dropin-relaxes-other: caught by dropin.only-io_uring
FRONT-EQUIV SELF-TEST: PASS (12/12 mutants caught: drop-last-chunk, reorder-pipelined, close-after-response, normalize-bare-lf, no-ring, socket-in-epoll, silent-fallback, config-front-ignored, unit-admits, dropin-broad, dropin-incomplete, dropin-relaxes-other)
rc=0
```

## Red evidence (before P7-uring-001)

`ci/remote.sh bash -c 'ci/heavy.sh cargo build --release --locked -q -p aegis-bin && oracles/front-equiv/run --binary target/release/aegis'`
(desktop, the default build at 00ca246):

```
  FAIL epoll.start: --config /tmp/aegis-front-equiv-mwyfe4_d/aegis-53175.json --cert /tmp/aegis-front-equiv-mwyfe4_d/cert.pem --key /tmp/aegis-front-equiv-mwyfe4_d/key.pem --audit-dir /tmp/aegis-front-equiv-mwyfe4_d/audit-53175 --front e...
  FAIL uring.start: --config /tmp/aegis-front-equiv-mwyfe4_d/aegis-53865.json --cert /tmp/aegis-front-equiv-mwyfe4_d/cert.pem --key /tmp/aegis-front-equiv-mwyfe4_d/key.pem --audit-dir /tmp/aegis-front-equiv-mwyfe4_d/audit-53865 --front u...
  FAIL cli.config-front-uring.start: --config /tmp/aegis-front-equiv-mwyfe4_d/aegis-44429.json --cert /tmp/aegis-front-equiv-mwyfe4_d/cert.pem --key /tmp/aegis-front-equiv-mwyfe4_d/key.pem --audit-dir /tmp/aegis-front-equiv-mwyfe4_d/audi...
  FAIL cli.config-front-epoll.start: --config /tmp/aegis-front-equiv-mwyfe4_d/aegis-50753.json --cert /tmp/aegis-front-equiv-mwyfe4_d/cert.pem --key /tmp/aegis-front-equiv-mwyfe4_d/key.pem --audit-dir /tmp/aegis-front-equiv-mwyfe4_d/audi...
  FAIL cli.cli-overrides-config.start: --config /tmp/aegis-front-equiv-mwyfe4_d/aegis-41013.json --cert /tmp/aegis-front-equiv-mwyfe4_d/cert.pem --key /tmp/aegis-front-equiv-mwyfe4_d/key.pem --audit-dir /tmp/aegis-front-equiv-mwyfe4_d/au...
  FAIL fallback.message-names-io_uring: stderr does not name io_uring: 'aegis: unknown argument "--front"\nusage: aegis --config <path> [--cert <pem>] [--key <pem>] [--audit-dir <dir>] [--runtime-dir <dir>] [--token-keyring <file>]\n    ...
  FAIL fallback.epoll-unaffected: --front epoll under the same filter: exited 64 at start: aegis: unknown argument "--front"
  FAIL unit.denies-io_uring: aegis-hardened.service alone admits ['io_uring_enter', 'io_uring_register', 'io_uring_setup'] (SystemCallFilter=@system-service includes @aio; add SystemCallFilter=~io_uring_setup io_uring_enter io_uring_regi...
  FAIL runtime.unit-denies: io_uring_setup under the unit's filter: ok
FRONT-EQUIV: FAIL (9 failed: epoll.start, uring.start, cli.config-front-uring.start, cli.config-front-epoll.start, cli.cli-overrides-config.start, fallback.message-names-io_uring, fallback.epoll-unaffected, unit.denies-io_uring, runtime....
oracle-rc=1
error: the package 'aegis-bin' does not contain this feature: uring
build-uring-rc=101
```

The gate command itself, `cargo build ... -p aegis-bin --features uring`, also fails today: aegis-bin has no `uring`
feature until P7-spec-002 adds it.

## Findings

1. **The hardened unit admits io_uring today, and the gate stays red until that is fixed.**
   - `SystemCallFilter=@system-service` includes `@aio`, which contains io_uring_setup, _enter and _register.
     The `~@privileged @resources ...` line does not remove them.
   - The offline expansion shows it, and so does the runtime probe: a transient `systemd-run --user` service with
     the unit's filter lines got `io_uring_setup: ok`.
   - The fix is one line in `deploy/aegis-hardened.service`:
     `SystemCallFilter=~io_uring_setup io_uring_enter io_uring_register`. With that line, systemd-analyze exposure
     stays at 1.6, and so does unit + drop-in.
   - That file is not in this unit's write scope, and **no Phase-7 unit owns it**. It is an integrator edit
     (P7-spec-002 or a hub fix).
   - The self-test uses that fixed unit as its positive fixture (`unitcheck.fixture_good`), and today's file as the
     `unit-admits` mutant.
2. **aegis sends two 400 responses on a bad chunk-size line or a bare LF in a chunk line.** The first is hyper's,
   with a `date` field. The second is the strict filter's reject, without one. Then the connection closes. This is
   deterministic: 45 of 45 tries across one-write, split-write and reference-front delivery. The oracle compares it
   as-is, so a uring front must reproduce it. It still violates one-request-one-response and belongs to
   aegis-transport (no Phase-7 owner).
3. **The per-IP admission GCRA (1000/s, burst 2000) makes transport-limits-sized runs time-dependent.** 300 × 3000
   requests gave 260 successes and 2740 4xx on epoll. Such counts would differ between fronts by timing alone. The
   load phases are therefore sized ≤ 1200 requests, with a 2.5 s refill pause before each, and on epoll they must be
   all-2xx (`corpus.load.*.ran`).

## Harness issues found while writing the oracle (all fixed before the green run)

- A 70 KB head (431): the server closes with unread bytes, and the RST raced the 431 away in 1 of 15 tries through
  the reference front. Both 431 cases now fit in one TLS record, and failed client writes no longer abort the
  reads.
- Bytes buffered behind the last parsed response were dropped. They are now part of the compared `after` field.

## Follow-ups (integrator)

- Add the io_uring deny line to `deploy/aegis-hardened.service` (finding 1).
- `ci/oracles.sh` has no "own gate, no aggregate" marker other than `kamrui`. front-equiv's `needs` says
  `kamrui`, with a comment that it really runs on the desktop. That keeps oracles-remote, oracles-local and
  oracles-quiet from running it with no `--binary`. A dedicated marker such as `own-gate` would be cleaner.
- Rungs: FRONT-1 at R2 (behavioural equivalence on one corpus, one host). The /proc identity is evidence, not proof
  that every byte uses the ring. io_uring perf stays advisory (D-P7.3).
