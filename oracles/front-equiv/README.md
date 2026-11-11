# front-equiv: epoll vs io_uring front equivalence (unit P7-oracle-uring-001)

Gate `front-equiv` (gates/phase-7.toml, desktop, `remote = true`). Clauses: F1 **FRONT-1** ("responses and rejects
are a function of the request bytes, never of the front"), PREFLIGHT **D-P7.3** (opt-in front, fails closed, not in
the hardened unit without a drop-in). Implementer: P7-uring-001 (crates/monban-uring), wired by P7-bin-001.

```
oracles/front-equiv/run --binary target/release/monban     # gate: monban-bin built with --features uring
oracles/front-equiv/run --binary-from-build               # builds that into target/front-equiv via ci/heavy.sh first
oracles/front-equiv/run --self-test                        # reference front must PASS, every mutant must FAIL
                       [--unit deploy/monban-hardened.service] [--dropin deploy/uring.conf] [-v]
```

Run it on the desktop: `ci/remote.sh oracles/front-equiv/run ...` (needs kernel.io_uring_disabled=0, which the run
mode checks). Tools: python3 (stdlib), openssl CLI, curl with HTTP2, `systemd-analyze`, `systemd-run --user`, and h2load
1.69.0, which the oracle fetches itself on first use from the pinned Alpine 3.22 packages in `h2load.lock` (the same
nghttp2=1.69.0-r0 as the transport-limits image). They are sha256-checked and unpacked into
`$AEGIS_TOOLS/h2load-1.69.0` (on the desktop: ~/aegis-ci/tools). This needs no Docker, apt or sudo. A missing tool is
a FAIL, never a skip.

## The interface the implementer must provide (exact)

The serve command line stays `monban --config <path> [--cert] [--key] [--audit-dir] ...` (there is no `serve`
subcommand) and gains:

| input | meaning | required behaviour |
|---|---|---|
| `--front epoll` | every HTTP listener uses today's tokio/epoll accept + I/O | identical to no flag |
| `--front uring` | every HTTP listener's accept and connection I/O go through io_uring (crates/monban-uring) | see below |
| `--front <anything else>` | usage error | exit **64** (EX_USAGE) before anything is bound |
| F8 `listeners[].front = "epoll" \| "uring"` | per-listener selection (P7-spec-001 F8 `listener.front`) | absent = epoll |
| F8 `front` with any other value | config error | exit **78** before anything is bound (CFG-1) |
| both flag and field | the CLI flag wins for every listener | `--front epoll` + `"front": "uring"` serves epoll |
| neither | epoll | the default build and the `uring` build both default to epoll |

The flag may appear anywhere among the serve options, like `--cert`. A build without feature `uring` must refuse
`--front uring` and `"front": "uring"` (exit 64 or 78, with a message). The gate cannot observe this, because it builds
with `--features uring`.

With `--front uring` (or the config field), on the **same binary** that serves `--front epoll`:

1. **FRONT-1 equivalence.** Every case below gives byte-identical normalized responses, the same close behaviour and
   the same upstream view as `--front epoll`.
2. **It is really io_uring** (/proc evidence, same pid as launched, no helper process):
   - the process holds at least one `anon_inode:[io_uring]` fd;
   - the summed `CqTail` over those rings advances by at least 1 per client TCP connection the run opened;
   - the server-side socket of a live client connection is an fd of that process and is **not registered in any
     eventpoll instance** (`tfd:` in /proc/<pid>/fdinfo);
   - the listening socket is not registered in epoll either.

   The ring fd itself may be registered in tokio's epoll; the connection sockets may not.
   Conversely, `--front epoll` must hold **no** io_uring fd, and its connection socket **is** in an epoll instance.
3. **It fails closed.** When io_uring_setup fails (here: a seccomp filter returning EPERM on io_uring_setup, _enter and
   _register, as `kernel.io_uring_disabled=2` or the hardened unit without the drop-in would do), `--front uring`:
   - exits non-zero within 8 s;
   - never accepts a connection on its listener port;
   - prints a message containing `io_uring`.

   It never falls back to epoll. `--front epoll` under the same filter still starts and serves.
4. SIGHUP reload, admin `/healthz` + `/metrics`, and SIGTERM drain (an idle keep-alive connection gets closed, exit
   0) behave as on epoll. The admin listener may stay on epoll.

## What is checked

**[equiv]** One deterministic upstream serves both runs: every response is a function of the request it received,
with the client-facing port normalized. The same binary runs first with `--front epoll`, then with `--front uring`.

- Responses are compared as raw bytes after two normalizations: the `date:` field value is masked, and the
  listener port is replaced by `{P}`.
- Close behaviour is `open` or `closed`, observed for 1.5 s after the last expected response (RST, FIN and
  close_notify all count as closed). Any bytes that arrive in that window, including bytes already buffered behind
  the last parsed response, are compared too (`after`).
- A connection that ends in the middle of a read is recorded as `<closed>`, whether it ended with EOF or a reset.
  A failed client write (the server closed while the client was still sending) is not itself compared: later
  writes are skipped, the reads still run, and what the server sent before it closed is compared.
- Every 431 case fits in one TLS record. Then the server never closes with unread TCP bytes, so no RST can race
  the response away. A 70 KB head lost its 431 that way in 1 of 15 tries through the reference front, which is
  why that case was removed.
- The upstream view is the list of (normalized request head, body sha256, body length) per case.

| group | cases | clause |
|---|---|---|
| forwarding (the proxy-e2e corpus) | canonical GET (path/query/header canon, hop-by-hop strip), chunked POST, CL POST, 256 KiB POST, response hop-by-hop, `/exact` vs `/exact/` 404, `/api/dir/`, opaque query, `%zz` 400, `//` 308, `..` 400, SNI≠Host 421, other vhost, no-authz 403 (GET/POST), unknown policy 403 | CANON-1/2/4/6, INV-NONEMPTY via FRONT-1 |
| bodies | 1 MiB CL body, 300 kB upstream-chunked body, slow streamed body (3 writes, 200 ms apart), close-delimited upstream body, large then small on one connection | FRONT-1 (no lost or extra bytes) |
| connection | 3 pipelined GETs; 4 pipelined mixed (POST, 40 kB, 403, GET); request in 1-byte writes; body in 700-byte writes; sequential keep-alive; `Connection: close`; HTTP/1.0; `Expect: 100-continue` | FRONT-1 (ordering, framing, close) |
| strict-H1 rejects | bare LF, obs-fold, CL+TE, duplicate CL, TE≠chunked, space before colon, absolute-form, leading CRLF, NUL in value, TE on 1.0, bad chunk size, bare LF in chunk line, Expect≠100-continue (417), 140 fields (431), 100 × 150-byte fields (431), double space in request line, reject after a good request on the same connection, CL+TE smuggle with a pipelined follower | H1 grammar (c) via FRONT-1; on epoll each must be a reject (status ≥ 400 or close) and the upstream must not see it |
| h2 (curl --http2) | canonical, `:authority` 421, 403, 308, 1 MiB body, 256 KiB POST | CANON-4/6 via FRONT-1 |
| load (h2load 1.69.0, TLS, ALPN) | 1 conn × 1000 requested streams × 1000 req (advertised stream cap); 300 conns × 1200 req; `--h1` 50 conns × 1000 req; mixed 200/403/308/404 over 4 conns; zero-window stall (2 conns × 10 streams of 4 MiB, `-w 0`) | TBI-4/7/8 via FRONT-1: equal succeeded/failed/errored/timeout and status-class counts, equal upstream request count, both stall runs reaped within 13 s or neither |
| reload | SIGHUP with an added route, then the new route is served | CFG-3 via FRONT-1 |
| drain | SIGTERM with an idle keep-alive connection: closed, exit code equal | NC8 via FRONT-1 |

**[identity]** The /proc evidence above, for both runs.

**[cli]** The default is epoll. `"front": "uring"` in the config gives the uring identity, and `"front": "epoll"` gives
epoll. `--front epoll` overrides `"front": "uring"`. `--front kqueue` exits 64 and `"front": "kqueue"` exits 78, with
nothing bound in either case.

**[fallback]** Fails closed, as in item 3 above (noring_exec.py installs the filter and then exec()s the subject, so
the pid is unchanged).

**[unit]** The checks run on `deploy/monban-hardened.service` alone and with `deploy/uring.conf` (unitcheck.py):

| check | pass |
|---|---|
| `unit.denies-io_uring` | the unit's effective SystemCallFilter denies io_uring_setup, _enter and _register. The set is computed with systemd.exec semantics over recursive `systemd-analyze syscall-filter` expansion. |
| `dropin.admits-io_uring` | unit + drop-in admits io_uring_setup and io_uring_enter |
| `dropin.only-io_uring` | the drop-in has only `[Service]` + `SystemCallFilter=` lines naming io_uring_* syscalls, and the allowed set grows by io_uring syscalls only (it never shrinks) |
| `dropin.exposure` | `systemd-analyze security --offline=yes` on unit + drop-in is ≤ 2.0 (the systemd-hardening bar) |
| `runtime.unit-denies` / `runtime.dropin-admits` | a transient `systemd-run --user` service carrying exactly those SystemCallFilter lines plus SystemCallErrorNumber=EPERM runs `uring.py probe`. io_uring_setup must return EPERM under the unit alone and succeed with the drop-in. This is the authoritative cross-check of the offline expansion. |

**PASS** iff every check passes.

## Self-test (negative controls)

The subject is `monban-front-ref` → `front_ref.py`. It implements the interface above around today's default monban
(`target/release/monban`, built through ci/heavy.sh if missing):

- With `--front epoll` it exec()s monban.
- With `--front uring` it probes io_uring_setup (and refuses if that fails), owns a real ring (one IORING_OP_NOP per
  accepted connection), terminates TLS itself with blocking sockets + poll(2), and relays plaintext to an monban child.

The unit fixture is the real hardened unit plus the deny line it needs (`unitcheck.fixture_good`). The baseline must
PASS. Then every mutant must FAIL:

| mutant | what it is | caught by (2026-11-06, desktop) |
|---|---|---|
| `drop-last-chunk` | withholds the last 4096 bytes of each h1 response with a body ≥ 16 KiB | equiv.body.big-1m, equiv.body.big-chunked-upstream, equiv.body.big-then-small, equiv.pipeline.mixed |
| `reorder-pipelined` | swaps two h1 responses that complete within 300 ms | equiv.pipeline.3, equiv.pipeline.mixed, equiv.reject.bad-chunk-size, equiv.reject.bare-lf-chunk-line |
| `close-after-response` | closes after the first h1 response | equiv.get.canonical, equiv.post.chunked, equiv.post.length, equiv.post.large-256k, equiv.response.hop-by-hop, equiv.slash.exact, ... |
| `normalize-bare-lf` | rewrites bare LF to CRLF (a lenient front: rejects vanish) | equiv.post.large-256k, equiv.fragmented.1-byte-writes, equiv.reject.bare-lf, equiv.reject.bare-lf-chunk-line, equiv.reject.after-good-on-same-conn |
| `no-ring` | "uring" without any ring | uring.identity.has-io_uring, uring.identity.cq-moves-with-traffic |
| `socket-in-epoll` | registers client sockets in an epoll instance | uring.identity.conn-not-in-epoll |
| `silent-fallback` | io_uring unavailable, so serves without a ring | fallback.uring-refuses-without-io_uring, fallback.nothing-listened, fallback.message-names-io_uring |
| `config-front-ignored` | ignores `listeners[].front` | cli.config-front-uring.identity.has-io_uring, cli.config-front-uring.identity.cq-moves-with-traffic, cli.config-front-uring.identity.conn-not-in-epoll |
| `unit-admits` | hardened unit without the io_uring deny (= today's file) | unit.denies-io_uring, runtime.unit-denies |
| `dropin-broad` | drop-in also admits `ptrace` | dropin.only-io_uring |
| `dropin-incomplete` | drop-in admits only io_uring_register | dropin.admits-io_uring, runtime.dropin-admits |
| `dropin-relaxes-other` | drop-in also sets `NoNewPrivileges=no` | dropin.only-io_uring |

Measured by `ci/remote.sh oracles/front-equiv/run --self-test` on 2026-11-06. The full log tail is in units/phase-7/reports/P7-oracle-uring-001.md.

## Red before P7-uring-001 (2026-11-06)

`run --binary target/release/monban` (the default build at 00ca246): `FRONT-EQUIV: FAIL`.

- `--front` is an unknown argument (exit 64), and `listeners[].front` is an unknown F8 field (exit 78).
- The hardened unit admits io_uring today: `SystemCallFilter=@system-service` includes `@aio`, which contains
  io_uring_setup, _enter and _register, and the `~` line does not remove them. The runtime probe confirms
  io_uring_setup succeeds under the unit's filter.
- That needs `SystemCallFilter=~io_uring_setup io_uring_enter io_uring_register` in deploy/monban-hardened.service.
  That file is outside this unit's write scope, and no Phase-7 unit owns it. It is an integrator edit, and the gate
  stays red until it lands.

## Observed epoll behaviour worth knowing (monban at 00ca246)

- A bad chunk-size line or a bare LF in a chunk line gets **two** `400` responses on one connection: first one with
  a `date` field, then one without, then the connection closes. The second response comes from the strict
  framing filter's reject after hyper's own 400. It is deterministic: 45 of 45 tries across one-write, split and
  reference-front deliveries. The oracle compares it as-is, so a uring front must reproduce it byte for byte. It
  is also a strict-H1 wart worth fixing in monban-transport (one request, one response). That fix is outside every
  Phase-7 unit's scope.
- Admission (per-IP GCRA 1000/s, burst 2000, crates/monban-bin/src/shared.rs) returns 4xx under the transport-limits
  style 3000-request runs. The load phases are therefore sized ≤ 1200 requests, with a 2.5 s refill pause before
  each, so that no reject depends on timing.

## Provenance

Written for this unit; nothing ported from research. The corpus extends oracles/proxy-e2e (same config shape and
cases); the h2load usage follows oracles/transport-limits.

## Known limits

- The uring identity is behavioural /proc evidence: an io_uring fd, completions proportional to connections, and
  sockets kept out of epoll. It does not prove that every byte moved through the ring. A front that registered its
  sockets with io_uring POLL_ADD and then used read(2) would pass.
- Close behaviour is coarse (open/closed). RST versus FIN depends on timing (unread bytes at close) and is not
  compared.
- The zero-window stall run is compared as "both reaped within 13 s, or neither". The absolute TBI-8 bound is the
  transport-limits gate's job.
- The fallback check simulates `io_uring_disabled` with seccomp EPERM. ENOSYS kernels (io_uring compiled out) are
  not exercised. The implementation should treat any io_uring_setup error the same way.
- `needs` says `kamrui` only because that is ci/oracles.sh's sole "own gate, no aggregate" marker. The gate runs on
  the desktop. A dedicated marker in ci/oracles.sh is an integrator follow-up.
