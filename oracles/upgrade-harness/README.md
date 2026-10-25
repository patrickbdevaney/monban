# upgrade-harness: oracle for zero-downtime upgrade (UP-1..7)

Gates `spec/SPEC_INVARIANTS.md` §G **UP-1** (a listener is always open in a live process; no non-empty accept queue
is closed unpolled), **UP-2** (never a second-process SO_REUSEPORT bind), **UP-4** (old process exits by the drain
deadline D) and **UP-7** (a reload never degrades service), black-box, under load. ARCHITECTURE §3.11 gate shape:
"200 upgrades at 5/s under 2k new conn/s with 0 RSTs"; the unit acceptance runs 100.

## Usage

```
oracles/upgrade-harness/run --subject target/release/upgrade-subject --reloads 100 [--listeners 4]
    options: --interval 0.2 (s between reloads, 5/s)  --rate 2000 (new conn/s)  --drain-ms 2000
             --listeners N (1..64, default 1): the subject serves N ports; the load is spread round-robin
oracles/upgrade-harness/run --self-test
```

`run` re-executes itself under `ci/heavy.sh` (heavy-job lock, memory cap, nice) unless already inside it, then runs
`python3 -I harness.py` (stdlib only). The last line is `UPGRADE-HARNESS: PASS|FAIL (...)`; exit 0 only on PASS.
Subject stderr goes to `.work/subject.log` (git-ignored); the per-run temp dir is removed on exit.

## Subject protocol

```
<subject> --listen 127.0.0.1:<port> [--listen 127.0.0.1:<port2> ...] --pidfile <file> --drain-ms <D>
```
`--listen` is repeated once per listener (`--listeners N`). SIGHUP = upgrade. Whichever process owns the listeners
after a *completed* upgrade rewrites `<file>` (atomically)
with its pid. SIGTERM = drain and exit. Every request `GET / HTTP/1.1 ... Connection: close` gets a `200` with a
`Content-Length` body. The harness launches the subject with `close_fds=True` in its own session.

## What is checked

A single-threaded epoll client opens `--rate` new connections per second (round-robin over the N ports), sends one request on each and reads the
response. Meanwhile, every `--interval` seconds, it sends SIGHUP to the pid in the pidfile and waits (≤10 s) for the
pidfile to name a new pid. Counted:

| counter | meaning |
|---|---|
| `refused` | connect failed with ECONNREFUSED (no listener for an instant) |
| `rst` | ECONNRESET / EPIPE on connect, send or recv (a queued or accepted connection was reset) |
| `dropped_before_D` | EOF before a complete response, or no response within D + 3 s |
| `client_err` | any other client-side error (port exhaustion, EMFILE ...): counted against PASS, never hidden |
| `reloads_done` | reloads whose pidfile changed; must equal `--reloads` (a subject that ignores SIGHUP cannot pass) |
| `old_alive` | handed-over pids still alive (not zombie) D + 1 s after the load ends (UP-4) |

| `ok_per_listener` | completed responses per port; every port must be > 0 (a subject that hands over only some listeners cannot pass) |

**PASS** iff `refused = rst = dropped_before_D = client_err = old_alive = 0`, `reloads_done = N`, `ok > 0`, and
every listener served traffic. With `--self-test --listeners N` the naive controls also serve N ports.

## Self-test (negative controls)

Built-in naive subjects (in `harness.py`, same CLI) that must be caught:

1. `reuseport`: the new process binds the same port with SO_REUSEPORT; once it listens, the old process closes its
   listener. Connections the kernel had already queued on the old socket are reset (ARCHITECTURE §3.11; HAProxy
   measured 2–3 per million per reload). Same rate and reload count as the real gate. If it shows no
   drop/RST/refusal at the default, the self-test escalates to 2× rate, then 2× rate with 4× reloads, and **prints
   what was needed**; if still green the self-test FAILs (a control that cannot be made red is reported).
2. `close-rebind`: the old process closes its listener before the new one binds: refusals in the gap.
3. `deaf`: ignores SIGHUP: must FAIL on `reloads_done < N` instead of passing vacuously.

## Results re-run in-repo (laptop, Linux 6.17, provisional)

* Real subject, 100 reloads at 5/s under 2k conn/s: see the unit report; development runs gave 0/0/0 with reload
  latency p50 ≈ 4.7 ms. One early run showed `rst=1`: a genuine subject bug (a connection accepted but not yet
  registered with the drain tracker when the drain found the tracker empty, reset at process exit); fixed by
  registering in the accept loop before handing off. The harness caught it.
* `reuseport` control at the default rate: 9–14 RSTs over 100 reloads (≈ 0.1 per reload; far above HAProxy's rate
  because the Python naive server accepts slower, leaving the old queue non-empty more often). `close-rebind`:
  1000–1300 refused plus 6–12 RSTs over 20 reloads. `deaf`: 0/2 reloads. No escalation was needed.

## Provenance and limits

* Research: ARCHITECTURE §3.11 (R-OPS-7) and its HAProxy citation; no research script was ported or executed; the
  naive controls are written from the description.
* P2-upgrade-002 (SCM_RIGHTS transport): 100 reloads with `--listeners 4` at 2k conn/s: 0/0/0, 42 000 ok spread
  10 500 per listener, reload p50 ≈ 8.7 ms. A pre-existing subject race surfaced at 1 listener (EOF drops: the
  drain's phase 1 closed a just-accepted connection whose first request had not arrived yet as "idle keep-alive");
  fixed in the subject (only connections that already got a response count as idle). The harness caught it.
* Loopback only, plain HTTP/1.1. UP-3 (H2 GOAWAY last_stream_id), UP-5 (STEK) and UP-6 (CLOEXEC) are
  not observable black-box here; they are covered by `aegis-ops` unit tests.
* The client counts at connection granularity; a subject that answered with a wrong-but-200 body would pass.
* Laptop timings are provisional; `client_err` would flag ephemeral-port exhaustion at much higher rates.
