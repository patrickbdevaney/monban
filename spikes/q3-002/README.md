# q3-002: out-of-process adapter hop (UDS/pipe + postcard), same vs cross core (N95 1-core stand-in, not a KVM VPS; grade ≤B)

**Question (plan row):** ipcbench same/cross core on a VPS.
**Flips if:** hop >12 µs → R-MOD-1 budget <≈8k calls/s/core.
**Verdict: flip (provisional, stand-in hardware).** The R-MOD-1 transport (postcard over a UDS socketpair) costs
**14.2 µs same core / 15.3 µs cross core** (p50, 64 B) on the stand-in. Both are above 12 µs in every rep, so the
budget `rate × hop ≤ 10% of a core` gives **≈6.5–7.0k calls/s/core**, not 12.4k.

Every kamrui number below is **"N95 1-core stand-in, not a KVM VPS; grade ≤B"**.

## Method
- Source read: `research/state/raw/round-003/02-bench/src/main.rs` (untrusted). It ran UDS/TCP/shm transports with
  postcard/bincode/raw frames and pinned nothing itself (relied on external `taskset`, so client and server always
  shared the cpuset). `src/main.rs` here is a **re-write** of only the UDS + postcard path, plus a pipe-pair
  variant, with explicit placement: client and server each call `sched_setaffinity` themselves, so *same* = both on
  core 3, *cross* = client core 3, server core 2. bincode is dropped (banned, RUSTSEC-2025-0141).
- Frame: 4-byte LE length + postcard `Req{op, seq, body: serde_bytes}`; server (a re-exec of the binary over an
  inherited socketpair or two pipes) decodes, echoes the body, encodes `Resp{seq, status, body}`. Blocking reads,
  one call in flight (a synchronous adapter call). Sizes: 64 B and 64 KiB bodies (round-3 `echo64` / `echo65536`).
- Per run: warm-up max(n/10, 300) calls, then n timed calls (n = 20000 for 64 B, 3000 for 64 KiB); p50/p90/p99/max
  of per-call wall time (`Instant`), calls/s = n / total time, CPU µs per call from `getrusage` (client = self over
  the timed loop; server = child over its lifetime incl. warm-up and exec, divided by all calls).
- Placement × transport × size = 8 configs × 5 reps, ABBA order. Deps: postcard 1.1.3, serde 1.0.229,
  serde_bytes 0.11.19, libc 0.2.191; all 15 locked crates ≥9 days old on 2026-10-25 (`lock-age.txt`).
- kamrui: Intel N95, 4 Gracemont cores in one module (shared 2 MiB L2, 6 MiB L3), no SMT, bare metal, kernel
  6.17.0-41-generic, governor `powersave`. Clock during the runs: **~2.1 GHz same core, 0.9–1.55 GHz cross core**
  (`scaling_cur_freq`; the cores share one frequency domain and the light ping-pong never drives turbo). loadavg
  0.54 at start (Forgejo idle). Steal 0.
- Contrast: same binary on the laptop (i9-14900HX, P-cores cpu4 / cpu6, 3 reps), contended (loadavg ~40).

## Results, kamrui (N95 1-core stand-in, not a KVM VPS; grade ≤B). File: `kamrui-ipc.jsonl`
Bands = min–max over 5 reps (median).

| transport | placement | body | p50 µs | p99 µs | calls/s, 1 in flight | client+server CPU µs/call | 0.1 / p50 (calls/s/core) |
|---|---|---|---|---|---|---|---|
| **UDS + postcard** | **same core** | 64 B | **14.1–14.5 (14.2)** | 16.7–20.8 (17.0) | 67.4k–71.6k (70.7k) | 14.0–14.8 (14.2) | **7.0k** |
| UDS + postcard | same core | 64 KiB | 55.9–57.1 (56.2) | 65.4–91.3 (90.2) | 15.6k–17.5k (16.3k) | 57.8–64.1 (61.5) | 1.8k |
| **UDS + postcard** | **cross core** | 64 B | **15.0–16.6 (15.3)** | 21.7–23.9 (23.1) | 58.3k–67.3k (64.6k) | 20.1–22.3 (20.8) | **6.5k** |
| UDS + postcard | cross core | 64 KiB | 58.8–60.6 (59.6) | 63.4–89.7 (86.6) | 14.9k–16.9k (15.3k) | 78.8–88.6 (87.2) | 1.7k |
| pipe pair + postcard | same core | 64 B | 7.5–7.7 (7.6) | 8.4–10.8 (8.7) | 118.6k–131.3k (129.9k) | 7.6–8.4 (7.8) | 13.1k |
| pipe pair + postcard | same core | 64 KiB | 60.6–66.5 (63.7) | 66.0–94.1 (68.1) | 14.5k–16.3k (15.6k) | 61.6–69.2 (64.2) | 1.6k |
| pipe pair + postcard | cross core | 64 B | 11.0–11.3 (11.2) | 13.6–16.4 (14.7) | 83.2k–90.6k (85.0k) | 10.6–11.2 (11.1) | 8.9k |
| pipe pair + postcard | cross core | 64 KiB | 69.9–75.1 (71.5) | 75.1–110.1 (85.7) | 12.3k–14.2k (13.4k) | 67.2–75.7 (70.9) | 1.4k |

- Cross core costs little more than same core on the N95 (shared L2 module), unlike the laptop's 4.8 → 8.07 µs.
- Cross-core CPU per call (20.8 µs total, ≈10.4 µs on the caller's core) exceeds the wall time: both sides pay the
  wake-up path. A budget counted in *caller-core CPU* would be ≈9.6k calls/s/core; the plan's rule uses hop wall time.
- Pipes are ~2× cheaper than UDS for small frames on this kernel/CPU (7.6 vs 14.2 µs same core); at 64 KiB the copy
  dominates and UDS is slightly better.
- Sensitivity (`kamrui-ipc-spinner.jsonl`): a busy-loop on core 0 to try to lift the shared clock made it worse
  (UDS 64 B p50 17.3–17.9 µs, clock 1.6 GHz): package power is shared, so co-located load slows the hop.

### Contended re-run (noisy neighbour). File: `kamrui-ipc-contended.jsonl`
2 reps while another agent's CBMC job ran at 99% on core 2 (the cross-core server core) and loadavg was ~6, clock
1.5 GHz: UDS + postcard 64 B p50 19.0–19.4 µs same core, 17.8–18.6 µs cross core (p99 27–30 µs); 64 KiB ~85 µs
(cross p99 up to 956 µs); pipes 10.3 / 13.7 µs. A neighbour pushes the hop further above 12 µs (budget ≈5.2–5.5k).

### Laptop contrast (i9-14900HX, contended; provisional). File: `laptop-ipc.jsonl`
UDS + postcard 64 B: same core 4.8–5.0 µs (median 4.9; reproduces round-3's 4.8 µs), cross core 4.5–5.2 µs (4.9;
round-3 had 8.07 µs). 64 KiB: 18.3 µs same, 27.2 µs cross. Pipes 64 B: 3.3 same / 4.7 cross. The N95 hop is
**~2.9× the laptop's**.

## Decision against the trigger
Hop >12 µs? **Yes** for the R-MOD-1 transport (UDS + postcard): 14.2 µs same core, 15.3 µs cross core; no rep was
below 14.1 µs. Flip: the R-MOD-1 out-of-process adapter budget on household-class hardware becomes
**≈6.5k calls/s/core** (0.1 / 15.3 µs; 7.0k if adapter and caller share the core), below the ≈8k threshold and about
half the laptop-derived 12.4k. A pipe-pair transport would recover ≈8.9–13.1k (cross/same core) at this frame size.

## Reproduce
```
cd spikes/q3-002
CARGO_TARGET_DIR=$PWD/target ../../ci/heavy.sh cargo build --release --offline
ssh kamrui 'mkdir -p ~/aegis-spike-q3/q3-002'; scp target/release/ipchop bench.sh kamrui:aegis-spike-q3/q3-002/
ssh kamrui 'cd ~/aegis-spike-q3/q3-002 && ./bench.sh ./ipchop kamrui-ipc.jsonl 3 2 5'
scp kamrui:aegis-spike-q3/q3-002/kamrui-ipc.jsonl . && python3 -I summarize.py kamrui-ipc.jsonl
# laptop contrast: ../../ci/heavy.sh ./bench.sh target/release/ipchop laptop-ipc.jsonl 4 6 3
rm -rf target; ssh kamrui 'rm -rf ~/aegis-spike-q3'
```

## Limits (honest)
- Not a KVM guest: no virtualised IPIs/timers (which usually make cross-core wake-ups *more* expensive), no steal,
  no SMT sibling. The N95 runs at 0.9–2.1 GHz under `powersave` here, likely slower than a typical $5 vCPU, so the
  absolute hop may be lower on a real VPS. Because the flip rests on this stand-in, a real KVM run could revert it.
  Treat the 6.5k figure as the household floor until then.
- Echo handler only (no adapter work); one call in flight (no batching or pipelining, which would amortise the hop).
- Server CPU per call includes process exec and warm-up (amortised over ≥3,300 calls; small but non-zero for
  64 KiB runs).
- shm/futex, TCP and fd-passed bodies (`bodies as fds` in R-MOD-1) were not re-measured.
- Laptop contrast contended (loadavg ~40) and run at nice 15 under `ci/heavy.sh`.
