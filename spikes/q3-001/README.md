# q3-001: TLS 1.3 handshake capacity on one core (N95 1-core stand-in, not a KVM VPS; grade ≤B)

**Question (plan row):** handshake rate on a real $5 1-vCPU KVM (full/resumed × X25519/hybrid; steal, kernel).
**Flips if:** hybrid >1.3× X25519 → R-PERF-1; <500 full handshakes/s → S0.5 retune.
**Verdict: keep** on both triggers (details and limits below). Separate from the triggers: the §6 household
estimate (~3.1–3.7k req/s of 429-after-full-TLS, X25519) is **~3× too high on this hardware**: measured 0.98–1.04k.

There is no real VPS. Every kamrui number below is **"N95 1-core stand-in, not a KVM VPS; grade ≤B"**.

## Method
- `src/main.rs` (`hsbench`): rustls 0.23.46 + aws-lc-rs 1.18.2 (aws-lc-sys 0.46.0). Dependency set = `oracles/hrr-verdicts/Cargo.lock`
  verbatim (only the root package name differs; `libc 0.2.191` was already in that lock). Release build, thin LTO.
- Server: **one thread**, nonblocking sockets + `poll(2)`, many connections in flight, so the core never idles
  waiting for a client flight. TLS 1.3 only; ECDSA-P256 self-signed cert (rcgen); one kx group per run on both sides
  (no HRR: `hrr_total` = 0 in every run); stateless aws-lc `Ticketer`, 2 tickets per connection (rustls default).
  CPU per handshake from `getrusage(RUSAGE_SELF)` (user+sys, measured window only).
- Cases: `full` (handshake, tickets, close_notify, close; client has resumption disabled); `resumed` (client cache,
  PSK-DHE; 100.0% resumed in every kamrui run); `reject` = **reject-after-full-TLS**: full handshake, read one
  HTTP/1.1 request, answer `429` + `Retry-After`, close_notify, close; `reject_notickets` = same with
  `send_tls13_tickets = 0` (what a server that is refusing anyway could do).
- Load generator: same binary, 24 blocking threads, accepts any cert but verifies the handshake signature.
- kamrui: Intel N95 (4 Gracemont E-cores, no SMT, 2 MiB shared L2, 6 MiB L3), kernel 6.17.0-41-generic, governor
  `powersave` (intel_pstate active, cannot be changed without sudo), glibc 2.42 (laptop-built gnu binary, glibc 2.39,
  runs unmodified; `ldd` clean). **Server pinned to core 3** with `taskset`; **load generator on cores 0–2**.
  Flags include `aes avx2 bmi2 adx sha_ni vaes vpclmulqdq pclmulqdq`, no `hypervisor` (bare metal; full flag list in
  the `flags` row of `kamrui-hs.jsonl`).
- Protocol: 12 configs (3 groups × 4 cases) × 5 reps, ABBA order (reversed on odd reps), 2 s warm-up + 8 s
  measured, fresh server process per run. Bands = min–max over the 5 reps, median in brackets.
- Background load on kamrui at start: loadavg 0.44 (Forgejo + Forgejo-DB containers idle, rustdesk, NX, a python
  job agent ~2.6% CPU). Steal: 0 jiffies (all-CPU and server core, every run; bare metal, so expected).
- Contrast: same binary on the laptop (i9-14900HX, server on P-core cpu4, clients cpu8–15) — **heavily contended**
  (loadavg 10 → 40 during the run, other agents' jobs; the bench runs under `ci/heavy.sh` at nice 15).

## Results, kamrui (N95 1-core stand-in, not a KVM VPS; grade ≤B). File: `kamrui-hs.jsonl`

| group | case | handshakes/s on one core | server CPU µs/handshake |
|---|---|---|---|
| X25519 | full | 948–1045 (1022) | 955–1037 (974) |
| X25519 | resumed | 998–1029 (1018) | 972–998 (982) |
| X25519 | reject-after-full-TLS (429) | 980–1040 (1037) | 961–1018 (965) |
| X25519 | reject, no tickets | 1080–1132 (1107) | 883–926 (899) |
| X25519MLKEM768 | full | 910–927 (924) | 1079–1098 (1083) |
| X25519MLKEM768 | resumed | 836–884 (869) | 1131–1196 (1151) |
| X25519MLKEM768 | reject-after-full-TLS (429) | 872–916 (906) | 1091–1147 (1101) |
| X25519MLKEM768 | reject, no tickets | 978–986 (981) | 1014–1022 (1018) |
| SecP256r1MLKEM768 | full | 813–843 (832) | 1185–1230 (1200) |
| SecP256r1MLKEM768 | resumed | 761–820 (795) | 1219–1314 (1257) |
| SecP256r1MLKEM768 | reject-after-full-TLS (429) | 816–845 (829) | 1184–1223 (1206) |
| SecP256r1MLKEM768 | reject, no tickets | 858–903 (881) | 1108–1165 (1133) |

Server core utilisation ≥0.982 in every run (saturated). 0 TLS errors server-side; client "fail" counts are
connection-refused retries after each server process exits (verified: a client that stops before the server shows
0 failures).

Hybrid overhead (server CPU µs/handshake, ratio of medians; band = min/max .. max/min):

| ratio vs X25519 | full | resumed | reject (429) | reject, no tickets |
|---|---|---|---|---|
| X25519MLKEM768 | **1.11** (1.04–1.15) | 1.17 (1.13–1.23) | 1.14 (1.07–1.19) | 1.13 (1.10–1.16) |
| SecP256r1MLKEM768 | 1.23 (1.14–1.29) | 1.28 (1.22–1.35) | 1.25 (1.16–1.27) | 1.26 (1.20–1.32) |

Other ratios: resumed/full 1.01 (X25519), 1.06 (hybrid): with rustls' PSK-DHE resumption plus 2 fresh tickets,
resumption saves the ECDSA signature but pays the key exchange and ticket sealing again, so it is **not cheaper**
on the server. The 429 after the handshake costs ~nothing extra (reject/full 0.99–1.02). Not issuing tickets on a
rejected connection saves 6–8%.

### Contended re-run (noisy neighbour). File: `kamrui-hs-contended.jsonl`
A 2-rep re-run happened while another agent's Lean/CBMC CI jobs started on kamrui (loadavg 1.4 → 10, server clock
1.4 GHz). Server CPU rose ~15%: X25519 full 1112–1130 µs/hs (858–885 hs/s), X25519MLKEM768 full 1285–1315 µs
(732–752 hs/s), SecP256r1MLKEM768 full 1431–1465 µs (671–681 hs/s); reject-after-full-TLS 809–854 / 717–730 /
688–693 per s. Ratios: X25519MLKEM768 1.16 full (band 1.14–1.18), ≤1.22 worst case; SecP256r1MLKEM768 1.29 full
(band 1.27–1.32). Both triggers still keep (≥671 full hs/s; X25519MLKEM768 <1.3×). Not used for the headline
bands, kept as a noisy-neighbour data point.

### Why the absolute numbers are low: clock
`scaling_cur_freq` on the server core during a co-located run: **1.40–1.55 GHz** (all 4 cores busy, package power
limit; turbo is 3.4 GHz). With only the server busy (remote load generator over Tailscale, trial run) it stayed
~1.5 GHz under `powersave`. `openssl speed` on the same idle core (≈2.2 GHz): ECDSA-P256 sign 18.6k/s, X25519 10.5k/s
— about 3× slower than the laptop's 51k/s and 35k/s. Server time is ~92% user, ~7% sys (`user_us_per_hs` /
`sys_us_per_hs`, and `/proc/<pid>/stat`: 184 user vs 17 sys ticks over 2 s).

### Laptop contrast (i9-14900HX, contended; provisional). File: `laptop-hs.jsonl`
X25519 full 113–137 µs/hs (median 125, ≈6.9k hs/s), X25519MLKEM768 full 135–143 µs (139; ≈6.2k hs/s), hybrid
ratio 1.11 (0.99–1.26) — consistent with ARCHITECTURE §6 (123.4–141.7 µs, +12.5–17.5%). The N95 stand-in is
**~7.8× slower per handshake** than the laptop. SecP256r1MLKEM768 laptop rows are **invalid** (load generator
starved: server utilisation 0.01–0.05 while loadavg hit 40); not used.

## Decision against the triggers
- **Hybrid >1.3× X25519?** No. X25519MLKEM768 full 1.11× (band 1.04–1.15), reject 1.14× (≤1.19), resumed 1.17×
  (≤1.23). R-PERF-1 / W2 "hybrid ≤1.3×" **keeps**. Note: SecP256r1MLKEM768 (the FIPS-style group) is 1.23× median
  and its resumed/no-ticket bands touch 1.32–1.35×; if R-PERF-1 is read as applying to every offered hybrid group,
  that group is at the threshold on this hardware.
- **<500 full handshakes/s on one core?** No. 813–1045 full/s across groups, even at a power-limited ~1.5 GHz clock.
  S0.5 **keeps**. Margin is thin: S0.5 gives handshakes ≤50% of each accept window, i.e. ≈410–520 full hs/s of
  handshake budget on this box.
- **§6 household row (not a trigger, a correction):** measured reject-after-full-TLS on the stand-in is
  **~980–1040/s X25519, ~870–920/s X25519MLKEM768** (no tickets: ~1.08–1.13k / ~0.98k), versus the E-graded
  ~3.1–3.7k / ~2.7–3.3k. The "laptop × 0.5" scale factor is wrong for low-end silicon; on the N95 it is ≈0.13.
  A real KVM vCPU (EPYC/Xeon at 2.5–3.5 GHz, possible SMT sibling and steal) is probably between the two; until it
  is measured, the household row should quote the stand-in as the floor.

## Reproduce
```
cd spikes/q3-001
CARGO_TARGET_DIR=$PWD/target ../../ci/heavy.sh cargo build --release --offline   # lock = oracles/hrr-verdicts
ssh kamrui 'mkdir -p ~/aegis-spike-q3/q3-001'; scp target/release/hsbench bench.sh kamrui:monban-spike-q3/q3-001/
ssh kamrui 'cd ~/aegis-spike-q3/q3-001 && ./bench.sh ./hsbench kamrui-hs.jsonl 3 0-2 5 8 24'
scp kamrui:monban-spike-q3/q3-001/kamrui-hs.jsonl . && python3 -I summarize.py kamrui-hs.jsonl
# laptop contrast: ../../ci/heavy.sh ./bench.sh target/release/hsbench laptop-hs.jsonl 4 8-15 2 8 24
# remote load generator variant (orchestrated from the laptop; kamrui ufw only admits tailnet traffic):
#   ./bench-remote.sh kamrui desktop 100.103.183.65 OUT.jsonl 3 REPS
rm -rf target; ssh kamrui 'rm -rf ~/aegis-spike-q3'
```
Binary sha256 (first kamrui run): `d2562ac3…6f3d49`; later builds only add the user/sys split, client timeouts and
the frequency sample, not the measured path.

## Limits (honest)
- Not a KVM guest: no hypervisor, no steal (0 measured), no noisy neighbours, no SMT sibling. Bare-metal N95 under
  `powersave` running at ~1.4–1.55 GHz: likely **slower** than a typical $5 vCPU, so absolute rates are a pessimistic
  floor and the ratios are the transferable part.
- Load generator co-located on the same package (cores 0–2): it lowers the shared clock and shares the 2 MiB L2.
  A remote-load-generator variant was attempted (desktop → Tailscale, because kamrui's ufw blocks LAN ports). One
  clean X25519-full trial (loadavg 1.3, other cores idle except tailscaled ~45%) gave **908 µs/hs** (vs 974 median
  co-located) at ~1.5 GHz, but the load generator could not saturate the core over Tailscale (util 0.58), and the
  full 12-config trial ran while kamrui hosted another agent's Lean/Kani CI jobs (loadavg ≈ 9–10: 1146–1250 µs/hs
  X25519, hybrid ratio 1.17–1.25). Those runs are contaminated and not used for the verdict.
- Loopback TCP, so per-packet NIC/IRQ cost and real RTTs are absent; one single-threaded server design (a tokio
  server adds its own overhead). ECDSA-P256 only (ML-DSA certs not measured). Server cert chain length 1.
- Resumed numbers include issuing 2 new tickets per connection (rustls default); `reject_notickets` shows the
  ticket cost. 5 reps × 8 s per config; bands, not best trials.
- The laptop contrast ran under heavy contention and nice 15; its SecP256r1MLKEM768 rows are invalid.
