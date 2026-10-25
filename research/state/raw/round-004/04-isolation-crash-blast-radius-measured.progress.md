# 04-isolation-crash-blast-radius-measured — progress (round 4, explorer 04)
Started 2026-10-25 03:30 EDT. No prior progress file existed (fresh start after operator system crash).
Plan: (1) build fault-injection harness for substrates a/b/c (reuse r2 07-bench target dir under heavy.sh); (2) run interleaved >=5 trials pinned to 1 core; (3) web needle research (PHP-FPM source, wasmtime trap/pooling docs, issues); (4) recompute M0 escape rate w/ denominators; (5) L5 tables + CI gate spec.
Work dir: state/raw/round-004/04-work/

## 03:55 harness built + matrix launched
- Harness: 04-work/fi (finat = native/fork/cordon substrates in Rust+libc; fiwasm = Wasmtime 48.0.7 pooled M0; guest.wasm; fidriver = closed-loop client+supervisor). Built with rustc 1.98 reusing r2 target dir (partial wasmtime recompile was unavoidable: toolchain/lock drift; +400MB in shared target).
- Smoke findings (n=1000, 5%):
  * Ubuntu core_pattern pipes to apport; RLIMIT_CORE=0 is NOT honoured for pipe patterns -> each crashing worker hangs ~100 ms in the kernel waiting for apport -> cordon p99 100 ms and 1/4 capacity loss per crash. PR_SET_DUMPABLE=0 fixes (p99 104 ms -> 2.4 ms). L5: server must set dumpable=0 or RLIMIT_CORE=1 (pipe special-case) for crash-contained substrates.
  * native in-proc: panic contained by catch_unwind (blast 0); segv/abort blast ~5.4-6.1 healthy failures per fault with supervisor-held socket (socket activation), ~13-15 without; recovery p50 1.3 ms.
  * poison: native & cordon (no recycle) leak to ~all later requests (wrong answers); fork, fresh-instance wasm: 0; wasmreuse: leaks.
  * fdleak: native -> EMFILE storm (801/955 healthy fail); cordon no-recycle 630; cordon-recycle(max_requests=50) 35; fork 0.
- Main run: 5 interleaved trials x ~148 cells, n=3000, conc=16, server taskset core 2. Machine is externally loaded (loadavg 9-70, other loops on all cores) -> latency numbers are noisy; counts robust.

## 04:10 sources batch 1 (primary)
- php-src sapi/fpm/fpm/fpm_children.c (master): emergency_restart counts only WTERMSIG SIGSEGV|SIGBUS in a ring of N timestamps; all N within interval -> whole-pool reload. Baseline semantics for crash-loop damping.
- wasmtime src/commands/serve.rs: max_instance_reuse_count default 1 (WASIp2) / 128 (WASIp3); concurrent reuse 1 / 16 (P3). PR #11807 (merged 2025-10-20) states 'a trap can affect unrelated requests, and a security flaw could leak state across requests'.
- wasmtime #14313 (closed 2026-09): Instance::reset proposal; alexcrichton: new reset paths are 'a big hazard ... Anything that's gotten wrong is a CVE'. Reuse+reset 2.5-5.5x calls/s vs reinstantiate at 256KiB guests (crossover ~0.5MiB).
- docs.rs wasmtime 50.0.0 PoolingAllocationConfig: madvise reset to zero by default; keep_resident -> memset; pagemap_scan default no (kernel>=6.7).
- Advisory snapshot re-pulled 2026-10-25: 81 GHSAs, 0 new vs r2 classified.json. Recomputed (04-work/adv/recompute.py): M0 escape 12/5.43y=2.21/y [1.14,3.86]; 2024-26 1/2.81y=0.36/y [0,1.98]; M1 guest-triggerable host-abort DoS 11 in 2024-26 = 3.91/y [1.95,6.99] (2026: 8.6/y).
- google/security-research kernelCTF metadata (138 entries, 111 unique CVEs 2023-26): 80 (72%) need userns; 31 not: TLS(kTLS ULP) 11, BPF 7, io_uring 3, perf 3, AF_ALG 3, AF_UNIX 4, vsock 1, net_sched 1. A worker allowlist without socket/socketpair/setsockopt/sendmsg/bpf/perf/io_uring and with clone-flag filtering blocks all 111 by syscall reachability (my mapping).

## 04:25 sources batch 2
- man7 core(5): RLIMIT_CORE not enforced for piped core dumps; core_pipe_limit>0 => kernel waits for helper (this box: apport, core_pipe_limit=10) -> explains ~100 ms crash hang. 
- Baumann et al. HotOS'19 'A fork() in the road': fork-without-exec makes ASLR ineffective (same layout) citing Bittau et al. 'Hacking Blind' S&P 2014; posix_spawn ~0.5 ms flat; Chrome fork delays up to 100 ms.
- BROP (scs.stanford.edu/brop): needs crash-restart with same layout; nginx 1.4.0 + MySQL; ~4,000 requests, minutes. => zygote/cordon respawn without re-exec is a crash oracle; blast-radius-0 substrates convert crashes into free probes.
- php-src fpm_process_ctl.c: reload = execvp (fresh ASLR); php-fpm.conf.in: emergency_restart_threshold default 0 (off); www.conf.in pm.max_requests commented 500 (default 0), request_terminate_timeout 0.
- V8 v8-isolate.h: heap limit not raised by NearHeapLimitCallback => V8::FatalProcessOutOfMemory (whole process). Node worker returns +16MB and exits worker. workerd handling not verified.
- 0pointer socket activation: listening socket survives service death. Erlang supervisor intensity/period defaults 1/5 s, escalate on exceed. uWSGI harakiri/max-requests/reload-on-rss/min-worker-lifetime (60 s default).
- Ghavamnia et al. USENIX Sec'20 temporal syscall specialization (init vs serving phase filters; nginx etc.).

## 04:10-04:20 sources batch 3 + PHP control prepared
- GHSA-q8hx-mm92-4wvg (2024-10-09): tail calls + stack traces -> deterministic process abort (guest-triggerable, M0 default features) => in-process Wasm host can take native-abort blast radius. GHSA-75hq (2024-04-02) host panic from guest. GHSA-6wgr (2026-04-09) pooling cross-instance linear-memory leak (config-dependent).
- Morula (Lee et al. 2014, gatech PDF): zygote fork weakens ASLR; Morula pre-exec pool +13 MB/app, individually randomized.
- Cloudflare Workers security model blog: cordons by trust, layer-2 namespaces+seccomp applied before isolates load, patch gap < 24 h, misbehaving workers rescheduled to own process.
- Edera userns blog: 42 userns-gated CVEs 2020-25, nf_tables 43%.
- nginx ngx_process.c: master respawns worker on signal exit (no rerandomization w/o exec) -> BROP precondition.
- Apache mpm_common: MaxConnectionsPerChild default 0, leak limiter. Fastly sandbox lifecycle: fresh sandbox per request default; reuse opt-in (with_max_requests) with explicit 'globals may persist' warning.
- PHP control: php:8.4-fpm-alpine (89.7 MB), FastCGI driver 04-work/php/fcgi_driver.py. Smoke: segv/oom/fdleak/poison/panic blast 0; segv p99 104 ms with apport pipe, 4.7 ms with --ulimit core=1:1 (RLIMIT_CORE=1 pipe special case verified empirically).

## 04:15 run notes
- Trial 1 done 03:54-03:58 (loadavg 7-8). Trial 2 running under heavy external load (other loops ~20 cores busy, loadavg 30+): p99 inflated to 100-500 ms, a few healthy timeouts (err=4). Analysis will split crash-attributable failures (connect/EOF/wrong) from timeouts.
- BUG found+fixed in harness: with socket activation the pkill-by-socket-path cleanup missed SIGKILLed cordon supervisors' workers -> 272 idle orphans accumulated (0% CPU, none spinning). Killed; run_matrix.py now pkills orphans after each cell (trials 3-5).
- Expected-loss model (04-work/analysis/expected_loss.py, MODELLED): persistent n-day attacker, P(>=1 cross-request breach window/yr): Wasm alone 30-89% (M0 0.36-2.21/yr); fork-native+allowlist 16-59% (kernel 0.17-0.88/yr); Wasm inside OS sandbox 0.25-10.6% (lags 1-7 d wasm, 14 d kernel). Exposure fraction F: 0.1-4.2% / 0.65-3.4% / 0.0006-0.14%.

## 04:35 MAIN MATRIX DONE (740 cells = 5 trials x 148, 0 driver errors). Aggregates: 04-work/analysis/agg_main.json, blast_table.md
Headline (pooled healthy failures per injected fault, 1% rate): panic: all ~0 (catch_unwind works). abort/segv: native 9.3-9.7 (socket-activated) vs 24.2-24.4 (no SA); wasm/fork/cordon ~0. loop: native 3.3 + throughput x0.009; wasm 0 but p99 x35 and rps x0.15 (4-thread pool HOL, 100 ms epoch); fork 0, p99 x3.4, rps x0.48. oom: native 2.8; others ~0 (cordon 0.1). fdleak: native 68 (gray failure, no restart, rps x0.07), cordon 47, cordon-recycle(50) 0.02, fork 0. poison: native 97, cordon 87, wasmreuse 93, cordon-recycle 19, wasm-fresh 0, fork 0.
Recovery (exec+init of restarted server) p50 1.3-1.9 ms. Small cordon EOF failures (<=0.22/fault) concentrated in trial 2 at loadavg 100-350: likely wall-clock watchdog false positives on CPU-starved healthy requests.
