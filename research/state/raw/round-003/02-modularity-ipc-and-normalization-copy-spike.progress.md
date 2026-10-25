# progress (explorer 02 r3) 2026-10-25
- bench crate at 02-bench (built via heavy.sh using r2 target dir offline; ipcbench). Runs: 02-ipc-1core.jsonl (core13, n=10), 02-ipc-2core-control.jsonl, 02-rss-1core.jsonl, 02-norm-1core.jsonl. smoke (core27, loadavg 28): inproc echo64 25ns, uds-postcard 10.7us p50, shm-futex 4.07us, shm-spin5k 207-241us (NEGATIVE: pause ~140cyc x5000 on 1 core).
- SRC OPA envoy perf page: no result tables (docs only) -> no ext_authz number there. 
- SRC arXiv 2207.00592 (MeshInsight, UW/Duke/Bytedance, Jul 2022): sidecar latency +30-185%, CPU +41-92% on benchmark apps; gRPC proxying ~5x latency vs TCP per search snippet (unverified in text).
- SRC arXiv 2501.06234 LionsOS: seL4 ctx switch 400-600 cycles; Mi et al 2019 intra-core fastpath round-trip IPC 986 (seL4) 2717 (Fiasco) 8157 (Zircon) cycles. 
- SRC HAProxy SPOE.txt: no numbers; motivation blocking libs (LDAP); stat 'latency added by SPOE processing'.
- Envoy ext_proc: no published per-req figure; envoy-extproc-sdk anecdote ~4-5ms/filter (python docker-compose) -> grade D.
- Chromium Mojo: ipc_cpu_perftest reports CPU% not latency (144B msg 20Hz: IPC 5.7% vs Mojo 3.7% CPU) old; mojo_rtt_benchmark config only.
- SRC RUSTSEC-2025-0141 (issued 2026-01-07): bincode ceased development permanently, 1.3.3 'complete'; alternatives wincode/postcard/bitcode/rkyv. => dropping bincode from candidate wire formats; use postcard (still measured for control).
- SRC shmem-ipc (diwic) README: sharedring 3x faster than unix sockets at 64K, memfd sealing + eventfd signaling; vendor claim (D); no releases listed. Independent M4 rebench (not Linux): tuned UDS within 1-11% of shm (D).
- SRC iceoryx2 repo: Apache-2.0/MIT, Linux x86_64 tier2, bench i7-13700H Linux 6.10.10 charts only; maintainers ~100ns polling mode 8B payload (offsets) - vendor (D).
- SRC rust_serialization_benchmark (updated 2026-10-05, EPYC 7763 4 vCPU, rustc nightly 2026-10-04) log dataset: postcard 1.1.3 ser 415.58us deser 2.34ms borrow 628.78us size 724953; rkyv 0.8.18 ser 251.61us deser 1.56-1.92ms size 1011488. bincode absent.
- SRC MeshInsight arXiv 2207.00592 (Jul 2022) Table: built-in C++ filters Fault Injection +5.74us (3.1%), Rate limit ~8.2us; WebAssembly no-op +26.30us (14.3%) HTTP-mode Envoy, 100B msgs 30K rps; gRPC proxy overhead 5x latency 4x CPU vs TCP; HTTP 4x/3x. (verified in pdftotext)
- SRC Mojo README: Remote/Receiver endpoint ~6KB heap each (12KB/pair); Mojo call ~1/3 faster and 1/3 fewer ctx switches than legacy Chrome IPC; same-process should use direct calls.
- SRC Chrome Site Isolation 2018: ~10-13% total memory overhead from more processes (secondary press, C).
- SRC NGINX Unit repo archived 2025-10-08, last release 1.34.2 Feb 2025 (secondary search; C). 
- SRC Pingora ProxyHttp (pingora-proxy 0.9.0 docs.rs): request_body_filter(&mut Option<Bytes>) per-chunk, not whole body. bytes 1.12.1: clone/slice O(1) refcount; copy_from_slice copies. http-body 1.1.0 Body: Data: Buf, poll_frame.
- SRC Envoy ext_proc docs 1.37: only stats fields (request_header_latency_us etc), no benchmark numbers => no published per-call number.
- SRC Mozilla bug 864180: audio codecs moved back into app process to cut IPC overhead (reversal precedent, D). Copilot runtime rewrite: Node child process ~100MB baseline + IPC replaced by in-process cdylib (D-C).
- SRC Fuchsia round_trips.cc microbenchmark exists (code only, no published numbers found).
## MEASUREMENTS DONE (core 13 of i9-14900HX, SMT sibling 12 unpinned/other load, loadavg 10-23, powersave governor, kernel 6.17.0-14)
files: 02-ipc-1core.jsonl (10 runs), 02-ipc-2core-control.jsonl (5), 02-ipc-1core-tcp.jsonl, 02-ipc-1core-serdebytes.jsonl, 02-rss-1core.jsonl, 02-norm-1core.jsonl; code 02-bench/src
key (median of run p50, 1 core): timer 21ns; inproc dyn noop 23ns echo64 24 4K 68 64K 1642 redis 49 presign 1338.
UDS postcard 4.80us noop/4.87 echo64/9.80 4K/96.3 64K(serde &[u8] per-byte artifact)/redis 5.03/presign 6.93; p99 5.7..7.8us (64K 101us). bincode same +-2%. rawframe 4.76/4.73/5.80/19.6/4.80/6.54.
serde_bytes fix: postcard 64K min 19.7us ~ raw; 4K min 5.8.
shm-futex 2.05/2.06/2.22/7.42/2.12/3.46us, 465k calls/s. shm-spin5k on 1 core: 638us (NEGATIVE); on 2 cores: noop 195ns echo64 160ns 4K 1.49us 64K 17.1us redis 283ns presign 1.66us (futex 2core 4.8us: worse than 1core!).
UDS 2-core: 8.0us (worse than 1 core 4.8us: cross-core wakeups). TCP loopback 1 core: 8.1us noop, 37.5us 64K.
RSS: exec helper RSS 2.5MB, PSS 0.58-0.78MB, PrivDirty 0.56MB (binary 771KB); fork 1MB zygote PSS 0.55MB@32; 8MB zygote RSS 9.9MB PSS 0.77@32 priv 0.5MB; 64MB RSS 67MB PSS 2.5MB@32. spawn->first reply: exec 544us p50 (841 p99), fork 1MB 250us, 8MB 297us, 64MB 615us.
NORM 10MB: memcpy control 548us; zero-copy A: userspace 349us (incl copy#0), alloc 68KB, 0 explicit copies; sock path wall 2079us user 30us sys 2057us alloc 266KB; B1 2 copies: mem 690us, sock 2657us (user 888) alloc 21.2MB; B2 3 copies: mem 738, sock 2794 (user 916) alloc 31.7MB. => each avoided userspace copy is worth ~0.29-0.3ms/10MB (~29ms/GB) in sock path; +28%/+34% wall.
