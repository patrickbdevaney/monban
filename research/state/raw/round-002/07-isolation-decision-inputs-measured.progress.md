# Progress 07 (explorer 07, round 2) — started 2026-10-24 ~23:36 EDT
## Part A DONE (own classification): snapshot gh api 2026-10-25T03:37Z: 81 published GHSA (dedupe: 81 unique ids), 57 in 2026, 7 critical/6 high/45 med/23 low. Files: 07-data/adv.json, classify.py, classified.json
- 2024-2026 n=65. M0 (x86_64 Cranelift core wasm only, no component/WASI): guest-triggerable hits 6/65 (9%); exploitable sandbox escape = 1 (GHSA-897f-g5gm-fmxm, Cranelift SSA bit-packing, any arch, fixed in v43 / 36.0.19; <43 only); 2 x64 codegen over-reads (f64.copysign AVX, f64x2.splat no-SSE3) harmless unless signals-based-traps off/no guard; 1 pooling leak needs guard_size=0 & reservation<4GiB; 2 DoS (externref segment panic 19.0.0, tail-call+stack trace abort).
- M1 (M0 + sync P2 components + WASI non-fs + wasi-http): hits 25/65 (38%) = M0 6 + component 9 + wasi-http 6 + wasi misc ~4; ESC-class: + 2 string-transcoding OOB (GHSA-394w, GHSA-hx6p; default 4GiB reservation => abort/DoS only, corruption needs reduced reservation+no guards).
- M2 (+wasi-fs): 31/65 (48%), adds 2026 fs escapes (GHSA-vqjp, GHSA-m9f7 high; cap-std trailing slash), policy bypass.
- Removing cm-async/WASIp3 removes 14/65, gc+exceptions 6, winch 4, aarch64-only 2, memory64 1, wasi-fs 7 (+embedder-only 5).
- SKEPTIC finding: previous 'hardened pooling w/ small max_memory_size' recipe can re-enable GHSA-6wgr (pooling leak needs guard=0 & reservation==max_memory_size<4GiB) and widen GHSA-394w impact (reduced reservation + no guards => host corruption). Hardened != small reservation; keep default guard/reservation, accept VA cost.

## RESUME after crash (2026-10-25). B1 DONE: 07-bench/run5.txt (wasmtime =48.0.7, rustc 1.98, i9-14900HX pinned core, epoch on, Cranelift)
- native serde_json parse+reserialize: 105B 380ns; 756B 3.3us; 12.2KB 41.7us; 198KB 860us
- core wasm (host copy in/out): 105B 1.06us; 756B 6.1us; 12.2KB 84us; 198KB 1.31ms (wasm ~2.0x native; ~6.6ns/B vs 4.3)
- component noop 97ns (core noop 11ns); add 95ns => canonical-ABI call floor ~85ns over core
- component handle-bytes: 105B 1.24us; 756B 6.78us; 12.2KB 90.8us; 198KB 1.39ms. bytes vs str ~equal (utf8 validate cheap). Marginal comp-vs-core ≈ +0.2us fixed + ~0.03ns/B => ABI copy is ~2-7% of core cost; dominant cost is wasm-vs-native serde (2x) not ABI.
- fresh Store+instantiate pooling WASI-P2 linked: setup p50 4.2us p99 8.6; first call 11.7us; total 20.3us p50 / p99 30us (max 0.4ms). RSS 52KB/live instance after 1 req.
- caveat: pooling config total_core_instances=64 failed with 60 component instances => each component uses >1 core instance (WASI adapter modules); size pool accordingly. And ulimit -v breaks pooling (reserves 0x4082000000=~258GB VA for 64 inst).

## B2/B3 DONE (07-bench/sb/sb.c, sb{8,64,256}.txt; kernel 6.17.0-14, i9-14900HX, taskset 2 cores, Landlock enabled (LSM list), gcc13)
- getppid baseline 84-116 ns (varies w/ freq state between runs; compare within a run). Cacheable allowlist (no arg load) n=16..200 rules: +18..+30 ns (~+20-25%) regardless of list length => kernel (>=5.11) seccomp action bitmap cache works; worst-case (non-cacheable, arg loaded) n=60 +41ns, n=200 +108ns, n=500 +290..450ns (~0.5-0.8 ns per BPF insn linear). => rule: keep filter arg-free for hot syscalls; arg-checks on hot paths cost ~1ns/insn.
- fork() from zygote latency (parent call -> child first instr): heap 8MB p50 124us; 64MB 677us; 256MB 1466us (~fixed 60-80us + ~5.7-10us/MB mapped). vfork baseline 16-18us. full fork+exit+wait 8MB 400us, 64MB 1.7ms, 256MB 3.7ms.
- seccomp install 60-syscall allowlist in child: p50 ~123-131us (p99 ~150-340). Landlock create+1rule+restrict_self: p50 11-13us (p99 17-27us). => seccomp BPF compile/install dominates, Landlock negligible. Cheap trick: install filter once in zygote BEFORE fork (inherited; costs 0 per request) and Landlock too (12us) -> but then zygote itself is confined.
- CoW: child writing 4MB of inherited heap adds ~2.0ms (8MB zygote) = ~0.5ms/MB touched (first-touch CoW fault ~0.5us/4KB => ~2us incl copy? measured 2.0ms/1024pages ≈ 2us/page). 256KB write adds ~180us. PSS of idle forked child = heap/ (1+nchildren)... measured 187KB/child @8MB zygote, 1.3MB @64MB, 5.2MB @256MB because zygote pages shared among 51 procs (PSS=heap/51+~60KB) but Private_Dirty after touching 16MB=16.4MB.
- Contrast: in-process wasmtime pooling fresh instance 20us p50 / 30us p99 and 52KB RSS => ~6x cheaper than smallest fork (124us) and ~35x vs 64MB-zygote fork, w/o CoW tax; but OS sandbox adds kernel-level containment defense in depth against Cranelift/runtime bugs (1 sandbox-escape class GHSA-897f in M0).
- NOTE: my earlier note 'ulimit -v breaks pooling': pool reserves 0x4082000000 B VA (~258GB) for 64 inst.
- JSON written Sun Oct 25 12:21:39 AM EDT 2026
