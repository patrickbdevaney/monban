# 03 verification-footprint-and-golden-contract — progress (round 2)
## Checkpoint 1 (release asset sizes via gh api, 2026-10-24/25)
- lean4 v4.35.0 (2026-10-12) linux.tar.zst 566MB / zip 883MB; v4.36.0-rc1 577MB
- elan v4.2.4 (2026-08-25) 4MB
- verus release/0.2026.10.18.7d82994 x86-linux.zip 464MB; rolling 0.2026.10.25.98699c5 464MB
- kani-0.68.0 (2026-09-16) x86_64 linux tar.gz 133MB (+ rust nightly toolchain pulled at setup)
- cbmc-6.11.0 (2026-08-21) ubuntu-24.04 deb 70MB
- apalache v0.62.4 (2026-10-12) tgz 183MB (needs JVM 17+)
- tla2tools.jar v1.8.0 (2026-10-24) 4MB
- cvc5-1.4.2 (2026-10-08) Linux-x86_64-static.zip 41MB (gpl static 113MB)
- z3-5.3.1 (2026-10-15) x64-glibc-2.39.zip 65MB; ANOMALY z3-5.3.0 x64-glibc zip = 1494MB
- FStar v2026.10.18 Linux-x86_64 tar.gz 223MB (grew 193->223MB in 3 weeks)
- everparse v2026.10.06 Linux_x86_64 tar.gz 275MB
- aeneas nightly-2026.10.24 linux-x86_64 153MB + lean-build 65MB

## Checkpoint 2 (post-crash resume, 2026-10-24 23:55; installed sizes via zip central-directory range reads, no full download)
- lean 4.35.0 linux.zip: 926MB zip -> 3365MB installed, 18,571 files. lib/lean 2859MB (.private 1367MB, .so 475, .a 415, .ir 381, .olean 349). Mathlib NOT included. Bundles LLVM/clang libs (~370MB incl dup symlink-as-copies) and independent kernel checkers: lean4lean 37MB, nanoda_bin 1.3MB, leanchecker-paranoid 8.9MB, con-leche 17.6MB, con-ron 2.9MB, leanexport, cadical.
- Lean PRs: #15099 bundle nanoda (merged 2026-09-10), #15048 bundle lean4lean (2026-09-10), #15145 `lake check --paranoid` runs leanchecker-paranoid+lean4lean+nanoda+con-leche, accept only if all accept (2026-09-14), #15762 axioms reported before checkers (2026-10-19).
- Lean KERNEL soundness bugs 2026: #14807 is_prop stuck-term => proof-irrelevance unsound (merged 2026-08-18; reported by D. Selsam/OpenAI via internal models; nanoda ALSO accepted the bogus proof; lean4lean did not). #14577 nested-inductive param args unchecked (2026-07-28). #14498 opaque fvars (2026-07-22).
- verus 0.2026.10.18 x86-linux.zip: 487MB -> 1643MB installed (4617 files; duplicate rlibs under deps/), z3 35MB bundled. Requires rustup toolchain 1.99.1 + rustc-dev + llvm-tools (rust-toolchain.toml on main) -> not installed locally.
- cvc5 1.4.2 static zip 44MB -> 158MB installed, bin/cvc5 32MB alone.
- z3 5.3.1 x64 zip 69MB -> 141MB installed; bin/z3 40.5MB alone.

## Checkpoint 3 (2026-10-25 00:10)
- kani-0.68.0 bundle: 140MB tgz -> 508MB installed (playback/lib 238, lib/rustlib 152, cbmc 18.6, goto-instrument 15.6); PLUS pinned nightly-2026-08-21 (1.100.0-nightly) w/ llvm-tools,rustc-dev,rust-src,rustfmt = 299MB xz download.
- verus needs rust 1.99.1 (2026-10-15) + rustc-dev + llvm-tools: 295MB xz download (rustc-dev 125MB xz alone).
- everparse v2026.10.06: 288MB tgz -> 973MB installed (own fstar.exe 63MB, lib/fstar 239, cddl src 174, lowparse 137, pulse 114, krml 37).
- apalache 0.62.4: 192MB tgz -> 197MB (single jar), needs JVM 17+ (local OpenJDK 21 present).
- Kani #4905: Kani reported VERIFICATION SUCCESSFUL when CBMC hit bad_alloc writing JSON (exit 6 ignored); fix PR #4910 merged 2026-09-30, AFTER kani-0.68.0 (2026-09-16) = latest release => no released Kani contains the fix (as of 2026-10-25). Gate must check CBMC exit code / pin main.
- Kani #4965 (open, 2026-10-04): goto-instrument --ensure-one-backedge-per-target >20GB (22GB uncapped) on sha2 0.11 Sha256 4-byte harness; sha2 0.10.9 202MB. #4747: CBMC SIGSEGV under ulimit -v 10GiB vs clean OOM at 6GiB (16GB runner). #5043: 220 harnesses at 24-way parallel w/ 60s timeout: 30 changed verdict vs serial; --dfcc O(n^2), 8,111s on one harness; 26,994 std harnesses finished within 55s; proposes instruction-count budget 333G instr. #3965 contracts HashMap OOM >8GB.
- Verus #3184/#3213/#3214/#3215 check-api-safety gaps (Oct 2026); #2580 panic on large rlimit-count; #2458 parallel verification RFC.
- EXISTENCE PROOF: cedar-spec/cedar-lean (Lean v4.35.0) requires only batteries (+doc-gen4 dev only) — NO Mathlib — for authz semantics + SymCC proofs.
- COUNTER: Aeneas backends/lean requires mathlib @ v4.35.0 => Aeneas path drags full Mathlib.
- Lean minimal-subset install measurement REFUSED by heavy.sh (/home 9-10G free < 10G). Retry later or spike.

## Checkpoint 4 (2026-10-25 00:17) OWN MEASUREMENTS (laptop: 31GiB RAM, x86_64, Linux 6.17; all under heavy.sh where heavy)
- Rust 1.99.1 (Verus pin) installed sizes: rustc 416MB + rust-std 167 + cargo 37 + rustc-dev 685 + llvm-tools 216 = 1,521MB. => Verus total ~3.16GB (1,643 + 1,521).
- F* v2026.10.18 tgz 234MB -> 694MB installed (lib 623, bin 70). EverParse bundles z3-4.13.3 (33MB) + own fstar.exe.
- LEAN MINIMAL SUBSET (no Mathlib, no Batteries, no Lake libs): bin (76MB incl. all external checkers) + libleanshared*.so + libInit_shared.so + Init oleans/.ir + small runtime libs = 676MB on disk (vs 3,365MB full toolchain). Std adds more (not measured: heavy.sh refused, /home 9G).
- Toy Lean file Core.lean (budget invariant via induction+omega, attenuation monotonicity, failed=>no mutation): `lean -o Core.olean` wall 0.24s warm (8s cold), peak RSS 514MB (mostly mmapped Init oleans). False theorem correctly rejected by omega.
- leanchecker Core (kernel re-check replay): 0.19s, 453MB RSS (needs libLake_shared.so 14MB).
- leanexport Core: 14.3s, 991MB RSS, export 346MB NDJSON (includes all of Init).
- nanoda_bin 0.4.19 (bundled) on that export: 59,400 declarations checked, no typechecker errors, 49.7s wall, 362MB RSS. Note: Init declares sorryAx -> hard_error config rejects whole-export; per-theorem axiom audit (lake check) needed.
- bundled lean4lean invoked directly on oleans: "incompatible header" for every module (usage error or packaging mismatch; unresolved — intended path is `lake check`).
- bv_decide needs `import Std.Tactic.BVDecide` (Std, not Init).
- cvc5 1.4.2: QF_BV u64 budget inductive step unsat, 0.65s, 24MB RSS. z3 5.3.1: unsat 0.16s, 41MB RSS.
- TLC (tla2tools 1.8.0, 4.5MB jar, OpenJDK 21, -Xmx512m, 1 worker): Req spec Budget+NoMutationOnFail, Limit=20: 348 distinct states 0.49s 110MB; Limit=2000: 2,674,668 distinct states 4.4s 362MB.
- Apalache default heap -Xmx4096m (src/universal/bin/apalache-mc; docs running.md JVM_ARGS).
- Lean kernel arena (arena.lean-lang.org, generated 2026-10-24, Lean 4.34.1): Mathlib export 5.8GB/109.8M lines; official kernel 32.3min 9.9GB; nanoda 16.5m 6.0GB; lean4lean 38.8m 11.6GB; con-leche 21.6m 5.1GB. 73 bad tests: official, nanoda, lean4lean, kefir etc accept 0 bad; con-ron and con-leche accept 3 bad each (so paranoid = conjunction, soundness from any one sound checker).

## Checkpoint 5 (2026-10-25 00:30)
- Lean source Lean/Meta/Native.lean (v4.35.0): native_decide AND bv_decide "assert the result of that computation as an axiom" -> TCB adds Lean compiler + any @[implemented_by] (ImplementedByAttr.lean: "makes it possible to prove False with native_decide using incorrect implementations"). => golden axiom allowlist {propext, Classical.choice, Quot.sound}; ban native_decide/bv_decide in assurance proofs (use decide/omega/grind) or isolate.
- verify-rust-std Kani CI (run 40029035848, 2026-10-23): 4 partitions x {ubuntu, macos}; partition jobs 30-56 min; whole run wall 70min..2h56m (15 recent successful runs).
- Verus CI (2026-08-04): basic-test linux 8m, full-test macos 36m; nightly-verita (external verified projects) 42m (2026-10-24).
- Envoy extension-boundary advisories: CVE-2026-47207 (GHSA-68cv-hq5f-g6xv, 2026-06-23) ext_proc server packing 2 ProcessingResponses in one gRPC msg => UAF crash in Envoy (all versions); CVE-2024-23324 ext_authz bypass via PROXY-protocol invalid UTF-8 when failure_mode_allow=true; CVE-2026-73552 RBAC safe_regex fail-open on obs-text (error collapsed to no-match); CVE-2026-47205 ext_authz UAF; CVE-2026-50572 ext_authz segfault; CVE-2025-30157 ext_proc local replies crash.
- Proxy-Wasm ABI v0.2.1 spec: memory/CPU limits and external-resource lists are SHOULD; proxy_set_effective_context lets plugin switch to other connections/requests ("might limit"); global shared KV (CAS) + shared queues across plugins; crash => recreate VM with rate-limit. => incumbent plugin ABI is not capability-safe by spec.
- Component Model Goals.md: "capability-safe ... interfaces", shared-nothing. wasmtime-wasi 50.0.0 WasiCtxBuilder::new(): no env/args/preopens, stdin closed, IP name lookup denied, sockets addresses denied; clocks + RNG granted by default (timing channel).
- wasi-testsuite (Apache-2.0, pushed 2026-10-23, adapters/ per runtime) = conformance-suite precedent; cncf/k8s-conformance (pushed 2026-10-22) = self-certification program precedent.
- UNKNOWN-UNKNOWN: Lean core ships Std.Http (PR #10478 2026-01-25; data types #12126 2026-03-04): sans-I/O HTTP/1.1 server, 47 files 13,462 lines, 23 theorems (char-class/lowercase/URI-encoding lemmas), 0 sorry, NO framing/canonicality theorem. Candidate Lean-side reference parser for Cedar-style DRT vs Rust parser.
- CryptoProver arXiv 2608.00965 (v2 2026-10-16): Verus proofs of curve25519-dalek + chacha20 synthesized in 11.4h, $466.99 API (cloud LLM; optional accelerator only).

## Checkpoint 6 (2026-10-25 00:40)
- Init+Std subset = 1,002MB on disk. Std import baseline: 0.26s, 667MB RSS. BV.lean (4 obligations incl. bv_decide u32 mask): cold 48s / warm 10s wall, 665MB RSS.
- `#print axioms`: bv_decide theorem depends on [propext, Classical.choice, Quot.sound, len_mask._native.bv_decide.ax_1_5] (native axiom, confirmed empirically); omega theorem depends on no axioms.
- Apalache features.md: liveness via liveness-to-safety transformation (supported). F* INSTALL.md: requires z3-5.3.0 on PATH (binary releases bundle it).
- All downloaded toolchains deleted from scratch after measurement.
