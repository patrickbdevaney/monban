# progress 07 (r3) 2026-10-25
Prices fetched (primary pages, 2026-10-25):
- Decodo residential: PAYG $4/GB; 3GB $3.75; 10GB $3.50; 100GB $2.75; 1TB $2.00/GB (decodo.com/proxies/residential-proxies/pricing). no per-IP pricing.
- Bright Data residential: PAYG $4/GB (50% promo, orig $8); $499/141GB=$4; $999/332GB=$3; $1999/798GB=$3 (page modified 2026-08-31).
- Oxylabs residential: $6/GB <=5GB, $5 <=20, $4 <=125, $2.5/GB 1TB+.
- 2Captcha: Turnstile $1.45/1k, reCAPTCHAv2 $1-2.99, v3 $1.45-2.99, image $0.5-1. CapSolver price page 404; third-party says $0.8-1.2/1k Turnstile (secondary, D).
- Browserless: unit=30s; Prototyping $25/20k, Starter $140/180k overage .0017, Scale $350/500k .0015 => 120 units/hr => ~$0.18-0.24/hr browser time.
- Anthropic pricing (platform.claude.com/docs/en/about-claude/pricing): Haiku 5.5 $0.10 in/$0.50 out per MTok (<=100k prompt); Sonnet 5.5 $2/$10; Opus 5.5 $4/$20; Haiku4.5 $1/$5; Fable 5.1 $10/$50; cache hit Haiku 5.5 $0.01.
- DO droplets: $4 1vCPU 512MiB 500GiB; $6 1vCPU 1GiB 1000GiB. Hetzner cost-optimized from EUR5.99 (page says currently not available), regular perf EUR6.49.
- ISP proxies (secondary): Webshare ~$0.225-0.30/IP/mo; IPRoyal ~$2.40/IP/mo.
- rustls (InfoQ 2026-09): 0.23.37 2357 full hs/s/core, 7249 resumed/s/core (x86_64; suite unstated).
- Zyte API (zyte.com/pricing, 2026-10-25): HTTP tier1 $0.06-0.13/1k, tier5 $0.61-1.27/1k; browser-rendered tier1 $0.48-1.01/1k, tier5 $7.68-16.08/1k.
- Bright Data Web Unlocker: PAYG $1.50/1k, Scale $499/383k=$1.30/1k (modified 2026-08-25).
- Netflix concurrency-limits source (raw GitHub, fetched 2026-10-25): Gradient2 defaults initialLimit=20, minLimit=20, maxConcurrency=200, smoothing 0.2, rttTolerance 1.5, longWindow 600, queueSize const 4 (NOT sqrt); app-limited check inflight<limit/2; longRtt*0.95 if long/short>2. Vegas: initial 20, max 1000, alpha=3*log10(L), beta=6*log10(L), probe mult 30, smoothing 1.0. => r2 spec (min 4, start 16, max 64) deviates from library defaults (min 20!).
- Secondary: cred stuffing break-even/stats (mynetwatchman, Recorded Future) D-grade; MCP rate-limit vendor posts (zuplo, scalekit) anecdotal.
- OWN MEASUREMENT (std-only rustc -O, i9-14900HX pinned core, 2026-10-25): GCRA keyed HashMap(SipHash) 18 ns/check @1k keys, 88 ns @65k keys; global GCRA 1.2 ns; naive evict-arbitrary-key at 1M churn keys = 3.5 us/check (artifact of O(n) keys().next(); lesson: eviction must be O(1) amortised). src: raw/round-003/07-work/gcra_bench.rs
- r2 reuse: wasm component fresh store+instantiate p50 20.3us total; hello h1 140-207k req/s (multi-core, r2 02).
- DataDome mid-Apr 2026 campaign (secondary: clubic/rankiteo/cybersecuritynews/vpncentral, no primary found): 2.45B requests in ~5h (avg ~136k rps, peak 205,344 rps), 1.2M IPs, 16,402 ASNs, ~1 request per 9 s per IP => per-IP rate ~0.11/s -> swarm shape used in sim (0.1/s/IP). Grade C.
- Booter prices (BleepingComputer/StormWall 2026, secondary D): 1h attack ~$5; $25-500/day; L7 pricier than L3/4; StormWall est ~$38/h.
- Imperva 2024 report: ~25% bad-bot traffic from residential ISPs (secondary; 2026 report not found).
- Sim built: 07-work/swarm_sim.py (heapq DES, PS CPU, GCRA S1/S3, challenge ladder, Gradient2/Vegas, CoDel, 8 queues). Findings so far (seed1-3, mixed scenario): r2 defaults collapse: humans ok 1%; fixes = fresh-session class + expensive-tier concurrency cap. Verified agent 5 req/s hits S1 5/s burst 20 => 3% 429 (verified must bypass/have own S1).
- sweeps running: sweeps_cand_mixed.jsonl
- Anubis PoW measured (yumechi 2025-09-06 'Proof of Mutex' + docs.rs/pow-buster): native single-thread SHA-256 62.19 MH/s (SHA-NI) / 85.75-89.16 MH/s (AVX-512); Chromium SIMD128 14.74 MH/s; in-browser Anubis solver ~100-200 kH/s (7950X Chromium), Firefox ~20% of that; vendor solver ~650 kH/s multithread; => native/browser ~430-860x. Server-side verify bottleneck ~11.5k proofs/s at d4 (Go mutex). => sim human_hps=1.5e5, native_hps=6.2e7 (corrected from r2's 2.3M e2-micro figure).
- Anubis v1.28.0 (2026-10-08) .. v1.28.2 (2026-10-23): opt-in WASM PoW (Argon2id/HashX/SHA-256), leading BITS difficulty (Fast 2/4/6 -> SHA-256 8/16/24 bits; Argon2id 2/4/6; HashX 7/15/20); disabled by default; no perf numbers; v1.28.2 fixes concurrent WASM validation; mentions CVE-2026-111943 (eMudhra) -- unverified id.
- Phone/human d6 (24 bits) at 150 kH/s = 112 s => ladder rung d6 excludes humans (sim finds).
- SIM FINDINGS (CAND sweep, 3 seeds, mixed = 10k-IP solver swarm @1000 rps cost-100 + heavy hitter 300 rps cost-20 + 200 humans + 10 verified):
  * r2 defaults: human success 1% (session class polluted by PoW-minted cookies; no expensive-tier cap). fresh-session class + expensive-tier concurrency cap (exp_frac .25) -> 85-88% ok.
  * CPU-keyed ladder trigger (prev window >0.8) escalates to d6 under TLS saturation where challenges cannot help; humans FP 23% -> 12% when trigger removed; chaotic near threshold (cpu_scale .5 vs .25/1.0).
  * d6 (24 bit) unusable: browser ~150 kH/s => 112 s; FP: pow3 24 bits 23%, 22 bits 15%, 18 bits 9%. Attacker admitted exp/s unchanged (6.0-6.2/s) across PoW bits => PoW irrelevant to attacker; native 62 MH/s.
  * verified agents at 5 req/s hit S1 5 req/s burst 20 => 3-80% 429 (s1_rate 1-2 kills them; ok >=5).
  * tls_full_cap (reserve window share for resumed/keepalive vs full handshakes) 0.6: FP 13.8% -> 8.1%. step-up challenge for cost>=100 at any load: FP 11%. CoDel target for expensive queue must scale w/ service (0.25 s): FP 5.4% -> 1.0%.
  * Netflix default Lmin=20 raises human p99 455->730 ms vs Lmin 4-8; fixed L 4: 197 ms, L 64: 2702 ms.
- (checkpoint 2) Added to sim: tls_full_cap (reserve window for resumed), stepup_cost (cost>=100 anon -> PoW at any load), exp tier cap (exp_frac), codel_target_E, agg_exp_units_s (fresh/anon expensive aggregate GCRA charged at S5 admit) + agg_exp_est_units_s (established); fresh-session class. Aged-cookie farming: age-only promotion (fresh_age 60 s) lets a 100 req/s slow swarm reach 'established' and get 1470 units/s admitted until established-class aggregate cap added (then ~500).
- Per-identity budgets irrelevant vs many identities: sess_upm/sess_burst sweep 150-3000 no effect (swarm 10k IPs*0.1 req/s*100 units = 10 units/s/IP == per-cookie budget 600/min).
- Panels (10 seeds) running: panel_tuned2/panel_r2/panel_perip.jsonl; sweeps_tuned2_mixed.jsonl; structural_tuned2.jsonl. Final tuned in 07-work/tuned.json.
