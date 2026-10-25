# progress 04 (checkpoint 1)
- governor 0.10.4 2025-12-16 MIT (0.10.0 2025-03-27), 87.5M dl; repo boinkor-net/governor
- Anubis releases v1.28.2 2026-10-23, v1.28.1 2026-10-09; issues #765 (2025-07-06 Marginalia punching through, open), #978 (Huawei Cloud headless chrome solves PoW; fix=block Huawei in default config PR#1004, closed 2025-08-20 "not a bug"), #50 easy-to-bypass closed; #1037 blocked by software (human cost) open
- Netflix concurrency-limits: Apache-2, 3623 stars, pushed 2026-10-21; Vegas alpha2-3 beta4-6; Gradient2; AIMD; Percentage partition (live .9 / batch .1); no measured results in README
- Privacy Pass: RFC 9576/9577/9578 June 2024; token types 1 VOPRF P-384, 2 Blind RSA 2048; rate-limit-tokens-06 EXPIRED 2024-04-01; batched-tokens-09 in IETF LC ends 2026-10-29; expiration-extension WGLC; public-metadata-issuance-03
- thelibre.news Mar 2025: GNOME Anubis 81,000 reqs in 2.5h, 3% passed PoW; 1-2 min waits on phone; Diaspora 70% AI (OpenAI 25, Amazon 15, Anthropic 4.3); RTD blocking AI crawlers 800->200GB/day (-75%, $1500/mo); Fedora blocked Brazil; SourceHut tens of thousands IPs ~1 req each
- Codeberg Aug 2025 (Register): crawlers bypass Anubis, Huawei nets; Codeberg July 2026 unauth spike status
- IPIDEA disruption Jan 2026 Google GTIG: >9M devices est. (WSJ), 550+ threat groups used exits in a week
# checkpoint 2
- Google GTIG 2026-01-28 IPIDEA: 550+ threat groups/7d, 7,400 Tier-Two servers, 4 SDK families, 13 brands, 600+ Android apps, 3,075 Windows PE; millions of devices removed (WSJ >9M)
- rdnlsmith.com 2026-07 small-site: cgit->Forgejo CPU 100%->10% but bw 13Mbps; Anubis first 24h denied 1.10M reqs (778k AI-training rule, 256k AI catch-all); unclear causality (crawlers may have stopped); somaxconn tuning no effect
- Wikipedia Anubis: default 5 leading zeros (secs in browser), 6 = minutes; challenges UA containing "Mozilla"; Ormandy: native solver beats JS, cost <1 cent/month until millions of sites; Zakaria CLI solver 2026-07-09; Codeberg 2025-08-15 bots solve challenges; adopters GNOME, LKML, sourceware, FFmpeg, Wine, Wikimedia, UNESCO, OpenWRT, FreeCAD
- IETF http-wg 2025-05-22 HashCash proposal; Ben Schwartz (Meta): IETF wary of PoW burning CPU, recommends Privacy Pass
- Radar-via-blogs crawl-to-refer inconsistent: Anthropic 23,951:1 (Q1 SEOmator) vs 11,122 (DEV, May-Jun) vs 1,917 (ecorpit July) -> unreconciled, treat as E
# checkpoint 3
- Ormandy lock.cmpxchg8b.com/anubis.html (~Aug 2025): default 4 hex zeros=16 bits=2^16 SHA256; e2-micro C miner 0.017s; ~6 min compute for 11,508 sites; <1 cent/mo until millions of sites. NOTE Wikipedia says default 5 zeros -> default drifted/conflict; check config
- Envoy adaptive concurrency: gradient=(minRTT+B)/sampleRTT; limit=gradient*old+headroom (sqrt(limit)); example p90, update 100ms, min_conc 25, minRTT window 60s jitter10 req_count 50; min_concurrency 3 default; "experimental"
- crates: governor 0.10.4 (2025-12-16), gcra 0.6.0 (2024-08-01), ratelimit_meter 5.0.0 (2019 dead), pingora-limits 0.9.0 (2026-09-09, 472k dl), tower 0.5.3 (2026-01-12), tokio-rate-limit 0.10.0 (2026-08)
- ARC: Cloudflare blog 2025-10-30 (mod 2026-07-15); N=1000: present 288B, client present 735us, verify 740us, issue server 1349us; 70x cheaper issuance than 1000 VOPRF (99ms); private-verif only; no revocation after issuance; datatracker draft-ietf-privacypass-arc-crypto-01 shows "Dead WG doc/expired" while IETF124 minutes say adopted -> conflict; no deployment; PQ ARC doesn't exist (PQ AC 7.5kB-173kB sigs). Cloudflare uses Privacy Pass today; Cloudflare+Google exploring ACT for agent rate limiting. ARC ~4x CPU of BashP-RF.
- Apple PAT: only prominent attester (iOS16 2022); Cloudflare/Fastly issuers
# checkpoint 4
- Anubis botPolicies.yaml (main, 2026-10): WEIGH thresholds: <=0 allow; 0-10 metarefresh d1; 10-20 fast d2; 20-30 fast d4; >=30 fast d6; +10 for BR/CN, +10 generic Mozilla UA; CHALLENGE/DENY return HTTP 200; store=memory. (Wikipedia says default 5 zeros; Ormandy says 4 -> policy now graded)
- Anubis #1037: CG-NAT users blocked, GFW users, odd-core-count bug, non-integer nonce bug #1043; headless Chrome from Alibaba/Tencent/Hicloud claim
- go-away (WeebDataHoarder) MIT 212 stars pushed 2026-10-24; iocaine 3.5.1 2026-08-20 (Rust), PoW as last resort, goal cost~static file; anecdote hundreds GB garbage fed to GPTBot
- Kimwolf 1.8-3M active (Deepfield ~3M peak, latent 100-200M), Aisuru 1-4M, 29.7 Tbps; Mar 2026 takedown then Aisuru infra doubled in 4 months (Censys); 20+ Kimwolf offshoots
- arXiv 2505.21733 Kim et al: 130 self-declared bots, 40 days, selectively respect robots.txt
- RFC 8289 CoDel Jan 2018 Experimental: TARGET 5ms INTERVAL 100ms, next drop t+INTERVAL/sqrt(count)
- GitHub GraphQL: 5000 pts/h, cost=requests/100 min1; secondary: 100 concurrent, 2000 pts/min GraphQL, 900 REST, 90s CPU per 60s
