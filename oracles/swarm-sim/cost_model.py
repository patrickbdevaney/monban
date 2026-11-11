"""Ported verbatim from research/state/raw/round-003/07-work/cost_model.py (sha256 in README.md). Monban-PORT changes:
importing builds `out` and nothing else (the original printed it and wrote cost_model.json into its own directory).
All prices are a 2026-10-25 snapshot; stage costs mix grades B/C/D/E as labelled per row. ADVISORY.

Attacker + defender cost model sheet. Prices fetched 2026-10-25 (URLs in sources dict)."""
import json

SRC = {
 "decodo_resi": "https://decodo.com/proxies/residential-proxies/pricing (PAYG $4/GB; 1TB $2/GB)",
 "brightdata_resi": "https://brightdata.com/pricing/proxy-network/residential-proxies (PAYG $4 promo/$8 list; $3/GB at $999+; page modified 2026-08-31)",
 "oxylabs_resi": "https://oxylabs.io/products/residential-proxy-pool ($6/GB <=5GB ... $2.5/GB at 1TB+)",
 "2captcha": "https://2captcha.com/pricing (Turnstile $1.45/1k; reCAPTCHA v2 $1-2.99/1k; image $0.5-1/1k)",
 "browserless": "https://www.browserless.io/pricing (unit=30 s; overage $0.0015-0.0020/unit => $0.18-0.24/browser-hr)",
 "zyte": "https://www.zyte.com/pricing/ (HTTP tier1 $0.06-0.13/1k; browser tier1 $0.48-1.01/1k)",
 "brightdata_unlocker": "https://brightdata.com/pricing/web-unlocker ($1.30-1.50/1k)",
 "anthropic": "https://platform.claude.com/docs/en/about-claude/pricing (Haiku 5.5 $0.10/$0.50 per MTok; Sonnet 5.5 $2/$10; Opus 5.5 $4/$20)",
 "redsift_mlkem": "https://redsift.com/blog/post-quantum-mlkem-performance (server CPU/handshake 0.198->0.240 ms = +21%; +1,088 B server, +1,176 B client)",
 "datadome_2026_secondary": "https://clubic.com//actualite-611866-datadome-a-stoppe-une-attaque-ddos-de-2-45-milliards-de-requetes-et-c-est-fascinant.html (1.2M IPs, 2.45B req/5h; secondary)",
 "digitalocean": "https://www.digitalocean.com/pricing/droplets ($4: 1vCPU/512MiB/500GiB; $6: 1vCPU/1GiB/1000GiB)",
 "hetzner": "https://www.hetzner.com/cloud/ (from EUR5.99 cost-optimized shown 'currently not available'; EUR6.49 regular)",
}

proxy = {"decodo_1TB": 2.0, "mid_payg": 4.0, "oxylabs_small": 6.0}   # $/GB
TURNSTILE_1K = 1.45        # 2captcha
BROWSER_HR = (0.18, 0.24)  # browserless overage derived
TOK = {  # (in $/MTok, out $/MTok)
 "haiku-5.5": (0.10, 0.50), "sonnet-5.5": (2.0, 10.0), "opus-5.5": (4.0, 20.0)}
HS_BYTES = 6000            # TLS1.3 full handshake both directions incl. cert chain (assumption E; hybrid ML-KEM adds ~2.2 KB)

# attack classes: (name, req_bytes, resp_bytes_ok, resp_bytes_rejected, new_conn_per_req, captcha_per_req, notes)
classes = {
 "scrape":       dict(req=800,  resp=100_000, rej=400, conn=1.0, cap=0.05, note="HTML page ~100 KB; cookie/CAPTCHA solved once per ~20 reqs"),
 "cred_stuff":   dict(req=1_500, resp=3_000,   rej=400, conn=1.0, cap=1.0,  note="POST login; worst case one Turnstile solve per attempt"),
 "exp_endpoint": dict(req=1_000, resp=50_000,  rej=400, conn=1.0, cap=0.0,  note="deep path (blame/log/search); cost-100 class"),
 "mcp_tool_spam":dict(req=2_000, resp=2_000,   rej=400, conn=0.1, cap=0.0,  note="JSON-RPC tools/call over keep-alive HTTP; scripted, no LLM"),
}
out = {"sources": SRC, "assumptions": {"HS_BYTES": HS_BYTES}, "attacker_per_1M_requests_usd": {}, "attacker_llm_per_1M_usd": {}}

for n, c in classes.items():
    row = {}
    for pn, p in proxy.items():
        for outcome, rb in (("all_admitted", c["resp"]), ("all_rejected_429", c["rej"])):
            b = c["req"] + rb + HS_BYTES * c["conn"]
            row[f"{pn}/{outcome}"] = round(1e6 * b / 1e9 * p + 1e6 * c["cap"] * TURNSTILE_1K / 1000, 1)
    row["bytes_per_req_admitted"] = c["req"] + c["resp"] + HS_BYTES * c["conn"]
    row["bytes_per_req_rejected"] = c["req"] + c["rej"] + HS_BYTES * c["conn"]
    row["captcha_usd_per_1M"] = round(1e6 * c["cap"] * TURNSTILE_1K / 1000, 1)
    row["note"] = c["note"]
    out["attacker_per_1M_requests_usd"][n] = row

# managed alternatives per 1M successful pages
out["managed_per_1M_pages_usd"] = {
 "zyte_http_t1": [60, 130], "zyte_http_t5": [610, 1270], "zyte_browser_t1": [480, 1010], "zyte_browser_t5": [7680, 16080],
 "brightdata_unlocker": [1300, 1500],
 "own_browserless_4s_per_page": [round(1e6 * 4 / 3600 * h) for h in BROWSER_HR]}

# LLM-driven agent steps (MCP tool-spam or browsing), tokens per step
steps = {"mcp_tool_step": (1500, 250), "browse_step_with_screenshot": (6000, 400)}
for m, (pi, po) in TOK.items():
    out["attacker_llm_per_1M_usd"][m] = {s: round(1e6 * (i * pi + o * po) / 1e6, 0) for s, (i, o) in steps.items()}
    out["attacker_llm_per_1M_usd"][m]["per_step_usd_mcp"] = round((1500 * pi + 250 * po) / 1e6, 6)
# cached prompt variant (cache read Haiku 5.5 $0.01/MTok): mostly-cached 1250 of 1500 tokens
out["attacker_llm_per_1M_usd"]["haiku-5.5_cached_mcp"] = round(1e6 * (1250 * 0.01 + 250 * 0.10 + 250 * 0.50) / 1e6, 0)

# defender costs: CPU us per request per stage, reference core (i9-14900HX) and scaled to $5 VPS (cpu_scale .5)
VPS_USD_MONTH = 5.0
usd_per_cpu_s = VPS_USD_MONTH / (30.44 * 86400)
stages = [
 # name, us_ref, provenance
 ("S0 TLS1.3 full handshake (rustls 0.23.37 x86_64, 2357 hs/s/core)", 424.0, "C: InfoQ 2026-09 rustls one decade; suite unstated, no ML-KEM"),
 ("S0 TLS resumed handshake (7249/s/core)", 138.0, "C: same source"),
 ("S0 HTTP parse + header (hyper-class)", 10.0, "E: assumption; r2 hello h1 140-207k req/s multi-core gives <=~5 us/core bound only"),
 ("S1 per-/32 GCRA keyed (std HashMap SipHash, 65k keys)", 0.088, "D: own measurement 2026-10-25, 87.8 ns, i9-14900HX, single thread, rustc -O"),
 ("S1 per-/32 GCRA @1k keys", 0.018, "D: own measurement, 18.2 ns"),
 ("S1 global GCRA", 0.0012, "D: own measurement, 1.16 ns"),
 ("S1 naive key-eviction under 1M-key churn (O(n) keys().next())", 3.5, "D: own measurement, 3.5 us: eviction must be O(1)"),
 ("classify route->cost class", 1.0, "E: assumption"),
 ("S3 per-identity GCRA", 0.1, "E: from S1 measurement"),
 ("429 response write", 8.0, "E: assumption"),
 ("S4 challenge issue (HMAC + page)", 150.0, "E: assumption"),
 ("S4 challenge verify", 50.0, "E: assumption"),
 ("S6 wasm component fresh store+instantiate", 20.3, "B: r2 measured p50 (07-isolation), wasmtime pooling"),
 ("handler cost-1/5/20/100 (0.2/1/4/30 ms)", 200.0, "E: r2 swarm-sim-spec model; per class 200/1000/4000/30000 us"),
]
out["defender_stage_cost"] = []
for n, us, prov in stages:
    out["defender_stage_cost"].append(dict(stage=n, us_ref_core=us, us_on_5usd_vps_scale0p5=round(us / 0.5, 3),
        usd_per_1M=round(us / 0.5 * 1e-6 * 1e6 * usd_per_cpu_s, 6), provenance=prov))
out["usd_per_cpu_second_5usd_vps_fully_utilised"] = usd_per_cpu_s

# capacity and attacker $ to saturate one vCPU (1 hour)
cap = {}
for label, us in (("429 reject after full TLS", (424 + 10 + 0.1 + 8) / 0.5), ("challenge issue after full TLS", (424 + 10 + 1 + 150) / 0.5),
                  ("cost-100 handler after full TLS", (424 + 10 + 1 + 20) / 0.5 + 30000),
                  ("429 reject after full TLS, hybrid X25519MLKEM768 (+21% server hs CPU, Red Sift/OpenSSL)", (424 * 1.21 + 10 + 0.1 + 8) / 0.5)):
    rps = 1e6 / us
    row = dict(us_per_req=round(us, 1), rps_to_saturate_one_vcpu=round(rps, 1))
    for pn, p in proxy.items():
        b = 1000 + 400 + HS_BYTES + (2264 if "hybrid" in label else 0)
        row[f"attacker_usd_per_hour_{pn}"] = round(rps * 3600 * b / 1e9 * p, 2)
    cap[label] = row
out["saturate_one_vcpu"] = cap
# Monban-PORT: print + json.dump(out, open("cost_model.json", "w")) removed
