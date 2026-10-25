"""Ported verbatim from research/state/raw/round-003/07-work/swarm_sim.py (sha256 in README.md); in-repo changes are
marked `# AEGIS-PORT:` (mutation hook for the oracle self-test, named configs, no __main__). ADVISORY, grade D.

AEGIS r3 explorer 07: discrete-event simulation of the S0-S6 admission pipeline on a 1 vCPU box.
Run: python3 -I swarm_sim.py <mode>   (stdlib only, heapq, deterministic per seed)
All stage costs / thresholds are parameters in P (defaults = r2 L5 abuse-L5-admission-pipeline-1vcpu unless noted).
Time unit: seconds.  CPU model: processor-sharing (PS) for handler work; cheap pipeline stages are charged
to 5 ms windows that steal speed from PS (and drop arrivals when a window is saturated)."""
import heapq, math, random, sys, json, collections

P0 = dict(
    seed=1, T=120.0, warm=20.0,
    # costs (reference core = i9-14900HX, scaled by 1/cpu_scale to the $5 VPS; E-assumption cpu_scale)
    cpu_scale=0.5, tls_full_us=424.0, tls_resume_us=138.0, parse_us=10.0, gcra_us=0.2, classify_us=1.0,
    reject_us=8.0, chal_issue_us=150.0, chal_verify_us=50.0, sandbox_us=20.0,
    # handler cpu seconds per cost class (units 1,5,20,100) and io multiple (spec abuse-L5-swarm-sim-spec)
    svc_ms={1: 0.2, 5: 1.0, 20: 4.0, 100: 30.0}, io_mult=0.5,
    # S0
    max_conns=2048, ip_conn_cap=32, win=0.005, win_cap=0.9,
    # S1 pre-auth GCRA per /32 (req/s, burst), bounded store, /24 aggregate
    s1_rate=5.0, s1_burst=20, s1_store=65536, agg_rate=50.0, agg_burst=200, ips_per_24=1,
    # S3 cost budgets (units/min, burst units)
    anon_upm=60.0, anon_burst=120, sess_upm=600.0, sess_burst=1200, ver_upm=1200.0, ver_burst=2400,
    # S4 ladder
    ladder=True, max_level=3, trig_sojourn=0.005, trig_hold=0.1, lvl_up_every=1.0, lvl_down_after=5.0,
    meta_delay=1.0, human_hps=1.5e5, phone_factor=5.0, pow_bits={2: 16, 3: 24}, abandon=30.0,
    accessible_lane=True, ladder_cost_aware=False,
    # S5 concurrency
    algo="gradient2", L0=16, Lmin=4, Lmax=64, shares=(0.30, 0.50, 0.0, 0.20), qmax=32, fresh_class=False, fresh_age=60.0,
    exp_frac=1.0, exp_cost=20, trig_cpu=0.8, tls_full_cap=1.0, codel_target_E=None, stepup_cost=None, stepup_level=2, s1_skip_cookie=False, agg_exp_units_s=None, agg_exp_est_units_s=None, agg_exp_burst_s=2.0,
    g_smooth=0.2, g_tol=1.5, g_queue=4, g_window=0.5, g_long=600,
    v_alpha=3, v_beta=6,
    codel=True, codel_target=0.005, codel_interval=0.1, lifo=True, fixed_L=None,
    # config switch: "full" or "perip_only" (S0+S1 only, unlimited concurrency)
    config="full",
    # attacker economics
    proxy_usd_gb=4.0, handshake_bytes=6000, req_bytes=1000, resp_ok_bytes=50000, resp_rej_bytes=400, resp_chal_bytes=3000,
    cpu_usd_hr=0.01, browser_usd_hr=0.20, native_hps=6.2e7,
)

# ---------- scenario ----------
def scenario(name, **kw):
    s = dict(humans=200, nat_humans=20, access_frac=0.05, new_frac=0.30, human_rate=0.2,
             human_mix=((1, .60), (5, .30), (20, .08), (100, .02)),
             verified=10, ver_rate=5.0,
             swarm_ips=0, swarm_rate_ip=0.0, swarm_life=3, swarm_cost=100, swarm_kind="naive", swarm_ignore429=True,
             heavy_rate=0.0, heavy_cost=20, heavy_kind="naive")
    s.update(kw); s["name"] = name; return s

MUTATIONS = ("time", "hash")  # AEGIS-PORT: deliberate nondeterminism, used only by `run --self-test`

class Sim:
    def __init__(s, P, sc, mutate=None):  # AEGIS-PORT: mutate hook
        s.P, s.sc = P, sc
        s.mutate = mutate
        seed = P["seed"]
        if mutate == "time":  # AEGIS-PORT: wall-clock leaks into the seed
            import time as _time
            seed = seed ^ (_time.time_ns() & 0xFFFFFFFF)
        elif mutate == "hash":  # AEGIS-PORT: per-scenario seed from str hash (randomized per interpreter process)
            seed = seed ^ (hash(sc["name"]) & 0xFFFFFFFF)
        s.rng = random.Random(seed)
        s.t = 0.0; s.q = []; s.seq = 0
        # PS
        s.V = 0.0; s.tlast = 0.0; s.psheap = []; s.psn = 0; s.psver = 0; s.speed = 1.0
        s.win_charge = 0.0; s.win_full = 0.0; s.prev_win = 0.0
        # limiter
        cfg = P
        s.L = float(cfg["fixed_L"] or cfg["L0"]); s.inflight = [0, 0, 0, 0]; s.inflE = 0; s.queues = [collections.deque() for _ in range(8)]; s.cmint = {}
        s.open_conns = 0; s.ip_open = collections.Counter()
        s.longrtt = None; s.rtt_sum = 0.0; s.rtt_n = 0; s.vminrtt = None
        s.s1 = collections.OrderedDict(); s.agg = {}; s.bud = {}
        s.codel = [dict(first_above=0.0, dropping=False, next_drop=0.0, count=0) for _ in range(8)]
        s.level = 0; s.over_since = None; s.calm_since = 0.0; s.last_up = -9
        s.stats = collections.defaultdict(lambda: collections.defaultdict(float))
        s.lat = collections.defaultdict(list)
        s.cookies = {}   # cookie id -> expiry
        s.ip_cookie = {}  # (ip) -> cookie id for attackers
        s.levels_time = collections.Counter(); s.Lsamples = []
        s.nid = 0
        s.init_actors()

    # ---- event helpers
    def at(s, t, kind, data=None):
        s.seq += 1; heapq.heappush(s.q, (t, s.seq, kind, data))

    def st(s, g, k, v=1.0):
        if s.t >= s.P["warm"]: s.stats[g][k] += v

    def charge(s, us, full=False):  # returns False if window saturated (arrival dropped)
        c = us * 1e-6 / s.P["cpu_scale"]
        lim = s.P["win"] * s.P["win_cap"]
        if s.win_charge + c > lim: return False
        if full:
            if s.win_full + c > lim * s.P["tls_full_cap"]: return False
            s.win_full += c
        s.win_charge += c; return True

    # ---- processor sharing
    def ps_advance(s):
        dt = s.t - s.tlast
        if s.psn > 0: s.V += dt * s.speed / s.psn
        s.tlast = s.t
    def ps_resched(s):
        s.psver += 1
        while s.psheap and s.psheap[0][2] is None: heapq.heappop(s.psheap)
        if s.psn > 0 and s.psheap:
            fv = s.psheap[0][0]
            dt = max(0.0, (fv - s.V) * s.psn / s.speed)
            s.at(s.t + dt, "psdone", s.psver)
    def ps_add(s, work, req):
        s.ps_advance(); s.seq += 1
        heapq.heappush(s.psheap, [s.V + work, s.seq, req]); s.psn += 1; s.ps_resched()
    def ps_done(s, ver):
        if ver != s.psver: return
        s.ps_advance()
        while s.psheap and (s.psheap[0][2] is None or s.psheap[0][0] <= s.V + 1e-12):
            e = heapq.heappop(s.psheap)
            if e[2] is None: continue
            s.psn -= 1; s.handler_cpu_done(e[2])
        s.ps_resched()

    # ---- actors / arrivals
    def init_actors(s):
        sc, P = s.sc, s.P; r = s.rng
        s.humans = []
        for i in range(sc["humans"]):
            nat = i < sc["nat_humans"]
            s.humans.append(dict(ip=("nat",) if nat else ("h", i), cookie=None, acc=r.random() < sc["access_frac"],
                                 phone=r.random() < 0.4, ready=r.random() >= sc["new_frac"]))
            if s.humans[-1]["ready"]:
                s.humans[-1]["cookie"] = ("hc", i); s.cookies[("hc", i)] = 1e9
        if sc["humans"]: s.at(r.expovariate(sc["humans"] * sc["human_rate"]), "gen", "human")
        if sc["verified"]: s.at(r.expovariate(sc["verified"] * sc["ver_rate"]), "gen", "ver")
        if sc["swarm_ips"] and sc["swarm_rate_ip"] > 0:
            s.slot_gen = [0] * sc["swarm_ips"]; s.slot_cnt = [0] * sc["swarm_ips"]
            s.at(r.expovariate(sc["swarm_ips"] * sc["swarm_rate_ip"]), "gen", "swarm")
        if sc["heavy_rate"] > 0: s.at(r.expovariate(sc["heavy_rate"]), "gen", "heavy")
        s.at(P["win"], "tick"); s.at(P["g_window"], "gtick"); s.at(0.05, "ltick")

    def pick_cost(s, mix):
        x = s.rng.random(); a = 0
        for c, p in mix:
            a += p
            if x < a: return c
        return mix[-1][0]

    def gen(s, who):
        sc, r = s.sc, s.rng
        if who == "human":
            h = r.randrange(sc["humans"]); H = s.humans[h]
            s.at(s.t + r.expovariate(sc["humans"] * sc["human_rate"]), "gen", "human")
            req = dict(g="human", ip=H["ip"], a24=H["ip"], cost=s.pick_cost(sc["human_mix"]), H=H, newconn=r.random() < 0.1,
                       cookie=H["cookie"], ver=False, t0=s.t, t0s=s.t, kind="human",
                       tags=(("hacc",) if H["acc"] else ()) + (("hnat",) if i_is_nat(H) else ()) + (("hnew",) if not H["ready"] else ()))
        elif who == "ver":
            s.at(s.t + r.expovariate(sc["verified"] * sc["ver_rate"]), "gen", "ver")
            a = r.randrange(sc["verified"])
            req = dict(g="verified", ip=("v", a), a24=("v", a), cost=s.pick_cost(((1, .5), (5, .5))), newconn=False,
                       cookie=("vk", a), ver=True, t0=s.t, kind="ver")
        elif who == "swarm":
            s.at(s.t + r.expovariate(sc["swarm_ips"] * sc["swarm_rate_ip"]), "gen", "swarm")
            sl = r.randrange(sc["swarm_ips"]); s.slot_cnt[sl] += 1
            if s.slot_cnt[sl] > sc["swarm_life"]: s.slot_cnt[sl] = 1; s.slot_gen[sl] += 1
            ip = ("s", sl, s.slot_gen[sl])
            req = dict(g="swarm", ip=ip, a24=("s24", (sl // P_ips24(s.P)) ), cost=sc["swarm_cost"], newconn=True,
                       cookie=s.ip_cookie.get(ip), ver=False, t0=s.t, kind=sc["swarm_kind"])
        else:
            s.at(s.t + r.expovariate(sc["heavy_rate"]), "gen", "heavy")
            req = dict(g="heavy", ip=("hv",), a24=("hv",), cost=sc["heavy_cost"], newconn=r.random() < 0.02,
                       cookie=s.ip_cookie.get(("hv",)), ver=False, t0=s.t, kind=sc["heavy_kind"])
        s.st(req["g"], "sent")
        for tg in req.get("tags", ()): s.st(tg, "sent")
        s.arrive(req)

    # ---- attacker spend
    def spend_bytes(s, g, nbytes):
        if g in ("swarm", "heavy"): s.st(g, "usd", nbytes / 1e9 * s.P["proxy_usd_gb"])
    def spend_cpu(s, g, sec, browser=False):
        if g in ("swarm", "heavy"): s.st(g, "usd", sec / 3600.0 * (s.P["browser_usd_hr"] if browser else s.P["cpu_usd_hr"]))

    # ---- GCRA
    def gcra(s, store, key, t_emit, burst_s, cost=1.0):
        """GCRA: conforming iff new TAT - now <= burst_s (burst_s = burst/rate)."""
        tat = store.get(key, 0.0); base = tat if tat > s.t else s.t
        new = base + t_emit * cost
        if new - s.t > burst_s + 1e-12: return False
        store[key] = new; return True

    # ---- pipeline
    def fail(s, req, why, bytes_=None):
        g = req["g"]; s.st(g, "rej_" + why)
        if req.get("held"): s.release_conn(req)
        s.spend_bytes(g, (bytes_ if bytes_ is not None else s.P["resp_rej_bytes"]))
        s.hfp(req)

    def hfp(s, req):
        if req["g"] == "human" and not req.get("fpd"):
            req["fpd"] = True; s.st("human", "fp")
            for tg in req.get("tags", ()): s.st(tg, "fp")

    def release_conn(s, req):
        if req.get("held"):
            s.open_conns -= 1; s.ip_open[req["ip"]] -= 1; req["held"] = False

    def arrive(s, req, followup=False):
        P, g = s.P, req["g"]
        if s.t >= P["warm"]: pass
        nb = P["req_bytes"] + (P["handshake_bytes"] if req["newconn"] and not followup else 0)
        s.spend_bytes(g, nb)
        us = P["parse_us"] + (P["tls_full_us"] if (req["newconn"] and g in ("swarm", "heavy")) else
                              P["tls_resume_us"] if req["newconn"] else 0.0)
        if s.open_conns >= P["max_conns"] or s.ip_open[req["ip"]] >= P["ip_conn_cap"]:
            s.st(g, "rej_conn"); s.hfp(req)
            return
        isfull = req["newconn"] and g in ("swarm", "heavy")
        if not s.charge(us, full=isfull):
            s.st(g, "rej_drop"); s.hfp(req)
            return
        req["held"] = True; s.open_conns += 1; s.ip_open[req["ip"]] += 1
        # S1 per-/32 pre-auth GCRA, bounded LRU store; then /24 aggregate
        s.charge(P["gcra_us"])
        key = req["ip"]
        if key in s.s1: s.s1.move_to_end(key)
        elif len(s.s1) >= P["s1_store"]:
            for _ in range(2):
                if not s.s1: break
                s.s1.popitem(last=False)
        ck0 = req["cookie"]
        skip = P["s1_skip_cookie"] and (req["ver"] or (ck0 is not None and s.cookies.get(ck0, 0) > s.t))
        if skip: s.charge(0.6)  # HMAC verify of signed cookie (assumed 0.6 us, E)
        ok = True if skip else s.gcra(s.s1, key, 1.0 / P["s1_rate"], P["s1_burst"] / P["s1_rate"])
        if ok and not skip and P["agg_rate"] > 0:
            ok = s.gcra(s.agg, req["a24"], 1.0 / P["agg_rate"], P["agg_burst"] / P["agg_rate"])
        if not ok:
            s.charge(P["reject_us"]); return s.fail(req, "429")
        if P["config"] == "perip_only":
            return s.start_handler(req, 0)
        # classify -> identity class 0 verified, 1 session, 2 anon
        s.charge(P["classify_us"])
        ck = req["cookie"]
        if req["ver"]: cls = 0
        elif ck is not None and s.cookies.get(ck, 0) > s.t:
            cls = 2 if (P["fresh_class"] and s.t - s.cmint.get(ck, -1e9) < P["fresh_age"]) else 1
        else: cls = 3
        req["cls"] = cls
        # S3 cost budget
        if cls == 0: store_key = ("v", ck); upm, bur = P["ver_upm"], P["ver_burst"]
        elif cls in (1, 2): store_key = ("s", ck); upm, bur = P["sess_upm"], P["sess_burst"]
        else: store_key = ("a", req["ip"]); upm, bur = P["anon_upm"], P["anon_burst"]
        rate = upm / 60.0
        c = req["cost"]
        if not s.gcra(s.bud, store_key, 1.0 / rate, bur / rate, cost=c):
            s.charge(P["reject_us"]); return s.fail(req, "429")
        # S4 ladder: only anonymous, only when level>0
        if cls == 3 and not followup and P["stepup_cost"] is not None and c >= P["stepup_cost"]:
            req["force_lvl"] = max(s.level, P["stepup_level"]); return s.challenge(req)
        if cls == 3 and s.level > 0 and P["ladder"] and not followup:
            if P["ladder_cost_aware"] and c < P["exp_cost"]:
                pass
            else:
                return s.challenge(req)
        s.admit_s5(req, cls)

    def challenge(s, req):
        P, g = s.P, req["g"]
        if not s.charge(P["chal_issue_us"]):
            return s.fail(req, "drop", 0)
        s.st(g, "chal"); s.spend_bytes(g, P["resp_chal_bytes"]); s.release_conn(req)
        lvl = req.get("force_lvl") or min(s.level, P["max_level"]); lvl = min(lvl, 3); r = s.rng
        kind = req["kind"]
        if g == "human":
            H = req["H"]
            if H["acc"] and P["accessible_lane"]:
                # operator-issued token / Privacy Pass redemption lane: bypass at small fixed delay
                s.at(s.t + 2.0, "follow", (req, True, lvl)); return
            if H["acc"]:  # no-JS user, no lane: stuck at level>=2, passes only metarefresh
                if lvl >= 2: s.st(g, "stuck"); return s.fail(req, "abandon", 0)
            hps = P["human_hps"] / (P["phone_factor"] if H["phone"] else 1.0)
            if lvl == 1: dly = P["meta_delay"]
            else: dly = 2 ** P["pow_bits"][lvl] / hps + 0.3
            if dly > P["abandon"]: s.st(g, "stuck"); return s.fail(req, "abandon", 0)
            s.at(s.t + dly, "follow", (req, True, lvl)); return
        # bots
        if kind == "naive":
            ok = (lvl == 1 and r.random() < 0.2)  # plain HTTP client sometimes follows meta-refresh
            if ok: s.at(s.t + P["meta_delay"], "follow", (req, True, lvl)); return
            s.st(g, "chal_fail"); return s.fail(req, "challenge", 0)
        if kind == "solver":
            if lvl == 1: s.at(s.t + P["meta_delay"], "follow", (req, True, lvl)); return
            hashes = 2 ** P["pow_bits"][lvl]; sec = hashes / P["native_hps"]
            s.spend_cpu(g, sec); s.at(s.t + sec, "follow", (req, True, lvl)); return
        if kind == "browser":
            hps = P["human_hps"]
            if lvl == 1: sec = P["meta_delay"]
            else: sec = 2 ** P["pow_bits"][lvl] / hps + 0.3
            s.spend_cpu(g, sec, browser=True); s.at(s.t + sec, "follow", (req, True, lvl)); return

    def follow(s, data):
        req, _, lvl = data
        P = s.P
        s.charge(P["chal_verify_us"])
        s.release_conn(req)
        # solved: mint session cookie bound to client
        cid = ("c", s.nid); s.nid += 1
        s.cookies[cid] = s.t + 3600; s.cmint[cid] = s.t
        g = req["g"]
        if g == "human": req["H"]["cookie"] = cid
        else: s.ip_cookie[req["ip"]] = cid
        r2 = dict(req); r2["cookie"] = cid; r2["newconn"] = False; r2["t0s"] = s.t
        s.spend_bytes(g, P["req_bytes"])
        s.st(g, "solved")
        s.arrive(r2, followup=True)

    def start_handler(s, req, cls):
        s.admit_s5(req, cls)

    # S5 ----
    def admit_s5(s, req, cls):
        P = s.P
        if P["config"] == "perip_only":
            req["tadm"] = s.t; req["cls_"] = 0; req["E"] = False; return s.run_handler(req)
        if P["agg_exp_units_s"] and cls in (2, 3) and req["cost"] >= P["exp_cost"]:
            if not s.gcra(s.bud, "aggE", 1.0 / P["agg_exp_units_s"], P["agg_exp_burst_s"], cost=req["cost"]):
                s.charge(P["reject_us"]); return s.fail(req, "429")
        if P["agg_exp_est_units_s"] and cls == 1 and req["cost"] >= P["exp_cost"]:
            if not s.gcra(s.bud, "aggE1", 1.0 / P["agg_exp_est_units_s"], P["agg_exp_burst_s"], cost=req["cost"]):
                s.charge(P["reject_us"]); return s.fail(req, "429")
        isE = P["exp_frac"] < 1.0 and req["cost"] >= P["exp_cost"]
        qi = cls + (4 if isE else 0); q = s.queues[qi]
        if len(q) >= P["qmax"]:
            return s.fail(req, "503")
        req["tq"] = s.t; req["E"] = isE; req["qi"] = qi; q.append(req)
        s.drain()

    def drain(s):
        P = s.P; sh = P["shares"]
        capE = max(1, int(P["exp_frac"] * s.L)) if P["exp_frac"] < 1.0 else 10**9
        for _ in range(256):
            if sum(s.inflight) >= s.L: return
            cand = []
            for k in range(4):
                if s.queues[k] or (s.queues[k + 4] and s.inflE < capE):
                    cand.append(k)
            if not cand: return
            below = [k for k in cand if sh[k] > 0 and s.inflight[k] < sh[k] * s.L]
            pool = below or cand
            k = min(pool, key=lambda x: (s.inflight[x] / sh[x]) if sh[x] > 0 else 9e9)
            req = s.take(k, capE)
            if req is None: continue
            s.dispatch(req, k)

    def take(s, k, capE):
        P = s.P
        order = [k, k + 4] if s.queues[k] else [k + 4]
        for qi in order:
            if qi >= 4 and s.inflE >= capE: continue
            q = s.queues[qi]
            while q:
                lifo = P["lifo"] and k == 3 and len(q) > 4
                req = q.pop() if lifo else q.popleft()
                soj = s.t - req["tq"]
                if P["codel"] and s.codel_drop(qi, soj):
                    s.fail(req, "503"); continue
                return req
        return None

    def dispatch(s, req, cls):
        s.inflight[cls] += 1; req["cls_"] = cls; req["tadm"] = s.t
        if req["E"]: s.inflE += 1
        s.run_handler(req)

    def run_handler(s, req):
        P = s.P
        s.charge(P["sandbox_us"])
        cpu = P["svc_ms"][req["cost"]] * 1e-3
        req["io"] = cpu * P["io_mult"]
        s.ps_add(cpu, req)

    def handler_cpu_done(s, req):
        s.at(s.t + req["io"], "iodone", req)

    def iodone(s, req):
        P = s.P; g = req["g"]
        now = s.t
        s.release_conn(req)
        if P["config"] != "perip_only":
            s.inflight[req["cls_"]] -= 1
            if req["E"]: s.inflE -= 1
            rtt = now - req["tadm"]
            s.rtt_sum += rtt; s.rtt_n += 1
            if P["algo"] == "vegas" and (s.vminrtt is None or rtt < s.vminrtt): s.vminrtt = rtt
        s.st(g, "ok"); s.spend_bytes(g, P["resp_ok_bytes"])
        for tg in req.get("tags", ()): s.st(tg, "ok")
        if req["cost"] >= 20: s.st(g, "ok_exp")
        if now >= P["warm"]:
            s.lat[g].append(now - req["t0"])
            if g == "human": s.lat["human_srv"].append(now - req.get("t0s", req["t0"]))
            if g == "human": s.lat["human_c%d" % req["cost"]].append(now - req["t0"])
        if P["config"] != "perip_only": s.drain()

    def codel_drop(s, k, soj):
        P = s.P; c = s.codel[k]; now = s.t
        tgt = P["codel_target_E"] if (k >= 4 and P["codel_target_E"] is not None) else P["codel_target"]
        if soj < tgt:
            c["first_above"] = 0.0; c["dropping"] = False; return False
        if c["first_above"] == 0.0:
            c["first_above"] = now + P["codel_interval"]; return False
        if not c["dropping"]:
            if now >= c["first_above"]:
                c["dropping"] = True; c["count"] = 1; c["next_drop"] = now + P["codel_interval"] / math.sqrt(1)
                return True
            return False
        if now >= c["next_drop"]:
            c["count"] += 1; c["next_drop"] = now + P["codel_interval"] / math.sqrt(c["count"]); return True
        return False

    # timers ----
    def tick(s):
        s.prev_win = s.win_charge / s.P["win"]; s.win_charge = 0.0; s.win_full = 0.0
        ns = max(0.05, 1.0 - s.prev_win)
        if abs(ns - s.speed) > 1e-9:
            s.ps_advance(); s.speed = ns; s.ps_resched()
        s.at(s.t + s.P["win"], "tick")

    def gtick(s):
        P = s.P
        if s.rtt_n >= 5 and P["fixed_L"] is None and P["config"] != "perip_only":
            short = s.rtt_sum / s.rtt_n; s.rtt_sum = 0.0; s.rtt_n = 0
            if P["algo"] == "gradient2":
                if s.longrtt is None: s.longrtt = short
                else:
                    a = 2.0 / (P["g_long"] + 1)
                    s.longrtt = s.longrtt * (1 - a) + short * a
                if s.longrtt / short > 2: s.longrtt *= 0.95
                if sum(s.inflight) >= s.L / 2:
                    g = max(0.5, min(1.0, P["g_tol"] * s.longrtt / short))
                    nl = s.L * g + P["g_queue"]
                    nl = s.L * (1 - P["g_smooth"]) + nl * P["g_smooth"]
                    s.L = max(P["Lmin"], min(P["Lmax"], nl))
            elif P["algo"] == "vegas":
                if s.vminrtt:
                    qs = math.ceil(s.L * (1 - s.vminrtt / short)); lg = max(1, math.log10(s.L))
                    if sum(s.inflight) >= s.L / 2:
                        if qs < P["v_alpha"] * lg: s.L += lg
                        elif qs > P["v_beta"] * lg: s.L -= lg
                    s.L = max(P["Lmin"], min(P["Lmax"], s.L))
            s.drain()
        else:
            s.rtt_sum = 0.0; s.rtt_n = 0
        s.at(s.t + P["g_window"], "gtick")

    def ltick(s):
        """ladder controller: anon-queue sojourn > trig for hold => up; calm => down"""
        P = s.P; q = s.queues[3]
        soj = (s.t - q[0]["tq"]) if q else 0.0
        stress = soj > P["trig_sojourn"] or (sum(s.inflight) >= s.L and len(q) > 0) or s.prev_win > P["trig_cpu"]
        if stress:
            if s.over_since is None: s.over_since = s.t
            s.calm_since = s.t
            if s.t - s.over_since >= P["trig_hold"] and s.t - s.last_up >= P["lvl_up_every"] and s.level < P["max_level"]:
                s.level += 1; s.last_up = s.t
        else:
            s.over_since = None
            if s.level > 0 and s.t - s.calm_since >= P["lvl_down_after"]:
                s.level -= 1; s.calm_since = s.t
        if s.t >= P["warm"]:
            s.levels_time[s.level] += 0.05
            s.Lsamples.append(s.L)
        if len(s.s1) > 0 and int(s.t * 20) % 40 == 0:  # purge expired GCRA entries ~2s
            pass
        s.at(s.t + 0.05, "ltick")

    def run(s):
        while s.q:
            t, _, k, d = heapq.heappop(s.q)
            if t > s.P["T"]: break
            s.t = t
            if k == "gen": s.gen(d)
            elif k == "psdone": s.ps_done(d)
            elif k == "iodone": s.iodone(d)
            elif k == "tick": s.tick()
            elif k == "gtick": s.gtick()
            elif k == "ltick": s.ltick()
            elif k == "follow": s.follow(d)
        return s.report()

    def report(s):
        P = s.P; out = {"scenario": s.sc["name"], "seed": P["seed"]}
        dur = P["T"] - P["warm"]
        def pct(a, p):
            if not a: return None
            a = sorted(a); return a[min(len(a) - 1, int(p * len(a)))]
        for g in ("human", "verified", "swarm", "heavy"):
            S = s.stats.get(g)
            if not S: continue
            sent = S["sent"]; d = dict(sent=int(sent), ok=int(S["ok"]), ok_rate=round(S["ok"] / sent, 4) if sent else None,
                                        ok_exp=int(S["ok_exp"]), r429=int(S["rej_429"]), r503=int(S["rej_503"]),
                                        drop=int(S["rej_drop"] + S["rej_conn"]), chal=int(S["chal"]), solved=int(S["solved"]),
                                        chal_fail=int(S["rej_challenge"]), abandon=int(S["rej_abandon"]))
            if g == "human": d["fp_rate"] = round(S["fp"] / sent, 4) if sent else None
            if g in ("swarm", "heavy"):
                d["usd"] = round(S["usd"], 4); d["usd_per_ok_exp"] = (S["usd"] / S["ok_exp"]) if S["ok_exp"] else None
                d["usd_per_1k_attempts"] = round(S["usd"] / sent * 1000, 4) if sent else None
                d["admitted_units_s"] = round(S["ok"] * (s.sc["swarm_cost"] if g == "swarm" else s.sc["heavy_cost"]) / dur, 1)
            L = s.lat.get(g, [])
            d["p50_ms"] = round(1000 * pct(L, .5), 2) if L else None; d["p99_ms"] = round(1000 * pct(L, .99), 2) if L else None
            out[g] = d
        for tg in ("hacc", "hnat", "hnew"):
            S = s.stats.get(tg)
            if S and S["sent"]: out[tg] = dict(sent=int(S["sent"]), ok_rate=round(S["ok"] / S["sent"], 4), fp_rate=round(S["fp"] / S["sent"], 4))
        L = s.lat.get("human_srv", [])
        out["human_srv_p99_ms"] = round(1000 * pct(L, .99), 2) if L else None
        out["human_srv_p50_ms"] = round(1000 * pct(L, .5), 2) if L else None
        out["ladder_time"] = {k: round(v / dur, 3) for k, v in sorted(s.levels_time.items())}
        out["L_mean"] = round(sum(s.Lsamples) / len(s.Lsamples), 1) if s.Lsamples else None
        out["cpu_ovh_util_last"] = round(s.prev_win, 3)
        return out

def i_is_nat(H): return H["ip"] == ("nat",)

def P_ips24(P): return max(1, P["ips_per_24"])

def run(over=None, mutate=None, **sckw):  # AEGIS-PORT: mutate passthrough
    P = dict(P0); sc = scenario(sckw.pop("name", "x"), **sckw)
    if over: P.update(over)
    return Sim(P, sc, mutate).run()

SCEN = {
 "baseline": dict(),
 "swarm_naive_1k": dict(swarm_ips=10000, swarm_rate_ip=0.1, swarm_life=3, swarm_cost=100, swarm_kind="naive"),
 "swarm_solver_1k": dict(swarm_ips=10000, swarm_rate_ip=0.1, swarm_life=3, swarm_cost=100, swarm_kind="solver"),
 "swarm_browser_1k": dict(swarm_ips=10000, swarm_rate_ip=0.1, swarm_life=3, swarm_cost=100, swarm_kind="browser"),
 "heavy_only": dict(heavy_rate=300, heavy_cost=20, heavy_kind="naive"),
 "aged_swarm": dict(swarm_ips=10000, swarm_rate_ip=0.03, swarm_life=100, swarm_cost=100, swarm_kind="solver"),
 "cheap_flood": dict(swarm_ips=10000, swarm_rate_ip=0.1, swarm_life=3, swarm_cost=5, swarm_kind="solver"),
 "flash_crowd": dict(humans=1000, nat_humans=50, new_frac=0.8),
 "dc_swarm_1k_ips": dict(swarm_ips=1000, swarm_rate_ip=1.0, swarm_life=1000, swarm_cost=100, swarm_kind="solver"),
 "mixed": dict(swarm_ips=10000, swarm_rate_ip=0.1, swarm_life=3, swarm_cost=100, swarm_kind="solver",
               heavy_rate=300, heavy_cost=20, heavy_kind="naive"),
}

# AEGIS-PORT: named configs. TUNED = research/state/raw/round-003/07-work/tuned.json (the ARCHITECTURE §3.4 table),
# R2 = round-2 defaults (P0), PERIP = S0+S1 only. BROKEN = TUNED minus every identity-count-independent defence
# (no expensive-tier aggregates, no fresh class, no expensive concurrency cap): self-test negative control.
TUNED = {"fresh_class": True, "shares": (0.3, 0.4, 0.1, 0.2), "exp_frac": 0.25, "trig_cpu": 9,
         "ladder_cost_aware": True, "lvl_up_every": 5.0, "pow_bits": {2: 16, 3: 18}, "s1_rate": 10, "s1_burst": 50,
         "tls_full_cap": 0.5, "stepup_cost": 100, "anon_upm": 600, "anon_burst": 600, "codel_target": 0.02,
         "codel_target_E": 0.25, "L0": 8, "agg_exp_units_s": 300, "agg_exp_est_units_s": 400}
CONFIGS = {"TUNED": TUNED, "R2": {}, "PERIP": {"config": "perip_only"},
           "BROKEN": dict(TUNED, agg_exp_units_s=None, agg_exp_est_units_s=None, fresh_class=False,
                          shares=(0.3, 0.5, 0.0, 0.2), exp_frac=1.0)}
