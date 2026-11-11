"""Monban admission reference model: integer GCRA + the S0..S6 admission pipeline (ARCHITECTURE §3.4).

Stdlib only; loaded by admission_props.py and ref_subject.py (python3 -I). This is the *subject-side* reference: it
plays the role of the future Rust crates monban-admission / monban-budget until they exist. The property checker in
admission_props.py is written separately and does not import the pipeline logic below (only constants and
`classify`, which is the frozen spec function for S2).

Semantics (normative for the event protocol, see README.md):
  * time is integer nanoseconds (u64); every limiter is GCRA with emission interval T (ns per unit) and burst b
    (units); tolerance tau = b*T. A request of cost c at time now is conforming iff
        new = max(tat, now) + c*T  does not exceed u64::MAX  and  new - now <= tau;
    on conformance tat := new.  (Admitted cost in any window W is then <= b + W/T: I1.)
  * bounded key stores (S1 per-IP, S3 per-identity) are LRU with capacity M, touched on lookup. A newly inserted
    entry (first seen *or* re-seen after eviction) starts with min(b_class, b_anon) units available:
        tat0 = now + (b_class - min(b_class, b_anon)) * T_class      (I4: eviction never mints more than b_anon)
  * S3 = per-identity budget then, for cost >= exp_cost, the class-group aggregate (fresh+anon -> F, established
    -> E; verified is not aggregated). S3 is atomic: an aggregate reject rolls back the identity debit (the entry is
    still touched). A request is *charged* iff it passes S3 (admitted, or rejected at S4/S5/S6).
  * post-hoc debit (S6, on `done` of an admitted request): d = max(0, actual_cost - cost);
        tat := min(sat_add(max(tat, t_done), d*T), t_done + 600 s)                     (I5)
    applied only if the entry is still resident; it neither inserts nor touches the LRU order.
  * a fault injected at stage Sk fires on entry to Sk (before any state access) and rejects with 503 (I7).
"""

from collections import OrderedDict

U64 = (1 << 64) - 1
CAP_NS = 600 * 10**9          # I5: post-hoc debit cap, now + 10 min
STAGES = ("S0", "S1", "S2", "S3", "S4", "S5", "S6")
CLASSES = ("verified", "established", "fresh", "anon")
SHARES = {"verified": 0.30, "established": 0.40, "fresh": 0.10, "anon": 0.20}   # ARCHITECTURE §3.4 S2
REJECT_STATUSES = (401, 429, 503)

# Mutations used by --self-test. Each one is a realistic limiter bug.
MUTATIONS = (
    "tat_shared",           # S3 TAT keyed by class only: identities share one TAT (I2)
    "fail_open",            # a stage error skips the stage instead of rejecting (I7)
    "no_burst_cap",         # GCRA tests the *old* TAT against tau, so one request may exceed the burst (I1)
    "evict_mint_verified",  # a key re-inserted after eviction gets verified-class parameters (I4)
    "tat_overflow",         # TAT arithmetic wraps mod 2^64 instead of saturating (I5 / I1)
    "no_debit_cap",         # post-hoc debit not capped at now + 10 min: unbounded lockout (I5)
    "no_aggregate",         # expensive-tier aggregate removed; relies on per-identity budgets (I8 / I11)
    "reject_200",           # budget rejects answered with HTTP 200 (I7)
)


def classify(ev, cfg):
    """S2 (spec function): class from the presented credential and the current time."""
    cred = ev.get("cred") or {}
    kind = cred.get("kind", "none")
    if kind == "verified":
        return "verified"
    if kind == "cookie":
        age = ev["t"] - cred.get("minted", 0)
        if age < 0:
            return "anon"                       # cookie from the future: invalid, treated as no credential
        if age >= cfg["fresh_age_ns"] and cred.get("promoted", False):
            return "established"                # I9: age alone never promotes
        return "fresh"
    return "anon"


def bucket_of(ev, cls):
    cred = ev.get("cred") or {}
    if cls == "verified":
        return ("v", cred["id"]), "verified"
    if cls in ("established", "fresh"):
        return ("s", cred["id"]), "session"
    return ("a", ev["ip"]), "anon"


def agg_group(cls, cost, cfg):
    if cost < cfg["exp_cost"]:
        return None
    if cls in ("fresh", "anon"):
        return "F"
    if cls == "established":
        return "E"
    return None


class _LRU:
    def __init__(self, cap):
        self.cap = cap
        self.d = OrderedDict()
        self.evicted = set()        # keys evicted at least once (only used by the evict_mint_verified mutation)

    def lookup(self, key, init):
        if key in self.d:
            self.d.move_to_end(key)
            return self.d[key], False
        reinsert = key in self.evicted
        while len(self.d) >= self.cap:
            k, _ = self.d.popitem(last=False)
            self.evicted.add(k)
        e = init(reinsert)
        self.d[key] = e
        return e, reinsert


class Pipeline:
    def __init__(self, cfg, mutation=None):
        if mutation is not None and mutation not in MUTATIONS:
            raise ValueError("unknown mutation %r" % mutation)
        self.c = cfg
        self.m = mutation
        self.s1 = _LRU(cfg["s1_store"])
        self.s3 = _LRU(cfg["s3_store"])
        self.agg = {"F": 0, "E": 0}
        self.conns = {}                  # conn -> prefix
        self.prefix_open = {}
        self.inflight = {}               # req id -> (cls, bucket key, bucket params, cost)
        self.infl_cls = {k: 0 for k in CLASSES}

    # ---- GCRA
    def _conform(self, tat, now, T, b, cost):
        base = tat if tat > now else now
        inc = cost * T
        if self.m == "tat_overflow":
            new = (base + inc) & U64
            return new if new - now <= b * T else None
        if self.m == "no_burst_cap":
            if base - now > b * T:
                return None
            return min(base + inc, U64)
        if inc > U64 or base + inc > U64:
            return None
        new = base + inc
        return new if new - now <= b * T else None

    def _params(self, pname):
        return self.c["cls"][pname]["T"], self.c["cls"][pname]["b"]

    def _new_entry(self, now, pname):
        def init(reinsert):
            p = pname
            if reinsert and self.m == "evict_mint_verified":
                return {"tat": now, "p": "verified"}     # bug: full verified burst minted by eviction
            T, b = self._params(p)
            b_anon = self.c["cls"]["anon"]["b"]
            return {"tat": now + (b - min(b, b_anon)) * T, "p": p}
        return init

    def _reject(self, ev, stage, status):
        if self.m == "reject_200" and status == 429:
            status = 200
        return {"id": ev["id"], "decision": "reject", "status": status, "stage": stage}

    def _fault(self, ev, stage):
        return ev.get("fault") == stage and self.m != "fail_open"

    # ---- events
    def arrive(self, ev):
        c, now, cost = self.c, ev["t"], ev["cost"]
        # S0 listener: connection caps
        if self._fault(ev, "S0"):
            return self._reject(ev, "S0", 503)
        conn = ev.get("conn")
        if ev.get("newconn") and conn not in self.conns:
            pfx = ev["prefix"]
            if len(self.conns) >= c["max_conns"] or self.prefix_open.get(pfx, 0) >= c["prefix_cap"]:
                return self._reject(ev, "S0", 503)
            self.conns[conn] = pfx
            self.prefix_open[pfx] = self.prefix_open.get(pfx, 0) + 1
        # S1 pre-auth per-IP GCRA (1 unit per request), bounded LRU store
        if self._fault(ev, "S1"):
            return self._reject(ev, "S1", 503)
        e1, _ = self.s1.lookup(ev["ip"], lambda _r: {"tat": now})
        n1 = self._conform(e1["tat"], now, c["s1_T"], c["s1_b"], 1)
        if n1 is None:
            return self._reject(ev, "S1", 429)
        e1["tat"] = n1
        # S2 classify
        if self._fault(ev, "S2"):
            return self._reject(ev, "S2", 503)
        cls = classify(ev, c)
        # S3 per-identity budget + expensive-tier aggregate (atomic)
        if self._fault(ev, "S3"):
            return self._reject(ev, "S3", 503)
        key, pname = bucket_of(ev, cls)
        if self.m == "tat_shared":
            key = ("shared", pname)
        e3, _ = self.s3.lookup(key, self._new_entry(now, pname))
        T3, b3 = self._params(e3["p"])
        n3 = self._conform(e3["tat"], now, T3, b3, cost)
        if n3 is None:
            return self._reject(ev, "S3", 429)
        grp = agg_group(cls, cost, c)
        na = None
        if grp is not None and self.m != "no_aggregate":
            a = c["agg"][grp]
            na = self._conform(self.agg[grp], now, a["T"], a["b"], cost)
            if na is None:
                return self._reject(ev, "S3A", 503)
        e3["tat"] = n3
        if na is not None:
            self.agg[grp] = na
        # S4 step-up PoW for expensive anonymous requests (accessible lane bypasses)
        if self._fault(ev, "S4"):
            return self._reject(ev, "S4", 503)
        if (cls == "anon" and cost >= c["stepup_cost"] and ev.get("pow", 0) < c["stepup_bits"]
                and ev.get("lane") != "accessible"):
            return self._reject(ev, "S4", 401)
        # S5 class-partitioned concurrency (reservation + work-conserving borrow)
        if self._fault(ev, "S5"):
            return self._reject(ev, "S5", 503)
        L = c["L"]
        total = sum(self.infl_cls.values())
        res = {k: int(SHARES[k] * L) for k in CLASSES}
        if total >= L:
            return self._reject(ev, "S5", 503)
        if self.infl_cls[cls] >= res[cls]:
            others = sum(max(0, res[k] - self.infl_cls[k]) for k in CLASSES if k != cls)
            if L - total <= others:
                return self._reject(ev, "S5", 503)
        # S6 handler dispatch under deadline/fuel
        if self._fault(ev, "S6"):
            return self._reject(ev, "S6", 503)
        self.inflight[ev["id"]] = (cls, key, cost)
        self.infl_cls[cls] += 1
        return {"id": ev["id"], "decision": "admit", "status": 200, "stage": "S6"}

    def done(self, ev):
        rec = self.inflight.pop(ev["id"], None)
        if rec is None:
            return
        cls, key, cost = rec
        self.infl_cls[cls] -= 1
        d = ev.get("actual_cost", cost) - cost
        if d <= 0:
            return
        e = self.s3.d.get(key)           # no insert, no LRU touch
        if e is None:
            return
        now = ev["t"]
        T, _ = self._params(e["p"])
        base = e["tat"] if e["tat"] > now else now
        if self.m == "tat_overflow":
            new = (base + d * T) & U64
        else:
            new = min(base + d * T, U64)
        if self.m != "no_debit_cap":
            new = min(new, now + CAP_NS)
        e["tat"] = new

    def close(self, ev):
        pfx = self.conns.pop(ev["conn"], None)
        if pfx is not None:
            self.prefix_open[pfx] -= 1


def run_trace(cfg, events, mutation=None):
    """Feed one trace to a fresh pipeline; return the list of decisions (one per arrive, in order)."""
    p = Pipeline(cfg, mutation)
    out = []
    for ev in events:
        ty = ev["type"]
        if ty == "arrive":
            out.append(p.arrive(ev))
        elif ty == "done":
            p.done(ev)
        elif ty == "close":
            p.close(ev)
    return out
