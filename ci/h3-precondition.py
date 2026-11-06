#!/usr/bin/env python3
"""HTTP/3 precondition check (PREFLIGHT D-P7.1; IMPLEMENTATION_PLAN §3 Phase 7). A manual check, never a gate: the
live mode needs the network, and gates do not depend on the network. The gate `no-quic` runs only the offline
self-test.

The plan makes HTTP/3 depend on two preconditions, both mandatory:
  (a) hyperium/h3 PRs #366, #377 and #378 (frame-length bounds, decoded-header memory, QPACK "Header Accordions")
      are merged, AND a release of the `h3` crate was published on crates.io after the last of the three merges
      (a fix that is only on the default branch does not count);
  (b) six calendar months have passed without a HIGH (or CRITICAL) advisory against quinn, quinn-proto or quinn-udp.
      Sources: the GitHub repository advisories of quinn-rs/quinn and OSV (crates.io ecosystem) for the three crates,
      deduplicated by id and alias. A withdrawn advisory is ignored. Severity: the GitHub `severity`, else OSV
      `database_specific.severity`, else the CVSS v3 base score (>= 7.0 is HIGH); an advisory with no usable rating
      counts as HIGH (fail closed: an unrated advisory never starts the clock early). The clock runs out on
      last_high + 6 calendar months (day clamped to the month's end): 2026-09-30 -> 2027-03-30.

Prints exactly one verdict line: `H3-PRECONDITION: MET (...)` or `H3-PRECONDITION: NOT MET (...)`, with dates. If
HTTP/3 is built later it still needs our own frame/QPACK limits in front of h3, and the floors quinn-proto >= 0.11.19
and quinn-udp >= 0.5.16 (D-P7.1).

Usage:
  python3 -I ci/h3-precondition.py                    live probe (User-Agent aegis-ci; exit 0 on either verdict,
                                                      2 if a probe fails)
  python3 -I ci/h3-precondition.py --record FILE      live probe, and write the trimmed responses as a fixture
  python3 -I ci/h3-precondition.py --offline FILE     evaluate one fixture (no network)
  python3 -I ci/h3-precondition.py --offline-selftest evaluate every ci/fixtures/h3-precondition/*.json and require
                                                      each fixture's `expect` verdict; also requires the mandatory
                                                      fixtures (MET, the 2026-11-06 snapshot NOT MET, a HIGH at day
                                                      179 NOT MET) to be present
Fixture format: {"as_of": "YYYY-MM-DD", "expect": "MET" | "NOT MET", "note": "...",
                 "responses": {"GET <url>" | "POST <url> <body>": <json>}}.
Offline mode runs the same code path as the live mode, with the HTTP fetcher replaced by a lookup in `responses`.
"""
import datetime as dt
import glob
import json
import math
import os
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "ci", "fixtures", "h3-precondition")
UA = "aegis-ci"
PRS = (366, 377, 378)
H3_REPO = "hyperium/h3"
QUINN_REPO = "quinn-rs/quinn"
QUINN_CRATES = ("quinn", "quinn-proto", "quinn-udp")
GH = "https://api.github.com"
CRATES = "https://crates.io/api/v1/crates"
OSV = "https://api.osv.dev/v1"
MONTHS = 6
# Mandatory fixtures of the offline self-test (unit P7-spec-001 oracles).
REQUIRED = {
    "met.json": "MET",
    "snapshot-2026-11-06.json": "NOT MET",
    "high-day-179.json": "NOT MET",
}


class ProbeError(Exception):
    pass


# ------------------------------------------------------------------------------------------------ fetchers

def live_fetch(method, url, body=None):
    data = None if body is None else body.encode()
    req = urllib.request.Request(url, data=data, method=method, headers={
        "User-Agent": UA,
        "Accept": "application/vnd.github+json" if url.startswith(GH) else "application/json",
        **({"Content-Type": "application/json"} if data is not None else {}),
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        raise ProbeError(f"{method} {url}: {e}") from e


def key(method, url, body=None):
    return f"{method} {url}" if body is None else f"{method} {url} {body}"


class Recorder:
    """Wraps a fetcher and keeps a trimmed copy of every response (only the members the evaluator reads)."""

    def __init__(self, inner):
        self.inner, self.responses = inner, {}

    def __call__(self, method, url, body=None):
        r = self.inner(method, url, body)
        self.responses[key(method, url, body)] = trim(url, r)
        return r


def fixture_fetch(responses):
    def f(method, url, body=None):
        k = key(method, url, body)
        if k not in responses:
            raise ProbeError(f"fixture has no response for {k}")
        return responses[k]
    return f


def trim(url, r):
    if url.startswith(f"{GH}/repos/{H3_REPO}/pulls/"):
        return {k: r.get(k) for k in ("number", "state", "merged_at", "title")}
    if url.startswith(CRATES):
        return {"versions": [{k: v.get(k) for k in ("num", "created_at", "yanked")} for v in r.get("versions", [])]}
    if url.startswith(f"{GH}/repos/{QUINN_REPO}/security-advisories"):
        return [{"ghsa_id": a.get("ghsa_id"), "cve_id": a.get("cve_id"), "severity": a.get("severity"),
                 "published_at": a.get("published_at"), "withdrawn_at": a.get("withdrawn_at"),
                 "state": a.get("state"),
                 "vulnerabilities": [{"package": {"name": (v.get("package") or {}).get("name")}}
                                     for v in a.get("vulnerabilities") or []]} for a in r]
    if url == f"{OSV}/querybatch":
        return {"results": [{"vulns": [{"id": v.get("id")} for v in res.get("vulns", [])]}
                            for res in r.get("results", [])]}
    if url.startswith(f"{OSV}/vulns/"):
        ds = r.get("database_specific") or {}
        return {"id": r.get("id"), "published": r.get("published"), "withdrawn": r.get("withdrawn"),
                "aliases": r.get("aliases") or [], "severity": r.get("severity") or [],
                "database_specific": {"severity": ds["severity"]} if "severity" in ds else {}}
    return r


# ------------------------------------------------------------------------------------------------ dates

def parse_ts(s):
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    try:
        t = dt.datetime.fromisoformat(s)
    except ValueError:
        try:
            return dt.date.fromisoformat(s[:10])
        except ValueError:
            return None
    return t.date() if isinstance(t, dt.datetime) else t


def add_months(d, n):
    y, m = divmod(d.month - 1 + n, 12)
    y, m = d.year + y, m + 1
    nxt = dt.date(y + (m == 12), m % 12 + 1, 1)
    last = (nxt - dt.timedelta(days=1)).day
    return dt.date(y, m, min(d.day, last))


# ------------------------------------------------------------------------------------------------ severity

_CVSS3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x):
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector):
    """CVSS v3.0/v3.1 base score from a vector string, or None if it is not a complete v3 base vector."""
    if not vector or not vector.startswith("CVSS:3."):
        return None
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        s = m["S"]
        av, ac, ui = _CVSS3["AV"][m["AV"]], _CVSS3["AC"][m["AC"]], _CVSS3["UI"][m["UI"]]
        pr = {"N": 0.85, "L": 0.68 if s == "C" else 0.62, "H": 0.5 if s == "C" else 0.27}[m["PR"]]
        c, i, a = (_CVSS3["CIA"][m[k]] for k in ("C", "I", "A"))
    except KeyError:
        return None
    if s not in ("U", "C"):
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 6.42 * iss if s == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    expl = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    return _roundup(min(impact + expl, 10)) if s == "U" else _roundup(min(1.08 * (impact + expl), 10))


def level(word):
    w = (word or "").strip().upper()
    return {"LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(w)


def level_of_score(x):
    return 4 if x >= 9.0 else 3 if x >= 7.0 else 2 if x >= 4.0 else 1 if x > 0 else 0


NAMES = {0: "NONE", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}


# ------------------------------------------------------------------------------------------------ probes

def probe_prs(fetch):
    out = []
    for n in PRS:
        r = fetch("GET", f"{GH}/repos/{H3_REPO}/pulls/{n}")
        if not isinstance(r, dict) or r.get("number") != n:
            raise ProbeError(f"PR #{n}: unexpected response")
        out.append((n, r.get("state"), parse_ts(r.get("merged_at"))))
    return out


def probe_h3_releases(fetch):
    r = fetch("GET", f"{CRATES}/h3")
    vs = r.get("versions") if isinstance(r, dict) else None
    if not isinstance(vs, list) or not vs:
        raise ProbeError("crates.io h3: no versions")
    return [(v.get("num"), parse_ts(v.get("created_at"))) for v in vs if not v.get("yanked") and v.get("created_at")]


def probe_advisories(fetch):
    """[(ids frozenset, level or None, published date, packages)] after dedup by id/alias; withdrawn removed."""
    recs = []
    gh = fetch("GET", f"{GH}/repos/{QUINN_REPO}/security-advisories?per_page=100")
    if not isinstance(gh, list):
        raise ProbeError("GitHub security-advisories: unexpected response")
    for a in gh:
        if a.get("withdrawn_at") or (a.get("state") not in (None, "published")):
            continue
        ids = {x for x in (a.get("ghsa_id"), a.get("cve_id")) if x}
        pkgs = {(v.get("package") or {}).get("name") for v in a.get("vulnerabilities") or []}
        recs.append([ids, level(a.get("severity")), parse_ts(a.get("published_at")), pkgs, "github"])
    body = json.dumps({"queries": [{"package": {"ecosystem": "crates.io", "name": c}} for c in QUINN_CRATES]},
                      sort_keys=True, separators=(",", ":"))
    batch = fetch("POST", f"{OSV}/querybatch", body)
    results = batch.get("results") if isinstance(batch, dict) else None
    if not isinstance(results, list) or len(results) != len(QUINN_CRATES):
        raise ProbeError("OSV querybatch: unexpected response")
    seen = set()
    for crate, res in zip(QUINN_CRATES, results):
        for v in res.get("vulns", []) or []:
            vid = v.get("id")
            if not vid or vid in seen:
                continue
            seen.add(vid)
            d = fetch("GET", f"{OSV}/vulns/{vid}")
            if d.get("withdrawn"):
                continue
            lv = level((d.get("database_specific") or {}).get("severity"))
            if lv is None:
                scores = [cvss3_score(s.get("score")) for s in d.get("severity") or [] if s.get("type") == "CVSS_V3"]
                scores = [x for x in scores if x is not None]
                lv = level_of_score(max(scores)) if scores else None
            recs.append([{vid, *(d.get("aliases") or [])}, lv, parse_ts(d.get("published")), {crate}, "osv"])
    # Merge records that share any id (union-find by repeated sweep; the sets are small).
    merged = []
    for r in recs:
        hit = [m for m in merged if m[0] & r[0]]
        for m in hit:
            merged.remove(m)
            r[0] |= m[0]
            r[3] |= m[3]
            r[1] = m[1] if r[1] is None else (r[1] if m[1] is None else max(r[1], m[1]))
            r[2] = m[2] if r[2] is None else (r[2] if m[2] is None else min(r[2], m[2]))
        merged.append(r)
    return [(frozenset(m[0]), m[1], m[2], m[3]) for m in merged]


def evaluate(fetch, as_of):
    prs = probe_prs(fetch)
    releases = probe_h3_releases(fetch)
    advs = probe_advisories(fetch)
    reasons_a = []
    open_prs = [f"#{n} {st or '?'}" for n, st, merged in prs if merged is None]
    latest_rel = max(releases, key=lambda x: x[1]) if releases else (None, None)
    if open_prs:
        reasons_a.append("PR " + ", ".join(open_prs) + " (not merged)")
    else:
        last_merge = max(m for _, _, m in prs)
        after = [r for r in releases if r[1] > last_merge]
        if not after:
            reasons_a.append(f"all PRs merged (last {last_merge}) but no h3 release after it")
    a_met = not reasons_a
    a_text = ("a: met (PRs " + ", ".join(f"#{n} merged {m}" for n, _, m in prs)
              + f"; h3 {latest_rel[0]} released {latest_rel[1]})") if a_met else \
        "a: " + "; ".join(reasons_a) + f"; latest h3 {latest_rel[0]} {latest_rel[1]}"
    window_start = add_months(as_of, -MONTHS)
    high = [x for x in advs if x[1] is None or x[1] >= 3]
    unrated = [x for x in high if x[1] is None]
    undated = [x for x in high if x[2] is None]
    dated_high = [x for x in high if x[2] is not None]
    in_window = [x for x in dated_high if x[2] > window_start]
    medium = [x for x in advs if x[1] is not None and x[1] < 3 and x[2] is not None and x[2] > window_start]
    if undated:
        b_met = False
        b_text = "b: HIGH advisory without a publication date (" + ", ".join(sorted(min(x[0]) for x in undated)) + ")"
    elif not dated_high:
        b_met = True
        b_text = "b: met (no HIGH advisory on record)"
    else:
        last = max(dated_high, key=lambda x: x[2])
        ends = add_months(last[2], MONTHS)
        name = sorted(last[0], key=lambda s: (not s.startswith("GHSA"), s))[0]
        b_met = as_of >= ends
        b_text = (f"b: {'met' if b_met else 'not met'}: {len(in_window)} HIGH + {len(medium)} lower in "
                  f"{window_start}..{as_of}; last HIGH {name} {last[2]}, clock ends {ends}")
        if unrated:
            b_text += f"; {len(unrated)} unrated counted as HIGH"
    verdict = "MET" if a_met and b_met else "NOT MET"
    return verdict, f"as of {as_of}; {a_text}; {b_text}"


# ------------------------------------------------------------------------------------------------ modes

def run_fixture(path):
    fx = json.load(open(path))
    as_of = dt.date.fromisoformat(fx["as_of"])
    return fx, evaluate(fixture_fetch(fx["responses"]), as_of)


def selftest():
    files = sorted(glob.glob(os.path.join(FIXTURES, "*.json")))
    names = {os.path.basename(f) for f in files}
    missing = [n for n in REQUIRED if n not in names]
    if missing:
        print(f"H3-PRECONDITION SELF-TEST: FAIL (missing mandatory fixtures: {', '.join(missing)})")
        return 1
    bad, seen = [], {"MET": 0, "NOT MET": 0}
    for f in files:
        n = os.path.basename(f)
        try:
            fx, (verdict, why) = run_fixture(f)
        except (ProbeError, KeyError, ValueError, TypeError, AttributeError) as e:
            bad.append(f"{n}: {type(e).__name__}: {e}")
            continue
        want = fx.get("expect")
        if n in REQUIRED and want != REQUIRED[n]:
            bad.append(f"{n}: fixture expects {want!r}, the unit requires {REQUIRED[n]!r}")
        if verdict != want:
            bad.append(f"{n}: got {verdict}, want {want} ({why})")
        else:
            seen[verdict] += 1
            print(f"  ok  {n}: {verdict} ({why})")
    # The check must be able to say both things, or it is not a check.
    if not seen["MET"] or not seen["NOT MET"]:
        bad.append(f"verdicts seen {seen}: need at least one MET and one NOT MET")
    if bad:
        print("H3-PRECONDITION SELF-TEST: FAIL")
        for b in bad:
            print("  - " + b)
        return 1
    print(f"H3-PRECONDITION SELF-TEST: PASS ({len(files)} fixtures: {seen['MET']} MET, {seen['NOT MET']} NOT MET, "
          "each as expected)")
    return 0


def main(argv):
    if "--offline-selftest" in argv:
        return selftest()
    if "--offline" in argv:
        i = argv.index("--offline")
        if i + 1 >= len(argv):
            print("usage: --offline FILE", file=sys.stderr)
            return 2
        try:
            _, (verdict, why) = run_fixture(argv[i + 1])
        except (ProbeError, KeyError, ValueError, OSError) as e:
            print(f"H3-PRECONDITION: ERROR ({e})")
            return 2
        print(f"H3-PRECONDITION: {verdict} ({why})")
        return 0
    rec_path = None
    if "--record" in argv:
        i = argv.index("--record")
        if i + 1 >= len(argv):
            print("usage: --record FILE", file=sys.stderr)
            return 2
        rec_path = argv[i + 1]
    fetch = Recorder(live_fetch)
    as_of = dt.datetime.now(dt.timezone.utc).date()
    try:
        verdict, why = evaluate(fetch, as_of)
    except ProbeError as e:
        print(f"H3-PRECONDITION: ERROR (probe failed: {e})")
        return 2
    print(f"H3-PRECONDITION: {verdict} ({why})")
    if rec_path:
        with open(rec_path, "w") as f:
            json.dump({"as_of": as_of.isoformat(), "expect": verdict,
                       "note": f"recorded live by ci/h3-precondition.py --record on {as_of}",
                       "responses": fetch.responses}, f, indent=1, sort_keys=True)
            f.write("\n")
        print(f"recorded {len(fetch.responses)} responses -> {rec_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
