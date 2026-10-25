"""q4-008: combine per-source results into the per-clause table and decision (stdlib; python3 -I -B).

usage: python3 -I -B summarize.py RESULTS_DIR   -> writes RESULTS_DIR/summary.json, prints a markdown table
Decision rule: a rejecting clause flips when its BENIGN line rate exceeds 0.1% in at least one modern source
(2024-2026). Older sources (SecRepo 2017-2023, NASA 1995) are reported for comparison only and never decide.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyze import HOST_CLAUSES, OK308, PATH_CLAUSES, QUERY_CLAUSES  # noqa: E402

MODERN = ["secrepo-2024-2026", "cc-main-2026-43"]
ERA = ["secrepo-2017-2023", "nasa-1995"]
THRESH = 0.1


def main(d):
    res = {}
    for fn in sorted(os.listdir(d)):
        if fn.endswith(".json") and fn != "summary.json":
            r = json.load(open(os.path.join(d, fn)))
            res[r["source"]] = r
    srcs = [s for s in MODERN + ERA if s in res]
    rows = {}
    for c in PATH_CLAUSES + QUERY_CLAUSES + HOST_CLAUSES + [OK308]:
        row = {}
        for s in srcs:
            for k in ("raw", "benign"):
                cl = res[s][k]["clauses"][c]
                row["%s/%s" % (s, k)] = {"pct_lines": cl["pct_lines"], "pct_sole": cl["pct_sole"],
                                         "pct_unique": cl["pct_unique"], "lines": cl["lines"]}
        applicable = [s for s in MODERN if s in res and not (c.startswith("h.") and res[s]["format"] != "cc")]
        mx = max([row["%s/benign" % s]["pct_lines"] for s in applicable] or [0.0])
        row["max_modern_benign_pct"] = mx
        row["decision"] = ("already 308" if c == OK308 else ("flip" if mx > THRESH else "keep reject"))
        rows[c] = row
    totals = {s: {k: {"lines": res[s][k]["lines"], "pct_ref_reject": res[s][k]["pct_ref_reject"],
                      "pct_ref_308": res[s][k]["pct_ref_308"], "unique_targets": res[s][k]["unique_targets"]}
                  for k in ("raw", "benign")} for s in srcs}
    out = {"threshold_pct": THRESH, "modern": MODERN, "era": ERA, "totals": totals, "clauses": rows,
           "disagreements": {s: res[s]["detector_vs_reference_disagreements"] for s in srcs}}
    json.dump(out, open(os.path.join(d, "summary.json"), "w"), indent=1)
    hdr = ["clause"] + ["%s raw / benign (sole)" % s for s in srcs] + ["decision"]
    print("| " + " | ".join(hdr) + " |")
    print("|" + "---|" * len(hdr))
    for c, row in rows.items():
        if all(row["%s/raw" % s]["lines"] == 0 for s in srcs):
            continue
        cells = [c]
        for s in srcs:
            r, b = row["%s/raw" % s], row["%s/benign" % s]
            cells.append("%.4f / %.4f (%.4f)" % (r["pct_lines"], b["pct_lines"], b["pct_sole"]))
        cells.append(row["decision"])
        print("| " + " | ".join(cells) + " |")
    print()
    for s in srcs:
        t = totals[s]
        print("%s: raw %d lines (any CANON reject %.3f%%, 308 %.3f%%); benign %d lines (reject %.3f%%, 308 %.3f%%)"
              % (s, t["raw"]["lines"], t["raw"]["pct_ref_reject"], t["raw"]["pct_ref_308"], t["benign"]["lines"],
                 t["benign"]["pct_ref_reject"], t["benign"]["pct_ref_308"]))


if __name__ == "__main__":
    main(sys.argv[1])
