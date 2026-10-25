#!/usr/bin/env python3
"""Crate count per REPO_LAYOUT §6: packages reachable from the root through *normal* dependency edges only
(no build-/dev-deps), target x86_64-unknown-linux-gnu, root excluded. Proc-macros are reachable through normal edges
but ship no code; they are counted and also reported separately.
usage: python3 -I crates.py <manifest dir> <features or ''>  -> JSON on stdout"""
import json, subprocess, sys

def reach(manifest_dir, features):
    cmd = ["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", "x86_64-unknown-linux-gnu",
           "--manifest-path", f"{manifest_dir}/Cargo.toml"]
    if features:
        cmd += ["--features", features]
    m = json.loads(subprocess.run(cmd, capture_output=True, text=True, check=True).stdout)
    pk = {p["id"]: p for p in m["packages"]}
    nodes = {n["id"]: n for n in m["resolve"]["nodes"]}
    root = m["resolve"]["root"]
    seen, todo = set(), [root]
    while todo:
        i = todo.pop()
        for d in nodes[i]["deps"]:
            if any(k["kind"] is None for k in d["dep_kinds"]) and d["pkg"] not in seen:
                seen.add(d["pkg"])
                todo.append(d["pkg"])
    names = sorted(f"{pk[i]['name']}@{pk[i]['version']}" for i in seen)
    pm = sorted(f"{pk[i]['name']}@{pk[i]['version']}" for i in seen
                if any("proc-macro" in t["kind"] for t in pk[i]["targets"]))
    tree = {e: tree_set(manifest_dir, features, e) for e in ("normal", "normal,no-proc-macro")}
    return {"features": features,
            "metadata_normal": len(names), "metadata_proc_macros": len(pm),
            "tree_normal": len(tree["normal"]), "tree_shipped": len(tree["normal,no-proc-macro"]),
            "metadata_only_not_in_tree": sorted(set(names) - tree["normal"]),
            "proc_macro_list": pm, "list": names, "shipped_list": sorted(tree["normal,no-proc-macro"])}

def tree_set(manifest_dir, features, edges):
    """cargo tree uses the real (v2/v3) feature resolver; cargo metadata's resolve over-approximates weak `dep?/feat`
    features (e.g. rustls-webpki `ring?/alloc` shows ring as a dependency)."""
    cmd = ["cargo", "tree", "--locked", "-e", edges, "--target", "x86_64-unknown-linux-gnu", "--prefix", "none",
           "--no-dedupe", "--format", "{p}", "--manifest-path", f"{manifest_dir}/Cargo.toml"]
    if features:
        cmd += ["--features", features]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.splitlines()
    pkgs = {l.split(" (")[0].replace(" v", "@", 1).strip() for l in out if l.strip()}
    root = out[0].split(" (")[0].replace(" v", "@", 1).strip()
    return pkgs - {root}

if __name__ == "__main__":
    print(json.dumps(reach(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else ""), indent=1))
