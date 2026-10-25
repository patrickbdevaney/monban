#!/usr/bin/env python3
"""fips_client_policy (P-PQ6) prototype gate. Light: reads cargo metadata/tree, nm, a linker map, probe output;
compiling is done by run.sh under ci/heavy.sh.

P-PQ6 (cmvp): no rustls client reachable, OR every client kx_groups = [SECP256R1MLKEM768] with no
key-share-prediction store. PASS iff mode A (compiled-out) or mode B (pq-only) holds:

  A compiled-out  = M1 feature `tls-client` OFF in the cmvp feature set (cargo tree, real feature resolver)
                  ∧ B0 positive control: the artifact carries rustls *server* symbols (else the scan is blind -> ERROR)
                  ∧ B1 zero `rustls::client::*` symbols in the unstripped twin (nm -C)
                  ∧ B2 zero `rustls::client` sections in the linker map of the shipped stripped binary (if given)
  B pq-only       = S1 clippy disallowed-methods log clean except the one blessed constructor
                  ∧ S2 exactly one `disallowed_methods` expect/allow in first-party source, in the blessed module
                  ∧ M2 every non-rustls crate in the graph whose source builds a ClientConfig is allowlisted as
                       "takes an injected config" (none in this prototype)
                  ∧ P1 probe report(s) for every blessed constructor: kx_groups == [secp256r1MLKEM768],
                       resumption == NoClientSessionStorage/Disabled, both ClientHellos list and share only 0x11EB,
                       2nd ClientHello has no pre_shared_key and no early_data, negotiated SECP256R1MLKEM768.
usage: fips_client_policy.py --manifest DIR --features F --bin UNSTRIPPED [--map MAP] [--clippy-log LOG]
                             [--probe JSON]... [--src DIR] [--json]
Exit 0 PASS, 1 FAIL, 2 ERROR (cannot judge)."""
import json, os, re, subprocess, sys

CLIENT_SYM = re.compile(r"rustls::client::")
SERVER_SYM = re.compile(r"rustls::server::")
# Mangled forms (legacy _ZN...6rustls6client... and v0 ..._6rustls6client...) for the linker map.
CLIENT_MANGLED = re.compile(r"6rustls6client")
SERVER_MANGLED = re.compile(r"6rustls6server")
CLIENT_CTOR_SRC = re.compile(r"ClientConfig::builder|with_platform_verifier\(|ClientConfig\s*\{")
INJECTED_CONFIG_ALLOW = {}  # crate name -> reason ("accepts an Arc<ClientConfig> from the caller"); none needed here
PQ = "secp256r1MLKEM768"


def arg(name, default=None, multi=False):
    a = sys.argv[1:]
    vals = [a[i + 1] for i, x in enumerate(a) if x == name and i + 1 < len(a)]
    return vals if multi else (vals[-1] if vals else default)


def tree(manifest, features):
    cmd = ["cargo", "tree", "--locked", "-e", "normal,no-proc-macro", "-e", "features", "--target",
           "x86_64-unknown-linux-gnu", "--prefix", "none", "--no-dedupe", "--manifest-path", f"{manifest}/Cargo.toml"]
    if features:
        cmd += ["--features", features]
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


def metadata_pkgs(manifest, features):
    """Packages actually in the build (cargo tree, real resolver) with their source dirs (cargo metadata)."""
    cmd = ["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", "x86_64-unknown-linux-gnu",
           "--manifest-path", f"{manifest}/Cargo.toml"] + (["--features", features] if features else [])
    m = json.loads(subprocess.run(cmd, capture_output=True, text=True, check=True).stdout)
    t = tree(manifest, features)
    live = {l.split(" feature ")[0].split(" (")[0].strip() for l in t.splitlines() if l.strip()}
    rootn = next(n for n in m["resolve"]["nodes"] if n["id"] == m["resolve"]["root"])
    out = []
    for p in m["packages"]:
        if f"{p['name']} v{p['version']}" in live:
            out.append((p["name"], p["version"], os.path.dirname(p["manifest_path"]), p["source"] is None))
    return out, t, rootn["features"]


def blessed(s2):
    """Exactly one disallowed_* suppression in first-party source, directly on `fn pq_only_client_config`."""
    if s2 is None or len(s2) != 1:
        return False
    path, line = s2[0].split(":")[0], int(s2[0].split(":")[1])
    rest = open(path).read().splitlines()[line:line + 2]
    return any("fn pq_only_client_config" in x for x in rest)


def main():
    manifest, features, binp = arg("--manifest"), arg("--features", ""), arg("--bin")
    mapp, clippy_log, probes, src = arg("--map"), arg("--clippy-log"), arg("--probe", multi=True), arg("--src")
    r = {"manifest": manifest, "features": features, "bin": binp, "checks": {}}
    c = r["checks"]

    pkgs, t, root_features = metadata_pkgs(manifest, features)
    root = next((p for p in pkgs if p[3]), None)
    c["M1_root_features"] = root_features
    c["M1_tls_client_feature_on"] = "tls-client" in root_features
    c["M0_rustls_in_graph"] = any(p[0] == "rustls" for p in pkgs)
    ctor = []
    for name, ver, d, first_party in pkgs:
        if name == "rustls" or first_party:
            continue
        hits = subprocess.run(["grep", "-rlE", CLIENT_CTOR_SRC.pattern, os.path.join(d, "src")],
                              capture_output=True, text=True).stdout.split()
        if hits:
            ctor.append(f"{name}@{ver}")
    c["M2_third_party_client_ctors"] = ctor
    c["M2_unallowlisted"] = [x for x in ctor if x.split("@")[0] not in INJECTED_CONFIG_ALLOW]

    nm = subprocess.run(["nm", "-C", "--defined-only", binp], capture_output=True, text=True)
    syms = nm.stdout.splitlines()
    c["B_symbols_total"] = len(syms)
    c["B0_server_symbols"] = sum(1 for s in syms if SERVER_SYM.search(s))
    cs = [s.split(" ", 2)[-1] for s in syms if CLIENT_SYM.search(s)]
    c["B1_client_symbols"] = len(cs)
    c["B1_client_symbol_sample"] = sorted(cs)[:8]
    if mapp:
        mp = open(mapp, errors="replace").read()
        c["B2_map_client_refs"] = len(CLIENT_MANGLED.findall(mp))
        c["B2_map_server_refs"] = len(SERVER_MANGLED.findall(mp))

    if clippy_log is not None:
        log = open(clippy_log, errors="replace").read()
        c["S1_clippy_disallowed_hits"] = len(re.findall(r"use of a disallowed (method|type)", log))
    if src:
        ex = subprocess.run(["grep", "-rnE", r"(expect|allow)\(clippy::disallowed_(methods|types)", src],
                            capture_output=True, text=True).stdout.splitlines()
        c["S2_suppressions"] = ex
    pr = []
    for p in probes:
        j = json.load(open(p))
        h1, h2 = j["hellos"]
        bad = []
        if j["kx_groups"] != [PQ]:
            bad.append(f"kx_groups={j['kx_groups']}")
        if "NoClientSessionStorage" not in j["resumption"] or "Disabled" not in j["resumption"]:
            bad.append(f"resumption={j['resumption']}")
        for i, h in enumerate((h1, h2), 1):
            if h["supported_groups"] != ["0x11EB"] or h["key_share"] != ["0x11EB"]:
                bad.append(f"hello{i} groups={h['supported_groups']} shares={h['key_share']}")
            if h["negotiated"] != PQ:
                bad.append(f"hello{i} negotiated={h['negotiated']}")
        if h2["pre_shared_key"] or h2["early_data"] or h2["kind"] == "Resumed":
            bad.append("hello2 resumes (session store present)")
        if h2["key_share"] != h1["key_share"]:
            bad.append(f"key-share prediction: hello2 shares {h2['key_share']} != hello1 {h1['key_share']}")
        pr.append({"probe": os.path.basename(p), "violations": bad})
    c["P1_probes"] = pr

    # Verdict
    if c["B_symbols_total"] == 0 or c["B0_server_symbols"] == 0:
        r["verdict"], r["reason"] = "ERROR", "positive control failed: no rustls server symbols (stripped or wrong artifact)"
    else:
        a = (not c["M1_tls_client_feature_on"]) and c["B1_client_symbols"] == 0 and c.get("B2_map_client_refs", 0) == 0
        why_a = [] if a else [m for m, bad in (
            ("feature tls-client on", c["M1_tls_client_feature_on"]),
            (f"{c['B1_client_symbols']} rustls::client symbols", c["B1_client_symbols"] > 0),
            (f"{c.get('B2_map_client_refs', 0)} rustls::client map refs", c.get("B2_map_client_refs", 0) > 0)) if bad]
        s2 = c.get("S2_suppressions")
        b_parts = {
            "S1 clippy clean": clippy_log is not None and c["S1_clippy_disallowed_hits"] == 0,
            "S2 one blessed suppression": blessed(s2),
            "M2 third-party ctors allowlisted": not c["M2_unallowlisted"],
            "P1 probes present and clean": bool(pr) and all(not x["violations"] for x in pr),
        }
        b = all(b_parts.values())
        if a:
            r["verdict"], r["mode"] = "PASS", "compiled-out"
        elif b:
            r["verdict"], r["mode"] = "PASS", "pq-only"
        else:
            r["verdict"] = "FAIL"
            r["reason"] = {"compiled-out": why_a, "pq-only": [k for k, v in b_parts.items() if not v]}
    print(json.dumps(r, indent=1))
    return {"PASS": 0, "FAIL": 1}.get(r["verdict"], 2)


if __name__ == "__main__":
    sys.exit(main())
