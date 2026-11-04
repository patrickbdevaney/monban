#!/usr/bin/env python3
"""Self-tests of both cmvp-binary entry points. Heavy (builds the fixtures through lib/fixtures.sh); run on kamrui:
    ci/remote.sh --host kamrui oracles/cmvp-binary/run --self-test
    ci/remote.sh --host kamrui oracles/cmvp-binary/client-policy --self-test
Every case states the verdict AND the check id that must produce it, so a case that goes red for the wrong reason
is a mismatch too."""
import copy
import datetime
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
FIX = os.path.join(HERE, "fixtures")
T = os.path.join(os.path.realpath(os.path.join(ROOT, "target")), "cmvp-binary-fixtures")
P, C = os.path.join(T, "plain", "release"), os.path.join(T, "client", "release")
sys.path.insert(0, HERE)
import client_policy as cp  # noqa: E402
import fips_binary as fb  # noqa: E402


def build():
    r = subprocess.run([os.path.join(HERE, "lib", "fixtures.sh")])
    if r.returncode != 0:
        print(f"fixture build failed (exit {r.returncode})")
        return False
    return True


def row(name, want, got, why, ok):
    print(f"  {name:34s} expect {want:28s} got {got:6s} {'ok' if ok else 'MISMATCH'}  {why[:150]}")


# ======================================================================== fips-binary (`run`)
def real_metadata():
    r = subprocess.run([os.path.join(ROOT, "profiles/cmvp/build.sh"), "--metadata"], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"profiles/cmvp/build.sh --metadata failed: {r.stderr.strip()[-300:]}")
    return json.loads(r.stdout)


def meta_mutants(base):
    """Mutations of the real cmvp resolve graph, each breaking one F3 clause."""
    pk = {p["id"]: p for p in base["packages"]}
    fs_id = next(i for i, p in pk.items() if p["name"] == "aws-lc-fips-sys")
    rs_ids = [i for i, p in pk.items() if p["name"] == "aws-lc-rs"]
    out = {}

    m = copy.deepcopy(base)  # no fips-sys node at all
    m["resolve"]["nodes"] = [n for n in m["resolve"]["nodes"] if n["id"] != fs_id]
    out["meta_no_fips_sys"] = m

    m = copy.deepcopy(base)  # a second (decoy) fips-sys node
    p2 = copy.deepcopy(pk[fs_id]); p2["version"] = "0.14.3"; p2["id"] = fs_id.replace(pk[fs_id]["version"], "0.14.3")
    m["packages"].append(p2)
    n2 = copy.deepcopy(next(n for n in m["resolve"]["nodes"] if n["id"] == fs_id)); n2["id"] = p2["id"]
    m["resolve"]["nodes"].append(n2)
    out["meta_two_fips_sys"] = m

    m = copy.deepcopy(base)  # registry aws-lc-sys instead of the void path crate
    for p in m["packages"]:
        if p["name"] == "aws-lc-sys":
            p["source"] = "registry+https://github.com/rust-lang/crates.io-index"
    out["meta_registry_aws_lc_sys"] = m

    m = copy.deepcopy(base)  # path aws-lc-sys that has a build script (not void)
    for p in m["packages"]:
        if p["name"] == "aws-lc-sys":
            p["targets"] = p["targets"] + [{"kind": ["custom-build"], "name": "build-script-build"}]
    out["meta_aws_lc_sys_build_script"] = m

    m = copy.deepcopy(base)  # aws-lc-rs without feature fips
    for n in m["resolve"]["nodes"]:
        if n["id"] in rs_ids:
            n["features"] = [f for f in n["features"] if f != "fips"]
    out["meta_rs_no_fips"] = m

    m = copy.deepcopy(base)  # fips-sys off the pins.toml version
    for p in m["packages"]:
        if p["id"] == fs_id:
            p["version"] = "0.13.12"
    out["meta_fips_sys_off_pin"] = m

    m = copy.deepcopy(base)  # aws-lc-rs not linking fips-sys
    for n in m["resolve"]["nodes"]:
        if n["id"] in rs_ids:
            n["deps"] = [d for d in n["deps"] if d.get("pkg") != fs_id]
    out["meta_rs_unlinked"] = m
    return out


def fips_binary_selftest():
    if not build():
        print("CMVP-BINARY SELF-TEST: FAIL (fixture build)")
        return 1
    work = os.path.join(T, "selftest-run")
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    try:
        base = real_metadata()
    except (RuntimeError, ValueError) as e:
        print(f"CMVP-BINARY SELF-TEST: FAIL (cannot read the real cmvp graph: {e})")
        return 1
    mpath = {}
    for k, v in [("meta_real", base)] + sorted(meta_mutants(base).items()):
        mpath[k] = os.path.join(work, k + ".json")
        json.dump(v, open(mpath[k], "w"))
    b = lambda n: os.path.join(P, n)  # noqa: E731
    cases = [  # name, binary, expect, metadata, want verdict, required violation prefix
        ("good (real cmvp graph)", b("fips_good"), "cmvp", "meta_real", "PASS", None),
        ("floor negative control", b("fips_floor"), "floor", None, "PASS", None),
        ("floor judged as cmvp", b("fips_floor"), "cmvp", "meta_real", "FAIL", "F1:"),
        ("good judged as floor", b("fips_good"), "floor", None, "FAIL", "F1':"),
        ("mut no contiguous string", b("fips_nostring"), "cmvp", "meta_real", "FAIL", "F1:"),
        ("mut string, runtime none", b("fips_rt_none"), "cmvp", "meta_real", "FAIL", "F4:"),
        ("mut string, runtime 4.2.0", b("fips_rt_420"), "cmvp", "meta_real", "FAIL", "F4:"),
        ("mut floor build with string", b("fips_rt_none"), "floor", None, "FAIL", "F1':"),
        ("mut --fips-check mismatch", b("fips_mismatch"), "cmvp", "meta_real", "FAIL", "F4:"),
        ("mut --fips-check missing", b("fips_noflag"), "cmvp", "meta_real", "FAIL", "F4:"),
        ("mut decoy 2nd module id", b("fips_decoy"), "cmvp", "meta_real", "FAIL", "F2:"),
        ("mut non-FIPS module id", os.path.join(work, "nonfips"), "cmvp", "meta_real", "FAIL", "F2:"),
        ("mut binary missing", os.path.join(work, "absent"), "cmvp", "meta_real", "ERROR", None),
    ] + [(k, b("fips_good"), "cmvp", k, "FAIL", "F3:") for k in sorted(mpath) if k != "meta_real"]
    # non-FIPS identity next to the FIPS one (aws-lc-sys linked too): append the floor module's bytes to fips_good
    shutil.copy2(b("fips_good"), os.path.join(work, "nonfips"))
    with open(os.path.join(work, "nonfips"), "ab") as f:
        f.write(b"\0AWS-LC 5.11.0\0")
    fails = 0
    for name, binp, expect, meta, want, pre in cases:
        v, bad, info = fb.judge(binp, expect, mpath.get(meta))
        ok = v == want and (pre is None or any(x.startswith(pre) for x in bad))
        if want == "PASS":
            ok = ok and not bad
        fails += not ok
        row(name, want + (f" {pre}" if pre else ""), v, "; ".join(bad) or info[0], ok)
    # the entry point with RELATIVE --binary/--metadata (the gate passes target/cmvp/release/aegis): they must be
    # resolved before --fips-check runs the binary with cwd /
    rel = [os.path.relpath(b("fips_good"), T), os.path.relpath(mpath["meta_real"], T)]
    r = subprocess.run([os.path.join(HERE, "run"), "--binary", rel[0], "--metadata", rel[1]], cwd=T,
                       capture_output=True, text=True, timeout=600)
    last = (r.stdout.strip().splitlines() or [""])[-1]
    ok = r.returncode == 0 and last.startswith("CMVP-BINARY: PASS")
    fails += not ok
    row("entry point, relative paths", "PASS (exit 0)", "PASS" if ok else f"rc={r.returncode}", last, ok)
    n = len(cases) + 1
    if fails:
        print(f"CMVP-BINARY SELF-TEST: FAIL ({fails}/{n} mismatches)")
        return 1
    print(f"CMVP-BINARY SELF-TEST: PASS ({n}/{n}: 2 baselines PASS (cmvp fixture on the real cmvp graph, floor "
          f"negative control), {n - 3} mutants caught with the expected check id, entry point with relative paths)")
    return 0


# ======================================================================== client-policy
def relink_flag_drift(relink_flags):
    """build.sh --check cargo flags that change what is compiled but are absent from the docker relink's flags."""
    import re
    import shlex
    txt = open(os.path.join(ROOT, "profiles/cmvp/build.sh")).read()
    m = re.search(r"^\s*flags=\((.*)\)\s*$", txt, re.M)
    if not m:
        raise ValueError("no flags=(...) line in profiles/cmvp/build.sh")
    flags = [x for x in shlex.split(m.group(1)) if x.startswith("--") and x not in ("--keep-going", "--features")]
    if re.search(r"flags\+=\(--release\)", txt):
        flags.append("--release")
    return [x for x in flags if x not in relink_flags]


def client_policy_selftest():
    if not build():
        print("CLIENT-POLICY SELF-TEST: FAIL (fixture build)")
        return 1
    work = os.path.join(T, "selftest-cp")
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    today = datetime.date(2026, 11, 4)
    probes = {}
    for x in ("pq_client", "bad_client", "bad_resume"):
        p = os.path.join(work, f"probe-{x}.json")
        r = subprocess.run([os.path.join(C, x), "--probe"], capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            print(f"CLIENT-POLICY SELF-TEST: FAIL (probe {x}: {r.stderr.strip()[-200:]})")
            return 1
        open(p, "w").write(r.stdout)
        probes[x] = p
    clippy = {x: os.path.join(T, f"clippy-{x}.log") for x in
              ("srv_only", "pq_client", "bad_client", "bad_resume", "dead_client")}

    def opts(binary, features="", package=None, bin_name=None, td=None, relink="none", **kw):
        o = {"mode": None, "binary": binary, "manifest": FIX, "package": package, "bin_name": bin_name,
             "features": features, "relink": relink, "target_dir": td, "map": None, "twin": None,
             "clippy_log": None, "probes": [], "src": None, "blessed_fn": "pq_only_client_config",
             "mtls": None, "today": today}
        o.update(kw)
        o["work"] = os.path.join(work, "relink-" + os.path.basename(binary) + ("-" + features if features else ""))
        return o

    # Relinked views (twin + shipped-config map, R0 checked) of each fixture, exactly as on the cmvp tree.
    views = {}

    def view(key, binary, features, td, package=None):
        # own work dir: a case that relinks the same fixture must not delete these views' maps
        rv = cp.relink_views("host", FIX, package, os.path.basename(binary), features, td, binary,
                             os.path.join(work, "view-" + key))
        views[key] = rv
        return rv

    TP, TC = os.path.join(T, "plain"), os.path.join(T, "client")
    try:
        view("srv_only", os.path.join(P, "srv_only"), "", TP)
        view("srv_mtls", os.path.join(P, "srv_mtls"), "", TP, "cmvp-fixtures-mtls")
        for x in ("pq_client", "bad_client", "bad_resume", "dead_client"):
            view(x, os.path.join(C, x), "tls-client", TC)
    except (RuntimeError, OSError) as e:
        print(f"CLIENT-POLICY SELF-TEST: FAIL (relink: {e})")
        return 1
    for k, rv in views.items():
        print(f"  relink {k:12s} R0 identical {rv['R0_identical']} restored {rv['judged_restored']} "
              f"sha {rv['sha_judged'][:16]}")

    def V(k, **kw):  # explicit views of fixture k
        return {"twin": views[k]["twin"], "map": views[k]["map"], **kw}

    # mutant source tree: a second disallowed_methods suppression (spike mutant 12)
    msrc = os.path.join(work, "mut-src")
    shutil.copytree(os.path.join(FIX, "src"), msrc)
    p = os.path.join(msrc, "bin", "bad_client.rs")
    txt = open(p).read()
    assert "fn main" in txt
    open(p, "w").write(txt.replace("fn main", "#[allow(clippy::disallowed_methods)]\nfn main", 1))
    # an R0 mutant: the judged binary is not what the shipped configuration links to
    r0b = os.path.join(work, "srv_only.tampered")
    shutil.copy2(os.path.join(P, "srv_only"), r0b)
    with open(r0b, "ab") as f:
        f.write(b"\0")
    # mTLS justifications (D13 C2)
    jgood, jexp = os.path.join(work, "mtls-ok.toml"), os.path.join(work, "mtls-expired.toml")
    entry = ('[[mtls]]\nverifier = "WebPkiClientVerifier"\nadvisory = "RUSTSEC-2026-0382"\n'
             'reason = "self-test: listener mTLS against a private CA, chain building not affected"\n'
             'approver = "self-test"\nexpires = "{}"\n')
    open(jgood, "w").write(entry.format("2027-01-01"))
    open(jexp, "w").write(entry.format("2026-11-03"))

    pq = dict(clippy_log=clippy["pq_client"], probes=[probes["pq_client"]])
    S, PQB = os.path.join(P, "srv_only"), os.path.join(C, "pq_client")
    cases = [
        # --- the spike's 12 (srv_only relinks for real: R0 + twin + map) ---
        ("srv_only", "compiled-out", opts(S, "", None, "srv_only", TP, "host", clippy_log=clippy["srv_only"]),
         "PASS", None),
        ("pq_client", "pq-only", opts(PQB, "tls-client", **V("pq_client", **pq)), "PASS", None),
        ("bad_client", "both", opts(os.path.join(C, "bad_client"), "tls-client", **V(
            "bad_client", clippy_log=clippy["bad_client"], probes=[probes["bad_client"]])), "FAIL", None),
        ("bad_resume", "both", opts(os.path.join(C, "bad_resume"), "tls-client", **V(
            "bad_resume", clippy_log=clippy["bad_resume"], probes=[probes["bad_resume"]])), "FAIL", None),
        ("dead_client", "both", opts(os.path.join(C, "dead_client"), "tls-client", **V(
            "dead_client", clippy_log=clippy["dead_client"])), "FAIL", None),
        ("mut_srv_feature_on", "compiled-out", opts(S, "tls-client", **V("srv_only")), "FAIL", "M1:"),
        ("mut_srv_stripped", "both", opts(S, ""), "ERROR", "B0:"),
        ("mut_srv_client_bin", "compiled-out", opts(S, "", twin=views["bad_client"]["twin"],
                                                    map=views["srv_only"]["map"]), "FAIL", "B1:"),
        ("mut_pq_no_probe", "pq-only", opts(PQB, "tls-client", **V("pq_client", clippy_log=clippy["pq_client"])),
         "FAIL", "P1:"),
        ("mut_pq_bad_probe", "pq-only", opts(PQB, "tls-client", **V(
            "pq_client", clippy_log=clippy["pq_client"], probes=[probes["bad_resume"]])), "FAIL", "P1:"),
        ("mut_pq_clippy_dirty", "pq-only", opts(PQB, "tls-client", **V(
            "pq_client", clippy_log=clippy["bad_client"], probes=[probes["pq_client"]])), "FAIL", "S1:"),
        ("mut_pq_second_suppression", "pq-only", opts(PQB, "tls-client", **V("pq_client", src=[msrc], **pq)),
         "FAIL", "S2:"),
        # --- cross-mode: a PASS in one mode is not a PASS in the other ---
        ("srv_only as pq-only", "pq-only", opts(S, "", **V("srv_only", clippy_log=clippy["srv_only"])),
         "FAIL", "P1:"),
        ("pq_client as compiled-out", "compiled-out", opts(PQB, "tls-client", **V("pq_client", **pq)),
         "FAIL", "M1:"),
        # --- added: map/twin evidence ---
        ("mut_srv_client_map", "compiled-out", opts(S, "", twin=views["srv_only"]["twin"],
                                                    map=views["bad_client"]["map"]), "FAIL", "B2:"),
        ("mut_srv_no_map", "compiled-out", opts(S, "", twin=views["srv_only"]["twin"]), "FAIL", "B2:"),
        ("mut_srv_r0_tampered", "compiled-out", opts(r0b, "", None, "srv_only", TP, "host"), "ERROR", None),
        # --- D13 (RUSTSEC-2026-0382): client-certificate verification on the listener ---
        ("d13_srv_mtls", "compiled-out", opts(os.path.join(P, "srv_mtls"), "", "cmvp-fixtures-mtls",
                                              **V("srv_mtls")), "FAIL", "C2:"),
        ("d13_srv_mtls_justified", "compiled-out", opts(os.path.join(P, "srv_mtls"), "", "cmvp-fixtures-mtls",
                                                        **V("srv_mtls", mtls=jgood)), "PASS", None),
        ("d13_srv_mtls_expired_just", "compiled-out", opts(os.path.join(P, "srv_mtls"), "", "cmvp-fixtures-mtls",
                                                           **V("srv_mtls", mtls=jexp)), "FAIL", "C2:"),
        ("d13_binary_only", "compiled-out", opts(S, "", twin=views["srv_mtls"]["twin"],
                                                 map=views["srv_only"]["map"]), "FAIL", "C2:"),
        ("d13_source_only", "compiled-out", opts(S, "", "cmvp-fixtures-mtls", **V("srv_only")), "FAIL", "C2:"),
    ]
    fails, n = 0, 0
    for name, mode, o, want, pre in cases:
        for m in (["compiled-out", "pq-only"] if mode == "both" else [mode]):
            n += 1
            oo = dict(o, mode=m)
            r = cp.judge(oo)
            why = r.get("reason", [])
            ok = r["verdict"] == want and (pre is None or any(x.startswith(pre) for x in why))
            fails += not ok
            row(f"{name} [{m}]", want + (f" {pre}" if pre else ""), r["verdict"],
                "; ".join(why) or r.get("client_cert_line", ""), ok)
            if name in ("srv_only", "d13_srv_mtls"):
                print("     " + r.get("client_cert_line", ""))
    # --- the entry point with RELATIVE --binary/--manifest/--target-dir (the gate passes target/cmvp/release/aegis):
    # unresolved, the relink's -Map= paths would be written relative to the workspace root rustc runs in -> ERROR
    n += 1
    r = subprocess.run([os.path.join(HERE, "client-policy"), "--mode", "compiled-out", "--binary",
                        os.path.relpath(S, T), "--manifest", os.path.relpath(FIX, T), "--target-dir", "plain",
                        "--relink", "host", "--work", os.path.join("selftest-cp", "relative-work"),
                        "--mtls-justification", os.path.join("selftest-cp", "absent.toml")],
                       cwd=T, capture_output=True, text=True, timeout=1200)
    last = (r.stdout.strip().splitlines() or [""])[-1]
    ok = r.returncode == 0 and last == "CLIENT-POLICY: PASS (compiled-out)"
    fails += not ok
    row("srv_only entry point, relative paths", "PASS (exit 0)", "PASS" if ok else f"rc={r.returncode}", last, ok)
    # --- the docker relink uses build.sh's compile-relevant cargo flags (the R0 ERROR of P6-cmvp-002 was a missing
    # --no-default-features); mutant: the same check against the list minus that flag must report it
    n += 2
    try:
        missing, mut_missing = relink_flag_drift(cp.DOCKER_CARGO_FLAGS), \
            relink_flag_drift([x for x in cp.DOCKER_CARGO_FLAGS if x != "--no-default-features"])
    except (OSError, ValueError) as e:
        missing, mut_missing = [f"cannot read build.sh: {e}"], []
    fails += bool(missing)
    row("relink flags == build.sh flags", "none missing", "n=" + str(len(missing)), str(missing), not missing)
    ok = mut_missing == ["--no-default-features"]
    fails += not ok
    row("mut relink w/o --no-default-features", "drift caught", "n=" + str(len(mut_missing)), str(mut_missing), ok)
    # --- the real cmvp overlay graph (light): M1 baseline and feature mutants, D13 source baseline ---
    try:
        r = subprocess.run([os.path.join(ROOT, "profiles/cmvp/build.sh"), "--metadata"], capture_output=True)
        if r.returncode != 0:
            raise RuntimeError("profiles/cmvp/build.sh --metadata failed")
        src = os.path.join(ROOT, "target", "cmvp-src")
        for feats, want_on in (("aegis-bin/cmvp", []), ("aegis-bin/cmvp,aegis-tls/tls-client", ["aegis-tls/tls-client"]),
                               ("aegis-bin/cmvp,aegis-egress/tls-client", ["aegis-egress/tls-client"]),
                               ("aegis-bin/cmvp,aegis-ops/acme", ["aegis-ops/acme"])):
            n += 1
            g = cp.graph(src, "aegis-bin", feats)
            on = sorted(f"{nm}/{f}" for nm, v, d, fp, fs in g if fp for f in fs if f in cp.CLIENT_FEATURES)
            ok = set(want_on) <= set(on) and (on == [] if not want_on else True) and any(x[0] == "rustls" for x in g)
            fails += not ok
            row(f"real cmvp M1 --features {feats}", "M1 on " + (",".join(want_on) or "none"), "on=" + str(len(on)),
                str(on), ok)
            if not want_on:
                vs = []
                auth = []
                for nm, v, d, fp, fs in g:
                    files = list(cp.rust_files(d))
                    if nm not in cp.VERIFIER_DEFINERS:
                        vs += cp.grep(files, cp.VERIFIER_SRC)
                    if fp:
                        auth += [os.path.relpath(h.split(":")[0], src) + ":" + h.split(":")[1]
                                 for h in cp.grep(files, cp.CLIENT_AUTH_SITE)]
                n += 1
                fails += bool(vs)
                row("real cmvp D13 source baseline", "no verifier construction", "n=" + str(len(vs)),
                    "; ".join(vs[:3]) or "client-auth sites: " + ", ".join(auth), not vs)
    except (RuntimeError, OSError, ValueError) as e:
        fails += 1
        print(f"  real cmvp graph cases: cannot run ({e})  MISMATCH")
    if fails:
        print(f"CLIENT-POLICY SELF-TEST: FAIL ({fails}/{n} mismatches)")
        return 1
    print(f"CLIENT-POLICY SELF-TEST: PASS ({n}/{n}: spike's 12 ported (5 binaries + 7 mutants), cross-mode, "
          f"map/twin/R0 mutants, D13 mTLS mutants, entry point with relative paths, relink flags vs build.sh, real cmvp graph M1 + D13 source "
          f"baseline)")
    return 0
