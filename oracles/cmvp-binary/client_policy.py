#!/usr/bin/env python3
"""cmvp-binary `client-policy`: the cmvp-client-policy gate (P-PQ6; premise of the RUSTSEC-2026-0349 and
RUSTSEC-2026-0382 ledger entries; PLAN-6 D13). Ported from spikes/cmvp-client-policy/fips_client_policy.py.

  client-policy --mode compiled-out|pq-only --binary PATH [options]     judge one shipped (stripped) binary
  client-policy --self-test                                             fixtures + the spike's 12 mutants + D13

Real cmvp run (gates/phase-6.toml): `--binary target/cmvp/release/monban` and no other option. Then:
  manifest = target/cmvp-src (re-prepared by `profiles/cmvp/build.sh --metadata`), package monban-bin, features
  monban-bin/cmvp, relink = docker (the AL2023 image, mounts, env and cargo flags of profiles/cmvp/build.sh --check,
  including --no-default-features). Path arguments are resolved to absolute paths when parsed.

Evidence views
  graph   `cargo tree` (the real feature resolver) for the package set and enabled features; source dirs from
          `cargo metadata`.
  twin    unstripped twin: relink of the final crate only (`cargo rustc ... -- -C strip=none -C link-arg=-Wl,-Map=`),
          read with `nm -C --defined-only`. Not the shipped bytes (spike finding 1): a second, demangled view.
  map     linker map of a relink of the SHIPPED configuration (`cargo rustc ... -- -C link-arg=-Wl,-Map=`). R0: the
          relinked binary must be byte-identical (sha256) to --binary, else the map is not evidence of the shipped
          link -> ERROR. The judged binary is restored afterwards (sha256 re-checked).
  --map/--twin given explicitly skip the relink (and R0, which is then reported as "not checked").

Mode A, compiled-out (PASS line exactly `CLIENT-POLICY: PASS (compiled-out)`, the ledger's evidence_must):
  M0 rustls is in the graph (else nothing to judge -> ERROR)
  M1 no first-party package has a client feature on (tls-client: monban-tls, monban-egress; acme: monban-ops)
  B0 positive control: the twin has rustls::server symbols and the map has rustls::server sections; a missing or
     blind view (stripped, wrong artifact) -> ERROR. Both views are required for a compiled-out PASS.
  B1 0 `rustls::client::` symbols in the twin            B2 0 `6rustls6client` refs in the shipped map
Mode B, pq-only (`CLIENT-POLICY: PASS (pq-only)`):
  S1 clippy log (disallowed-methods/-types config, fixtures/clippy.toml shape) has 0 disallowed hits and no error
  S2 exactly one `#[expect/allow(clippy::disallowed_*)]` in first-party source, directly on --blessed-fn
  M2 no unallowlisted third-party crate in the graph builds a ClientConfig (source grep, backstop)
  P1 >= 1 probe report, each: kx_groups == [secp256r1MLKEM768], resumption NoClientSessionStorage/Disabled, both
     ClientHellos list and share only 0x11EB, negotiated SECP256R1MLKEM768, 2nd hello no PSK/early data, same share
Both modes, D13 (webpki 0.103.13 / RUSTSEC-2026-0382):
  C1 informational line `CLIENT-CERT: ...`: the listener client-auth sites in first-party source
     (with_no_client_auth / with_client_cert_verifier), client-cert verifier construction anywhere in the graph's
     source, and the ClientCertVerifier impls linked (twin symbols, map refs).
  C2 FAIL if a WebPkiClientVerifier (or any ClientCertVerifier other than rustls' NoClientAuth) is constructed in
     source or linked in the binary, unless --mtls-justification (default oracles/cmvp-binary/mtls-justification.toml,
     absent = none) holds a live entry for that verifier citing RUSTSEC-2026-0382.
Last line `CLIENT-POLICY: PASS (<mode>)`, `CLIENT-POLICY: FAIL (...)` or `CLIENT-POLICY: ERROR (...)`.
Exit 0 PASS, 1 FAIL, 2 ERROR. --json prints the full record before the last line.
"""
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CLIENT_SYM = re.compile(r"rustls::client::")
SERVER_SYM = re.compile(r"rustls::server::")
CLIENT_MANGLED = re.compile(r"6rustls6client")
SERVER_MANGLED = re.compile(r"6rustls6server")
CLIENT_CTOR_SRC = re.compile(r"ClientConfig::builder|with_platform_verifier\(|ClientConfig\s*\{")
# D13: client-certificate verifier construction (source) and linked verifier impls (binary).
VERIFIER_SRC = re.compile(r"WebPkiClientVerifier|with_client_cert_verifier|AllowAnyAuthenticatedClient|"
                          r"AllowAnyAnonymousOrAuthenticatedClient|impl\s+(?:[\w:]+::)?ClientCertVerifier\s+for")
WEBPKI_SRC = re.compile(r"WebPkiClientVerifier|AllowAnyAuthenticatedClient|AllowAnyAnonymousOrAuthenticatedClient")
CUSTOM_IMPL_SRC = re.compile(r"impl\s+(?:[\w:]+::)?ClientCertVerifier\s+for")
INSTALL_SRC = re.compile(r"with_client_cert_verifier")
CLIENT_AUTH_SITE = re.compile(r"with_no_client_auth\(|with_client_cert_verifier\(")
VERIFIER_IMPL_SYM = re.compile(r"<([^<>]*?(?:<[^<>]*>)?[^<>]*?) as rustls::[\w:]*ClientCertVerifier>")
WEBPKI_CV = "WebPkiClientVerifier"
CLIENT_FEATURES = {"tls-client", "acme"}
INJECTED_CONFIG_ALLOW = {}  # crate -> reason ("accepts an Arc<ClientConfig> from the caller"); none needed so far
VERIFIER_DEFINERS = {"rustls", "rustls-webpki"}  # define the types; their own source is not "construction"
# The cargo flags of profiles/cmvp/build.sh --check that change what is compiled (it adds -p/--features per package,
# --release for the release profile, and --keep-going, which changes nothing that is built). The self-test checks this
# list against build.sh's `flags=(...)` line.
DOCKER_CARGO_FLAGS = ["--locked", "--release", "--no-default-features"]
PQ = "secp256r1MLKEM768"
TARGET = "x86_64-unknown-linux-gnu"


def arg(name, default=None, multi=False):
    a = sys.argv[1:]
    vals = [a[i + 1] for i, x in enumerate(a) if x == name and i + 1 < len(a)]
    return vals if multi else (vals[-1] if vals else default)


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# ---------------------------------------------------------------- graph
def graph(manifest, package, features, no_default_features=False):
    """[(name, version, src_dir, first_party, features)] for every package in the real (cargo tree) build."""
    sel = (["-p", package] if package else []) + (["--features", features] if features else []) + \
        (["--no-default-features"] if no_default_features else [])
    t = sh(["cargo", "tree", "--locked", "-e", "normal,no-proc-macro", "--target", TARGET, "--prefix", "none",
            "--format", "{p}|{f}", "--manifest-path", f"{manifest}/Cargo.toml"] + sel)
    if t.returncode != 0:
        raise RuntimeError(f"cargo tree failed: {t.stderr.strip()[-400:]}")
    feats = {}
    for line in t.stdout.splitlines():
        if "|" not in line:
            continue
        p, f = line.split("|", 1)
        f = f.replace(" (*)", "").strip()
        parts = p.split()
        if len(parts) < 2:
            continue
        key = (parts[0], parts[1].lstrip("v"))
        feats.setdefault(key, set()).update(x for x in f.split(",") if x)
    m = sh(["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", TARGET,
            "--manifest-path", f"{manifest}/Cargo.toml"])
    if m.returncode != 0:
        raise RuntimeError(f"cargo metadata failed: {m.stderr.strip()[-400:]}")
    out = []
    for p in json.loads(m.stdout)["packages"]:
        k = (p["name"], p["version"])
        if k in feats:
            out.append((p["name"], p["version"], os.path.dirname(p["manifest_path"]), p["source"] is None,
                        sorted(feats[k])))
    return out


def rust_files(d):
    """First-/third-party `src/` files, skipping test-only files and comment lines (documented limit)."""
    base = os.path.join(d, "src")
    for dp, dns, fns in os.walk(base):
        dns[:] = [x for x in dns if x not in ("tests", "target")]
        for fn in fns:
            if fn.endswith(".rs") and fn != "tests.rs" and not fn.endswith("_tests.rs"):
                yield os.path.join(dp, fn)


def grep(paths, rx):
    hits = []
    for p in paths:
        try:
            for i, line in enumerate(open(p, errors="replace"), 1):
                s = line.strip()
                if s.startswith("//"):
                    continue
                if rx.search(line):
                    hits.append(f"{p}:{i}: {s[:120]}")
        except OSError:
            pass
    return hits


# ---------------------------------------------------------------- relink
def relink(kind, manifest, package, bin_name, features, target_dir, extra, image=None):
    """Re-run rustc on the final crate only, with extra rustc args. Returns the path cargo uplifts the bin to."""
    if kind == "host":
        cmd = ["cargo", "rustc", "--release", "--locked", "-q", "--manifest-path", f"{manifest}/Cargo.toml",
               "--bin", bin_name] + (["-p", package] if package else []) + \
              (["--features", features] if features else []) + ["--"] + extra
        # cwd = the manifest dir, as docker's -w /src: cargo finds .cargo/config.toml (the repo's rustflags) from its
        # cwd, so a relink started elsewhere gets other rustflags and is not the shipped binary (R0 ERROR).
        r = sh(cmd, env=dict(os.environ, CARGO_TARGET_DIR=target_dir), cwd=manifest)
    elif kind == "docker":
        # Mirrors profiles/cmvp/build.sh --check (image, mounts, env, --no-default-features); keep in sync. Without
        # --no-default-features cargo passes `--cfg feature="default"` to monban-bin, which changes its -C metadata
        # (symbol hashes) and so .text/.rodata: the relink is then not the shipped binary and R0 is ERROR.
        rustup = os.path.realpath(os.environ.get("RUSTUP_HOME", os.path.expanduser("~/.rustup")))
        go = os.path.realpath(os.environ.get("AEGIS_GO", os.path.expanduser("~/aegis-ci/go1.27.3")))
        chan = re.search(r'channel *= *"(.*)"', open(os.path.join(ROOT, "rust-toolchain.toml")).read()).group(1)
        tc = f"{rustup}/toolchains/{chan}-x86_64-unknown-linux-gnu"
        cf = os.path.join(ROOT, "deploy/build/al2023.Containerfile")
        img = image or "monban-al2023-build:" + sha256(cf)[:12]
        if sh(["docker", "image", "inspect", img]).returncode != 0:
            raise RuntimeError(f"relink: image {img} missing (run profiles/cmvp/build.sh first)")
        # extra args reference host paths under target_dir; rewrite them to the /out mount
        extra = [x.replace(target_dir, "/out") for x in extra]
        cmd = ["docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
               "-v", f"{os.path.realpath(manifest)}:/src:ro", "-v", f"{target_dir}:/out", "-v", f"{tc}:/opt/rust:ro",
               "-v", f"{go}:/opt/go:ro", "-e", "HOME=/out/home", "-e", "CARGO_HOME=/out/cargo-home",
               "-e", "CARGO_TARGET_DIR=/out", "-e", "GOCACHE=/out/gocache", "-e", "GOPATH=/out/gopath",
               "-e", "GOTOOLCHAIN=local", "-e", "GOFLAGS=-mod=mod", "-e", "CARGO_INCREMENTAL=0",
               "-e", f"CARGO_BUILD_JOBS={os.environ.get('CARGO_BUILD_JOBS', '4')}",
               "-e", "PATH=/opt/rust/bin:/opt/go/bin:/usr/bin:/bin", "-w", "/src", img,
               "cargo", "rustc", *DOCKER_CARGO_FLAGS, "-q", "-p", package, "--bin", bin_name,
               "--features", features, "--"] + extra
        r = sh(cmd)
    else:
        raise RuntimeError(f"unknown relink kind {kind}")
    if r.returncode != 0:
        raise RuntimeError(f"relink ({kind}) failed: {r.stderr.strip()[-600:]}")
    return os.path.join(target_dir, "release", bin_name)


def relink_views(kind, manifest, package, bin_name, features, target_dir, binp, work):
    """Produce twin + twin map + shipped map; check R0 (byte-identical relink); restore the judged binary."""
    os.makedirs(work, exist_ok=True)
    saved = os.path.join(work, "judged.saved")
    shutil.copy2(binp, saved)
    sha0 = sha256(saved)
    up = os.path.join(target_dir, "release", bin_name)
    try:
        # A fresh map path per run changes the rustc args, so cargo cannot treat the final crate as fresh and skip
        # the link; the map must then exist, which proves a link happened (else R0 would compare a binary with
        # itself).
        for f in os.listdir(work):
            if f.endswith(".map"):
                os.remove(os.path.join(work, f))
        nonce = f"{os.getpid()}-{time.time_ns()}"
        twin_map = os.path.join(work, f"twin-{nonce}.map")
        ship_map = os.path.join(work, f"shipped-{nonce}.map")
        out = relink(kind, manifest, package, bin_name, features, target_dir,
                     ["-C", "strip=none", "-C", f"link-arg=-Wl,-Map={twin_map}"])
        if not os.path.isfile(twin_map):
            raise RuntimeError("relink (twin) did not link: no map written")
        twin = os.path.join(work, "twin")
        shutil.copy2(out, twin)
        out = relink(kind, manifest, package, bin_name, features, target_dir, ["-C", f"link-arg=-Wl,-Map={ship_map}"])
        if not os.path.isfile(ship_map):
            raise RuntimeError("relink (shipped config) did not link: no map written")
        sha1 = sha256(out)
        relinked = os.path.join(work, "relinked")
        shutil.copy2(out, relinked)
    finally:
        if os.path.exists(up) and os.path.realpath(up) == os.path.realpath(binp) and sha256(up) != sha0:
            shutil.copy2(saved, up)
    restored = sha256(binp) == sha0
    text_same = {}
    for sec in (".text", ".rodata"):
        a, b = os.path.join(work, "sec-twin"), os.path.join(work, "sec-judged")
        if sh(["objcopy", "-O", "binary", f"--only-section={sec}", twin, a]).returncode == 0 and \
                sh(["objcopy", "-O", "binary", f"--only-section={sec}", saved, b]).returncode == 0:
            text_same[sec] = sha256(a) == sha256(b)
    return {"twin_sections_identical": text_same, "twin": twin, "twin_map": twin_map, "map": ship_map, "sha_judged": sha0, "sha_relinked": sha1,
            "R0_identical": sha1 == sha0, "judged_restored": restored}


# ---------------------------------------------------------------- probes / clippy / justification
def probe_violations(p):
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
    return bad


def blessed(s2, fn):
    if s2 is None or len(s2) != 1:
        return False
    path, line = s2[0].split(":")[0], int(s2[0].split(":")[1])
    rest = open(path).read().splitlines()[line:line + 2]
    return any(f"fn {fn}" in x for x in rest)


def justified(path, verifiers, today):
    """Verifiers (names) covered by a live entry of the mTLS justification file."""
    if not path or not os.path.exists(path):
        return set(), "none recorded"
    import tomllib
    try:
        d = tomllib.load(open(path, "rb"))
    except (OSError, ValueError) as e:
        return set(), f"unreadable ({e})"
    ok = set()
    for e in d.get("mtls", []):
        try:
            live = datetime.date.fromisoformat(str(e.get("expires", ""))) >= today
        except ValueError:
            live = False
        if (live and e.get("advisory") == "RUSTSEC-2026-0382" and e.get("reason") and e.get("approver")
                and e.get("verifier") in verifiers):
            ok.add(e["verifier"])
    return ok, f"{path}: {len(d.get('mtls', []))} entries, live+covering {sorted(ok)}"


# ---------------------------------------------------------------- main judgment
def judge(o):
    r = {"mode": o["mode"], "binary": o["binary"], "checks": {}}
    c = r["checks"]

    def err(msg):
        r["verdict"], r["reason"] = "ERROR", [msg]
        return r

    if not os.path.isfile(o["binary"]):
        return err(f"binary not found: {o['binary']}")
    try:
        pkgs = graph(o["manifest"], o["package"], o["features"], o.get("no_default_features", False))
    except RuntimeError as e:
        return err(str(e))
    c["M0_rustls_in_graph"] = any(p[0] == "rustls" for p in pkgs)
    c["M1_client_features_on"] = [f"{n}/{f}" for n, v, d, fp, fs in pkgs if fp for f in fs if f in CLIENT_FEATURES]
    ctor, verif_src, auth_sites = [], [], []
    for name, ver, d, fp, fs in pkgs:
        files = list(rust_files(d))
        if name not in VERIFIER_DEFINERS:
            verif_src += [f"{name}@{ver} {h}" for h in grep(files, VERIFIER_SRC)]
        if fp:
            auth_sites += [os.path.relpath(h.split(":")[0], o["manifest"]) + ":" + h.split(":")[1]
                           for h in grep(files, CLIENT_AUTH_SITE)]
        elif name != "rustls" and grep(files, CLIENT_CTOR_SRC):
            ctor.append(f"{name}@{ver}")
    c["M2_third_party_client_ctors"] = ctor
    c["M2_unallowlisted"] = [x for x in ctor if x.split("@")[0] not in INJECTED_CONFIG_ALLOW]

    # binary views
    twin, mapp = o.get("twin"), o.get("map")
    if o["relink"] != "none" and not (twin or mapp):
        try:
            rv = relink_views(o["relink"], o["manifest"], o["package"], o["bin_name"], o["features"],
                              o["target_dir"], o["binary"], o["work"])
        except (RuntimeError, OSError) as e:
            return err(str(e))
        c["R0"] = {k: rv[k] for k in ("sha_judged", "sha_relinked", "R0_identical", "judged_restored",
                                        "twin_sections_identical")}
        twin, mapp = rv["twin"], rv["map"]
        if not rv["judged_restored"]:
            return err("judged binary changed during relink and could not be restored")
        if not rv["R0_identical"]:
            return err(f"R0: relink of the shipped configuration is not byte-identical to the judged binary "
                       f"({rv['sha_relinked'][:16]} != {rv['sha_judged'][:16]}): its map is not evidence")
    else:
        c["R0"] = "not checked (views given explicitly)"
    symsrc = twin or o["binary"]
    nm = sh(["nm", "-C", "--defined-only", symsrc])
    syms = nm.stdout.splitlines() if nm.returncode == 0 else []
    c["B_symbol_view"] = os.path.basename(symsrc) + (" (twin)" if twin else " (judged binary)")
    c["B_symbols_total"] = len(syms)
    c["B0_server_symbols"] = sum(1 for s in syms if SERVER_SYM.search(s))
    cs = [s.split(" ", 2)[-1] for s in syms if CLIENT_SYM.search(s)]
    c["B1_client_symbols"] = len(cs)
    c["B1_client_symbol_sample"] = sorted(cs)[:8]
    mp = ""
    if mapp:
        try:
            mp = open(mapp, errors="replace").read()
        except OSError as e:
            return err(f"map unreadable: {e}")
        c["B2_map_client_refs"] = len(CLIENT_MANGLED.findall(mp))
        c["B2_map_server_refs"] = len(SERVER_MANGLED.findall(mp))
    impls = sorted({m.group(1).split("::")[-1] for s in syms for m in VERIFIER_IMPL_SYM.finditer(s)})
    c["C1_verifier_impls_linked"] = impls
    c["C1_webpki_cv_symbols"] = sum(1 for s in syms if WEBPKI_CV in s)
    c["C1_webpki_cv_map_refs"] = mp.count(WEBPKI_CV)
    c["C1_verifier_src"] = verif_src
    c["C1_client_auth_sites"] = auth_sites

    # pq-only inputs
    log = None
    if o.get("clippy_log"):
        log = open(o["clippy_log"], errors="replace").read()
        c["S1_clippy_disallowed_hits"] = len(re.findall(r"use of a disallowed (method|type)", log))
        c["S1_clippy_errors"] = len(re.findall(r"(?m)^error", log))
    srcs = o.get("src") or [os.path.join(d, "src") for n, v, d, fp, fs in pkgs if fp]
    ex = []
    for s in srcs:
        ex += sh(["grep", "-rnE", r"(expect|allow)\(clippy::disallowed_(methods|types)", s]).stdout.splitlines()
    c["S2_suppressions"] = ex
    c["P1_probes"] = [{"probe": os.path.basename(p), "violations": probe_violations(p)} for p in o.get("probes", [])]

    # D13 verdict part
    bad_verifiers = set(x for x in impls if x != "NoClientAuth")
    if c["C1_webpki_cv_symbols"] or c["C1_webpki_cv_map_refs"] or any(WEBPKI_SRC.search(x) for x in verif_src):
        bad_verifiers.add(WEBPKI_CV)
    custom = [x for x in verif_src if CUSTOM_IMPL_SRC.search(x)]
    if custom:
        bad_verifiers.add("custom-ClientCertVerifier-impl")
    webpki_src = [x for x in verif_src if WEBPKI_SRC.search(x)]
    if any(INSTALL_SRC.search(x) for x in verif_src) and not webpki_src and not custom:
        bad_verifiers.add("unidentified-verifier")  # installed, but its construction is not visible to the grep
    ok, jinfo = justified(o.get("mtls"), bad_verifiers, o["today"])
    c["C2_unjustified_verifiers"] = sorted(bad_verifiers - ok)
    c["C2_justification"] = jinfo
    r["client_cert_line"] = (
        "CLIENT-CERT: client-auth builder sites in first-party source (server and client builders, cfg-gated code "
        "included): "
        + (", ".join(auth_sites) if auth_sites else "none") + "; verifier construction in graph source: "
        + (str(len(verif_src)) + " " + "; ".join(verif_src[:4]) if verif_src else "none")
        + f"; ClientCertVerifier impls linked: {impls or 'none'}; WebPkiClientVerifier symbols "
        f"{c['C1_webpki_cv_symbols']}, map refs {c['C1_webpki_cv_map_refs']}; mTLS justification: {jinfo}")

    # verdict
    blind = []
    if not c["M0_rustls_in_graph"]:
        blind.append("M0: rustls not in the graph (wrong manifest/package)")
    if c["B_symbols_total"] == 0 and not mapp:
        blind.append("B0: no symbols (stripped) and no map: the scan is blind")
    elif c["B_symbols_total"] and c["B0_server_symbols"] == 0:
        blind.append("B0: no rustls::server symbols (wrong artifact)")
    if mapp and c["B2_map_server_refs"] == 0:
        blind.append("B0: map has no rustls::server refs (wrong or empty map)")
    if blind:
        r["verdict"], r["reason"] = "ERROR", blind
        return r
    why = []
    if o["mode"] == "compiled-out":
        if c["M1_client_features_on"]:
            why.append(f"M1: client features on: {c['M1_client_features_on']}")
        if c["B_symbols_total"] == 0:
            why.append("B1: no unstripped symbol view (twin or unstripped binary) to judge")
        if c["B1_client_symbols"]:
            why.append(f"B1: {c['B1_client_symbols']} rustls::client symbols")
        if not mapp:
            why.append("B2: no linker map of the shipped link")
        elif c["B2_map_client_refs"]:
            why.append(f"B2: {c['B2_map_client_refs']} rustls::client map refs")
    else:
        if log is None or c["S1_clippy_disallowed_hits"] or c["S1_clippy_errors"]:
            why.append("S1: clippy log missing or dirty")
        if not blessed(ex, o["blessed_fn"]):
            why.append(f"S2: suppressions != exactly one on fn {o['blessed_fn']} ({len(ex)})")
        if c["M2_unallowlisted"]:
            why.append(f"M2: third-party ClientConfig builders {c['M2_unallowlisted']}")
        if not c["P1_probes"] or any(p["violations"] for p in c["P1_probes"]):
            why.append("P1: probes missing or violating: "
                       + "; ".join(f"{p['probe']}: {p['violations']}" for p in c["P1_probes"] if p["violations"]))
    if c["C2_unjustified_verifiers"]:
        why.append(f"C2: client-certificate verifier(s) {c['C2_unjustified_verifiers']} reachable in cmvp "
                   f"without a live mTLS justification (RUSTSEC-2026-0382)")
    r["verdict"] = "FAIL" if why else "PASS"
    if why:
        r["reason"] = why
    return r


def options_from_argv():
    real = arg("--manifest") is None
    o = {
        "mode": arg("--mode"),
        "binary": arg("--binary"),
        "manifest": arg("--manifest", os.path.join(ROOT, "target/cmvp-src")),
        "package": arg("--package", "monban-bin" if real else None),
        "bin_name": arg("--bin-name", "monban" if real else None),
        "features": arg("--features", "monban-bin/cmvp" if real else ""),
        "relink": arg("--relink", "docker" if real else "none"),
        "no_default_features": real,  # build.sh builds the cmvp packages with --no-default-features
        "target_dir": arg("--target-dir", os.path.join(os.path.realpath(os.path.join(ROOT, "target")), "cmvp")),
        "map": arg("--map"),
        "twin": arg("--twin"),
        "clippy_log": arg("--clippy-log"),
        "probes": arg("--probe", multi=True),
        "src": arg("--src", multi=True),
        "blessed_fn": arg("--blessed-fn", "pq_only_client_config"),
        "mtls": arg("--mtls-justification", os.path.join(HERE, "mtls-justification.toml")),
        "today": datetime.date.fromisoformat(arg("--today", datetime.date.today().isoformat())),
    }
    # Resolve every path argument now: rustc runs the linker from the workspace root (relative -Map= paths would land
    # there), docker bind mounts need absolute paths, and later checks compare real paths.
    for k in ("binary", "manifest", "target_dir", "map", "twin", "clippy_log", "mtls"):
        if o[k]:
            o[k] = os.path.abspath(o[k])
    o["probes"] = [os.path.abspath(x) for x in o["probes"]]
    o["src"] = [os.path.abspath(x) for x in o["src"]]
    o["work"] = os.path.abspath(arg("--work", os.path.join(o["target_dir"], "oracle-cmvp-binary")))
    if real:
        r = sh([os.path.join(ROOT, "profiles/cmvp/build.sh"), "--metadata"])
        if r.returncode != 0:
            raise RuntimeError(f"profiles/cmvp/build.sh --metadata failed: {r.stderr.strip()[-400:]}")
    if o["relink"] != "none" and not o["bin_name"]:
        o["bin_name"] = os.path.basename(o["binary"])
    return o


def report(r, as_json=False):
    c = r["checks"]
    print(f"graph: rustls in graph {c.get('M0_rustls_in_graph')}; client features on {c.get('M1_client_features_on')}")
    if "R0" in c:
        print(f"R0 relink: {c['R0']}")
    if "B_symbols_total" in c:
        print(f"twin/nm ({c['B_symbol_view']}): {c['B_symbols_total']} symbols, server {c['B0_server_symbols']}, "
              f"client {c['B1_client_symbols']} {c['B1_client_symbol_sample'][:3]}")
    if "B2_map_client_refs" in c:
        print(f"map: client refs {c['B2_map_client_refs']}, server refs {c['B2_map_server_refs']}")
    if r.get("client_cert_line"):
        print(r["client_cert_line"])
    if as_json:
        print(json.dumps(r, indent=1, default=str))
    if r["verdict"] == "PASS":
        print(f"CLIENT-POLICY: PASS ({r['mode']})")
        return 0
    print(f"CLIENT-POLICY: {r['verdict']} ({'; '.join(r.get('reason', []))[:700]})")
    return 1 if r["verdict"] == "FAIL" else 2


def main():
    if "--self-test" in sys.argv:
        sys.path.insert(0, HERE)
        import selftest
        return selftest.client_policy_selftest()
    mode = arg("--mode")
    if mode not in ("compiled-out", "pq-only") or not arg("--binary"):
        print("usage: client-policy --mode compiled-out|pq-only --binary PATH [...] | --self-test", file=sys.stderr)
        print("CLIENT-POLICY: ERROR (usage)")
        return 2
    try:
        o = options_from_argv()
    except (RuntimeError, ValueError) as e:
        print(f"CLIENT-POLICY: ERROR ({e})")
        return 2
    return report(judge(o), "--json" in sys.argv)


if __name__ == "__main__":
    sys.exit(main())
