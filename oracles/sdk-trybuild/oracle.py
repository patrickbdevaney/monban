#!/usr/bin/env python3
"""sdk-trybuild oracle (gate sdk-trybuild, unit P4-oracle-trybuild-001). Invoked by ./run; stdlib only.

  oracle.py check      build the real aegis-sdk, run its doc tests, judge the corpus against expected.txt
  oracle.py self-test  judge the corpus and the SDK's compile_fail doc tests against mutated SDK copies; every
                       mutant must turn the verdict red
  oracle.py bless      check, then rewrite snapshots.txt from the observed rejection codes (review the diff)

trybuild-equivalent, without the trybuild crate: every case is compiled by the pinned rustc itself (metadata only),
then by clippy-driver with the workspace lints and the ban list (clippy.toml), then scanned for the host seam. The
rejection codes are compared with snapshots.txt the way trybuild compares .stderr files. Compiled B2 cases run
through a harness built on the SDK's own host loop (`aegis_sdk::host`) over a recording backend.
"""
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import corpus  # noqa: E402  (own directory, inserted explicitly because python3 -I drops it)

TARGET = os.environ.get("SDK_TRYBUILD_TARGET", os.path.join(HERE, "target"))
JOBS = max(1, int(os.environ.get("CARGO_BUILD_JOBS", "4")))
SDK_SRC = os.path.join(REPO, "sdk", "aegis-sdk", "src")
WORKSPACE_CLIPPY = ["unwrap_used", "expect_used", "panic", "todo", "unimplemented", "indexing_slicing", "dbg_macro"]
BAN_CLIPPY = ["disallowed_methods", "disallowed_types", "mem_forget"]
OWNER_RE = re.compile(r'\bhost::|aegis_sdk::host|feature\s*=\s*"host"')
EXTERN_NAMES = ("aegis_sdk", "aegis_types", "aegis_data_ir", "aegis_authz")


def log(msg):
    print(msg, flush=True)


def run(cmd, env=None, cwd=REPO, timeout=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    return subprocess.run(cmd, cwd=cwd, env=e, capture_output=True, text=True, timeout=timeout)


# ---------------------------------------------------------------------------------------------------------------- build
def cargo_build(features):
    """Build aegis-sdk with `features` in the main workspace (locked); return its lib artifacts and native paths."""
    base = ["cargo", "build", "--manifest-path", os.path.join(REPO, "Cargo.toml"), "-p", "aegis-sdk",
            "--features", features, "--locked", "--message-format=json-render-diagnostics"]
    env = {"CARGO_TARGET_DIR": TARGET}
    r = run(base + ["--offline"], env)
    if r.returncode != 0 and ("offline" in r.stderr or "download" in r.stderr):
        r = run(base, env)
    if r.returncode != 0:
        raise RuntimeError(f"cargo build ({features}) failed:\n{r.stderr[-4000:]}")
    libs, native = {}, set()
    for line in r.stdout.splitlines():
        try:
            m = json.loads(line)
        except ValueError:
            continue
        if m.get("reason") == "compiler-artifact" and "lib" in m["target"]["kind"]:
            rl = [f for f in m["filenames"] if f.endswith(".rlib")]
            if rl:
                libs[m["target"]["name"]] = rl[0]
        elif m.get("reason") == "build-script-executed":
            native.update(m.get("linked_paths", []))
    for n in ("aegis_sdk", "aegis_types", "aegis_data_ir"):
        if n not in libs:
            raise RuntimeError(f"cargo build ({features}): no rlib for {n}")
    return {"libs": libs, "deps": [os.path.dirname(libs["aegis_types"])], "native": sorted(native)}


def dep_args(build):
    return [a for d in build["deps"] for a in ("-L", f"dependency={d}")]


def rustc_lib(name, src, externs, build, out_dir, cfgs=()):
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, f"lib{name}.rlib")
    cmd = ["rustc", "--edition", "2024", "--crate-name", name, "--crate-type", "rlib", "-C", "panic=abort",
           "-C", f"metadata=sdktrybuild-{os.path.basename(out_dir)}", "--cap-lints", "allow", "-o", out, src]
    cmd += dep_args(build) + ["-L", f"dependency={out_dir}"]
    for c in cfgs:
        cmd += ["--cfg", c]
    for n in externs:
        cmd += ["--extern", f"{n}={build['libs'][n]}"]
    r = run(cmd)
    if r.returncode != 0:
        raise RuntimeError(f"rustc {name} ({src}) failed:\n{r.stderr[-3000:]}")
    return out


def harness_build(build_a, sdk_src, out_dir):
    """The runtime harness needs `Principal` minting (aegis-types feature authn-path), which the corpus build must
    not have. One cargo target dir cannot hold both (a dependency feature change reuses artifact file names), so the
    three first-party crates are recompiled here by rustc against build A's third-party rlibs."""
    b = {"libs": dict(build_a["libs"]), "deps": build_a["deps"] + [out_dir], "native": build_a["native"]}
    b["libs"]["aegis_types"] = rustc_lib("aegis_types", os.path.join(REPO, "crates", "aegis-types", "src", "lib.rs"),
                                         [], b, out_dir, cfgs=['feature="authn-path"'])
    b["libs"]["aegis_data_ir"] = rustc_lib("aegis_data_ir", os.path.join(REPO, "crates", "aegis-data-ir", "src", "lib.rs"),
                                           ["aegis_types", "aws_lc_rs"], b, out_dir)
    b["libs"]["aegis_sdk"] = rustc_lib("aegis_sdk", os.path.join(sdk_src, "lib.rs"),
                                       ["aegis_types", "aegis_data_ir"], b, out_dir, cfgs=['feature="host"'])
    b["libs"].pop("aegis_authz", None)
    return b


def rustc_sdk(src_dir, build, out_dir):
    """Compile an (optionally mutated) copy of the SDK sources with feature host against `build`'s dependencies."""
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "libaegis_sdk.rlib")
    cmd = ["rustc", "--edition", "2024", "--crate-name", "aegis_sdk", "--crate-type", "rlib", "--cfg", 'feature="host"',
           "-C", "panic=abort", "-C", "metadata=sdktrybuildmut", "--cap-lints", "allow",
           "-o", out, os.path.join(src_dir, "lib.rs")] + dep_args(build)
    for n in ("aegis_types", "aegis_data_ir", "aegis_authz"):
        if n in build["libs"]:
            cmd += ["--extern", f"{n}={build['libs'][n]}"]
    r = run(cmd)
    if r.returncode != 0:
        raise RuntimeError(f"rustc of SDK copy {src_dir} failed:\n{r.stderr[-3000:]}")
    b = dict(build)
    b["libs"] = dict(build["libs"], aegis_sdk=out)
    return b


def toolchain():
    v = run(["rustc", "--version"]).stdout.strip()
    sysroot = run(["rustc", "--print", "sysroot"]).stdout.strip()
    return v, os.path.join(sysroot, "bin", "clippy-driver")


# -------------------------------------------------------------------------------------------------------------- compile
def tags_of(stderr):
    tags = set()
    for line in stderr.splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if d.get("$message_type") != "diagnostic" or d.get("level") != "error":
            continue
        code = (d.get("code") or {}).get("code")
        msg = d.get("message", "")
        if code and re.fullmatch(r"E\d{4}", code):
            tags.add(code)
        elif code:
            tags.add("lint:" + code)
        elif msg.startswith("lifetime may not live long enough"):
            tags.add("LT")
        elif msg.startswith("aborting due to"):
            continue
        else:
            tags.add("msg:" + re.sub(r"\s+", "_", msg)[:48])
    return tags


def compile_case(tool, path, build, out_dir, extra=(), env=None, crate_type="lib"):
    name = "case_" + re.sub(r"\W", "_", os.path.basename(path)[:-3]).lower()
    cmd = [tool, "--edition", "2024", "--crate-type", crate_type, "--crate-name", name, "--emit=metadata",
           "-C", "panic=abort", "--error-format=json", "-A", "unused", "-A", "dead_code",
           "-A", "missing_debug_implementations", "--out-dir", out_dir] + dep_args(build) + list(extra)
    for n in EXTERN_NAMES:
        if n in build["libs"]:
            cmd += ["--extern", f"{n}={build['libs'][n]}"]
    r = run(cmd + [path], env=env, timeout=300)
    if r.returncode == 0:
        return set()
    t = tags_of(r.stderr)
    if os.environ.get("SDK_TRYBUILD_DEBUG"):
        firsts = [json.loads(x).get("rendered") or "" for x in r.stderr.splitlines() if x.startswith("{")]
        log(f"    [{os.path.basename(path)} {os.path.basename(tool)}] " + " || ".join(firsts[:3])[:400])
    return t or {"msg:unparsed_failure"}


def judge_case(case, build, clippy, work):
    """Returns (stage, tags): stage in rustc|lint|owner|compiled."""
    cid, _group, _cls, src, _why, _must = case
    path = os.path.join(work, f"{cid}.rs")
    with open(path, "w") as fh:
        fh.write(src)
    od = os.path.join(work, "out", cid)
    os.makedirs(od, exist_ok=True)
    t = compile_case("rustc", path, build, od)
    if t:
        return "rustc", t
    lint = ["-F", "unsafe_code", "-D", "unused_must_use"]
    for c in WORKSPACE_CLIPPY + BAN_CLIPPY:
        lint += ["-D", f"clippy::{c}"]
    t = compile_case(clippy, path, build, od, extra=lint, env={"CLIPPY_CONF_DIR": HERE})
    if t:
        return "lint", t
    if OWNER_RE.search(src):
        return "owner", {"owner:host"}
    return "compiled", set()


# -------------------------------------------------------------------------------------------------------------- harness
HARNESS_HEAD = r'''#![allow(unused, dead_code, unused_imports, non_snake_case)]
use aegis_data_ir::{Op, OpKind, Pred, Value};
use aegis_sdk::host::{self, Backend, Request, Session};
use aegis_sdk::{ScopedHandler, SdkError};
use aegis_types::{authn_path, Principal, RouteId, TenantId};
use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;

#[derive(Default)]
struct Rec { ops: RefCell<Vec<Op>>, open: Cell<bool> }
impl Backend for Rec {
    type Rows = ();
    fn begin(&self) -> Result<(), SdkError> { self.open.set(true); Ok(()) }
    fn run(&self, op: Op) -> Result<(), SdkError> { self.ops.borrow_mut().push(op); Ok(()) }
    fn commit(&self) -> Result<(), SdkError> { self.open.set(false); Ok(()) }
    fn rollback(&self) { self.open.set(false); }
}
struct Sess(u8);
impl Session for Sess {
    fn permits(&self, k: u8) -> bool { self.0 & k != 0 }
    fn live(&self) -> bool { true }
}
fn has_eq(p: &Pred, f: u32, v: &Value) -> bool {
    match p {
        Pred::Eq(g, w) => *g == f && w == v,
        Pred::And(a, b) => has_eq(a, f, v) || has_eq(b, f, v),
        _ => false,
    }
}
/// Drives one handler through the SDK host loop under route endowment `mask`; returns (ops seen, ok, jobs, tx left open).
fn drive<H: ScopedHandler>(h: &H, mask: u8, p: &Principal) -> (Vec<Op>, bool, usize, bool) {
    let rec = Rec::default();
    let sess = Sess(mask);
    let Ok(route) = RouteId::new(1) else { return (Vec::new(), false, 0, false) };
    let (ok, jobs) = {
        let req = Request { principal: p, route, backend: &rec, session: &sess };
        let d = host::drive(h, &req);
        (d.result.is_ok(), d.jobs.len())
    };
    let open = rec.open.get();
    (rec.ops.into_inner(), ok, jobs, open)
}
macro_rules! scenarios {
    ($name:literal, $m:ident) => {{
        let (Ok(me), Ok(_other)) = (TenantId::new(0xA), TenantId::new(0xB)) else { println!("HARNESS-ERROR tenant"); return };
        let Ok(p) = authn_path::mint(me, Some(b"alice")) else { println!("HARNESS-ERROR mint"); return };
        let raw = $m::Raw { param: String::from("a<b>"), path_tenant: 0xB, header_tenant: Some(0xB) };
        let mine = $m::owner(&p);
        let mut v: BTreeSet<&str> = BTreeSet::new();
        let mut f: Vec<&str> = Vec::new();
        let tenant_ok = |ops: &[Op]| ops.iter().all(|o| o.tenant == me);
        // list (route endowment: select only)
        let (ops, ok, _, open) = drive(&$m::ListNotes { raw: raw.clone() }, $m::SELECT, &p);
        if !tenant_ok(&ops) { v.insert("tenant"); }
        if ops.iter().any(|o| o.kind != OpKind::Select) { v.insert("write-on-read"); }
        if ops.iter().any(|o| o.kind == OpKind::Select && !has_eq(&o.filter, $m::ARCHIVED, &Value::Int(0))) { v.insert("archived"); }
        if open { v.insert("open-tx"); }
        if ok && ops.len() == 1 { f.push("list"); }
        // create (insert)
        let (ops, ok, jobs, open) = drive(&$m::CreateNote { raw: raw.clone() }, $m::INSERT, &p);
        if !tenant_ok(&ops) { v.insert("tenant"); }
        if ops.iter().any(|o| o.writes.iter().any(|(c, x)| *c == $m::OWNER && *x != mine)) { v.insert("owner-forged"); }
        if open { v.insert("open-tx"); }
        if ok && ops.len() == 1 && jobs == 1 { f.push("create"); }
        // touch (insert), and touch under a read endowment
        let (ops, ok, _, _) = drive(&$m::TouchNote, $m::INSERT, &p);
        if !tenant_ok(&ops) { v.insert("tenant"); }
        if ok && ops.len() == 1 { f.push("touch"); }
        let (ops, ok, _, _) = drive(&$m::TouchNote, $m::SELECT, &p);
        if ops.iter().any(|o| o.kind != OpKind::Select) { v.insert("write-on-read"); }
        if !ok && ops.is_empty() { f.push("touch-denied-on-read"); }
        // delete (delete)
        let (ops, ok, _, open) = drive(&$m::DeleteNote { id: 5 }, $m::DELETE, &p);
        if !tenant_ok(&ops) { v.insert("tenant"); }
        if ops.iter().any(|o| o.kind == OpKind::Delete && !has_eq(&o.filter, $m::OWNER, &mine)) { v.insert("owner"); }
        if open { v.insert("open-tx"); }
        if ok && ops.len() == 1 { f.push("delete"); }
        let vs: Vec<&str> = v.into_iter().collect();
        println!("CASE {} violations={} functional={}", $name,
                 if vs.is_empty() { String::from("-") } else { vs.join(",") }, f.join(","));
    }};
}
'''


def run_harness(ids_srcs, build, work):
    """Compile all compiled B2 cases into one harness binary over the SDK host loop; return {id: (violations, functional)}."""
    if not ids_srcs:
        return {}
    parts = [HARNESS_HEAD]
    for cid, src in ids_srcs:
        parts.append(f"mod m_{cid} {{\n{src}\n}}\n")
    parts.append("fn main() {\n")
    for cid, _ in ids_srcs:
        parts.append(f'    scenarios!("{cid}", m_{cid});\n')
    parts.append("}\n")
    path = os.path.join(work, "harness.rs")
    with open(path, "w") as fh:
        fh.write("".join(parts))
    exe = os.path.join(work, "harness")
    cmd = ["rustc", "--edition", "2024", "--crate-type", "bin", "--crate-name", "sdk_trybuild_harness",
           "-C", "panic=abort", "-A", "warnings", "-o", exe] + dep_args(build)
    for npath in build["native"]:
        cmd += ["-L", npath]
    for n in ("aegis_sdk", "aegis_types", "aegis_data_ir"):
        cmd += ["--extern", f"{n}={build['libs'][n]}"]
    r = run(cmd + [path], timeout=600)
    if r.returncode != 0:
        raise RuntimeError(f"harness build failed:\n{r.stderr[-4000:]}")
    r = run([exe], timeout=120)
    out = {}
    for line in r.stdout.splitlines():
        m = re.fullmatch(r"CASE (\S+) violations=(\S+) functional=(\S*)", line.strip())
        if m:
            out[m.group(1)] = (set() if m.group(2) == "-" else set(m.group(2).split(",")),
                               set(filter(None, m.group(3).split(","))))
    if r.returncode != 0 or "HARNESS-ERROR" in r.stdout or len(out) != len(ids_srcs):
        raise RuntimeError(f"harness run failed (rc {r.returncode}):\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}")
    return out


BASE_FUNCTIONAL = {"list", "create", "touch", "touch-denied-on-read", "delete"}


# ------------------------------------------------------------------------------------------------------------ doc tests
def doc_compile_fail_blocks(lib_rs):
    """The ```compile_fail[,Exxxx] blocks of the crate docs, as rustdoc sees them."""
    blocks, cur, code = [], None, None
    with open(lib_rs) as fh:
        for line in fh:
            if not line.startswith("//!"):
                continue
            body = line[3:].rstrip("\n")
            body = body[1:] if body.startswith(" ") else body
            if cur is None:
                m = re.fullmatch(r"```compile_fail(?:,(E\d{4}))?", body.strip())
                if m:
                    cur, code = [], m.group(1)
            elif body.strip() == "```":
                blocks.append((code, "\n".join(cur)))
                cur = None
            else:
                cur.append(body)
    return blocks


def doc_check(lib_rs, build, work):
    """Replicates rustdoc's compile_fail semantics for the SDK docs (used on mutated copies, where cargo cannot
    run). Returns a list of failure strings (empty = every block fails to compile with its declared code)."""
    fails = []
    blocks = doc_compile_fail_blocks(lib_rs)
    if not blocks:
        return ["no compile_fail doc blocks found"]
    for i, (code, body) in enumerate(blocks):
        path = os.path.join(work, f"doc_{i}.rs")
        with open(path, "w") as fh:
            fh.write("fn main() {\n" + body + "\n}\n")
        od = os.path.join(work, "out", f"doc_{i}")
        os.makedirs(od, exist_ok=True)
        t = compile_case("rustc", path, build, od)
        if not t:
            fails.append(f"doc block {i} ({code or 'any'}) compiled")
        elif code and code not in t:
            fails.append(f"doc block {i} expected {code}, got {','.join(sorted(t))}")
    return fails


# -------------------------------------------------------------------------------------------------------------- verdict
def read_expected():
    exp = {"probe": {}}
    with open(os.path.join(HERE, "expected.txt")) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            k, _, rest = line.partition(" ")
            if k == "probe":
                pid, cat = rest.split()
                exp["probe"][pid] = cat
            elif k == "rustc":
                exp["rustc"] = rest
            elif k == "threshold":
                exp["threshold"] = int(rest)
            else:
                exp[k] = rest.split()
    return exp


def read_snapshots():
    snaps = {}
    p = os.path.join(HERE, "snapshots.txt")
    if os.path.exists(p):
        with open(p) as fh:
            for line in fh:
                if line.strip() and not line.startswith("#"):
                    cid, stage, tags = line.split()
                    snaps[cid] = (stage, set(tags.split(",")))
    return snaps


def evaluate(build_a, build_b, work, clippy, quiet=False):
    """Judge every case. Returns (results, problems) where results[id] = dict(stage, tags, cat, viol, func)."""
    cases = corpus.cases()
    os.makedirs(work, exist_ok=True)
    results = {}
    with concurrent.futures.ThreadPoolExecutor(JOBS) as ex:
        futs = {ex.submit(judge_case, c, build_a, clippy, work): c for c in cases}
        for fu in concurrent.futures.as_completed(futs):
            c = futs[fu]
            stage, tags = fu.result()
            results[c[0]] = dict(stage=stage, tags=tags, group=c[1], cls=c[2], why=c[4], must=c[5], src=c[3],
                                 viol=set(), func=set())
    rt = [(cid, r["src"]) for cid, r in results.items()
          if r["stage"] == "compiled" and r["group"] in ("b2", "control") and "pub struct ListNotes" in r["src"]]
    for cid, (viol, func) in run_harness(rt, build_b, work).items():
        results[cid]["viol"], results[cid]["func"] = viol, func
    for cid, r in results.items():
        if r["stage"] != "compiled":
            r["cat"] = "caught"
        elif cid in dict(rt) and not r["viol"]:
            r["cat"] = "neutralized"
        else:
            r["cat"] = "residual"
    return results


def verdict(results, exp, snaps, rustc_v, check_snapshots=True):
    problems = []
    if exp.get("rustc") != rustc_v:
        problems.append(f"rustc pin: expected '{exp.get('rustc')}', have '{rustc_v}' (snapshots are rustc-specific)")
    order = [c[0] for c in corpus.cases()]
    if set(exp["b2"]) != {i for i in order if results[i]["group"] == "b2"} or len(exp["b2"]) != 32:
        problems.append("corpus B2 ids differ from expected.txt")
    if set(exp["f7b"]) != {i for i in order if results[i]["group"] == "f7b"}:
        problems.append("corpus F7b ids differ from expected.txt")
    caught = [i for i in exp["b2"] if results[i]["cat"] == "caught"]
    residual = {i for i in exp["b2"] if results[i]["cat"] == "residual"}
    neutral = {i for i in exp["b2"] if results[i]["cat"] == "neutralized"}
    if len(caught) < exp["threshold"]:
        problems.append(f"B2 caught {len(caught)}/32 < {exp['threshold']}")
    if residual != set(exp["residual"]):
        problems.append(f"residual {sorted(residual)} != frozen {exp['residual']}")
    if neutral != set(exp["neutralized"]):
        problems.append(f"neutralized {sorted(neutral)} != frozen {exp['neutralized']}")
    f7b_missed = [i for i in exp["f7b"] if results[i]["cat"] != "caught"]
    if f7b_missed:
        problems.append(f"F7b accepted: {f7b_missed}")
    for i in exp["controls"]:
        r = results[i]
        if r["stage"] != "compiled":
            problems.append(f"control {i} rejected at {r['stage']}: {','.join(sorted(r['tags']))}")
        elif r["viol"]:
            problems.append(f"control {i} runtime violations {sorted(r['viol'])}")
    if results["BASE"]["func"] != BASE_FUNCTIONAL:
        problems.append(f"BASE functional {sorted(results['BASE']['func'])} != {sorted(BASE_FUNCTIONAL)}")
    for pid, cat in exp["probe"].items():
        if results[pid]["cat"] != cat:
            problems.append(f"probe {pid}: {results[pid]['cat']} != frozen {cat}")
    for cid, r in results.items():
        if r["stage"] == "compiled":
            continue
        if r["must"] and not (r["tags"] & set(r["must"])):
            problems.append(f"{cid} rejected for an unintended reason: {','.join(sorted(r['tags']))} "
                            f"(intended one of {','.join(r['must'])})")
        if check_snapshots:
            s = snaps.get(cid)
            if s is None:
                problems.append(f"{cid} has no snapshot")
            elif s != (r["stage"], r["tags"]):
                problems.append(f"{cid} snapshot mismatch: {s[0]} {','.join(sorted(s[1]))} -> "
                                f"{r['stage']} {','.join(sorted(r['tags']))}")
    if check_snapshots:
        stale = [c for c in snaps if c not in results or results[c]["stage"] == "compiled"]
        if stale:
            problems.append(f"snapshots for cases that now compile or no longer exist: {stale}")
    return problems, caught, residual, neutral


def table(results):
    order = [c[0] for c in corpus.cases()]
    for cid in order:
        r = results[cid]
        tag = ",".join(sorted(r["tags"])) if r["tags"] else "-"
        extra = ""
        if r["viol"] or r["func"]:
            extra = f" viol={','.join(sorted(r['viol'])) or '-'}"
        log(f"  {r['group']:7} {cid:9} {r['cat']:11} {r['stage']:8} {tag}{extra}  | {r['why'][:90]}")


def write_snapshots(results):
    lines = ["# sdk-trybuild rejection snapshots (stage + rustc/clippy codes), rustc-specific. Written by",
             "# `oracle.py bless` after review; the gate compares exactly (like trybuild .stderr files)."]
    for c in corpus.cases():
        r = results[c[0]]
        if r["stage"] != "compiled":
            lines.append(f"{c[0]} {r['stage']} {','.join(sorted(r['tags']))}")
    with open(os.path.join(HERE, "snapshots.txt"), "w") as fh:
        fh.write("\n".join(lines) + "\n")
    for ln in lines:  # also on stdout, for blessing on a remote build box (ci/remote.sh returns only output)
        log("SNAP " + ln)


# ---------------------------------------------------------------------------------------------------------------- modes
def cmd_check(bless=False):
    rustc_v, clippy = toolchain()
    log(f"toolchain: {rustc_v}; clippy-driver {clippy}")
    exp = read_expected()
    build_a = cargo_build("host")
    build_b = harness_build(build_a, SDK_SRC, os.path.join(TARGET, "sdk-trybuild", "harness-real"))
    log("doc tests: cargo test --doc -p aegis-sdk")
    base = ["cargo", "test", "--manifest-path", os.path.join(REPO, "Cargo.toml"), "--doc", "-p", "aegis-sdk", "--locked"]
    # Own target dir: the doc-test build reuses the dev artifact names with panic=unwind and would overwrite the
    # panic=abort rlibs the corpus links against.
    denv = {"CARGO_TARGET_DIR": os.path.join(TARGET, "doc")}
    r = run(base + ["--offline"], denv)
    if r.returncode != 0 and ("offline" in r.stderr or "download" in r.stderr):
        r = run(base, denv)
    doc_lines = [ln for ln in (r.stdout + r.stderr).splitlines() if ln.startswith("test result")]
    log("  " + (doc_lines[-1] if doc_lines else "(no test result line)"))
    work = os.path.join(TARGET, "sdk-trybuild", "real")
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    problems = []
    if r.returncode != 0:
        problems.append("cargo test --doc -p aegis-sdk failed:\n" + r.stdout[-2000:] + r.stderr[-2000:])
    dfail = doc_check(os.path.join(SDK_SRC, "lib.rs"), build_a, work)
    nblocks = len(doc_compile_fail_blocks(os.path.join(SDK_SRC, "lib.rs")))
    log(f"  compile_fail replication on the real SDK: {nblocks - len(dfail)}/{nblocks} as declared")
    problems += [f"doc replication: {d}" for d in dfail]
    results = evaluate(build_a, build_b, work, clippy)
    table(results)
    if bless:
        write_snapshots(results)
        log("snapshots.txt rewritten")
    p2, caught, residual, neutral = verdict(results, exp, read_snapshots(), rustc_v)
    problems += p2
    tiers = {}
    for i in exp["b2"]:
        if results[i]["cat"] == "caught":
            k = "absent" if results[i]["why"].startswith("absent") else results[i]["stage"]
            tiers[k] = tiers.get(k, 0) + 1
    f7b_c = sum(1 for i in exp["f7b"] if results[i]["cat"] == "caught")
    ctl = sum(1 for i in exp["controls"] if results[i]["stage"] == "compiled" and not results[i]["viol"])
    for p in problems:
        log("PROBLEM: " + p)
    summary = (f"B2 caught {len(caught)}/32 (rustc type {tiers.get('rustc', 0)}, dependency/API absent "
               f"{tiers.get('absent', 0)}, lint {tiers.get('lint', 0) + tiers.get('owner', 0)}), neutralized "
               f"{','.join(sorted(neutral)) or '-'}, residual {','.join(sorted(residual)) or '-'}; F7b {f7b_c}/"
               f"{len(exp['f7b'])}; controls {ctl}/{len(exp['controls'])}; doc tests "
               f"{'ok' if r.returncode == 0 else 'FAIL'}")
    if problems:
        log(f"SDK-TRYBUILD: FAIL ({len(problems)} problems; {summary})")
        return 1
    log(f"SDK-TRYBUILD: PASS ({summary})")
    return 0


SDK_MUTANTS = [
    ("ctx-clone", "Ctx: Clone", "surface.rs", "#[derive(Debug)]\npub struct Ctx<'r> {", "#[derive(Debug, Clone)]\npub struct Ctx<'r> {"),
    ("granted-pub", "Granted fields pub", "surface.rs",
     "pub struct Granted<'r, C> {\n    _c: PhantomData<C>,\n    _r: PhantomData<&'r ()>,",
     "pub struct Granted<'r, C> {\n    pub _c: PhantomData<C>,\n    pub _r: PhantomData<&'r ()>,"),
    ("detach-open", "JobQueue::detach does not require Tx<Committed>", "streaming.rs+host.rs",
     ("fn detach<J: Job>(&self, after: &Tx<'r, Committed>, job: J)", "fn detach<J: Job>(&self, _after: &Tx<'r, Committed>, job: J)"),
     ("fn detach<J: Job, S>(&self, after: &Tx<'r, S>, job: J)", "fn detach<J: Job, S>(&self, _after: &Tx<'r, S>, job: J)")),
    ("ctx-constructible", "Ctx constructible (pub mint, pub Grants)", "surface.rs",
     ("    pub(crate) fn mint(principal: &'r Principal, route: RouteId, grants: &'r dyn Grants) -> Self {",
      "pub(crate) trait Grants: core::fmt::Debug {"),
     ("    pub fn mint(principal: &'r Principal, route: RouteId, grants: &'r dyn Grants) -> Self {",
      "pub trait Grants: core::fmt::Debug {")),
    ("tenant-unbound", "host does not overwrite Op::tenant", "host.rs", "        op.tenant = self.tenant;\n", ""),
    ("grant-unchecked", "Ctx::grant ignores the live session", "surface.rs",
     "if self.grants.permits(K) { Ok(Granted::mint()) }", "if true || self.grants.permits(K) { Ok(Granted::mint()) }"),
]


def mutate_sdk(mid, work):
    d = os.path.join(work, "src")
    shutil.rmtree(d, ignore_errors=True)
    shutil.copytree(SDK_SRC, d)
    _, _, files, old, new = next(m for m in SDK_MUTANTS if m[0] == mid)
    if isinstance(old, str):
        old, new = (old,), (new,)
    flist = files.split("+")
    for o, n in zip(old, new):
        hits = [f for f in flist if o in open(os.path.join(d, f)).read()]
        if len(hits) != 1:
            raise RuntimeError(f"SDK mutant {mid}: anchor found in {hits}: {o[:50]!r}")
        p = os.path.join(d, hits[0])
        s = open(p).read()
        if s.count(o) != 1:
            raise RuntimeError(f"SDK mutant {mid}: anchor not unique in {hits[0]}")
        with open(p, "w") as fh:
            fh.write(s.replace(o, n, 1))
    return d


def cmd_self_test():
    rustc_v, clippy = toolchain()
    exp = read_expected()
    snaps = read_snapshots()
    build_a = cargo_build("host")
    detected, missed = [], []
    for mid, desc, *_ in SDK_MUTANTS:
        work = os.path.join(TARGET, "sdk-trybuild", "mut-" + mid)
        shutil.rmtree(work, ignore_errors=True)
        os.makedirs(work)
        src = mutate_sdk(mid, work)
        reasons = []
        try:
            ma = rustc_sdk(src, build_a, os.path.join(work, "rlib-a"))
            mb = harness_build(build_a, src, os.path.join(work, "rlib-b"))
        except RuntimeError as err:
            reasons.append(f"mutated SDK does not build ({str(err).splitlines()[0]})")
            ma = mb = None
        if ma:
            reasons += [f"doc: {d}" for d in doc_check(os.path.join(src, "lib.rs"), ma, work)]
            try:
                results = evaluate(ma, mb, work, clippy, quiet=True)
                p, caught, residual, neutral = verdict(results, exp, snaps, rustc_v)
                reasons += p
            except RuntimeError as err:
                reasons.append(f"corpus run broke: {str(err).splitlines()[0]}")
        if reasons:
            detected.append(mid)
            log(f"  [{mid}] {desc}: RED ({len(reasons)}): " + " | ".join(r.splitlines()[0] for r in reasons[:4]))
        else:
            missed.append(mid)
            log(f"  [{mid}] {desc}: still green (NOT detected)")
    if missed:
        log(f"SDK-TRYBUILD SELF-TEST: FAIL (undetected SDK mutants: {','.join(missed)})")
        return 1
    log(f"SDK-TRYBUILD SELF-TEST: PASS ({len(detected)}/{len(SDK_MUTANTS)} SDK mutants turn the gate red)")
    return 0


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "check"
    try:
        if mode == "check":
            return cmd_check()
        if mode == "bless":
            return cmd_check(bless=True)
        if mode == "self-test":
            return cmd_self_test()
    except (RuntimeError, OSError, subprocess.SubprocessError) as err:
        tag = "SDK-TRYBUILD SELF-TEST" if mode == "self-test" else "SDK-TRYBUILD"
        log(str(err))
        log(f"{tag}: FAIL (infrastructure: {str(err).splitlines()[0][:120]})")
        return 1
    log(f"usage: oracle.py check|bless|self-test (got {mode})")
    return 2


if __name__ == "__main__":
    sys.exit(main())
