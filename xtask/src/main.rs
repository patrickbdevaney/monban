//! Repository gates. Each command prints `<NAME>: PASS|FAIL` and exits non-zero on failure.
//! Every gate has a `--self-test` negative control that must report a violation on a mutated input.
//!
//!   cargo xtask layering [--self-test]
//!   cargo xtask lock-targets [--self-test]
//!   cargo xtask lock-age [--min-days N] [--self-test]
//!   cargo xtask repo-advisories [--self-test]
//!   cargo xtask fips-lock --profile cmvp|floor [--self-test]
//!   cargo xtask ledger-check [--ledger PATH] [--evidence-dir DIR] [--self-test]
//!   cargo xtask metrics-check [--self-test]
//!   cargo xtask budget [--self-test]
//!   cargo xtask unsafe-sites [--self-test]
//!   cargo xtask allowlist-lock [--check] [--self-test]   (fail-closed stub until P4-datair-001)
#![forbid(unsafe_code)]

mod allowlist;
mod budget;
mod json;
mod ledger;
mod lock;
mod metrics;

use json::Json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

fn root() -> PathBuf {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.parent().map(Path::to_path_buf).unwrap_or(here)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |f: &str| args.iter().any(|a| a == f);
    let opt = |f: &str| args.iter().position(|a| a == f).and_then(|i| args.get(i + 1)).cloned();
    let self_test = flag("--self-test");
    let res = match args.first().map(String::as_str) {
        Some("layering") => layering(self_test),
        Some("lock-targets") => lock_targets(self_test),
        Some("lock-age") => {
            let days = opt("--min-days").and_then(|d| d.parse().ok()).unwrap_or(7u64);
            lock_age(days, self_test)
        }
        Some("repo-advisories") => repo_advisories(self_test),
        Some("budget") => budget::budget(self_test),
        Some("unsafe-sites") => unsafe_sites_gate(self_test),
        Some("allowlist-lock") => allowlist::allowlist_lock(self_test),
        Some("metrics-check") => metrics::metrics_check(self_test),
        Some("fips-lock") => fips_lock(&opt("--profile").unwrap_or_else(|| "cmvp".into()), self_test),
        Some("ledger-check") => ledger::run(&args),
        _ => {
            eprintln!(
                "usage: cargo xtask <layering|lock-targets|lock-age|repo-advisories|fips-lock|ledger-check|metrics-check|budget|unsafe-sites|allowlist-lock> [--self-test]"
            );
            return ExitCode::from(2);
        }
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// Reports a gate result; in self-test mode the expectation is inverted (the mutated input must fail).
fn verdict(name: &str, violations: &[String], self_test: bool) -> Result<(), String> {
    if self_test {
        if violations.is_empty() {
            return Err(format!("{name} SELF-TEST: FAIL (mutated input was not rejected)"));
        }
        println!("{name} SELF-TEST: PASS (mutated input rejected: {})", violations.join("; "));
        return Ok(());
    }
    if violations.is_empty() {
        println!("{name}: PASS");
        Ok(())
    } else {
        for v in violations {
            println!("  - {v}");
        }
        Err(format!("{name}: FAIL ({} violations)", violations.len()))
    }
}

fn run(cmd: &mut Command) -> Result<String, String> {
    let out = cmd.output().map_err(|e| format!("spawn {cmd:?}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{cmd:?} failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    String::from_utf8(out.stdout).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------- layering

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Layer {
    N(u8),
    Sdk,
    /// Native handler applications (`apps/*`): may depend on aegis-sdk only; only L5 may depend on them.
    App,
    Tool,
}

#[derive(Clone, Debug)]
struct Pkg {
    name: String,
    dir: PathBuf,
    layer: Option<Layer>,
    /// (dependency name, kind, enabled features) for workspace-path dependencies only.
    deps: Vec<(String, String, Vec<String>)>,
    /// Every value of the package's own `[features]` table (e.g. `"aegis-sdk/host"`), to catch forwarded gates.
    fwd: Vec<String>,
}

/// Constructor-gate modules and the only crate allowed to use each: (defining crate, cargo feature, module, owner).
/// aegis-types gates (REPO_LAYOUT §3, F2) and the SDK host driving loop (decision D2(b), P4-spec-002).
const OWNERS: &[(&str, &str, &str, &str)] = &[
    ("aegis-types", "authn-path", "authn_path", "aegis-token"),
    ("aegis-types", "canon-owner", "canon_owner", "aegis-canon"),
    ("aegis-types", "raw-owner", "raw_owner", "aegis-transport"),
    ("aegis-sdk", "host", "host", "aegis-adapter-host"),
];
/// Same-layer edges allowed by the crate table (REPO_LAYOUT §4). Everything else must point strictly downward.
const INTRA_LAYER: &[(&str, &str)] =
    &[("aegis-admission", "aegis-budget"), ("aegis-config", "aegis-canon"), ("aegis-adapter-host", "aegis-state")];
/// Layered crates allowed to depend on the SDK (the F7 host; D2(b)). Apps and these are its only dependents.
const SDK_HOSTS: &[&str] = &["aegis-adapter-host"];
/// Phase 7 crates whose layer PLAN-7 fixes (P7-spec-002): moving one in its manifest fails layering.
const PINNED_LAYERS: &[(&str, u8)] =
    &[("aegis-wire", 2), ("aegis-adapter-mysql", 4), ("aegis-uring", 4), ("aegis-otlp", 5)];
/// Separate binaries (layer 5) that no package may depend on, of any kind: aegis-bin execs or sits beside them and
/// never links them (X-8 aegis-pdp, X-13 aegis-p2, PREFLIGHT D-P7.6 aegis-otlp).
const SEPARATE_BINARIES: &[&str] = &["aegis-pdp", "aegis-p2", "aegis-otlp"];
/// Crates permitted to relax `forbid(unsafe_code)` (each site audited and capped by `cargo xtask unsafe-sites`).
const UNSAFE_ALLOWED: &[&str] = &["aegis-iso", "aegis-wasm", "aegis-uring"];
/// Per-crate unsafe-site caps (PLAN-5 D4, DEVIATIONS X-14): aegis-iso ≤ 20 (fork, prctl, seccomp, landlock_*,
/// setitimer, fd adoption, _exit); aegis-wasm ≤ 1 (the digest-checked `Module::deserialize_file`). Every crate in
/// `UNSAFE_ALLOWED` must have a cap here; every other workspace crate has cap 0. aegis-uring ≤ 6 (DEVIATIONS X-19:
/// io-uring 0.7.15 `SubmissionQueue::push` and ring setup are `unsafe fn`; opt-in feature `uring` only).
const UNSAFE_SITE_CAPS: &[(&str, usize)] = &[("aegis-iso", 20), ("aegis-wasm", 1), ("aegis-uring", 6)];

fn workspace_model() -> Result<Vec<Pkg>, String> {
    let out = run(Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps", "--offline"])
        .current_dir(root()))?;
    let meta = json::parse(&out)?;
    let mut pkgs = Vec::new();
    for p in meta.get("packages").map(Json::arr).unwrap_or(&[]) {
        let name = p.get("name").and_then(Json::str).unwrap_or_default().to_string();
        let manifest = PathBuf::from(p.get("manifest_path").and_then(Json::str).unwrap_or_default());
        let layer = match p.path(&["metadata", "aegis", "layer"]) {
            Some(Json::Num(n)) if *n >= 0.0 && *n <= 9.0 => Some(Layer::N(*n as u8)),
            Some(Json::Str(s)) if s == "sdk" => Some(Layer::Sdk),
            Some(Json::Str(s)) if s == "app" => Some(Layer::App),
            Some(Json::Str(s)) if s == "tool" => Some(Layer::Tool),
            _ => None,
        };
        let deps = p
            .get("dependencies")
            .map(Json::arr)
            .unwrap_or(&[])
            .iter()
            .filter(|d| d.get("path").is_some())
            .map(|d| {
                let n = d.get("name").and_then(Json::str).unwrap_or_default().to_string();
                let k = d.get("kind").and_then(Json::str).unwrap_or("normal").to_string();
                let f = d
                    .get("features")
                    .map(Json::arr)
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(Json::str)
                    .map(String::from)
                    .collect();
                (n, k, f)
            })
            .collect();
        let fwd = match p.get("features") {
            Some(Json::Obj(m)) => {
                m.values().flat_map(|v| v.arr().iter().filter_map(Json::str).map(String::from)).collect()
            }
            _ => Vec::new(),
        };
        pkgs.push(Pkg { name, dir: manifest.parent().map(Path::to_path_buf).unwrap_or_default(), layer, deps, fwd });
    }
    Ok(pkgs)
}

fn check_layering(pkgs: &[Pkg]) -> Vec<String> {
    let mut v = Vec::new();
    let layer_of: BTreeMap<&str, &Option<Layer>> = pkgs.iter().map(|p| (p.name.as_str(), &p.layer)).collect();
    for (name, want) in PINNED_LAYERS {
        match layer_of.get(name) {
            Some(Some(Layer::N(l))) if l == want => {}
            Some(got) => v.push(format!("{name}: layer {got:?}, PLAN-7 fixes it at {want}")),
            None => v.push(format!("{name}: missing (PLAN-7 workspace member, layer {want})")),
        }
    }
    for p in pkgs {
        for (dn, kind, _) in &p.deps {
            if SEPARATE_BINARIES.contains(&dn.as_str()) {
                v.push(format!("{} -> {dn} [{kind}]: {dn} is a separate binary; nothing may depend on it", p.name));
            }
        }
        let Some(pl) = &p.layer else {
            v.push(format!("{}: missing [package.metadata.aegis] layer", p.name));
            continue;
        };
        for (dn, kind, feats) in &p.deps {
            let Some(Some(dl)) = layer_of.get(dn.as_str()) else { continue };
            let ok = match (pl, dl) {
                (Layer::Tool, _) => true,
                (_, Layer::Tool) => kind == "dev",
                (Layer::Sdk, Layer::N(d)) => *d <= 2,
                (Layer::N(_), Layer::Sdk) => SDK_HOSTS.contains(&p.name.as_str()),
                (Layer::Sdk, Layer::Sdk) | (Layer::Sdk, Layer::App) => false,
                (Layer::App, Layer::Sdk) => true,
                (Layer::App, _) => false,
                (Layer::N(a), Layer::App) => *a == 5,
                (Layer::N(a), Layer::N(b)) => {
                    b < a || (a == b && INTRA_LAYER.contains(&(p.name.as_str(), dn.as_str())))
                }
            };
            if !ok {
                v.push(format!("{} ({pl:?}) -> {dn} ({dl:?}) [{kind}]: upward or cross-zone edge", p.name));
            }
            for f in feats {
                if let Some((_, _, _, owner)) = OWNERS.iter().find(|(c, feat, _, _)| c == dn && feat == f)
                    && p.name != *owner
                {
                    v.push(format!("{} enables {dn}/{f}; only {owner} may", p.name));
                }
            }
        }
        // A gate feature forwarded through the package's own [features] table ("dep/feat" or "dep?/feat").
        for fv in &p.fwd {
            let Some((dep, feat)) = fv.split_once('/') else { continue };
            let dep = dep.trim_end_matches('?');
            if let Some((_, _, _, owner)) = OWNERS.iter().find(|(c, f, _, _)| *c == dep && *f == feat)
                && p.name != *owner
            {
                v.push(format!("{} enables {dep}/{feat} (forwarded feature); only {owner} may", p.name));
            }
        }
    }
    v
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n != "target") {
                rust_files(&p, out);
            }
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn check_sources(pkgs: &[Pkg]) -> Vec<String> {
    let mut v = Vec::new();
    for p in pkgs.iter().filter(|p| p.layer != Some(Layer::Tool)) {
        let mut files = Vec::new();
        rust_files(&p.dir.join("src"), &mut files);
        let roots: BTreeSet<PathBuf> =
            ["src/lib.rs", "src/main.rs"].iter().map(|r| p.dir.join(r)).filter(|f| f.exists()).collect();
        for r in &roots {
            let src = std::fs::read_to_string(r).unwrap_or_default();
            let forbids = src.contains("#![forbid(unsafe_code)]");
            if !forbids && !UNSAFE_ALLOWED.contains(&p.name.as_str()) {
                v.push(format!("{}: {} lacks #![forbid(unsafe_code)]", p.name, r.display()));
            }
        }
        for f in &files {
            let src = std::fs::read_to_string(f).unwrap_or_default();
            v.extend(source_violations(&p.name, &f.display().to_string(), &src));
        }
    }
    v
}

/// Owner-gate violations in one source file of package `pkg`. The defining crate itself is exempt.
fn source_violations(pkg: &str, file: &str, src: &str) -> Vec<String> {
    let mut v = Vec::new();
    for (krate, _, module, owner) in OWNERS {
        if pkg == *owner || pkg == *krate {
            continue;
        }
        let hit = if *krate == "aegis-types" {
            src.contains(&format!("{module}::")).then_some("path")
        } else {
            gated_module_ref(src, &krate.replace('-', "_"), module)
        };
        if let Some(how) = hit {
            v.push(format!("{pkg}: {file} uses {}::{module} ({how}; owner: {owner})", krate.replace('-', "_")));
        }
    }
    v
}

/// Finds a reference to `krate::module` in any spelling a `use` can take (whitespace ignored): a direct path, a brace
/// group naming the module, a glob import followed by `module::`, or an alias of the crate (which cannot be followed,
/// so it fails closed).
fn gated_module_ref(src: &str, krate: &str, module: &str) -> Option<&'static str> {
    let s: String = src.chars().filter(|c| !c.is_whitespace()).collect();
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let token_at = |hay: &str, needle: &str| {
        hay.match_indices(needle).any(|(i, _)| {
            let before = hay.get(..i).and_then(|h| h.chars().next_back());
            let after = hay.get(i + needle.len()..).and_then(|h| h.chars().next());
            let open_end = !needle.chars().next_back().is_some_and(ident);
            !before.is_some_and(ident) && (open_end || !after.is_some_and(ident))
        })
    };
    if s.contains(&format!("{krate}::{module}")) {
        return Some("path");
    }
    let open = format!("{krate}::{{");
    for (i, _) in s.match_indices(&open) {
        let rest = s.get(i + open.len()..).unwrap_or_default();
        let mut depth = 1usize;
        let mut end = rest.len();
        for (j, c) in rest.char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = j;
                        break;
                    }
                }
                _ => {}
            }
        }
        if token_at(rest.get(..end).unwrap_or_default(), module) {
            return Some("use group");
        }
    }
    if s.contains(&format!("{krate}::*")) && token_at(&s, &format!("{module}::")) {
        return Some("glob import");
    }
    if s.contains(&format!("{krate}as")) {
        return Some("crate alias");
    }
    None
}

fn layering(self_test: bool) -> Result<(), String> {
    let mut pkgs = workspace_model()?;
    if self_test {
        // Negative control from IMPLEMENTATION_PLAN Phase 0: an injected upward edge must fail.
        if let Some(t) = pkgs.iter_mut().find(|p| p.name == "aegis-transport") {
            t.deps.push(("aegis-adapter-pg".into(), "normal".into(), vec![]));
        }
        if let Some(t) = pkgs.iter_mut().find(|p| p.name == "aegis-agent") {
            t.deps.push(("aegis-types".into(), "normal".into(), vec!["authn-path".into()]));
        }
        // P4-spec-002 (D2(b)): a non-owner enabling the SDK host feature, directly or forwarded; an app reaching past
        // the SDK; a non-host layered crate depending on the SDK.
        if let Some(t) = pkgs.iter_mut().find(|p| p.name == "aegis-state") {
            t.deps.push(("aegis-sdk".into(), "normal".into(), vec!["host".into()]));
        }
        if let Some(t) = pkgs.iter_mut().find(|p| p.name == "aegis-bin") {
            t.fwd.push("aegis-sdk?/host".into());
        }
        // P7-spec-002: aegis-bin linking the aegis-otlp exporter binary; the L2 parser crate reaching an L4 adapter;
        // a Phase 7 crate moved off its PLAN-7 layer.
        if let Some(t) = pkgs.iter_mut().find(|p| p.name == "aegis-bin") {
            t.deps.push(("aegis-otlp".into(), "normal".into(), vec![]));
        }
        if let Some(t) = pkgs.iter_mut().find(|p| p.name == "aegis-wire") {
            t.deps.push(("aegis-adapter-mysql".into(), "normal".into(), vec![]));
        }
        if let Some(t) = pkgs.iter_mut().find(|p| p.name == "aegis-uring") {
            t.layer = Some(Layer::N(3));
        }
        pkgs.push(Pkg {
            name: "selftest-app".into(),
            dir: PathBuf::new(),
            layer: Some(Layer::App),
            deps: vec![
                ("aegis-sdk".into(), "normal".into(), vec![]),
                ("aegis-data-ir".into(), "normal".into(), vec![]),
            ],
            fwd: vec![],
        });
    }
    let mut v = check_layering(&pkgs);
    if !self_test {
        v.extend(check_sources(&pkgs));
    }
    if self_test {
        // Source mutants: every `use` spelling of aegis_sdk::host in a non-owner crate must be reported.
        let mutants = [
            "use aegis_sdk::host::Backend;",
            "use aegis_sdk::{Ctx, host::{drive, Request}};",
            "use aegis_sdk :: {\n    host,\n    Ctx,\n};",
            "use aegis_sdk::*;\nfn f() { let _ = host::drive; }",
            "extern crate aegis_sdk as sdk;",
        ];
        for (i, m) in mutants.iter().enumerate() {
            v.extend(source_violations("aegis-state", &format!("selftest-mutant-{i}.rs"), m));
        }
        // Controls that must stay clean: the owner itself, the defining crate, and look-alike paths.
        let clean = [
            ("aegis-adapter-host", "use aegis_sdk::host::{drive, Backend};"),
            ("aegis-sdk", "use crate::host::drive;"),
            ("aegis-bin", "use aegis_adapter_host::pdp_uds; use aegis_sdk::{Ctx, ScopedHandler};"),
            ("aegis-bin", "use aegis_sdk::*; fn f() { let _ = aegis_adapter_host::x; }"),
        ];
        for (pkg, src) in clean {
            let bad = source_violations(pkg, "selftest-control.rs", src);
            if !bad.is_empty() {
                return Err(format!(
                    "LAYERING SELF-TEST: FAIL (false positive on a clean control: {})",
                    bad.join("; ")
                ));
            }
        }
        let mut wants: Vec<String> = [
            "aegis-transport (N(3)) -> aegis-adapter-pg",
            "aegis-agent enables aegis-types/authn-path",
            "aegis-state enables aegis-sdk/host",
            "aegis-state (N(4)) -> aegis-sdk (Sdk)",
            "aegis-bin enables aegis-sdk/host (forwarded feature)",
            "selftest-app (App) -> aegis-data-ir",
            "aegis-bin -> aegis-otlp [normal]: aegis-otlp is a separate binary",
            "aegis-bin (N(5)) -> aegis-otlp (N(5))",
            "aegis-wire (N(2)) -> aegis-adapter-mysql (N(4))",
            "aegis-uring: layer Some(N(3)), PLAN-7 fixes it at 4",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        wants.extend((0..mutants.len()).map(|i| format!("aegis-state: selftest-mutant-{i}.rs uses aegis_sdk::host")));
        for want in &wants {
            if !v.iter().any(|x| x.starts_with(want.as_str())) {
                return Err(format!("LAYERING SELF-TEST: FAIL (injected violation not reported: {want})"));
            }
        }
        if v.iter().any(|x| x.starts_with("selftest-app (App) -> aegis-sdk")) {
            return Err("LAYERING SELF-TEST: FAIL (app -> aegis-sdk edge wrongly rejected)".into());
        }
    }
    verdict("LAYERING", &v, self_test)
}

// ---------------------------------------------------------------- unsafe sites (PLAN-5 D4, DEVIATIONS X-14)

fn ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Unsafe sites of one source file: one per `unsafe` keyword in code (block, fn, impl, trait, extern; comments and
/// string/char literals ignored), as (1-based line, justified). A site is justified by a `// SAFETY:` comment on the
/// same line or in the run of `//` comment and `#[..]` attribute lines directly above it.
fn unsafe_sites(src: &str) -> Vec<(usize, bool)> {
    let code = budget::strip_comments_and_strings(src);
    let raw: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    for (i, l) in code.lines().enumerate() {
        let n = l
            .match_indices("unsafe")
            .filter(|(p, _)| {
                let before = l.get(..*p).and_then(|s| s.chars().next_back());
                let after = l.get(p + 6..).and_then(|s| s.chars().next());
                !before.is_some_and(ident_char) && !after.is_some_and(ident_char)
            })
            .count();
        if n == 0 {
            continue;
        }
        let same_line = raw.get(i).is_some_and(|r| r.contains("// SAFETY:"));
        let mut above = false;
        let mut j = i;
        while j > 0 {
            j -= 1;
            let t = raw.get(j).map(|r| r.trim_start()).unwrap_or_default();
            if t.starts_with("//") {
                if t.starts_with("// SAFETY:") {
                    above = true;
                    break;
                }
            } else if !t.starts_with("#[") {
                break;
            }
        }
        out.extend(std::iter::repeat_n((i + 1, same_line || above), n));
    }
    out
}

/// One workspace source file: (package, path, contents).
type SrcFile = (String, String, String);

/// Judges unsafe sites over `files` and the per-package `unsafe_code` lint level read from each manifest
/// (`manifests`: package → lint value, absent when the manifest inherits the workspace's `forbid`).
/// Returns (violations, per-package site counts).
fn check_unsafe_sites(
    files: &[SrcFile],
    manifests: &BTreeMap<String, String>,
) -> (Vec<String>, BTreeMap<String, usize>) {
    let mut v = Vec::new();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for a in UNSAFE_ALLOWED {
        if !UNSAFE_SITE_CAPS.iter().any(|(c, _)| c == a) {
            v.push(format!("{a}: in UNSAFE_ALLOWED without a site cap"));
        }
    }
    for (pkg, file, src) in files {
        let allowed = UNSAFE_ALLOWED.contains(&pkg.as_str());
        for (line, justified) in unsafe_sites(src) {
            *counts.entry(pkg.clone()).or_default() += 1;
            if !justified {
                v.push(format!("{pkg}: {file}:{line}: unsafe site without a `// SAFETY:` comment"));
            }
        }
        let code: String = budget::strip_comments_and_strings(src).chars().filter(|c| !c.is_whitespace()).collect();
        if !allowed && (code.contains("allow(unsafe_code") || code.contains("warn(unsafe_code")) {
            v.push(format!("{pkg}: {file} relaxes unsafe_code but {pkg} is not in UNSAFE_ALLOWED"));
        }
    }
    for (pkg, n) in &counts {
        let cap = UNSAFE_SITE_CAPS.iter().find(|(c, _)| c == pkg).map_or(0, |(_, k)| *k);
        if *n > cap {
            v.push(format!("{pkg}: {n} unsafe sites > cap {cap}"));
        }
    }
    for (pkg, level) in manifests {
        let allowed = UNSAFE_ALLOWED.contains(&pkg.as_str());
        let ok = level == "forbid" || (allowed && level == "deny");
        if !ok {
            v.push(format!(
                "{pkg}: Cargo.toml sets unsafe_code = \"{level}\" (only forbid, or deny for {UNSAFE_ALLOWED:?})"
            ));
        }
    }
    (v, counts)
}

/// The `unsafe_code` level a package manifest sets in its own `[lints.rust]` table, if any.
fn manifest_unsafe_level(toml: &str) -> Option<String> {
    let mut in_rust = false;
    for l in toml.lines() {
        let t = l.trim();
        if t.starts_with('[') {
            in_rust = t == "[lints.rust]";
            continue;
        }
        if in_rust && let Some(rest) = t.strip_prefix("unsafe_code") {
            let val = rest.trim_start().trim_start_matches('=').trim();
            let val = val.split(['#']).next().unwrap_or_default().trim();
            // `"deny"` or `{ level = "deny", .. }`
            let lvl = val.split('"').nth(1).unwrap_or(val);
            return Some(lvl.to_string());
        }
    }
    None
}

fn unsafe_sites_gate(self_test: bool) -> Result<(), String> {
    if self_test {
        return unsafe_sites_self_test();
    }
    let pkgs = workspace_model()?;
    let mut files: Vec<SrcFile> = Vec::new();
    let mut manifests = BTreeMap::new();
    for p in &pkgs {
        let mut fs = Vec::new();
        rust_files(&p.dir, &mut fs);
        fs.sort();
        for f in fs {
            let src = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
            let rel = f.strip_prefix(root()).unwrap_or(&f).display().to_string();
            files.push((p.name.clone(), rel, src));
        }
        let toml = std::fs::read_to_string(p.dir.join("Cargo.toml")).unwrap_or_default();
        if let Some(l) = manifest_unsafe_level(&toml) {
            manifests.insert(p.name.clone(), l);
        }
    }
    let (v, counts) = check_unsafe_sites(&files, &manifests);
    let caps: Vec<String> =
        UNSAFE_SITE_CAPS.iter().map(|(c, k)| format!("{c} {}/{k}", counts.get(*c).copied().unwrap_or(0))).collect();
    println!("unsafe-sites: {} packages, {} source files; {}", pkgs.len(), files.len(), caps.join(", "));
    verdict("UNSAFE-SITES", &v, false)
}

/// (label, files, manifest lint levels, expected violation substring).
type UnsafeMutant<'a> = (&'a str, Vec<SrcFile>, BTreeMap<String, String>, &'a str);

fn unsafe_sites_self_test() -> Result<(), String> {
    let site = "    // SAFETY: the fd is owned and open.\n    #[allow(unsafe_code)]\n    unsafe { f() };\n";
    let src_n = |n: usize| format!("fn x() {{\n{}}}\n", site.repeat(n));
    let mk = |pkg: &str, src: String| (pkg.to_string(), format!("{pkg}/src/lib.rs"), src);
    let deny = |pkgs: &[&str]| pkgs.iter().map(|p| (p.to_string(), "deny".to_string())).collect::<BTreeMap<_, _>>();
    let clean_bin = "// unsafe is not used here\nfn y() { let s = \"unsafe { }\"; let _c = 'u'; unsafe_fn(); }\n";
    let base: Vec<SrcFile> = vec![
        mk("aegis-iso", src_n(20)),
        mk("aegis-wasm", "fn d() {\n    let m = unsafe { g() }; // SAFETY: digest checked above.\n}\n".into()),
        mk("aegis-bin", clean_bin.into()),
    ];
    let manifests = deny(&["aegis-iso", "aegis-wasm"]);
    let mut failures = Vec::new();
    let (v, counts) = check_unsafe_sites(&base, &manifests);
    if v.is_empty() && counts.get("aegis-iso") == Some(&20) && counts.get("aegis-wasm") == Some(&1) {
        println!("  control (aegis-iso 20, aegis-wasm 1, comments/strings ignored): PASS (as required)");
    } else {
        failures.push(format!("clean control rejected or miscounted: {v:?} {counts:?}"));
    }
    let with = |pkg: &str, src: String| {
        let mut f = base.clone();
        f.retain(|(p, _, _)| p != pkg);
        f.push(mk(pkg, src));
        f
    };
    let mutants: Vec<UnsafeMutant> = vec![
        ("21st aegis-iso site", with("aegis-iso", src_n(21)), manifests.clone(), "aegis-iso: 21 unsafe sites > cap 20"),
        ("2nd aegis-wasm site", with("aegis-wasm", src_n(2)), manifests.clone(), "aegis-wasm: 2 unsafe sites > cap 1"),
        ("7th aegis-uring site", with("aegis-uring", src_n(7)), deny(&["aegis-iso", "aegis-wasm", "aegis-uring"]), "aegis-uring: 7 unsafe sites > cap 6"),
        (
            "site without // SAFETY:",
            with("aegis-iso", "fn z() {\n    // the fd is open\n    unsafe { f() };\n}\n".into()),
            manifests.clone(),
            "unsafe site without a `// SAFETY:` comment",
        ),
        (
            "unsafe in a third crate",
            with("aegis-bin", src_n(1)),
            manifests.clone(),
            "aegis-bin: 1 unsafe sites > cap 0",
        ),
        (
            "third crate relaxes the lint in source",
            with("aegis-bin", "#![allow(unsafe_code)]\nfn y() {}\n".into()),
            manifests.clone(),
            "aegis-bin: aegis-bin/src/lib.rs relaxes unsafe_code",
        ),
        (
            "third crate relaxes the lint in Cargo.toml",
            base.clone(),
            deny(&["aegis-iso", "aegis-wasm", "aegis-bin"]),
            "aegis-bin: Cargo.toml sets unsafe_code = \"deny\"",
        ),
        (
            "allowed crate sets unsafe_code = allow",
            base.clone(),
            [("aegis-iso".to_string(), "allow".to_string())].into_iter().collect(),
            "aegis-iso: Cargo.toml sets unsafe_code = \"allow\"",
        ),
    ];
    for (label, files, m, want) in &mutants {
        let (v, _) = check_unsafe_sites(files, m);
        if v.iter().any(|x| x.contains(want)) {
            println!("  mutant '{label}': FAIL (as required: {})", v.join("; "));
        } else {
            failures.push(format!("mutant '{label}' not rejected (want '{want}', got {v:?})"));
        }
    }
    let lvl = |s: &str| manifest_unsafe_level(s);
    if lvl("[lints.rust]\nunsafe_code = \"deny\"\n").as_deref() != Some("deny")
        || lvl("[lints.rust]\nunsafe_code = { level = \"allow\", priority = 1 }\n").as_deref() != Some("allow")
        || lvl("[lints]\nworkspace = true\n").is_some()
    {
        failures.push("manifest unsafe_code parser wrong".into());
    }
    if failures.is_empty() {
        println!("UNSAFE-SITES SELF-TEST: PASS ({} mutants rejected)", mutants.len());
        Ok(())
    } else {
        for f in &failures {
            println!("  - {f}");
        }
        Err(format!("UNSAFE-SITES SELF-TEST: FAIL ({} problems)", failures.len()))
    }
}

// ---------------------------------------------------------------- lock targets

fn read_lock() -> Result<Vec<lock::LockPkg>, String> {
    let s = std::fs::read_to_string(root().join("Cargo.lock")).map_err(|e| format!("Cargo.lock: {e}"))?;
    lock::parse_lock(&s)
}

fn check_lock_targets(pkgs: &[lock::LockPkg], targets: &BTreeMap<String, String>) -> Vec<String> {
    let mut v = Vec::new();
    for (name, want) in targets {
        for p in pkgs.iter().filter(|p| &p.name == name) {
            if &p.version != want {
                v.push(format!("{name}: lock resolves {} but golden target is {want}", p.version));
            }
        }
    }
    v
}

fn lock_targets(self_test: bool) -> Result<(), String> {
    let mut pkgs = read_lock()?;
    let targets = lock::parse_kv(
        &std::fs::read_to_string(root().join("supply-chain/lock-targets.toml")).map_err(|e| e.to_string())?,
    );
    if self_test {
        let (n, want) = targets.iter().next().ok_or("no targets to mutate")?;
        pkgs.push(lock::LockPkg {
            name: n.clone(),
            version: format!("{want}-mutated"),
            source: Some("registry".into()),
        });
    }
    let present = targets.keys().filter(|k| pkgs.iter().any(|p| &p.name == *k)).count();
    println!("lock-targets: {present}/{} pinned crates present in Cargo.lock", targets.len());
    verdict("LOCK-TARGETS", &check_lock_targets(&pkgs, &targets), self_test)
}

// ---------------------------------------------------------------- lock age (cooldown)

fn curl_json(url: &str, post: Option<&str>) -> Result<Json, String> {
    let mut c = Command::new("curl");
    c.args(["-sfL", "--retry", "3", "--max-time", "30", "-A", "aegis-xtask (supply-chain gate)"]);
    let tok = std::env::var("GITHUB_TOKEN").ok().or_else(|| {
        Command::new("gh")
            .args(["auth", "token"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|t| t.trim().to_string())
    });
    if let Some(tok) = tok
        && url.starts_with("https://api.github.com")
    {
        c.args(["-H", &format!("Authorization: Bearer {tok}")]);
    }
    if let Some(body) = post {
        c.args(["-H", "Content-Type: application/json", "--data-binary", body]);
    }
    json::parse(&run(c.arg(url))?)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn rfc3339_day(s: &str) -> Option<i64> {
    let y = s.get(0..4)?.parse().ok()?;
    let m = s.get(5..7)?.parse().ok()?;
    let d = s.get(8..10)?.parse().ok()?;
    Some(days_from_civil(y, m, d))
}

fn today() -> i64 {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    (secs / 86_400) as i64
}

fn exceptions() -> BTreeSet<(String, String)> {
    // supply-chain/exceptions.toml: [[exception]] crate = "x" version = "y" reason = "..." expires = "YYYY-MM-DD"
    let s = std::fs::read_to_string(root().join("supply-chain/exceptions.toml")).unwrap_or_default();
    let mut out = BTreeSet::new();
    for block in s.split("[[exception]]").skip(1) {
        let kv = lock::parse_kv(block);
        let live = kv.get("expires").and_then(|e| rfc3339_day(e)).is_some_and(|d| d >= today());
        if let (Some(c), Some(v), true) = (kv.get("crate"), kv.get("version"), live) {
            out.insert((c.clone(), v.clone()));
        }
    }
    out
}

/// Live `kind = "advisory-accepted"` ledger entries as (crate, version, advisory id). Each entry names the advisories it
/// accepts, so a new advisory against the same crate@version still fails the gate.
fn advisory_exceptions() -> BTreeSet<(String, String, String)> {
    let s = std::fs::read_to_string(root().join("supply-chain/exceptions.toml")).unwrap_or_default();
    let mut out = BTreeSet::new();
    for block in s.split("[[exception]]").skip(1) {
        let kv = lock::parse_kv(block);
        let live = kv.get("expires").and_then(|e| rfc3339_day(e)).is_some_and(|d| d >= today());
        if !live || kv.get("kind").map(String::as_str) != Some("advisory-accepted") {
            continue;
        }
        if let (Some(c), Some(v), Some(a)) = (kv.get("crate"), kv.get("version"), kv.get("advisory")) {
            for id in a.split(',').map(str::trim).filter(|x| !x.is_empty()) {
                out.insert((c.clone(), v.clone(), id.to_string()));
            }
        }
    }
    out
}

fn lock_age(min_days: u64, self_test: bool) -> Result<(), String> {
    // The root (floor) lock plus the committed cmvp overlay lock (PLAN-6 D1: lock-age applies to both), deduplicated.
    let mut pkgs = read_lock()?;
    if let Ok(s) = std::fs::read_to_string(root().join("profiles/cmvp/Cargo.lock")) {
        pkgs.extend(lock::parse_lock(&s).map_err(|e| format!("profiles/cmvp/Cargo.lock: {e}"))?);
    }
    let mut seen = BTreeSet::new();
    pkgs.retain(|p| seen.insert((p.name.clone(), p.version.clone())));
    let exc = exceptions();
    let mut v = Vec::new();
    let mut ages: Vec<(String, String, i64)> = Vec::new();
    // A published version's created_at never changes, so fetched days are cached under target/ (not committed) and
    // only new lock entries hit crates.io, at most one request per second (crates.io crawler policy).
    let cache_path = root().join("target/xtask-cache/crates-created.tsv");
    let mut cache: BTreeMap<(String, String), i64> = std::fs::read_to_string(&cache_path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut f = l.split('\t');
            Some(((f.next()?.to_string(), f.next()?.to_string()), f.next()?.parse().ok()?))
        })
        .collect();
    let mut fetched = 0usize;
    for p in pkgs.iter().filter(|p| p.source.as_deref().is_some_and(|s| s.starts_with("registry+"))) {
        let key = (p.name.clone(), p.version.clone());
        let created = match cache.get(&key) {
            Some(d) => *d,
            None => {
                if fetched > 0 {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
                fetched += 1;
                let j = curl_json(&format!("https://crates.io/api/v1/crates/{}/{}", p.name, p.version), None)?;
                let d = j
                    .path(&["version", "created_at"])
                    .and_then(Json::str)
                    .and_then(rfc3339_day)
                    .ok_or(format!("{}: no created_at", p.name))?;
                cache.insert(key, d);
                d
            }
        };
        ages.push((p.name.clone(), p.version.clone(), today() - created));
    }
    if fetched > 0 {
        let body: String = cache.iter().map(|((n, v), d)| format!("{n}\t{v}\t{d}\n")).collect();
        if let Some(dir) = cache_path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(&cache_path, body);
    }
    if self_test {
        ages.push(("selftest-fresh-crate".into(), "0.0.1".into(), 0));
    }
    for (n, ver, age) in &ages {
        if (*age as u64) < min_days && !exc.contains(&(n.clone(), ver.clone())) {
            v.push(format!("{n} {ver} published {age} d ago (< {min_days} d) with no live exception"));
        }
    }
    println!(
        "lock-age: {} registry packages checked in Cargo.lock + profiles/cmvp/Cargo.lock (min {min_days} d)",
        ages.len()
    );
    verdict("LOCK-AGE", &v, self_test)
}

// ---------------------------------------------------------------- advisories beyond RustSec

fn repo_advisories(self_test: bool) -> Result<(), String> {
    let mut pkgs: Vec<(String, String)> = read_lock()?
        .into_iter()
        .filter(|p| p.source.as_deref().is_some_and(|s| s.starts_with("registry+")))
        .map(|p| (p.name, p.version))
        .collect();
    if self_test {
        // A version with known GHSA/OSV advisories (h2 0.3.0, RUSTSEC-2024-0003 et al.).
        pkgs.push(("h2".into(), "0.3.0".into()));
    }
    let mut accepted = advisory_exceptions();
    if self_test {
        // Must stay red: an acceptance for a different advisory id does not cover h2 0.3.0's advisories.
        accepted.insert(("h2".into(), "0.3.0".into(), "GHSA-0000-0000-0000".into()));
    }
    let open = |n: &str, ver: &str, ids: Vec<&str>| -> Vec<String> {
        ids.into_iter()
            .filter(|id| !accepted.contains(&(n.into(), ver.into(), (*id).into())))
            .map(String::from)
            .collect()
    };
    let mut v = Vec::new();
    for chunk in pkgs.chunks(500) {
        let queries: Vec<String> = chunk
            .iter()
            .map(|(n, ver)| format!(r#"{{"package":{{"name":"{n}","ecosystem":"crates.io"}},"version":"{ver}"}}"#))
            .collect();
        let body = format!(r#"{{"queries":[{}]}}"#, queries.join(","));
        let res = curl_json("https://api.osv.dev/v1/querybatch", Some(&body))?;
        for ((n, ver), r) in chunk.iter().zip(res.get("results").map(Json::arr).unwrap_or(&[])) {
            let ids: Vec<&str> = r
                .get("vulns")
                .map(Json::arr)
                .unwrap_or(&[])
                .iter()
                .filter_map(|x| x.get("id").and_then(Json::str))
                .collect();
            let ids = open(n, ver, ids);
            if !ids.is_empty() {
                v.push(format!("{n} {ver}: OSV {}", ids.join(",")));
            }
        }
    }
    // GitHub global advisories include unreviewed repository advisories that never reach RustSec/OSV
    // (r4c12.repo-ghsa-osv-blindspot).
    for (n, ver) in &pkgs {
        let url =
            format!("https://api.github.com/advisories?ecosystem=rust&affects={n}@{ver}&per_page=100&type=unreviewed");
        match ghsa_cached(n, ver, &url) {
            Ok(j) => {
                let ids = open(n, ver, j.arr().iter().filter_map(|a| a.get("ghsa_id").and_then(Json::str)).collect());
                if !ids.is_empty() {
                    v.push(format!("{n} {ver}: GHSA unreviewed {}", ids.join(",")));
                }
            }
            Err(e) => v.push(format!("{n} {ver}: GitHub advisory query failed ({e}); gate cannot pass blind")),
        }
    }
    println!(
        "repo-advisories: {} packages queried (OSV + GitHub unreviewed), {} ledgered acceptances",
        pkgs.len(),
        accepted.len()
    );
    verdict("REPO-ADVISORIES", &v, self_test)
}

/// GitHub advisory responses cached per crate@version for 24 h under target/xtask-cache (unauthenticated GitHub allows
/// 60 requests/hour). A stale or missing entry is re-fetched; a fetch failure is never served from an expired cache.
fn ghsa_cached(name: &str, ver: &str, url: &str) -> Result<Json, String> {
    let dir = root().join("target").join("xtask-cache").join("ghsa");
    let file = dir.join(format!("{name}@{ver}.json"));
    let fresh = std::fs::metadata(&file)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age.as_secs() < 86_400);
    if fresh
        && let Ok(text) = std::fs::read_to_string(&file)
        && let Ok(j) = json::parse(&text)
    {
        return Ok(j);
    }
    let j = curl_json(url, None)?;
    if std::fs::create_dir_all(&dir).is_ok() {
        let _ = std::fs::write(&file, render_json(&j));
    }
    Ok(j)
}

fn render_json(j: &Json) -> String {
    match j {
        Json::Null => "null".into(),
        Json::Bool(b) => b.to_string(),
        Json::Num(n) => format!("{n}"),
        Json::Str(s) => format!("{s:?}"),
        Json::Arr(v) => format!("[{}]", v.iter().map(render_json).collect::<Vec<_>>().join(",")),
        Json::Obj(m) => {
            format!("{{{}}}", m.iter().map(|(k, v)| format!("{k:?}:{}", render_json(v))).collect::<Vec<_>>().join(","))
        }
    }
}

// ---------------------------------------------------------------- FIPS lock (PLAN-6 D1; BACKLOG G1-G5, G7)
//
// Input is the `cargo metadata --locked` resolve graph (G7: features per node, and cargo itself refuses a lock that
// does not match the manifests), never Cargo.lock text.
//   cmvp:  profiles/cmvp/build.sh --metadata (the overlay tree with profiles/cmvp/Cargo.lock)
//   floor: the root workspace and root Cargo.lock (profiles/floor is the root lock, renamed only in reports; D1)
// Checks (oracles/hrr-verdicts/README.md "Spec for cargo xtask fips-lock"):
//   G1  (both) at least one rustls node, and every rustls node has feature prefer-post-quantum
//   G2a (cmvp) exactly one aws-lc-fips-sys node (a second one is the decoy)
//   G2b (cmvp) every aws-lc-rs node has feature fips and links exactly {pinned aws-lc-fips-sys}
//   G2c (cmvp) no non-FIPS AWS-LC: an aws-lc-sys node must be the in-tree void crate (path, no build script), and
//              only aws-lc-rs may depend on it
//   G3  (cmvp) every aws-lc-rs node in [1.15.2, 1.17.1]; every node of a pinned name equals its pin
//   G4  (both) rustls >= 0.23.46 (RUSTSEC-2026-0349), rustls-webpki >= 0.103.16 (RUSTSEC-2026-0382). In cmvp a node
//              below a floor is REPORTED, and passes only with a live advisory-accepted ledger entry for that
//              crate@version naming that advisory (the triangle, r4tri.no-co-resolvable-lock); in floor it fails.
//   G5  (floor) no aws-lc-fips-sys below 0.13.13 (0.13.11/.12 carry RUSTSEC-2026-0042/0043: uncertified lineage)
// G2b's binary half and G6 (module string in the binary) are the fips-binary gate (P6-cmvp-001).

const FIPS_AWSLCRS_WINDOW: ((u64, u64, u64), (u64, u64, u64)) = ((1, 15, 2), (1, 17, 1));
/// (crate, floor, advisory the floor fixes).
const FIPS_FLOORS: &[(&str, (u64, u64, u64), &str)] =
    &[("rustls", (0, 23, 46), "RUSTSEC-2026-0349"), ("rustls-webpki", (0, 103, 16), "RUSTSEC-2026-0382")];
const FIPS_LINEAGE_FLOOR: (u64, u64, u64) = (0, 13, 13);
const VOID_AWS_LC_SYS: &str = "profiles/cmvp/void/aws-lc-sys";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FipsProfile {
    Cmvp,
    Floor,
}

struct FipsCtx<'a> {
    pins: &'a BTreeMap<String, String>,
    /// Live advisory-accepted ledger entries (crate, version, advisory).
    accepted: &'a BTreeSet<(String, String, String)>,
    /// Absolute manifest path the void aws-lc-sys must have in the cmvp graph.
    void_manifest: String,
}

fn fmt_v(v: (u64, u64, u64)) -> String {
    format!("{}.{}.{}", v.0, v.1, v.2)
}

/// Returns (violations, reports). Every violation starts with its check id.
fn named<'a>(nodes: &'a [lock::Node], n: &'a str) -> impl Iterator<Item = &'a lock::Node> {
    nodes.iter().filter(move |p| p.name == n)
}

fn check_fips(profile: FipsProfile, nodes: &[lock::Node], cx: &FipsCtx) -> (Vec<String>, Vec<String>) {
    let mut v = Vec::new();
    let mut rep = Vec::new();
    // G1
    let rustls: Vec<&lock::Node> = named(nodes, "rustls").collect();
    if rustls.is_empty() {
        v.push("G1: no rustls node in the resolve graph".into());
    }
    for r in rustls.iter().filter(|r| !r.has_feature("prefer-post-quantum")) {
        v.push(format!("G1: rustls {} lacks feature prefer-post-quantum", r.version));
    }
    // G4
    for (name, floor, adv) in FIPS_FLOORS {
        for p in named(nodes, name) {
            if lock::semver(&p.version).is_some_and(|x| x >= *floor) {
                continue;
            }
            let ledgered = cx.accepted.contains(&((*name).into(), p.version.clone(), (*adv).into()));
            let what = format!("{name} {} < floor {} ({adv})", p.version, fmt_v(*floor));
            if profile == FipsProfile::Cmvp && ledgered {
                rep.push(format!("G4 REPORTED: {what}, ledgered advisory-accepted"));
            } else if profile == FipsProfile::Cmvp {
                v.push(format!("G4: {what} and no live advisory-accepted ledger entry for {name}@{} {adv}", p.version));
            } else {
                v.push(format!("G4: {what}"));
            }
        }
    }
    match profile {
        FipsProfile::Cmvp => {
            let fips: Vec<&lock::Node> = named(nodes, "aws-lc-fips-sys").collect();
            if fips.len() != 1 {
                let vs: Vec<&str> = fips.iter().map(|p| p.version.as_str()).collect();
                v.push(format!("G2a: expected exactly one aws-lc-fips-sys node, found {} {vs:?}", fips.len()));
            }
            let pin = cx.pins.get("aws-lc-fips-sys").cloned().unwrap_or_default();
            let awslcrs: Vec<&lock::Node> = named(nodes, "aws-lc-rs").collect();
            if awslcrs.is_empty() {
                v.push("G2b: no aws-lc-rs node".into());
            }
            for a in &awslcrs {
                if !a.has_feature("fips") {
                    v.push(format!("G2b: aws-lc-rs {} lacks feature fips (it would link aws-lc-sys)", a.version));
                }
                let linked: BTreeSet<&str> =
                    a.deps.iter().filter(|(n, _)| n == "aws-lc-fips-sys").map(|(_, ver)| ver.as_str()).collect();
                if linked != BTreeSet::from([pin.as_str()]) {
                    v.push(format!("G2b: aws-lc-rs {} links aws-lc-fips-sys {linked:?}, want {{{pin}}}", a.version));
                }
                let w = FIPS_AWSLCRS_WINDOW;
                if !lock::semver(&a.version).is_some_and(|x| x >= w.0 && x <= w.1) {
                    v.push(format!("G3: aws-lc-rs {} outside [{}, {}]", a.version, fmt_v(w.0), fmt_v(w.1)));
                }
            }
            for s in named(nodes, "aws-lc-sys") {
                if s.source.is_some() || s.manifest != cx.void_manifest || s.build_script {
                    v.push(format!(
                        "G2c: non-FIPS aws-lc-sys {} ({}) in the cmvp graph; only the void crate {VOID_AWS_LC_SYS} is allowed",
                        s.version,
                        s.source.as_deref().unwrap_or(&s.manifest)
                    ));
                }
            }
            for p in nodes.iter().filter(|p| p.name != "aws-lc-rs" && p.deps.iter().any(|(n, _)| n == "aws-lc-sys")) {
                v.push(format!("G2c: {} {} depends on aws-lc-sys directly", p.name, p.version));
            }
            for (n, want) in cx.pins {
                let ns: Vec<&lock::Node> = named(nodes, n).collect();
                if ns.is_empty() {
                    v.push(format!("G3: {n} pinned {want} but absent"));
                }
                for p in ns.iter().filter(|p| &p.version != want) {
                    v.push(format!("G3: {n} {} != pinned {want}", p.version));
                }
            }
        }
        FipsProfile::Floor => {
            for p in named(nodes, "aws-lc-fips-sys") {
                if !lock::semver(&p.version).is_some_and(|x| x >= FIPS_LINEAGE_FLOOR) {
                    v.push(format!(
                        "G5: aws-lc-fips-sys {} below {} (RUSTSEC-2026-0042/0043; uncertified lineage)",
                        p.version,
                        fmt_v(FIPS_LINEAGE_FLOOR)
                    ));
                }
            }
        }
    }
    (v, rep)
}

fn fips_graph(profile: FipsProfile) -> Result<Vec<lock::Node>, String> {
    let out = match profile {
        FipsProfile::Cmvp => run(Command::new(root().join("profiles/cmvp/build.sh")).arg("--metadata"))?,
        FipsProfile::Floor => {
            run(Command::new("cargo").args(["metadata", "--locked", "--format-version", "1"]).current_dir(root()))?
        }
    };
    lock::parse_metadata(&json::parse(&out)?)
}

/// The void crate's source must stay empty: only blank lines, `//` comments and inner attributes.
fn void_crate_violations() -> Vec<String> {
    let f = root().join(VOID_AWS_LC_SYS).join("lib.rs");
    match std::fs::read_to_string(&f) {
        Ok(s) => s
            .lines()
            .map(str::trim)
            .filter(|l| !(l.is_empty() || l.starts_with("//") || l.starts_with("#![")))
            .map(|l| format!("G2c: void aws-lc-sys has code: {l}"))
            .collect(),
        Err(e) => vec![format!("G2c: {}: {e}", f.display())],
    }
}

fn fips_lock(profile: &str, self_test: bool) -> Result<(), String> {
    let pins_of = |p: &str| -> Result<BTreeMap<String, String>, String> {
        let f = root().join("profiles").join(p).join("pins.toml");
        Ok(lock::parse_kv(&std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?))
    };
    let void_manifest = root().join("target/cmvp-src").join(VOID_AWS_LC_SYS).join("Cargo.toml");
    let void_manifest = void_manifest.to_string_lossy().into_owned();
    if self_test {
        return fips_self_test(&pins_of("cmvp")?, &void_manifest);
    }
    let (prof, pins) = match profile {
        "cmvp" => (FipsProfile::Cmvp, pins_of("cmvp")?),
        "floor" => (FipsProfile::Floor, BTreeMap::new()),
        p => return Err(format!("FIPS-LOCK: FAIL (unknown profile {p}; cmvp or floor)")),
    };
    let nodes =
        fips_graph(prof).map_err(|e| format!("FIPS-LOCK ({profile}): FAIL (G7: cargo metadata --locked: {e})"))?;
    let accepted = advisory_exceptions();
    let (mut v, rep) = check_fips(prof, &nodes, &FipsCtx { pins: &pins, accepted: &accepted, void_manifest });
    if prof == FipsProfile::Cmvp {
        v.extend(void_crate_violations());
    }
    let ver = |n: &str| -> String {
        let s: BTreeSet<&str> = nodes.iter().filter(|p| p.name == n).map(|p| p.version.as_str()).collect();
        s.into_iter().collect::<Vec<_>>().join(",")
    };
    println!(
        "fips-lock ({profile}): {} resolve nodes; rustls {} (prefer-post-quantum on all), rustls-webpki {}, aws-lc-rs {}, aws-lc-fips-sys [{}], aws-lc-sys [{}]",
        nodes.len(),
        ver("rustls"),
        ver("rustls-webpki"),
        ver("aws-lc-rs"),
        ver("aws-lc-fips-sys"),
        ver("aws-lc-sys"),
    );
    for r in &rep {
        println!("  {r}");
    }
    verdict(&format!("FIPS-LOCK ({profile})"), &v, false)
}

/// Synthetic graphs: a clean cmvp and a clean floor baseline (both must pass), then one mutant per check, each of
/// which must be rejected with its own check id.
fn fips_self_test(pins: &BTreeMap<String, String>, void_manifest: &str) -> Result<(), String> {
    const REG: &str = "registry+https://github.com/rust-lang/crates.io-index";
    let node = |n: &str, ver: &str, feats: &[&str], deps: &[(&str, &str)]| lock::Node {
        name: n.into(),
        version: ver.into(),
        source: Some(REG.into()),
        manifest: format!("/registry/{n}-{ver}/Cargo.toml"),
        features: feats.iter().map(|s| (*s).to_string()).collect(),
        deps: deps.iter().map(|(a, b)| ((*a).to_string(), (*b).to_string())).collect(),
        build_script: n.ends_with("-sys"),
    };
    let pin = |n: &str| pins.get(n).cloned().unwrap_or_default();
    let (p_rustls, p_rs, p_fips) = (pin("rustls"), pin("aws-lc-rs"), pin("aws-lc-fips-sys"));
    let mut void = node("aws-lc-sys", "0.36.0", &["prebuilt-nasm"], &[]);
    void.source = None;
    void.manifest = void_manifest.into();
    void.build_script = false;
    let cmvp = vec![
        node("rustls", &p_rustls, &["aws_lc_rs", "fips", "prefer-post-quantum", "std"], &[("aws-lc-rs", &p_rs)]),
        node("rustls-webpki", "0.103.13", &["aws-lc-rs", "aws-lc-rs-fips"], &[("aws-lc-rs", &p_rs)]),
        node("aws-lc-rs", &p_rs, &["aws-lc-sys", "fips"], &[("aws-lc-fips-sys", &p_fips), ("aws-lc-sys", "0.36.0")]),
        node("aws-lc-fips-sys", &p_fips, &[], &[]),
        void,
    ];
    let floor = vec![
        node("rustls", "0.23.46", &["aws_lc_rs", "prefer-post-quantum", "std"], &[("aws-lc-rs", "1.18.2")]),
        node("rustls-webpki", "0.103.16", &["aws-lc-rs"], &[("aws-lc-rs", "1.18.2")]),
        node("aws-lc-rs", "1.18.2", &["aws-lc-sys"], &[("aws-lc-sys", "0.46.0")]),
        node("aws-lc-sys", "0.46.0", &[], &[]),
    ];
    let accepted: BTreeSet<(String, String, String)> =
        [("rustls", p_rustls.as_str(), "RUSTSEC-2026-0349"), ("rustls-webpki", "0.103.13", "RUSTSEC-2026-0382")]
            .iter()
            .map(|(a, b, c)| ((*a).to_string(), (*b).to_string(), (*c).to_string()))
            .collect();
    let none = BTreeSet::new();
    let cx = FipsCtx { pins, accepted: &accepted, void_manifest: void_manifest.into() };
    let mut fails = Vec::new();
    for (name, prof, g) in [("cmvp", FipsProfile::Cmvp, &cmvp), ("floor", FipsProfile::Floor, &floor)] {
        let (v, _) = check_fips(prof, g, &cx);
        if !v.is_empty() {
            fails.push(format!("baseline {name} not clean: {}", v.join("; ")));
        }
    }
    let set = |g: &mut Vec<lock::Node>, n: &str, f: &dyn Fn(&mut lock::Node)| {
        g.iter_mut().filter(|p| p.name == n).for_each(f)
    };
    // (mutant, profile, expected check id, graph, pins override, accepted set)
    type Mut<'a> = (&'a str, FipsProfile, &'a str, Vec<lock::Node>, Option<BTreeMap<String, String>>, bool);
    let mut muts: Vec<Mut> = Vec::new();
    let mut g = cmvp.clone();
    g.push(node("aws-lc-fips-sys", "0.14.3", &[], &[]));
    muts.push(("decoy aws-lc-fips-sys 0.14.3 beside the pin", FipsProfile::Cmvp, "G2a", g, None, true));
    let mut g = cmvp.clone();
    set(&mut g, "aws-lc-sys", &|p| {
        p.source = Some(REG.into());
        p.manifest = "/registry/aws-lc-sys-0.36.0/Cargo.toml".into();
        p.build_script = true;
    });
    muts.push(("registry aws-lc-sys present in cmvp", FipsProfile::Cmvp, "G2c", g, None, true));
    let mut g = cmvp.clone();
    g.push(node("evil", "1.0.0", &[], &[("aws-lc-sys", "0.36.0")]));
    muts.push(("a crate other than aws-lc-rs depends on aws-lc-sys", FipsProfile::Cmvp, "G2c", g, None, true));
    let mut g = cmvp.clone();
    set(&mut g, "aws-lc-rs", &|p| p.features.retain(|f| f != "fips"));
    muts.push(("aws-lc-rs without feature fips", FipsProfile::Cmvp, "G2b", g, None, true));
    let mut g = cmvp.clone();
    set(&mut g, "aws-lc-rs", &|p| {
        p.deps = vec![("aws-lc-fips-sys".into(), "0.14.3".into())];
    });
    g.retain(|p| p.name != "aws-lc-fips-sys");
    g.push(node("aws-lc-fips-sys", "0.14.3", &[], &[]));
    muts.push(("aws-lc-rs links aws-lc-fips-sys 0.14.3", FipsProfile::Cmvp, "G2b", g, None, true));
    for (prof, base) in [(FipsProfile::Cmvp, &cmvp), (FipsProfile::Floor, &floor)] {
        let mut g = base.clone();
        set(&mut g, "rustls", &|p| p.features.retain(|f| f != "prefer-post-quantum"));
        muts.push(("rustls node without prefer-post-quantum", prof, "G1", g, None, true));
        let mut g = base.clone();
        g.retain(|p| p.name != "rustls");
        muts.push(("no rustls node at all", prof, "G1", g, None, true));
    }
    // G3: the window must catch 1.17.2 even when pins.toml is edited to agree with it (the pin cannot hide it).
    let mut g = cmvp.clone();
    set(&mut g, "aws-lc-rs", &|p| p.version = "1.17.2".into());
    let mut pins2 = pins.clone();
    pins2.insert("aws-lc-rs".into(), "1.17.2".into());
    muts.push((
        "aws-lc-rs 1.17.2 (outside [1.15.2,1.17.1]) with a matching pin",
        FipsProfile::Cmvp,
        "G3",
        g,
        Some(pins2),
        true,
    ));
    let mut g = cmvp.clone();
    set(&mut g, "aws-lc-rs", &|p| p.version = "1.15.1".into());
    let mut pins2 = pins.clone();
    pins2.insert("aws-lc-rs".into(), "1.15.1".into());
    muts.push((
        "aws-lc-rs 1.15.1 (below the window) with a matching pin",
        FipsProfile::Cmvp,
        "G3",
        g,
        Some(pins2),
        true,
    ));
    let mut g = cmvp.clone();
    g.push(node("rustls", "0.23.42", &["prefer-post-quantum"], &[]));
    muts.push(("second rustls node off the pin", FipsProfile::Cmvp, "G3", g, None, true));
    let mut g = floor.clone();
    set(&mut g, "rustls", &|p| p.version = "0.23.45".into());
    muts.push(("floor rustls 0.23.45 < 0.23.46", FipsProfile::Floor, "G4", g, None, true));
    let mut g = floor.clone();
    set(&mut g, "rustls-webpki", &|p| p.version = "0.103.15".into());
    muts.push(("floor rustls-webpki 0.103.15 < 0.103.16", FipsProfile::Floor, "G4", g, None, true));
    muts.push(("cmvp rustls below floor with no ledger entry", FipsProfile::Cmvp, "G4", cmvp.clone(), None, false));
    let mut g = floor.clone();
    set(&mut g, "aws-lc-rs", &|p| {
        p.features.push("fips".into());
        p.deps.push(("aws-lc-fips-sys".into(), "0.13.11".into()));
    });
    g.push(node("aws-lc-fips-sys", "0.13.11", &[], &[]));
    muts.push(("floor lineage broken: aws-lc-fips-sys 0.13.11", FipsProfile::Floor, "G5", g, None, true));
    let total = muts.len();
    let mut caught = 0;
    for (what, prof, id, g, p2, acc) in &muts {
        let pins_m = p2.as_ref().unwrap_or(pins);
        let cxm = FipsCtx {
            pins: pins_m,
            accepted: if *acc { &accepted } else { &none },
            void_manifest: void_manifest.into(),
        };
        let (v, _) = check_fips(*prof, g, &cxm);
        if v.iter().any(|x| x.starts_with(&format!("{id}:"))) {
            caught += 1;
        } else {
            fails.push(format!("mutant '{what}' ({prof:?}) not caught by {id} (got: {v:?})"));
        }
    }
    if fails.is_empty() {
        println!("FIPS-LOCK SELF-TEST: PASS ({caught}/{total} mutants caught; cmvp and floor baselines clean)");
        Ok(())
    } else {
        for f in &fails {
            println!("  - {f}");
        }
        Err(format!("FIPS-LOCK SELF-TEST: FAIL ({caught}/{total} mutants caught)"))
    }
}
