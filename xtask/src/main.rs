//! Repository gates. Each command prints `<NAME>: PASS|FAIL` and exits non-zero on failure.
//! Every gate has a `--self-test` negative control that must report a violation on a mutated input.
//!
//!   cargo xtask layering [--self-test]
//!   cargo xtask lock-targets [--self-test]
//!   cargo xtask lock-age [--min-days N] [--self-test]
//!   cargo xtask repo-advisories [--self-test]
//!   cargo xtask fips-lock --profile cmvp [--self-test]
//!   cargo xtask metrics-check [--self-test]
//!   cargo xtask budget [--self-test]
#![forbid(unsafe_code)]

mod budget;
mod json;
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
        Some("metrics-check") => metrics::metrics_check(self_test),
        Some("fips-lock") => fips_lock(&opt("--profile").unwrap_or_else(|| "cmvp".into()), self_test),
        _ => {
            eprintln!(
                "usage: cargo xtask <layering|lock-targets|lock-age|repo-advisories|fips-lock|metrics-check|budget> [--self-test]"
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
    Tool,
}

#[derive(Clone, Debug)]
struct Pkg {
    name: String,
    dir: PathBuf,
    layer: Option<Layer>,
    /// (dependency name, kind, enabled features) for workspace-path dependencies only.
    deps: Vec<(String, String, Vec<String>)>,
}

/// Constructor-gate modules of aegis-types and the only crate allowed to use each (REPO_LAYOUT §3, F2).
const OWNERS: &[(&str, &str, &str)] = &[
    ("authn-path", "authn_path", "aegis-token"),
    ("canon-owner", "canon_owner", "aegis-canon"),
    ("raw-owner", "raw_owner", "aegis-transport"),
];
/// Same-layer edges allowed by the crate table (REPO_LAYOUT §4). Everything else must point strictly downward.
const INTRA_LAYER: &[(&str, &str)] = &[("aegis-admission", "aegis-budget"), ("aegis-config", "aegis-canon")];
/// Crates permitted to relax `forbid(unsafe_code)` (each call site audited, ≤20 sites).
const UNSAFE_ALLOWED: &[&str] = &["aegis-iso"];

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
        pkgs.push(Pkg { name, dir: manifest.parent().map(Path::to_path_buf).unwrap_or_default(), layer, deps });
    }
    Ok(pkgs)
}

fn check_layering(pkgs: &[Pkg]) -> Vec<String> {
    let mut v = Vec::new();
    let layer_of: BTreeMap<&str, &Option<Layer>> = pkgs.iter().map(|p| (p.name.as_str(), &p.layer)).collect();
    for p in pkgs {
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
                (Layer::N(_), Layer::Sdk) | (Layer::Sdk, Layer::Sdk) => false,
                (Layer::N(a), Layer::N(b)) => {
                    b < a || (a == b && INTRA_LAYER.contains(&(p.name.as_str(), dn.as_str())))
                }
            };
            if !ok {
                v.push(format!("{} ({pl:?}) -> {dn} ({dl:?}) [{kind}]: upward or cross-zone edge", p.name));
            }
            if dn == "aegis-types" {
                for f in feats {
                    if let Some((_, _, owner)) = OWNERS.iter().find(|(feat, _, _)| feat == f)
                        && p.name != *owner
                    {
                        v.push(format!("{} enables aegis-types/{f}; only {owner} may", p.name));
                    }
                }
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
            for (_, module, owner) in OWNERS {
                if p.name != *owner && p.name != "aegis-types" && src.contains(&format!("{module}::")) {
                    v.push(format!("{}: {} uses aegis_types::{module} (owner: {owner})", p.name, f.display()));
                }
            }
        }
    }
    v
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
    }
    let mut v = check_layering(&pkgs);
    if !self_test {
        v.extend(check_sources(&pkgs));
    }
    if self_test {
        for want in ["aegis-transport (N(3)) -> aegis-adapter-pg", "aegis-agent enables aegis-types/authn-path"] {
            if !v.iter().any(|x| x.starts_with(want)) {
                return Err(format!("LAYERING SELF-TEST: FAIL (injected violation not reported: {want})"));
            }
        }
    }
    verdict("LAYERING", &v, self_test)
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
            deps: vec![],
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
    let pkgs = read_lock()?;
    let exc = exceptions();
    let mut v = Vec::new();
    let mut ages: Vec<(String, String, i64)> = Vec::new();
    for p in pkgs.iter().filter(|p| p.source.as_deref().is_some_and(|s| s.starts_with("registry+"))) {
        let j = curl_json(&format!("https://crates.io/api/v1/crates/{}/{}", p.name, p.version), None)?;
        let created = j
            .path(&["version", "created_at"])
            .and_then(Json::str)
            .and_then(rfc3339_day)
            .ok_or(format!("{}: no created_at", p.name))?;
        ages.push((p.name.clone(), p.version.clone(), today() - created));
    }
    if self_test {
        ages.push(("selftest-fresh-crate".into(), "0.0.1".into(), 0));
    }
    for (n, ver, age) in &ages {
        if (*age as u64) < min_days && !exc.contains(&(n.clone(), ver.clone())) {
            v.push(format!("{n} {ver} published {age} d ago (< {min_days} d) with no live exception"));
        }
    }
    println!("lock-age: {} registry packages checked (min {min_days} d)", ages.len());
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

// ---------------------------------------------------------------- FIPS lock (Phase 6 gate; usable from Phase 0)

fn check_fips_lock(pkgs: &[lock::LockPkg], pins: &BTreeMap<String, String>) -> Vec<String> {
    let mut v = Vec::new();
    let fips: Vec<&lock::LockPkg> = pkgs.iter().filter(|p| p.name == "aws-lc-fips-sys").collect();
    if fips.len() != 1 {
        v.push(format!("expected exactly one aws-lc-fips-sys node, found {}", fips.len()));
    }
    if pkgs.iter().any(|p| p.name == "aws-lc-sys") {
        v.push("non-FIPS aws-lc-sys present in the cmvp lock".into());
    }
    let reach = pkgs.iter().any(|p| p.name == "aws-lc-rs" && p.deps.iter().any(|d| d.starts_with("aws-lc-fips-sys")));
    if !reach {
        v.push("aws-lc-fips-sys not reachable from aws-lc-rs".into());
    }
    for (n, want) in pins {
        match pkgs.iter().find(|p| &p.name == n) {
            Some(p) if &p.version == want => {}
            Some(p) => v.push(format!("{n}: {} != pinned {want}", p.version)),
            None => v.push(format!("{n}: pinned but absent")),
        }
    }
    v
}

fn fips_lock(profile: &str, self_test: bool) -> Result<(), String> {
    let dir = root().join("profiles").join(profile);
    let pins = lock::parse_kv(
        &std::fs::read_to_string(dir.join("pins.toml")).map_err(|e| format!("{profile}/pins.toml: {e}"))?,
    );
    let mut pkgs = match std::fs::read_to_string(dir.join("Cargo.lock")) {
        Ok(s) => lock::parse_lock(&s)?,
        Err(_) => Vec::new(),
    };
    if self_test {
        pkgs.push(lock::LockPkg {
            name: "aws-lc-fips-sys".into(),
            version: "0.14.3".into(),
            source: None,
            deps: vec![],
        });
    }
    verdict("FIPS-LOCK", &check_fips_lock(&pkgs, &pins), self_test)
}
