//! P2 golden builds (PLAN-5 D15): the default build and the shipped p2 build enable neither `test-hooks` nor
//! `mutants` nor `p2-mutants` on any crate.
//!
//! * Manifests: no workspace manifest enables `aegis-bin/p2-mutants` or `aegis-p2/{test-hooks,mutants}`; the only
//!   manifests that name `aegis-iso`/`aegis-wasm` `test-hooks`/`mutants` are aegis-p2's and aegis-bin's own feature
//!   lists and the test subject p2-subject (never built in one cargo invocation with aegis-p2 or aegis-bin, D18).
//!   aegis-bin's and aegis-p2's `default` lists are empty and aegis-bin's `p2` enables no test-only feature.
//! * Resolution: `cargo tree -e features` of the default build, of `-p aegis-bin --features aegis-bin/p2`, and of
//!   the gate's shipped build (`-p aegis-bin --features aegis-bin/p2 -p aegis-p2`, one invocation, so features
//!   unify as they do there) shows no `test-hooks`, `mutants`, `p2-mutants` or `e2e-mutants` feature on any crate.
//!   Positive controls: the same filter sees them in a `p2-mutants` and a `test-hooks` resolution.
//! * The binary under test (unless built with `p2-mutants`) ignores `AEGIS_P2_MUTANT` (no P2 negative-control
//!   banner) and refuses a config with a wasm route whose worker is missing with exit 78 before any socket: in the
//!   core build because there is no P2 supervisor, in the `p2` build because the sandboxed compile cannot run.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn manifests(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        if p.is_dir() {
            if !matches!(name.as_str(), "target" | ".git" | ".claude" | "research" | "node_modules" | ".lake") {
                manifests(&p, out);
            }
        } else if name == "Cargo.toml" {
            out.push(p);
        }
    }
}

/// Manifests that may name the P2 test-only features: their own definitions and the test subject (D15, D18).
const P2_FEATURE_OWNERS: &[&str] =
    &["crates/aegis-p2/Cargo.toml", "crates/aegis-bin/Cargo.toml", "subjects/p2-subject/Cargo.toml"];

fn line_starting<'a>(text: &'a str, key: &str) -> &'a str {
    text.lines().find(|l| l.trim_start().starts_with(key)).map(|l| l.split('#').next().unwrap_or("")).unwrap_or("")
}

#[test]
fn no_manifest_enables_the_p2_test_features() {
    let root = root();
    let mut ms = Vec::new();
    manifests(&root, &mut ms);
    assert!(ms.len() > 10, "workspace manifests not found under {}", root.display());
    let bin = std::fs::read_to_string(root.join("crates/aegis-bin/Cargo.toml")).unwrap();
    assert_eq!(line_starting(&bin, "default").replace(' ', ""), "default=[]");
    let p2 = line_starting(&bin, "p2 ");
    assert!(p2.contains("dep:aegis-iso"), "aegis-bin feature p2 not found: {p2:?}");
    assert!(!p2.contains("mutants") && !p2.contains("test-hooks"), "aegis-bin p2 enables a test feature: {p2}");
    let worker = std::fs::read_to_string(root.join("crates/aegis-p2/Cargo.toml")).unwrap();
    assert_eq!(line_starting(&worker, "default").replace(' ', ""), "default=[]");
    for m in ms {
        let rel = m.strip_prefix(&root).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        let owner = P2_FEATURE_OWNERS.iter().any(|o| rel == *o);
        let text = std::fs::read_to_string(&m).unwrap();
        for l in text.lines().map(|l| l.split('#').next().unwrap_or("")) {
            assert!(!(l.contains("aegis-bin") && l.contains("p2-mutants")), "{rel} enables aegis-bin/p2-mutants: {l}");
            assert!(
                !(l.contains("aegis-p2") && (l.contains("test-hooks") || l.contains("mutants"))),
                "{rel} enables an aegis-p2 test-only feature: {l}"
            );
            let lower = l.contains("aegis-iso") || l.contains("aegis-wasm");
            let test_feature = l.contains("test-hooks") || l.contains("mutants");
            assert!(!(lower && test_feature) || owner, "{rel} enables an aegis-iso/aegis-wasm test feature: {l}");
        }
    }
}

/// The crates that carry a test-only feature (D15) and the features they must not have in a golden build.
const WATCHED: &[&str] = &["aegis-bin", "aegis-iso", "aegis-wasm", "aegis-p2", "aegis-transport"];
const TEST_FEATURES: &[&str] = &["test-hooks", "mutants", "p2-mutants", "e2e-mutants", "e2e-raw-target"];

/// The features of `pkg` that the build `args` resolves (`cargo tree -e features -i <pkg>`: the inverted tree is
/// the form that also lists the features a root's command-line features enable). `None`: `pkg` is not in it.
fn resolved_features(pkg: &str, args: &[&str]) -> Option<Vec<String>> {
    let out = std::process::Command::new(env!("CARGO"))
        .current_dir(root())
        .args(["tree", "--locked", "--offline", "-e", "features", "--prefix", "none", "-i", pkg])
        .args(args)
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() && err.contains("did not match any packages") {
        return None;
    }
    assert!(out.status.success(), "cargo tree -i {pkg} {args:?}: {err}");
    let text = String::from_utf8(out.stdout).unwrap();
    let head = format!("{pkg} feature \"");
    let mut v: Vec<String> = text
        .lines()
        .filter_map(|l| l.strip_prefix(head.as_str()))
        .filter_map(|r| r.split('"').next().map(str::to_string))
        .collect();
    v.sort();
    v.dedup();
    Some(v)
}

/// Every `crate/feature` test-only pair the build `args` enables.
fn test_features(args: &[&str]) -> Vec<String> {
    let mut hits = Vec::new();
    for pkg in WATCHED {
        for f in resolved_features(pkg, args).unwrap_or_default() {
            if TEST_FEATURES.contains(&f.as_str()) {
                hits.push(format!("{pkg}/{f}"));
            }
        }
    }
    hits
}

#[test]
fn default_and_p2_builds_resolve_no_test_feature() {
    for args in [
        &["-p", "aegis-bin"][..],
        &["-p", "aegis-bin", "--features", "aegis-bin/p2"][..],
        &["-p", "aegis-bin", "--features", "aegis-bin/p2", "-p", "aegis-p2"][..],
    ] {
        assert_eq!(test_features(args), Vec::<String>::new(), "golden build {args:?}");
        // `p2` is resolved exactly when asked for, and it brings aegis-iso (its one dependency) into the graph.
        let bin = resolved_features("aegis-bin", args).unwrap();
        let p2 = args.contains(&"aegis-bin/p2");
        assert_eq!(bin.iter().any(|f| f == "p2"), p2, "aegis-bin features {bin:?} for {args:?}");
        assert_eq!(resolved_features("aegis-iso", args).is_some(), p2, "aegis-iso presence for {args:?}");
    }
    // Positive controls: the same check sees the features where a negative-control or test build enables them.
    let hits = test_features(&["-p", "aegis-bin", "--features", "aegis-bin/p2-mutants"]);
    assert!(hits.iter().any(|h| h == "aegis-bin/p2-mutants") && hits.iter().any(|h| h == "aegis-iso/mutants"));
    let hits = test_features(&["-p", "aegis-p2", "--features", "aegis-p2/test-hooks"]);
    assert!(hits.iter().any(|h| h == "aegis-iso/test-hooks") && hits.iter().any(|h| h == "aegis-wasm/test-hooks"));
    let hits = test_features(&["-p", "aegis-p2", "--features", "aegis-p2/mutants"]);
    assert!(hits.iter().any(|h| h == "aegis-wasm/mutants"), "{hits:?}");
}

#[cfg(not(feature = "p2-mutants"))]
#[test]
fn golden_binary_ignores_p2_mutant_env_and_refuses_a_wasm_route_without_worker() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    let dir = std::env::temp_dir().join(format!("aegis-golden-p2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // The module's digest matches, so the boot gets as far as the (missing) worker.
    let wasm: &[u8] = b"\0asm\x01\0\0\0";
    let module = dir.join("m.wasm");
    std::fs::write(&module, wasm).unwrap();
    let digest = aegis_config::hex(&aegis_config::sha256(wasm));
    let kr = dir.join("kr.json");
    std::fs::write(&kr, format!(r#"{{"keys":[{{"kid":"6b","key":"{}"}}]}}"#, "11".repeat(32))).unwrap();
    std::fs::set_permissions(&kr, std::fs::Permissions::from_mode(0o600)).unwrap();
    let cfg = dir.join("aegis.json");
    std::fs::write(
        &cfg,
        format!(
            r#"{{"v":1,"listeners":[{{"name":"pub","bind":"127.0.0.1:1","profile":"P-PUBLIC-WEB"}}],
               "p2":{{"worker":"/nonexistent/aegis-p2","cache_dir":"{}",
                      "modules":[{{"id":"m","path":"{}","sha256":"{digest}"}}]}},
               "vhosts":[{{"host":"aegis.test","routes":[{{"id":1,"path":"/m/","to":{{"wasm":"m"}},
               "authz":"allow-all"}}]}}]}}"#,
            dir.join("cache").display(),
            module.display()
        ),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_aegis"))
        .args(["--config", cfg.to_str().unwrap(), "--audit-dir", dir.join("audit").to_str().unwrap()])
        .args(["--token-keyring", kr.to_str().unwrap(), "--runtime-dir", dir.to_str().unwrap()])
        .env("AEGIS_P2_MUTANT", "boot-without-landlock-accepted")
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(78), "{err}");
    let why = if cfg!(feature = "p2") { "/nonexistent/aegis-p2" } else { "feature `p2`" };
    assert!(err.contains(why), "{err}");
    assert!(!err.contains("NEGATIVE-CONTROL"), "golden build honoured AEGIS_P2_MUTANT: {err}");
}
