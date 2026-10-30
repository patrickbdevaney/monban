//! The golden build never enables the `e2e-mutants` negative controls (PLAN D16), and app routes fail closed at boot.
//!
//! * No manifest in the workspace enables `aegis-bin/e2e-mutants` (directly or forwarded), and aegis-bin's
//!   `default` feature list does not contain it. The only builds with it are the oracles' explicit
//!   `--features e2e-mutants` builds into `target/e2e-mutants`.
//! * The binary under test (the golden build when this test runs without the feature) ignores
//!   `AEGIS_E2E_MUTANT`: no negative-control banner, and a config with an app route but no token key ring is refused
//!   with exit 78 (EX_CONFIG) before any socket.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
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

#[test]
fn no_manifest_enables_the_negative_controls() {
    let mut ms = Vec::new();
    manifests(&root(), &mut ms);
    assert!(ms.len() > 10, "workspace manifests not found under {}", root().display());
    let own = std::fs::read_to_string(root().join("crates/aegis-bin/Cargo.toml")).unwrap();
    let default = own.lines().find(|l| l.trim_start().starts_with("default")).unwrap_or("");
    assert!(!default.contains("e2e-mutants"), "aegis-bin default features enable e2e-mutants: {default}");
    for m in ms {
        let text = std::fs::read_to_string(&m).unwrap();
        if m.ends_with("crates/aegis-bin/Cargo.toml") {
            continue;
        }
        for l in text.lines().map(|l| l.split('#').next().unwrap_or("")) {
            assert!(
                !(l.contains("aegis-bin") && l.contains("e2e-mutants")),
                "{} enables aegis-bin/e2e-mutants: {l}",
                m.display()
            );
        }
    }
}

#[cfg(not(feature = "e2e-mutants"))]
#[test]
fn golden_binary_ignores_mutant_env_and_refuses_app_routes_without_keyring() {
    let dir = std::env::temp_dir().join(format!("aegis-golden-build-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("notes.db");
    std::fs::write(&db, b"").unwrap();
    let cfg = dir.join("aegis.json");
    std::fs::write(
        &cfg,
        format!(
            r#"{{"v":1,"listeners":[{{"name":"pub","bind":"127.0.0.1:1","profile":"P-PUBLIC-WEB"}}],
               "data":{{"backends":[{{"id":"sq","engine":"sqlite","dsn_ref":"path:{}","pin":"sqlite"}}]}},
               "vhosts":[{{"host":"aegis.test","routes":[{{"id":1,"path":"/n/","to":{{"upstream":"app:notes"}},
               "authz":"allow-all"}}]}}]}}"#,
            db.display()
        ),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_aegis"))
        .args(["--config", cfg.to_str().unwrap(), "--audit-dir", dir.join("audit").to_str().unwrap()])
        .env("AEGIS_E2E_MUTANT", "tenant-from-path,commit-despite-cancel,body-before-cp,empty-caps-means-all")
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(78), "{err}");
    assert!(err.contains("token-keyring"), "{err}");
    assert!(!err.contains("NEGATIVE-CONTROL"), "golden build honoured AEGIS_E2E_MUTANT: {err}");
}
