//! `cargo xtask metrics-check [--self-test]` (Phase-2 metrics gate, ARCHITECTURE §3.10).
//!
//! Runs the `aegis-metrics` `dump` example with no default features (metrics are always compiled, no feature
//! flag) and checks that every family in the crate's `GOLDEN` table, and every family this gate requires on its
//! own, appears in the exposition with a matching `# TYPE` line and at least one sample, and that the exposition
//! ends with `# EOF`. `--self-test` deletes one golden family from the dump and must report it missing.
//!
//! Self-contained (std only, no `super::` items) so it can also be compiled on its own for its tests.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Families the gate requires independently of the crate's `GOLDEN` table, so trimming `GOLDEN` cannot pass.
/// Name and OpenMetrics type.
pub const REQUIRED: &[(&str, &str)] = &[
    ("aegis_admission_rejects", "counter"),
    ("aegis_budget_debits", "counter"),
    ("aegis_crash_budget_trips", "counter"),
    ("aegis_cert_seconds_to_expiry", "gauge"),
    ("aegis_fips_status", "gauge"),
    ("aegis_config_generation_hash", "gauge"),
    ("aegis_config_lkg_fallbacks", "counter"),
    ("aegis_upgrade_forced_closes", "counter"),
];

/// One `GOLDEN` row as printed by `dump --golden`: `name type label,label`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoldenRow {
    /// Family name.
    pub name: String,
    /// `counter` or `gauge`.
    pub kind: String,
    /// Label names.
    pub labels: Vec<String>,
}

fn repo_root() -> PathBuf {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.parent().map(Path::to_path_buf).unwrap_or(here)
}

/// Runs the dump example (through `ci/heavy.sh`, which is reentrant) and returns its stdout.
fn run_dump(extra: &[&str]) -> Result<String, String> {
    let root = repo_root();
    let mut cmd = Command::new(root.join("ci/heavy.sh"));
    cmd.current_dir(&root).args([
        "cargo",
        "run",
        "-q",
        "-p",
        "aegis-metrics",
        "--example",
        "dump",
        "--no-default-features",
    ]);
    if !extra.is_empty() {
        cmd.arg("--").args(extra);
    }
    let out = cmd.output().map_err(|e| format!("spawn {cmd:?}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{cmd:?} failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    String::from_utf8(out.stdout).map_err(|e| e.to_string())
}

/// Parses `dump --golden` output.
pub fn parse_golden(text: &str) -> Result<Vec<GoldenRow>, String> {
    let mut rows = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut parts = line.split(' ');
        let (Some(name), Some(kind)) = (parts.next(), parts.next()) else {
            return Err(format!("bad GOLDEN row {line:?}"));
        };
        let labels = parts.next().unwrap_or("").split(',').filter(|s| !s.is_empty()).map(str::to_owned).collect();
        rows.push(GoldenRow { name: name.to_owned(), kind: kind.to_owned(), labels });
    }
    if rows.is_empty() {
        return Err("GOLDEN table is empty".into());
    }
    Ok(rows)
}

fn sample_name_matches(sample_line: &str, want: &str) -> bool {
    sample_line.strip_prefix(want).is_some_and(|rest| rest.starts_with('{') || rest.starts_with(' '))
}

/// Returns one violation per missing or malformed golden family in `exposition`.
pub fn check_exposition(exposition: &str, golden: &[GoldenRow]) -> Vec<String> {
    let mut v = Vec::new();
    for (name, kind) in REQUIRED {
        if !golden.iter().any(|g| g.name == *name && g.kind == *kind) {
            v.push(format!("GOLDEN table lacks required family {name} ({kind})"));
        }
    }
    let lines: Vec<&str> = exposition.lines().collect();
    if lines.last().copied() != Some("# EOF") {
        v.push("exposition does not end with '# EOF'".into());
    }
    if lines.iter().filter(|l| **l == "# EOF").count() != 1 {
        v.push("exposition must contain exactly one '# EOF'".into());
    }
    for g in golden {
        let type_line = format!("# TYPE {} {}", g.name, g.kind);
        let types = lines.iter().filter(|l| l.starts_with(&format!("# TYPE {} ", g.name))).count();
        if !lines.contains(&type_line.as_str()) {
            v.push(format!("{} missing ('{type_line}' not found)", g.name));
            continue;
        }
        if types != 1 {
            v.push(format!("{} has {types} TYPE lines", g.name));
        }
        let sample = if g.kind == "counter" { format!("{}_total", g.name) } else { g.name.clone() };
        let samples: Vec<&&str> = lines.iter().filter(|l| sample_name_matches(l, &sample)).collect();
        if samples.is_empty() {
            v.push(format!("{} has no '{sample}' samples", g.name));
        }
        for l in samples {
            let ok =
                g.labels.iter().all(|k| l.contains(&format!("{k}=\""))) && (g.labels.is_empty() != l.contains('{'));
            if !ok {
                v.push(format!("{} sample has wrong labels: {l}", g.name));
            }
        }
    }
    v
}

/// Removes every line that belongs to `family` (metadata and samples): the self-test mutation.
pub fn drop_family(exposition: &str, family: &str) -> String {
    exposition
        .lines()
        .filter(|l| {
            let meta = ["# TYPE ", "# UNIT ", "# HELP "].iter().any(|p| l.starts_with(&format!("{p}{family} ")));
            !(meta || sample_name_matches(l, family) || sample_name_matches(l, &format!("{family}_total")))
        })
        .map(|l| format!("{l}\n"))
        .collect()
}

/// Pure core of the gate (also used by the tests): checks `exposition` against `golden`, or, in self-test
/// mode, drops the first golden family and requires a violation.
pub fn evaluate(exposition: &str, golden: &[GoldenRow], self_test: bool) -> Result<String, String> {
    if self_test {
        let victim = golden.first().map(|g| g.name.clone()).ok_or("GOLDEN table is empty")?;
        let mutated = drop_family(exposition, &victim);
        let v = check_exposition(&mutated, golden);
        if v.iter().any(|m| m.starts_with(&victim)) {
            return Ok(format!("METRICS-CHECK SELF-TEST: PASS (mutated input rejected: {})", v.join("; ")));
        }
        return Err(format!("METRICS-CHECK SELF-TEST: FAIL (dropping {victim} was not reported)"));
    }
    let v = check_exposition(exposition, golden);
    if v.is_empty() {
        Ok(format!("METRICS-CHECK: PASS ({} golden families present)", golden.len()))
    } else {
        Err(format!("METRICS-CHECK: FAIL ({} violations)\n  - {}", v.len(), v.join("\n  - ")))
    }
}

/// Entry point for `cargo xtask metrics-check [--self-test]`.
pub fn metrics_check(self_test: bool) -> Result<(), String> {
    let golden = parse_golden(&run_dump(&["--golden"])?)?;
    let exposition = run_dump(&[])?;
    let msg = evaluate(&exposition, &golden, self_test)?;
    println!("{msg}");
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    const GOLDEN_TXT: &str = "a_c counter stage\na_g gauge \n";
    const GOOD: &str = "# TYPE a_c counter\n# HELP a_c h\na_c_total{stage=\"S0\"} 0\n\
                        # TYPE a_g gauge\n# HELP a_g h\na_g 0\n# EOF\n";

    fn rows() -> Vec<GoldenRow> {
        let mut r = parse_golden(GOLDEN_TXT).unwrap();
        // satisfy REQUIRED for the synthetic cases
        r.extend(REQUIRED.iter().map(|(n, k)| GoldenRow { name: (*n).into(), kind: (*k).into(), labels: vec![] }));
        r
    }

    fn good_full() -> String {
        let mut s = GOOD.strip_suffix("# EOF\n").unwrap().to_owned();
        for (n, k) in REQUIRED {
            let sample = if *k == "counter" { format!("{n}_total") } else { (*n).to_owned() };
            s.push_str(&format!("# TYPE {n} {k}\n{sample} 0\n"));
        }
        s + "# EOF\n"
    }

    #[test]
    fn synthetic_pass_and_failures() {
        let g = rows();
        assert!(evaluate(&good_full(), &g, false).is_ok());
        assert!(evaluate(&good_full(), &g, true).is_ok());
        let no_eof = good_full().replace("# EOF\n", "");
        assert!(check_exposition(&no_eof, &g).iter().any(|m| m.contains("EOF")));
        let wrong_type = good_full().replace("# TYPE a_g gauge", "# TYPE a_g counter");
        assert!(!check_exposition(&wrong_type, &g).is_empty());
        let no_label = good_full().replace("a_c_total{stage=\"S0\"} 0", "a_c_total 0");
        assert!(!check_exposition(&no_label, &g).is_empty());
        let trimmed: Vec<GoldenRow> = g.iter().filter(|r| r.name != "aegis_fips_status").cloned().collect();
        assert!(check_exposition(&good_full(), &trimmed).iter().any(|m| m.contains("lacks required")));
        assert!(drop_family(&good_full(), "a_c").lines().all(|l| !l.contains("a_c")));
    }

    /// Demonstration on the real crate: runs `cargo run -p aegis-metrics --example dump` and checks it.
    /// Ignored by default because it spawns a cargo build; run with `--ignored`.
    #[test]
    #[ignore = "spawns cargo; run explicitly with --ignored"]
    fn real_dump_passes_and_self_test_rejects() {
        metrics_check(false).unwrap();
        metrics_check(true).unwrap();
        let golden = parse_golden(&run_dump(&["--golden"]).unwrap()).unwrap();
        assert_eq!(golden.len(), REQUIRED.len());
        let exposition = run_dump(&[]).unwrap();
        for g in &golden {
            let mutated = drop_family(&exposition, &g.name);
            let err = evaluate(&mutated, &golden, false).unwrap_err();
            assert!(err.contains(&format!("{} missing", g.name)), "{err}");
        }
    }
}
