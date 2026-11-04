//! `cargo xtask ledger-check [--ledger PATH] [--evidence-dir DIR] [--self-test]` (PLAN-6 D10).
//!
//! Validates `supply-chain/exceptions.toml`, the expiring exception ledger:
//! - every `[[exception]]` has non-empty `crate`, `version`, `kind`, `reason`, `approver` and `expires`;
//! - `expires` is a real `YYYY-MM-DD` date and is not before today (UTC, system clock);
//! - `kind` is `cooldown-bypass` or `advisory-accepted`; unknown keys and duplicate keys are errors;
//! - an `advisory-accepted` entry also names `advisory`, `evidence` (a gate log path) and `evidence_must` (a literal
//!   line). The log, looked up by file name under `--evidence-dir` (default `gates/out/logs`), must exist, contain
//!   `evidence_must` as a whole line, end in `[exit 0]` (ci/run-gates.py's log trailer), and have been written in the
//!   current gate run: its mtime must be at or after the mtime of `<evidence-dir>/.run-start`, which
//!   ci/run-gates.py writes before its first step. No marker means no proof of freshness, so the check fails closed.
//!
//! The ledger is parsed by a strict subset-of-TOML reader (xtask has no dependencies on purpose): comments, blank
//! lines, `[[exception]]` headers and `key = "basic string"` pairs. Anything else is an error, so a malformed entry can
//! never be skipped silently.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const NAME: &str = "LEDGER-CHECK";
const KINDS: &[&str] = &["cooldown-bypass", "advisory-accepted"];
const REQUIRED: &[&str] = &["crate", "version", "kind", "reason", "approver", "expires"];
const KNOWN: &[&str] =
    &["crate", "version", "kind", "advisory", "reason", "approver", "expires", "evidence", "evidence_must"];
const MARKER: &str = ".run-start";

pub fn run(args: &[String]) -> Result<(), String> {
    let args: Vec<&str> = args.iter().map(String::as_str).filter(|a| *a != "ledger-check").collect();
    let opt = |f: &str| args.iter().position(|a| *a == f).and_then(|i| args.get(i + 1)).map(|s| PathBuf::from(*s));
    if args.contains(&"--self-test") {
        return self_test();
    }
    let root = super::root();
    let ledger = opt("--ledger").map_or_else(|| root.join("supply-chain/exceptions.toml"), |p| root.join(p));
    let evidence_dir = opt("--evidence-dir").map_or_else(|| root.join("gates/out/logs"), |p| root.join(p));
    let text =
        std::fs::read_to_string(&ledger).map_err(|e| format!("{NAME}: FAIL (read {}: {e})", ledger.display()))?;
    let (n, v) = check(&text, &evidence_dir, super::today());
    if v.is_empty() {
        println!("{NAME}: PASS ({n} entries, none expired, all advisory-accepted evidence fresh)");
        Ok(())
    } else {
        for x in &v {
            println!("  - {x}");
        }
        Err(format!("{NAME}: FAIL ({} violation(s) in {n} entries)", v.len()))
    }
}

/// Returns (entry count, violations).
fn check(text: &str, evidence_dir: &Path, today: i64) -> (usize, Vec<String>) {
    let (entries, mut v) = parse(text);
    let marker = mtime(&evidence_dir.join(MARKER));
    for (line, e) in &entries {
        let id = format!(
            "entry at line {line} ({}@{})",
            e.get("crate").map_or("?", String::as_str),
            e.get("version").map_or("?", String::as_str)
        );
        for k in REQUIRED {
            if e.get(*k).is_none_or(|x| x.trim().is_empty()) {
                v.push(format!("{id}: missing or empty `{k}`"));
            }
        }
        for k in e.keys() {
            if !KNOWN.contains(&k.as_str()) {
                v.push(format!("{id}: unknown key `{k}`"));
            }
        }
        if let Some(x) = e.get("expires") {
            match parse_date(x) {
                None => v.push(format!("{id}: `expires = \"{x}\"` is not a valid YYYY-MM-DD date")),
                Some(d) if d < today => v.push(format!("{id}: expired on {x}")),
                Some(_) => {}
            }
        }
        match e.get("kind").map(String::as_str) {
            None => {}
            Some(k) if !KINDS.contains(&k) => v.push(format!("{id}: unknown kind `{k}` (known: {})", KINDS.join(", "))),
            Some("advisory-accepted") => evidence(&id, e, evidence_dir, marker, &mut v),
            Some(_) => {}
        }
    }
    (entries.len(), v)
}

fn evidence(id: &str, e: &BTreeMap<String, String>, dir: &Path, marker: Option<SystemTime>, v: &mut Vec<String>) {
    for k in ["advisory", "evidence", "evidence_must"] {
        if e.get(k).is_none_or(|x| x.trim().is_empty()) {
            v.push(format!("{id}: advisory-accepted needs `{k}`"));
        }
    }
    let (Some(ev), Some(must)) = (e.get("evidence"), e.get("evidence_must")) else { return };
    if ev.trim().is_empty() || must.trim().is_empty() {
        return;
    }
    let p = Path::new(ev);
    if p.is_absolute() || p.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        v.push(format!("{id}: evidence `{ev}` must be a relative path without `..`"));
        return;
    }
    let Some(file) = p.file_name() else {
        v.push(format!("{id}: evidence `{ev}` has no file name"));
        return;
    };
    let path = dir.join(file);
    let Ok(log) = std::fs::read_to_string(&path) else {
        v.push(format!("{id}: evidence log {} does not exist or is unreadable", path.display()));
        return;
    };
    if !log.lines().any(|l| l.trim_end() == must.as_str()) {
        v.push(format!("{id}: evidence log {} has no line `{must}`", path.display()));
    }
    let last = log.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("");
    if last.trim() != "[exit 0]" {
        v.push(format!("{id}: evidence log {} does not end in `[exit 0]` (last line `{last}`)", path.display()));
    }
    match (marker, mtime(&path)) {
        (None, _) => v.push(format!(
            "{id}: no run marker {} (ci/run-gates.py writes it at run start), so evidence freshness is unproven",
            dir.join(MARKER).display()
        )),
        (Some(_), None) => v.push(format!("{id}: cannot read mtime of {}", path.display())),
        (Some(m), Some(t)) if t < m => v.push(format!(
            "{id}: evidence log {} predates the current gate run (written before {MARKER}): its sha is from another run",
            path.display()
        )),
        _ => {}
    }
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

type Entry = BTreeMap<String, String>;

/// Strict reader for the ledger's TOML subset. Returns (header line, entry) pairs and syntax violations.
fn parse(text: &str) -> (Vec<(usize, Entry)>, Vec<String>) {
    let mut out: Vec<(usize, Entry)> = Vec::new();
    let mut v = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        let l = raw.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if l == "[[exception]]" {
            out.push((n, BTreeMap::new()));
            continue;
        }
        let Some((k, rest)) = l.split_once('=') else {
            v.push(format!("line {n}: not `[[exception]]`, a comment or `key = \"value\"`: `{l}`"));
            continue;
        };
        let k = k.trim();
        if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            v.push(format!("line {n}: bad key `{k}`"));
            continue;
        }
        let Some(val) = basic_string(rest.trim()) else {
            v.push(format!("line {n}: value of `{k}` is not a single-line basic string"));
            continue;
        };
        let Some((_, e)) = out.last_mut() else {
            v.push(format!("line {n}: `{k}` outside any [[exception]]"));
            continue;
        };
        if e.insert(k.to_string(), val).is_some() {
            v.push(format!("line {n}: duplicate key `{k}`"));
        }
    }
    (out, v)
}

/// `"..."` with `\"` and `\\` escapes, optionally followed by a `#` comment.
fn basic_string(s: &str) -> Option<String> {
    let mut it = s.strip_prefix('"')?.chars();
    let mut out = String::new();
    loop {
        match it.next()? {
            '"' => break,
            '\\' => match it.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                _ => return None,
            },
            c => out.push(c),
        }
    }
    let tail: String = it.collect();
    let tail = tail.trim();
    (tail.is_empty() || tail.starts_with('#')).then_some(out)
}

fn parse_date(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 10 || b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?;
        t.bytes().all(|c| c.is_ascii_digit()).then(|| t.parse().ok())?
    };
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let max = *dim.get(usize::try_from(m.checked_sub(1)?).ok()?)?;
    (1..=max).contains(&d).then(|| super::days_from_civil(y, m, d))
}

/// Inverse of `days_from_civil` (Howard Hinnant's algorithm), for building self-test dates.
fn civil(z: i64) -> String {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

// ---- self-test -----------------------------------------------------------------------------------------------------

const MUST: &str = "CLIENT-POLICY: PASS (compiled-out)";
const LOG: &str = "phase6-cmvp-client-policy-cmd.log";

fn clean_ledger(today: i64) -> String {
    let exp = civil(today + 30);
    format!(
        "# header comment\n\n[[exception]]\ncrate = \"a\"\nversion = \"1.0.0\"\nkind = \"cooldown-bypass\"\n\
         reason = \"r\"\napprover = \"spec-author\"\nexpires = \"{exp}\"\n\n[[exception]]\ncrate = \"aws-lc-rs\"\n\
         version = \"1.15.3\"\nkind = \"advisory-accepted\"\nadvisory = \"RUSTSEC-2026-0349\"\nreason = \"r\"\n\
         approver = \"spec-author\"\nexpires = \"{exp}\"\nevidence = \"gates/out/logs/{LOG}\"\n\
         evidence_must = \"{MUST}\"\n"
    )
}

fn good_log() -> String {
    format!("$ oracles/cmvp-binary/client-policy --mode compiled-out\nchecking\n{MUST}\n\n[exit 0]\n")
}

/// Fixture: ledger text, log content (None = absent), marker present, log older than marker.
struct Case {
    name: &'static str,
    ledger: String,
    log: Option<String>,
    marker: bool,
    stale: bool,
}

fn case(name: &'static str, ledger: String) -> Case {
    Case { name, ledger, log: Some(good_log()), marker: true, stale: false }
}

fn without(ledger: &str, key: &str, nth: usize) -> String {
    // Drops the nth (0-based) line starting with `key =`.
    let mut seen = 0;
    ledger
        .lines()
        .filter(|l| {
            if l.starts_with(&format!("{key} =")) {
                seen += 1;
                return seen - 1 != nth;
            }
            true
        })
        .map(|l| format!("{l}\n"))
        .collect()
}

fn self_test() -> Result<(), String> {
    let today = super::today();
    let clean = clean_ledger(today);
    let exp = civil(today + 30);
    let mut mutants = vec![
        case("expired entry", clean.replacen(&exp, &civil(today - 1), 1)),
        case("missing approver", without(&clean, "approver", 0)),
        case("missing reason", without(&clean, "reason", 0)),
        case("missing expires", without(&clean, "expires", 0)),
        case("empty approver", clean.replacen("approver = \"spec-author\"", "approver = \"\"", 1)),
        case("invalid expires date", clean.replacen(&exp, "2026-02-30", 1)),
        case("unknown kind", clean.replacen("cooldown-bypass", "cooldown-bypas", 1)),
        case("unknown key", clean.replacen("approver =", "aprover = \"x\"\napprover =", 1)),
        case("duplicate key", clean.replacen("reason = \"r\"", "reason = \"r\"\nreason = \"s\"", 1)),
        case("unparseable line", format!("{clean}crate: oops\n")),
        case("advisory-accepted without evidence", without(&clean, "evidence", 0)),
        case("advisory-accepted without evidence_must", without(&clean, "evidence_must", 0)),
        case("advisory-accepted without advisory", without(&clean, "advisory", 0)),
        case("evidence path escapes", clean.replacen("gates/out/logs/", "../", 1)),
    ];
    mutants.push(Case { log: None, ..case("evidence log missing", clean.clone()) });
    mutants.push(Case {
        log: Some(good_log().replace(MUST, "CLIENT-POLICY: FAIL (compiled-out)")),
        ..case("evidence log not PASS", clean.clone())
    });
    mutants.push(Case {
        log: Some(good_log().replace(MUST, &format!("{MUST} (x)"))),
        ..case("evidence_must only as a substring", clean.clone())
    });
    mutants.push(Case {
        log: Some(good_log().replace("[exit 0]", "[exit 1]")),
        ..case("evidence log exit non-zero", clean.clone())
    });
    mutants
        .push(Case { stale: true, ..case("evidence log sha from another run (predates run marker)", clean.clone()) });
    mutants.push(Case { marker: false, ..case("no run marker", clean.clone()) });

    let base = super::root().join(format!("target/xtask-ledger-selftest-{}", std::process::id()));
    let res = (|| {
        let mut bad = Vec::new();
        let (_, v) = run_case(&base, &case("clean", clean.clone()), today)?;
        if !v.is_empty() {
            bad.push(format!("clean ledger rejected: {}", v.join("; ")));
        }
        for m in &mutants {
            let (_, v) = run_case(&base, m, today)?;
            if v.is_empty() {
                bad.push(format!("mutant not rejected: {}", m.name));
            } else {
                println!("  red  {:55} {}", m.name, v.first().map_or("", String::as_str));
            }
        }
        Ok::<_, String>(bad)
    })();
    let _ = std::fs::remove_dir_all(&base);
    let bad = res?;
    if bad.is_empty() {
        println!("{NAME} SELF-TEST: PASS (clean ledger green; {}/{} mutants red)", mutants.len(), mutants.len());
        Ok(())
    } else {
        for b in &bad {
            println!("  - {b}");
        }
        Err(format!("{NAME} SELF-TEST: FAIL ({} problem(s))", bad.len()))
    }
}

fn run_case(base: &Path, c: &Case, today: i64) -> Result<(usize, Vec<String>), String> {
    let _ = std::fs::remove_dir_all(base);
    let dir = base.join("logs");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{NAME} SELF-TEST: FAIL (mkdir {}: {e})", dir.display()))?;
    let now = SystemTime::now();
    let set = |p: &Path, body: &str, t: SystemTime| -> Result<(), String> {
        std::fs::write(p, body).map_err(|e| format!("{NAME} SELF-TEST: FAIL (write {}: {e})", p.display()))?;
        std::fs::File::options()
            .write(true)
            .open(p)
            .and_then(|f| f.set_modified(t))
            .map_err(|e| format!("{NAME} SELF-TEST: FAIL (set mtime {}: {e})", p.display()))
    };
    let marker_t = now.checked_sub(Duration::from_secs(100)).unwrap_or(now);
    if c.marker {
        set(&dir.join(MARKER), "selftest\n", marker_t)?;
    }
    if let Some(log) = &c.log {
        let t = if c.stale { now.checked_sub(Duration::from_secs(200)).unwrap_or(now) } else { now };
        set(&dir.join(LOG), log, t)?;
    }
    Ok(check(&c.ledger, &dir, today))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        for z in [0, 20_000, 20_761, 21_000, -1] {
            assert_eq!(parse_date(&civil(z)), Some(z));
        }
        assert_eq!(parse_date("2026-02-29"), None);
        assert!(parse_date("2028-02-29").is_some());
        assert_eq!(parse_date("2026-1-01"), None);
    }

    #[test]
    fn strings() {
        assert_eq!(basic_string("\"a\\\"b\" # c").as_deref(), Some("a\"b"));
        assert_eq!(basic_string("\"a\" x"), None);
        assert_eq!(basic_string("a"), None);
    }
}
