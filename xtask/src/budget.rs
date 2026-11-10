//! `cargo xtask budget [--self-test]`: binary budget gate (REPO_LAYOUT §6, R-PERF-1).
//!
//! Measures the default release build of `aegis-bin` (binary `aegis`) and judges it against the §6 limits:
//!
//! | criterion | limit | how it is measured |
//! |---|---|---|
//! | stripped size | ≤ 6.0 MB (6,000,000 bytes, decimal) | `target/release/aegis`; stripped by the release profile, confirmed by the absence of a `.symtab` ELF section |
//! | shipped crates | ≤ 60 third-party | `cargo tree -e normal,no-proc-macro --no-dedupe`, deduped by name+version (the resolved build graph, as in spikes/otlp-footprint; `cargo metadata` over-counts never-built crates such as ring). Workspace crates are reported but not counted against the limit (the floor came from a hello-world build that counted dependencies) |
//! | non-crypto unsafe | ≤ 5,100 lines | lines with the word `unsafe` outside comments and string/char literals in `src/**/*.rs` of each shipped third-party crate in the cargo registry; aws-lc-*, rustls*, ring are counted separately as crypto |
//! | idle RSS | ≤ 8 MB (8,000,000 bytes) | VmRSS of a started `aegis` after 1 s; `n/a` while the binary exits at boot (fail-closed), not judged |
//! | 1k idle TLS | ≤ 25 MB | `n/a` until a listener exists, not judged |
//!
//! Then it builds and measures the `--features native` build (the native data plane, PLAN D17, into `target/native`)
//! against the same criteria with its own stripped-size ceiling of 8.0 MB (DEVIATIONS X-12).
//!
//! Third, the P2 worker binary `aegis-p2` (PLAN-5 D3, DEVIATIONS X-13: the only binary that links wasmtime and
//! cranelift), built into `target/p2`, against its own explicit ceilings for stripped size, third-party crates and
//! non-crypto unsafe lines (set from the 2026-10-31 measurement). All three must pass.
//!
//! Finally, aegis-bin's `p2` feature must add no third-party crate: the resolved graphs of `p2` and `native,p2` must
//! hold exactly the third-party crates of the default and `native` builds (`cargo tree`, no build needed).
//!
//! Measurement (`measure`) and judgement (`judge_build`) are separate so `--self-test` can feed synthetic
//! measurements: each single over-budget input must FAIL (for each build) and a within-budget input must PASS.
//!
//! Repository root: env `AEGIS_ROOT`, else `crate::root()`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// Stripped size limit, default build (bytes, decimal MB).
pub const MAX_STRIPPED_BYTES: u64 = 6_000_000;
/// Stripped size ceiling of the `--features native` build (PLAN D17, DEVIATIONS X-12: bundled C SQLite).
pub const MAX_NATIVE_STRIPPED_BYTES: u64 = 8_000_000;

/// One measured release binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Build {
    pub name: &'static str,
    /// Cargo package and binary name.
    pub package: &'static str,
    pub bin: &'static str,
    /// Cargo features (empty: the default build).
    pub features: &'static str,
    /// Target directory relative to the repository root (`None`: `CARGO_TARGET_DIR` or `target`).
    pub target: Option<&'static str>,
    pub max_size: u64,
    /// Third-party shipped crate ceiling.
    pub max_crates: usize,
    /// Non-crypto `unsafe` line ceiling.
    pub max_unsafe: u64,
    /// Start the binary with a minimal serving config for the idle-RSS probe (aegis-bin only).
    pub serve: bool,
}

/// The default build: the core (mode R, gateway G), REPO_LAYOUT §6 limits.
pub const CORE: Build = Build {
    name: "default",
    package: "aegis-bin",
    bin: "aegis",
    features: "",
    target: None,
    max_size: MAX_STRIPPED_BYTES,
    max_crates: MAX_CRATES,
    max_unsafe: MAX_NONCRYPTO_UNSAFE,
    serve: true,
};
/// The native data plane (modes A/D): the same limits except its own size ceiling. Built into `target/native` (the
/// directory the native-e2e gate uses), so the core build in `target/release` is never overwritten.
pub const NATIVE: Build = Build {
    name: "native",
    package: "aegis-bin",
    bin: "aegis",
    features: "native",
    target: Some("target/native"),
    max_size: MAX_NATIVE_STRIPPED_BYTES,
    max_crates: MAX_CRATES,
    max_unsafe: MAX_NONCRYPTO_UNSAFE,
    serve: true,
};
/// The P2 worker (PLAN-5 D3, DEVIATIONS X-13): wasmtime + cranelift, its own ceilings. Built into `target/p2`, the
/// shipped p2 configuration (no `test-hooks`, no `mutants`; PLAN-5 D15).
pub const P2: Build = Build {
    name: "p2-worker",
    package: "aegis-p2",
    bin: "aegis-p2",
    features: "",
    target: Some("target/p2"),
    max_size: MAX_P2_STRIPPED_BYTES,
    max_crates: MAX_P2_CRATES,
    max_unsafe: MAX_P2_NONCRYPTO_UNSAFE,
    serve: false,
};
/// aegis-bin feature sets that must resolve to exactly the third-party crates of a measured build (PLAN-5 D3: the
/// `p2` feature adds only the aegis-iso supervisor and the F14 decoder, no third-party crate).
pub const SAME_CRATES: &[(&str, &str)] = &[("p2", ""), ("native,p2", "native")];
/// Shipped third-party crate limit (both aegis-bin builds).
pub const MAX_CRATES: usize = 60;
/// aegis-p2 ceilings (DEVIATIONS X-13), set by the integrator from the measurement of 2026-10-31 (PLAN-5 Q3):
/// * size: the skeleton links no wasmtime code (286,584 B), so the ceiling comes from a probe with the same release
///   profile exercising the worker's wasmtime surface (compile, serialize, deserialize_file, pooling, fuel, epoch,
///   linker, InstancePre): 9,548,896 B stripped. 11.0 MB leaves ~1.45 MB for aegis-iso, F14 and the subcommands.
/// * crates: 64 third-party (wasmtime 50.0.1 + cranelift 0.137.1 graph, incl. libc/rustix/sha2); any new crate needs
///   an integrator decision, as in aegis-bin.
/// * non-crypto unsafe: 6,243 lines over those 64 crates; 6,500 leaves room for a wasmtime 50.0.x security bump.
pub const MAX_P2_STRIPPED_BYTES: u64 = 11_000_000;
pub const MAX_P2_CRATES: usize = 64;
pub const MAX_P2_NONCRYPTO_UNSAFE: u64 = 6_500;
/// Non-crypto `unsafe` line limit over shipped third-party sources. 5,000 until 2026-11-10; raised to 5,100 by operator
/// decision for the RUSTSEC-2026-0459 fix (rusqlite 0.40.2 -> 0.41.1 adds 110 lines, no new crate; no patched version
/// fits under 5,000; measured 5,058; DEVIATIONS X-10).
pub const MAX_NONCRYPTO_UNSAFE: u64 = 5_100;
/// Idle RSS limit (bytes, decimal MB).
pub const MAX_IDLE_RSS_BYTES: u64 = 8_000_000;
/// RSS limit with 1k idle TLS connections (bytes, decimal MB).
pub const MAX_TLS1K_RSS_BYTES: u64 = 25_000_000;

/// A runtime measurement that may not be possible yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Runtime {
    /// Measured value in bytes.
    Bytes(u64),
    /// Not measurable yet; the reason is printed and the criterion is not judged.
    NotApplicable(String),
}

/// Everything the gate judges. Produced by `measure` or synthesised by the self-test.
#[derive(Clone, Debug)]
pub struct Measured {
    /// Size of the binary in bytes.
    pub size_bytes: u64,
    /// `Some(true)` if no `.symtab` section, `Some(false)` if present, `None` if not an ELF64 LE file.
    pub stripped: Option<bool>,
    /// Shipped third-party crates (name, version).
    pub third_party: Vec<(String, String)>,
    /// Shipped workspace crates (name, version).
    pub workspace: Vec<(String, String)>,
    /// `unsafe` lines in crypto crates (aws-lc-*, rustls*, ring).
    pub unsafe_crypto: u64,
    /// `unsafe` lines in all other shipped third-party crates.
    pub unsafe_noncrypto: u64,
    /// Per-crate unsafe counts for the report: (name-version, lines, crypto).
    pub unsafe_by_crate: Vec<(String, u64, bool)>,
    /// Shipped third-party crates whose sources were not found in the registry (cannot be counted).
    pub missing_sources: Vec<String>,
    /// Idle RSS.
    pub idle_rss: Runtime,
    /// RSS with 1k idle TLS connections.
    pub tls1k_rss: Runtime,
}

fn repo_root() -> PathBuf {
    match std::env::var_os("AEGIS_ROOT") {
        Some(r) if !r.is_empty() => PathBuf::from(r),
        _ => crate::root(),
    }
}

fn target_dir(root: &Path) -> PathBuf {
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(t) if !t.is_empty() => {
            let t = PathBuf::from(t);
            if t.is_absolute() { t } else { root.join(t) }
        }
        _ => root.join("target"),
    }
}

fn cargo_home() -> PathBuf {
    match std::env::var_os("CARGO_HOME") {
        Some(h) if !h.is_empty() => PathBuf::from(h),
        _ => PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".cargo"),
    }
}

/// Crypto crates whose `unsafe` is budgeted separately (REPO_LAYOUT §6 "non-crypto unsafe").
pub fn is_crypto(name: &str) -> bool {
    name.starts_with("aws-lc-") || name.starts_with("rustls") || name == "ring"
}

// ---------------------------------------------------------------- judgement

/// Returns the violated criteria under the default build's limits; empty means within budget.
pub fn judge(m: &Measured) -> Vec<String> {
    judge_build(m, &CORE)
}

/// Returns the violated criteria for build `b` (its size ceiling, the shared limits otherwise). Runtime criteria that
/// are `NotApplicable` are skipped.
pub fn judge_build(m: &Measured, b: &Build) -> Vec<String> {
    let mut v = Vec::new();
    match m.stripped {
        Some(true) => {}
        Some(false) => v.push("binary is not stripped (.symtab present); size is not a stripped measurement".into()),
        None => v.push("cannot confirm the binary is stripped (not an ELF64 little-endian file)".into()),
    }
    if m.size_bytes > b.max_size {
        v.push(format!("{} build: stripped size {} B > {} B", b.name, m.size_bytes, b.max_size));
    }
    if m.third_party.len() > b.max_crates {
        v.push(format!("{} build: shipped third-party crates {} > {}", b.name, m.third_party.len(), b.max_crates));
    }
    if !m.missing_sources.is_empty() {
        v.push(format!("unsafe count incomplete, sources not found for: {}", m.missing_sources.join(", ")));
    }
    if m.unsafe_noncrypto > b.max_unsafe {
        v.push(format!("{} build: non-crypto unsafe lines {} > {}", b.name, m.unsafe_noncrypto, b.max_unsafe));
    }
    if let Runtime::Bytes(b) = m.idle_rss
        && b > MAX_IDLE_RSS_BYTES
    {
        v.push(format!("idle RSS {b} B > {MAX_IDLE_RSS_BYTES} B"));
    }
    if let Runtime::Bytes(b) = m.tls1k_rss
        && b > MAX_TLS1K_RSS_BYTES
    {
        v.push(format!("1k idle TLS RSS {b} B > {MAX_TLS1K_RSS_BYTES} B"));
    }
    v
}

fn mb(b: u64) -> String {
    format!("{:.2} MB", b as f64 / 1_000_000.0)
}

fn ok(pass: bool) -> &'static str {
    if pass { "ok" } else { "OVER" }
}

fn print_table(m: &Measured, b: &Build) {
    let rt = |r: &Runtime, lim: u64| match r {
        Runtime::Bytes(b) => (format!("{} ({b} B)", mb(*b)), ok(*b <= lim).to_string()),
        Runtime::NotApplicable(why) => (format!("n/a ({why})"), "not judged".to_string()),
    };
    let stripped = match m.stripped {
        Some(true) => "yes (no .symtab)",
        Some(false) => "NO (.symtab present)",
        None => "unknown",
    };
    let rows: Vec<(String, String, String, String)> = vec![
        (
            "stripped size".into(),
            format!("{} ({} B), stripped: {stripped}", mb(m.size_bytes), m.size_bytes),
            format!("<= {}", mb(b.max_size)),
            ok(m.size_bytes <= b.max_size && m.stripped == Some(true)).into(),
        ),
        (
            "shipped crates (third-party)".into(),
            m.third_party.len().to_string(),
            format!("<= {}", b.max_crates),
            ok(m.third_party.len() <= b.max_crates).into(),
        ),
        ("shipped crates (workspace)".into(), m.workspace.len().to_string(), "reported".into(), "-".into()),
        (
            "shipped crates (total)".into(),
            (m.third_party.len() + m.workspace.len()).to_string(),
            "reported".into(),
            "-".into(),
        ),
        (
            "unsafe lines, non-crypto".into(),
            m.unsafe_noncrypto.to_string(),
            format!("<= {}", b.max_unsafe),
            ok(m.unsafe_noncrypto <= b.max_unsafe && m.missing_sources.is_empty()).into(),
        ),
        ("unsafe lines, crypto".into(), m.unsafe_crypto.to_string(), "reported".into(), "-".into()),
        {
            let (val, st) = rt(&m.idle_rss, MAX_IDLE_RSS_BYTES);
            ("idle RSS".into(), val, format!("<= {}", mb(MAX_IDLE_RSS_BYTES)), st)
        },
        {
            let (val, st) = rt(&m.tls1k_rss, MAX_TLS1K_RSS_BYTES);
            ("1k idle TLS RSS".into(), val, format!("<= {}", mb(MAX_TLS1K_RSS_BYTES)), st)
        },
    ];
    let w0 = rows.iter().map(|r| r.0.len()).max().unwrap_or(0);
    let w1 = rows.iter().map(|r| r.1.len()).max().unwrap_or(0);
    let w2 = rows.iter().map(|r| r.2.len()).max().unwrap_or(0);
    println!("  {:w0$}  {:w1$}  {:w2$}  status", "criterion", "measured", "limit");
    for (a, b, c, d) in &rows {
        println!("  {a:w0$}  {b:w1$}  {c:w2$}  {d}");
    }
}

// ---------------------------------------------------------------- measurement

fn build_target(root: &Path, b: &Build) -> PathBuf {
    match b.target {
        Some(t) => root.join(t),
        None => target_dir(root),
    }
}

fn feature_args(b: &Build) -> Vec<&'static str> {
    if b.features.is_empty() { Vec::new() } else { vec!["--features", b.features] }
}

/// Builds the release binary of build `b` through `ci/heavy.sh` and measures every criterion.
pub fn measure(root: &Path, b: &Build) -> Result<Measured, String> {
    let target = build_target(root, b);
    let status = Command::new(root.join("ci/heavy.sh"))
        .current_dir(root)
        .env("CARGO_TARGET_DIR", &target)
        .args(["cargo", "build", "--release", "--locked", "-p", b.package, "--bin", b.bin])
        .args(feature_args(b))
        .status()
        .map_err(|e| format!("spawn ci/heavy.sh: {e}"))?;
    if !status.success() {
        return Err(format!("BUDGET: FAIL (release build of {} ({}) failed: {status})", b.package, b.name));
    }
    let bin = target.join("release").join(b.bin);
    let bytes = std::fs::read(&bin).map_err(|e| format!("read {}: {e}", bin.display()))?;
    let size_bytes = bytes.len() as u64;
    let stripped = elf_has_section(&bytes, ".symtab").map(|has| !has);
    drop(bytes);

    let (third_party, workspace) = shipped_crates(root, b.package, b.features)?;
    let (unsafe_crypto, unsafe_noncrypto, unsafe_by_crate, missing_sources) = count_unsafe(&third_party);
    let idle_rss = idle_rss(&bin, root, b.serve);
    Ok(Measured {
        size_bytes,
        stripped,
        third_party,
        workspace,
        unsafe_crypto,
        unsafe_noncrypto,
        unsafe_by_crate,
        missing_sources,
        idle_rss,
        tls1k_rss: Runtime::NotApplicable("until the listener exists".into()),
    })
}

/// (name, version) pairs.
pub type Crates = Vec<(String, String)>;

/// Parses `cargo tree --prefix none --no-dedupe` output into deduped (third-party, workspace) crate lists.
/// Workspace crates are those with a local path source in the line, e.g. `aegis-types v0.0.0 (/path)`.
pub fn parse_tree(out: &str, root: &Path) -> (Crates, Crates) {
    let root_s = root.to_string_lossy();
    let mut third = BTreeSet::new();
    let mut ws = BTreeSet::new();
    for line in out.lines() {
        let mut parts = line.split_whitespace();
        let (Some(name), Some(ver)) = (parts.next(), parts.next()) else { continue };
        let ver = ver.trim_start_matches('v').to_string();
        let rest: Vec<&str> = parts.collect();
        let local = rest.iter().any(|p| {
            let p = p.trim_start_matches('(').trim_end_matches(')');
            p.starts_with('/') && p.starts_with(root_s.as_ref())
        });
        if local {
            ws.insert((name.to_string(), ver));
        } else {
            third.insert((name.to_string(), ver));
        }
    }
    (third.into_iter().collect(), ws.into_iter().collect())
}

fn shipped_crates(root: &Path, package: &str, features: &str) -> Result<(Crates, Crates), String> {
    let feats: Vec<&str> = if features.is_empty() { Vec::new() } else { vec!["--features", features] };
    let out = crate::run(Command::new("cargo").current_dir(root).arg("tree").args(feats).args([
        "--locked",
        "-p",
        package,
        "-e",
        "normal,no-proc-macro",
        "--prefix",
        "none",
        "--no-dedupe",
    ]))?;
    let canon = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    Ok(parse_tree(&out, &canon))
}

/// Returns `Some(true)` if the ELF64 little-endian file has a section named `name`, `None` if it cannot be parsed.
pub fn elf_has_section(b: &[u8], name: &str) -> Option<bool> {
    let u16_at = |o: usize| b.get(o..o + 2).and_then(|s| s.try_into().ok()).map(u16::from_le_bytes);
    let u32_at = |o: usize| b.get(o..o + 4).and_then(|s| s.try_into().ok()).map(u32::from_le_bytes);
    let u64_at = |o: usize| b.get(o..o + 8).and_then(|s| s.try_into().ok()).map(u64::from_le_bytes);
    if b.get(0..4)? != b"\x7fELF" || *b.get(4)? != 2 || *b.get(5)? != 1 {
        return None;
    }
    let shoff = usize::try_from(u64_at(0x28)?).ok()?;
    let shentsize = usize::from(u16_at(0x3A)?);
    let shnum = usize::from(u16_at(0x3C)?);
    let shstrndx = usize::from(u16_at(0x3E)?);
    let sh = |i: usize| shoff.checked_add(i.checked_mul(shentsize)?);
    let strtab_hdr = sh(shstrndx)?;
    let strtab_off = usize::try_from(u64_at(strtab_hdr + 0x18)?).ok()?;
    for i in 0..shnum {
        let h = sh(i)?;
        let name_off = usize::try_from(u32_at(h)?).ok()?;
        let start = strtab_off.checked_add(name_off)?;
        let tail = b.get(start..)?;
        let end = tail.iter().position(|&c| c == 0)?;
        if tail.get(..end)? == name.as_bytes() {
            return Some(true);
        }
    }
    Some(false)
}

/// Directory names that hold code compiled only for other architectures or operating systems than the shipped
/// x86_64/aarch64 Linux targets (e.g. linux-raw-sys ships 20 per-arch binding trees, only one of which builds).
/// Approximate by design: it measures closer to compiled code than a raw grep; cargo-geiger replaces it later.
const NON_TARGET_DIRS: &[&str] = &[
    "arm",
    "csky",
    "hexagon",
    "loongarch64",
    "m68k",
    "mips",
    "mips32r6",
    "mips64",
    "mips64r6",
    "powerpc",
    "powerpc64",
    "riscv32",
    "riscv64",
    "s390x",
    "sparc",
    "sparc64",
    "x32",
    "x86",
    "windows",
    "wasi",
    "apple",
    "freebsd",
    "netbsd",
    "openbsd",
    "dragonfly",
    "solarish",
    "illumos",
    "haiku",
    "hurd",
    "redox",
    "fuchsia",
    "emscripten",
    "vxworks",
    "solid",
    "hermit",
    "espidf",
    "horizon",
    "nto",
    "aix",
    "cygwin",
    "uefi",
    "wasm",
];

/// (crate, path prefix) pairs excluded because that backend is not selected on Linux: rustix uses its
/// `linux_raw` backend there, never `backend/libc`.
const NON_TARGET_PATHS: &[(&str, &str)] = &[("rustix", "src/backend/libc")];

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        match e.file_type() {
            Ok(t)
                if t.is_dir()
                    && p.file_name().and_then(|n| n.to_str()).is_some_and(|n| NON_TARGET_DIRS.contains(&n)) => {}
            Ok(t) if t.is_dir() => rs_files(&p, out),
            Ok(t) if t.is_file() && p.extension().is_some_and(|x| x == "rs") => out.push(p),
            _ => {}
        }
    }
}

/// Finds `<cargo home>/registry/src/*/<name>-<version>` for a crate.
fn crate_source(name: &str, ver: &str) -> Option<PathBuf> {
    let reg = cargo_home().join("registry").join("src");
    let dirname = format!("{name}-{ver}");
    std::fs::read_dir(reg).ok()?.flatten().map(|e| e.path().join(&dirname)).find(|p| p.is_dir())
}

type UnsafeCounts = (u64, u64, Vec<(String, u64, bool)>, Vec<String>);

fn count_unsafe(third_party: &[(String, String)]) -> UnsafeCounts {
    let (mut crypto, mut noncrypto) = (0u64, 0u64);
    let mut by_crate = Vec::new();
    let mut missing = Vec::new();
    for (name, ver) in third_party {
        let Some(dir) = crate_source(name, ver) else {
            missing.push(format!("{name}-{ver}"));
            continue;
        };
        let mut files = Vec::new();
        rs_files(&dir.join("src"), &mut files);
        // Crate-specific backends that do not build on the shipped Linux targets.
        files.retain(|f| {
            let rel = f.strip_prefix(&dir).unwrap_or(f);
            !NON_TARGET_PATHS.iter().any(|(c, sub)| c == name && rel.starts_with(sub))
        });
        let mut n = 0u64;
        for f in files {
            if let Ok(bytes) = std::fs::read(&f) {
                n += unsafe_lines(&String::from_utf8_lossy(&bytes));
            }
        }
        let c = is_crypto(name);
        if c {
            crypto += n;
        } else {
            noncrypto += n;
        }
        by_crate.push((format!("{name}-{ver}"), n, c));
    }
    (crypto, noncrypto, by_crate, missing)
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Replaces comments and string/char literal contents with spaces (newlines kept). Best effort Rust lexing:
/// nested block comments, escapes, raw strings `r#".."#` / `br".."`, and char literals vs lifetimes.
pub fn strip_comments_and_strings(src: &str) -> String {
    let c: Vec<char> = src.chars().collect();
    let at = |i: usize| c.get(i).copied().unwrap_or('\0');
    let blank = |ch: char| if ch == '\n' { '\n' } else { ' ' };
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    while i < c.len() {
        let ch = at(i);
        if ch == '/' && at(i + 1) == '/' {
            while i < c.len() && at(i) != '\n' {
                out.push(' ');
                i += 1;
            }
        } else if ch == '/' && at(i + 1) == '*' {
            let mut depth = 0usize;
            while i < c.len() {
                if at(i) == '/' && at(i + 1) == '*' {
                    depth += 1;
                    out.push_str("  ");
                    i += 2;
                } else if at(i) == '*' && at(i + 1) == '/' {
                    depth = depth.saturating_sub(1);
                    out.push_str("  ");
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    out.push(blank(at(i)));
                    i += 1;
                }
            }
        } else if ch == 'r'
            && (at(i + 1) == '"' || at(i + 1) == '#')
            && (i == 0 || !is_ident(at(i - 1)) || (at(i - 1) == 'b' && (i < 2 || !is_ident(at(i - 2)))))
        {
            // Possible raw string: r"..." or r#..#"..."#..#
            let mut j = i + 1;
            let mut hashes = 0usize;
            while at(j) == '#' {
                hashes += 1;
                j += 1;
            }
            if at(j) != '"' {
                out.push(ch);
                i += 1;
                continue;
            }
            for _ in i..=j {
                out.push(' ');
            }
            i = j + 1;
            while i < c.len() {
                if at(i) == '"' && (1..=hashes).all(|k| at(i + k) == '#') {
                    for _ in 0..=hashes {
                        out.push(' ');
                    }
                    i += hashes + 1;
                    break;
                }
                out.push(blank(at(i)));
                i += 1;
            }
        } else if ch == '"' {
            out.push(' ');
            i += 1;
            while i < c.len() {
                let d = at(i);
                if d == '\\' {
                    out.push(' ');
                    out.push(blank(at(i + 1)));
                    i += 2;
                } else if d == '"' {
                    out.push(' ');
                    i += 1;
                    break;
                } else {
                    out.push(blank(d));
                    i += 1;
                }
            }
        } else if ch == '\'' {
            // Char literal ('x', '\n', '\u{..}') or lifetime/label ('a).
            if at(i + 1) == '\\' {
                out.push(' ');
                i += 1;
                while i < c.len() && at(i) != '\'' && at(i) != '\n' {
                    if at(i) == '\\' {
                        out.push(' ');
                        i += 1;
                    }
                    out.push(' ');
                    i += 1;
                }
                if at(i) == '\'' {
                    out.push(' ');
                    i += 1;
                }
            } else if at(i + 2) == '\'' && at(i + 1) != '\n' {
                out.push_str("   ");
                i += 3;
            } else {
                out.push(ch);
                i += 1;
            }
        } else {
            out.push(ch);
            i += 1;
        }
    }
    out
}

/// Counts lines that contain the word `unsafe` in code (not in comments or literals).
pub fn unsafe_lines(src: &str) -> u64 {
    let code = strip_comments_and_strings(src);
    code.lines()
        .filter(|l| {
            l.match_indices("unsafe").any(|(p, _)| {
                let before = l.get(..p).and_then(|s| s.chars().next_back());
                let after = l.get(p + 6..).and_then(|s| s.chars().next());
                !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
            })
        })
        .count() as u64
}

/// Writes a minimal serving setup (self-signed P-256 cert via the openssl CLI, one loopback listener, one route,
/// admin on loopback) into `dir` and returns the arguments to start aegis with. None if openssl is missing.
fn serving_args(dir: &Path) -> Option<Vec<String>> {
    std::fs::create_dir_all(dir).ok()?;
    let (key, crt, cfg) = (dir.join("key.pem"), dir.join("cert.pem"), dir.join("aegis.json"));
    let ok = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2"])
        .args(["-subj", "/CN=budget.test", "-addext", "subjectAltName=DNS:budget.test"])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&crt)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        return None;
    }
    let pid = std::process::id();
    let port = 20_000 + (pid % 20_000) as u16;
    let doc = format!(
        r#"{{"v":1,"listeners":[{{"name":"pub","bind":"127.0.0.1:{port}","profile":"P-PUBLIC-WEB","alpn":["h2","http/1.1"]}}],"admin":{{"bind":"127.0.0.1:{}"}},"vhosts":[{{"host":"budget.test","routes":[{{"id":1,"path":"/","to":{{"upstream":"127.0.0.1:9"}},"authz":"allow-all"}}]}}]}}"#,
        port + 1
    );
    std::fs::write(&cfg, doc).ok()?;
    let s = |p: &Path| p.display().to_string();
    Some(vec![
        "--config".into(),
        s(&cfg),
        "--cert".into(),
        s(&crt),
        "--key".into(),
        s(&key),
        "--audit-dir".into(),
        s(&dir.join("audit")),
    ])
}

/// Starts the binary (with `serve`: serving a minimal config, falling back to no arguments if openssl is
/// unavailable) and reads VmRSS after 1.5 s. If it exits before then the criterion is not applicable.
fn idle_rss(bin: &Path, root: &Path, serve: bool) -> Runtime {
    let scratch = root.join("target").join("xtask-budget-run");
    let _ = std::fs::remove_dir_all(&scratch);
    let args = if serve { serving_args(&scratch).unwrap_or_default() } else { Vec::new() };
    let mut child = match Command::new(bin)
        .args(&args)
        .env_remove("NOTIFY_SOCKET")
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return Runtime::NotApplicable(format!("cannot start binary: {e}")),
    };
    std::thread::sleep(Duration::from_millis(1500));
    if let Ok(Some(st)) = child.try_wait() {
        let why = if !serve {
            "fail-closed without a supervisor"
        } else if args.is_empty() {
            "fail-closed boot (no openssl for a test config)"
        } else {
            "exited with the test config"
        };
        return Runtime::NotApplicable(format!("binary exits: {why}, {st}"));
    }
    let status = std::fs::read_to_string(format!("/proc/{}/status", child.id())).unwrap_or_default();
    let _ = child.kill();
    let _ = child.wait();
    let kb = status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|n| n.parse::<u64>().ok());
    match kb {
        Some(kb) => Runtime::Bytes(kb * 1024),
        None => Runtime::NotApplicable("VmRSS not readable".into()),
    }
}

// ---------------------------------------------------------------- entry point

fn synthetic_ok() -> Measured {
    let crates = |n: usize| (0..n).map(|i| (format!("c{i}"), "1.0.0".to_string())).collect::<Vec<_>>();
    Measured {
        size_bytes: 5_000_000,
        stripped: Some(true),
        third_party: crates(40),
        workspace: crates(23),
        unsafe_crypto: 90_000,
        unsafe_noncrypto: 3_000,
        unsafe_by_crate: Vec::new(),
        missing_sources: Vec::new(),
        idle_rss: Runtime::Bytes(5_000_000),
        tls1k_rss: Runtime::NotApplicable("synthetic".into()),
    }
}

fn self_test_run() -> Result<(), String> {
    let mut failures = Vec::new();
    let base = synthetic_ok();
    let v = judge(&base);
    if v.is_empty() {
        println!("  within-budget synthetic set: PASS (as required)");
    } else {
        failures.push(format!("within-budget set rejected: {}", v.join("; ")));
    }
    let over: Vec<(&str, Measured)> = vec![
        ("size 6.1 MB", Measured { size_bytes: 6_100_000, ..base.clone() }),
        (
            "61 crates",
            Measured { third_party: (0..61).map(|i| (format!("c{i}"), "1.0.0".into())).collect(), ..base.clone() },
        ),
        (
            "ceiling + 1 non-crypto unsafe lines",
            Measured { unsafe_noncrypto: MAX_NONCRYPTO_UNSAFE + 1, ..base.clone() },
        ),
        ("idle RSS 8.1 MB", Measured { idle_rss: Runtime::Bytes(8_100_000), ..base.clone() }),
        ("1k TLS RSS 25.1 MB", Measured { tls1k_rss: Runtime::Bytes(25_100_000), ..base.clone() }),
        ("unstripped binary", Measured { stripped: Some(false), ..base.clone() }),
        ("missing crate sources", Measured { missing_sources: vec!["x-1.0.0".into()], ..base.clone() }),
    ];
    for (label, m) in &over {
        let v = judge(m);
        if v.is_empty() {
            failures.push(format!("over-budget input '{label}' was not rejected"));
        } else {
            println!("  over-budget '{label}': FAIL (as required: {})", v.join("; "));
        }
    }
    // Boundary: exactly at each limit passes.
    let edge = Measured {
        size_bytes: MAX_STRIPPED_BYTES,
        third_party: (0..MAX_CRATES).map(|i| (format!("c{i}"), "1.0.0".into())).collect(),
        unsafe_noncrypto: MAX_NONCRYPTO_UNSAFE,
        idle_rss: Runtime::Bytes(MAX_IDLE_RSS_BYTES),
        ..base.clone()
    };
    if !judge(&edge).is_empty() {
        failures.push("input exactly at the limits was rejected".into());
    }
    // The native build (PLAN D17): its own 8.0 MB ceiling, the shared limits otherwise; the core keeps 6.0 MB.
    let native_ok = Measured { size_bytes: 7_900_000, ..base.clone() };
    if judge_build(&native_ok, &NATIVE).is_empty() && !judge_build(&native_ok, &CORE).is_empty() {
        println!("  native 7.9 MB: PASS under the native ceiling, FAIL under the core limit (as required)");
    } else {
        failures.push("7.9 MB must pass the native ceiling and fail the core limit".into());
    }
    let native_over: Vec<(&str, Measured)> = vec![
        ("native size 8.1 MB", Measured { size_bytes: 8_100_000, ..base.clone() }),
        (
            "native 61 crates",
            Measured { third_party: (0..61).map(|i| (format!("c{i}"), "1.0.0".into())).collect(), ..base.clone() },
        ),
        ("native unstripped", Measured { stripped: Some(false), ..base.clone() }),
    ];
    for (label, m) in &native_over {
        let v = judge_build(m, &NATIVE);
        if v.is_empty() {
            failures.push(format!("over-budget input '{label}' was not rejected"));
        } else {
            println!("  over-budget '{label}': FAIL (as required: {})", v.join("; "));
        }
    }
    if !judge_build(&Measured { size_bytes: MAX_NATIVE_STRIPPED_BYTES, ..base.clone() }, &NATIVE).is_empty() {
        failures.push("native input exactly at the ceiling was rejected".into());
    }
    if NATIVE.features != "native" || !CORE.features.is_empty() || CORE.max_size != 6_000_000 {
        failures.push("build table: the default build must be featureless at 6.0 MB, native at `native`".into());
    }
    // The P2 worker (PLAN-5 D3, DEVIATIONS X-13): its own ceilings; each single over-ceiling input must FAIL, the
    // input exactly at its ceilings must PASS, and its ceilings must not leak into the aegis-bin builds.
    let p2_edge = Measured {
        size_bytes: MAX_P2_STRIPPED_BYTES,
        third_party: (0..MAX_P2_CRATES).map(|i| (format!("c{i}"), "1.0.0".into())).collect(),
        unsafe_noncrypto: MAX_P2_NONCRYPTO_UNSAFE,
        ..base.clone()
    };
    if judge_build(&p2_edge, &P2).is_empty() && !judge_build(&p2_edge, &CORE).is_empty() {
        println!("  p2-worker at its ceilings: PASS under P2, FAIL under the core limits (as required)");
    } else {
        failures.push("p2-worker input at its ceilings must pass P2 and fail the core limits".into());
    }
    let p2_over: Vec<(&str, Measured)> = vec![
        ("p2-worker size over ceiling", Measured { size_bytes: MAX_P2_STRIPPED_BYTES + 1, ..p2_edge.clone() }),
        (
            "p2-worker crates over ceiling",
            Measured {
                third_party: (0..=MAX_P2_CRATES).map(|i| (format!("c{i}"), "1.0.0".into())).collect(),
                ..p2_edge.clone()
            },
        ),
        (
            "p2-worker non-crypto unsafe over ceiling",
            Measured { unsafe_noncrypto: MAX_P2_NONCRYPTO_UNSAFE + 1, ..p2_edge.clone() },
        ),
        ("p2-worker unstripped", Measured { stripped: Some(false), ..p2_edge.clone() }),
    ];
    for (label, m) in &p2_over {
        let v = judge_build(m, &P2);
        if v.is_empty() {
            failures.push(format!("over-budget input '{label}' was not rejected"));
        } else {
            println!("  over-budget '{label}': FAIL (as required: {})", v.join("; "));
        }
    }
    if P2.package != "aegis-p2" || P2.bin != "aegis-p2" || !P2.features.is_empty() || P2.target != Some("target/p2") {
        failures.push("build table: the p2 worker must be aegis-p2, featureless, in target/p2 (PLAN-5 D15)".into());
    }
    // aegis-bin `p2` must add no third-party crate (PLAN-5 D3).
    let c = |n: &str| (n.to_string(), "1.0.0".to_string());
    let core_set = vec![c("tokio"), c("hyper")];
    if !same_crates_violations("p2", &core_set, "", &core_set).is_empty() {
        failures.push("identical p2/default crate sets were rejected".into());
    }
    let with_wasmtime = vec![c("tokio"), c("hyper"), c("wasmtime")];
    let v = same_crates_violations("p2", &with_wasmtime, "", &core_set);
    if v.is_empty() {
        failures.push("aegis-bin p2 adding a third-party crate (wasmtime) was not rejected".into());
    } else {
        println!("  mutant 'aegis-bin p2 adds wasmtime': FAIL (as required: {})", v.join("; "));
    }
    if SAME_CRATES != [("p2", ""), ("native,p2", "native")] {
        failures.push("SAME_CRATES must compare p2 with default and native,p2 with native".into());
    }
    // Lexer: comment/string/char occurrences do not count; code occurrences do; crypto classification.
    let src = "// unsafe\n/* unsafe /* nested */ unsafe */ let s = \"unsafe\";\nlet r = r#\"unsafe\"#;\n\
               let c = '\"'; unsafe { f() }\nfn g<'a>(x: &'a u8) {}\nunsafe_fn();\nunsafe impl Send for X {}\n";
    let n = unsafe_lines(src);
    if n != 2 {
        failures.push(format!("unsafe line counter: expected 2, got {n}"));
    }
    if !(is_crypto("aws-lc-sys") && is_crypto("rustls-webpki") && is_crypto("ring") && !is_crypto("libc")) {
        failures.push("crypto classification wrong".into());
    }
    // cargo tree parsing: workspace vs third-party, dedupe by name+version.
    let tree = "aegis-bin v0.0.0 (/r/crates/aegis-bin)\nlibc v0.2.1\nlibc v0.2.1\nlibc v0.3.0\n";
    let (t, w) = parse_tree(tree, Path::new("/r"));
    if t.len() != 2 || w.len() != 1 {
        failures.push(format!("cargo tree parse: expected 2 third-party / 1 workspace, got {} / {}", t.len(), w.len()));
    }
    if failures.is_empty() {
        println!("BUDGET SELF-TEST: PASS");
        Ok(())
    } else {
        for f in &failures {
            println!("  - {f}");
        }
        Err(format!("BUDGET SELF-TEST: FAIL ({} problems)", failures.len()))
    }
}

/// `cargo xtask budget [--self-test]`.
pub fn budget(self_test: bool) -> Result<(), String> {
    if self_test {
        return self_test_run();
    }
    let root = repo_root();
    let mut lines = Vec::new();
    let mut failed = false;
    for b in [CORE, NATIVE, P2] {
        match report(&root, &b) {
            Ok(l) => lines.push(l),
            Err(l) => {
                failed = true;
                lines.push(l);
            }
        }
    }
    for (with, base) in SAME_CRATES {
        let (a, _) = shipped_crates(&root, "aegis-bin", with)?;
        let (b, _) = shipped_crates(&root, "aegis-bin", base)?;
        let v = same_crates_violations(with, &a, base, &b);
        println!(
            "budget: aegis-bin --features {with}: {} third-party crates (vs {} for {})",
            a.len(),
            b.len(),
            if base.is_empty() { "default" } else { base }
        );
        if v.is_empty() {
            lines.push(format!("aegis-bin {with}: no new third-party crate"));
        } else {
            for x in &v {
                println!("  - {x}");
            }
            failed = true;
            lines.push(v.join("; "));
        }
    }
    let all = lines.join("; ");
    if failed {
        return Err(format!("BUDGET: FAIL ({all})"));
    }
    println!("BUDGET: PASS ({all})");
    Ok(())
}

/// Third-party crates that aegis-bin feature set `with` resolves beyond those of `base` (PLAN-5 D3).
pub fn same_crates_violations(with: &str, a: &[(String, String)], base: &str, b: &[(String, String)]) -> Vec<String> {
    let base = if base.is_empty() { "default" } else { base };
    a.iter()
        .filter(|c| !b.contains(c))
        .map(|(n, v)| format!("aegis-bin --features {with} adds third-party crate {n} {v} (not in the {base} build)"))
        .collect()
}

/// Measure, print and judge one build. `Ok`/`Err` carry its summary line.
fn report(root: &Path, b: &Build) -> Result<String, String> {
    let m = measure(root, b)?;
    let feats = if b.features.is_empty() { String::new() } else { format!(", --features {}", b.features) };
    println!(
        "budget: {} {} release build{feats} ({})",
        b.package,
        b.name,
        build_target(root, b).join("release").join(b.bin).display()
    );
    print_table(&m, b);
    println!(
        "  third-party shipped: {}",
        m.third_party.iter().map(|(n, v)| format!("{n} {v}")).collect::<Vec<_>>().join(", ")
    );
    let mut top: Vec<_> = m.unsafe_by_crate.iter().filter(|c| c.1 > 0).collect();
    top.sort_by_key(|c| std::cmp::Reverse(c.1));
    println!(
        "  unsafe by crate: {}",
        top.iter()
            .map(|(n, l, c)| format!("{n}={l}{}", if *c { " (crypto)" } else { "" }))
            .collect::<Vec<_>>()
            .join(", ")
    );
    for r in [&m.idle_rss, &m.tls1k_rss] {
        if let Runtime::NotApplicable(why) = r {
            println!("  note: runtime criterion not judged yet: {why}");
        }
    }
    let v = judge_build(&m, b);
    let summary = format!(
        "{}: size {} B (<= {}), {} third-party + {} workspace crates, non-crypto unsafe {} lines, crypto unsafe {} lines",
        b.name,
        m.size_bytes,
        b.max_size,
        m.third_party.len(),
        m.workspace.len(),
        m.unsafe_noncrypto,
        m.unsafe_crypto
    );
    if v.is_empty() {
        Ok(summary)
    } else {
        for x in &v {
            println!("  - {x}");
        }
        Err(format!("{}; {summary}", v.join("; ")))
    }
}
