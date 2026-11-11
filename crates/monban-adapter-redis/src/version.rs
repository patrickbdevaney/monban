//! Server-version gate for Valkey / Redis (R-DB-5; CVE-2025-67733), read from `supply-chain/engine-pins.toml`.
//!
//! The pins file is the single source of truth and is compiled in with `include_str!` (no hand-copied constant).
//! Rule (the `fixed_in (kv)` semantics in the pins file, identical to `ci/engines.sh floor_ok`): a version is
//! admitted only if it is a plain `major.minor.patch` release of the right kind, its `major.minor` branch is listed
//! in that kind's `fixed_in`, and it is `>=` that entry. Unlisted branches are refused: newer branches are not
//! assumed fixed (Redis 8.8.x shipped after the fix and is unfixed, so 8.8 is not listed and is refused).
//! Pre-releases are refused (Valkey `valkey_release_stage` other than `ga`, any version with a suffix).
//!
//! Valkey reports a frozen compatibility `redis_version` (7.2.4 on Valkey 9.1.2); the gate reads `valkey_version`
//! for Valkey and `redis_version` only for Redis, and never accepts a Valkey server on its compatibility field.
//!
//! The parser reads exactly the subset the pins file uses for these keys: `[engines.NAME]` headers and single-line
//! `kind = "..."`, `policy = "..."`, `fixed_in = ["...", ...]` pairs. Anything it cannot read exactly makes the
//! whole kind refuse every version (fail closed); a unit test asserts the shipped file parses.

use std::fmt;

/// The shipped pins file.
pub const PINS_TOML: &str = include_str!("../../../supply-chain/engine-pins.toml");

/// Which RESP server family answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KvKind {
    Valkey,
    Redis,
}

impl KvKind {
    pub const fn name(self) -> &'static str {
        match self {
            KvKind::Valkey => "valkey",
            KvKind::Redis => "redis",
        }
    }
    pub fn from_name(s: &str) -> Option<KvKind> {
        match s {
            "valkey" => Some(KvKind::Valkey),
            "redis" => Some(KvKind::Redis),
            _ => None,
        }
    }
}

/// `major.minor.patch`, ordered lexicographically.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

fn num(s: &str) -> Option<u32> {
    if s.is_empty() || s.len() > 9 || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
        return None;
    }
    s.parse().ok()
}

impl Version {
    /// Strict `M.m.p` (decimal, no leading zeros, no suffix). `9.1.0-rc1`, `8.10`, ` 8.10.2` are `None`.
    pub fn parse(s: &str) -> Option<Version> {
        let mut it = s.split('.');
        let v = Version { major: num(it.next()?)?, minor: num(it.next()?)?, patch: num(it.next()?)? };
        if it.next().is_some() { None } else { Some(v) }
    }
}

/// The first fixed release per branch, per kind, as read from the pins file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvPins {
    valkey: Result<Vec<Version>, String>,
    redis: Result<Vec<Version>, String>,
}

impl KvPins {
    /// The compiled-in pins.
    pub fn shipped() -> KvPins {
        KvPins::parse(PINS_TOML)
    }

    /// Parse a pins file. Never fails as a whole: a kind whose entries are unreadable carries the reason and
    /// refuses every version.
    pub fn parse(text: &str) -> KvPins {
        let mut sections: Vec<(String, Section)> = Vec::new();
        for raw in text.lines() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            if let Some(h) = line.strip_prefix('[') {
                let name = h.strip_suffix(']').unwrap_or("").trim().to_string();
                sections.push((name, Section::default()));
                continue;
            }
            let Some((name, sec)) = sections.last_mut() else { continue };
            if !name.starts_with("engines.") {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else { continue };
            let (k, v) = (k.trim(), v.trim());
            match k {
                "kind" => sec.kind = Some(string_lit(v)),
                "policy" => sec.policy = Some(string_lit(v)),
                "fixed_in" => sec.fixed_in = Some(string_array(v)),
                _ => {}
            }
        }
        let collect = |kind: KvKind| -> Result<Vec<Version>, String> {
            let mut out = Vec::new();
            let mut seen = false;
            for (name, s) in &sections {
                match &s.kind {
                    Some(Some(k)) if k == kind.name() => {}
                    Some(Some(_)) => continue,
                    _ if name.starts_with("engines.") => return Err(format!("[{name}]: unreadable kind")),
                    _ => continue,
                }
                seen = true;
                match s.policy.as_ref().and_then(|p| p.as_deref()) {
                    Some("allow") => {}
                    Some("blocked") => return Err(format!("[{name}]: {} pin is blocked", kind.name())),
                    other => return Err(format!("[{name}]: policy {other:?}")),
                }
                let list = match &s.fixed_in {
                    Some(Some(l)) if !l.is_empty() => l,
                    _ => return Err(format!("[{name}]: fixed_in missing or unreadable")),
                };
                for f in list {
                    out.push(Version::parse(f).ok_or_else(|| format!("[{name}]: fixed_in entry {f:?}"))?);
                }
            }
            if !seen || out.is_empty() {
                return Err(format!("no {} pin", kind.name()));
            }
            Ok(out)
        };
        KvPins { valkey: collect(KvKind::Valkey), redis: collect(KvKind::Redis) }
    }

    fn floors(&self, kind: KvKind) -> Result<&[Version], &str> {
        match kind {
            KvKind::Valkey => self.valkey.as_deref().map_err(String::as_str),
            KvKind::Redis => self.redis.as_deref().map_err(String::as_str),
        }
    }

    /// The gate. `version` is the server-reported text for `kind` (Valkey: `valkey_version`).
    pub fn admit(&self, kind: KvKind, version: &str) -> Result<AdmittedVersion, VersionRefusal> {
        let floors = self.floors(kind).map_err(|e| VersionRefusal::Pins(e.to_string()))?;
        let v = Version::parse(version).ok_or_else(|| VersionRefusal::Unparseable(version.to_string()))?;
        // Same branch listed twice: the higher fix applies.
        let fix = floors.iter().filter(|f| f.major == v.major && f.minor == v.minor).max();
        match fix {
            None => Err(VersionRefusal::BranchNotListed { kind, version: v }),
            Some(f) if v < *f => Err(VersionRefusal::BelowFix { kind, version: v, fixed_in: *f }),
            Some(_) => Ok(AdmittedVersion { kind, version: v }),
        }
    }
}

#[derive(Default)]
struct Section {
    kind: Option<Option<String>>,
    policy: Option<Option<String>>,
    fixed_in: Option<Option<Vec<String>>>,
}

/// Drop a `#` comment that is outside a string literal.
fn strip_comment(l: &str) -> &str {
    let mut in_str = false;
    for (i, c) in l.char_indices() {
        match c {
            '"' => in_str = !in_str,
            '#' if !in_str => return l.get(..i).unwrap_or(""),
            _ => {}
        }
    }
    l
}

/// `"text"` with no escapes; anything else is `None`.
fn string_lit(v: &str) -> Option<String> {
    let inner = v.strip_prefix('"')?.strip_suffix('"')?;
    if inner.contains('"') || inner.contains('\\') { None } else { Some(inner.to_string()) }
}

/// `["a", "b"]` on one line.
fn string_array(v: &str) -> Option<Vec<String>> {
    let inner = v.strip_prefix('[')?.strip_suffix(']')?.trim();
    if inner.is_empty() {
        return Some(Vec::new());
    }
    inner.trim_end_matches(',').split(',').map(|e| string_lit(e.trim())).collect()
}

/// A server version that passed the gate. Pooled connections re-check against it ([`recheck`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AdmittedVersion {
    pub kind: KvKind,
    pub version: Version,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionRefusal {
    /// The pins file has no readable allowed entry for this kind.
    Pins(String),
    Unparseable(String),
    /// Pre-release (`valkey_release_stage` not `ga`).
    PreRelease(String),
    BranchNotListed {
        kind: KvKind,
        version: Version,
    },
    BelowFix {
        kind: KvKind,
        version: Version,
        fixed_in: Version,
    },
    /// The server's identity could not be established, or two sources (HELLO, INFO) disagree.
    Identity(String),
    /// A re-connect under an admitted pool key reported a different server (R-DB-1-style recycle).
    Changed {
        admitted: AdmittedVersion,
        now: AdmittedVersion,
    },
}

impl fmt::Display for VersionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionRefusal::Pins(e) => write!(f, "engine pins: {e} (refused)"),
            VersionRefusal::Unparseable(v) => write!(f, "unparseable server version {v:?} (refused)"),
            VersionRefusal::PreRelease(s) => write!(f, "pre-release server ({s}) refused"),
            VersionRefusal::BranchNotListed { kind, version } => write!(
                f,
                "{} {version}: branch {}.{} has no fixed release listed for CVE-2025-67733 (refused)",
                kind.name(),
                version.major,
                version.minor
            ),
            VersionRefusal::BelowFix { kind, version, fixed_in } => {
                write!(f, "{} {version} below branch fix {fixed_in} (CVE-2025-67733)", kind.name())
            }
            VersionRefusal::Identity(e) => write!(f, "server identity: {e} (refused)"),
            VersionRefusal::Changed { admitted, now } => write!(
                f,
                "server changed from {} {} to {} {} (recycle)",
                admitted.kind.name(),
                admitted.version,
                now.kind.name(),
                now.version
            ),
        }
    }
}

impl std::error::Error for VersionRefusal {}

/// Identity a server reported, from `HELLO` and (when the user may run it) `INFO server`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerReport {
    /// HELLO `server` field.
    pub hello_server: Option<String>,
    /// HELLO `version` field.
    pub hello_version: Option<String>,
    /// `INFO server` fields, when INFO was permitted.
    pub info: Option<Vec<(String, String)>>,
}

impl ServerReport {
    fn info_field(&self, k: &str) -> Option<&str> {
        self.info.as_ref()?.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }

    /// `(kind, version)` from `INFO server`: Valkey iff `valkey_version` or `server_name:valkey` is present, then
    /// its version is `valkey_version` (never the compatibility `redis_version`).
    pub fn from_info(&self) -> Result<Option<(KvKind, String)>, VersionRefusal> {
        if self.info.is_none() {
            return Ok(None);
        }
        let vk = self.info_field("valkey_version");
        let name = self.info_field("server_name");
        if vk.is_some() || name == Some("valkey") {
            let v = vk.ok_or_else(|| VersionRefusal::Identity("server_name valkey without valkey_version".into()))?;
            match self.info_field("valkey_release_stage") {
                None | Some("ga") => {}
                Some(s) => return Err(VersionRefusal::PreRelease(format!("valkey_release_stage {s}"))),
            }
            return Ok(Some((KvKind::Valkey, v.to_string())));
        }
        if let Some(n) = name {
            return Err(VersionRefusal::Identity(format!("unknown server_name {n:?}")));
        }
        let rv = self.info_field("redis_version").ok_or_else(|| VersionRefusal::Identity("no redis_version".into()))?;
        Ok(Some((KvKind::Redis, rv.to_string())))
    }

    /// `(kind, version)` from HELLO.
    pub fn from_hello(&self) -> Result<(KvKind, String), VersionRefusal> {
        let s = self.hello_server.as_deref().ok_or_else(|| VersionRefusal::Identity("HELLO without server".into()))?;
        let k = KvKind::from_name(s).ok_or_else(|| VersionRefusal::Identity(format!("HELLO server {s:?}")))?;
        let v = self.hello_version.clone().ok_or_else(|| VersionRefusal::Identity("HELLO without version".into()))?;
        Ok((k, v))
    }
}

/// First admission of an endpoint: requires `INFO server` (an admin or provisioning connection), and HELLO must
/// agree with it on kind and version.
pub fn admit_report(pins: &KvPins, r: &ServerReport) -> Result<AdmittedVersion, VersionRefusal> {
    let (ik, iv) = r
        .from_info()?
        .ok_or_else(|| VersionRefusal::Identity("INFO server not permitted for first admission".into()))?;
    let (hk, hv) = r.from_hello()?;
    if (ik, iv.as_str()) != (hk, hv.as_str()) {
        return Err(VersionRefusal::Identity(format!("HELLO says {} {hv}, INFO says {} {iv}", hk.name(), ik.name())));
    }
    pins.admit(ik, &iv)
}

/// Re-connect under an already admitted endpoint (e.g. a per-tenant ACL user that may not run INFO): the HELLO
/// identity (and INFO, if permitted) must equal the admitted one exactly, and still pass the gate.
pub fn recheck(pins: &KvPins, admitted: &AdmittedVersion, r: &ServerReport) -> Result<AdmittedVersion, VersionRefusal> {
    let (hk, hv) = r.from_hello()?;
    let now = pins.admit(hk, &hv)?;
    if let Some((ik, iv)) = r.from_info()?
        && (ik, iv.as_str()) != (hk, hv.as_str())
    {
        return Err(VersionRefusal::Identity(format!("HELLO says {} {hv}, INFO says {} {iv}", hk.name(), ik.name())));
    }
    if now != *admitted {
        return Err(VersionRefusal::Changed { admitted: *admitted, now });
    }
    Ok(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap_or(Version { major: 0, minor: 0, patch: 0 })
    }

    #[test]
    fn shipped_pins_parse_and_gate() {
        let p = KvPins::shipped();
        assert!(p.valkey.is_ok() && p.redis.is_ok(), "{p:?}");
        // The two pinned engines.
        assert!(p.admit(KvKind::Valkey, "9.1.2").is_ok());
        assert!(p.admit(KvKind::Redis, "8.10.2").is_ok());
        // Valkey branch fixes.
        assert!(p.admit(KvKind::Valkey, "9.0.3").is_ok());
        assert!(matches!(p.admit(KvKind::Valkey, "9.0.2"), Err(VersionRefusal::BelowFix { .. })));
        assert!(p.admit(KvKind::Valkey, "9.1.0").is_ok());
        assert!(p.admit(KvKind::Valkey, "7.2.12").is_ok());
        assert!(p.admit(KvKind::Valkey, "7.2.11").is_err());
        assert!(matches!(p.admit(KvKind::Valkey, "9.2.0"), Err(VersionRefusal::BranchNotListed { .. })));
        // Valkey's compatibility redis_version is never accepted as a Redis version of the same server.
        assert!(p.admit(KvKind::Redis, "7.2.4").is_err());
        // Redis: 8.8 is refused whatever the patch; 8.10.0+ admitted; 8.6.1 fixed, 8.6.0 not.
        for bad in ["8.8.0", "8.8.4", "8.8.99", "8.6.0", "7.2.12", "8.9.241", "6.2.20", "8.12.0"] {
            assert!(p.admit(KvKind::Redis, bad).is_err(), "{bad}");
        }
        for ok in ["8.10.0", "8.10.3", "8.6.1", "8.4.2", "8.2.5", "8.0.6", "7.4.8", "7.2.13"] {
            assert!(p.admit(KvKind::Redis, ok).is_ok(), "{ok}");
        }
        for junk in ["", "9.1", "9.1.2-rc1", "9.1.2.0", " 9.1.2", "09.1.2", "9.1.x", "8.10-rc2"] {
            assert!(matches!(p.admit(KvKind::Valkey, junk), Err(VersionRefusal::Unparseable(_))), "{junk}");
        }
    }

    #[test]
    fn unreadable_or_blocked_pins_refuse_everything() {
        let blocked = "[engines.valkey]\nkind = \"valkey\"\npolicy = \"blocked\"\nfixed_in = [\"9.1.0\"]\n";
        assert!(matches!(KvPins::parse(blocked).admit(KvKind::Valkey, "9.1.2"), Err(VersionRefusal::Pins(_))));
        let bad = "[engines.valkey]\nkind = \"valkey\"\npolicy = \"allow\"\nfixed_in = [\"9.1\"]\n";
        assert!(KvPins::parse(bad).admit(KvKind::Valkey, "9.1.2").is_err());
        let multiline = "[engines.redis]\nkind = \"redis\"\npolicy = \"allow\"\nfixed_in = [\n\"8.10.0\"]\n";
        assert!(KvPins::parse(multiline).admit(KvKind::Redis, "8.10.2").is_err());
        assert!(KvPins::parse("").admit(KvKind::Redis, "8.10.2").is_err());
        let ok = "[engines.r]\nkind = \"redis\" # c\npolicy = \"allow\"\nfixed_in = [\"8.10.0\", \"8.6.1\"]\n";
        assert_eq!(
            KvPins::parse(ok).admit(KvKind::Redis, "8.10.2"),
            Ok(AdmittedVersion { kind: KvKind::Redis, version: v("8.10.2") })
        );
        assert!(KvPins::parse(ok).admit(KvKind::Valkey, "9.1.2").is_err());
    }

    fn report(hs: &str, hv: &str, info: Option<&[(&str, &str)]>) -> ServerReport {
        ServerReport {
            hello_server: Some(hs.into()),
            hello_version: Some(hv.into()),
            info: info.map(|i| i.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()),
        }
    }

    #[test]
    fn valkey_is_read_from_valkey_version() {
        let p = KvPins::shipped();
        let info = [("redis_version", "7.2.4"), ("server_name", "valkey"), ("valkey_version", "9.1.2")];
        let r = report("valkey", "9.1.2", Some(&info));
        let a = admit_report(&p, &r);
        assert_eq!(a, Ok(AdmittedVersion { kind: KvKind::Valkey, version: v("9.1.2") }));
        // Older Valkey hiding behind a passing compatibility field.
        let old = [("redis_version", "8.10.2"), ("server_name", "valkey"), ("valkey_version", "9.0.2")];
        assert!(admit_report(&p, &report("valkey", "9.0.2", Some(&old))).is_err());
        // Pre-release stage.
        let rc = [("server_name", "valkey"), ("valkey_version", "9.1.2"), ("valkey_release_stage", "rc1")];
        assert!(matches!(admit_report(&p, &report("valkey", "9.1.2", Some(&rc))), Err(VersionRefusal::PreRelease(_))));
        // HELLO / INFO disagreement.
        assert!(admit_report(&p, &report("redis", "8.10.2", Some(&info))).is_err());
        // First admission needs INFO.
        assert!(admit_report(&p, &report("valkey", "9.1.2", None)).is_err());
        // Recheck with HELLO only.
        if let Ok(a) = a {
            assert!(recheck(&p, &a, &report("valkey", "9.1.2", None)).is_ok());
            assert!(matches!(recheck(&p, &a, &report("valkey", "9.1.0", None)), Err(VersionRefusal::Changed { .. })));
            assert!(recheck(&p, &a, &report("redis", "8.10.2", None)).is_err());
        }
        let redis = [("redis_version", "8.10.2")];
        assert!(admit_report(&p, &report("redis", "8.10.2", Some(&redis))).is_ok());
        let redis88 = [("redis_version", "8.8.4")];
        assert!(admit_report(&p, &report("redis", "8.8.4", Some(&redis88))).is_err());
    }
}
