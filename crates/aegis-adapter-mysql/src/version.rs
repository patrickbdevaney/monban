//! Server version gate, read from `supply-chain/engine-pins.toml` at compile time (`[engines.mariadb] floor`).
//!
//! The rule is the one `ci/engines.sh` applies to kind `mariadb`: same release series (major.minor) as the floor,
//! numeric comparison, no pre-release, and at least the floor (11.8.9 at the time of writing: the fixed release of
//! every 2026 advisory that affects 11.8). The legacy `5.5.5-` prefix MariaDB sends to old clients is stripped. A
//! refused server is refused before any credential is sent ([`crate::conn::Connection::connect`]).

use std::fmt;

use crate::MysqlError;

/// The pins file, embedded (cargo rebuilds this crate when it changes).
const PINS: &str = include_str!("../../../supply-chain/engine-pins.toml");

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MariaVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl fmt::Display for MariaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// `"11.8.9"` (exactly three numeric parts).
pub fn parse_version(s: &str) -> Option<MariaVersion> {
    let mut it = s.split('.');
    let mut num = || -> Option<u32> {
        let p = it.next()?;
        if p.is_empty() || p.len() > 6 || !p.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        p.parse().ok()
    };
    let v = MariaVersion { major: num()?, minor: num()?, patch: num()? };
    if it.next().is_some() {
        return None;
    }
    Some(v)
}

/// The version token of a handshake `server_version`: `"5.5.5-11.8.9-MariaDB-ubu2404"` → `"11.8.9"`.
pub fn version_token(server_version: &str) -> &str {
    let v = server_version.strip_prefix("5.5.5-").unwrap_or(server_version);
    v.split('-').next().unwrap_or("")
}

/// `floor = "x.y.z"` of the `[engines.mariadb]` table in `pins`.
pub fn floor_from_pins(pins: &str) -> Option<MariaVersion> {
    let mut inside = false;
    for line in pins.lines() {
        let l = line.split('#').next().unwrap_or("").trim();
        if l.starts_with('[') {
            inside = l == "[engines.mariadb]";
            continue;
        }
        if !inside {
            continue;
        }
        if let Some((k, v)) = l.split_once('=')
            && k.trim() == "floor"
        {
            return parse_version(v.trim().strip_prefix('"')?.strip_suffix('"')?);
        }
    }
    None
}

/// The compiled-in floor.
pub fn floor() -> Option<MariaVersion> {
    floor_from_pins(PINS)
}

/// Admit a handshake `server_version` against `floor` (module rule).
pub fn admit_with(server_version: &str, floor: Option<MariaVersion>) -> Result<MariaVersion, MysqlError> {
    let Some(f) = floor else {
        return Err(MysqlError::VersionRefused("no [engines.mariadb] floor in engine-pins.toml".into()));
    };
    if !server_version.contains("MariaDB") {
        return Err(MysqlError::VersionRefused(format!("{server_version:?} is not a MariaDB server")));
    }
    let lower = server_version.to_ascii_lowercase();
    if ["alpha", "beta", "gamma", "-rc", "preview", "debug"].iter().any(|w| lower.contains(w)) {
        return Err(MysqlError::VersionRefused(format!("{server_version:?} is a pre-release or debug build")));
    }
    let tok = version_token(server_version);
    let v = parse_version(tok)
        .ok_or_else(|| MysqlError::VersionRefused(format!("unparsable server version {server_version:?}")))?;
    if (v.major, v.minor) != (f.major, f.minor) {
        return Err(MysqlError::VersionRefused(format!("{v} is outside the pinned {}.{} series", f.major, f.minor)));
    }
    if v < f {
        return Err(MysqlError::VersionRefused(format!("{v} is below the floor {f}")));
    }
    Ok(v)
}

/// Admit a handshake `server_version` against the compiled-in floor.
pub fn admit_server_version(server_version: &str) -> Result<MariaVersion, MysqlError> {
    admit_with(server_version, floor())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn pins_floor_present() {
        let f = floor().expect("floor in engine-pins.toml");
        assert!(f >= MariaVersion { major: 11, minor: 8, patch: 9 });
    }

    #[test]
    fn gate() {
        let f = Some(MariaVersion { major: 11, minor: 8, patch: 9 });
        assert!(admit_with("11.8.9-MariaDB-ubu2404", f).is_ok());
        assert!(admit_with("5.5.5-11.8.10-MariaDB", f).is_ok());
        for bad in ["11.8.8-MariaDB", "11.4.13-MariaDB", "12.3.3-MariaDB", "11.8.9-rc-MariaDB", "8.4.3", "11.8-MariaDB"]
        {
            assert!(admit_with(bad, f).is_err(), "{bad}");
        }
        assert!(admit_with("11.8.9-MariaDB", None).is_err());
        assert_eq!(
            floor_from_pins(
                "[engines.x]\nfloor = \"1.2.3\"\n[engines.mariadb]\nkind = \"mariadb\"\nfloor = \"11.8.9\" # c\n"
            ),
            Some(MariaVersion { major: 11, minor: 8, patch: 9 })
        );
    }
}
