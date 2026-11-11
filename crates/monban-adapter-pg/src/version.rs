//! PostgreSQL version gate (R-DB-1 minor floor, R-DB-8 PG19 block; gates pg-version-floor and pg19-blocked).
//!
//! Floors and blocked majors are compiled by `build.rs` from `supply-chain/engine-pins.toml` (no hand-copied
//! constant). Admission follows `monban_data_ir::EnginePin::admit` (blocked major, major without a floor, or a version
//! below its major's floor are refused) plus the pins-file rule that pre-releases never satisfy a floor.
//!
//! The version is the leading token of the `server_version` ParameterStatus (text before the first ASCII space).
//! `server_version_num` is never consulted: real 17/18/19 servers do not report it at startup, and a server that
//! reports both could make them disagree. The token must be exactly ASCII `major.minor`, each component parsed
//! numerically with overflow refused (no wrap-around), so `17.9 < 17.11` and `18.10 > 18.6`.
//!
//! Pooled connections are re-admitted on every new startup for the same pool key with [`recheck`]: a server whose
//! token differs from the one admitted earlier is refused (a minor upgrade restarts the postmaster; the pool must be
//! recycled, R-DB-1), whatever the new version's own verdict would be.

use monban_data_ir::{EngineFamily, EnginePin, EngineVersion, PinError};
use std::fmt;

mod pins {
    include!(concat!(env!("OUT_DIR"), "/pg_pins.rs"));
}
pub use pins::{PG_BLOCKED_MAJORS, PG_FLOORS};

/// The compiled PostgreSQL pin as F4 data.
pub fn pg_pin() -> EnginePin {
    EnginePin {
        family: EngineFamily::Postgres,
        floors: PG_FLOORS.iter().map(|&(major, minor)| EngineVersion { major, minor, patch: 0 }).collect(),
        blocked_majors: PG_BLOCKED_MAJORS.to_vec(),
    }
}

/// Text before the first ASCII space (`"17.11 (Debian 17.11-1.pgdg13+1)"` → `"17.11"`).
pub fn leading_token(server_version: &str) -> &str {
    server_version.split(' ').next().unwrap_or("")
}

/// Classification of a `server_version` leading token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerVersion {
    /// `major.minor`, both ASCII decimal and within u32.
    Release(EngineVersion),
    /// `NNalpha*`, `NNbeta*`, `NNrc*`, `NNdevel*` (digits after the tag only).
    PreRelease { major: u32 },
    /// Anything else, including u32 overflow and three-part versions such as `9.6.24`.
    Unparseable,
}

fn decimal(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u32>().ok()
}

/// Classify a leading token (call [`leading_token`] first).
pub fn parse_token(tok: &str) -> ServerVersion {
    if let Some((a, b)) = tok.split_once('.') {
        return match (decimal(a), decimal(b)) {
            (Some(major), Some(minor)) => ServerVersion::Release(EngineVersion { major, minor, patch: 0 }),
            _ => ServerVersion::Unparseable,
        };
    }
    let digits_end = tok.bytes().position(|b| !b.is_ascii_digit()).unwrap_or(tok.len());
    let (num, rest) = tok.split_at_checked(digits_end).unwrap_or(("", ""));
    let Some(major) = decimal(num) else { return ServerVersion::Unparseable };
    for tag in ["alpha", "beta", "rc", "devel"] {
        if let Some(tail) = rest.strip_prefix(tag)
            && tail.bytes().all(|b| b.is_ascii_digit())
        {
            return ServerVersion::PreRelease { major };
        }
    }
    ServerVersion::Unparseable
}

/// Why a server was not admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionRefusal {
    /// The startup carried no `server_version` ParameterStatus.
    Missing,
    Unparseable {
        server_version: String,
    },
    PreRelease {
        token: String,
        blocked_major: bool,
    },
    Pin {
        token: String,
        version: EngineVersion,
        err: PinError,
    },
    /// A re-established pooled connection reports a different token than the one admitted (R-DB-1 recycle).
    Changed {
        admitted: String,
        now: Option<String>,
    },
}

impl fmt::Display for VersionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionRefusal::Missing => write!(f, "server did not report server_version"),
            VersionRefusal::Unparseable { server_version } => {
                write!(f, "unparseable server_version {:?}", server_version.escape_debug().to_string())
            }
            VersionRefusal::PreRelease { token, blocked_major } => write!(
                f,
                "pre-release {token} never satisfies a floor{}",
                if *blocked_major { " (major blocked, R-DB-8)" } else { "" }
            ),
            VersionRefusal::Pin { token, version, err } => match err {
                PinError::BlockedMajor => {
                    write!(
                        f,
                        "major {} blocked (R-DB-8: ON CONFLICT WHERE evaluated before RLS): {token}",
                        version.major
                    )
                }
                PinError::UnknownMajor => {
                    write!(f, "major {} has no floor in engine-pins.toml: {token}", version.major)
                }
                PinError::BelowFloor => {
                    let floor = PG_FLOORS.iter().find(|(m, _)| *m == version.major).map_or(0, |(_, n)| *n);
                    write!(f, "{token} below floor {}.{floor} (CVE-2026-14666, R-DB-1)", version.major)
                }
            },
            VersionRefusal::Changed { admitted, now } => write!(
                f,
                "server version changed {admitted} -> {} on reconnect; pool entry recycled (R-DB-1)",
                now.as_deref().unwrap_or("<none>")
            ),
        }
    }
}

impl std::error::Error for VersionRefusal {}

/// An admitted server: the exact leading token and its numeric version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedVersion {
    token: String,
    version: EngineVersion,
}

impl AdmittedVersion {
    /// Only gates in this crate admit (the PG gate here, the CockroachDB gate in `crdb`).
    #[cfg(feature = "crdb")]
    pub(crate) fn new(token: String, version: EngineVersion) -> AdmittedVersion {
        AdmittedVersion { token, version }
    }
    pub fn token(&self) -> &str {
        &self.token
    }
    pub fn version(&self) -> EngineVersion {
        self.version
    }
}

/// Admit or refuse the `server_version` a startup reported (`None` = not reported).
pub fn admit_server_version(server_version: Option<&str>) -> Result<AdmittedVersion, VersionRefusal> {
    let sv = server_version.ok_or(VersionRefusal::Missing)?;
    let tok = leading_token(sv);
    match parse_token(tok) {
        ServerVersion::Release(version) => match pg_pin().admit(version) {
            Ok(()) => Ok(AdmittedVersion { token: tok.to_owned(), version }),
            Err(err) => Err(VersionRefusal::Pin { token: tok.to_owned(), version, err }),
        },
        ServerVersion::PreRelease { major } => {
            Err(VersionRefusal::PreRelease { token: tok.to_owned(), blocked_major: PG_BLOCKED_MAJORS.contains(&major) })
        }
        ServerVersion::Unparseable => Err(VersionRefusal::Unparseable { server_version: sv.to_owned() }),
    }
}

/// Re-admission of a re-established pooled connection: the token must equal the one admitted for this pool key, and
/// the version must still pass the gate (it always does if equal, but the gate is re-run rather than assumed).
pub fn recheck(admitted: &AdmittedVersion, server_version: Option<&str>) -> Result<AdmittedVersion, VersionRefusal> {
    let now = server_version.map(leading_token);
    if now != Some(admitted.token()) {
        return Err(VersionRefusal::Changed { admitted: admitted.token.clone(), now: now.map(str::to_owned) });
    }
    admit_server_version(server_version)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> bool {
        admit_server_version(Some(s)).is_ok()
    }

    #[test]
    fn floors_come_from_pins_and_compare_numerically() {
        assert!(!PG_FLOORS.is_empty() && PG_BLOCKED_MAJORS.contains(&19));
        for &(maj, mnr) in PG_FLOORS {
            assert!(ok(&format!("{maj}.{mnr}")));
            assert!(ok(&format!("{maj}.{}", mnr + 1)));
            assert!(ok(&format!("{maj}.{}", mnr + 10)));
            assert!(ok(&format!("{maj}.{mnr} (Debian {maj}.{mnr}-1.pgdg13+1)")));
            if mnr > 0 {
                assert!(!ok(&format!("{maj}.{}", mnr - 1)));
            }
            assert!(!ok(&format!("{maj}rc1")));
        }
    }

    #[test]
    fn refusals() {
        for s in [
            "19.0",
            "19.1",
            "19.12",
            "19rc1",
            "19beta3",
            "14.24",
            "16.15",
            "20.0",
            "9.6.24",
            "garbage",
            "",
            "17.x",
            "17.",
            ".11",
            "v18.6",
            "17.11garbage",
            "１７.１１",
            "17.4294967307",
            "4294967313.11",
            "18devel",
            "18rc",
            "17.-1",
            "+17.11",
            "17.11.",
            "17..11",
        ] {
            assert!(!ok(s), "{s:?} accepted");
        }
        assert_eq!(admit_server_version(None), Err(VersionRefusal::Missing));
        assert!(matches!(
            admit_server_version(Some("19.0")),
            Err(VersionRefusal::Pin { err: PinError::BlockedMajor, .. })
        ));
    }

    #[test]
    fn recheck_refuses_any_change() {
        let a = admit_server_version(Some("17.11")).unwrap_or_else(|e| unreachable!("{e}"));
        assert!(recheck(&a, Some("17.11 (Debian)")).is_ok());
        assert!(matches!(recheck(&a, Some("17.12")), Err(VersionRefusal::Changed { .. })));
        assert!(matches!(recheck(&a, None), Err(VersionRefusal::Changed { .. })));
    }
}
