//! Command line.
//!
//! ```text
//! aegis --config <path> [--cert <pem>] [--key <pem>] [--audit-dir <dir>] [--runtime-dir <dir>] [--token-keyring <file>]
//!       [--front epoll|uring]
//! aegis check-config <path> [--print-effective]
//! ```
//! Certificate defaults: `$CREDENTIALS_DIRECTORY/tls.crt` and `tls.key` (systemd `LoadCredential=`). Audit default:
//! `$STATE_DIRECTORY/audit`. F8 has no field for either, so they are process options, not config.
//!
//! `--front epoll|uring` (D-P7.3, FRONT-1; oracles/front-equiv contract) selects the accept/read/write front of every
//! HTTP listener and overrides F8 `listeners[].front`. Any other value, and `uring` in a build without feature
//! `uring`, is a usage error (exit 64) before anything is bound.

use std::ffi::OsString;
use std::path::PathBuf;

/// What to run.
#[derive(Debug)]
pub enum Cmd {
    /// No arguments: fail-closed boot (exit 78, nothing bound).
    Bare,
    /// `check-config`.
    Check { path: PathBuf, print_effective: bool },
    /// Serve.
    Serve(ServeOpts),
    /// `--help`.
    Help,
}

/// Options of the serving process.
#[derive(Debug, Clone)]
pub struct ServeOpts {
    pub config: PathBuf,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub audit_dir: Option<PathBuf>,
    pub runtime_dir: Option<PathBuf>,
    /// F5 Tier-L key ring for app routes (`{"keys":[{"kid":hex,"key":64 hex}]}`, mode 0600; PLAN D16).
    pub token_keyring: Option<PathBuf>,
    /// `--front`: overrides every listener's F8 `front` when given.
    pub front: Option<aegis_config::Front>,
    /// The original arguments (re-used verbatim by the upgrade child).
    pub args: Vec<OsString>,
}

pub const USAGE: &str = "usage: aegis --config <path> [--cert <pem>] [--key <pem>] [--audit-dir <dir>] [--runtime-dir <dir>] [--token-keyring <file>] [--front epoll|uring]\n       aegis check-config <path> [--print-effective]\n       aegis --fips-check";

/// A command-line error (exit 64, EX_USAGE).
#[derive(Debug)]
pub struct UsageError(pub String);

pub fn parse(args: &[OsString]) -> Result<Cmd, UsageError> {
    let mut it = args.iter();
    let Some(first) = it.next() else { return Ok(Cmd::Bare) };
    let path = |v: Option<&OsString>, what: &str| -> Result<PathBuf, UsageError> {
        v.map(PathBuf::from).ok_or_else(|| UsageError(format!("{what} needs a value")))
    };
    if first.to_str() == Some("check-config") {
        let mut file = None;
        let mut print_effective = false;
        for a in it {
            match a.to_str() {
                Some("--print-effective") => print_effective = true,
                Some(s) if s.starts_with("--") => return Err(UsageError(format!("unknown option {s}"))),
                _ if file.is_none() => file = Some(PathBuf::from(a)),
                _ => return Err(UsageError("check-config takes one path".into())),
            }
        }
        let path = file.ok_or_else(|| UsageError("check-config needs a path".into()))?;
        return Ok(Cmd::Check { path, print_effective });
    }
    let mut o = ServeOpts {
        config: PathBuf::new(),
        cert: None,
        key: None,
        audit_dir: None,
        runtime_dir: None,
        token_keyring: None,
        front: None,
        args: args.to_vec(),
    };
    let mut config = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("--help" | "-h") => return Ok(Cmd::Help),
            Some("--config") => config = Some(path(it.next(), "--config")?),
            Some("--cert") => o.cert = Some(path(it.next(), "--cert")?),
            Some("--key") => o.key = Some(path(it.next(), "--key")?),
            Some("--audit-dir") => o.audit_dir = Some(path(it.next(), "--audit-dir")?),
            Some("--runtime-dir") => o.runtime_dir = Some(path(it.next(), "--runtime-dir")?),
            Some("--token-keyring") => o.token_keyring = Some(path(it.next(), "--token-keyring")?),
            Some("--front") => o.front = Some(front(it.next())?),
            _ => return Err(UsageError(format!("unknown argument {a:?}"))),
        }
    }
    o.config = config.ok_or_else(|| UsageError("--config is required".into()))?;
    Ok(Cmd::Serve(o))
}

/// `--front` value: `epoll`, or `uring` when this build has the io_uring front.
fn front(v: Option<&OsString>) -> Result<aegis_config::Front, UsageError> {
    match v.and_then(|v| v.to_str()) {
        Some("epoll") => Ok(aegis_config::Front::Epoll),
        Some("uring") if cfg!(feature = "uring") => Ok(aegis_config::Front::Uring),
        Some("uring") => Err(UsageError("--front uring: this build has no feature `uring` (no io_uring front)".into())),
        Some(other) => Err(UsageError(format!("--front {other:?}: expected epoll or uring"))),
        None => Err(UsageError("--front needs a value (epoll or uring)".into())),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    fn a(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses() {
        assert!(matches!(parse(&[]), Ok(Cmd::Bare)));
        assert!(matches!(
            parse(&a(&["check-config", "x.json", "--print-effective"])),
            Ok(Cmd::Check { print_effective: true, .. })
        ));
        assert!(matches!(parse(&a(&["--config", "c.json", "--cert", "c.pem"])), Ok(Cmd::Serve(_))));
        assert!(parse(&a(&["--cert", "c.pem"])).is_err());
        assert!(parse(&a(&["--bogus"])).is_err());
        let Ok(Cmd::Serve(o)) = parse(&a(&["--front", "epoll", "--config", "c.json"])) else { panic!() };
        assert_eq!(o.front, Some(aegis_config::Front::Epoll));
        assert!(parse(&a(&["--config", "c.json", "--front", "kqueue"])).is_err());
        assert!(parse(&a(&["--config", "c.json", "--front"])).is_err());
        assert_eq!(parse(&a(&["--config", "c.json", "--front", "uring"])).is_ok(), cfg!(feature = "uring"));
    }
}
