//! Connection configuration and the `postgresql://` DSN subset this client accepts.
//!
//! ```text
//! postgresql://[user[:password]@][host][:port][/dbname][?key=value&...]
//! ```
//! `host` is a name, an IPv4 literal, `[IPv6]`, or a percent-encoded absolute directory (`%2Frun%2Fpostgresql`)
//! for a Unix socket (`<dir>/.s.PGSQL.<port>`). Query keys: `host` (same forms; a value starting with `/` selects a
//! Unix socket), `port`, `user`, `password`, `dbname`, `connect_timeout` (seconds), `application_name`,
//! `statement_timeout` (ms, sent as a startup GUC), `sslmode` (`disable` only: this client has no TLS, so asking for
//! TLS is refused instead of silently downgraded). Any other key is refused (fail closed: `options` would let a DSN
//! inject arbitrary GUCs). Values must not contain NUL.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use super::msg::DEFAULT_MAX_MESSAGE;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Endpoint {
    Tcp {
        host: String,
        port: u16,
    },
    /// Path of the socket file itself.
    Unix {
        path: PathBuf,
    },
}

/// Everything needed to open and start one connection. `Debug` redacts the password.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ConnectConfig {
    pub endpoint: Endpoint,
    pub user: String,
    pub password: Option<String>,
    pub dbname: String,
    pub application_name: Option<String>,
    /// Startup `statement_timeout` GUC in ms (per-op budgets use `Connection::set_local_statement_timeout`).
    pub statement_timeout_ms: Option<u32>,
    /// Bound on TCP connect and on the whole startup/auth exchange.
    pub connect_timeout: Duration,
    /// Cap on any single backend message (bytes, length field included).
    pub max_message: usize,
}

impl fmt::Debug for ConnectConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectConfig")
            .field("endpoint", &self.endpoint)
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("dbname", &self.dbname)
            .field("application_name", &self.application_name)
            .field("statement_timeout_ms", &self.statement_timeout_ms)
            .field("connect_timeout", &self.connect_timeout)
            .field("max_message", &self.max_message)
            .finish()
    }
}

pub const DEFAULT_PORT: u16 = 5432;
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_DSN: usize = 4096;
const MAX_CONNECT_TIMEOUT_S: u64 = 300;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DsnError(pub String);

impl fmt::Display for DsnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bad DSN: {}", self.0)
    }
}

impl std::error::Error for DsnError {}

fn bad<T>(m: impl Into<String>) -> Result<T, DsnError> {
    Err(DsnError(m.into()))
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Strict percent-decoding to UTF-8 without NUL.
fn pct(s: &str) -> Result<String, DsnError> {
    let mut out = Vec::with_capacity(s.len());
    let mut it = s.bytes();
    while let Some(c) = it.next() {
        if c == b'%' {
            let (Some(h), Some(l)) = (it.next().and_then(hex), it.next().and_then(hex)) else {
                return bad("bad percent escape");
            };
            out.push(h * 16 + l);
        } else {
            out.push(c);
        }
    }
    if out.contains(&0) {
        return bad("NUL in DSN component");
    }
    String::from_utf8(out).or_else(|_| bad("DSN component not UTF-8"))
}

fn port(s: &str) -> Result<u16, DsnError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return bad("port");
    }
    match s.parse::<u16>() {
        Ok(p) if p != 0 => Ok(p),
        _ => bad("port"),
    }
}

impl ConnectConfig {
    /// Parse a DSN. The result is a pure value: nothing is resolved or opened.
    pub fn from_dsn(dsn: &str) -> Result<ConnectConfig, DsnError> {
        if dsn.len() > MAX_DSN {
            return bad("too long");
        }
        let rest = dsn
            .strip_prefix("postgresql://")
            .or_else(|| dsn.strip_prefix("postgres://"))
            .ok_or(DsnError("scheme must be postgresql:// or postgres://".into()))?;
        let (main, query) = rest.split_once('?').unwrap_or((rest, ""));
        if main.contains('#') || query.contains('#') {
            return bad("fragment");
        }
        let (authority, path) = main.split_once('/').unwrap_or((main, ""));
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        let (mut user, mut password) = (None, None);
        if let Some(ui) = userinfo {
            match ui.split_once(':') {
                Some((u, p)) => {
                    user = Some(pct(u)?);
                    password = Some(pct(p)?);
                }
                None => user = Some(pct(ui)?),
            }
        }
        let (mut host, mut portn): (Option<String>, Option<u16>) = (None, None);
        if let Some(v6) = hostport.strip_prefix('[') {
            let (h, tail) = v6.split_once(']').ok_or(DsnError("unterminated [IPv6]".into()))?;
            host = Some(h.to_owned());
            if let Some(p) = tail.strip_prefix(':') {
                portn = Some(port(p)?);
            } else if !tail.is_empty() {
                return bad("junk after [IPv6]");
            }
        } else if !hostport.is_empty() {
            if hostport.contains(',') {
                return bad("multiple hosts are not supported");
            }
            match hostport.rsplit_once(':') {
                Some((h, p)) => {
                    host = Some(pct(h)?);
                    portn = Some(port(p)?);
                }
                None => host = Some(pct(hostport)?),
            }
        }
        let mut dbname = if path.is_empty() { None } else { Some(pct(path)?) };
        let (mut app, mut stmt_to, mut timeout) = (None, None, DEFAULT_CONNECT_TIMEOUT);
        let mut seen = Vec::new();
        for kv in query.split('&').filter(|s| !s.is_empty()) {
            let (k, v) = kv.split_once('=').ok_or(DsnError(format!("query item without '=': {kv:?}")))?;
            let (k, v) = (pct(k)?, pct(v)?);
            if seen.contains(&k) {
                return bad(format!("duplicate query key {k}"));
            }
            seen.push(k.clone());
            match k.as_str() {
                "host" => host = Some(v),
                "port" => portn = Some(port(&v)?),
                "user" => user = Some(v),
                "password" => password = Some(v),
                "dbname" => dbname = Some(v),
                "application_name" => app = Some(v),
                "statement_timeout" => {
                    stmt_to = Some(v.parse::<u32>().or_else(|_| bad("statement_timeout (ms)"))?);
                }
                "connect_timeout" => {
                    let s = v.parse::<u64>().or_else(|_| bad("connect_timeout"))?;
                    if s == 0 || s > MAX_CONNECT_TIMEOUT_S {
                        return bad("connect_timeout must be 1..=300 s");
                    }
                    timeout = Duration::from_secs(s);
                }
                "sslmode" => {
                    if v != "disable" {
                        return bad(format!("sslmode={v}: this client has no TLS; only sslmode=disable"));
                    }
                }
                other => return bad(format!("unsupported query key {other}")),
            }
        }
        let port = portn.unwrap_or(DEFAULT_PORT);
        let endpoint = match host {
            Some(h) if h.starts_with('/') => Endpoint::Unix { path: PathBuf::from(h).join(format!(".s.PGSQL.{port}")) },
            Some(h) if !h.is_empty() => Endpoint::Tcp { host: h, port },
            _ => return bad("no host (a Unix socket directory must be given explicitly)"),
        };
        let user = match user {
            Some(u) if !u.is_empty() => u,
            _ => return bad("no user"),
        };
        let dbname = dbname.filter(|d| !d.is_empty()).unwrap_or_else(|| user.clone());
        Ok(ConnectConfig {
            endpoint,
            user,
            password,
            dbname,
            application_name: app,
            statement_timeout_ms: stmt_to,
            connect_timeout: timeout,
            max_message: DEFAULT_MAX_MESSAGE,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsn_forms() {
        let c = ConnectConfig::from_dsn("postgresql://postgres:s%40cret@127.0.0.1:5433/db")
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(c.endpoint, Endpoint::Tcp { host: "127.0.0.1".into(), port: 5433 });
        assert_eq!((c.user.as_str(), c.password.as_deref(), c.dbname.as_str()), ("postgres", Some("s@cret"), "db"));
        assert!(!format!("{c:?}").contains("s@cret"));
        let u = ConnectConfig::from_dsn("postgresql://app@%2Frun%2Fpg/x").unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(u.endpoint, Endpoint::Unix { path: "/run/pg/.s.PGSQL.5432".into() });
        let q = ConnectConfig::from_dsn("postgres://u@[::1]:7/?host=/tmp&port=9&connect_timeout=3")
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(q.endpoint, Endpoint::Unix { path: "/tmp/.s.PGSQL.9".into() });
        assert_eq!(q.dbname, "u");
        for b in [
            "mysql://u@h/d",
            "postgresql://h/d",
            "postgresql://u@h:0/d",
            "postgresql://u@h:99999/d",
            "postgresql://u@h/d?sslmode=require",
            "postgresql://u@h/d?options=-c%20role%3Dx",
            "postgresql://u%00x@h/d",
            "postgresql://u@h/d%0",
            "postgresql://u@a,b/d",
            "postgresql://u@/d",
            "postgresql://u@h/d?port=1&port=2",
        ] {
            assert!(ConnectConfig::from_dsn(b).is_err(), "{b}");
        }
    }
}
