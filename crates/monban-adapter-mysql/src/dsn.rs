//! Connection configuration and the `mysql://` DSN subset this client accepts.
//!
//! ```text
//! mysql://[user[:password]@]host[:port][/database][?connect_timeout=S&io_timeout=S]
//! ```
//! (`mariadb://` is accepted as a synonym.) The host must be a loopback address (`127.0.0.0/8`, `[::1]`, or
//! `localhost`, which is resolved to `127.0.0.1` without DNS): this client has no TLS path yet (PREFLIGHT D-P7.8
//! "loopback or TLS"), so a remote server is refused rather than spoken to in cleartext. Any other query key is
//! refused (fail closed). Values are percent-decoded and must not contain NUL.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::MysqlError;

pub const DEFAULT_PORT: u16 = 3306;
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(30);
/// Cap on one logical packet (server reply or client command), bytes. The server's max_allowed_packet default is
/// 16 MiB; a reply above this cap is refused and the connection dropped.
pub const DEFAULT_MAX_PACKET: usize = 16 << 20;
const MAX_DSN: usize = 4096;
const MAX_TIMEOUT_S: u64 = 300;

/// Everything needed to open one connection. `Debug` redacts the password.
#[derive(Clone, PartialEq, Eq)]
pub struct ConnectConfig {
    pub addr: SocketAddr,
    pub user: String,
    pub password: String,
    /// Default database (empty: none).
    pub database: String,
    /// Bound on TCP connect plus the whole handshake / auth / session setup.
    pub connect_timeout: Duration,
    /// Default bound on one command round trip (callers may pass their own deadline).
    pub io_timeout: Duration,
    /// Cap on any logical packet, bytes.
    pub max_packet: usize,
}

impl fmt::Debug for ConnectConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectConfig")
            .field("addr", &self.addr)
            .field("user", &self.user)
            .field("password", &"***")
            .field("database", &self.database)
            .field("connect_timeout", &self.connect_timeout)
            .field("io_timeout", &self.io_timeout)
            .field("max_packet", &self.max_packet)
            .finish()
    }
}

fn bad<T>(m: impl Into<String>) -> Result<T, MysqlError> {
    Err(MysqlError::Dsn(m.into()))
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn pct_decode(s: &str) -> Result<String, MysqlError> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while let Some(&c) = b.get(i) {
        if c == b'%' {
            let (Some(h), Some(l)) = (
                b.get(i.saturating_add(1)).and_then(|x| hexval(*x)),
                b.get(i.saturating_add(2)).and_then(|x| hexval(*x)),
            ) else {
                return bad("bad percent escape");
            };
            out.push(h << 4 | l);
            i = i.saturating_add(3);
        } else {
            out.push(c);
            i = i.saturating_add(1);
        }
    }
    let s = String::from_utf8(out).map_err(|_| MysqlError::Dsn("percent escape is not UTF-8".into()))?;
    if s.contains('\0') {
        return bad("NUL in DSN value");
    }
    Ok(s)
}

fn timeout(v: &str) -> Result<Duration, MysqlError> {
    match v.parse::<u64>() {
        Ok(s) if (1..=MAX_TIMEOUT_S).contains(&s) => Ok(Duration::from_secs(s)),
        _ => bad(format!("timeout must be 1..={MAX_TIMEOUT_S} seconds")),
    }
}

/// Whether `ip` is loopback (the only plaintext path this client takes).
pub fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_loopback(),
        IpAddr::V6(v) => v.is_loopback() || v.to_ipv4_mapped().is_some_and(|m| m.is_loopback()),
    }
}

impl ConnectConfig {
    /// Parse a `mysql://` DSN (module docs). A non-loopback host is [`MysqlError::NotLoopback`].
    pub fn from_dsn(dsn: &str) -> Result<ConnectConfig, MysqlError> {
        if dsn.len() > MAX_DSN {
            return bad("DSN too long");
        }
        let rest = dsn
            .strip_prefix("mysql://")
            .or_else(|| dsn.strip_prefix("mariadb://"))
            .ok_or_else(|| MysqlError::Dsn("scheme must be mysql:// or mariadb://".into()))?;
        let (rest, query) = match rest.split_once('?') {
            Some((a, q)) => (a, Some(q)),
            None => (rest, None),
        };
        if rest.contains('#') {
            return bad("fragment not allowed");
        }
        let (auth, hostpart) = match rest.rsplit_once('@') {
            Some((a, h)) => (Some(a), h),
            None => (None, rest),
        };
        let (user, password) = match auth {
            None => ("root".to_string(), String::new()),
            Some(a) => match a.split_once(':') {
                Some((u, p)) => (pct_decode(u)?, pct_decode(p)?),
                None => (pct_decode(a)?, String::new()),
            },
        };
        if user.is_empty() {
            return bad("empty user");
        }
        let (hostport, database) = match hostpart.split_once('/') {
            Some((h, d)) => (h, pct_decode(d)?),
            None => (hostpart, String::new()),
        };
        if database.contains('/') || database.len() > 64 {
            return bad("bad database name");
        }
        let (host, port) = if let Some(h) = hostport.strip_prefix('[') {
            let (h, tail) = h.split_once(']').ok_or_else(|| MysqlError::Dsn("unterminated [IPv6]".into()))?;
            let port = match tail {
                "" => None,
                t => Some(t.strip_prefix(':').ok_or_else(|| MysqlError::Dsn("junk after [IPv6]".into()))?),
            };
            (h, port)
        } else {
            match hostport.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (hostport, None),
            }
        };
        let port = match port {
            None => DEFAULT_PORT,
            Some(p) => match p.parse::<u16>() {
                Ok(n) if n != 0 => n,
                _ => return bad("bad port"),
            },
        };
        let ip: IpAddr = if host.eq_ignore_ascii_case("localhost") || host.is_empty() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            host.parse().map_err(|_| MysqlError::NotLoopback(format!("host {host:?} is not a loopback IP literal")))?
        };
        if !is_loopback(ip) {
            return Err(MysqlError::NotLoopback(format!("{ip} is not loopback")));
        }
        let mut cfg = ConnectConfig {
            addr: SocketAddr::new(ip, port),
            user,
            password,
            database,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            io_timeout: DEFAULT_IO_TIMEOUT,
            max_packet: DEFAULT_MAX_PACKET,
        };
        if let Some(q) = query {
            for kv in q.split('&').filter(|s| !s.is_empty()) {
                let (k, v) = kv.split_once('=').ok_or_else(|| MysqlError::Dsn(format!("query item {kv:?}")))?;
                match k {
                    "connect_timeout" => cfg.connect_timeout = timeout(v)?,
                    "io_timeout" => cfg.io_timeout = timeout(v)?,
                    _ => return bad(format!("unknown DSN key {k:?}")),
                }
            }
        }
        Ok(cfg)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        let c = ConnectConfig::from_dsn("mysql://root:p%40ss@127.0.0.1:32771/monban?connect_timeout=5").unwrap();
        assert_eq!(c.addr, "127.0.0.1:32771".parse().unwrap());
        assert_eq!((c.user.as_str(), c.password.as_str(), c.database.as_str()), ("root", "p@ss", "monban"));
        assert_eq!(c.connect_timeout, Duration::from_secs(5));
        assert!(!format!("{c:?}").contains("p@ss"));
        let c = ConnectConfig::from_dsn("mariadb://u@[::1]/d").unwrap();
        assert_eq!(c.addr.port(), 3306);
        assert!(ConnectConfig::from_dsn("mysql://u@localhost").is_ok());
    }

    #[test]
    fn refuses() {
        for d in [
            "postgresql://u@127.0.0.1/d",
            "mysql://u@10.0.0.1/d",
            "mysql://u@db.example/d",
            "mysql://u@127.0.0.1:0/d",
            "mysql://u@127.0.0.1/d?sslmode=require",
            "mysql://u@127.0.0.1/d?connect_timeout=0",
            "mysql://u:%zz@127.0.0.1/d",
            "mysql://u:a%00@127.0.0.1/d",
            "mysql://:p@127.0.0.1/d",
        ] {
            assert!(ConnectConfig::from_dsn(d).is_err(), "{d}");
        }
        assert!(matches!(ConnectConfig::from_dsn("mysql://u@192.168.1.5/d"), Err(MysqlError::NotLoopback(_))));
    }
}
