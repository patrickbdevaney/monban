//! Strict outbound URL parser. Not WHATWG: no IDNA, no percent-decoding of the host, no IPv4 shorthand.
//!
//! Host rules are monban-canon's (`canon_sni`): ASCII-lowercase LDH labels or A-labels, no trailing dot, and an IPv4
//! literal only as the canonical dotted quad (decimal/octal/hex/short forms are rejected, so a different parser at
//! the far end can never read a different address). IPv6 literals are bracketed, parsed by `std`, and zone ids are
//! rejected. Userinfo is rejected. Only `http` and `https` exist.

use core::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::string::{String, ToString};

use crate::error::EgressError;

/// Longest URL accepted (bytes).
pub const MAX_URL: usize = 4096;

/// URL scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// `http`.
    Http,
    /// `https`.
    Https,
}

impl Scheme {
    /// The scheme's text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    /// Default port.
    pub fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

/// A URL host.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Host {
    /// A DNS name (lowercase, validated by monban-canon host rules).
    Name(String),
    /// A canonical dotted-quad IPv4 literal.
    V4(Ipv4Addr),
    /// A bracketed IPv6 literal (no zone id).
    V6(Ipv6Addr),
}

impl Host {
    /// The literal address, if the host is one.
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Name(_) => None,
            Self::V4(a) => Some(IpAddr::V4(*a)),
            Self::V6(a) => Some(IpAddr::V6(*a)),
        }
    }

    /// The text the policy allowlist matches against: the name, the dotted quad, or the IPv6 text without brackets.
    pub fn allowlist_key(&self) -> String {
        match self {
            Self::Name(n) => n.clone(),
            Self::V4(a) => a.to_string(),
            Self::V6(a) => a.to_string(),
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(n) => f.write_str(n),
            Self::V4(a) => write!(f, "{a}"),
            Self::V6(a) => write!(f, "[{a}]"),
        }
    }
}

/// A parsed outbound URL. The fragment is dropped; `path` holds path and query.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Url {
    scheme: Scheme,
    host: Host,
    port: u16,
    path: String,
}

impl Url {
    /// Parse an absolute `http`/`https` URL.
    pub fn parse(input: &str) -> Result<Self, EgressError> {
        check_chars(input)?;
        let (scheme, rest) = input.split_once("://").ok_or(EgressError::InvalidUrl("no-scheme"))?;
        let scheme = parse_scheme(scheme)?;
        let rest = rest.split('#').next().unwrap_or("");
        let split = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, path) = (rest.get(..split).unwrap_or(""), rest.get(split..).unwrap_or(""));
        let (host, port) = parse_authority(authority, scheme)?;
        let path = parse_path(path)?;
        Ok(Self { scheme, host, port, path })
    }

    /// Resolve a redirect `Location` against this URL (absolute, scheme-relative, absolute-path, query-only and
    /// relative-path references). The result is parsed as strictly as [`Url::parse`].
    pub fn join(&self, location: &str) -> Result<Self, EgressError> {
        if location.is_empty() {
            return Err(EgressError::BadRedirect("empty-location"));
        }
        check_chars(location)?;
        let loc = location.split('#').next().unwrap_or("");
        let head_end = loc.find(['/', '?']).unwrap_or(loc.len());
        let head = loc.get(..head_end).unwrap_or("");
        if loc.starts_with("//") {
            return Self::parse(&format!("{}:{loc}", self.scheme.as_str()));
        }
        if head.contains(':') {
            // Either a full absolute URL or a scheme without `//` (`https:evil`, `javascript:`): only the first is
            // accepted.
            return Self::parse(loc);
        }
        let base_path = self.path.split('?').next().unwrap_or("/");
        let path = if loc.starts_with('/') {
            loc.to_string()
        } else if loc.starts_with('?') {
            format!("{base_path}{loc}")
        } else if loc.is_empty() {
            self.path.clone()
        } else {
            let dir = base_path.rfind('/').and_then(|i| base_path.get(..=i)).unwrap_or("/");
            format!("{dir}{loc}")
        };
        Ok(Self { scheme: self.scheme, host: self.host.clone(), port: self.port, path: parse_path(&path)? })
    }

    /// Scheme.
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Host.
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// Effective port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Path and query (always starts with `/`).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// `Host` header value: the original name (or literal), with the port only when it is not the default.
    pub fn host_header(&self) -> String {
        if self.port == self.scheme.default_port() {
            self.host.to_string()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Same origin (scheme, host, port).
    pub fn same_origin(&self, other: &Url) -> bool {
        self.scheme == other.scheme && self.host == other.host && self.port == other.port
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}{}", self.scheme.as_str(), self.host_header(), self.path)
    }
}

fn check_chars(s: &str) -> Result<(), EgressError> {
    if s.len() > MAX_URL {
        return Err(EgressError::InvalidUrl("too-long"));
    }
    if !s.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(EgressError::InvalidUrl("bad-char"));
    }
    if s.contains('\\') {
        return Err(EgressError::InvalidUrl("backslash"));
    }
    Ok(())
}

fn parse_scheme(s: &str) -> Result<Scheme, EgressError> {
    match s.to_ascii_lowercase().as_str() {
        "http" => Ok(Scheme::Http),
        "https" => Ok(Scheme::Https),
        _ => Err(EgressError::InvalidUrl("scheme")),
    }
}

fn parse_port(p: &str) -> Result<u16, EgressError> {
    let ok = !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) && !p.starts_with('0');
    if !ok {
        return Err(EgressError::InvalidUrl("port"));
    }
    match p.parse::<u32>() {
        Ok(n @ 1..=65535) => u16::try_from(n).map_err(|_| EgressError::InvalidUrl("port")),
        _ => Err(EgressError::InvalidUrl("port")),
    }
}

fn parse_authority(a: &str, scheme: Scheme) -> Result<(Host, u16), EgressError> {
    if a.is_empty() {
        return Err(EgressError::InvalidUrl("empty-host"));
    }
    if a.contains('@') {
        return Err(EgressError::InvalidUrl("userinfo"));
    }
    if let Some(rest) = a.strip_prefix('[') {
        let (inner, after) = rest.split_once(']').ok_or(EgressError::InvalidUrl("ipv6"))?;
        if inner.contains('%') {
            return Err(EgressError::InvalidUrl("zone-id"));
        }
        // std accepts embedded dotted quads (`::ffff:1.2.3.4`); classification judges those addresses.
        let ip: Ipv6Addr = inner.parse().map_err(|_| EgressError::InvalidUrl("ipv6"))?;
        let port = match after {
            "" => scheme.default_port(),
            p => parse_port(p.strip_prefix(':').ok_or(EgressError::InvalidUrl("port"))?)?,
        };
        return Ok((Host::V6(ip), port));
    }
    if a.contains(['[', ']']) {
        return Err(EgressError::InvalidUrl("ipv6"));
    }
    let (host, port) = match a.split_once(':') {
        Some((h, p)) => (h, parse_port(p)?),
        None => (a, scheme.default_port()),
    };
    if host.contains('%') {
        return Err(EgressError::InvalidUrl("host-percent"));
    }
    let canon = monban_canon::canon_sni(host.as_bytes()).map_err(|r| {
        EgressError::InvalidUrl(match r.reason() {
            "non-canonical IPv4" => "ipv4-noncanonical",
            "trailing dot" => "trailing-dot",
            _ => "host",
        })
    })?;
    let name = core::str::from_utf8(canon.as_bytes()).map_err(|_| EgressError::InvalidUrl("host"))?;
    let host = match name.parse::<Ipv4Addr>() {
        Ok(v4) => Host::V4(v4),
        Err(_) => Host::Name(name.to_string()),
    };
    Ok((host, port))
}

fn parse_path(p: &str) -> Result<String, EgressError> {
    let p = if p.is_empty() {
        "/".to_string()
    } else if p.starts_with('?') {
        format!("/{p}")
    } else {
        p.to_string()
    };
    let b = p.as_bytes();
    let mut i = 0usize;
    while let Some(&c) = b.get(i) {
        let ok = c.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?".contains(&c);
        if c == b'%' {
            let hex = |j: usize| b.get(j).is_some_and(u8::is_ascii_hexdigit);
            if !(hex(i.saturating_add(1)) && hex(i.saturating_add(2))) {
                return Err(EgressError::InvalidUrl("bad-percent"));
            }
        } else if !ok {
            return Err(EgressError::InvalidUrl("path-char"));
        }
        i = i.saturating_add(1);
    }
    Ok(p)
}
