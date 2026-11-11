//! Caller-supplied egress policy. Everything defaults to deny: an empty host allowlist admits nothing.

use core::time::Duration;
use std::string::String;
use std::vec::Vec;

use crate::addr::Prefix;
use crate::url::{Host, Url};

/// One allowlist entry for the URL host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostRule {
    /// Exactly this host (lowercase name, dotted quad, or IPv6 text without brackets).
    Exact(String),
    /// Any strict subdomain of this name (`Suffix("example.com")` admits `a.example.com`, not `example.com`).
    Suffix(String),
}

impl HostRule {
    fn matches(&self, host: &Host) -> bool {
        let key = host.allowlist_key();
        match self {
            Self::Exact(h) => key == h.to_ascii_lowercase(),
            Self::Suffix(s) => {
                matches!(host, Host::Name(_))
                    && key.len() > s.len()
                    && key.ends_with(&s.to_ascii_lowercase())
                    && key.as_bytes().get(key.len().saturating_sub(s.len()).saturating_sub(1)) == Some(&b'.')
            }
        }
    }
}

/// Outbound fetch policy.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Hosts that may be fetched, checked on the first URL and on every redirect hop.
    pub allowed_hosts: Vec<HostRule>,
    /// Ports that may be used. Empty: only the scheme's default port.
    pub allowed_ports: Vec<u16>,
    /// Allow plain `http` (default false: https only).
    pub allow_plain_http: bool,
    /// Prefixes in otherwise-forbidden but re-admittable classes (loopback, RFC 1918, CGNAT, ULA) that this caller
    /// may reach. Never admits metadata, link-local, multicast, reserved or embedded-IPv4 forms.
    pub readmit: Vec<Prefix>,
    /// Maximum redirect hops followed (each re-vetted). A redirect beyond this is an error.
    pub max_redirects: u8,
    /// Follow redirects that change scheme, host or port.
    pub cross_origin_redirects: bool,
    /// Wall-clock budget for the whole fetch (resolution, every hop, body).
    pub deadline: Duration,
    /// Response body cap (bytes, after de-chunking).
    pub max_response_bytes: usize,
    /// Response head cap (status line + headers).
    pub max_header_bytes: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allowed_hosts: Vec::new(),
            allowed_ports: Vec::new(),
            allow_plain_http: false,
            readmit: Vec::new(),
            max_redirects: 3,
            cross_origin_redirects: false,
            deadline: Duration::from_secs(10),
            max_response_bytes: 1 << 20,
            max_header_bytes: 16 << 10,
        }
    }
}

impl Policy {
    /// Whether the URL's host is allowlisted.
    pub fn host_allowed(&self, url: &Url) -> bool {
        self.allowed_hosts.iter().any(|r| r.matches(url.host()))
    }

    /// Whether the URL's port is allowed.
    pub fn port_allowed(&self, url: &Url) -> bool {
        if self.allowed_ports.is_empty() {
            url.port() == url.scheme().default_port()
        } else {
            self.allowed_ports.contains(&url.port())
        }
    }
}
