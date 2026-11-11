//! Typed egress errors. Every failure path returns one of these; nothing in this crate panics.

use core::fmt;
use std::net::IpAddr;
use std::string::String;

use crate::addr::AddrClass;

/// Why an outbound fetch was refused or failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressError {
    /// The URL (or a redirect `Location`) failed the strict parser. The reason is a stable code.
    InvalidUrl(&'static str),
    /// The scheme is not allowed by the policy (plain `http` needs `Policy::allow_plain_http`).
    SchemeNotAllowed,
    /// The host is not on the policy allowlist.
    HostNotAllowed,
    /// The port is not on the policy allowlist.
    PortNotAllowed,
    /// The resolver failed or returned no address.
    Resolve(String),
    /// A resolved (or literal) address is in a forbidden range.
    ForbiddenAddress {
        /// The offending address.
        addr: IpAddr,
        /// Its class.
        class: AddrClass,
    },
    /// More redirects than `Policy::max_redirects`.
    TooManyRedirects,
    /// An `https` URL redirected to `http`.
    SchemeDowngrade,
    /// A redirect left the origin and the policy forbids cross-origin redirects.
    CrossOriginRedirect,
    /// A redirect response carried an unusable `Location`.
    BadRedirect(&'static str),
    /// The caller's request is malformed (header injection, reserved header, ...).
    BadRequest(&'static str),
    /// TCP connect failed on every vetted address.
    Connect(String),
    /// The TLS handshake failed.
    Tls(String),
    /// `https` was requested but the crate was built without the `tls-client` feature (cmvp build).
    TlsUnavailable,
    /// The per-request deadline elapsed.
    Timeout,
    /// The response head exceeded `Policy::max_header_bytes`.
    HeadersTooLarge,
    /// The response body exceeded `Policy::max_response_bytes`.
    ResponseTooLarge,
    /// The response is not well-formed HTTP/1.x.
    BadResponse(&'static str),
    /// An I/O error after the connection was established.
    Io(String),
}

impl EgressError {
    /// Stable machine-readable code (used by the oracle subject protocol).
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidUrl(_) => "invalid-url",
            Self::SchemeNotAllowed => "scheme-not-allowed",
            Self::HostNotAllowed => "host-not-allowed",
            Self::PortNotAllowed => "port-not-allowed",
            Self::Resolve(_) => "resolve",
            Self::ForbiddenAddress { .. } => "forbidden-address",
            Self::TooManyRedirects => "too-many-redirects",
            Self::SchemeDowngrade => "scheme-downgrade",
            Self::CrossOriginRedirect => "cross-origin-redirect",
            Self::BadRedirect(_) => "bad-redirect",
            Self::BadRequest(_) => "bad-request",
            Self::Connect(_) => "connect",
            Self::Tls(_) => "tls",
            Self::TlsUnavailable => "tls-unavailable",
            Self::Timeout => "timeout",
            Self::HeadersTooLarge => "headers-too-large",
            Self::ResponseTooLarge => "response-too-large",
            Self::BadResponse(_) => "bad-response",
            Self::Io(_) => "io",
        }
    }
}

impl fmt::Display for EgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(r) => write!(f, "invalid URL: {r}"),
            Self::BadRedirect(r) => write!(f, "bad redirect: {r}"),
            Self::BadRequest(r) => write!(f, "bad request: {r}"),
            Self::BadResponse(r) => write!(f, "bad response: {r}"),
            Self::Resolve(e) => write!(f, "resolve: {e}"),
            Self::Connect(e) => write!(f, "connect: {e}"),
            Self::Tls(e) => write!(f, "tls: {e}"),
            Self::Io(e) => write!(f, "io: {e}"),
            Self::ForbiddenAddress { addr, class } => write!(f, "forbidden address {addr} ({})", class.code()),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for EgressError {}
