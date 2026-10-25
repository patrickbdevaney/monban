//! CANON-6: SNI, `:authority`/Host and Origin bind to one vhost. The check order is frozen (canon-diff
//! `canon_request`): framing of Host/`:authority` (400) -> userinfo (400) -> authority syntax (400) ->
//! Host != `:authority` (400) -> vhost lookup (h2 421 / h1 404) -> SNI binding (421) -> Origin syntax (403) ->
//! Origin binding (421).

use aegis_types::{Canon, kind::Authority};

use crate::host::{authority_inner, host_inner, origin_inner};
use crate::{Reject, seal};

const fn rej(status: u16, reason: &'static str) -> Reject {
    Reject::new(status, "request", reason)
}

/// HTTP version family of the exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Proto {
    H1,
    H2,
}

impl Proto {
    /// `h1` or `h2`; anything else is a bad envelope (400).
    pub fn parse(s: &[u8]) -> Result<Self, Reject> {
        match s {
            b"h1" => Ok(Self::H1),
            b"h2" => Ok(Self::H2),
            _ => Err(Reject::bad_envelope()),
        }
    }
}

/// Request scheme. Only `http` and `https` are served.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    /// Exactly `http` or `https` (callers lowercase first where the grammar is case-insensitive); anything else
    /// is a bad envelope (400).
    pub fn parse(s: &[u8]) -> Result<Self, Reject> {
        match s {
            b"http" => Ok(Self::Http),
            b"https" => Ok(Self::Https),
            _ => Err(Reject::bad_envelope()),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    pub(crate) fn default_port(self) -> u32 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

/// One configured virtual host: its canonical authority and the serialized origins allowed to call it.
#[derive(Clone, Copy, Debug)]
pub struct Vhost<'a> {
    pub authority: &'a [u8],
    pub origins: &'a [&'a [u8]],
}

/// The identity-bearing parts of one exchange, raw.
#[derive(Clone, Copy, Debug)]
pub struct RequestIdentity<'a> {
    pub proto: Proto,
    pub scheme: Scheme,
    /// TLS SNI, if any.
    pub sni: Option<&'a [u8]>,
    /// h2 `:authority` (h1 absolute-form is not served, so `Some` on h1 is rejected).
    pub authority: Option<&'a [u8]>,
    /// Every Host field line, in order.
    pub host: &'a [&'a [u8]],
    /// The Origin field, if any.
    pub origin: Option<&'a [u8]>,
}

/// Bind the exchange to exactly one vhost (CANON-6). Ok carries the vhost's canonical authority.
pub fn canon_request(r: &RequestIdentity<'_>, vhosts: &[Vhost<'_>]) -> Result<Canon<Authority>, Reject> {
    let raw: &[u8] = match r.proto {
        Proto::H1 => {
            if r.authority.is_some() {
                return Err(rej(400, "absolute-form/:authority on h1 not served"));
            }
            match r.host {
                [] => return Err(rej(400, "missing Host")),
                [one] => one,
                _ => return Err(rej(400, "duplicate Host")),
            }
        }
        Proto::H2 => {
            let Some(a) = r.authority else {
                return Err(rej(400, "missing :authority"));
            };
            if r.host.len() > 1 {
                return Err(rej(400, "duplicate Host"));
            }
            a
        }
    };
    if raw.contains(&b'@') || r.host.iter().any(|h| h.contains(&b'@')) {
        return Err(rej(400, "userinfo in authority"));
    }
    let a = authority_inner(raw, r.scheme).map_err(|e| rej(400, e))?;
    if r.proto == Proto::H2
        && let Some(h) = r.host.first()
        && authority_inner(h, r.scheme).ok().as_deref() != Some(a.as_slice())
    {
        return Err(rej(400, "Host != :authority"));
    }
    let Some(vh) = vhosts.iter().find(|v| v.authority == a.as_slice()) else {
        return Err(match r.proto {
            Proto::H2 => rej(421, "unknown vhost"),
            Proto::H1 => rej(404, "unknown vhost"),
        });
    };
    if let Some(sni) = r.sni {
        if r.scheme != Scheme::Https {
            return Err(rej(400, "SNI on cleartext"));
        }
        let host_part = match a.iter().rposition(|&b| b == b':') {
            Some(i) => a.get(..i).unwrap_or(b""),
            None => a.as_slice(),
        };
        if host_inner(sni).ok().as_deref() != Some(host_part) {
            return Err(rej(421, "SNI not bound to vhost"));
        }
    }
    if let Some(origin) = r.origin {
        let o = origin_inner(origin).map_err(|_| rej(403, "Origin unparseable"))?;
        if !vh.origins.contains(&o.as_slice()) {
            return Err(rej(421, "Origin not bound to vhost"));
        }
    }
    Ok(seal(a))
}
