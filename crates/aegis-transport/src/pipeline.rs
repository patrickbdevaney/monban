//! The Exchange pipeline shared by the h1 and h2 drivers: canonical head (CANON-6 binding through aegis-canon),
//! F3 hook 1 (`on_head`), bounded body, F3 hook 2 (`on_message`), reply. Handlers see `Head` and the size-checked
//! message only, never raw request bytes (CANON-3).

use aegis_canon::kind::{Authority, RoutePath};
use aegis_canon::{Canon, Proto, RequestIdentity, Scheme, Vhost, canon_path, canon_request};
use aegis_types::RouteId;

use crate::exchange::{ExchangeBudget, FrontEnd, Head, HeadVerdict, MessageVerdict, Method, Mode};

/// A front end plus routing and the reply. `route` and `respond` must be total and bounded like the F3 hooks.
pub trait App: FrontEnd + Send + Sync + 'static {
    /// Map the canonical authority, path and method to a route; `None` answers 404.
    fn route(&self, authority: &Canon<Authority>, path: &Canon<RoutePath>, method: Method) -> Option<RouteId>;
    /// Produce the reply for an accepted exchange.
    fn respond(&self, head: &Head<'_>, message: &[u8]) -> Reply;
}

/// Response body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplyBody {
    Empty,
    Static(&'static [u8]),
    Owned(Vec<u8>),
    /// `len` bytes of `byte`, generated chunk by chunk (each chunk a fresh allocation).
    Fill {
        len: u64,
        byte: u8,
    },
}

impl ReplyBody {
    pub fn len(&self) -> u64 {
        match self {
            Self::Empty => 0,
            Self::Static(s) => u64::try_from(s.len()).unwrap_or(u64::MAX),
            Self::Owned(v) => u64::try_from(v.len()).unwrap_or(u64::MAX),
            Self::Fill { len, .. } => *len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes `[off, off + max)` of the body as a fresh buffer.
    pub(crate) fn chunk(&self, off: u64, max: u64) -> Vec<u8> {
        let n = self.len().saturating_sub(off).min(max);
        let start = usize::try_from(off).unwrap_or(usize::MAX);
        let n_us = usize::try_from(n).unwrap_or(0);
        let end = start.saturating_add(n_us);
        match self {
            Self::Empty => Vec::new(),
            Self::Static(s) => s.get(start..end).map(<[u8]>::to_vec).unwrap_or_default(),
            Self::Owned(v) => v.get(start..end).map(<[u8]>::to_vec).unwrap_or_default(),
            Self::Fill { byte, .. } => vec![*byte; n_us],
        }
    }
}

/// A reply: status, optional content type, body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub content_type: Option<&'static str>,
    pub body: ReplyBody,
    /// `Location` for 3xx produced by the core (canonical path only).
    pub location: Option<Vec<u8>>,
}

impl Reply {
    pub fn status(status: u16) -> Self {
        Self { status, content_type: None, body: ReplyBody::Empty, location: None }
    }

    pub fn new(status: u16, content_type: &'static str, body: ReplyBody) -> Self {
        Self { status, content_type: Some(content_type), body, location: None }
    }
}

/// Configured virtual hosts (canonical authority, allowed serialized origins).
#[derive(Clone, Debug, Default)]
pub struct VhostTable {
    entries: Vec<(Vec<u8>, Vec<Vec<u8>>)>,
}

impl VhostTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a vhost by its canonical authority (`host` or `host:port`, lowercase A-labels).
    pub fn add(&mut self, authority: &[u8], origins: &[&[u8]]) {
        self.entries.push((authority.to_vec(), origins.iter().map(|o| o.to_vec()).collect()));
    }
}

/// What the TLS / cleartext layer knows about the connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnInfo {
    pub scheme: Scheme,
    pub sni: Option<Vec<u8>>,
}

/// Raw identity-bearing parts of one request head, as parsed by hyper / h2.
#[derive(Debug)]
pub(crate) struct RawHead<'a> {
    pub proto: Proto,
    pub method: &'a http::Method,
    /// h2 `:scheme` (None on h1).
    pub scheme: Option<&'a str>,
    /// h2 `:authority` (None on h1).
    pub authority: Option<&'a [u8]>,
    pub hosts: Vec<&'a [u8]>,
    pub origin: Option<&'a [u8]>,
    pub path_and_query: &'a [u8],
}

/// An accepted head: owned canonical values the `Head` view borrows from.
#[derive(Debug)]
pub(crate) struct Admitted {
    pub authority: Canon<Authority>,
    pub path: Canon<RoutePath>,
    pub method: Method,
    pub route: RouteId,
    pub budget: ExchangeBudget,
}

impl Admitted {
    pub(crate) fn head(&self) -> Head<'_> {
        Head { route: self.route, authority: &self.authority, path: &self.path, method: self.method }
    }
}

fn map_method(m: &http::Method) -> Option<Method> {
    Some(match *m {
        http::Method::GET => Method::Get,
        http::Method::HEAD => Method::Head,
        http::Method::POST => Method::Post,
        http::Method::PUT => Method::Put,
        http::Method::PATCH => Method::Patch,
        http::Method::DELETE => Method::Delete,
        http::Method::OPTIONS => Method::Options,
        http::Method::CONNECT => Method::Connect,
        _ => return None,
    })
}

/// Why admission failed: the reply to send and whether it was a CANON-6 binding reject.
#[derive(Debug)]
pub(crate) struct Refused {
    pub reply: Reply,
    pub authority: bool,
}

fn refuse(status: u16) -> Refused {
    Refused { reply: Reply::status(status), authority: false }
}

/// CANON-6 binding, path canonicalization, routing and F3 hook 1.
pub(crate) fn admit<A: App + ?Sized>(
    app: &A,
    vhosts: &VhostTable,
    conn: &ConnInfo,
    raw: &RawHead<'_>,
) -> Result<Admitted, Refused> {
    if let Some(s) = raw.scheme
        && Scheme::parse(s.as_bytes()).ok() != Some(conn.scheme)
    {
        return Err(refuse(400));
    }
    let origins: Vec<Vec<&[u8]>> = vhosts.entries.iter().map(|(_, o)| o.iter().map(Vec::as_slice).collect()).collect();
    let table: Vec<Vhost<'_>> = vhosts
        .entries
        .iter()
        .zip(origins.iter())
        .map(|((a, _), o)| Vhost { authority: a.as_slice(), origins: o.as_slice() })
        .collect();
    let identity = RequestIdentity {
        proto: raw.proto,
        scheme: conn.scheme,
        sni: conn.sni.as_deref(),
        authority: raw.authority,
        host: &raw.hosts,
        origin: raw.origin,
    };
    let authority =
        canon_request(&identity, &table).map_err(|r| Refused { reply: Reply::status(r.status()), authority: true })?;
    let Some(method) = map_method(raw.method) else {
        return Err(refuse(501));
    };
    if method == Method::Connect {
        // Framed modes (CONNECT / extended CONNECT) are not served by this driver yet: fail closed.
        return Err(refuse(501));
    }
    let path_only = raw.path_and_query.split(|&b| b == b'?').next().unwrap_or(b"");
    let path = match canon_path(path_only) {
        Ok(p) => p,
        Err(r) => {
            let mut reply = Reply::status(r.status());
            reply.location = r.redirect_target().map(<[u8]>::to_vec);
            return Err(Refused { reply, authority: false });
        }
    };
    let Some(route) = app.route(&authority, &path, method) else {
        return Err(refuse(404));
    };
    let head = Head { route, authority: &authority, path: &path, method };
    match app.on_head(&head) {
        HeadVerdict::Accept(Mode::Unary, budget) => Ok(Admitted { authority, path, method, route, budget }),
        HeadVerdict::Accept(_, _) => Err(refuse(501)),
        HeadVerdict::Reject(s) => Err(refuse(sanitize_status(s))),
    }
}

/// Body cap for an admitted exchange: the tighter of the front end's budget and the profile limit.
pub(crate) fn body_cap(budget: &ExchangeBudget, max_body: u64) -> u64 {
    u64::from(budget.max_message_bytes).min(budget.max_total_bytes).min(max_body)
}

/// Stall deadline for an admitted exchange (front end may only tighten it).
pub(crate) fn stall_ms(budget: &ExchangeBudget, limit_ms: u64) -> u64 {
    u64::from(budget.stall_ms).clamp(1, limit_ms.max(1))
}

/// F3 hook 2 then the reply.
pub(crate) fn finish<A: App + ?Sized>(app: &A, adm: &Admitted, message: &[u8]) -> Reply {
    let head = adm.head();
    match app.on_message(&head, message) {
        MessageVerdict::Continue => {
            let mut r = app.respond(&head, message);
            r.status = sanitize_status(r.status);
            r
        }
        MessageVerdict::Close(s) => Reply::status(sanitize_status(s)),
    }
}

/// Statuses a handler may produce: 200..=599 except 1xx (interim responses are the core's business).
pub(crate) fn sanitize_status(s: u16) -> u16 {
    if (200..=599).contains(&s) { s } else { 500 }
}

/// Response head shared by both drivers.
pub(crate) fn response_head(reply: &Reply, head_request: bool) -> http::Response<()> {
    let mut b = http::Response::builder().status(reply.status);
    if let Some(ct) = reply.content_type {
        b = b.header(http::header::CONTENT_TYPE, ct);
    }
    if let Some(loc) = &reply.location
        && let Ok(v) = http::HeaderValue::from_bytes(loc)
    {
        b = b.header(http::header::LOCATION, v);
    }
    let len = if head_request && reply.body.is_empty() { None } else { Some(reply.body.len()) };
    if let Some(l) = len {
        b = b.header(http::header::CONTENT_LENGTH, l);
    }
    b.body(()).unwrap_or_else(|_| {
        let mut r = http::Response::new(());
        *r.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
        r
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn reply_chunks() {
        let b = ReplyBody::Fill { len: 10, byte: 7 };
        assert_eq!(b.chunk(8, 4), vec![7, 7]);
        assert_eq!(b.chunk(10, 4), Vec::<u8>::new());
        let s = ReplyBody::Static(b"hello");
        assert_eq!(s.chunk(1, 3), b"ell".to_vec());
        assert_eq!(s.chunk(4, 3), b"o".to_vec());
        assert_eq!(sanitize_status(101), 500);
        assert_eq!(sanitize_status(421), 421);
    }
}
