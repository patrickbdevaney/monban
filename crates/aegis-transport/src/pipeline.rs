//! The Exchange pipeline shared by the h1 and h2 drivers: admission (`App::arrive`), canonical head (CANON-6
//! binding through aegis-canon, path, query, header set), F3 hook 1 (`on_head`), bounded body, F3 hook 2
//! (`on_message`), then the request handler (`App::handle`, async). Handlers see canonical values and the
//! size-checked message only, never raw request bytes (CANON-3).

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use aegis_canon::kind::{Authority, HeaderSet, Query, RoutePath};
use aegis_canon::{
    Canon, Proto, QueryMode, RequestIdentity, Scheme, Vhost, canon_headers, canon_path, canon_query, canon_request,
};
use aegis_types::RouteId;

use crate::exchange::{ExchangeBudget, FrontEnd, Head, HeadVerdict, MessageVerdict, Method, Mode};

/// The future a request handler returns. It borrows the app (the server keeps it alive for the whole exchange).
pub type HandlerFuture<'a> = Pin<Box<dyn Future<Output = Reply> + Send + 'a>>;

/// A front end plus routing and the request handler. Every method must be total and bounded like the F3 hooks.
///
/// Implement either [`App::respond`] (synchronous, computed from the head and the message) or [`App::handle`]
/// (asynchronous, receives the whole canonical [`Request`]). The wrapper budgets stay in the transport either way:
/// the handler runs under the TBI-4 permit, its reply is sent through the TBI-6/7 ledger, and a handler that has
/// not answered within the exchange's stall deadline (TBI-8) is answered `504` by the core.
pub trait App: FrontEnd + Send + Sync + 'static {
    /// Map the canonical authority, path and method to a route; `None` answers 404.
    fn route(&self, authority: &Canon<Authority>, path: &Canon<RoutePath>, method: Method) -> Option<RouteId>;

    /// Produce the reply for an accepted exchange (synchronous apps). Default: 500.
    fn respond(&self, head: &Head<'_>, message: &[u8]) -> Reply {
        let _ = (head, message);
        Reply::status(500)
    }

    /// Produce the reply for an accepted exchange. Default: [`App::respond`] on the request's head and body.
    fn handle(&self, req: Request) -> HandlerFuture<'_> {
        let reply = self.respond(&req.head(), &req.body);
        Box::pin(std::future::ready(reply))
    }

    /// Query canonicalization mode (CANON-2: opaque unless the routes declare typed parameters).
    fn query_mode(&self) -> QueryMode {
        QueryMode::Opaque
    }

    /// Admission for one request, before anything about it is parsed or decided. `Ok(ticket)` admits it and the
    /// core calls [`App::depart`] with that ticket exactly once when the exchange ends; `Err(status)` answers it
    /// (sanitized like every handler status) and nothing else runs. `first`: the first arrival on the connection.
    fn arrive(&self, conn: &ConnInfo, first: bool) -> Result<u64, u16> {
        let _ = (conn, first);
        Ok(0)
    }

    /// The end of an admitted exchange. `cancelled`: it ended without a reply from the pipeline (body error,
    /// stall, reset).
    fn depart(&self, ticket: u64, cancelled: bool) {
        let _ = (ticket, cancelled);
    }

    /// The core refused a request on its head (CANON reject, unknown method, 404) with `status`.
    fn refused(&self, status: u16) {
        let _ = status;
    }

    /// A connection ended. `admitted`: at least one request on it was admitted by [`App::arrive`].
    fn conn_closed(&self, conn: &ConnInfo, admitted: bool) {
        let _ = (conn, admitted);
    }
}

/// An accepted, canonical request as the handler sees it.
#[derive(Debug)]
pub struct Request {
    pub route: RouteId,
    pub method: Method,
    pub authority: Canon<Authority>,
    pub path: Canon<RoutePath>,
    pub query: Canon<Query>,
    /// Every regular field of the request (h2 cookie crumbs joined with "; "), CANON-1/2 checked.
    pub headers: Canon<HeaderSet>,
    /// The size-checked message (at most the exchange budget and `max_body_bytes`), ledger-accounted (TBI-7)
    /// until the handler's future completes.
    pub body: Vec<u8>,
    pub conn: ConnInfo,
    /// NEGATIVE CONTROL ONLY (feature `e2e-raw-target`, oracles/proxy-e2e `--self-test`): the raw request target.
    #[cfg(feature = "e2e-raw-target")]
    pub raw_target: Vec<u8>,
}

impl Request {
    /// The F3 head of this request.
    pub fn head(&self) -> Head<'_> {
        Head { route: self.route, authority: &self.authority, path: &self.path, method: self.method }
    }
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
    /// Further end-to-end fields (lowercase names). Framing and hop-by-hop fields are dropped (the core regenerates
    /// framing), as are invalid names or values and duplicates of `content_type` / `location`.
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    /// The `content-length` to announce when no body is sent (a HEAD response or a 304), if known.
    pub length: Option<u64>,
}

impl Reply {
    pub fn status(status: u16) -> Self {
        Self { status, content_type: None, body: ReplyBody::Empty, location: None, headers: Vec::new(), length: None }
    }

    pub fn new(status: u16, content_type: &'static str, body: ReplyBody) -> Self {
        Self { content_type: Some(content_type), body, ..Self::status(status) }
    }

    /// Body bytes actually sent for this reply (none for HEAD, 1xx, 204, 304).
    pub(crate) fn sent_len(&self, head_request: bool) -> u64 {
        if head_request || self.status < 200 || self.status == 204 || self.status == 304 { 0 } else { self.body.len() }
    }
}

/// Configured virtual hosts (canonical authority, allowed serialized origins).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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
    /// The peer address, if the accepting layer passed one.
    pub peer: Option<SocketAddr>,
    /// Connection number, unique per server.
    pub id: u64,
}

/// Per-connection admission state.
#[derive(Debug, Default)]
pub(crate) struct ConnFlags {
    seen: AtomicBool,
    pub admitted: AtomicBool,
}

impl ConnFlags {
    pub(crate) fn admitted(&self) -> bool {
        self.admitted.load(Ordering::Relaxed)
    }
}

/// An admitted arrival: [`App::depart`] runs exactly once, on drop (cancelled unless [`Arrival::complete`] ran).
pub(crate) struct Arrival<'a, A: App> {
    app: &'a A,
    ticket: u64,
    cancelled: bool,
}

impl<A: App> Arrival<'_, A> {
    pub(crate) fn complete(&mut self) {
        self.cancelled = false;
    }
}

impl<A: App> Drop for Arrival<'_, A> {
    fn drop(&mut self) {
        self.app.depart(self.ticket, self.cancelled);
    }
}

/// Admission for one request (`App::arrive`). `Err` is the reply to send.
pub(crate) fn arrive<'a, A: App>(app: &'a A, conn: &ConnInfo, flags: &ConnFlags) -> Result<Arrival<'a, A>, Reply> {
    let first = !flags.seen.swap(true, Ordering::Relaxed);
    match app.arrive(conn, first) {
        Ok(ticket) => {
            flags.admitted.store(true, Ordering::Relaxed);
            Ok(Arrival { app, ticket, cancelled: true })
        }
        Err(s) => Err(Reply::status(sanitize_status(s))),
    }
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
    /// Every regular field (h2 cookie crumbs already joined), for the canonical header set.
    pub fields: Vec<(&'a [u8], &'a [u8])>,
}

/// An accepted head: owned canonical values the `Head` view borrows from.
#[derive(Debug)]
pub(crate) struct Admitted {
    pub authority: Canon<Authority>,
    pub path: Canon<RoutePath>,
    pub method: Method,
    pub route: RouteId,
    pub budget: ExchangeBudget,
    pub query: Canon<Query>,
    pub headers: Canon<HeaderSet>,
    #[cfg(feature = "e2e-raw-target")]
    pub raw_target: Vec<u8>,
}

impl Admitted {
    pub(crate) fn head(&self) -> Head<'_> {
        Head { route: self.route, authority: &self.authority, path: &self.path, method: self.method }
    }

    fn into_request(self, body: Vec<u8>, conn: &ConnInfo) -> Request {
        Request {
            route: self.route,
            method: self.method,
            authority: self.authority,
            path: self.path,
            query: self.query,
            headers: self.headers,
            body,
            conn: conn.clone(),
            #[cfg(feature = "e2e-raw-target")]
            raw_target: self.raw_target,
        }
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

/// CANON-6 binding, path / query / header-set canonicalization, routing and F3 hook 1. Every refusal except an
/// `on_head` reject is reported through `App::refused`.
pub(crate) fn admit<A: App + ?Sized>(
    app: &A,
    vhosts: &VhostTable,
    conn: &ConnInfo,
    raw: &RawHead<'_>,
) -> Result<Admitted, Refused> {
    let r = admit_inner(app, vhosts, conn, raw);
    if let Err((refused, true)) = &r {
        app.refused(refused.reply.status);
    }
    r.map_err(|(r, _)| *r)
}

/// A refusal made by the core (reported through `App::refused`).
fn core(r: Refused) -> (Box<Refused>, bool) {
    (Box::new(r), true)
}
fn admit_inner<A: App + ?Sized>(
    app: &A,
    vhosts: &VhostTable,
    conn: &ConnInfo,
    raw: &RawHead<'_>,
) -> Result<Admitted, (Box<Refused>, bool)> {
    if let Some(s) = raw.scheme
        && Scheme::parse(s.as_bytes()).ok() != Some(conn.scheme)
    {
        return Err(core(refuse(400)));
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
    let authority = canon_request(&identity, &table)
        .map_err(|r| core(Refused { reply: Reply::status(r.status()), authority: true }))?;
    let Some(method) = map_method(raw.method) else {
        return Err(core(refuse(501)));
    };
    if method == Method::Connect {
        // Framed modes (CONNECT / extended CONNECT) are not served by this driver yet: fail closed.
        return Err(core(refuse(501)));
    }
    let (path_only, raw_query) = match raw.path_and_query.iter().position(|&b| b == b'?') {
        Some(i) => {
            (raw.path_and_query.get(..i).unwrap_or(b""), raw.path_and_query.get(i.saturating_add(1)..).unwrap_or(b""))
        }
        None => (raw.path_and_query, &b""[..]),
    };
    let query = canon_query(raw_query, app.query_mode());
    let path = match canon_path(path_only) {
        Ok(p) => p,
        Err(r) => {
            let mut reply = Reply::status(r.status());
            // q4-008: `//` is answered with 308 to the merged path (plus the canonical query); never forwarded.
            reply.location = r.redirect_target().map(|t| {
                let mut loc = t.to_vec();
                if let Ok(q) = &query
                    && !q.as_bytes().is_empty()
                {
                    loc.push(b'?');
                    loc.extend_from_slice(q.as_bytes());
                }
                loc
            });
            return Err(core(Refused { reply, authority: false }));
        }
    };
    let Some(route) = app.route(&authority, &path, method) else {
        return Err(core(refuse(404)));
    };
    let head = Head { route, authority: &authority, path: &path, method };
    let budget = match app.on_head(&head) {
        HeadVerdict::Accept(Mode::Unary, budget) => budget,
        HeadVerdict::Accept(_, _) => return Err(core(refuse(501))),
        HeadVerdict::Reject(s) => return Err((Box::new(refuse(sanitize_status(s))), false)),
    };
    let query = query.map_err(|r| core(refuse(r.status())))?;
    // CANON-1/2 header set: names lowercased, OWS trimmed, duplicate singletons / CL+TE / bad CL rejected.
    let lines: Vec<Vec<u8>> = raw
        .fields
        .iter()
        .map(|(n, v)| {
            let mut l = Vec::with_capacity(n.len().saturating_add(v.len()).saturating_add(1));
            l.extend_from_slice(n);
            l.push(b':');
            l.extend_from_slice(v);
            l
        })
        .collect();
    let refs: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
    let headers = canon_headers(&refs).map_err(|r| core(refuse(r.status())))?;
    Ok(Admitted {
        authority,
        path,
        method,
        route,
        budget,
        query,
        headers,
        #[cfg(feature = "e2e-raw-target")]
        raw_target: raw.path_and_query.to_vec(),
    })
}

/// Body cap for an admitted exchange: the tighter of the front end's budget and the profile limit.
pub(crate) fn body_cap(budget: &ExchangeBudget, max_body: u64) -> u64 {
    u64::from(budget.max_message_bytes).min(budget.max_total_bytes).min(max_body)
}

/// Stall deadline for an admitted exchange (front end may only tighten it).
pub(crate) fn stall_ms(budget: &ExchangeBudget, limit_ms: u64) -> u64 {
    u64::from(budget.stall_ms).clamp(1, limit_ms.max(1))
}

/// F3 hook 2, then the handler under the exchange's stall deadline (504 if it has not answered by then).
pub(crate) async fn finish<A: App + ?Sized>(
    app: &A,
    adm: Admitted,
    conn: &ConnInfo,
    message: Vec<u8>,
    deadline: Duration,
) -> Reply {
    if let MessageVerdict::Close(s) = app.on_message(&adm.head(), &message) {
        return Reply::status(sanitize_status(s));
    }
    match tokio::time::timeout(deadline, app.handle(adm.into_request(message, conn))).await {
        Ok(mut r) => {
            r.status = sanitize_status(r.status);
            r
        }
        Err(_) => Reply::status(504),
    }
}

/// Statuses a handler may produce: 200..=599 except 1xx (interim responses are the core's business).
pub(crate) fn sanitize_status(s: u16) -> u16 {
    if (200..=599).contains(&s) { s } else { 500 }
}

/// Fields a reply may not set: framing (regenerated by the core) and hop-by-hop (RFC 9110 §7.6.1, RFC 9113 §8.2.2).
const NOT_FROM_HANDLER: &[&[u8]] = &[
    b"content-length",
    b"transfer-encoding",
    b"connection",
    b"keep-alive",
    b"proxy-connection",
    b"te",
    b"trailer",
    b"upgrade",
    b"http2-settings",
];

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
    for (n, v) in &reply.headers {
        let skip = NOT_FROM_HANDLER.contains(&n.as_slice())
            || (reply.content_type.is_some() && n == b"content-type")
            || (reply.location.is_some() && n == b"location");
        if skip {
            continue;
        }
        if let (Ok(n), Ok(v)) = (http::HeaderName::from_bytes(n), http::HeaderValue::from_bytes(v)) {
            b = b.header(n, v);
        }
    }
    // RFC 9110 §8.6: no Content-Length on 1xx / 204; on a 304 or a HEAD response only the announced length.
    let len = if reply.status < 200 || reply.status == 204 {
        None
    } else if reply.status == 304 || (head_request && reply.body.is_empty()) {
        reply.length
    } else {
        Some(reply.body.len())
    };
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
