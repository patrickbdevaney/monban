//! The proxy front end: an [`aegis_transport::App`] served by `aegis_transport::Server` on both HTTP/1.1 and h2.
//!
//! The transport runs, in order: admission ([`ProxyApp::arrive`], aegis-admission S0..S6) → CANON-6 binding
//! (`canon_request`: SNI / Host / `:authority` / Origin to one vhost, 421 on mismatch) → method → canonical path
//! (`canon_path`: 308 for `//` with the canonical query, never forwarded) → route match on the canonical path
//! ([`ProxyApp::route`]) → F3 hook 1 ([`ProxyApp::on_head`]: authz requirement; a route without `authz` ⇒ 403,
//! INV-NONEMPTY; only `allow-all` is evaluated before Phase 3) → canonical query (`canon_query`, opaque by default)
//! → canonical header set (`canon_headers`) → bounded body (TBI-6/7 ledger) → [`ProxyApp::handle`] under the TBI-4
//! permit. The handler builds the upstream request *only* from those canonical values (CANON-4): request line from
//! `Canon<RoutePath>` + `Canon<Query>`, `host` = the canonical authority, end-to-end fields from
//! `Canon<HeaderSet>` minus hop-by-hop and framing fields, `content-length` recomputed from the received body. No
//! raw byte of the client request reaches the upstream. The reply goes back through the transport's ledger-gated
//! send path.
//!
//! The decision is made on the head alone (`on_head`), so a refused request is answered before its body is read
//! and the upstream never sees it.

use std::sync::Arc;

use aegis_canon::kind::{Authority, RoutePath};
use aegis_canon::{Canon, QueryMode, header_fields};
use aegis_transport::exchange::{ExchangeBudget, FrontEnd, Head, HeadVerdict, MessageVerdict, Method, Mode};
use aegis_transport::{App, ConnInfo, HandlerFuture, Reply, ReplyBody, Request};
use aegis_types::RouteId;

use crate::plan::{Authz, RouteRt, Snapshot, UpstreamConnConfig};
use crate::shared::{Peer, Shared, bump};
use crate::upstream::{UpError, UpRequest};

/// An accepted request: everything the upstream will see, built from canonical values only.
#[derive(Debug)]
pub struct Admitted {
    pub method: http::Method,
    pub upstream: UpstreamConnConfig,
    pub authority: Vec<u8>,
    pub path_and_query: Vec<u8>,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub stall_ms: u64,
}

/// Hop-by-hop and framing fields: never forwarded, regenerated where needed (RFC 9110 §7.6.1, RFC 9113 §8.2.2).
const HOP: &[&[u8]] = &[
    b"host",
    b"content-length",
    b"transfer-encoding",
    b"connection",
    b"keep-alive",
    b"proxy-connection",
    b"te",
    b"trailer",
    b"upgrade",
    b"expect",
    b"http2-settings",
];

fn connection_tokens(fields: &[(Vec<u8>, Vec<u8>)]) -> Vec<Vec<u8>> {
    fields
        .iter()
        .filter(|(n, _)| n == b"connection")
        .flat_map(|(_, v)| v.split(|&b| b == b',').map(|t| crate::util::trim_ows(t).to_ascii_lowercase()))
        .filter(|t| !t.is_empty())
        .collect()
}

/// Drop hop-by-hop fields (and the ones `Connection` names) from a lowercase field list.
pub fn end_to_end(fields: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let named = connection_tokens(&fields);
    fields.into_iter().filter(|(n, _)| !HOP.contains(&n.as_slice()) && !named.contains(n)).collect()
}

fn http_method(m: Method) -> Option<http::Method> {
    Some(match m {
        Method::Get => http::Method::GET,
        Method::Head => http::Method::HEAD,
        Method::Post => http::Method::POST,
        Method::Put => http::Method::PUT,
        Method::Patch => http::Method::PATCH,
        Method::Delete => http::Method::DELETE,
        Method::Options => http::Method::OPTIONS,
        Method::Connect => return None,
    })
}

/// The proxy as a transport front end.
#[derive(Debug)]
pub struct ProxyApp {
    pub shared: Arc<Shared>,
}

fn find_route<'s>(snap: &'s Snapshot, authority: &[u8], path: &[u8]) -> Option<&'s RouteRt> {
    snap.vhost(authority)?.route(path)
}

/// The exchange budget for the served config: the profile limits bound the body and the stall (the transport takes
/// the tighter of this and its own limits).
fn budget(snap: &Snapshot) -> ExchangeBudget {
    let body = u32::try_from(snap.plan.limits.max_body_bytes).unwrap_or(u32::MAX);
    ExchangeBudget {
        max_message_bytes: body,
        max_frame_bytes: u32::try_from(snap.plan.wl.max_frame_size).unwrap_or(u32::MAX),
        max_messages: 1,
        max_total_bytes: u64::from(body),
        stall_ms: u32::try_from(snap.plan.limits.stall_timeout_ms).unwrap_or(u32::MAX),
    }
}

impl ProxyApp {
    /// `Err` is the authz refusal (403).
    fn authorize(&self, route: &RouteRt) -> Result<(), u16> {
        match &route.authz {
            Authz::AllowAll => Ok(()),
            Authz::Missing if self.shared.mutants.skip_authz_deny => Ok(()),
            Authz::Missing | Authz::Unknown(_) => Err(403),
        }
    }

    /// Everything the upstream will see, from the canonical request and the current routing table.
    fn upstream_request(&self, req: &Request) -> Result<Admitted, Reply> {
        let snap = self.shared.snapshot();
        let Some(method) = http_method(req.method) else { return Err(Reply::status(501)) };
        // The table may have been reloaded since the head was decided: resolve and authorize again.
        let Some(vhost) = snap.vhost(req.authority.as_bytes()) else { return Err(Reply::status(421)) };
        let Some(route) = vhost.route(req.path.as_bytes()) else { return Err(Reply::status(404)) };
        if let Err(s) = self.authorize(route) {
            bump(&self.shared.stats.authz_denied);
            return Err(Reply::status(s));
        }
        let all: Vec<(Vec<u8>, Vec<u8>)> = header_fields(&req.headers).map(|(n, v)| (n.to_vec(), v.to_vec())).collect();
        let mut path_and_query = req.path.as_bytes().to_vec();
        if !req.query.as_bytes().is_empty() {
            path_and_query.push(b'?');
            path_and_query.extend_from_slice(req.query.as_bytes());
        }
        #[cfg(feature = "e2e-mutants")]
        if self.shared.mutants.raw_path {
            path_and_query = req.raw_target.clone();
        }
        Ok(Admitted {
            method,
            upstream: route.upstream.clone(),
            authority: req.authority.as_bytes().to_vec(),
            path_and_query,
            headers: end_to_end(all),
            stall_ms: snap.plan.limits.stall_timeout_ms,
        })
    }
}

impl FrontEnd for ProxyApp {
    fn on_head(&self, head: &Head<'_>) -> HeadVerdict {
        let snap = self.shared.snapshot();
        let Some(route) = find_route(&snap, head.authority.as_bytes(), head.path.as_bytes()) else {
            return HeadVerdict::Reject(404);
        };
        match self.authorize(route) {
            Ok(()) => HeadVerdict::Accept(Mode::Unary, budget(&snap)),
            Err(s) => {
                bump(&self.shared.stats.authz_denied);
                HeadVerdict::Reject(s)
            }
        }
    }

    fn on_message(&self, _head: &Head<'_>, _message: &[u8]) -> MessageVerdict {
        MessageVerdict::Continue
    }
}

impl App for ProxyApp {
    fn route(&self, authority: &Canon<Authority>, path: &Canon<RoutePath>, _method: Method) -> Option<RouteId> {
        let snap = self.shared.snapshot();
        find_route(&snap, authority.as_bytes(), path.as_bytes()).and_then(|r| RouteId::new(r.id).ok())
    }

    fn handle(&self, req: Request) -> HandlerFuture<'_> {
        Box::pin(async move {
            match self.upstream_request(&req) {
                Ok(adm) => forward(&self.shared, &adm, &req.body).await,
                Err(reply) => reply,
            }
        })
    }

    fn query_mode(&self) -> QueryMode {
        self.shared.snapshot().plan.query
    }

    fn arrive(&self, conn: &ConnInfo, first: bool) -> Result<u64, u16> {
        let id = self.shared.next_id();
        bump(&self.shared.stats.requests);
        self.shared.admit(id, &Peer::new(conn.peer, conn.id), first).map(|()| id)
    }

    fn depart(&self, ticket: u64, cancelled: bool) {
        self.shared.done(ticket, cancelled);
    }

    fn refused(&self, _status: u16) {
        bump(&self.shared.stats.canon_rejects);
    }

    fn conn_closed(&self, conn: &ConnInfo, admitted: bool) {
        if admitted {
            self.shared.conn_closed(&Peer::new(conn.peer, conn.id));
        }
    }
}

/// Forward an admitted request with its (size-checked) body and build the client reply.
pub async fn forward(shared: &Arc<Shared>, adm: &Admitted, body: &[u8]) -> Reply {
    let req = UpRequest {
        method: &adm.method,
        authority: &adm.authority,
        path_and_query: &adm.path_and_query,
        headers: &adm.headers,
        body,
    };
    match shared.pool.request(shared, &adm.upstream, &req, adm.stall_ms).await {
        Ok(resp) => {
            bump(&shared.stats.forwarded);
            let head = adm.method == http::Method::HEAD;
            // A HEAD or 304 response announces the length of the body it does not carry: keep it verbatim.
            let length = resp
                .headers
                .iter()
                .find(|(n, _)| n == b"content-length")
                .filter(|_| head || resp.status == 304)
                .and_then(|(_, v)| std::str::from_utf8(v).ok()?.parse::<u64>().ok());
            let mut reply = Reply::status(resp.status);
            reply.headers = end_to_end(resp.headers);
            reply.length = length;
            reply.body = if head || resp.body.is_empty() { ReplyBody::Empty } else { ReplyBody::Owned(resp.body) };
            reply
        }
        Err(e) => {
            bump(&shared.stats.upstream_errors);
            eprintln!("aegis: upstream {}: {e}", adm.upstream.target);
            Reply::status(if matches!(e, UpError::Timeout) { 504 } else { 502 })
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn hop_by_hop_dropped() {
        let f = vec![
            (b"connection".to_vec(), b"x-secret, keep-alive".to_vec()),
            (b"x-secret".to_vec(), b"1".to_vec()),
            (b"x-ok".to_vec(), b"2".to_vec()),
            (b"transfer-encoding".to_vec(), b"chunked".to_vec()),
            (b"host".to_vec(), b"h".to_vec()),
        ];
        assert_eq!(end_to_end(f), vec![(b"x-ok".to_vec(), b"2".to_vec())]);
    }
}
