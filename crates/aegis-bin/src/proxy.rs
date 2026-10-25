//! The per-request pipeline, independent of the inbound protocol:
//!
//! admission (aegis-admission S0..S6) → CANON-6 binding (`canon_request`: SNI / Host / `:authority` / Origin to one
//! vhost, 421 on mismatch) → method → canonical path (`canon_path`: 308 for `//`, never forwarded) → route match on
//! the canonical path → authz requirement (route without `authz` ⇒ 403, INV-NONEMPTY; only `allow-all` is evaluated
//! before Phase 3) → canonical query (`canon_query`, opaque by default) → canonical header set (`canon_headers`) →
//! upstream request built *only* from those canonical values (CANON-4): request line from `Canon<RoutePath>` +
//! `Canon<Query>`, `host` = the canonical authority, end-to-end fields from `Canon<HeaderSet>` minus hop-by-hop and
//! framing fields, `content-length` recomputed from the received body. No raw byte of the client request reaches
//! the upstream.
//!
//! The decision is made on the head alone ([`head`]), so a refused request is answered before its body is read and
//! the upstream never sees it.

use std::sync::Arc;

use aegis_canon::{Proto, Scheme, canon_headers, canon_path, canon_query, canon_request, header_fields};

use crate::plan::{Authz, UpstreamConnConfig};
use crate::shared::{Shared, bump};
use crate::upstream::{UpError, UpRequest};

/// One inbound request head, as parsed by the h1 or h2 driver (raw; nothing here is trusted).
#[derive(Debug)]
pub struct Inbound<'a> {
    pub proto: Proto,
    pub scheme: Scheme,
    pub sni: Option<&'a [u8]>,
    pub method: &'a [u8],
    /// h2 `:authority` (None on h1).
    pub authority: Option<&'a [u8]>,
    /// Request target as received (origin-form path and optional query).
    pub target: &'a [u8],
    /// Regular fields in arrival order (names as received). h2 cookie crumbs already joined.
    pub fields: Vec<(&'a [u8], &'a [u8])>,
}

/// A response to send to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    /// Lowercase names; `content-length` only when it must be kept verbatim (HEAD / 304).
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn status(status: u16) -> Self {
        Self { status, headers: Vec::new(), body: Vec::new() }
    }

    fn redirect(location: Vec<u8>) -> Self {
        Self { status: 308, headers: vec![(b"location".to_vec(), location)], body: Vec::new() }
    }

    /// The content length the writer must announce, if the reply carries one verbatim.
    pub fn explicit_length(&self) -> Option<&[u8]> {
        self.headers.iter().find(|(n, _)| n == b"content-length").map(|(_, v)| v.as_slice())
    }
}

/// An accepted request: everything the upstream will see, built from canonical values only.
#[derive(Debug)]
pub struct Admitted {
    pub method: http::Method,
    pub upstream: UpstreamConnConfig,
    pub authority: Vec<u8>,
    pub path_and_query: Vec<u8>,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body_cap: u64,
    pub expect_continue: bool,
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

fn method(m: &[u8]) -> Option<http::Method> {
    Some(match m {
        b"GET" => http::Method::GET,
        b"HEAD" => http::Method::HEAD,
        b"POST" => http::Method::POST,
        b"PUT" => http::Method::PUT,
        b"PATCH" => http::Method::PATCH,
        b"DELETE" => http::Method::DELETE,
        b"OPTIONS" => http::Method::OPTIONS,
        _ => return None,
    })
}

fn refuse(shared: &Shared, status: u16) -> Reply {
    bump(&shared.stats.canon_rejects);
    Reply::status(status)
}

/// Decide a request from its head. `Err` is the complete reply (nothing is forwarded).
pub fn head(shared: &Shared, inb: &Inbound<'_>) -> Result<Admitted, Reply> {
    let snap = shared.snapshot();
    let hosts: Vec<&[u8]> =
        inb.fields.iter().filter(|(n, _)| n.eq_ignore_ascii_case(b"host")).map(|(_, v)| *v).collect();
    let origin = inb.fields.iter().find(|(n, _)| n.eq_ignore_ascii_case(b"origin")).map(|(_, v)| *v);
    let identity = aegis_canon::RequestIdentity {
        proto: inb.proto,
        scheme: inb.scheme,
        sni: inb.sni,
        authority: inb.authority,
        host: &hosts,
        origin,
    };
    // CANON-6: SNI, Host / :authority and Origin bind to exactly one vhost (421 otherwise).
    let authority = snap.with_vhosts(|t| canon_request(&identity, t)).map_err(|r| refuse(shared, r.status()))?;
    let Some(method) = method(inb.method) else { return Err(refuse(shared, 501)) };
    let (raw_path, raw_query) = match inb.target.iter().position(|&b| b == b'?') {
        Some(i) => (inb.target.get(..i).unwrap_or(b""), inb.target.get(i.saturating_add(1)..).unwrap_or(b"")),
        None => (inb.target, &b""[..]),
    };
    let query = canon_query(raw_query, snap.plan.query);
    let path = match canon_path(raw_path) {
        Ok(p) => p,
        Err(r) => {
            bump(&shared.stats.canon_rejects);
            // q4-008: `//` is answered with 308 to the merged path; it is never forwarded.
            return Err(match r.redirect_target() {
                Some(t) if r.status() == 308 => {
                    let mut loc = t.to_vec();
                    if let Ok(q) = &query
                        && !q.as_bytes().is_empty()
                    {
                        loc.push(b'?');
                        loc.extend_from_slice(q.as_bytes());
                    }
                    Reply::redirect(loc)
                }
                _ => Reply::status(r.status()),
            });
        }
    };
    let Some(vhost) = snap.vhost(authority.as_bytes()) else { return Err(refuse(shared, 421)) };
    let Some(route) = vhost.route(path.as_bytes()) else { return Err(refuse(shared, 404)) };
    match &route.authz {
        Authz::AllowAll => {}
        Authz::Missing if shared.mutants.skip_authz_deny => {}
        Authz::Missing | Authz::Unknown(_) => {
            bump(&shared.stats.authz_denied);
            return Err(Reply::status(403));
        }
    }
    let query = query.map_err(|r| refuse(shared, r.status()))?;
    // CANON-1/2 header set: names lowercased, OWS trimmed, duplicate singletons / CL+TE / bad CL rejected.
    let lines: Vec<Vec<u8>> = inb
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
    let canon = canon_headers(&refs).map_err(|r| refuse(shared, r.status()))?;
    let all: Vec<(Vec<u8>, Vec<u8>)> = header_fields(&canon).map(|(n, v)| (n.to_vec(), v.to_vec())).collect();
    let expect_continue = all.iter().any(|(n, v)| n == b"expect" && v.eq_ignore_ascii_case(b"100-continue"));
    let headers = end_to_end(all);
    let mut path_and_query = path.as_bytes().to_vec();
    if !query.as_bytes().is_empty() {
        path_and_query.push(b'?');
        path_and_query.extend_from_slice(query.as_bytes());
    }
    if shared.mutants.raw_path {
        path_and_query = inb.target.to_vec();
    }
    Ok(Admitted {
        method,
        upstream: route.upstream.clone(),
        authority: authority.as_bytes().to_vec(),
        path_and_query,
        headers,
        body_cap: snap.plan.limits.max_body_bytes,
        expect_continue,
        stall_ms: snap.plan.limits.stall_timeout_ms,
    })
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
            let keep_len = adm.method == http::Method::HEAD || resp.status == 304;
            let len: Option<(Vec<u8>, Vec<u8>)> =
                resp.headers.iter().find(|(n, _)| n == b"content-length").filter(|_| keep_len).cloned();
            let mut headers = end_to_end(resp.headers);
            headers.extend(len);
            Reply {
                status: resp.status,
                headers,
                body: if adm.method == http::Method::HEAD { Vec::new() } else { resp.body },
            }
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
