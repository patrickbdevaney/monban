//! One request on a `{"wasm": <module-id>}` route (oracles/p2-e2e "Subject contract", F14 Part 3).
//!
//! Order: route authz requirement (INV-NONEMPTY; 403) → F5 Tier-L token (`aegis_token::verify` with
//! `Req{aud = vhost host, ops = the method's op bit, res = the canonical path segments, tenant = the token's tenant
//! caveat}`; 401/403) → the canonical `req-head` (I5: method, canonical path, canonical query, the allowlisted
//! request fields only, body length) → [`super::Runtime::serve`] on the blocking pool → the reply.
//!
//! Data: the route's endowment (its F8 `data` block, resolved at boot by the native data plane) and the verified
//! principal travel with the request as a [`super::data::Store`]; a route without `data` holds no capability.
//!
//! Responses (PLAN D17, F14 I7): the module's decision is one input of the F6 tri-state combiner next to the
//! route's authz decision. `handle()` = 0 completed by `resp-end` is Allow; 1 is Deny; everything else (trap, fuel,
//! wall bound, quota, worker death, decode failure, another code) is Error, which the combiner never turns into
//! Allow. Allow is the module's status, headers (after the supervisor's I5 re-check) and body, re-serialized by
//! aegis-transport with host-computed framing; anything else is the one fixed Deny response, byte for byte, with
//! no module byte. A principal in penalty gets 429 before dispatch.

use std::sync::Arc;

use aegis_authz::{Decision, combine};
use aegis_canon::header_fields;
use aegis_canon::kind::RoutePath;
use aegis_token::{Caveat, TokenL};
use aegis_transport::exchange::Method;
use aegis_transport::{Reply, ReplyBody, Request};

use super::exchange::Outcome;
use super::frame::{Query, REQ_HEADER_ALLOW, ReqHead};
use super::{Key, Served};
use crate::plan::{Authz, RouteTo};
use crate::shared::{Shared, bump};

/// The host's fixed Deny response (oracles/hostile-modules `DENY`): every Deny and every Error of a P2 route.
pub fn deny() -> Reply {
    Reply::new(403, "text/plain", ReplyBody::Static(b"denied\n"))
}

/// A principal in crash-budget penalty (D7).
fn penalty() -> Reply {
    Reply::new(429, "text/plain", ReplyBody::Static(b"crash budget exhausted\n"))
}

fn method_name(m: Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Head => "HEAD",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Patch => "PATCH",
        Method::Delete => "DELETE",
        Method::Options => "OPTIONS",
        Method::Connect => "CONNECT",
    }
}

/// The F5 op bit a method needs (the F10 kind order: select insert update delete upsert).
fn op_bit(m: Method) -> u64 {
    match m {
        Method::Get | Method::Head | Method::Options | Method::Connect => 1,
        Method::Post => 2,
        Method::Put | Method::Patch => 4,
        Method::Delete => 8,
    }
}

/// Canonical path segments for the token's `res` caveat (a trailing `/` is not a segment).
fn segments(path: &str) -> Option<Vec<String>> {
    let p = match path.strip_suffix('/') {
        Some(p) if !p.is_empty() => p,
        _ => path,
    };
    aegis_token::path_segments(p)
}

/// Tier-L verification; `Ok` is the request's crash-budget and cordon key (tenant, issuer kid of the verified
/// token) with the verified principal, `Err` 401 or 403.
fn authenticate(
    keyring: &aegis_token::KeyRing,
    req: &Request,
    aud: &str,
    path: &str,
) -> Result<(Key, aegis_types::Principal), u16> {
    let v = header_fields(&req.headers).find(|(n, _)| *n == b"authorization").map(|(_, v)| v).ok_or(401u16)?;
    let tok = v.strip_prefix(b"Bearer ").or_else(|| v.strip_prefix(b"bearer ")).ok_or(401u16)?;
    let bytes = aegis_agent::b64::decode_url(crate::util::trim_ows(tok)).ok_or(401u16)?;
    let t = TokenL::decode(&bytes).map_err(|_| 401u16)?;
    // The tenant comes only from the token's tenant caveat (INV-NO-AMBIENT); a token without one is refused.
    let tenant =
        t.caveats.iter().find_map(|c| if let Caveat::Tenant(x) = c { Some(*x) } else { None }).ok_or(401u16)?;
    let r = aegis_token::Req {
        aud: aud.to_string(),
        ops: op_bit(req.method),
        res: segments(path).ok_or(401u16)?,
        tenant,
        holder: Vec::new(),
        tool: String::new(),
        args: Vec::new(),
        now: u64::try_from(crate::util::unix_s()).unwrap_or(0),
    };
    match aegis_token::verify(&bytes, keyring, &r) {
        Ok(principal) if principal.tenant().get() == tenant => Ok((Key::new(tenant, t.kid), principal)),
        Ok(_) => Err(403),
        Err(aegis_token::VerifyError::Denied) => Err(403),
        Err(_) => Err(401),
    }
}

fn unhex(b: u8) -> Option<u8> {
    char::from(b).to_digit(16).and_then(|d| u8::try_from(d).ok())
}

/// Percent-decodes one canonical typed-query component into UTF-8 (`None`: a bad escape or invalid UTF-8).
fn pct_decode(s: &[u8]) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let mut it = s.iter();
    while let Some(&b) = it.next() {
        if b == b'%' {
            let (h, l) = (unhex(*it.next()?)?, unhex(*it.next()?)?);
            out.push(h * 16 + l);
        } else {
            out.push(b);
        }
    }
    String::from_utf8(out).ok()
}

/// F14 `query` from the canonical query (`Canon<Query>` is already checked by aegis-canon in the configured mode).
fn query(q: &[u8], mode: aegis_canon::QueryMode) -> Option<Query> {
    match mode {
        aegis_canon::QueryMode::Opaque => Some(Query::Opaque(q.to_vec())),
        aegis_canon::QueryMode::Typed => {
            let mut out = Vec::new();
            for p in q.split(|&b| b == b'&').filter(|p| !p.is_empty()) {
                let (n, v) = match p.iter().position(|&b| b == b'=') {
                    Some(i) => (p.get(..i)?, p.get(i + 1..)?),
                    None => (p, &b""[..]),
                };
                out.push((pct_decode(n)?, pct_decode(v)?));
            }
            Some(Query::Typed(out))
        }
    }
}

/// The canonical `req-head` (I5); `None` if a canonical value cannot be expressed (400).
fn req_head(req: &Request, path: &PathText<'_>, mode: aegis_canon::QueryMode) -> Option<ReqHead> {
    let headers = header_fields(&req.headers)
        .filter_map(|(n, v)| {
            let n = std::str::from_utf8(n).ok()?;
            REQ_HEADER_ALLOW.contains(&n).then(|| (n.to_string(), v.to_vec()))
        })
        .collect();
    Some(ReqHead {
        method: method_name(req.method).to_string(),
        path: path.0.to_string(),
        query: query(req.query.as_bytes(), mode)?,
        headers,
        body_len: Some(u64::try_from(req.body.len()).unwrap_or(u64::MAX)),
    })
}

/// The canonical route path as text.
struct PathText<'a>(&'a str);

fn path_text(p: &aegis_canon::Canon<RoutePath>) -> Option<PathText<'_>> {
    std::str::from_utf8(p.as_bytes()).ok().map(PathText)
}

/// The module's Allow answer, re-serialized: status and the I5-checked fields as structured values, the body as an
/// opaque payload; aegis-transport computes the framing.
fn allow(status: u16, headers: Vec<(Vec<u8>, Vec<u8>)>, body: Vec<u8>) -> Reply {
    let mut r = Reply::status(status);
    r.headers = headers;
    r.body = if body.is_empty() { ReplyBody::Empty } else { ReplyBody::Owned(body) };
    r
}

/// Serves `req` if its route targets a P2 module; `None` for any other route.
pub async fn handle(shared: &Arc<Shared>, req: &Request) -> Option<Reply> {
    let snap = shared.snapshot();
    let vhost = snap.vhost(req.authority.as_bytes())?;
    let route = vhost.route(req.path.as_bytes())?;
    let RouteTo::Wasm(module) = &route.to else { return None };
    if route.authz != Authz::AllowAll {
        bump(&shared.stats.authz_denied);
        return Some(Reply::status(403));
    }
    let Some(rt) = shared.p2.clone() else { return Some(Reply::status(503)) };
    let Some(path) = path_text(&req.path) else { return Some(Reply::status(400)) };
    let Some(keyring) = rt.keyring() else { return Some(Reply::status(503)) };
    let (key, principal) = match authenticate(&keyring, req, &vhost.host, path.0) {
        Ok(k) => k,
        Err(s) => return Some(Reply::status(s)),
    };
    let Some(head) = req_head(req, &path, snap.plan.query) else { return Some(Reply::status(400)) };
    let head = head.encode();
    let module = module.clone();
    let body = req.body.clone();
    let store = crate::native::p2_store(shared.native.as_ref(), &snap.native, &vhost.host, route.id, principal);
    let config_hash = snap.hash;
    drop(snap);
    let served =
        tokio::task::spawn_blocking(move || rt.serve(&key, &module, &head, &body, store.as_deref(), config_hash)).await;
    // The route's authz decision (allow-all, checked above) and the module's, combined (F6; I7).
    let module_decision = match &served {
        Ok(Served::Done(Outcome::Allow { .. })) => Decision::Allow,
        Ok(Served::Done(Outcome::Deny)) => Decision::Deny,
        _ => Decision::Error,
    };
    let decision = combine(&[Decision::Allow, module_decision]);
    Some(match served {
        Ok(Served::Done(Outcome::Allow { status, headers, body })) if decision == Decision::Allow => {
            allow(status, headers, body)
        }
        Ok(Served::Penalty) => penalty(),
        Ok(Served::Unavailable) => Reply::status(503),
        // Deny and every Error (I7, D17): the one fixed response.
        Ok(Served::Done(_)) | Err(_) => deny(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn typed_query_is_decoded_in_order() {
        let q = query(b"b=2&a=%C3%A9&c", aegis_canon::QueryMode::Typed).unwrap();
        assert_eq!(
            q,
            Query::Typed(vec![("b".into(), "2".into()), ("a".into(), "\u{e9}".into()), ("c".into(), String::new())])
        );
        assert_eq!(query(b"a=%ff", aegis_canon::QueryMode::Typed), None);
        assert_eq!(query(b"a=%f", aegis_canon::QueryMode::Typed), None);
        assert_eq!(query(b"n=1", aegis_canon::QueryMode::Opaque), Some(Query::Opaque(b"n=1".to_vec())));
    }

    #[test]
    fn op_bits_and_segments() {
        assert_eq!(op_bit(Method::Get), 1);
        assert_eq!(op_bit(Method::Delete), 8);
        assert_eq!(segments("/a/"), Some(vec!["a".to_string()]));
        assert_eq!(deny().status, 403);
        assert_eq!(penalty().status, 429);
    }
}
