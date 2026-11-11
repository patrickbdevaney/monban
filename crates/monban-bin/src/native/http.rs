//! One request on an app route (oracles/native-e2e "Subject contract").
//!
//! Order: method → `monban-deadline-ms` (can only lower the deadline; 400 out of range) → Tier-L token
//! (`monban_token::verify` with `Req{aud = vhost host, ops = the endpoint's op bit, res = canonical segments,
//! tenant = the token's tenant caveat}`; 401/403, no effect) → the app parses the request (400 / uniform 404) → the
//! path tenant must be the principal's (else the uniform denial, W6) → mutations need an `Idempotency-Key` (428)
//! → the request takes its (backend, tenant) slot ([`super::scope::Registry`]) → a key that already committed is
//! answered from the backend's `monban_idem` (INV-IDEMP) → the handler runs on the blocking pool (X-11) while this
//! task watches the deadline.
//!
//! * Nothing is sent before the handler returned, i.e. after its commit point (NC7): a 2xx implies the effect is
//!   durable when its first byte leaves.
//! * Deadline: before the commit point → 504 and the commit refuses (NC1); after it → 202 with the key echoed, and
//!   the stored outcome is served by key (NC2).
//! * Client gone before the commit point → cancelled, nothing commits (NC1): monban-transport drops this future on
//!   an h1 FIN/RST or an h2 `RST_STREAM` before the reply (and on a transport timeout or connection teardown), and
//!   [`InFlight`]'s `Drop` cancels the commit gate.

use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use monban_adapter_host::dispatch::{DispatchError, EngineError, Refusal};
use monban_adapter_host::host::reply::{HttpReply, Json, reply};
use monban_adapter_host::host::{ScopeOutcome, SessionHandle};
use monban_canon::header_fields;
use monban_data_ir::OpKind;
use monban_token::{Caveat, TokenL};
use monban_transport::exchange::Method;
use monban_transport::{Reply, ReplyBody, Request};
use monban_types::{Principal, RouteId};

use super::scope::{AppTicket, Claim, Idem, Phase, ReqCtx, Slot};
use super::{AppRoute, DataPlane};
use crate::shared::Shared;
use crate::util::{Either, race};

/// Deadline of a request when no backend gives one.
const DEFAULT_DEADLINE_MS: u64 = 5000;
const MAX_DEADLINE_HEADER_MS: u64 = 60_000;
/// Poll period of the deadline / drain watch while the handler runs.
const TICK: Duration = Duration::from_millis(10);

fn to_reply(h: HttpReply) -> Reply {
    let mut r = Reply::new(h.status, h.content_type(), ReplyBody::Owned(h.body.clone()));
    r.headers = h.headers().iter().skip(1).map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec())).collect();
    r
}

/// A JSON reply with the fixed content type and headers (nosniff, CSP sandbox, no-store).
fn json(status: u16, body: String) -> Reply {
    let mut h = reply(Ok(Json(body)));
    h.status = status;
    to_reply(h)
}

fn error(status: u16, code: &str) -> Reply {
    json(status, format!("{{\"error\":\"{code}\"}}"))
}

/// The uniform denial: byte for byte the reply to a missing note or a missing capability (W6).
fn denied() -> Reply {
    to_reply(reply::<String>(Err(DispatchError::Refused(Refusal::Denied).to_sdk())))
}

fn unavailable() -> Reply {
    to_reply(reply::<String>(Err(DispatchError::Engine(EngineError::Unavailable(String::new())).to_sdk())))
}

fn header<'a>(req: &'a Request, name: &[u8]) -> Option<&'a [u8]> {
    header_fields(&req.headers).find(|(n, _)| *n == name).map(|(_, v)| v)
}

fn app_method(m: Method) -> Option<notes::Method> {
    Some(match m {
        Method::Get => notes::Method::Get,
        Method::Post => notes::Method::Post,
        Method::Patch => notes::Method::Patch,
        Method::Put => notes::Method::Put,
        Method::Delete => notes::Method::Delete,
        _ => return None,
    })
}

/// F5 / `monban_sdk::op_code` op bits.
fn op_bit(k: OpKind) -> u8 {
    match k {
        OpKind::Select => 1,
        OpKind::Insert => 2,
        OpKind::Update => 4,
        OpKind::Delete => 8,
        OpKind::Upsert => 16,
    }
}

/// Canonical path segments for the token's `res` caveat (a trailing `/` is not a segment).
fn segments(path: &str) -> Option<Vec<String>> {
    let p = match path.strip_suffix('/') {
        Some(p) if !p.is_empty() => p,
        _ => path,
    };
    monban_token::path_segments(p)
}

/// Tier-L verification. `Ok((principal, token op mask))`; `Err(status)` is 401 or 403.
fn authenticate(dp: &DataPlane, req: &Request, aud: &str, op: u8, path: &str) -> Result<(Principal, u8), u16> {
    let v = header(req, b"authorization").ok_or(401u16)?;
    let tok = v.strip_prefix(b"Bearer ").or_else(|| v.strip_prefix(b"bearer ")).ok_or(401u16)?;
    let bytes = monban_agent::b64::decode_url(crate::util::trim_ows(tok)).ok_or(401u16)?;
    let t = TokenL::decode(&bytes).map_err(|_| 401u16)?;
    // The tenant comes only from the token's tenant caveat (INV-NO-AMBIENT); a token without one is refused.
    let tenant =
        t.caveats.iter().find_map(|c| if let Caveat::Tenant(x) = c { Some(*x) } else { None }).ok_or(401u16)?;
    let ops = t.caveats.iter().fold(0x1fu8, |m, c| if let Caveat::Ops(o) = c { m & *o } else { m });
    let r = monban_token::Req {
        aud: aud.to_string(),
        ops: u64::from(op),
        res: segments(path).ok_or(401u16)?,
        tenant,
        holder: Vec::new(),
        tool: String::new(),
        args: Vec::new(),
        now: u64::try_from(crate::util::unix_s()).unwrap_or(0),
    };
    match monban_token::verify(&bytes, &dp.keyring, &r) {
        Ok(p) => Ok((p, ops)),
        Err(monban_token::VerifyError::Denied) => Err(403),
        Err(_) => Err(401),
    }
}

fn push_json_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 || c == '\u{2028}' || c == '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn render_out(out: notes::Out, ctx: &ReqCtx) -> Reply {
    match out {
        notes::Out::Json { status, body } => json(status, body),
        notes::Out::Row { status } => {
            let g = ctx.rows.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some((names, rows)) = g.as_ref() else { return denied() };
            let Some(row) = rows.first() else { return denied() };
            let mut s = String::from("{");
            for (i, (n, v)) in names.iter().zip(row.iter()).enumerate() {
                if i > 0 {
                    s.push(',');
                }
                push_json_str(&mut s, n);
                s.push(':');
                match v {
                    Some(v) => push_json_str(&mut s, v),
                    None => s.push_str("null"),
                }
            }
            s.push('}');
            json(status, s)
        }
    }
}

fn accepted(key: Option<&str>) -> Reply {
    let mut r = json(202, "{\"status\":\"accepted\"}".into());
    if let Some(k) = key {
        r.headers.push((b"idempotency-key".to_vec(), k.as_bytes().to_vec()));
    }
    r
}

/// A held (backend, tenant) slot and, once the handler was started, its ticket. On drop: the request is
/// cancelled if its commit point was not passed (a no-op after it), and the slot is released when the pool task has
/// ended (at once if it already has, else by a task that waits for it).
struct InFlight {
    dp: Arc<DataPlane>,
    slot: Slot,
    ctx: Option<Arc<ReqCtx>>,
    ticket: Option<AppTicket>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if let Some(c) = &self.ctx {
            c.gate.cancel();
        }
        let (dp, slot) = (Arc::clone(&self.dp), self.slot);
        match (self.ticket.take(), tokio::runtime::Handle::try_current()) {
            (Some(t), Ok(rt)) => {
                rt.spawn(async move {
                    let _ = t.await;
                    dp.reg.release(slot);
                });
            }
            // No runtime to wait on: dropping the ticket cancels the task's token; the gate is already cancelled.
            _ => dp.reg.release(slot),
        }
    }
}

/// Serve one request on an app route.
pub async fn handle(
    shared: &Arc<Shared>,
    dp: &Arc<DataPlane>,
    route: &AppRoute,
    route_id: u64,
    req: &Request,
) -> Reply {
    let t0 = Instant::now();
    let Some(method) = app_method(req.method) else { return error(405, "method") };
    // Deadline: the backend's op budget, lowered by the header, and kept inside the transport's own handler bound.
    let budget = route.backend.and_then(|i| dp.engines.get(i)).map_or(DEFAULT_DEADLINE_MS, |b| b.budget_ms);
    let mut dl_ms = budget.min(shared.snapshot().plan.limits.stall_timeout_ms.saturating_sub(100).max(1));
    if let Some(v) = header(req, b"monban-deadline-ms") {
        match std::str::from_utf8(v).ok().and_then(|s| s.parse::<u64>().ok()) {
            Some(ms) if (1..=MAX_DEADLINE_HEADER_MS).contains(&ms) => dl_ms = dl_ms.min(ms),
            _ => return error(400, "bad_deadline"),
        }
    }
    let deadline = t0 + Duration::from_millis(dl_ms);
    let Ok(path) = std::str::from_utf8(req.path.as_bytes()) else { return denied() };
    let (principal, token_ops) = match authenticate(dp, req, &route.host, op_bit(method.op_kind()), path) {
        Ok(v) => v,
        Err(401) => return error(401, "unauthenticated"),
        Err(s) => return error(s, "forbidden"),
    };
    let rest = path.strip_prefix(route.path.as_str()).unwrap_or("");
    let app = match notes::parse(method, rest, &req.body) {
        Ok(a) => a,
        Err(notes::Refusal::NotFound) => return denied(),
        Err(notes::Refusal::BadBody) => return error(400, "bad_body"),
    };
    // The path names a tenant; it must be the token's (uniform denial otherwise). The data tenant is always the
    // principal's: the SDK binds every op to it.
    let mut data_tenant = principal.tenant();
    let path_tenant = monban_data_ir::parse_tenant_text(app.path_tenant());
    if dp.mutants.tenant_from_path {
        // NEGATIVE CONTROL (e2e-mutants only): the tenant is taken from the path, not from the token.
        let Some(t) = path_tenant else { return denied() };
        data_tenant = t;
    } else if path_tenant != Some(principal.tenant()) {
        return denied();
    }
    let committed = app.committed();
    let key = match &committed {
        None => None,
        Some(_) => match header(req, b"idempotency-key").and_then(|k| std::str::from_utf8(k).ok()) {
            Some(k)
                if !k.is_empty()
                    && k.len() <= 64
                    && k.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-') =>
            {
                Some(k.to_string())
            }
            _ => return error(428, "idempotency_key_required"),
        },
    };
    // A route without a data capability still runs the app (it is denied at its first grant); it borrows the
    // first backend's pool and slot, and its executor refuses to begin. With no backend at all, deny here.
    let reach = route.backend.is_some();
    let idx = match route.backend {
        Some(i) => i,
        None if !dp.engines.is_empty() => 0,
        None => return denied(),
    };
    let Some(backend) = dp.engines.get(idx) else { return unavailable() };
    let slot: Slot = (idx, principal.tenant());
    // One request per (backend, tenant) at a time: the seams the assembly owns see only the tenant (scope.rs).
    loop {
        let freed = dp.reg.freed();
        let mut freed = pin!(freed);
        freed.as_mut().enable();
        if dp.reg.try_take(slot) {
            break;
        }
        if tokio::time::timeout_at(deadline.into(), freed).await.is_err() {
            return error(504, "deadline");
        }
    }
    let mut inflight = InFlight { dp: Arc::clone(dp), slot, ctx: None, ticket: None };
    let mut idem = None;
    let mut claim = None;
    if let (Some(notes::Out::Json { status, body }), Some(k), true) = (&committed, &key, reach) {
        let ph = DataPlane::principal_hex(&principal);
        // Replay of a committed key: the stored outcome, nothing re-executed (INV-IDEMP).
        let (dp2, p2, k2) = (Arc::clone(dp), principal.clone(), k.clone());
        let found = match backend.engine.pool().try_run(move || dp2.lookup(idx, &p2, &k2)) {
            Ok(t) => t.await,
            Err(_) => return error(503, "busy"),
        };
        match found {
            Ok(Ok(Some((status, body)))) => return json(status, body),
            Ok(Ok(None)) => {}
            _ => return unavailable(),
        }
        match Claim::take(&dp.claims, &ph, k) {
            Some(c) => claim = Some(c),
            None => return error(409, "in_progress"),
        }
        idem = Some(Idem { principal: ph, key: k.clone(), status: *status, body: body.clone() });
    }
    let Ok(rid) = RouteId::new(route_id) else { return denied() };
    let session = SessionHandle::new(principal, rid, route.caps.clone(), token_ops);
    let ctx = Arc::new(ReqCtx::new(reach, data_tenant, idem, claim, &dp.mutants));
    dp.reg.set(slot, Arc::clone(&ctx));
    inflight.ctx = Some(Arc::clone(&ctx));
    match backend.engine.call(Arc::new(app), &session) {
        Ok(t) => inflight.ticket = Some(t),
        Err(_) => return error(503, "busy"),
    }
    loop {
        let Some(ticket) = inflight.ticket.as_mut() else { return unavailable() };
        match race(ticket, tokio::time::sleep(TICK)).await {
            Either::Left(r) => {
                inflight.ticket = None; // finished: the slot is released at once
                return match r {
                    Ok(ScopeOutcome { result: Ok(out), .. }) => render_out(out, &ctx),
                    Ok(ScopeOutcome { result: Err(e), .. }) => to_reply(reply::<String>(Err(e))),
                    Err(_) => unavailable(),
                };
            }
            Either::Right(()) => {}
        }
        if dp.is_dropping() {
            // NEGATIVE CONTROL `ack-then-drop` (e2e-mutants only): a fabricated success during shutdown.
            return json(201, "{\"status\":\"ok\"}".into());
        }
        if ctx.early.load(Ordering::Acquire)
            && let Some(out) = committed.clone()
        {
            // NEGATIVE CONTROL `body-before-cp` (e2e-mutants only): the reply leaves before the commit point.
            return render_out(out, &ctx);
        }
        if Instant::now() >= deadline {
            return match ctx.gate.cancel() {
                Phase::Open | Phase::Cancelled | Phase::Failed => error(504, "deadline"),
                Phase::Committed => accepted(key.as_deref()),
                Phase::Committing => {
                    // The commit point was passed: wait for COMMIT to settle, then 202 iff it committed.
                    if let Some(t) = inflight.ticket.as_mut()
                        && tokio::time::timeout(Duration::from_millis(budget), t).await.is_ok()
                    {
                        inflight.ticket = None;
                    }
                    if ctx.gate.phase() == Phase::Committed { accepted(key.as_deref()) } else { error(504, "deadline") }
                }
            };
        }
    }
}
