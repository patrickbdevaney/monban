//! `aegis agent --config <agent.json>`: the MCP listener gate (aegis-agent) on the AEGIS transport.
//!
//! Wiring (all fail closed):
//! * inbound: `aegis_transport::Server` (strict H1 / h2c, TBI wrapper limits at their golden values) with a vhost
//!   table built from the gate's Host and Origin allowlists (CANON-6 binding in the core; an unbound Origin is
//!   answered 403 there, as MCP mandates, via `App::origin_refusal_status`), then the gate itself;
//! * authorization: the out-of-process Cedar PDP over the PDP-1 SOCK_SEQPACKET client from aegis-adapter-host
//!   (no Cedar in this binary); a missing or failing PDP is `Decision::Error` and every call is denied (403);
//! * upstream: aegis-egress only (allowlisted hosts and ports from the config, resolve-once vetted addresses,
//!   explicit re-admission of private ranges, no redirects followed, deadline and response caps).
//!
//! Boot refuses (exit 78) on any config, secret or upstream-URL error before a socket is bound. The gate runs on the
//! blocking pool (its PDP exchange is a blocking socket call under the PDP deadline).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use aegis_adapter_host::pdp_uds::UdsTransport;
use aegis_agent::gate::{self, HttpRequest, Response, UpstreamReply, Verdict};
use aegis_agent::{AgentConfig, Gate, PdpAuthorizer};
use aegis_canon::kind::{Authority, RoutePath};
use aegis_canon::{Canon, header_fields};
use aegis_egress::{Egress, HostRule, NetConnector, Policy, Prefix, SystemResolver, Url};
use aegis_transport::exchange::{ExchangeBudget, FrontEnd, Head, HeadVerdict, MessageVerdict, Method, Mode};
use aegis_transport::{App, HandlerFuture, Reply, ReplyBody, Request, Server, VhostTable, WrapperLimits};
use aegis_types::RouteId;

const EX_USAGE: u8 = 64;
const EX_CONFIG: u8 = 78;
const EX_OSERR: u8 = 71;
/// Config and secret files larger than this are refused.
const MAX_FILE: u64 = 1 << 20;
/// Request body budget (the JSON owner's own cap is the same 1 MiB).
const BODY: u32 = 1 << 20;
/// Upstream fetch deadline.
const UPSTREAM_DEADLINE: Duration = Duration::from_secs(10);
/// Async workers of the agent listener's runtime. Decision (P8-bin-002, R5): this stays the constant 2 and does not
/// follow F8 `runtime.worker_threads`. `aegis agent` is configured by the aegis-agent `AgentConfig` file, not by an
/// F8 document, so F8 `runtime` never reaches it, and giving the agent config a worker field is an interface change
/// (spec author, not this unit). The listener is not CPU-bound on its async workers either: every call blocks on the
/// PDP exchange under its deadline, on the blocking pool ([`AGENT_BLOCKING`]), and no scaling gate measures it.
/// No timing default changes.
const AGENT_WORKERS: usize = 2;
/// Blocking-pool threads of the agent listener (the gate's PDP exchange runs there).
const AGENT_BLOCKING: usize = 8;

pub const USAGE: &str = "aegis agent --config <agent.json>";

fn log(m: &str) {
    eprintln!("aegis agent: {m}");
}

fn read_small(p: &Path) -> Result<Vec<u8>, String> {
    let md = std::fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
    if md.len() > MAX_FILE {
        return Err(format!("{}: larger than {MAX_FILE} bytes", p.display()));
    }
    std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))
}

/// A secret file: its bytes, minus one trailing newline.
fn read_secret(p: &str) -> Result<Vec<u8>, String> {
    let mut b = read_small(Path::new(p))?;
    if b.last() == Some(&b'\n') {
        b.pop();
    }
    Ok(b)
}

/// The egress policy for the configured upstreams: exactly their hosts and ports, plain http only if an upstream
/// uses it, private ranges only through the explicit `egress_readmit` list, no redirects.
fn egress_policy(cfg: &AgentConfig) -> Result<Policy, String> {
    let mut p = Policy {
        max_redirects: 0,
        cross_origin_redirects: false,
        deadline: UPSTREAM_DEADLINE,
        max_response_bytes: usize::try_from(BODY).unwrap_or(usize::MAX),
        ..Policy::default()
    };
    for r in &cfg.routes {
        for u in &r.upstreams {
            let url = Url::parse(&u.url).map_err(|e| format!("route {}: upstream {}: {e}", r.path, u.url))?;
            let rule = HostRule::Exact(url.host().allowlist_key());
            if !p.allowed_hosts.contains(&rule) {
                p.allowed_hosts.push(rule);
            }
            if !p.allowed_ports.contains(&url.port()) {
                p.allowed_ports.push(url.port());
            }
            if url.scheme() == aegis_egress::Scheme::Http {
                p.allow_plain_http = true;
            }
        }
    }
    for s in &cfg.egress_readmit {
        p.readmit.push(Prefix::parse(s).ok_or_else(|| format!("egress_readmit: bad prefix {s:?}"))?);
    }
    Ok(p)
}

struct AgentApp {
    gate: Arc<Gate>,
    egress: Egress<SystemResolver, NetConnector>,
    policy: Policy,
}

fn budget() -> ExchangeBudget {
    ExchangeBudget {
        max_message_bytes: BODY,
        max_frame_bytes: 16_384,
        max_messages: 1,
        max_total_bytes: u64::from(BODY),
        stall_ms: 10_000,
    }
}

fn gate_method(m: Method) -> gate::Method {
    match m {
        Method::Get => gate::Method::Get,
        Method::Head => gate::Method::Head,
        Method::Post => gate::Method::Post,
        Method::Put => gate::Method::Put,
        Method::Patch => gate::Method::Patch,
        Method::Delete => gate::Method::Delete,
        Method::Options => gate::Method::Options,
        Method::Connect => gate::Method::Other,
    }
}

fn to_reply(r: Response) -> Reply {
    let mut reply = Reply::status(r.status);
    reply.headers = r.headers.into_iter().map(|(n, v)| (n.into_bytes(), v.into_bytes())).collect();
    if !r.body.is_empty() {
        reply.content_type = Some("application/json");
        reply.body = ReplyBody::Owned(r.body);
    }
    reply
}

impl FrontEnd for AgentApp {
    fn on_head(&self, head: &Head<'_>) -> HeadVerdict {
        match self.gate.target(head.path.as_bytes()) {
            Some(_) => HeadVerdict::Accept(Mode::Unary, budget()),
            None => HeadVerdict::Reject(404),
        }
    }

    fn on_message(&self, _head: &Head<'_>, _message: &[u8]) -> MessageVerdict {
        MessageVerdict::Continue
    }
}

impl App for AgentApp {
    fn route(&self, _authority: &Canon<Authority>, path: &Canon<RoutePath>, _method: Method) -> Option<RouteId> {
        let id = match self.gate.target(path.as_bytes())? {
            gate::Target::Mcp(i) => i,
            gate::Target::Metadata(i) => i.saturating_add(1 << 20),
        };
        RouteId::new(u64::try_from(id).ok()?.saturating_add(1)).ok()
    }

    /// MCP mandates 403 for an invalid Origin; the CANON-6 binding itself still runs in the transport core.
    fn origin_refusal_status(&self) -> u16 {
        403
    }

    fn handle(&self, req: Request) -> HandlerFuture<'_> {
        Box::pin(async move {
            let now = u64::try_from(crate::util::unix_s()).unwrap_or(0);
            let gate = self.gate.clone();
            let method = gate_method(req.method);
            let checked = tokio::task::spawn_blocking(move || {
                let fields: Vec<(&[u8], &[u8])> = header_fields(&req.headers).collect();
                let hr = HttpRequest {
                    method,
                    authority: req.authority.as_bytes(),
                    path: req.path.as_bytes(),
                    headers: &fields,
                    body: &req.body,
                };
                gate.check(&hr, now)
            })
            .await;
            let fwd = match checked {
                Ok(Verdict::Reply(r)) => return to_reply(r),
                Ok(Verdict::Forward(f)) => f,
                Err(_) => return Reply::status(500),
            };
            let mut replies = Vec::with_capacity(fwd.calls().len());
            for call in fwd.calls() {
                let r = match Url::parse(&call.url) {
                    Ok(url) => {
                        let rq = aegis_egress::Request {
                            method: aegis_egress::Method::Post,
                            url,
                            headers: call.headers.clone(),
                            body: call.body.clone(),
                        };
                        self.egress
                            .fetch(&self.policy, rq)
                            .await
                            .map(|resp| UpstreamReply { status: resp.status, body: resp.body })
                            .map_err(|_| ())
                    }
                    Err(_) => Err(()),
                };
                replies.push(r);
            }
            to_reply(self.gate.complete(*fwd, replies, now))
        })
    }
}

fn parse_args(args: &[OsString]) -> Result<PathBuf, String> {
    let mut it = args.iter();
    let mut config = None;
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("--config") => config = it.next().map(PathBuf::from),
            _ => return Err(format!("unknown argument {a:?}\nusage: {USAGE}")),
        }
    }
    config.ok_or_else(|| format!("--config is required\nusage: {USAGE}"))
}

/// Entry point for `aegis agent ...` (`args` without the `agent` word).
pub fn run(args: &[OsString]) -> ExitCode {
    let path = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            log(&e);
            return ExitCode::from(EX_USAGE);
        }
    };
    let boot = || -> Result<(AgentConfig, Arc<Gate>, Policy), String> {
        let cfg = AgentConfig::parse(&read_small(&path)?)?;
        let secret = read_secret(&cfg.hs256_secret_file)?;
        let upstream_cred = match &cfg.upstream_credential_file {
            Some(f) => {
                let t = String::from_utf8(read_secret(f)?).map_err(|_| format!("{f}: not UTF-8"))?;
                Some(format!("Bearer {t}"))
            }
            None => None,
        };
        let policy = egress_policy(&cfg)?;
        let pdp = UdsTransport::new(PathBuf::from(&cfg.pdp_socket), Duration::from_millis(cfg.pdp_deadline_ms));
        let gate = Gate::new(&cfg, &secret, upstream_cred, Box::new(PdpAuthorizer::new(pdp)))?;
        Ok((cfg, Arc::new(gate), policy))
    };
    let (cfg, gate, policy) = match boot() {
        Ok(v) => v,
        Err(e) => {
            log(&format!("refusing to serve: {e}"));
            return ExitCode::from(EX_CONFIG);
        }
    };
    if aegis_adapter_host::pdp_uds::connect_to(Path::new(&cfg.pdp_socket)).is_err() {
        log(&format!("warning: PDP socket {} not reachable now; every call is denied until it is", cfg.pdp_socket));
    }
    let mut vhosts = VhostTable::new();
    let origins: Vec<&[u8]> = gate.origins().iter().map(String::as_bytes).collect();
    for h in gate.hosts() {
        vhosts.add(h.as_bytes(), &origins);
    }
    let app = AgentApp { gate, egress: Egress::new(SystemResolver, NetConnector::plain()), policy };
    let srv = match Server::new(app, vhosts, WrapperLimits::GOLDEN) {
        Ok(s) => s,
        Err(e) => {
            log(&format!("transport limits: {e}"));
            return ExitCode::from(EX_CONFIG);
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(AGENT_WORKERS)
        .max_blocking_threads(AGENT_BLOCKING)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log(&format!("runtime: {e}"));
            return ExitCode::from(EX_OSERR);
        }
    };
    rt.block_on(async move {
        let listener = match tokio::net::TcpListener::bind(&cfg.listen).await {
            Ok(l) => l,
            Err(e) => {
                log(&format!("bind {}: {e}", cfg.listen));
                return ExitCode::from(EX_OSERR);
            }
        };
        let addr = listener.local_addr().map(|a| a.to_string()).unwrap_or_default();
        let routes: Vec<&str> = cfg.routes.iter().map(|r| r.path.as_str()).collect();
        log(&format!("listening on http://{addr} routes {routes:?}"));
        println!("LISTENING http://{addr}");
        loop {
            match listener.accept().await {
                Ok((sock, peer)) => {
                    let _ = sock.set_nodelay(true);
                    tokio::spawn(srv.clone().serve_plain_from(sock, Some(peer)));
                }
                Err(e) => {
                    log(&format!("accept: {e}"));
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    })
}
