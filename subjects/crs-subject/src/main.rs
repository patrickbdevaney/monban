//! crs-subject: the CRS data plane over the `oracles/crs-diff --family data` protocol, against live engines
//! (P4-crs-001; SPEC §B CRS C2, C3, C5, C5b, C8; R-DB-5).
//!
//! Usage: `crs-subject [--mutant <name>]... --pg <dsn> --redis <url>` (the oracle appends `--pg` / `--redis`).
//!
//! One JSON request per line on stdin, one JSON reply per line on stdout (`oracles/crs-diff/README.md`, "Subject
//! wire protocol"). Everything observable comes from the production crates:
//!
//! * `do sql` ([`pg`]): one data request. A backend is checked out of an `aegis_adapter_pg::Pool` under the
//!   request's [`PoolKey`](aegis_adapter_pg::PoolKey) (principal, tenant, per-tenant login role, epoch); a recycled
//!   connection runs the adapter's C8 reset (DISCARD ALL + cache-generation bump) before its session is reachable.
//!   The subject then reads `pg_backend_pid()` (`conn`) and whether any per-connection object survived (temp
//!   relation, prepared statement, session GUC: `temp_residual`, read before the request dirties the session),
//!   binds the tenant with the adapter's `rls_bind` inside a transaction and reads the tenant GUC back (`guc`),
//!   dirties the session (temp table, `PREPARE`, session-level GUC) and releases the connection through the NC3
//!   path. `cache` is the pool connection id plus the driver cache generation it is bound to. The same request
//!   also checks out a Valkey connection from a second pool under the same key shape, authenticated as the
//!   tenant's ACL user (`aegis_adapter_redis::TenantUser`, R-DB-5), and probes it server side ([`kv`]): the
//!   tenant's own key must be writable and another tenant's key refused with NOPERM. `guc.tenant` is the tenant
//!   only when both engines agree on it; otherwise it names the disagreement, so a KV session bound to the wrong
//!   tenant (or to no tenant) fails the oracle's GUC check.
//! * `do idem` / `do outbox` ([`scoped`]): `aegis_state::State` in a private temporary directory. Idempotency is
//!   keyed by `IdemKey(principal, key)`; an outbox entry is an effect of a committed request and carries its
//!   (principal, tenant) scope, and only entries of the current scope are listed.
//!
//! Engine provisioning (harness duty, PLAN D12): per-tenant PG login roles (LOGIN, no superuser, no BYPASSRLS,
//! SCRAM password) and per-tenant Valkey ACL users are created on first use through admin connections. On Valkey
//! the subject creates an admin ACL user and turns `default` off before the adapter's provisioning connection
//! (`Connection::connect_provisioning`, which runs the D12 check) is opened; the admin password is derived from the
//! run's random PG password, so the oracle's later subject processes on the same engines can log in again.
//!
//! Mutants (oracle names; `--mutant` may repeat): `shared-pool` (one pool key for every scope, admin login),
//! `pool-key-no-tenant` (the key keeps only the epoch: shared login, no tenant, no principal),
//! `pool-key-no-epoch` (the adapter's hidden `PoolMutations::pool_key_no_epoch`), `no-reset-on-recycle`
//! (`PoolMutations::recycle_no_reset`), `idem-key-without-principal` (aegis-state's hidden
//! `StateMutations::idem_key_without_principal`), `outbox-no-principal` (the listing ignores the scope).
//!
//! Epochs are pool-key coordinates only; the subject never calls `Pool::retire_before`, because the oracle's C5b
//! differential sends a lower epoch after a higher one (A at epoch 9, then B at epoch 5) and requires a reply.
#![forbid(unsafe_code)]

mod json;
mod kv;
mod pg;
mod scoped;

use std::io::{BufRead, Read, Write};
use std::process::ExitCode;

use aegis_adapter_pg::data_ir::parse_tenant_text;
use aegis_adapter_pg::{KeyError, PoolKey, TenantId};
use json::{Json, esc};

const MAX_LINE: u64 = 1 << 20;

/// The oracle's mutant names.
const MUTANTS: [&str; 6] = [
    "shared-pool",
    "pool-key-no-tenant",
    "pool-key-no-epoch",
    "no-reset-on-recycle",
    "idem-key-without-principal",
    "outbox-no-principal",
];

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Mutants {
    pub shared_pool: bool,
    pub key_no_tenant: bool,
    pub key_no_epoch: bool,
    pub no_reset: bool,
    pub idem_no_principal: bool,
    pub outbox_no_principal: bool,
}

/// The scope of the following requests.
#[derive(Clone, Debug)]
pub(crate) struct Scope {
    pub principal: String,
    pub tenant: TenantId,
    pub epoch: u64,
}

/// Principal bytes of the shared pool keys (mutants only).
const SHARED_PRINCIPAL: &[u8] = b"*";

/// The pool key of a request, and whether its connection logs in with the shared admin login instead of the
/// tenant's own role (the mutants that drop the tenant from the key cannot use a per-tenant login).
pub(crate) fn pool_key(
    m: Mutants,
    s: &Scope,
    tenant_login: &str,
    shared_login: &str,
    shared_tenant: TenantId,
) -> Result<(PoolKey, bool), KeyError> {
    if m.shared_pool {
        return Ok((PoolKey::new(SHARED_PRINCIPAL, shared_tenant, shared_login, 0)?, true));
    }
    if m.key_no_tenant {
        return Ok((PoolKey::new(SHARED_PRINCIPAL, shared_tenant, shared_login, s.epoch)?, true));
    }
    Ok((PoolKey::new(s.principal.as_bytes(), s.tenant, tenant_login, s.epoch)?, false))
}

/// Random lower-case hex from the kernel CSPRNG.
pub(crate) fn random_hex(bytes: usize) -> Result<String, String> {
    let mut f = std::fs::File::open("/dev/urandom").map_err(|e| format!("/dev/urandom: {e}"))?;
    let mut b = vec![0u8; bytes];
    f.read_exact(&mut b).map_err(|e| format!("/dev/urandom: {e}"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

struct Args {
    muts: Mutants,
    pg: String,
    redis: String,
}

fn parse_args() -> Result<Args, String> {
    let mut muts = Mutants::default();
    let (mut pg, mut redis) = (None, None);
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--mutant" => {
                let n = it.next().ok_or("--mutant needs a name")?;
                match n.as_str() {
                    "shared-pool" => muts.shared_pool = true,
                    "pool-key-no-tenant" => muts.key_no_tenant = true,
                    "pool-key-no-epoch" => muts.key_no_epoch = true,
                    "no-reset-on-recycle" => muts.no_reset = true,
                    "idem-key-without-principal" => muts.idem_no_principal = true,
                    "outbox-no-principal" => muts.outbox_no_principal = true,
                    other => return Err(format!("unknown mutant {other:?} (known: {})", MUTANTS.join(", "))),
                }
            }
            "--pg" => pg = Some(it.next().ok_or("--pg needs a DSN")?),
            "--redis" => redis = Some(it.next().ok_or("--redis needs a URL")?),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(Args { muts, pg: pg.ok_or("--pg <dsn> is required")?, redis: redis.ok_or("--redis <url> is required")? })
}

struct Subject {
    muts: Mutants,
    scope: Option<Scope>,
    pg: pg::Pg,
    kv: kv::Kv,
    st: scoped::Scoped,
}

/// A request field as text (strings as they are, anything else as its JSON text).
fn text_field(req: &Json, k: &str) -> Result<String, String> {
    match req.get(k) {
        Some(Json::Str(s)) => Ok(s.clone()),
        Some(j) => Ok(json::emit(j)),
        None => Err(format!("missing field {k:?}")),
    }
}

impl Subject {
    fn scope(&self) -> Result<&Scope, String> {
        self.scope.as_ref().ok_or_else(|| "no scope set".to_string())
    }

    fn set_scope(&mut self, req: &Json) -> Result<String, String> {
        let principal = text_field(req, "principal")?;
        if principal.is_empty() {
            return Err("empty principal".into());
        }
        let tenant = req
            .get("tenant")
            .and_then(Json::str)
            .and_then(parse_tenant_text)
            .ok_or("tenant must be 16 lower-case hex digits, not all zero")?;
        let epoch = match req.get("epoch") {
            Some(Json::Num(t)) => t.parse::<u64>().map_err(|_| format!("epoch {t} is not a u64"))?,
            _ => return Err("epoch must be a number".into()),
        };
        self.scope = Some(Scope { principal, tenant, epoch });
        Ok("{\"ok\":true}".into())
    }

    fn do_sql(&mut self) -> Result<String, String> {
        let s = self.scope()?.clone();
        let obs = self.pg.request(self.muts, &s)?;
        let kv_tenant = self.kv.request(self.muts, &s)?;
        let tenant = match obs.guc.as_deref() {
            Some(g) if g == kv_tenant => g.to_string(),
            g => format!("mismatch(pg={},kv={kv_tenant})", g.unwrap_or("<unset>")),
        };
        Ok(format!(
            "{{\"conn\":{},\"guc\":{{\"tenant\":{}}},\"temp_residual\":{},\"cache\":{}}}",
            esc(&obs.conn),
            esc(&tenant),
            obs.residual,
            esc(&obs.cache)
        ))
    }

    fn do_idem(&mut self, req: &Json) -> Result<String, String> {
        let s = self.scope()?.clone();
        let key = text_field(req, "key")?;
        let value = text_field(req, "value")?;
        let (prior, fresh) = self.st.idem(&s, &key, &value)?;
        let prior = prior.map_or_else(|| "null".to_string(), |p| esc(&p));
        Ok(format!("{{\"idem\":{prior},\"fresh\":{fresh}}}"))
    }

    fn do_outbox(&mut self, req: &Json) -> Result<String, String> {
        let s = self.scope()?.clone();
        let entry = text_field(req, "entry")?;
        let vis = self.st.outbox(&s, &entry, self.muts.outbox_no_principal)?;
        let items: Vec<String> = vis.iter().map(|e| esc(e)).collect();
        Ok(format!("{{\"outbox\":[{}]}}", items.join(",")))
    }

    /// `None`: `bye` (exit without a reply).
    fn handle(&mut self, line: &str) -> Option<Result<String, String>> {
        let req = match json::parse(line) {
            Ok(j) => j,
            Err(e) => return Some(Err(format!("bad request: {e}"))),
        };
        let r = match req.get("op").and_then(Json::str) {
            Some("hello") => Ok("{\"ok\":true}".into()),
            Some("scope") => self.set_scope(&req),
            Some("do") => match req.get("kind").and_then(Json::str) {
                Some("sql") => self.do_sql(),
                Some("idem") => self.do_idem(&req),
                Some("outbox") => self.do_outbox(&req),
                other => Err(format!("unknown kind {other:?}")),
            },
            Some("bye") => return None,
            other => Err(format!("unknown op {other:?}")),
        };
        Some(r)
    }
}

fn serve(subj: &mut Subject) -> ExitCode {
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut out = std::io::stdout().lock();
    loop {
        let mut buf = Vec::new();
        match (&mut input).take(MAX_LINE).read_until(b'\n', &mut buf) {
            Ok(0) => return ExitCode::SUCCESS,
            Ok(_) => {}
            Err(_) => return ExitCode::from(2),
        }
        let over = buf.last() != Some(&b'\n') && buf.len() as u64 >= MAX_LINE;
        if over {
            let mut sink = Vec::new();
            if input.read_until(b'\n', &mut sink).is_err() {
                return ExitCode::from(2);
            }
        }
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let reply = if over {
            Err("request line too long".to_string())
        } else {
            match subj.handle(line) {
                None => return ExitCode::SUCCESS,
                Some(r) => r,
            }
        };
        let text = match reply {
            Ok(t) => t,
            Err(e) => {
                eprintln!("crs-subject: {e}");
                format!("{{\"error\":{}}}", esc(&e))
            }
        };
        if writeln!(out, "{text}").and_then(|()| out.flush()).is_err() {
            return ExitCode::from(2);
        }
    }
}

fn run(a: Args) -> Result<ExitCode, String> {
    let pg = pg::Pg::open(&a.pg, a.muts)?;
    let kv = kv::Kv::open(&a.redis, &pg.kv_admin_password()?, a.muts)?;
    let st = scoped::Scoped::open(a.muts)?;
    let mut subj = Subject { muts: a.muts, scope: None, pg, kv, st };
    let code = serve(&mut subj);
    let Subject { pg, kv, st, .. } = subj;
    pg.close();
    kv.close();
    st.close();
    Ok(code)
}

fn main() -> ExitCode {
    let a = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!(
                "crs-subject: {e}\nusage: crs-subject [--mutant <name>]... --pg <dsn> --redis <url>   (oracles/crs-diff \
                 --family data protocol on stdin/stdout)"
            );
            return ExitCode::from(2);
        }
    };
    match run(a) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("crs-subject: {e}");
            ExitCode::from(1)
        }
    }
}
