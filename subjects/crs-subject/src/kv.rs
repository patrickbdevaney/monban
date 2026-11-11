//! The Valkey half of `do sql`: D12 provisioning, per-tenant ACL users, a scope-keyed pool, the confinement probe.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use monban_adapter_pg::TenantId;
use monban_adapter_pg::data_ir::tenant_text;
use monban_adapter_pg::pool::PoolMutations;
use monban_adapter_pg::{PlainReuse, Pool, PoolConfig, Pooled};
use monban_adapter_redis::render::physical_key;
use monban_adapter_redis::resp::{self, DEFAULT_LIMITS};
use monban_adapter_redis::{ConnectConfig, Connection, Endpoint, KvPins, Reply, TenantUser};

use crate::{Mutants, Scope, pool_key, random_hex};

/// The admin ACL user this harness creates (PLAN D12: `default` is turned off, so provisioning needs its own user).
const ADMIN_USER: &str = "crs-admin";
const QUIT: Duration = Duration::from_millis(200);
const BOOT_TIMEOUT: Duration = Duration::from_secs(10);
/// KV collection of the confinement probe.
const PROBE_COLLECTION: &str = "crs";

/// A pooled per-tenant (or, under the mutants, shared) Valkey connection. A RESP2 connection under a per-tenant ACL
/// user has no session state it could change (`-@all +get +set +del`), so it is returned to the pool as it is.
struct KvConn(Connection);

impl Pooled for KvConn {
    fn close(self) {
        self.0.close(QUIT);
    }
}

impl PlainReuse for KvConn {}

pub struct Kv {
    pins: KvPins,
    admin_cfg: ConnectConfig,
    admin: Connection,
    users: HashMap<TenantId, TenantUser>,
    pool: Pool<KvConn>,
    shared_tenant: TenantId,
}

/// One raw RESP2 round trip on a bootstrap socket (harness provisioning only; the adapter has no raw escape hatch).
fn raw_call<S: Read + Write>(s: &mut S, args: &[&[u8]]) -> Result<Reply, String> {
    let bytes = resp::encode(args, 1 << 16).map_err(|e| format!("encode: {e:?}"))?;
    s.write_all(&bytes).map_err(|e| format!("write: {e}"))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some((r, _)) = resp::parse(&buf, &DEFAULT_LIMITS).map_err(|e| format!("reply: {e:?}"))? {
            return Ok(r);
        }
        let n = s.read(&mut chunk).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("server closed the bootstrap connection".into());
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
    }
}

fn is_ok(r: &Reply) -> bool {
    matches!(r, Reply::Simple(s) if s == b"OK")
}

/// D12 engine provisioning: if `crs-admin` cannot log in yet, create it (as the stock `default` user) and turn
/// `default` off. Idempotent across the oracle's subject processes.
fn bootstrap<S: Read + Write>(s: &mut S, admin_pw: &str) -> Result<(), String> {
    if is_ok(&raw_call(s, &[b"AUTH", ADMIN_USER.as_bytes(), admin_pw.as_bytes()])?) {
        return Ok(());
    }
    let pass = format!(">{admin_pw}");
    let r = raw_call(
        s,
        &[b"ACL", b"SETUSER", ADMIN_USER.as_bytes(), b"reset", b"on", pass.as_bytes(), b"~*", b"&*", b"+@all"],
    )?;
    if !is_ok(&r) {
        return Err(format!("ACL SETUSER {ADMIN_USER}: {r:?}"));
    }
    let r = raw_call(s, &[b"ACL", b"SETUSER", b"default", b"off"])?;
    if !is_ok(&r) {
        return Err(format!("ACL SETUSER default off: {r:?}"));
    }
    Ok(())
}

fn bootstrap_endpoint(ep: &Endpoint, admin_pw: &str) -> Result<(), String> {
    match ep {
        Endpoint::Tcp { host, port } => {
            let addr = (host.as_str(), *port)
                .to_socket_addrs()
                .map_err(|e| format!("resolve {host}: {e}"))?
                .next()
                .ok_or_else(|| format!("resolve {host}: no address"))?;
            let mut s = TcpStream::connect_timeout(&addr, BOOT_TIMEOUT).map_err(|e| format!("connect: {e}"))?;
            s.set_read_timeout(Some(BOOT_TIMEOUT)).map_err(|e| e.to_string())?;
            s.set_write_timeout(Some(BOOT_TIMEOUT)).map_err(|e| e.to_string())?;
            bootstrap(&mut s, admin_pw)
        }
        Endpoint::Unix { path } => {
            let mut s = UnixStream::connect(path).map_err(|e| format!("connect: {e}"))?;
            s.set_read_timeout(Some(BOOT_TIMEOUT)).map_err(|e| e.to_string())?;
            s.set_write_timeout(Some(BOOT_TIMEOUT)).map_err(|e| e.to_string())?;
            bootstrap(&mut s, admin_pw)
        }
    }
}

/// Some valid tenant other than `t` (the confinement probe's foreign key).
fn other_tenant(t: TenantId) -> Result<TenantId, String> {
    TenantId::new(if t.get() == 1 { 2 } else { 1 }).map_err(|_| "tenant id".to_string())
}

/// Server-side tenant confinement of a KV session: the tenant's own key must be writable and another tenant's key
/// refused with NOPERM. Returns the tenant text when both hold, else what the session turned out to be.
fn probe(c: &mut Connection, t: TenantId) -> Result<String, String> {
    let own = physical_key(t, PROBE_COLLECTION, "probe").map_err(|e| format!("probe key: {e:?}"))?;
    let foreign = physical_key(other_tenant(t)?, PROBE_COLLECTION, "probe").map_err(|e| format!("probe key: {e:?}"))?;
    let text = tenant_text(t);
    let w = c.command(&[b"SET", own.as_bytes(), text.as_bytes()]).map_err(|e| format!("kv probe SET: {e}"))?;
    if !is_ok(&w) {
        return Ok(if w.is_noperm() { "kv:own-key-denied".into() } else { format!("kv:own-key-error {w:?}") });
    }
    let r = c.command(&[b"GET", foreign.as_bytes()]).map_err(|e| format!("kv probe GET: {e}"))?;
    Ok(if r.is_noperm() { text } else { "kv:unconfined".into() })
}

impl Kv {
    pub fn open(url: &str, admin_pw: &str, m: Mutants) -> Result<Kv, String> {
        let base = ConnectConfig::from_url(url).map_err(|e| format!("--redis: {e}"))?;
        bootstrap_endpoint(&base.endpoint, admin_pw).map_err(|e| format!("valkey bootstrap: {e}"))?;
        let admin_cfg =
            ConnectConfig { username: Some(ADMIN_USER.into()), password: Some(admin_pw.into()), ..base.clone() };
        let pins = KvPins::shipped();
        // The adapter's provisioning connection: first admission + the D12 `default` check.
        let admin = Connection::connect_provisioning(&admin_cfg, &pins).map_err(|e| format!("valkey admin: {e}"))?;
        let muts = PoolMutations { pool_key_no_epoch: m.key_no_epoch, ..PoolMutations::NONE };
        let pool = Pool::new_with(PoolConfig::default(), muts);
        let shared_tenant = TenantId::new(u64::MAX).map_err(|_| "shared tenant id".to_string())?;
        Ok(Kv { pins, admin_cfg, admin, users: HashMap::new(), pool, shared_tenant })
    }

    fn ensure_user(&mut self, t: TenantId) -> Result<TenantUser, String> {
        if let Some(u) = self.users.get(&t) {
            return Ok(u.clone());
        }
        let u = TenantUser::new(t, random_hex(24)?).map_err(|e| format!("tenant user: {e}"))?;
        self.admin.provision(&u).map_err(|e| format!("provision {}: {e}", u.username()))?;
        self.users.insert(t, u.clone());
        Ok(u)
    }

    /// The tenant the KV session of this request is confined to (see [`probe`]).
    pub fn request(&mut self, m: Mutants, s: &Scope) -> Result<String, String> {
        let u = self.ensure_user(s.tenant)?;
        let (key, shared) =
            pool_key(m, s, u.username(), ADMIN_USER, self.shared_tenant).map_err(|e| format!("kv pool key: {e}"))?;
        let cfg = if shared {
            self.admin_cfg.clone()
        } else {
            ConnectConfig {
                username: Some(u.username().into()),
                password: Some(u.password().into()),
                ..self.admin_cfg.clone()
            }
        };
        let pinned = *self.admin.admitted();
        let pins = &self.pins;
        let mut co = self
            .pool
            .acquire(&key, |_| Connection::connect(&cfg, pins, Some(&pinned)).map(KvConn))
            .map_err(|e| format!("kv acquire: {e}"))?;
        let out = match co.session() {
            Ok(c) => probe(&mut c.0, s.tenant),
            Err(e) => Err(e.to_string()),
        };
        if out.is_ok() && co.peek().0.is_reusable() {
            self.pool.put_back(co);
        } else {
            drop(co); // closes the connection, never pools it
        }
        out
    }

    pub fn close(self) {
        self.pool.close_idle();
        self.admin.close(QUIT);
    }
}
