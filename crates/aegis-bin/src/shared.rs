//! Process-wide state shared by the listeners, the admin endpoint and the control thread.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use aegis_admission::{Admission, Arrive, Close, Credential, Done, Lane, Stage, Verdict};
use aegis_budget::Gcra;
use aegis_metrics::{AdmissionStage, BudgetScope, Registry};
use tokio::sync::Notify;

use crate::plan::Snapshot;
use crate::upstream::Pool;

/// Proxy counters exported next to the golden families (not golden; names are `aegis_proxy_*`).
#[derive(Debug, Default)]
pub struct ProxyStats {
    pub requests: AtomicU64,
    pub forwarded: AtomicU64,
    pub authz_denied: AtomicU64,
    pub canon_rejects: AtomicU64,
    pub upstream_errors: AtomicU64,
    pub upstream_connects: AtomicU64,
    pub config_reloads: AtomicU64,
}

pub fn bump(a: &AtomicU64) {
    let _ = a.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_add(1)));
}

/// Negative controls for `oracles/proxy-e2e --self-test` (feature `e2e-mutants` only; env `AEGIS_E2E_MUTANT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Mutants {
    /// Forward the raw request target instead of the canonical path and query.
    pub raw_path: bool,
    /// Treat a route without `authz` as allowed (breaks INV-NONEMPTY).
    pub skip_authz_deny: bool,
    /// On a failed reload, drop the served config instead of keeping the last-known-good (breaks CFG-3).
    pub skip_lkg: bool,
}

impl Mutants {
    #[cfg(feature = "e2e-mutants")]
    pub fn from_env() -> Self {
        let v = std::env::var("AEGIS_E2E_MUTANT").unwrap_or_default();
        let has = |n: &str| v.split(',').any(|s| s.trim() == n);
        let m = Self { raw_path: has("raw-path"), skip_authz_deny: has("skip-authz-deny"), skip_lkg: has("skip-lkg") };
        if m != Self::default() {
            eprintln!("aegis: E2E NEGATIVE-CONTROL BUILD, mutants active: {m:?}");
        }
        m
    }
    #[cfg(not(feature = "e2e-mutants"))]
    pub fn from_env() -> Self {
        Self::default()
    }
}

/// Provisional admission numbers (ARCHITECTURE §3.4 numbers are D-grade): generous per-IP rate, no expensive tier
/// (every proxied request costs 1, below `exp_cost`), concurrency cap 4096.
pub fn admission_config() -> aegis_admission::Config {
    let per_ip = Gcra::new(1_000_000, 2_000); // 1000/s sustained, burst 2000
    aegis_admission::Config {
        s1: per_ip,
        s1_store: 65_536,
        s3_store: 65_536,
        anon: per_ip,
        session: per_ip,
        verified: per_ip,
        agg_f: Gcra::new(1_000_000, 2_000),
        agg_e: Gcra::new(1_000_000, 2_000),
        exp_cost: u64::MAX,
        stepup_cost: u64::MAX,
        stepup_bits: 0,
        limit: 4096,
        max_conns: 16_384,
        prefix_cap: 4096,
        fresh_age_ns: 3_600_000_000_000,
    }
}

fn stage_label(s: Stage) -> AdmissionStage {
    match s {
        Stage::S0 => AdmissionStage::S0,
        Stage::S1 => AdmissionStage::S1,
        Stage::S2 => AdmissionStage::S2,
        Stage::S3 => AdmissionStage::S3,
        Stage::S3A => AdmissionStage::S3A,
        Stage::S4 => AdmissionStage::S4,
        Stage::S5 => AdmissionStage::S5,
        Stage::S6 => AdmissionStage::S6,
    }
}

#[derive(Debug)]
pub struct Shared {
    pub registry: Registry,
    pub stats: ProxyStats,
    snapshot: RwLock<Arc<Snapshot>>,
    pub pool: Pool,
    admission: Mutex<Admission>,
    started: Instant,
    next_id: AtomicU64,
    /// Upgrade / shutdown: stop keep-alive, GOAWAY h2.
    pub draining: AtomicBool,
    pub drain_notify: Notify,
    /// Stop accepting (listener fds are closed by the accept tasks).
    pub stop_accept: AtomicBool,
    pub stop_notify: Notify,
    pub accept_tasks: AtomicUsize,
    pub live_conns: AtomicUsize,
    pub mutants: Mutants,
    /// notAfter of the serving certificate (Unix s), `i64::MIN` before the first install (CERT-1 gauge source).
    pub cert_not_after: AtomicI64,
}

impl Shared {
    pub fn new(snapshot: Snapshot) -> Arc<Self> {
        let s = Arc::new(Self {
            registry: Registry::new(),
            stats: ProxyStats::default(),
            pool: Pool::new(snapshot.epoch),
            snapshot: RwLock::new(Arc::new(snapshot)),
            admission: Mutex::new(Admission::new(admission_config())),
            started: Instant::now(),
            next_id: AtomicU64::new(1),
            draining: AtomicBool::new(false),
            drain_notify: Notify::new(),
            stop_accept: AtomicBool::new(false),
            stop_notify: Notify::new(),
            accept_tasks: AtomicUsize::new(0),
            live_conns: AtomicUsize::new(0),
            mutants: Mutants::from_env(),
            cert_not_after: AtomicI64::new(i64::MIN),
        });
        let h = s.snapshot().hash;
        s.registry.set_config_hash(&h);
        s
    }

    pub fn snapshot(&self) -> Arc<Snapshot> {
        match self.snapshot.read() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Install a new routing table. A new epoch flushes every pooled upstream connection (CRS C5).
    pub fn install(&self, snap: Snapshot) {
        let epoch = snap.epoch;
        self.registry.set_config_hash(&snap.hash);
        match self.snapshot.write() {
            Ok(mut g) => *g = Arc::new(snap),
            Err(p) => *p.into_inner() = Arc::new(snap),
        }
        self.pool.set_epoch(epoch);
    }

    pub fn now_ns(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    pub fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    fn admission(&self) -> std::sync::MutexGuard<'_, Admission> {
        self.admission.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Admission S0..S6 for one request (anonymous, cost 1). `Err(status)` is a 401/429/503 reject (I7).
    pub fn admit(&self, id: u64, peer: &Peer, newconn: bool) -> Result<(), u16> {
        let ev = Arrive {
            id,
            t: self.now_ns(),
            ip: peer.ip.clone(),
            prefix: peer.prefix.clone(),
            conn: peer.conn.clone(),
            newconn,
            cred: Credential::None,
            cost: 1,
            pow: 0,
            lane: Lane::Std,
            fault: None,
        };
        let v = self.admission().arrive(&ev);
        match v {
            Verdict::Admit => {
                self.registry.budget_debits.inc(BudgetScope::Ip);
                self.registry.budget_debits.inc(BudgetScope::Identity);
                Ok(())
            }
            Verdict::Reject { stage, .. } => {
                self.registry.admission_rejects.inc(stage_label(stage));
                Err(v.http_status())
            }
        }
    }

    pub fn done(&self, id: u64, cancelled: bool) {
        let ev = Done { id, t: self.now_ns(), actual_cost: 1, cancelled };
        self.admission().done(&ev);
    }

    pub fn conn_closed(&self, peer: &Peer) {
        let ev = Close { conn: peer.conn.clone(), t: self.now_ns() };
        self.admission().close(&ev);
    }
}

/// The client side of one connection, as admission keys it.
#[derive(Clone, Debug)]
pub struct Peer {
    pub ip: String,
    /// /24 (IPv4) or /48 (IPv6) prefix: the S0 per-prefix cap key.
    pub prefix: String,
    pub conn: String,
}

impl Peer {
    pub fn new(addr: Option<std::net::SocketAddr>, conn_id: u64) -> Self {
        let (ip, prefix) = match addr.map(|a| a.ip()) {
            Some(std::net::IpAddr::V4(v4)) => {
                let [a, b, c, _] = v4.octets();
                (v4.to_string(), format!("{a}.{b}.{c}.0/24"))
            }
            Some(std::net::IpAddr::V6(v6)) => {
                let [a, b, c, ..] = v6.segments();
                (v6.to_string(), format!("{a:x}:{b:x}:{c:x}::/48"))
            }
            None => ("local".to_string(), "local".to_string()),
        };
        Self { ip, prefix, conn: format!("c{conn_id}") }
    }
}

/// RAII live-connection gauge (drain waits for it to reach zero).
#[derive(Debug)]
pub struct ConnGuard(Arc<Shared>);

impl ConnGuard {
    pub fn new(s: &Arc<Shared>) -> Self {
        s.live_conns.fetch_add(1, Ordering::AcqRel);
        Self(s.clone())
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.live_conns.fetch_sub(1, Ordering::AcqRel);
    }
}
