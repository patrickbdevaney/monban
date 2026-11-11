//! Process-wide state shared by the listeners, the admin endpoint and the control thread.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use monban_admission::{Admission, Arrive, Close, Credential, Done, Lane, Stage, Verdict};
use monban_budget::Gcra;
use monban_metrics::{AdmissionStage, BudgetScope, Registry};
use tokio::sync::Notify;

use crate::plan::Snapshot;
use crate::upstream::Pool;

/// Proxy counters exported next to the golden families (not golden; names are `monban_proxy_*`).
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
    // oracles/native-e2e --self-test (modes A/D):
    /// The tenant is taken from the request path, not from the token (breaks INV-NO-AMBIENT / W6).
    pub tenant_from_path: bool,
    /// Commit although the request was cancelled before the commit point (breaks NC1).
    pub commit_despite_cancel: bool,
    /// Answer before the commit point (breaks NC7).
    pub body_before_cp: bool,
    /// An app route without a data block may use every op on the first backend (breaks INV-NONEMPTY).
    pub empty_caps_means_all: bool,
    /// Ignore SIGTERM (breaks NC8).
    pub no_drain: bool,
    /// On SIGTERM, answer in-flight requests 2xx and exit without committing (breaks NC8 / INV-DURABLE).
    pub ack_then_drop: bool,
}

impl Mutants {
    #[cfg(feature = "e2e-mutants")]
    pub fn from_env() -> Self {
        let v = std::env::var("AEGIS_E2E_MUTANT").unwrap_or_default();
        let has = |n: &str| v.split(',').any(|s| s.trim() == n);
        let m = Self {
            raw_path: has("raw-path"),
            skip_authz_deny: has("skip-authz-deny"),
            skip_lkg: has("skip-lkg"),
            tenant_from_path: has("tenant-from-path"),
            commit_despite_cancel: has("commit-despite-cancel"),
            body_before_cp: has("body-before-cp"),
            empty_caps_means_all: has("empty-caps-means-all"),
            no_drain: has("no-drain"),
            ack_then_drop: has("ack-then-drop"),
        };
        if m != Self::default() {
            eprintln!("monban: E2E NEGATIVE-CONTROL BUILD, mutants active: {m:?}");
        }
        m
    }
    #[cfg(not(feature = "e2e-mutants"))]
    pub fn from_env() -> Self {
        Self::default()
    }
}

/// The admission pipeline's numbers from F8 `admission` (P7-spec-001; ARCHITECTURE §3.4 numbers are D-grade). An
/// absent block is [`monban_config::Admission::default`], exactly the pre-Phase-7 constants: per IP 1000/s, burst
/// 2000 (`Gcra::new(1_000_000, 2_000)`), S1 store 65536, 16384 connections, 4096 per prefix, concurrency 4096.
/// `per_ip` is the S1 per-source limit and also the S3 anon/session/verified per-identity limit (as before). No
/// expensive tier (every proxied request costs 1, below `exp_cost`), so the aggregate limiters never apply.
pub fn admission_config(a: &monban_config::Admission) -> monban_admission::Config {
    let per_ip = Gcra::new(a.per_ip.emission_interval_ns(), a.per_ip.burst);
    let store = usize::try_from(a.per_ip_store).unwrap_or(usize::MAX);
    monban_admission::Config {
        s1: per_ip,
        s1_store: store,
        s3_store: 65_536,
        anon: per_ip,
        session: per_ip,
        verified: per_ip,
        agg_f: Gcra::new(1_000_000, 2_000),
        agg_e: Gcra::new(1_000_000, 2_000),
        exp_cost: u64::MAX,
        stepup_cost: u64::MAX,
        stepup_bits: 0,
        limit: a.concurrency,
        max_conns: a.max_conns,
        prefix_cap: a.per_prefix_conns,
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
    /// Upgrade / shutdown started (`/healthz` reports it; the transport drains the connections).
    pub draining: AtomicBool,
    /// Stop accepting (listener fds are closed by the accept tasks).
    pub stop_accept: AtomicBool,
    pub stop_notify: Notify,
    pub accept_tasks: AtomicUsize,
    pub live_conns: AtomicUsize,
    pub mutants: Mutants,
    /// notAfter of the serving certificate (Unix s), `i64::MIN` before the first install (CERT-1 gauge source).
    pub cert_not_after: AtomicI64,
    /// The native data plane (modes A/D), when the config binds a route to an app.
    pub native: Option<Arc<crate::native::DataPlane>>,
    /// The P2 supervisor (feature `p2`; `None` in other builds).
    pub p2: Option<Arc<crate::p2::Runtime>>,
}

impl Shared {
    pub fn new(
        snapshot: Snapshot,
        native: Option<Arc<crate::native::DataPlane>>,
        p2: Option<Arc<crate::p2::Runtime>>,
    ) -> Arc<Self> {
        let admission = Mutex::new(Admission::new(admission_config(&snapshot.plan.admission)));
        let s = Arc::new(Self {
            registry: Registry::new(),
            stats: ProxyStats::default(),
            pool: Pool::new(snapshot.epoch),
            snapshot: RwLock::new(Arc::new(snapshot)),
            admission,
            started: Instant::now(),
            next_id: AtomicU64::new(1),
            draining: AtomicBool::new(false),
            stop_accept: AtomicBool::new(false),
            stop_notify: Notify::new(),
            accept_tasks: AtomicUsize::new(0),
            live_conns: AtomicUsize::new(0),
            mutants: Mutants::from_env(),
            cert_not_after: AtomicI64::new(i64::MIN),
            native,
            p2,
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    fn cfg(extra: &str) -> monban_config::Config {
        let doc = format!(
            r#"{{"v":1,"listeners":[{{"name":"pub","bind":"127.0.0.1:8443","profile":"P-PUBLIC-WEB"}}]{extra},
               "vhosts":[{{"host":"monban.test","routes":[{{"id":1,"path":"/","to":{{"upstream":"127.0.0.1:9"}},"authz":"allow-all"}}]}}]}}"#
        );
        monban_config::parse_config(doc.as_bytes()).unwrap()
    }

    /// Absent `admission` = exactly the pre-Phase-7 constants.
    #[test]
    fn absent_admission_is_todays_constants() {
        let c = admission_config(cfg("").admission());
        let per_ip = Gcra::new(1_000_000, 2_000);
        assert_eq!((c.s1, c.anon, c.session, c.verified), (per_ip, per_ip, per_ip, per_ip));
        assert_eq!((c.s1_store, c.s3_store), (65_536, 65_536));
        assert_eq!((c.limit, c.max_conns, c.prefix_cap), (4096, 16_384, 4096));
        assert_eq!((c.agg_f, c.agg_e), (per_ip, per_ip));
        assert_eq!(
            (c.exp_cost, c.stepup_cost, c.stepup_bits, c.fresh_age_ns),
            (u64::MAX, u64::MAX, 0, 3_600_000_000_000)
        );
    }

    /// A configured block reaches S0 / S1 / S3 / S5.
    #[test]
    fn configured_admission_is_wired() {
        let c = admission_config(
            cfg(r#","admission":{"per_ip":{"rate_per_s":200000,"burst":400000},"per_ip_store":2048,
                  "max_conns":100,"per_prefix_conns":50,"concurrency":64}"#)
            .admission(),
        );
        let per_ip = Gcra::new(5_000, 400_000);
        assert_eq!((c.s1, c.anon, c.session, c.verified), (per_ip, per_ip, per_ip, per_ip));
        assert_eq!((c.s1_store, c.limit, c.max_conns, c.prefix_cap), (2048, 64, 100, 50));
    }
}
