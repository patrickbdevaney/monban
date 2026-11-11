//! The P4-pg-003 pool slotted into monban-adapter-host's executor seam (`dispatch::Executor<monban_adapter_pg::Rendered>`).
//!
//! It lives in the assembly (PLAN D15) because monban-adapter-host has no dependency edge to monban-adapter-pg (same
//! layer). Lifted from subjects/host-subject (public API of both crates only), plus [`PgExecutor::raw`]: host-owned
//! statements (the D14 `monban_idem` outcome row) inside the scope's tenant-bound transaction.
//!
//! Per scope:
//! * `begin`: `PoolKey::new(principal_bytes, tenant, login_role, epoch)` → `pool.acquire`. A recycled connection runs
//!   the C8 reset as two host calls with a cancellation point at site `db.DISCARD` between them (`reset_send`, check
//!   the scope's cancel token, `reset_finish`). Then `BEGIN`, then `rls_bind` (SET LOCAL ROLE + tenant GUC) right after
//!   it, then the transaction-local `statement_timeout` = op budget ms.
//! * `execute`: cancellation point, then the rendered statement with the op's row/byte caps and deadline.
//! * `commit`: cancellation point (a cancel before the commit point never commits), `COMMIT`, release `Completed`.
//! * `rollback`: cancelled → release `Cancelled` (always quarantined; the pool recovers or discards); otherwise
//!   `ROLLBACK` and release `HandlerError` (the NC3 predicate decides).
//! * Every checkout ends in exactly one `pool.release`: `PgTx` releases it as `Cancelled` on drop if neither commit
//!   nor rollback did. `Nc3Observer::charge` (quarantine time, discards) is debited to the releasing principal
//!   through the host's `ChargeSink` (NC4).
//! * At the request deadline (or client gone) before the commit point, [`PgTx::interrupt`] sends a CancelRequest
//!   with the session's BackendKeyData (armed per scope by scope.rs `Gate`), so a blocked statement stops on the
//!   server; the scope then rolls back and the checkout is released `Cancelled` (ROLLBACK, Close, DISCARD ALL, or
//!   discard): reset or retired, never pooled with an open transaction (R8, crdb-live).
//! * [`PgExecutor::bump_epoch`] retires older-epoch connections (`pool.retire_before`, CRS C5); the assembly calls it
//!   on every auth/config epoch bump.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use monban_adapter_host::dispatch::{EngineError, Executor, ScopeInfo};
use monban_adapter_host::host::CancelToken;
use monban_adapter_host::host::budget::{ChargeSink, OpLimits, Usage};
use monban_adapter_host::host::session::principal_bytes;
use monban_adapter_pg::wire::{self, QueryResult, ResultLimits};
use monban_adapter_pg::{
    Charge, Checkout, Epoch, Nc3Observer, PgConn, PgSession, Pool, PoolConfig, PoolKey, Release, Released, Rendered,
    rls_bind,
};

/// The statement-execution half of a pooled PG session (implemented by `PgConn`; tests use a fake).
pub trait PgSql: PgSession + Send + 'static {
    fn query(
        &mut self,
        sql: &str,
        params: &[Option<&str>],
        deadline: Instant,
        lim: ResultLimits,
    ) -> Result<QueryResult, wire::Error>;
    /// The session's BackendKeyData, for a CancelRequest from another thread.
    fn cancel_key(&self) -> Option<wire::CancelKey>;
}

impl PgSql for PgConn {
    fn cancel_key(&self) -> Option<wire::CancelKey> {
        self.connection_ref().cancel_key().cloned()
    }
    fn query(
        &mut self,
        sql: &str,
        params: &[Option<&str>],
        deadline: Instant,
        lim: ResultLimits,
    ) -> Result<QueryResult, wire::Error> {
        self.connection().query_limited(sql, params, deadline, lim)
    }
}

type Connect<C> = dyn Fn(&PoolKey) -> Result<C, wire::Error> + Send + Sync;

/// Executor over the NC3 pool.
pub struct PgExecutor<C: PgSql> {
    pool: Pool<C>,
    connect: Box<Connect<C>>,
    login_role: String,
    rls_role: String,
    setting: String,
    epoch: AtomicU64,
    op_budget_ms: u64,
    charges: Arc<dyn ChargeSink>,
    /// CockroachDB (feature `adapter-crdb`): no RLS role switch or tenant GUC (the tenant conjunct, the upsert guard
    /// and the schema gate are the isolation, P7-oracle-adapters-001); `BEGIN ... SERIALIZABLE`.
    #[cfg(feature = "adapter-crdb")]
    crdb: bool,
}

impl<C: PgSql> fmt::Debug for PgExecutor<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgExecutor")
            .field("login_role", &self.login_role)
            .field("epoch", &self.epoch.load(Ordering::SeqCst))
            .field("open", &self.pool.open())
            .finish_non_exhaustive()
    }
}

/// Construction parameters of [`PgExecutor`].
pub struct PgExecConfig<C> {
    pub pool: PoolConfig,
    /// Opens one connection for a pool key (`connect_admitted` as the key's login role, wrapped in `PgConn`).
    pub connect: Box<Connect<C>>,
    pub login_role: String,
    /// Role for `SET LOCAL ROLE` (the role the FORCE RLS policy applies to).
    pub rls_role: String,
    /// Transaction-local GUC carrying the tenant (`rls_policy`'s setting).
    pub setting: String,
    pub epoch: Epoch,
    /// Op budget in ms: statement_timeout, T_recover and the release budget.
    pub op_budget_ms: u64,
    pub charges: Arc<dyn ChargeSink>,
    /// A CockroachDB backend (feature `adapter-crdb`); see [`PgExecutor`].
    #[cfg(feature = "adapter-crdb")]
    pub crdb: bool,
}

impl<C: PgSql> PgExecutor<C> {
    pub fn new(cfg: PgExecConfig<C>) -> PgExecutor<C> {
        PgExecutor {
            pool: Pool::new(cfg.pool),
            connect: cfg.connect,
            login_role: cfg.login_role,
            rls_role: cfg.rls_role,
            setting: cfg.setting,
            epoch: AtomicU64::new(cfg.epoch),
            op_budget_ms: cfg.op_budget_ms,
            charges: cfg.charges,
            #[cfg(feature = "adapter-crdb")]
            crdb: cfg.crdb,
        }
    }

    #[cfg(test)]
    pub fn pool(&self) -> &Pool<C> {
        &self.pool
    }

    /// Auth/config epoch bump (C5): new scopes key on `epoch`; idle connections of older epochs are closed and their
    /// acquisitions/checkins refused.
    pub fn bump_epoch(&self, epoch: Epoch) {
        self.epoch.fetch_max(epoch, Ordering::SeqCst);
        let _ = self.pool.retire_before(epoch);
    }
}

/// NC4: pool charges against the releasing principal.
struct Charger<'a> {
    sink: &'a dyn ChargeSink,
    who: &'a [u8],
}

impl<C> Nc3Observer<C> for Charger<'_> {
    fn charge(&mut self, cost: u64, _why: Charge) {
        self.sink.charge(self.who, cost);
    }
}

/// One scope's checkout. Ends in exactly one release (commit, rollback, or `Drop` as `Cancelled`).
pub struct PgTx<C: PgSql> {
    pool: Pool<C>,
    co: Option<Checkout<C>>,
    who: Vec<u8>,
    cancel: CancelToken,
    op_budget_ms: u64,
    charges: Arc<dyn ChargeSink>,
}

impl<C: PgSql> fmt::Debug for PgTx<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgTx").field("held", &self.co.is_some()).finish_non_exhaustive()
    }
}

impl<C: PgSql> PgTx<C> {
    fn release(&mut self, how: Release) -> Option<Released> {
        let co = self.co.take()?;
        let mut obs = Charger { sink: &*self.charges, who: &self.who };
        Some(self.pool.release(co, how, self.op_budget_ms, &mut obs))
    }

    fn session(&mut self) -> Result<&mut C, EngineError> {
        let co = self.co.as_mut().ok_or_else(|| EngineError::Unavailable("checkout released".into()))?;
        co.session().map_err(|e| EngineError::Unavailable(e.to_string()))
    }

    fn check_cancel(&self, site: &str) -> Result<(), EngineError> {
        if self.cancel.is_cancelled() { Err(EngineError::Unavailable(format!("cancelled at {site}"))) } else { Ok(()) }
    }

    /// A CancelRequest for this checkout's backend, to run on another thread while a statement blocks (R8: the
    /// request deadline stops the statement on the server). The checkout is released only after the interrupt was
    /// disarmed and joined (scope.rs `Gate::disarm`), so the request never reaches a backend another scope holds.
    pub fn interrupt(&self) -> Option<Box<dyn FnOnce() + Send>> {
        let key = self.co.as_ref()?.peek().cancel_key()?;
        Some(Box::new(move || {
            let _ = wire::send_cancel(&key, CANCEL_TIMEOUT);
        }))
    }
}

/// Bound on one CancelRequest (connect + write).
const CANCEL_TIMEOUT: Duration = Duration::from_millis(500);

impl<C: PgSql> Drop for PgTx<C> {
    fn drop(&mut self) {
        let _ = self.release(Release::Cancelled);
    }
}

fn deadline(ms: u64) -> Instant {
    Instant::now() + Duration::from_millis(ms)
}

fn wire_err(e: wire::Error) -> EngineError {
    match e {
        wire::Error::Db(d) if d.code == "23505" || d.code == "40001" || d.code == "40P01" => EngineError::Conflict,
        other => EngineError::Unavailable(other.to_string()),
    }
}

fn run_sql<C: PgSql>(c: &mut C, r: &Rendered, ms: u64, lim: ResultLimits) -> Result<QueryResult, EngineError> {
    let texts = r.param_texts();
    let params: Vec<Option<&str>> = texts.iter().map(|s| Some(s.as_str())).collect();
    c.query(&r.sql, &params, deadline(ms), lim).map_err(wire_err)
}

fn plain(sql: &str) -> Rendered {
    Rendered { sql: sql.into(), params: Vec::new() }
}

/// The transaction-local `statement_timeout` = op budget.
fn statement_timeout(budget_ms: u64) -> Rendered {
    Rendered {
        sql: "SELECT pg_catalog.set_config('statement_timeout', $1, true)".into(),
        params: vec![monban_adapter_pg::Param::Text(format!("{budget_ms}ms"))],
    }
}

impl<C: PgSql> PgExecutor<C> {
    /// A host-owned statement inside the open transaction of `tx` (after `rls_bind`, so it runs as the RLS role with
    /// the scope's tenant bound). A cancellation point like every statement.
    pub fn raw(
        &self,
        tx: &mut PgTx<C>,
        sql: &str,
        params: &[Option<&str>],
        max_rows: usize,
    ) -> Result<QueryResult, EngineError> {
        tx.check_cancel("db.host")?;
        let lim = ResultLimits { max_rows, max_bytes: 1 << 20 };
        tx.session()?.query(sql, params, deadline(self.op_budget_ms), lim).map_err(wire_err)
    }
}

impl<C: PgSql> Executor<Rendered> for PgExecutor<C> {
    type Tx = PgTx<C>;
    type Rows = Vec<Vec<Option<String>>>;

    fn begin(&self, scope: &ScopeInfo<'_>) -> Result<PgTx<C>, EngineError> {
        if scope.cancel.is_cancelled() {
            return Err(EngineError::Unavailable("cancelled before begin".into()));
        }
        let who = principal_bytes(scope.principal);
        let epoch = self.epoch.load(Ordering::SeqCst);
        let key = PoolKey::new(&who, scope.tenant, &self.login_role, epoch)
            .map_err(|e| EngineError::Unavailable(e.to_string()))?;
        let co = self.pool.acquire(&key, |k| (self.connect)(k)).map_err(|e| EngineError::Unavailable(e.to_string()))?;
        let mut tx = PgTx {
            pool: self.pool.clone(),
            co: Some(co),
            who,
            cancel: scope.cancel.clone(),
            op_budget_ms: self.op_budget_ms,
            charges: Arc::clone(&self.charges),
        };
        // From here on every early return drops `tx`, which releases the checkout as Cancelled.
        let budget = self.op_budget_ms;
        if let Some(co) = tx.co.as_mut()
            && co.needs_reset()
        {
            co.reset_send(budget).map_err(|e| EngineError::Unavailable(e.to_string()))?;
            tx.check_cancel("db.DISCARD")?; // C8 reset is a round trip: a cancellation point between write and read
            if let Some(co) = tx.co.as_mut() {
                co.reset_finish(budget).map_err(|e| EngineError::Unavailable(e.to_string()))?;
            }
        }
        let lim = ResultLimits { max_rows: 1, max_bytes: 4096 };
        #[cfg(feature = "adapter-crdb")]
        if self.crdb {
            let c = tx.session()?;
            run_sql(c, &plain("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE"), budget, lim)?;
            run_sql(c, &statement_timeout(budget), budget, lim)?;
            return Ok(tx);
        }
        let binds =
            rls_bind(scope.tenant, &self.rls_role, &self.setting).map_err(|e| EngineError::Refused(e.to_string()))?;
        let c = tx.session()?;
        run_sql(c, &plain("BEGIN"), budget, lim)?;
        for b in &binds {
            run_sql(c, b, budget, lim)?; // rls_bind right after BEGIN
        }
        run_sql(c, &statement_timeout(budget), budget, lim)?;
        Ok(tx)
    }

    fn execute(&self, tx: &mut PgTx<C>, r: Rendered, l: OpLimits) -> Result<(Self::Rows, Usage), EngineError> {
        tx.check_cancel("db.query")?;
        let t0 = Instant::now();
        let lim = ResultLimits {
            max_rows: usize::try_from(l.rows).unwrap_or(usize::MAX),
            max_bytes: usize::try_from(l.bytes).unwrap_or(usize::MAX),
        };
        let res = run_sql(tx.session()?, &r, l.ms, lim)?;
        let bytes: usize = res.rows.iter().flatten().map(|v| v.as_ref().map_or(0, String::len)).sum();
        let used = Usage {
            rows: res.rows.len() as u64,
            bytes: bytes as u64,
            ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        };
        Ok((res.rows, used))
    }

    fn commit(&self, mut tx: PgTx<C>) -> Result<(), EngineError> {
        tx.check_cancel("db.COMMIT")?; // dropped tx: released Cancelled, nothing committed
        let lim = ResultLimits { max_rows: 1, max_bytes: 4096 };
        match run_sql(tx.session()?, &plain("COMMIT"), self.op_budget_ms, lim) {
            Ok(_) => {
                tx.release(Release::Completed);
                Ok(())
            }
            Err(e) => {
                tx.release(Release::HandlerError);
                Err(e)
            }
        }
    }

    fn rollback(&self, mut tx: PgTx<C>) {
        if tx.cancel.is_cancelled() {
            tx.release(Release::Cancelled);
            return;
        }
        let lim = ResultLimits { max_rows: 1, max_bytes: 4096 };
        if let Ok(c) = tx.session() {
            let _ = run_sql(c, &plain("ROLLBACK"), self.op_budget_ms, lim);
        }
        tx.release(Release::HandlerError);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use monban_adapter_host::host::budget::PrincipalLedger;
    use monban_adapter_pg::Pooled;
    use monban_adapter_pg::checkin::sim::SimProto;
    use monban_adapter_pg::wire::{ProtoState, TxnStatus};
    use std::sync::Mutex;

    /// A session whose protocol mirror is always clean (every statement completes); records what it was sent.
    struct Fake {
        proto: SimProto,
        log: Arc<Mutex<Vec<String>>>,
        fail_simple: bool,
        generation: u64,
    }

    impl Pooled for Fake {
        fn close(self) {
            if let Ok(mut l) = self.log.lock() {
                l.push("TERMINATE".into());
            }
        }
    }

    impl PgSession for Fake {
        fn proto(&self) -> &ProtoState {
            self.proto.state()
        }
        fn read_one(&mut self, _l: u64) -> Result<u64, wire::Error> {
            Ok(0)
        }
        fn send_sync(&mut self, _l: u64) -> Result<u64, wire::Error> {
            Ok(0)
        }
        fn send_simple(&mut self, sql: &str, _l: u64) -> Result<u64, wire::Error> {
            if self.fail_simple {
                return Err(wire::Error::Timeout);
            }
            if let Ok(mut l) = self.log.lock() {
                l.push(sql.to_string());
            }
            Ok(1)
        }
        fn send_close(&mut self, _k: u8, _n: &str, _l: u64) -> Result<u64, wire::Error> {
            Ok(0)
        }
        fn cancel_request(&mut self) -> Result<(), wire::Error> {
            if let Ok(mut l) = self.log.lock() {
                l.push("CANCELREQUEST".into());
            }
            Ok(())
        }
        fn generation(&self) -> u64 {
            self.generation
        }
        fn bump_generation(&mut self) -> u64 {
            self.generation += 1;
            self.generation
        }
    }

    impl PgSql for Fake {
        fn query(
            &mut self,
            sql: &str,
            p: &[Option<&str>],
            _d: Instant,
            _l: ResultLimits,
        ) -> Result<QueryResult, wire::Error> {
            if let Ok(mut l) = self.log.lock() {
                let ps: Vec<&str> = p.iter().map(|x| x.unwrap_or("NULL")).collect();
                l.push(if ps.is_empty() { sql.to_string() } else { format!("{sql} {ps:?}") });
            }
            Ok(QueryResult::default())
        }
        fn cancel_key(&self) -> Option<wire::CancelKey> {
            None
        }
    }

    fn setup(fail_simple: bool) -> (PgExecutor<Fake>, Arc<Mutex<Vec<String>>>, Arc<PrincipalLedger>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let l2 = Arc::clone(&log);
        let ledger = Arc::new(PrincipalLedger::new());
        let ex = PgExecutor::new(PgExecConfig {
            pool: PoolConfig { max_open: 2, max_idle_per_key: 1, acquire_timeout: Duration::from_millis(50) },
            connect: Box::new(move |_k| {
                if let Ok(mut l) = l2.lock() {
                    l.push("CONNECT".into());
                }
                Ok(Fake { proto: SimProto::started(TxnStatus::Idle), log: Arc::clone(&l2), fail_simple, generation: 0 })
            }),
            login_role: "monban_login".into(),
            rls_role: "monban_app".into(),
            setting: "monban.tenant".into(),
            epoch: 1,
            op_budget_ms: 100,
            charges: ledger.clone(),
            #[cfg(feature = "adapter-crdb")]
            crdb: false,
        });
        (ex, log, ledger)
    }

    fn take(log: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
        log.lock().map(|mut l| std::mem::take(&mut *l)).unwrap_or_default()
    }

    #[test]
    fn begin_binds_rls_after_begin_and_recycles_with_reset() -> Result<(), String> {
        let (ex, log, ledger) = setup(false);
        let p = crate::native::testutil::principal(monban_types::TenantId::new(42).map_err(|_| "t")?)?;
        let cancel = CancelToken::new();
        let info = ScopeInfo { principal: &p, tenant: p.tenant(), cancel: &cancel };
        let tx = ex.begin(&info).map_err(|e| e.to_string())?;
        ex.commit(tx).map_err(|e| e.to_string())?;
        let first = take(&log);
        assert_eq!(first.first().map(String::as_str), Some("CONNECT"));
        assert_eq!(first.get(1).map(String::as_str), Some("BEGIN"));
        assert!(first.get(2).is_some_and(|s| s.starts_with("SET LOCAL ROLE \"monban_app\"")), "{first:?}");
        assert!(first.get(3).is_some_and(|s| s.contains("set_config") && s.contains("000000000000002a")), "{first:?}");
        assert_eq!(first.last().map(String::as_str), Some("COMMIT"));
        // Same principal/tenant/role/epoch: the idle connection is reused, after the C8 reset.
        let tx = ex.begin(&info).map_err(|e| e.to_string())?;
        ex.rollback(tx);
        let second = take(&log);
        assert_eq!(second.first().map(String::as_str), Some("DISCARD ALL"), "{second:?}");
        assert_eq!(second.get(1).map(String::as_str), Some("BEGIN"));
        assert_eq!(second.last().map(String::as_str), Some("ROLLBACK"));
        assert_eq!(ledger.charged(&principal_bytes(&p)), 0);
        // Epoch bump (C5): the idle connection is retired, the next scope connects afresh.
        ex.bump_epoch(2);
        let tx = ex.begin(&info).map_err(|e| e.to_string())?;
        drop(tx); // a scope that ended without commit/rollback: released as Cancelled (quarantined, charged)
        let third = take(&log);
        assert!(third.contains(&"TERMINATE".to_string()) && third.contains(&"CONNECT".to_string()), "{third:?}");
        assert!(ledger.charged(&principal_bytes(&p)) >= 1);
        Ok(())
    }

    #[test]
    fn cancel_before_commit_never_commits_and_is_charged() -> Result<(), String> {
        let (ex, log, ledger) = setup(true); // recovery's DISCARD ALL fails: the connection is discarded
        let p = crate::native::testutil::principal(monban_types::TenantId::new(7).map_err(|_| "t")?)?;
        let cancel = CancelToken::new();
        let info = ScopeInfo { principal: &p, tenant: p.tenant(), cancel: &cancel };
        let tx = ex.begin(&info).map_err(|e| e.to_string())?;
        cancel.cancel();
        assert!(ex.commit(tx).is_err());
        let l = take(&log);
        assert!(!l.contains(&"COMMIT".to_string()), "{l:?}");
        assert!(l.contains(&"CANCELREQUEST".to_string()) && l.contains(&"TERMINATE".to_string()), "{l:?}");
        // Quarantine (>= 1) + discard (DISCARD_COST) charged to the cancelling principal.
        assert!(ledger.charged(&principal_bytes(&p)) > monban_adapter_pg::DISCARD_COST);
        assert_eq!(ex.pool().open(), 0);
        // A cancelled scope never begins.
        assert!(ex.begin(&info).is_err());
        Ok(())
    }
}
