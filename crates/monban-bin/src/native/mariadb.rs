//! MariaDB behind monban-adapter-host's executor seam (`dispatch::Executor<monban_adapter_mysql::Rendered>`; feature
//! `adapter-mariadb`, PREFLIGHT R4). The connection model is the one apps/notes `ALLOWLIST_MARIADB` documents:
//!
//! * one connection per request scope, held exclusively from `begin` to `commit`/`rollback`;
//! * per scope `START TRANSACTION` .. `COMMIT` / `ROLLBACK` (prepared statements only, through the adapter's binary
//!   protocol client; the session's strict `sql_mode` and utf8mb4 are pinned at connect);
//! * an UPDATE with RETURNING runs its `returning_select` (`SELECT .. FOR UPDATE`) first, inside the transaction, as
//!   `monban_adapter_mysql::Connection::run` does, but under the op's deadline;
//! * on scope end the connection goes back to the pool only if `Connection::is_reusable()` holds (not broken, no open
//!   transaction, nothing buffered, no unsolicited byte or EOF on the idle socket); otherwise it is terminated
//!   (COM_QUIT, close). A **cancelled** (deadline, client gone, request dropped) scope never returns its connection
//!   (C8/NC3): it is terminated, the server rolls the transaction back, and no session state or half-read result
//!   survives into another request. So does a scope dropped without commit or rollback.
//!
//! MariaDB has no row-level security: tenant isolation is the host-rendered tenant conjunct in every statement (and
//! the ODKU tenant guard), the live schema gate (InnoDB, byte-equality collations, `(tenant, id)` the only unique
//! key) and, for idempotency rows, the tenant predicate of every `monban_idem` lookup ([`super::DataPlane::lookup`]).
//! Cancellation points: begin, every statement, commit (as the SQLite and PG executors).

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use monban_adapter_host::dispatch::{EngineError, Executor, ScopeInfo};
use monban_adapter_host::host::CancelToken;
use monban_adapter_host::host::budget::{OpLimits, Usage};
use monban_adapter_mysql::{Cell, ConnectConfig, Connection, Limits, MysqlError, Param, QueryResult, Rendered};

use super::sqlite::Rows;

/// Bound on COM_QUIT when a connection is terminated.
const TERMINATE: Duration = Duration::from_millis(200);
/// MariaDB ER_DUP_ENTRY: a unique key already holds the row (insert of an existing own id, a latched idempotency
/// key).
const ER_DUP_ENTRY: u16 = 1062;
/// ER_LOCK_DEADLOCK: InnoDB rolled the transaction back.
const ER_LOCK_DEADLOCK: u16 = 1213;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn my_err(e: MysqlError) -> EngineError {
    match e {
        MysqlError::Server(s) if s.code == ER_DUP_ENTRY || s.code == ER_LOCK_DEADLOCK => EngineError::Conflict,
        other => EngineError::Unavailable(other.to_string()),
    }
}

/// One cell as text (`None` = NULL). Floats, temporals and non-UTF-8 bytes never reach a notes column (the schema
/// gate admits integer and string columns only); they are refused, not converted.
fn cell(c: Cell) -> Result<Option<String>, EngineError> {
    match c {
        Cell::Null => Ok(None),
        Cell::Int(i) => Ok(Some(i.to_string())),
        Cell::UInt(u) => Ok(Some(u.to_string())),
        Cell::Text(s) => Ok(Some(s)),
        Cell::Bytes(b) => String::from_utf8(b)
            .map(Some)
            .map_err(|_| EngineError::Unavailable("non-UTF-8 bytes in a result cell".into())),
        Cell::Float(_) | Cell::Temporal(_) => Err(EngineError::Unavailable("unsupported result cell type".into())),
    }
}

fn rows(r: QueryResult) -> Result<Rows, EngineError> {
    r.rows.into_iter().map(|row| row.into_iter().map(cell).collect()).collect()
}

#[derive(Default)]
struct Slots {
    idle: Vec<Connection>,
    open: usize,
}

/// The connection pool: at most `max_open` connections, at most `max_idle` kept idle.
struct Pool {
    cc: ConnectConfig,
    slots: Mutex<Slots>,
    freed: Condvar,
    max_open: usize,
    max_idle: usize,
}

impl Pool {
    /// An idle reusable connection, or a new one, before `deadline`.
    fn acquire(&self, deadline: Instant) -> Result<Connection, EngineError> {
        let mut stale = Vec::new();
        let mut g = lock(&self.slots);
        let got = loop {
            let mut found = None;
            while let Some(mut c) = g.idle.pop() {
                if c.is_reusable() {
                    found = Some(c);
                    break;
                }
                g.open = g.open.saturating_sub(1);
                stale.push(c);
            }
            if found.is_some() {
                break found;
            }
            if g.open < self.max_open {
                g.open = g.open.saturating_add(1);
                break None;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                drop(g);
                stale.into_iter().for_each(|c| c.terminate(TERMINATE));
                return Err(EngineError::Unavailable("MariaDB pool exhausted".into()));
            }
            g = self.freed.wait_timeout(g, left).map_or_else(|e| e.into_inner().0, |(g, _)| g);
        };
        drop(g);
        stale.into_iter().for_each(|c| c.terminate(TERMINATE));
        match got {
            Some(c) => Ok(c),
            None => {
                let mut cc = self.cc.clone();
                let left = deadline.saturating_duration_since(Instant::now());
                cc.connect_timeout = cc.connect_timeout.min(left.max(Duration::from_millis(1)));
                monban_adapter_mysql::connect(&cc).map_err(|e| {
                    self.forget();
                    EngineError::Unavailable(e.to_string())
                })
            }
        }
    }

    fn forget(&self) {
        let mut g = lock(&self.slots);
        g.open = g.open.saturating_sub(1);
        drop(g);
        self.freed.notify_one();
    }

    /// Scope end without a cancel: pooled again iff `is_reusable()` (and the idle cap has room), else terminated.
    fn give_back(&self, mut c: Connection) {
        if c.is_reusable() {
            let mut g = lock(&self.slots);
            if g.idle.len() < self.max_idle {
                g.idle.push(c);
                drop(g);
                self.freed.notify_one();
                return;
            }
        }
        self.retire(c);
    }

    /// Never reused: COM_QUIT and close (the server rolls back an open transaction).
    fn retire(&self, c: Connection) {
        c.terminate(TERMINATE);
        self.forget();
    }

    #[cfg(test)]
    fn counts(&self) -> (usize, usize) {
        let g = lock(&self.slots);
        (g.open, g.idle.len())
    }
}

/// The MariaDB executor of one backend.
pub struct MariadbExec {
    pool: Arc<Pool>,
    budget_ms: u64,
}

impl std::fmt::Debug for MariadbExec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MariadbExec").field("budget_ms", &self.budget_ms).finish_non_exhaustive()
    }
}

impl MariadbExec {
    /// `max_open` connections at most (F8 `max_conns`), one idle per open slot at most.
    pub fn new(cc: ConnectConfig, max_open: usize, budget_ms: u64) -> MariadbExec {
        let max_open = max_open.max(1);
        let pool =
            Pool { cc, slots: Mutex::new(Slots::default()), freed: Condvar::new(), max_open, max_idle: max_open };
        MariadbExec { pool: Arc::new(pool), budget_ms }
    }

    fn deadline(&self) -> Instant {
        Instant::now() + Duration::from_millis(self.budget_ms)
    }

    /// A host-owned statement inside the open transaction of `tx` (the D14 `monban_idem` row and lookups). A
    /// cancellation point like every statement.
    pub fn raw(&self, tx: &mut MariadbTx, sql: &str, params: &[Param]) -> Result<Rows, EngineError> {
        tx.check("db.host")?;
        let deadline = self.deadline();
        let c = tx.conn()?;
        c.set_limits(Limits { max_columns: 64, max_rows: 1, max_bytes: 1 << 20 });
        rows(c.execute_until(sql, params, deadline).map_err(my_err)?)
    }

    #[cfg(test)]
    fn counts(&self) -> (usize, usize) {
        self.pool.counts()
    }
}

/// One scope's connection inside `START TRANSACTION`. Ends in exactly one of: pooled again (commit or rollback,
/// `is_reusable()`), or terminated (cancelled, failed, not reusable, or dropped).
pub struct MariadbTx {
    conn: Option<Connection>,
    cancel: CancelToken,
    pool: Arc<Pool>,
}

impl std::fmt::Debug for MariadbTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MariadbTx").field("held", &self.conn.is_some()).finish_non_exhaustive()
    }
}

impl MariadbTx {
    fn check(&self, site: &str) -> Result<(), EngineError> {
        if self.cancel.is_cancelled() { Err(EngineError::Unavailable(format!("cancelled at {site}"))) } else { Ok(()) }
    }

    fn conn(&mut self) -> Result<&mut Connection, EngineError> {
        self.conn.as_mut().ok_or_else(|| EngineError::Unavailable("transaction ended".into()))
    }

    fn retire(&mut self) {
        if let Some(c) = self.conn.take() {
            self.pool.retire(c);
        }
    }
}

impl Drop for MariadbTx {
    fn drop(&mut self) {
        self.retire(); // a scope that ended without commit/rollback: never pooled again
    }
}

/// `Connection::run` under `deadline`: the returning-select emulation first (inside the transaction only).
fn run(c: &mut Connection, r: &Rendered, deadline: Instant) -> Result<QueryResult, MysqlError> {
    match &r.returning_select {
        None => c.execute_until(&r.stmt.sql, &r.stmt.params, deadline),
        Some(rs) => {
            if !c.in_transaction() {
                return Err(MysqlError::NotInTransaction);
            }
            let sel = c.execute_until(&rs.sql, &rs.params, deadline)?;
            let upd = c.execute_until(&r.stmt.sql, &r.stmt.params, deadline)?;
            Ok(QueryResult { affected_rows: upd.affected_rows, ..sel })
        }
    }
}

impl Executor<Rendered> for MariadbExec {
    type Tx = MariadbTx;
    type Rows = Rows;

    fn begin(&self, scope: &ScopeInfo<'_>) -> Result<MariadbTx, EngineError> {
        if scope.cancel.is_cancelled() {
            return Err(EngineError::Unavailable("cancelled before begin".into()));
        }
        let deadline = self.deadline();
        let conn = self.pool.acquire(deadline)?;
        let mut tx = MariadbTx { conn: Some(conn), cancel: scope.cancel.clone(), pool: Arc::clone(&self.pool) };
        // From here on every early return drops `tx`, which terminates the connection.
        tx.check("db.BEGIN")?;
        let c = tx.conn()?;
        c.execute_until("START TRANSACTION", &[], deadline).map_err(my_err)?;
        if !c.in_transaction() {
            return Err(EngineError::Unavailable("START TRANSACTION did not open a transaction".into()));
        }
        Ok(tx)
    }

    fn execute(&self, tx: &mut MariadbTx, r: Rendered, l: OpLimits) -> Result<(Rows, Usage), EngineError> {
        tx.check("db.query")?;
        let t0 = Instant::now();
        let c = tx.conn()?;
        // Over a cap: the adapter fails the statement and marks the connection broken (never pooled again).
        c.set_limits(Limits {
            max_columns: 4096,
            max_rows: usize::try_from(l.rows).unwrap_or(usize::MAX),
            max_bytes: usize::try_from(l.bytes).unwrap_or(usize::MAX),
        });
        let res = run(c, &r, t0 + Duration::from_millis(l.ms)).map_err(my_err)?;
        let out = rows(res)?;
        let bytes: usize = out.iter().flatten().map(|v| v.as_ref().map_or(0, String::len)).sum();
        let used = Usage {
            rows: u64::try_from(out.len()).unwrap_or(u64::MAX),
            bytes: u64::try_from(bytes).unwrap_or(u64::MAX),
            ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        };
        Ok((out, used))
    }

    fn commit(&self, mut tx: MariadbTx) -> Result<(), EngineError> {
        tx.check("db.COMMIT")?; // dropped tx: terminated, nothing committed
        let deadline = self.deadline();
        let r = tx.conn()?.execute_until("COMMIT", &[], deadline).map_err(my_err);
        match (r, tx.conn.take()) {
            (Ok(_), Some(c)) => {
                self.pool.give_back(c);
                Ok(())
            }
            (Ok(_), None) => Ok(()),
            (Err(e), c) => {
                if let Some(c) = c {
                    self.pool.retire(c);
                }
                Err(e)
            }
        }
    }

    fn rollback(&self, mut tx: MariadbTx) {
        if tx.cancel.is_cancelled() {
            tx.retire(); // C8/NC3: a cancelled scope never returns its connection
            return;
        }
        let deadline = self.deadline();
        let ok = tx.conn().is_ok_and(|c| c.execute_until("ROLLBACK", &[], deadline).is_ok());
        match tx.conn.take() {
            Some(c) if ok => self.pool.give_back(c),
            Some(c) => self.pool.retire(c),
            None => {}
        }
    }
}

impl super::scope::HostSql<Rendered> for MariadbExec {
    fn write_idem(&self, tx: &mut MariadbTx, tenant: &str, idem: &super::scope::Idem) -> Result<(), EngineError> {
        self.raw(
            tx,
            "INSERT INTO monban_idem (tenant, principal, k, status, body) VALUES (?, ?, ?, ?, ?)",
            &[
                Param::Text(tenant.into()),
                Param::Text(idem.principal.clone()),
                Param::Text(idem.key.clone()),
                Param::Int(i64::from(idem.status)),
                Param::Text(idem.body.clone()),
            ],
        )
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    //! `mariadb_live` needs a throwaway MariaDB with the native-e2e provisioning (`monban_app`, notes, monban_idem):
    //! `AEGIS_TEST_MARIADB_DSN=mysql://monban_app:..@127.0.0.1:P/monban`. Without the variable it does nothing.
    use super::*;

    #[test]
    fn cells_convert_or_refuse() {
        assert_eq!(cell(Cell::Null).unwrap(), None);
        assert_eq!(cell(Cell::Int(-3)).unwrap(), Some("-3".into()));
        assert_eq!(cell(Cell::UInt(7)).unwrap(), Some("7".into()));
        assert_eq!(cell(Cell::Text("a".into())).unwrap(), Some("a".into()));
        assert_eq!(cell(Cell::Bytes(b"b".to_vec())).unwrap(), Some("b".into()));
        assert!(cell(Cell::Bytes(vec![0xff])).is_err());
        assert!(cell(Cell::Float(1.0)).is_err());
        assert!(cell(Cell::Temporal(vec![])).is_err());
    }

    #[test]
    fn duplicate_and_deadlock_are_conflicts() {
        let se = |code| {
            MysqlError::Server(monban_adapter_mysql::ServerError {
                code,
                state: "23000".into(),
                message: String::new(),
            })
        };
        assert!(matches!(my_err(se(1062)), EngineError::Conflict));
        assert!(matches!(my_err(se(1213)), EngineError::Conflict));
        assert!(matches!(my_err(se(1205)), EngineError::Unavailable(_)));
        assert!(matches!(my_err(MysqlError::Timeout), EngineError::Unavailable(_)));
    }

    /// Against a live server: commit pools the connection again; a handler rollback pools it (reusable); a
    /// cancelled scope and a dropped scope never return theirs.
    #[test]
    fn mariadb_live() {
        let Ok(dsn) = std::env::var("AEGIS_TEST_MARIADB_DSN") else {
            eprintln!("mariadb_live: AEGIS_TEST_MARIADB_DSN not set; skipped");
            return;
        };
        let cc = ConnectConfig::from_dsn(&dsn).unwrap();
        let x = MariadbExec::new(cc, 2, 5000);
        let t = monban_types::TenantId::new(5).unwrap();
        let p = crate::native::testutil::principal(t).unwrap();
        let cancel = CancelToken::new();
        let info = ScopeInfo { principal: &p, tenant: t, cancel: &cancel };
        let mut tx = x.begin(&info).unwrap();
        let r = x.raw(&mut tx, "SELECT 1", &[]).unwrap();
        assert_eq!(r, vec![vec![Some("1".to_string())]]);
        x.commit(tx).unwrap();
        assert_eq!(x.counts(), (1, 1), "committed: pooled again");
        let tx = x.begin(&info).unwrap();
        x.rollback(tx);
        assert_eq!(x.counts(), (1, 1), "handler rollback: pooled again");
        let c2 = CancelToken::new();
        let info2 = ScopeInfo { principal: &p, tenant: t, cancel: &c2 };
        let tx = x.begin(&info2).unwrap();
        c2.cancel();
        x.rollback(tx);
        assert_eq!(x.counts(), (0, 0), "cancelled: terminated, never pooled");
        let tx = x.begin(&info).unwrap();
        drop(tx);
        assert_eq!(x.counts(), (0, 0), "dropped: terminated");
    }
}
