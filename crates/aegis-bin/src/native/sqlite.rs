//! SQLite behind aegis-adapter-host's executor seam (`dispatch::Executor<aegis_adapter_sqlite::Rendered>`).
//!
//! One connection per scope, opened through `SqliteDb::open` (floor, fixed connection configuration, UTF-8 check;
//! decision D7: nothing per request changes connection state), with the busy timeout set once at open to the
//! backend's op budget. `begin` is `BEGIN IMMEDIATE` (the write lock is taken up front, so a write never fails
//! halfway on a lock upgrade). Cancellation points: begin, every statement, commit. A scope that ends without
//! commit rolls back (`Drop`).

use std::path::PathBuf;
use std::time::{Duration, Instant};

use aegis_adapter_host::dispatch::{EngineError, Executor, ScopeInfo};
use aegis_adapter_host::host::CancelToken;
use aegis_adapter_host::host::budget::{OpLimits, Usage};
use aegis_adapter_sqlite::{OpenMode, Rendered, SqliteDb};
use rusqlite::types::Value as SqlValue;

/// Rows as text cells (`None` = NULL), the shape both golden SQL engines return.
pub type Rows = Vec<Vec<Option<String>>>;

/// SQLite primary result code SQLITE_CONSTRAINT.
const SQLITE_CONSTRAINT: i32 = 19;

pub fn open(path: &std::path::Path, budget_ms: u64) -> Result<SqliteDb, EngineError> {
    let db = SqliteDb::open(path, OpenMode::ReadWrite).map_err(|e| EngineError::Unavailable(format!("{e:?}")))?;
    db.connection()
        .busy_timeout(Duration::from_millis(budget_ms))
        .map_err(|e| EngineError::Unavailable(e.to_string()))?;
    Ok(db)
}

fn sq_err(e: &rusqlite::Error) -> EngineError {
    if e.sqlite_error().is_some_and(|f| f.extended_code & 0xff == SQLITE_CONSTRAINT) {
        EngineError::Conflict
    } else {
        EngineError::Unavailable(e.to_string())
    }
}

fn cell(v: SqlValue) -> Option<String> {
    match v {
        SqlValue::Null => None,
        SqlValue::Integer(i) => Some(i.to_string()),
        SqlValue::Real(f) => Some(f.to_string()),
        SqlValue::Text(s) => Some(s),
        SqlValue::Blob(b) => Some(String::from_utf8_lossy(&b).into_owned()),
    }
}

#[derive(Debug)]
pub struct SqliteExec {
    path: PathBuf,
    budget_ms: u64,
}

impl SqliteExec {
    pub fn new(path: PathBuf, budget_ms: u64) -> SqliteExec {
        SqliteExec { path, budget_ms }
    }

    /// A host-owned statement inside the open transaction (the D14 `aegis_idem` row).
    pub fn raw(&self, tx: &mut SqliteTx, sql: &str, params: &[&str]) -> Result<Rows, EngineError> {
        tx.check("db.host")?;
        let db = tx.db.as_ref().ok_or_else(|| EngineError::Unavailable("transaction ended".into()))?;
        query(db, sql, params)
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn budget_ms(&self) -> u64 {
        self.budget_ms
    }
}

/// A host-owned statement with text parameters (boot DDL, idempotency lookups, the outcome row).
pub fn query(db: &SqliteDb, sql: &str, params: &[&str]) -> Result<Rows, EngineError> {
    let mut st = db.connection().prepare(sql).map_err(|e| sq_err(&e))?;
    let n = st.column_count();
    let mut rows = st.query(rusqlite::params_from_iter(params.iter())).map_err(|e| sq_err(&e))?;
    let mut out = Vec::new();
    while let Some(r) = rows.next().map_err(|e| sq_err(&e))? {
        let mut v = Vec::with_capacity(n);
        for i in 0..n {
            v.push(cell(r.get::<_, SqlValue>(i).map_err(|e| sq_err(&e))?));
        }
        out.push(v);
    }
    Ok(out)
}

/// One scope's connection inside `BEGIN IMMEDIATE`.
#[derive(Debug)]
pub struct SqliteTx {
    db: Option<SqliteDb>,
    cancel: CancelToken,
}

impl SqliteTx {
    fn check(&self, site: &str) -> Result<(), EngineError> {
        if self.cancel.is_cancelled() { Err(EngineError::Unavailable(format!("cancelled at {site}"))) } else { Ok(()) }
    }
}

impl Drop for SqliteTx {
    fn drop(&mut self) {
        if let Some(db) = self.db.take() {
            let _ = db.connection().execute_batch("ROLLBACK");
        }
    }
}

impl Executor<Rendered> for SqliteExec {
    type Tx = SqliteTx;
    type Rows = Rows;

    fn begin(&self, scope: &ScopeInfo<'_>) -> Result<SqliteTx, EngineError> {
        if scope.cancel.is_cancelled() {
            return Err(EngineError::Unavailable("cancelled before begin".into()));
        }
        let db = open(&self.path, self.budget_ms)?;
        db.connection().execute_batch("BEGIN IMMEDIATE").map_err(|e| sq_err(&e))?;
        Ok(SqliteTx { db: Some(db), cancel: scope.cancel.clone() })
    }

    fn execute(&self, tx: &mut SqliteTx, r: Rendered, l: OpLimits) -> Result<(Rows, Usage), EngineError> {
        tx.check("db.query")?;
        let db = tx.db.as_ref().ok_or_else(|| EngineError::Unavailable("transaction ended".into()))?;
        let t0 = Instant::now();
        let raw = db.run(&r).map_err(|e| sq_err(&e))?;
        let n = u64::try_from(raw.len()).unwrap_or(u64::MAX);
        if n > l.rows {
            return Err(EngineError::Unavailable("row cap".into()));
        }
        let rows: Rows = raw.into_iter().map(|row| row.into_iter().map(cell).collect()).collect();
        let bytes: usize = rows.iter().flatten().map(|v| v.as_ref().map_or(0, String::len)).sum();
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        if bytes > l.bytes {
            return Err(EngineError::Unavailable("byte cap".into()));
        }
        let ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX); // above l.ms: dispatch Overrun
        Ok((rows, Usage { rows: n, bytes, ms }))
    }

    fn commit(&self, mut tx: SqliteTx) -> Result<(), EngineError> {
        tx.check("db.COMMIT")?; // dropped tx: rolled back, nothing committed
        let db = tx.db.take().ok_or_else(|| EngineError::Unavailable("transaction ended".into()))?;
        match db.connection().execute_batch("COMMIT") {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = db.connection().execute_batch("ROLLBACK");
                Err(sq_err(&e))
            }
        }
    }

    fn rollback(&self, tx: SqliteTx) {
        drop(tx);
    }
}
