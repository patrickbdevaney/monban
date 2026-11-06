//! CockroachDB over the PG wire (feature `crdb`, P7-adapter-crdb-001; PREFLIGHT D-P7.8, spikes/q4-005).
//!
//! The renderer and the live schema gate take [`Dialect::Crdb`] (`lower::render_dialect`,
//! `schema::check_live_schema_dialect`). This module holds what is CockroachDB-only on the connection side:
//!
//! * **Version gate.** CockroachDB reports `server_version` 13.0.0 (its PG-compatibility level), so the PostgreSQL
//!   gate refuses it as unparseable (three parts). The release is read from `SELECT version()`
//!   (`CockroachDB CCL v25.4.19 (...)`, third word, as ci/engines.sh and the oracles read it) and admitted against the
//!   floors that `build.rs` compiles from the `kind = "crdb"` pins of `supply-chain/engine-pins.toml` (no hand-copied
//!   constant): same release series (`major.minor`) as a floor, patch numerically at or above it, never a
//!   pre-release (`-alpha`, `-beta`, `-rc` ...), never a blocked series. A pooled re-connection must report exactly
//!   the admitted release ([`connect_admitted`] with `pinned`), or it is refused (R-DB-1 recycle).
//! * **SERIALIZABLE retry.** CockroachDB runs every transaction SERIALIZABLE and aborts one side of a conflict with
//!   SQLSTATE 40001 (also at COMMIT). [`run_serializable`] retries the WHOLE transaction (BEGIN .. body .. COMMIT),
//!   after a ROLLBACK of the failed attempt, with a bounded attempt count ([`RetryPolicy::max_attempts`], at most
//!   [`MAX_ATTEMPTS_CAP`]), capped exponential backoff and the caller's deadline. q4-005 measured that whole-
//!   transaction retry gives exactly-once effects under contention (8 threads x 40 transactions: 320 commits, 1830
//!   retries, at most 58 attempts). Only 40001 is retried: 40003 (statement completion unknown) and every other
//!   error are returned at once, since the outcome of the failed attempt may be unknown.

use std::fmt;
use std::time::{Duration, Instant};

use aegis_data_ir::EngineVersion;

use crate::lower::Dialect;
use crate::version::AdmittedVersion;
use crate::wire::{ConnectConfig, Connection, DbError, Error as WireError, TxnStatus};

mod pins {
    include!(concat!(env!("OUT_DIR"), "/crdb_pins.rs"));
}
pub use pins::{CRDB_BLOCKED_SERIES, CRDB_FLOORS};

/// The dialect this module serves.
pub const DIALECT: Dialect = Dialect::Crdb;

// ------------------------------------------------------------------------------------------------- version gate

/// Why a CockroachDB server was not admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrdbVersionRefusal {
    /// `version()` did not return one text value.
    Missing,
    /// Not `CockroachDB <edition> v<major>.<minor>.<patch>[ ...]`.
    Unparseable {
        version: String,
    },
    /// A pre-release never satisfies a floor.
    PreRelease {
        token: String,
    },
    /// The series is `policy = "blocked"` in engine-pins.toml.
    BlockedSeries {
        token: String,
    },
    /// No floor for this release series in engine-pins.toml.
    UnknownSeries {
        token: String,
    },
    BelowFloor {
        token: String,
        floor: (u32, u32, u32),
    },
    /// A re-established pooled connection reports a different release than the one admitted (R-DB-1 recycle).
    Changed {
        admitted: String,
        now: String,
    },
}

impl fmt::Display for CrdbVersionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CrdbVersionRefusal::Missing => write!(f, "server did not report version()"),
            CrdbVersionRefusal::Unparseable { version } => {
                write!(f, "unparseable CockroachDB version() {:?}", version.escape_debug().to_string())
            }
            CrdbVersionRefusal::PreRelease { token } => {
                write!(f, "pre-release CockroachDB {token} never satisfies a floor")
            }
            CrdbVersionRefusal::BlockedSeries { token } => write!(f, "CockroachDB series of {token} is blocked"),
            CrdbVersionRefusal::UnknownSeries { token } => {
                write!(f, "CockroachDB series of {token} has no floor in engine-pins.toml")
            }
            CrdbVersionRefusal::BelowFloor { token, floor: (a, b, c) } => {
                write!(f, "CockroachDB {token} below floor {a}.{b}.{c} (engine-pins.toml advisory)")
            }
            CrdbVersionRefusal::Changed { admitted, now } => {
                write!(f, "CockroachDB version changed {admitted} -> {now} on reconnect; pool entry recycled (R-DB-1)")
            }
        }
    }
}

impl std::error::Error for CrdbVersionRefusal {}

fn decimal(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u32>().ok()
}

fn release3(s: &str) -> Option<EngineVersion> {
    let mut it = s.split('.');
    let (major, minor, patch) = (decimal(it.next()?)?, decimal(it.next()?)?, decimal(it.next()?)?);
    if it.next().is_some() {
        return None;
    }
    Some(EngineVersion { major, minor, patch })
}

/// Classification of a CockroachDB `version()` string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrdbRelease {
    /// `v<major>.<minor>.<patch>`: the token without `v`, and its numeric value.
    Release(String, EngineVersion),
    /// `v<major>.<minor>.<patch>-<suffix>` (alpha, beta, rc, ...).
    PreRelease(String),
    Unparseable,
}

/// Parse `version()`: the first word must be `CockroachDB`, the third is the release (`v25.4.19`).
pub fn parse_version(version: &str) -> CrdbRelease {
    let mut words = version.split(' ');
    if words.next() != Some("CockroachDB") {
        return CrdbRelease::Unparseable;
    }
    let _edition = words.next();
    let Some(tok) = words.next().and_then(|w| w.strip_prefix('v')) else { return CrdbRelease::Unparseable };
    match tok.split_once('-') {
        Some((base, suffix)) if release3(base).is_some() && !suffix.is_empty() => {
            CrdbRelease::PreRelease(tok.to_owned())
        }
        Some(_) => CrdbRelease::Unparseable,
        None => match release3(tok) {
            Some(v) => CrdbRelease::Release(tok.to_owned(), v),
            None => CrdbRelease::Unparseable,
        },
    }
}

/// Admit or refuse a `version()` string (`None` = not reported).
pub fn admit_version(version: Option<&str>) -> Result<AdmittedVersion, CrdbVersionRefusal> {
    let v = version.ok_or(CrdbVersionRefusal::Missing)?;
    match parse_version(v) {
        CrdbRelease::Release(token, ev) => {
            if CRDB_BLOCKED_SERIES.contains(&(ev.major, ev.minor)) {
                return Err(CrdbVersionRefusal::BlockedSeries { token });
            }
            let Some(&floor) = CRDB_FLOORS.iter().find(|(a, b, _)| (*a, *b) == (ev.major, ev.minor)) else {
                return Err(CrdbVersionRefusal::UnknownSeries { token });
            };
            if ev.patch < floor.2 {
                return Err(CrdbVersionRefusal::BelowFloor { token, floor });
            }
            Ok(AdmittedVersion::new(token, ev))
        }
        CrdbRelease::PreRelease(token) => Err(CrdbVersionRefusal::PreRelease { token }),
        CrdbRelease::Unparseable => Err(CrdbVersionRefusal::Unparseable { version: v.to_owned() }),
    }
}

/// Re-admission of a re-established pooled connection: the release must equal the admitted one, and pass the gate.
pub fn recheck(admitted: &AdmittedVersion, version: Option<&str>) -> Result<AdmittedVersion, CrdbVersionRefusal> {
    let now = admit_version(version);
    match &now {
        Ok(a) if a.token() == admitted.token() => now,
        Ok(a) => Err(CrdbVersionRefusal::Changed { admitted: admitted.token().to_owned(), now: a.token().to_owned() }),
        Err(e) => Err(CrdbVersionRefusal::Changed { admitted: admitted.token().to_owned(), now: e.to_string() }),
    }
}

/// Why [`connect_admitted`] produced no connection.
#[derive(Debug)]
pub enum CrdbConnectError {
    Wire(WireError),
    /// Started, but the release is refused by the gate; the connection was terminated.
    Refused(CrdbVersionRefusal),
}

impl fmt::Display for CrdbConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CrdbConnectError::Wire(e) => write!(f, "{e}"),
            CrdbConnectError::Refused(r) => write!(f, "{r}"),
        }
    }
}

impl std::error::Error for CrdbConnectError {}

const TERMINATE_TIMEOUT: Duration = Duration::from_millis(200);

/// Open + start up + authenticate, then `SELECT version()` and gate the release. With `pinned = Some(a)` (a pooled
/// key admitted before) the release must be exactly `a`'s. A refused connection is terminated, never returned.
/// The version query is bounded by `cfg.connect_timeout`.
pub fn connect_admitted(
    cfg: &ConnectConfig,
    pinned: Option<&AdmittedVersion>,
) -> Result<(Connection, AdmittedVersion), CrdbConnectError> {
    let mut conn = Connection::connect(cfg).map_err(CrdbConnectError::Wire)?;
    let deadline = Instant::now() + cfg.connect_timeout;
    let version = match conn.query("SELECT version()", &[], deadline) {
        Ok(r) => match r.rows.as_slice() {
            [row] => match row.as_slice() {
                [Some(v)] => Some(v.clone()),
                _ => None,
            },
            _ => None,
        },
        Err(e) => {
            conn.terminate(TERMINATE_TIMEOUT);
            return Err(CrdbConnectError::Wire(e));
        }
    };
    let verdict = match pinned {
        Some(a) => recheck(a, version.as_deref()),
        None => admit_version(version.as_deref()),
    };
    match verdict {
        Ok(v) => Ok((conn, v)),
        Err(r) => {
            conn.terminate(TERMINATE_TIMEOUT);
            Err(CrdbConnectError::Refused(r))
        }
    }
}

// --------------------------------------------------------------------------------------------- SERIALIZABLE retry

/// SQLSTATE `serialization_failure`: CockroachDB's "restart transaction".
pub const SERIALIZATION_FAILURE: &str = "40001";
/// Hard upper bound on [`RetryPolicy::max_attempts`] (a policy above it is refused, never clamped silently).
pub const MAX_ATTEMPTS_CAP: u32 = 256;

/// Bounds of the whole-transaction retry. Every bound holds at once: at most `max_attempts` attempts, and none
/// started after the caller's deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Attempts in total, first one included (1..=[`MAX_ATTEMPTS_CAP`]).
    pub max_attempts: u32,
    /// Sleep before the second attempt; doubled per retry up to `max_backoff`, never past the deadline.
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for RetryPolicy {
    /// 32 attempts, 1 ms doubling to 64 ms. q4-005's worst case under deliberate 8-way contention on one row set was
    /// 58 attempts without backoff; with backoff and ordinary contention far fewer are needed, and a caller that
    /// expects hot rows raises it (up to the cap).
    fn default() -> Self {
        RetryPolicy {
            max_attempts: 32,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(64),
        }
    }
}

/// Why a retried transaction did not commit.
#[derive(Debug)]
pub enum TxnError {
    /// A non-retryable error (anything but 40001), returned at once. The failed attempt was rolled back if the
    /// connection was still usable.
    Failed { attempts: u32, error: WireError },
    /// Every one of `attempts` attempts ended in 40001.
    Exhausted { attempts: u32, last: DbError },
    /// The deadline passed before the next attempt could start.
    Deadline { attempts: u32, last: Option<DbError> },
    /// `max_attempts` is 0 or above [`MAX_ATTEMPTS_CAP`]: nothing was run.
    BadPolicy,
}

impl TxnError {
    /// Attempts made (0 for [`TxnError::BadPolicy`]).
    pub fn attempts(&self) -> u32 {
        match self {
            TxnError::Failed { attempts, .. }
            | TxnError::Exhausted { attempts, .. }
            | TxnError::Deadline { attempts, .. } => *attempts,
            TxnError::BadPolicy => 0,
        }
    }
}

impl fmt::Display for TxnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxnError::Failed { attempts, error } => write!(f, "transaction failed on attempt {attempts}: {error}"),
            TxnError::Exhausted { attempts, last } => {
                write!(f, "transaction not committed after {attempts} attempts (40001 each): {last}")
            }
            TxnError::Deadline { attempts, .. } => write!(f, "deadline passed after {attempts} attempt(s)"),
            TxnError::BadPolicy => write!(f, "retry policy max_attempts outside 1..={MAX_ATTEMPTS_CAP}"),
        }
    }
}

impl std::error::Error for TxnError {}

/// The 40001 SQLSTATE, if `e` is a server error carrying it.
pub fn serialization_failure(e: &WireError) -> Option<&DbError> {
    match e {
        WireError::Db(d) if d.code == SERIALIZATION_FAILURE => Some(d),
        _ => None,
    }
}

/// The retry loop, independent of the connection: `attempt(n)` (n = 1, 2, ..) runs one whole transaction and must
/// leave no effect when it returns an error. 40001 is retried after a backoff `sleep`; anything else is final.
/// Returns the value and the number of attempts made.
pub fn retry_serializable<T>(
    policy: &RetryPolicy,
    deadline: Instant,
    mut sleep: impl FnMut(Duration),
    mut attempt: impl FnMut(u32) -> Result<T, WireError>,
) -> Result<(T, u32), TxnError> {
    if policy.max_attempts == 0 || policy.max_attempts > MAX_ATTEMPTS_CAP {
        return Err(TxnError::BadPolicy);
    }
    let mut backoff = policy.initial_backoff;
    let mut last: Option<DbError> = None;
    for n in 1..=policy.max_attempts {
        if n > 1 {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(TxnError::Deadline { attempts: n - 1, last });
            }
            sleep(backoff.min(left));
            backoff = backoff.saturating_mul(2).min(policy.max_backoff);
        }
        if Instant::now() >= deadline {
            return Err(TxnError::Deadline { attempts: n - 1, last });
        }
        match attempt(n) {
            Ok(v) => return Ok((v, n)),
            Err(e) => match serialization_failure(&e) {
                Some(d) => last = Some(d.clone()),
                None => return Err(TxnError::Failed { attempts: n, error: e }),
            },
        }
    }
    match last {
        Some(last) => Err(TxnError::Exhausted { attempts: policy.max_attempts, last }),
        None => Err(TxnError::Deadline { attempts: policy.max_attempts, last: None }),
    }
}

/// ROLLBACK if a transaction is open (or failed) on a still-usable connection. A failing ROLLBACK is returned.
fn rollback_if_open(conn: &mut Connection, deadline: Instant) -> Result<(), WireError> {
    if conn.state().unrecoverable().is_some() || conn.state().outstanding() > 0 {
        return Ok(()); // unusable: the caller discards it; nothing more is sent
    }
    match conn.state().txn_status() {
        Some(TxnStatus::InTransaction | TxnStatus::Failed) => conn.simple_query("ROLLBACK", deadline).map(|_| ()),
        _ => Ok(()),
    }
}

/// One whole SERIALIZABLE transaction on `conn`, retried on 40001 under `policy` and `deadline`:
/// `BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE`, `body(conn, attempt)`, `COMMIT`. Any error (body, BEGIN or
/// COMMIT) rolls the attempt back first; a COMMIT that reports anything but `COMMIT` (the server rolled back an
/// aborted transaction the body did not report) is a non-retryable failure. `body` must not commit, roll back or
/// keep state across attempts: it is re-run from the start. The connection must be idle on entry.
pub fn run_serializable<T>(
    conn: &mut Connection,
    policy: &RetryPolicy,
    deadline: Instant,
    mut body: impl FnMut(&mut Connection, u32) -> Result<T, WireError>,
) -> Result<(T, u32), TxnError> {
    if conn.state().txn_status() != Some(TxnStatus::Idle) {
        return Err(TxnError::Failed {
            attempts: 0,
            error: WireError::Usage("run_serializable needs an idle connection".into()),
        });
    }
    retry_serializable(policy, deadline, std::thread::sleep, |n| {
        let r = conn.simple_query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE", deadline).and_then(|_| {
            let v = body(conn, n)?;
            let c = conn.simple_query("COMMIT", deadline)?;
            match c.last().map(|r| r.tag.as_str()) {
                Some("COMMIT") => Ok(v),
                other => Err(WireError::Usage(format!("COMMIT reported {other:?}: transaction was aborted"))),
            }
        });
        match r {
            Ok(v) => Ok(v),
            Err(e) => match rollback_if_open(conn, deadline) {
                Ok(()) => Err(e),
                // The failed attempt could not be closed: never retry on top of it.
                Err(rb) => Err(match rb {
                    WireError::Db(d) if d.code == SERIALIZATION_FAILURE => {
                        WireError::Usage(format!("ROLLBACK failed: {d}"))
                    }
                    other => other,
                }),
            },
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db(code: &str) -> WireError {
        WireError::Db(DbError {
            severity: "ERROR".into(),
            code: code.into(),
            message: "m".into(),
            ..DbError::default()
        })
    }

    fn ok(s: &str) -> bool {
        admit_version(Some(s)).is_ok()
    }

    #[test]
    fn floors_come_from_pins() {
        assert!(!CRDB_FLOORS.is_empty());
        for &(a, b, c) in CRDB_FLOORS {
            assert!(ok(&format!("CockroachDB CCL v{a}.{b}.{c} (x86_64-pc-linux-gnu, built 2026/10/29)")));
            assert!(ok(&format!("CockroachDB OSS v{a}.{b}.{}", c + 1)));
            assert!(ok(&format!("CockroachDB CCL v{a}.{b}.{}", c + 10)));
            if c > 0 {
                assert!(matches!(
                    admit_version(Some(&format!("CockroachDB CCL v{a}.{b}.{}", c - 1))),
                    Err(CrdbVersionRefusal::BelowFloor { .. })
                ));
            }
            assert!(matches!(
                admit_version(Some(&format!("CockroachDB CCL v{a}.{}.{c}", b + 1))),
                Err(CrdbVersionRefusal::UnknownSeries { .. })
            ));
            assert!(matches!(
                admit_version(Some(&format!("CockroachDB CCL v{a}.{b}.{}-rc.1", c + 1))),
                Err(CrdbVersionRefusal::PreRelease { .. })
            ));
            let adm = admit_version(Some(&format!("CockroachDB CCL v{a}.{b}.{c} (x)")));
            assert_eq!(adm.as_ref().map(|v| v.version()), Ok(EngineVersion { major: a, minor: b, patch: c }));
        }
    }

    #[test]
    fn refusals() {
        for s in [
            "",
            "13.0.0",
            "PostgreSQL 17.11 on x86_64",
            "CockroachDB CCL 25.4.19",
            "CockroachDB CCL v25.4",
            "CockroachDB CCL v25.4.19.1",
            "CockroachDB CCL v25.4.x",
            "CockroachDB CCL v25.4.-1",
            "CockroachDB CCL v25.4.4294967315",
            "CockroachDB CCL v25.4.19-",
            "CockroachDB CCL v25.4.19-beta.1",
            "CockroachDB CCL v25.4.0-alpha.00000000-1234-gabcdef",
            "CockroachDB CCL v２５.4.19",
            "cockroachdb CCL v25.4.19",
            "CockroachDB v25.4.19",
            "CockroachDB CCL v1.0.0",
        ] {
            assert!(!ok(s), "{s:?} accepted");
        }
        assert_eq!(admit_version(None), Err(CrdbVersionRefusal::Missing));
    }

    #[test]
    fn recheck_refuses_any_change() {
        let Some(&(a, b, c)) = CRDB_FLOORS.first() else { unreachable!("no floor") };
        let v = format!("CockroachDB CCL v{a}.{b}.{c} (x)");
        let adm = admit_version(Some(&v)).unwrap_or_else(|e| unreachable!("{e}"));
        assert!(recheck(&adm, Some(&v)).is_ok());
        assert!(matches!(
            recheck(&adm, Some(&format!("CockroachDB CCL v{a}.{b}.{}", c + 1))),
            Err(CrdbVersionRefusal::Changed { .. })
        ));
        assert!(matches!(recheck(&adm, None), Err(CrdbVersionRefusal::Changed { .. })));
    }

    #[test]
    fn upsert_guard_is_the_q4_005_form() {
        use crate::lower::{PgClass, PgColumn, PgTable, render, render_dialect};
        use aegis_data_ir::{Lowered, OpKind, Stmt, UpsertAction, Value};
        let col = |field, name: &str, class| PgColumn { field, name: name.into(), class };
        let table = PgTable {
            namespace: None,
            name: "t".into(),
            columns: vec![col(0, "id", PgClass::Int), col(1, "tenant", PgClass::Text), col(2, "x", PgClass::Text)],
            unique: vec![vec![1, 0]],
            fks: Vec::new(),
        };
        let l = Lowered {
            collection: "t".into(),
            kind: OpKind::Upsert,
            tenant_field: 1,
            tenant: Value::Str("00000000000000aa".into()),
            stmt: Stmt::Upsert {
                row: vec![(1, Value::Str("00000000000000aa".into())), (0, Value::Int(5)), (2, Value::Str("v".into()))],
                arbiter: vec![1, 0],
                action: UpsertAction::Update { set: vec![2], guard: 1 },
            },
            returning: vec![0],
        };
        let c = render_dialect(&l, &table, Dialect::Crdb).unwrap_or_else(|e| unreachable!("{e}"));
        assert!(
            c.sql.ends_with(
                " DO UPDATE SET \"x\" = excluded.\"x\" WHERE \"t\".\"tenant\"::text = excluded.\"tenant\"::text \
                 COLLATE \"C\" RETURNING \"id\""
            ),
            "{}",
            c.sql
        );
        assert!(c.sql.starts_with("INSERT INTO \"t\" ") && !c.sql.contains("UPSERT"));
        // The default dialect is byte-for-byte the PG form.
        let p = render(&l, &table).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(Some(p.clone()), render_dialect(&l, &table, Dialect::Postgres).ok());
        assert!(
            p.sql.contains(" WHERE (\"t\".\"tenant\"::text COLLATE \"C\") = (excluded.\"tenant\"::text COLLATE \"C\")")
        );
        assert_eq!(p.params, c.params);
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    #[test]
    fn retries_40001_then_commits() {
        let mut slept = Vec::new();
        let r = retry_serializable(
            &RetryPolicy::default(),
            far(),
            |d| slept.push(d),
            |n| {
                if n < 4 { Err(db("40001")) } else { Ok(n * 10) }
            },
        );
        assert!(matches!(r, Ok((40, 4))));
        assert_eq!(slept, vec![Duration::from_millis(1), Duration::from_millis(2), Duration::from_millis(4)]);
    }

    #[test]
    fn retry_is_bounded() {
        let p = RetryPolicy { max_attempts: 5, ..RetryPolicy::default() };
        let mut calls = 0u32;
        let r: Result<((), u32), TxnError> = retry_serializable(
            &p,
            far(),
            |_| {},
            |_| {
                calls += 1;
                Err(db("40001"))
            },
        );
        assert!(matches!(r, Err(TxnError::Exhausted { attempts: 5, .. })));
        assert_eq!(calls, 5);
        let mut slept = Duration::ZERO;
        let p = RetryPolicy { max_attempts: MAX_ATTEMPTS_CAP, ..RetryPolicy::default() };
        let _ = retry_serializable(&p, far(), |d| slept += d, |_| -> Result<(), WireError> { Err(db("40001")) });
        assert!(slept <= p.max_backoff * MAX_ATTEMPTS_CAP);
        for bad in [0, MAX_ATTEMPTS_CAP + 1] {
            let p = RetryPolicy { max_attempts: bad, ..RetryPolicy::default() };
            let r = retry_serializable(&p, far(), |_| {}, |_| -> Result<(), WireError> { unreachable!("ran") });
            assert!(matches!(r, Err(TxnError::BadPolicy)));
        }
    }

    #[test]
    fn other_errors_are_final() {
        for code in ["40003", "23505", "40P01", "57014", "4000"] {
            let mut calls = 0u32;
            let r: Result<((), u32), TxnError> = retry_serializable(
                &RetryPolicy::default(),
                far(),
                |_| {},
                |_| {
                    calls += 1;
                    Err(db(code))
                },
            );
            assert!(matches!(r, Err(TxnError::Failed { attempts: 1, .. })), "{code}");
            assert_eq!(calls, 1);
        }
        let r: Result<((), u32), TxnError> =
            retry_serializable(&RetryPolicy::default(), far(), |_| {}, |_| Err(WireError::Timeout));
        assert!(matches!(r, Err(TxnError::Failed { attempts: 1, error: WireError::Timeout })));
    }

    #[test]
    fn deadline_stops_retries() {
        let deadline = Instant::now() + Duration::from_millis(30);
        let mut calls = 0u32;
        let r: Result<((), u32), TxnError> = retry_serializable(
            &RetryPolicy { max_attempts: MAX_ATTEMPTS_CAP, ..RetryPolicy::default() },
            deadline,
            std::thread::sleep,
            |_| {
                calls += 1;
                Err(db("40001"))
            },
        );
        assert!(matches!(r, Err(TxnError::Deadline { .. })));
        assert!(calls < MAX_ATTEMPTS_CAP);
        let past = Instant::now();
        let r = retry_serializable(
            &RetryPolicy::default(),
            past,
            |_| {},
            |_| -> Result<(), WireError> { unreachable!("ran after the deadline") },
        );
        assert!(matches!(r, Err(TxnError::Deadline { attempts: 0, .. })));
    }
}
