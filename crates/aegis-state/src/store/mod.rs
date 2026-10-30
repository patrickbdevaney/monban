//! Durable store (INV-DURABLE): bundled SQLite 3.53.2, WAL, `synchronous=FULL`, one writer connection.
//!
//! Spike q2-007 keep-decision, with its mandatory start-up assertions:
//! 1. `journal_mode` and `synchronous` are re-read **after the first write** of every open and the store refuses to
//!    start if either is not what it set. On a fresh file SQLite converts to WAL lazily; an fsync EIO during that
//!    conversion silently falls back to the rollback journal while `PRAGMA journal_mode=WAL` already answered `wal`
//!    (found by the crash-harness EIO stage). Every open performs a write (the `opens` counter in `meta`), so the
//!    re-read always follows a real write.
//! 2. The SQLite library is at or above the golden floor 3.51.3.
//! 3. Bootstrap fsyncs every store file, then the store directory, then its parent, before [`Store::open`] returns
//!    (the caller serves only after that). Creation is retryable: the database is built first, then the
//!    [`MARKER_FILE`] is published by temp file + fsync + rename, and only the bootstrap directory fsync makes that
//!    rename durable. A store directory without the marker is an unfinished creation and is rebuilt.
//! 4. Fail-stop: after any commit error (including an fsync EIO) the store is poisoned. Every later call returns
//!    [`StoreError::Poisoned`]; it never retries an fsync and acks (fsyncgate).
//!
//! D7 (C8 for an in-process engine): every PRAGMA is fixed here at open and never changed later; the API takes no
//! SQL, so no caller can ATTACH a database or create a temp object. Defence in depth: DEFENSIVE on, triggers and
//! views disabled, ATTACH create/write disabled, untrusted schema, and every open (and [`Store::check`]) asserts
//! that `main` is the only attached database and the schema holds exactly the two store tables.
//!
//! Layout: `<root>/state/aegis.db` (+ `-wal`, `-shm`) and `<root>/state/STORE` (creation marker). Rows live in one table keyed by `(space, key)`; a space is a
//! `u8` namespace owned by a higher layer (idempotency, outbox, latch in P4-state-002; 0 and 1 for the crash
//! subject).
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};

/// Golden floor for the bundled SQLite (crash-harness pin and q2-007).
pub const SQLITE_FLOOR: i32 = 3_051_003;
/// Store sub-directory under the configured root.
pub const STATE_DIR: &str = "state";
/// Database file name inside [`STATE_DIR`].
pub const DB_FILE: &str = "aegis.db";
/// Creation marker inside [`STATE_DIR`]: published by temp file + fsync + rename once the database is complete,
/// and made durable by the bootstrap directory fsync before the first READY. Its absence means "creation never
/// completed" and the store is rebuilt from nothing. SQLite fsyncs the store directory on the first WAL sync of a
/// connection, which happens before the marker rename, so the bootstrap directory fsync is the only thing that makes
/// the marker's directory entry durable.
pub const MARKER_FILE: &str = "STORE";
const MARKER_TMP: &str = "STORE.tmp";
const MARKER_CONTENT: &[u8] = b"aegis-state store format 1\n";
/// On-disk format version recorded in `meta`; an open refuses any other value.
pub const FORMAT_VERSION: i64 = 1;

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS meta(k TEXT NOT NULL PRIMARY KEY, v INTEGER NOT NULL) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS kv(space INTEGER NOT NULL, k BLOB NOT NULL, v BLOB NOT NULL, PRIMARY KEY(space, k)) WITHOUT ROWID, STRICT;";
const SQL_FORMAT_INIT: &str = "INSERT INTO meta(k, v) VALUES('format', ?1) ON CONFLICT(k) DO NOTHING";
const SQL_FORMAT_GET: &str = "SELECT v FROM meta WHERE k = 'format'";
const SQL_OPENS_BUMP: &str = "INSERT INTO meta(k, v) VALUES('opens', 1) ON CONFLICT(k) DO UPDATE SET v = v + 1";
const SQL_PUT: &str =
    "INSERT INTO kv(space, k, v) VALUES(?1, ?2, ?3) ON CONFLICT(space, k) DO UPDATE SET v = excluded.v";
const SQL_DEL: &str = "DELETE FROM kv WHERE space = ?1 AND k = ?2";
const SQL_GET: &str = "SELECT v FROM kv WHERE space = ?1 AND k = ?2";
const SQL_SCAN: &str = "SELECT k, v FROM kv WHERE space = ?1 ORDER BY k";
const SQL_DUMP: &str = "SELECT space, k, v FROM kv ORDER BY space, k";
const SQL_SCHEMA_OBJECTS: &str = "SELECT type, name FROM sqlite_schema ORDER BY type, name";
const EXPECTED_SCHEMA: [(&str, &str); 2] = [("table", "kv"), ("table", "meta")];
/// `PRAGMA synchronous` value for FULL.
const SYNC_FULL: i64 = 2;

/// Version string of the linked (bundled) SQLite library.
pub fn sqlite_version() -> &'static str {
    rusqlite::version()
}

/// Namespace of a row. Assigned by the layer above the store.
pub type Space = u8;

/// Every row of the store: `(space, key) -> value`.
pub type Dump = BTreeMap<(Space, Vec<u8>), Vec<u8>>;

/// Rows of one space, ordered by key: `(key, value)`.
pub type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// One write inside an atomic commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// Insert or overwrite `(space, key)`.
    Put { space: Space, key: Vec<u8>, value: Vec<u8> },
    /// Remove `(space, key)` if present.
    Delete { space: Space, key: Vec<u8> },
}

/// Store failure. Every variant is fail-closed: the caller must not serve or ack on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// Bundled SQLite below [`SQLITE_FLOOR`].
    SqliteBelowFloor(String),
    /// A PRAGMA did not take effect (q2-007 assertion 1) or the connection is not configured as required.
    ModeNotInEffect(String),
    /// The database holds objects other than the store schema, a database other than `main` is attached, or the
    /// format version is unknown.
    Schema(String),
    /// File-system error during bootstrap (create, walk, fsync).
    Io(String),
    /// SQLite error.
    Sqlite(String),
    /// `PRAGMA integrity_check` reported a problem (detect only; nothing is repaired).
    Integrity(String),
    /// An earlier commit failed; the store is fail-stopped.
    Poisoned,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::SqliteBelowFloor(v) => write!(f, "SQLite {v} below golden floor 3.51.3"),
            StoreError::ModeNotInEffect(m) => write!(f, "mode not in effect: {m}"),
            StoreError::Schema(m) => write!(f, "schema: {m}"),
            StoreError::Io(m) => write!(f, "io: {m}"),
            StoreError::Sqlite(m) => write!(f, "sqlite: {m}"),
            StoreError::Integrity(m) => write!(f, "integrity: {m}"),
            StoreError::Poisoned => write!(f, "store poisoned by an earlier commit error (fail-stop)"),
        }
    }
}

impl std::error::Error for StoreError {}

fn sq(e: rusqlite::Error) -> StoreError {
    StoreError::Sqlite(e.to_string())
}

/// Self-test mutations for the crash harness (`--no-dirsync`, `--no-mode-recheck`). Each one removes a required
/// check, so production code must use [`Store::open`], which is [`CrashMutations::NONE`].
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrashMutations {
    /// Skip the directory fsyncs at bootstrap.
    pub no_dirsync: bool,
    /// Skip the journal_mode/synchronous re-read after the first write.
    pub no_mode_recheck: bool,
}

impl CrashMutations {
    /// No mutation: every check runs.
    pub const NONE: CrashMutations = CrashMutations { no_dirsync: false, no_mode_recheck: false };
}

/// The durable store. Single writer: one process, one connection, `&mut self` for every call.
#[derive(Debug)]
pub struct Store {
    conn: Connection,
    dir: PathBuf,
    poisoned: bool,
}

impl Store {
    /// Open or create the store under `root` and run the INV-DURABLE bootstrap. On `Ok`, every store file and both
    /// directories (`root/state` and `root`) have been fsynced, and WAL + FULL were confirmed after a write.
    pub fn open(root: &Path) -> Result<Store, StoreError> {
        Store::open_with(root, CrashMutations::NONE)
    }

    #[doc(hidden)]
    pub fn open_with(root: &Path, m: CrashMutations) -> Result<Store, StoreError> {
        if rusqlite::version_number() < SQLITE_FLOOR {
            return Err(StoreError::SqliteBelowFloor(rusqlite::version().to_string()));
        }
        let dir = root.join(STATE_DIR);
        if !dir.is_dir() {
            create_private_dir(&dir)?;
        }
        let marker = dir.join(MARKER_FILE);
        // Only a definite "not found" counts as absent; any other stat error refuses (never wipe on EACCES/EIO).
        let fresh = match std::fs::symlink_metadata(&marker) {
            Ok(_) => false,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
            Err(e) => return Err(StoreError::Io(format!("stat {}: {e}", marker.display()))),
        };
        if fresh {
            // No durable marker: creation never completed, so nothing was ever acked from these files (the marker is
            // made durable before the first READY). Start over so a crashed bootstrap is retryable.
            for f in [DB_FILE, "aegis.db-wal", "aegis.db-shm", "aegis.db-journal", MARKER_TMP] {
                remove_if_present(&dir.join(f))?;
            }
        } else {
            check_marker(&marker)?;
            remove_if_present(&dir.join(MARKER_TMP))?;
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(dir.join(DB_FILE), flags).map_err(sq)?;
        harden(&conn)?;
        // PRAGMA journal_mode answers with the mode in effect; a failed switch answers the old mode, no error.
        let jm: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0)).map_err(sq)?;
        if !jm.eq_ignore_ascii_case("wal") {
            return Err(StoreError::ModeNotInEffect(format!("journal_mode=WAL not in effect (got {jm})")));
        }
        conn.execute_batch("PRAGMA synchronous=FULL; PRAGMA temp_store=MEMORY;").map_err(sq)?;
        first_write(&conn)?;
        if !m.no_mode_recheck {
            recheck_modes(&conn)?;
        }
        check_attached(&conn)?;
        check_schema(&conn)?;
        if fresh {
            publish_marker(&dir)?;
        }
        bootstrap_fsync(root, &dir, !m.no_dirsync)?;
        Ok(Store { conn, dir, poisoned: false })
    }

    /// The store directory (`root/state`).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// True once a commit has failed; every later call returns [`StoreError::Poisoned`].
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn live(&self) -> Result<(), StoreError> {
        if self.poisoned { Err(StoreError::Poisoned) } else { Ok(()) }
    }

    /// Apply `ops` atomically. `Ok` only once the transaction is durable (WAL fsynced under `synchronous=FULL`).
    /// Any error poisons the store.
    pub fn commit(&mut self, ops: &[Op]) -> Result<(), StoreError> {
        self.live()?;
        let r = apply(&mut self.conn, ops);
        if r.is_err() {
            self.poisoned = true;
        }
        r
    }

    /// Read one row.
    pub fn get(&mut self, space: Space, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.live()?;
        let mut st = self.conn.prepare(SQL_GET).map_err(sq)?;
        let mut rows = st.query(params![i64::from(space), key]).map_err(sq)?;
        match rows.next().map_err(sq)? {
            Some(r) => Ok(Some(r.get(0).map_err(sq)?)),
            None => Ok(None),
        }
    }

    /// Every row of one space, ordered by key.
    pub fn scan(&mut self, space: Space) -> Result<Rows, StoreError> {
        self.live()?;
        let mut st = self.conn.prepare(SQL_SCAN).map_err(sq)?;
        let rows = st.query_map(params![i64::from(space)], |r| Ok((r.get(0)?, r.get(1)?))).map_err(sq)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sq)
    }

    /// Every row of the store.
    pub fn dump(&mut self) -> Result<Dump, StoreError> {
        self.live()?;
        let mut st = self.conn.prepare(SQL_DUMP).map_err(sq)?;
        let rows = st
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, Vec<u8>>(2)?)))
            .map_err(sq)?;
        let mut d = Dump::new();
        for row in rows {
            let (s, k, v) = row.map_err(sq)?;
            let s = Space::try_from(s).map_err(|_| StoreError::Schema(format!("space {s} out of range")))?;
            d.insert((s, k), v);
        }
        Ok(d)
    }

    /// Detect-only integrity check: `PRAGMA integrity_check`, the attached-database list and the schema. Never
    /// repairs. Returns a short description on success.
    pub fn check(&mut self) -> Result<String, StoreError> {
        self.live()?;
        let mut st = self.conn.prepare("PRAGMA integrity_check").map_err(sq)?;
        let rows = st.query_map([], |r| r.get::<_, String>(0)).map_err(sq)?;
        let msgs = rows.collect::<Result<Vec<_>, _>>().map_err(sq)?;
        if msgs.len() != 1 || msgs.first().map(String::as_str) != Some("ok") {
            return Err(StoreError::Integrity(msgs.join("; ")));
        }
        drop(st);
        check_attached(&self.conn)?;
        check_schema(&self.conn)?;
        Ok(format!("sqlite={} integrity_check=ok", rusqlite::version()))
    }
}

fn apply(conn: &mut Connection, ops: &[Op]) -> Result<(), StoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(sq)?;
    {
        let mut put = tx.prepare(SQL_PUT).map_err(sq)?;
        let mut del = tx.prepare(SQL_DEL).map_err(sq)?;
        for op in ops {
            match op {
                Op::Put { space, key, value } => {
                    put.execute(params![i64::from(*space), key, value]).map_err(sq)?;
                }
                Op::Delete { space, key } => {
                    del.execute(params![i64::from(*space), key]).map_err(sq)?;
                }
            }
        }
    }
    tx.commit().map_err(sq)
}

/// Connection-level settings fixed at open (D7). Each must report the requested value.
fn harden(conn: &Connection) -> Result<(), StoreError> {
    let wanted = [
        (DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true, "DEFENSIVE"),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false, "ENABLE_TRIGGER"),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false, "ENABLE_VIEW"),
        (DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false, "TRUSTED_SCHEMA"),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE, false, "ENABLE_ATTACH_CREATE"),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_WRITE, false, "ENABLE_ATTACH_WRITE"),
    ];
    for (cfg, val, name) in wanted {
        let got = conn.set_db_config(cfg, val).map_err(sq)?;
        if got != val {
            return Err(StoreError::ModeNotInEffect(format!("{name}={val} not in effect")));
        }
    }
    Ok(())
}

/// Schema creation plus the per-open `opens` bump: one IMMEDIATE transaction that always writes.
fn first_write(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch("BEGIN IMMEDIATE;").map_err(sq)?;
    let r = (|| -> Result<(), StoreError> {
        conn.execute_batch(SCHEMA).map_err(sq)?;
        conn.execute(SQL_FORMAT_INIT, params![FORMAT_VERSION]).map_err(sq)?;
        let fv: i64 = conn.query_row(SQL_FORMAT_GET, [], |r| r.get(0)).map_err(sq)?;
        if fv != FORMAT_VERSION {
            return Err(StoreError::Schema(format!("format version {fv}, expected {FORMAT_VERSION}")));
        }
        conn.execute(SQL_OPENS_BUMP, []).map_err(sq)?;
        conn.execute_batch("COMMIT;").map_err(sq)
    })();
    if r.is_err() {
        // Best effort; the connection is dropped by the failing open anyway.
        let _ = conn.execute_batch("ROLLBACK;");
    }
    r
}

/// q2-007 assertion 1: re-read both modes after the first write.
fn recheck_modes(conn: &Connection) -> Result<(), StoreError> {
    let jm: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0)).map_err(sq)?;
    if !jm.eq_ignore_ascii_case("wal") {
        return Err(StoreError::ModeNotInEffect(format!(
            "journal_mode=WAL not in effect after first write (got {jm})"
        )));
    }
    let sy: i64 = conn.query_row("PRAGMA synchronous", [], |r| r.get(0)).map_err(sq)?;
    if sy != SYNC_FULL {
        return Err(StoreError::ModeNotInEffect(format!(
            "synchronous=FULL not in effect after first write (got {sy})"
        )));
    }
    Ok(())
}

/// D7: `main` is the only database on the connection (no ATTACH). SQLite may open its own empty `temp` schema
/// (e.g. for `integrity_check`), which is allowed only while it holds no object (no temp table, index, trigger
/// or view).
fn check_attached(conn: &Connection) -> Result<(), StoreError> {
    let mut st = conn.prepare("PRAGMA database_list").map_err(sq)?;
    let names = st.query_map([], |r| r.get::<_, String>(1)).map_err(sq)?.collect::<Result<Vec<_>, _>>().map_err(sq)?;
    let non_temp: Vec<&str> = names.iter().map(String::as_str).filter(|n| *n != "temp").collect();
    if non_temp != ["main"] {
        return Err(StoreError::Schema(format!("attached databases {names:?}, expected main only")));
    }
    let temp_objects: i64 = conn.query_row("SELECT count(*) FROM temp.sqlite_schema", [], |r| r.get(0)).map_err(sq)?;
    if temp_objects != 0 {
        return Err(StoreError::Schema(format!("{temp_objects} temp schema objects present")));
    }
    Ok(())
}

/// The schema holds exactly the store tables (no trigger, view, index or foreign table).
fn check_schema(conn: &Connection) -> Result<(), StoreError> {
    let mut st = conn.prepare(SQL_SCHEMA_OBJECTS).map_err(sq)?;
    let objs = st
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(sq)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sq)?;
    let same = objs.len() == EXPECTED_SCHEMA.len()
        && objs.iter().zip(EXPECTED_SCHEMA.iter()).all(|((t, n), (et, en))| t == et && n == en);
    if !same {
        return Err(StoreError::Schema(format!("unexpected schema objects {objs:?}")));
    }
    Ok(())
}

fn remove_if_present(p: &Path) -> Result<(), StoreError> {
    match std::fs::remove_file(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(StoreError::Io(format!("unlink {}: {e}", p.display()))),
    }
}

fn check_marker(marker: &Path) -> Result<(), StoreError> {
    let b = std::fs::read(marker).map_err(|e| StoreError::Io(format!("read {}: {e}", marker.display())))?;
    if b != MARKER_CONTENT {
        return Err(StoreError::Schema(format!("{} does not hold the format-1 marker", marker.display())));
    }
    Ok(())
}

/// Temp file + fsync + rename. The directory fsync that makes the rename durable is the bootstrap's.
fn publish_marker(dir: &Path) -> Result<(), StoreError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = dir.join(MARKER_TMP);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| StoreError::Io(format!("create {}: {e}", tmp.display())))?;
    f.write_all(MARKER_CONTENT)
        .and_then(|()| f.sync_all())
        .map_err(|e| StoreError::Io(format!("write {}: {e}", tmp.display())))?;
    drop(f);
    let dst = dir.join(MARKER_FILE);
    std::fs::rename(&tmp, &dst)
        .map_err(|e| StoreError::Io(format!("rename {} -> {}: {e}", tmp.display(), dst.display())))
}

fn create_private_dir(dir: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(dir)
        .map_err(|e| StoreError::Io(format!("mkdir {}: {e}", dir.display())))
}

/// INV-DURABLE bootstrap: fsync every regular file in the store directory, then the store directory, then its
/// parent (which holds the `state` entry).
fn bootstrap_fsync(root: &Path, dir: &Path, dirsync: bool) -> Result<(), StoreError> {
    let mut files = Vec::new();
    let rd = std::fs::read_dir(dir).map_err(|e| StoreError::Io(format!("read_dir {}: {e}", dir.display())))?;
    for ent in rd {
        let ent = ent.map_err(|e| StoreError::Io(format!("read_dir {}: {e}", dir.display())))?;
        let ft = ent.file_type().map_err(|e| StoreError::Io(format!("stat {}: {e}", ent.path().display())))?;
        if ft.is_file() {
            files.push(ent.path());
        }
    }
    files.sort();
    for f in &files {
        std::fs::OpenOptions::new()
            .read(true)
            .open(f)
            .and_then(|h| h.sync_all())
            .map_err(|e| StoreError::Io(format!("fsync {}: {e}", f.display())))?;
    }
    if dirsync {
        for d in [dir, root] {
            std::fs::File::open(d)
                .and_then(|h| h.sync_all())
                .map_err(|e| StoreError::Io(format!("fsync dir {}: {e}", d.display())))?;
        }
    }
    Ok(())
}
