//! monban-state store: round trip, fail-stop, D7 schema/attach assertions, q2-007 mode checks.
use std::path::PathBuf;

use monban_state::store::{CrashMutations, DB_FILE, MARKER_FILE, STATE_DIR};
use monban_state::{CrashSubject, Op, Store, StoreError};

struct Tmp(PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn tmp(name: &str) -> Result<Tmp, String> {
    let p = std::env::temp_dir().join(format!("monban-state-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).map_err(|e| e.to_string())?;
    Ok(Tmp(p))
}
fn put(space: u8, k: &[u8], v: &[u8]) -> Op {
    Op::Put { space, key: k.to_vec(), value: v.to_vec() }
}

#[test]
fn round_trip_and_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let t = tmp("rt")?;
    {
        let mut s = Store::open(&t.0)?;
        s.commit(&[put(0, b"a", b"1"), put(1, b"b", b"2"), put(2, b"c", b"3")])?;
        s.commit(&[put(0, b"a", b"9"), Op::Delete { space: 2, key: b"c".to_vec() }])?;
        assert_eq!(s.get(0, b"a")?, Some(b"9".to_vec()));
        assert_eq!(s.get(2, b"c")?, None);
    }
    assert!(t.0.join(STATE_DIR).join(DB_FILE).is_file());
    let mut s = Store::open(&t.0)?;
    let d = s.dump()?;
    assert_eq!(d.len(), 2);
    assert_eq!(d.get(&(1, b"b".to_vec())), Some(&b"2".to_vec()));
    assert_eq!(s.scan(0)?, vec![(b"a".to_vec(), b"9".to_vec())]);
    assert!(s.check()?.contains("integrity_check=ok"));
    // the trait view agrees
    assert_eq!(CrashSubject::dump(&mut s)?, d);
    CrashSubject::check(&mut s)?;
    Ok(())
}

#[test]
fn modes_are_wal_full_and_fixed() -> Result<(), Box<dyn std::error::Error>> {
    let t = tmp("modes")?;
    drop(Store::open(&t.0)?);
    let c = rusqlite::Connection::open(t.0.join(STATE_DIR).join(DB_FILE))?;
    let jm: String = c.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
    assert_eq!(jm, "wal"); // persistent in the header
    Ok(())
}

#[test]
fn foreign_schema_object_refused() -> Result<(), Box<dyn std::error::Error>> {
    let t = tmp("schema")?;
    drop(Store::open(&t.0)?);
    {
        let c = rusqlite::Connection::open(t.0.join(STATE_DIR).join(DB_FILE))?;
        c.execute_batch("CREATE TABLE extra(x);")?;
    }
    match Store::open(&t.0) {
        Err(StoreError::Schema(m)) => assert!(m.contains("extra"), "{m}"),
        other => return Err(format!("expected Schema error, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn trigger_refused() -> Result<(), Box<dyn std::error::Error>> {
    let t = tmp("trigger")?;
    drop(Store::open(&t.0)?);
    {
        let c = rusqlite::Connection::open(t.0.join(STATE_DIR).join(DB_FILE))?;
        c.execute_batch("CREATE TRIGGER tr AFTER INSERT ON kv BEGIN DELETE FROM kv; END;")?;
    }
    assert!(matches!(Store::open(&t.0), Err(StoreError::Schema(_))));
    Ok(())
}

#[test]
fn unknown_format_refused() -> Result<(), Box<dyn std::error::Error>> {
    let t = tmp("format")?;
    drop(Store::open(&t.0)?);
    {
        let c = rusqlite::Connection::open(t.0.join(STATE_DIR).join(DB_FILE))?;
        c.execute_batch("UPDATE meta SET v = 99 WHERE k = 'format';")?;
    }
    assert!(matches!(Store::open(&t.0), Err(StoreError::Schema(_))));
    Ok(())
}

#[test]
fn poisoned_after_commit_error() -> Result<(), Box<dyn std::error::Error>> {
    let t = tmp("poison")?;
    let mut s = Store::open(&t.0)?;
    s.commit(&[put(0, b"a", b"1")])?;
    // Make the next commit fail: another connection holds the write lock (busy timeout is 0).
    let other = rusqlite::Connection::open(t.0.join(STATE_DIR).join(DB_FILE))?;
    other.execute_batch("BEGIN IMMEDIATE;")?;
    assert!(s.commit(&[put(0, b"b", b"2")]).is_err());
    assert!(s.is_poisoned());
    other.execute_batch("ROLLBACK;")?;
    assert_eq!(s.commit(&[put(0, b"c", b"3")]), Err(StoreError::Poisoned));
    assert_eq!(s.dump(), Err(StoreError::Poisoned));
    assert_eq!(s.get(0, b"a"), Err(StoreError::Poisoned));
    Ok(())
}

#[test]
fn missing_root_refused() {
    let p = std::env::temp_dir().join(format!("monban-state-missing-{}/nope", std::process::id()));
    assert!(matches!(Store::open(&p), Err(StoreError::Io(_))));
}

#[test]
fn missing_marker_means_unfinished_creation() -> Result<(), Box<dyn std::error::Error>> {
    let t = tmp("marker")?;
    {
        let mut s = Store::open(&t.0)?;
        s.commit(&[put(0, b"a", b"1")])?;
    }
    let m = t.0.join(STATE_DIR).join(MARKER_FILE);
    assert!(m.is_file());
    std::fs::remove_file(&m)?;
    let mut s = Store::open(&t.0)?;
    assert!(s.dump()?.is_empty(), "store without a marker is rebuilt from nothing");
    assert!(m.is_file());
    Ok(())
}

#[test]
fn bad_marker_refused() -> Result<(), Box<dyn std::error::Error>> {
    let t = tmp("badmarker")?;
    drop(Store::open(&t.0)?);
    std::fs::write(t.0.join(STATE_DIR).join(MARKER_FILE), b"other\n")?;
    assert!(matches!(Store::open(&t.0), Err(StoreError::Schema(_))));
    Ok(())
}

#[test]
fn mutations_none_is_default() {
    assert_eq!(CrashMutations::NONE, CrashMutations { no_dirsync: false, no_mode_recheck: false });
}
