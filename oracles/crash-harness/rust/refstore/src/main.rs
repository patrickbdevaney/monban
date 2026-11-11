//! Reference subjects for the Monban crash harness, speaking the subject line protocol (README "Subject protocol").
//! Port of research round-002 `wl/src/main.rs`, restricted to the golden floor (SQLite, redb) plus the own-log
//! controls, with the workload moved into the driver (the oracle owns the workload; a subject is only a store).
//!
//! usage: refstore serve <store> <cfg> <dir> [--no-dirsync] [--ack-early] [--no-mode-recheck]
//!   sqlite: wal-full | wal-normal | wal-extra | del-full | del-normal | trunc-full
//!   redb:   2pc (2PC + Durability::Immediate) | imm (1PC+C Immediate, redb default) | none (Durability::None)
//!   wal:    crc (len|crc32|payload records, fdatasync per commit, CRC-terminated recovery) | naive (no fsync)
//! Bootstrap (INV-DURABLE): after opening, fsync every file under <dir>, then <dir> and its subdirectories, before
//! printing READY. Self-test mutations: `--no-dirsync` skips the directory fsyncs; `--ack-early` replies OK before the
//! commit (and its fsync) has run; `--no-mode-recheck` (sqlite only) skips the journal_mode/synchronous re-read after
//! the first write (q2-007 assertion 1), so a silent WAL -> rollback-journal fallback is served.
use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

type Dump = BTreeMap<(u8, Vec<u8>), Vec<u8>>;
type Puts = Vec<(u8, Vec<u8>, Vec<u8>)>;

trait Store {
    fn commit(&mut self, puts: &Puts) -> Result<(), String>;
    fn dump(&mut self) -> Result<Dump, String>;
    fn integrity(&mut self) -> Result<String, String>;
}

mod sqlite_s {
    use super::*;
    use rusqlite::*;
    pub struct S(Connection);
    pub fn open(dir: &Path, cfg: &str, recheck: bool) -> Result<S, String> {
        let v = rusqlite::version_number();
        if v < 3_054_000 {
            return Err(format!("SQLite {} below golden floor 3.54.0", rusqlite::version()));
        }
        let (jm, sy) = match cfg {
            "wal-full" => ("WAL", "FULL"),
            "wal-normal" => ("WAL", "NORMAL"),
            "wal-extra" => ("WAL", "EXTRA"),
            "del-full" => ("DELETE", "FULL"),
            "del-normal" => ("DELETE", "NORMAL"),
            "trunc-full" => ("TRUNCATE", "FULL"),
            _ => return Err(format!("unknown sqlite cfg {cfg}")),
        };
        let c = Connection::open(dir.join("s.db")).map_err(|e| e.to_string())?;
        // PRAGMA journal_mode reports the mode in effect; a failed switch (e.g. fsync EIO while converting) returns
        // the OLD mode without an error. Fail closed instead of serving in a weaker mode (found by the EIO stage).
        let got: String = c.query_row(&format!("PRAGMA journal_mode={jm}"), [], |r| r.get(0)).map_err(|e| e.to_string())?;
        if !got.eq_ignore_ascii_case(jm) {
            return Err(format!("journal_mode={jm} not in effect (got {got})"));
        }
        c.execute_batch(&format!(
            "PRAGMA synchronous={sy}; CREATE TABLE IF NOT EXISTS t0(k BLOB PRIMARY KEY, v BLOB); CREATE TABLE IF NOT EXISTS t1(k BLOB PRIMARY KEY, v BLOB);"
        ))
        .map_err(|e| e.to_string())?;
        if !recheck {
            return Ok(S(c)); // MUTATION (--no-mode-recheck): trust the first PRAGMA answer
        }
        // Re-read after the first write: on a fresh file the WAL conversion happens lazily, and an I/O error there
        // makes SQLite fall back to the rollback journal while the earlier PRAGMA already reported "wal".
        let now: String = c.query_row("PRAGMA journal_mode", [], |r| r.get(0)).map_err(|e| e.to_string())?;
        if !now.eq_ignore_ascii_case(jm) {
            return Err(format!("journal_mode={jm} not in effect after schema write (got {now})"));
        }
        let want_sync: i64 = match sy { "NORMAL" => 1, "FULL" => 2, _ => 3 };
        let got_sync: i64 = c.query_row("PRAGMA synchronous", [], |r| r.get(0)).map_err(|e| e.to_string())?;
        if got_sync != want_sync {
            return Err(format!("synchronous={sy} not in effect (got {got_sync})"));
        }
        Ok(S(c))
    }
    impl Store for S {
        fn commit(&mut self, puts: &Puts) -> Result<(), String> {
            let tx = self.0.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|e| e.to_string())?;
            for (t, k, v) in puts {
                tx.execute(&format!("INSERT OR REPLACE INTO t{t}(k,v) VALUES(?1,?2)"), params![k, v]).map_err(|e| e.to_string())?;
            }
            tx.commit().map_err(|e| e.to_string())
        }
        fn dump(&mut self) -> Result<Dump, String> {
            let mut d = Dump::new();
            for t in 0..2u8 {
                let mut st = self.0.prepare(&format!("SELECT k,v FROM t{t}")).map_err(|e| e.to_string())?;
                let rows = st.query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))).map_err(|e| e.to_string())?;
                for x in rows {
                    let (k, v) = x.map_err(|e| e.to_string())?;
                    d.insert((t, k), v);
                }
            }
            Ok(d)
        }
        fn integrity(&mut self) -> Result<String, String> {
            let r: String = self.0.query_row("PRAGMA integrity_check", [], |r| r.get(0)).map_err(|e| e.to_string())?;
            if r == "ok" { Ok(format!("sqlite={} integrity_check=ok", rusqlite::version())) } else { Err(r) }
        }
    }
}

mod redb_s {
    use super::*;
    use redb::*;
    const T: [TableDefinition<&[u8], &[u8]>; 2] = [TableDefinition::new("A"), TableDefinition::new("B")];
    pub struct S(Database, String);
    pub fn open(dir: &Path, cfg: &str) -> Result<S, String> {
        if !matches!(cfg, "2pc" | "imm" | "none") {
            return Err(format!("unknown redb cfg {cfg}"));
        }
        let db = Database::create(dir.join("db.redb")).map_err(|e| format!("{e:?}"))?;
        Ok(S(db, cfg.into()))
    }
    impl Store for S {
        fn commit(&mut self, puts: &Puts) -> Result<(), String> {
            let mut w = self.0.begin_write().map_err(|e| e.to_string())?;
            match self.1.as_str() {
                "2pc" => w.set_two_phase_commit(true),
                "none" => w.set_durability(Durability::None).map_err(|e| e.to_string())?,
                _ => {}
            }
            for (t, k, v) in puts {
                let mut tb = w.open_table(T[*t as usize]).map_err(|e| e.to_string())?;
                tb.insert(&k[..], &v[..]).map_err(|e| e.to_string())?;
            }
            w.commit().map_err(|e| e.to_string())
        }
        fn dump(&mut self) -> Result<Dump, String> {
            let r = self.0.begin_read().map_err(|e| e.to_string())?;
            let mut d = Dump::new();
            for (n, td) in T.iter().enumerate() {
                match r.open_table(*td) {
                    Ok(t) => {
                        for x in t.iter().map_err(|e| e.to_string())? {
                            let (k, v) = x.map_err(|e| e.to_string())?;
                            d.insert((n as u8, k.value().to_vec()), v.value().to_vec());
                        }
                    }
                    Err(TableError::TableDoesNotExist(_)) => {}
                    Err(e) => return Err(e.to_string()),
                }
            }
            Ok(d)
        }
        // check_integrity() may repair; Ok(false) (repair was needed) is reported as an integrity failure.
        fn integrity(&mut self) -> Result<String, String> {
            match self.0.check_integrity() {
                Ok(true) => Ok("redb check_integrity=true".into()),
                Ok(false) => Err("redb check_integrity=false (repaired)".into()),
                Err(e) => Err(e.to_string()),
            }
        }
    }
}

// Own append-only log (the shape the future monban-state WAL is expected to take). record = len u32 | crc32 | payload.
mod wal_s {
    use super::*;
    use std::fs::*;
    use std::io::*;
    pub struct S(File, bool, PathBuf, bool);
    fn crc(b: &[u8]) -> u32 {
        let mut c = 0xFFFF_FFFFu32;
        for &x in b {
            c ^= x as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
            }
        }
        !c
    }
    pub fn open(dir: &Path, cfg: &str) -> std::result::Result<S, String> {
        if !matches!(cfg, "crc" | "naive") {
            return Err(format!("unknown wal cfg {cfg}"));
        }
        let p = dir.join("wal.log");
        let f = OpenOptions::new().create(true).append(true).read(true).open(&p).map_err(|e| e.to_string())?;
        Ok(S(f, cfg == "crc", p, false))
    }
    impl Store for S {
        fn commit(&mut self, puts: &Puts) -> std::result::Result<(), String> {
            if self.3 {
                return Err("store poisoned by an earlier I/O error (fail-stop)".into());
            }
            let mut pl = Vec::new();
            for (t, k, v) in puts {
                pl.push(*t);
                pl.extend((k.len() as u32).to_be_bytes());
                pl.extend(k);
                pl.extend((v.len() as u32).to_be_bytes());
                pl.extend(v);
            }
            let mut rec = Vec::new();
            rec.extend((pl.len() as u32).to_be_bytes());
            rec.extend(crc(&pl).to_be_bytes());
            rec.extend(&pl);
            if let Err(e) = self.0.write_all(&rec) {
                self.3 = true;
                return Err(e.to_string());
            }
            if self.1 {
                if let Err(e) = self.0.sync_data() {
                    // fsyncgate: never retry-and-ack; poison the store.
                    self.3 = true;
                    return Err(format!("fdatasync: {e}"));
                }
            }
            Ok(())
        }
        fn dump(&mut self) -> std::result::Result<Dump, String> {
            let mut b = Vec::new();
            File::open(&self.2).map_err(|e| e.to_string())?.read_to_end(&mut b).map_err(|e| e.to_string())?;
            let mut d = Dump::new();
            let mut p = 0;
            while p + 8 <= b.len() {
                let l = u32::from_be_bytes(b[p..p + 4].try_into().unwrap()) as usize;
                let c = u32::from_be_bytes(b[p + 4..p + 8].try_into().unwrap());
                if p + 8 + l > b.len() {
                    break;
                }
                let pl = &b[p + 8..p + 8 + l];
                if self.1 && crc(pl) != c {
                    break; // torn tail / corrupt record: recovery stops here
                }
                let mut q = 0;
                let mut recs = Vec::new();
                let ok = (|| -> Option<()> {
                    while q < pl.len() {
                        let t = *pl.get(q)?;
                        let kl = u32::from_be_bytes(pl.get(q + 1..q + 5)?.try_into().ok()?) as usize;
                        let k = pl.get(q + 5..q + 5 + kl)?.to_vec();
                        q += 5 + kl;
                        let vl = u32::from_be_bytes(pl.get(q..q + 4)?.try_into().ok()?) as usize;
                        let v = pl.get(q + 4..q + 4 + vl)?.to_vec();
                        q += 4 + vl;
                        recs.push((t, k, v));
                    }
                    Some(())
                })();
                if ok.is_none() {
                    return Err(format!("malformed record at offset {p}"));
                }
                for (t, k, v) in recs {
                    d.insert((t, k), v);
                }
                p += 8 + l;
            }
            Ok(d)
        }
        fn integrity(&mut self) -> std::result::Result<String, String> {
            Ok("wal n/a".into())
        }
    }
}

fn open(store: &str, cfg: &str, dir: &Path, recheck: bool) -> Result<Box<dyn Store>, String> {
    Ok(match store {
        "sqlite" => Box::new(sqlite_s::open(dir, cfg, recheck)?),
        "redb" => Box::new(redb_s::open(dir, cfg)?),
        "wal" => Box::new(wal_s::open(dir, cfg)?),
        _ => return Err(format!("unknown store {store}")),
    })
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>, dirs: &mut Vec<PathBuf>) -> std::io::Result<()> {
    dirs.push(dir.to_path_buf());
    let mut ents: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    ents.sort_by_key(|e| e.file_name());
    for e in ents {
        let ft = e.file_type()?;
        if ft.is_dir() {
            walk(&e.path(), files, dirs)?;
        } else if ft.is_file() {
            files.push(e.path());
        }
    }
    Ok(())
}

/// INV-DURABLE bootstrap: fsync file contents, then the directory entries, before serving.
fn bootstrap(dir: &Path, dirsync: bool) -> Result<(), String> {
    let (mut files, mut dirs) = (Vec::new(), Vec::new());
    walk(dir, &mut files, &mut dirs).map_err(|e| format!("walk: {e}"))?;
    for f in &files {
        std::fs::OpenOptions::new().read(true).open(f).and_then(|h| h.sync_all()).map_err(|e| format!("fsync {}: {e}", f.display()))?;
    }
    if dirsync {
        for d in dirs.iter().rev() {
            std::fs::File::open(d).and_then(|h| h.sync_all()).map_err(|e| format!("fsync dir {}: {e}", d.display()))?;
        }
    }
    Ok(())
}

/// Protocol replies go out as ONE write(2) each (the tracing shim turns "OK <i>" / "BEGUN <i>" into ack markers).
fn reply(line: &str) {
    use std::os::fd::FromRawFd;
    let mut f = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(1) });
    let mut b = line.as_bytes().to_vec();
    b.push(b'\n');
    if f.write_all(&b).is_err() {
        std::process::exit(4);
    }
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}
fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 || a[1] != "serve" {
        eprintln!("usage: refstore serve <store> <cfg> <dir> [--no-dirsync] [--ack-early] [--no-mode-recheck]");
        std::process::exit(2);
    }
    let (store, cfg, dir) = (&a[2], &a[3], Path::new(&a[4]));
    let dirsync = !a[5..].iter().any(|x| x == "--no-dirsync");
    let ack_early = a[5..].iter().any(|x| x == "--ack-early");
    let recheck = !a[5..].iter().any(|x| x == "--no-mode-recheck");
    let mut s = match open(store, cfg, dir, recheck).and_then(|s| bootstrap(dir, dirsync).map(|_| s)) {
        Ok(s) => s,
        Err(e) => {
            reply(&format!("ERR open {}", e.replace('\n', " ")));
            std::process::exit(3);
        }
    };
    // no-mode-recheck only means something for SQLite (the only store with a journal mode to fall back from)
    let muts = if store == "sqlite" { "ack-early,no-dirsync,no-mode-recheck" } else { "ack-early,no-dirsync" };
    reply(&format!("READY refstore {store}/{cfg} sqlite={} mutations={muts}", rusqlite::version()));
    let mut puts: Puts = Vec::new();
    let mut poisoned = false;
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let mut it = line.split(' ');
        match it.next().unwrap_or("") {
            "BEGIN" => {
                puts.clear();
                reply(&format!("BEGUN {}", it.next().unwrap_or("0")));
            }
            "PUT" => {
                let t: Option<u8> = it.next().and_then(|x| x.parse().ok()).filter(|t| *t < 2);
                let k = it.next().and_then(unhex);
                let v = it.next().and_then(unhex);
                match (t, k, v) {
                    (Some(t), Some(k), Some(v)) => puts.push((t, k, v)),
                    _ => {
                        reply("ERR proto bad PUT");
                        std::process::exit(2);
                    }
                }
            }
            "COMMIT" => {
                let i = it.next().unwrap_or("0").to_string();
                if poisoned {
                    reply(&format!("ERR {i} poisoned"));
                    continue;
                }
                if ack_early {
                    reply(&format!("OK {i}")); // MUTATION: ack before the commit's fsync
                }
                match s.commit(&puts) {
                    Ok(()) if ack_early => {}
                    Ok(()) => reply(&format!("OK {i}")),
                    Err(e) => {
                        poisoned = true; // fail-stop after any commit error (fsyncgate: never retry-and-ack)
                        reply(&format!("ERR {i} {}", e.replace('\n', " ")));
                    }
                }
                puts.clear();
            }
            "DUMP" => match s.dump() {
                Ok(d) => {
                    let mut out = String::new();
                    for ((t, k), v) in d {
                        out.push_str(&format!("KV {t} {} {}\n", hex(&k), hex(&v)));
                    }
                    out.push_str("END");
                    reply(&out);
                }
                Err(e) => reply(&format!("ERR dump {}", e.replace('\n', " "))),
            },
            "CHECK" => match s.integrity() {
                Ok(m) => reply(&format!("INTEGRITY ok {m}")),
                Err(e) => reply(&format!("INTEGRITY fail {}", e.replace('\n', " "))),
            },
            "QUIT" => break,
            other => {
                reply(&format!("ERR proto unknown command {other}"));
                std::process::exit(2);
            }
        }
    }
    drop(s);
}
