// AEGIS crash-consistency workload + oracle. Modes: run <store> <cfg> <dir> <n> | verify <store> <cfg> <dir> <acked>
use std::collections::BTreeMap;
use std::path::Path;
type Dump = BTreeMap<(u8, Vec<u8>), Vec<u8>>;

fn val(i: u64) -> Vec<u8> {
    let len = 64 + ((i % 7) as usize) * 300;
    let mut s = i.wrapping_mul(0x9E3779B97F4A7C15) | 1;
    let mut v = Vec::with_capacity(len + 12);
    v.extend_from_slice(&i.to_be_bytes());
    v.extend_from_slice(&(len as u32).to_be_bytes());
    for _ in 0..len { s ^= s << 13; s ^= s >> 7; s ^= s << 17; v.push((s >> 24) as u8); }
    v
}
// the txn: table0 {ctr, a{i%50}, g{i}}, table1 {ctr, b{i%50}}
fn ops(i: u64) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
    vec![
        (0, b"ctr".to_vec(), i.to_be_bytes().to_vec()),
        (0, format!("a{:03}", i % 50).into_bytes(), val(i)),
        (0, format!("g{:08}", i).into_bytes(), val(i)),
        (1, b"ctr".to_vec(), i.to_be_bytes().to_vec()),
        (1, format!("b{:03}", i % 50).into_bytes(), val(i + 1000)),
    ]
}
fn expected(c: u64) -> Dump {
    let mut d = Dump::new();
    for i in 1..=c { for (t, k, v) in ops(i) { d.insert((t, k), v); } }
    d
}
trait Store { fn txn(&mut self, i: u64) -> Result<(), String>; fn dump(&mut self) -> Result<Dump, String>; fn integrity(&mut self) -> Result<String, String> { Ok("n/a".into()) } }

mod redb_s {
    use super::*; use redb::*;
    const T: [TableDefinition<&[u8], &[u8]>; 2] = [TableDefinition::new("A"), TableDefinition::new("B")];
    pub struct S(pub Database, pub String);
    pub fn open(dir: &Path, cfg: &str) -> Result<S, String> {
        let db = Database::create(dir.join("db.redb")).map_err(|e| format!("{e:?}"))?; Ok(S(db, cfg.into()))
    }
    impl Store for S {
        fn txn(&mut self, i: u64) -> Result<(), String> {
            let mut w = self.0.begin_write().map_err(|e| e.to_string())?;
            match self.1.as_str() { "imm2pc" => w.set_two_phase_commit(true), "none" => { w.set_durability(Durability::None).map_err(|e| e.to_string())?; } _ => {} }
            for (t, k, v) in ops(i) { let mut tb = w.open_table(T[t as usize]).map_err(|e| e.to_string())?; tb.insert(&k[..], &v[..]).map_err(|e| e.to_string())?; }
            w.commit().map_err(|e| e.to_string())
        }
        fn dump(&mut self) -> Result<Dump, String> {
            let r = self.0.begin_read().map_err(|e| e.to_string())?; let mut d = Dump::new();
            for (n, td) in T.iter().enumerate() { match r.open_table(*td) { Ok(t) => { for x in t.iter().map_err(|e| e.to_string())? { let (k, v) = x.map_err(|e| e.to_string())?; d.insert((n as u8, k.value().to_vec()), v.value().to_vec()); } } Err(TableError::TableDoesNotExist(_)) => {} Err(e) => return Err(e.to_string()) } }
            Ok(d)
        }
        fn integrity(&mut self) -> Result<String, String> { let ok = self.0.check_integrity().map_err(|e| e.to_string())?; Ok(format!("check_integrity={ok}")) }
    }
}
mod fjall_s {
    use super::*; use fjall::*;
    pub struct S(Database, Keyspace, Keyspace, String);
    pub fn open(dir: &Path, cfg: &str) -> std::result::Result<S, String> {
        let db = Database::builder(dir.join("fj")).manual_journal_persist(false).open().map_err(|e| e.to_string())?;
        let o = || KeyspaceCreateOptions::default().max_memtable_size(64 * 1024);
        let a = db.keyspace("a", o).map_err(|e| e.to_string())?; let b = db.keyspace("b", o).map_err(|e| e.to_string())?;
        Ok(S(db, a, b, cfg.into()))
    }
    impl Store for S {
        fn txn(&mut self, i: u64) -> std::result::Result<(), String> {
            let mut b = self.0.batch();
            let m = match self.3.as_str() { "syncall" => Some(PersistMode::SyncAll), "syncdata" => Some(PersistMode::SyncData), _ => None };
            b = b.durability(m);
            for (t, k, v) in ops(i) { b.insert(if t == 0 { &self.1 } else { &self.2 }, k, v); }
            b.commit().map_err(|e| e.to_string())
        }
        fn dump(&mut self) -> std::result::Result<Dump, String> {
            let mut d = Dump::new();
            for (n, ks) in [&self.1, &self.2].iter().enumerate() { for g in ks.iter() { let (k, v) = g.into_inner().map_err(|e| e.to_string())?; d.insert((n as u8, k.to_vec()), v.to_vec()); } }
            Ok(d)
        }
    }
}
mod heed_s {
    use super::*; use heed::*; use heed::types::Bytes;
    type Db = heed::Database<'static, Bytes, Bytes>;
    pub struct S(Env, Db, Db);
    pub fn open(dir: &Path, cfg: &str) -> std::result::Result<S, String> {
        std::fs::create_dir_all(dir.join("lm")).map_err(|e| e.to_string())?;
        let mut o = EnvOpenOptions::new(); o.map_size(64 << 20).max_dbs(4);
        unsafe { match cfg { "nometasync" => { o.flags(EnvFlags::NO_META_SYNC); } "nosync" => { o.flags(EnvFlags::NO_SYNC); } _ => {} } }
        let env = unsafe { o.open(dir.join("lm")) }.map_err(|e| e.to_string())?;
        let w = env.write_txn().map_err(|e| e.to_string())?;
        let (a, b) = env.create_databases_and_commit(w, |wdo, w| -> std::result::Result<_, heed::Error> {
            let a = wdo.create_database::<Bytes, Bytes>(w, Some("a"))?; let b = wdo.create_database::<Bytes, Bytes>(w, Some("b"))?;
            Ok(CommitOrAbort::<_, ()>::Commit((a, b))) }).map_err(|e| e.to_string())?.unwrap_commit();
        Ok(S(env, a, b))
    }
    impl Store for S {
        fn txn(&mut self, i: u64) -> std::result::Result<(), String> {
            let mut w = self.0.write_txn().map_err(|e| e.to_string())?;
            for (t, k, v) in ops(i) { (if t == 0 { &self.1 } else { &self.2 }).put(&mut w, &k, &v).map_err(|e| e.to_string())?; }
            w.commit().map_err(|e| e.to_string())
        }
        fn dump(&mut self) -> std::result::Result<Dump, String> {
            let r = self.0.read_txn().map_err(|e| e.to_string())?; let mut d = Dump::new();
            for (n, db) in [&self.1, &self.2].iter().enumerate() { for x in db.iter(&r).map_err(|e| e.to_string())? { let (k, v) = x.map_err(|e| e.to_string())?; d.insert((n as u8, k.to_vec()), v.to_vec()); } }
            Ok(d)
        }
    }
}
mod sqlite_s {
    use super::*; use rusqlite::*;
    pub struct S(Connection);
    pub fn open(dir: &Path, cfg: &str) -> Result<S, String> {
        let c = Connection::open(dir.join("s.db")).map_err(|e| e.to_string())?;
        let (jm, sy) = match cfg { "wal-full" => ("WAL", "FULL"), "wal-normal" => ("WAL", "NORMAL"), "del-full" => ("DELETE", "FULL"), "del-normal" => ("DELETE", "NORMAL"), "del-extra" => ("DELETE", "EXTRA"), "wal-extra" => ("WAL", "EXTRA"), "trunc-full" => ("TRUNCATE", "FULL"), _ => return Err("cfg".into()) };
        let _: String = c.query_row(&format!("PRAGMA journal_mode={jm}"), [], |r| r.get(0)).map_err(|e| e.to_string())?;
        c.execute_batch(&format!("PRAGMA synchronous={sy}; CREATE TABLE IF NOT EXISTS t0(k BLOB PRIMARY KEY, v BLOB); CREATE TABLE IF NOT EXISTS t1(k BLOB PRIMARY KEY, v BLOB);")).map_err(|e| e.to_string())?;
        Ok(S(c))
    }
    impl Store for S {
        fn txn(&mut self, i: u64) -> Result<(), String> {
            let tx = self.0.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|e| e.to_string())?;
            for (t, k, v) in ops(i) { tx.execute(&format!("INSERT OR REPLACE INTO t{t}(k,v) VALUES(?1,?2)"), params![k, v]).map_err(|e| e.to_string())?; }
            tx.commit().map_err(|e| e.to_string())
        }
        fn dump(&mut self) -> Result<Dump, String> {
            let mut d = Dump::new();
            for t in 0..2u8 { let mut st = self.0.prepare(&format!("SELECT k,v FROM t{t}")).map_err(|e| e.to_string())?; let rows = st.query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))).map_err(|e| e.to_string())?; for x in rows { let (k, v) = x.map_err(|e| e.to_string())?; d.insert((t, k), v); } }
            Ok(d)
        }
        fn integrity(&mut self) -> Result<String, String> { let r: String = self.0.query_row("PRAGMA integrity_check", [], |r| r.get(0)).map_err(|e| e.to_string())?; if r == "ok" { Ok(r) } else { Err(r) } }
    }
}
mod canopy_s {
    use super::*; use canopydb::*;
    pub struct S(Database, String);
    pub fn open(dir: &Path, cfg: &str) -> std::result::Result<S, String> { std::fs::create_dir_all(dir.join("cn")).map_err(|e| e.to_string())?; Ok(S(Database::new(dir.join("cn")).map_err(|e| e.to_string())?, cfg.to_string())) }
    impl Store for S {
        fn txn(&mut self, i: u64) -> std::result::Result<(), String> {
            let w = self.0.begin_write().map_err(|e| e.to_string())?;
            { let mut t = [w.get_or_create_tree(b"A").map_err(|e| e.to_string())?, w.get_or_create_tree(b"B").map_err(|e| e.to_string())?];
              for (n, k, v) in ops(i) { t[n as usize].insert(&k, &v).map_err(|e| e.to_string())?; } }
            match self.1.as_str() { "sync" => w.commit_with(true), "async" => w.commit_with(false), _ => w.commit() }.map_err(|e| e.to_string())?; Ok(())
        }
        fn dump(&mut self) -> std::result::Result<Dump, String> {
            let r = self.0.begin_read().map_err(|e| e.to_string())?; let mut d = Dump::new();
            for (n, nm) in [&b"A"[..], &b"B"[..]].iter().enumerate() { if let Some(t) = r.get_tree(nm).map_err(|e| e.to_string())? { for x in t.iter().map_err(|e| e.to_string())? { let (k, v) = x.map_err(|e| e.to_string())?; d.insert((n as u8, k.to_vec()), v.to_vec()); } } }
            Ok(d)
        }
    }
}
// control stores: own append-only log. "naive": write, no fsync. "walcrc": record = len|crc|payload, fdatasync, parent-dir fsync at creation.
mod wal_s {
    use super::*; use std::fs::*; use std::io::*;
    pub struct S(File, bool, String, std::path::PathBuf);
    fn crc(b: &[u8]) -> u32 { let mut c = 0xFFFFFFFFu32; for &x in b { c ^= x as u32; for _ in 0..8 { c = if c & 1 != 0 { (c >> 1) ^ 0xEDB88320 } else { c >> 1 }; } } !c }
    pub fn open(dir: &Path, cfg: &str) -> std::result::Result<S, String> {
        let p = dir.join("wal.log"); let existed = p.exists();
        let f = OpenOptions::new().create(true).append(true).read(true).open(&p).map_err(|e| e.to_string())?;
        if !existed && cfg == "walcrc" { f.sync_all().map_err(|e| e.to_string())?; File::open(dir).map_err(|e| e.to_string())?.sync_all().map_err(|e| e.to_string())?; }
        Ok(S(f, cfg == "walcrc", cfg.into(), p))
    }
    impl Store for S {
        fn txn(&mut self, i: u64) -> std::result::Result<(), String> {
            let mut pl = Vec::new(); for (t, k, v) in ops(i) { pl.push(t); pl.extend((k.len() as u32).to_be_bytes()); pl.extend(&k); pl.extend((v.len() as u32).to_be_bytes()); pl.extend(&v); }
            let mut rec = Vec::new(); rec.extend((pl.len() as u32).to_be_bytes()); rec.extend(crc(&pl).to_be_bytes()); rec.extend(&pl);
            self.0.write_all(&rec).map_err(|e| e.to_string())?; if self.1 { self.0.sync_data().map_err(|e| e.to_string())?; } Ok(())
        }
        fn dump(&mut self) -> std::result::Result<Dump, String> {
            let mut b = Vec::new(); File::open(&self.3).map_err(|e| e.to_string())?.read_to_end(&mut b).map_err(|e| e.to_string())?;
            let mut d = Dump::new(); let mut p = 0;
            while p + 8 <= b.len() { let l = u32::from_be_bytes(b[p..p + 4].try_into().unwrap()) as usize; let c = u32::from_be_bytes(b[p + 4..p + 8].try_into().unwrap());
                if p + 8 + l > b.len() { break; } let pl = &b[p + 8..p + 8 + l];
                if self.2 == "walcrc" && crc(pl) != c { break; } // torn tail / corrupt: stop (recovery rule)
                let mut q = 0; while q < pl.len() { let t = pl[q]; let kl = u32::from_be_bytes(pl[q + 1..q + 5].try_into().unwrap()) as usize; let k = pl[q + 5..q + 5 + kl].to_vec(); q += 5 + kl; let vl = u32::from_be_bytes(pl[q..q + 4].try_into().unwrap()) as usize; let v = pl[q + 4..q + 4 + vl].to_vec(); q += 4 + vl; d.insert((t, k), v); }
                p += 8 + l; }
            Ok(d)
        }
    }
}
fn open(store: &str, cfg: &str, dir: &Path) -> Result<Box<dyn Store>, String> {
    Ok(match store {
        "redb" => Box::new(redb_s::open(dir, cfg)?), "fjall" => Box::new(fjall_s::open(dir, cfg)?), "heed" => Box::new(heed_s::open(dir, cfg)?),
        "sqlite" => Box::new(sqlite_s::open(dir, cfg)?), "canopydb" => Box::new(canopy_s::open(dir, cfg)?), "wal" => Box::new(wal_s::open(dir, cfg)?),
        _ => return Err("unknown store".into()) })
}
fn mark(i: u64) { unsafe { let f = libc::dlsym(libc::RTLD_DEFAULT, c"aegis_mark".as_ptr()); if !f.is_null() { let f: extern "C" fn(i64) = std::mem::transmute(f); f(i as i64); } } }
fn main() {
    let a: Vec<String> = std::env::args().collect(); let (mode, store, cfg, dir) = (&a[1], &a[2], &a[3], Path::new(&a[4]));
    if mode == "run" {
        let n: u64 = a[5].parse().unwrap(); let mut s = open(store, cfg, dir).expect("open");
        for i in 1..=n { s.txn(i).expect("txn"); mark(i); }
        std::process::exit(0);
    } else {
        let acked: u64 = a[5].parse().unwrap();
        let mut s = match open(store, cfg, dir) { Ok(s) => s, Err(e) => { println!("RESULT open_fail {}", e.replace('\n', " ")); return; } };
        let d = match s.dump() { Ok(d) => d, Err(e) => { println!("RESULT read_fail {}", e.replace('\n', " ")); return; } };
        let c = d.get(&(0, b"ctr".to_vec())).map(|v| u64::from_be_bytes(v[..8].try_into().unwrap())).unwrap_or(0);
        let c1 = d.get(&(1, b"ctr".to_vec())).map(|v| u64::from_be_bytes(v[..8].try_into().unwrap())).unwrap_or(0);
        let integ = s.integrity();
        let cls = if c > 100000 { "corrupt_ctr".to_string() } else if c != c1 { format!("atomicity ctrA={c} ctrB={c1}") } else if d != expected(c) { format!("state_mismatch c={c}") } else if c < acked { format!("lost_ack c={c} acked={acked}") } else { "ok".into() };
        let ic = match integ { Ok(s) => s, Err(e) => format!("INTEGRITY_FAIL {}", e.replace('\n', " ")) };
        println!("RESULT {} | c={} acked={} | {}", cls, c, acked, ic);
    }
}
