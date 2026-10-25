//! Admin audit trail: F9 events into an aegis-audit [`Log`] (tlog-tiles, signed checkpoints) over a simple file
//! sink. Admin events are fail-closed (Audit I7): [`Auditor::admin`] returns `Err` and the caller must not apply
//! the audited action (boot refuses to serve, a reload keeps the old config).
//!
//! Each process writes its own log directory `<audit-dir>/<unix-ms>-<pid>/` with a fresh Ed25519 checkpoint key
//! (its verifier key is written to `vkey`): resuming one log across restarts with a persistent key is aegis-state's
//! job (later unit). The production sink belongs to aegis-state too; this one writes each resource to a temp file,
//! fsyncs and renames it, refuses to change an existing resource, and fsyncs the touched directories in `sync`.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aegis_audit::{
    Action, Actor, AuditEvent, AuditSink, Detail, DetailKey, DetailValue, Ed25519NoteSigner, EventClass, FailurePolicy,
    FipsStatus, Log, LogConfig, Outcome, SinkError, TilePath, Untrusted,
};

#[derive(Debug)]
pub struct FileSink {
    root: PathBuf,
    dirty: BTreeSet<PathBuf>,
    tmp: u64,
}

fn io(e: io::Error) -> SinkError {
    SinkError::Io(e.to_string())
}

impl FileSink {
    pub fn new(root: &Path) -> io::Result<Self> {
        fs::create_dir_all(root)?;
        let mut s = Self { root: root.to_path_buf(), dirty: BTreeSet::new(), tmp: 0 };
        if let Some(p) = root.parent() {
            s.dirty.insert(p.to_path_buf());
        }
        Ok(s)
    }

    fn write_atomic(&mut self, path: &Path, data: &[u8]) -> io::Result<()> {
        let dir = path.parent().ok_or_else(|| io::Error::other("no parent"))?.to_path_buf();
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
            let mut d = dir.clone();
            while d.starts_with(&self.root) && d != self.root {
                self.dirty.insert(d.clone());
                if !d.pop() {
                    break;
                }
            }
            self.dirty.insert(self.root.clone());
        }
        self.tmp = self.tmp.saturating_add(1);
        let tmp = dir.join(format!(".tmp-{}", self.tmp));
        {
            let mut f = File::create(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)?;
        self.dirty.insert(dir);
        Ok(())
    }

    fn put(&mut self, rel: &str, data: &[u8]) -> Result<(), SinkError> {
        let path = self.root.join(rel);
        match fs::read(&path) {
            Ok(old) if old == data => Ok(()),
            Ok(_) => Err(SinkError::Conflict(rel.to_string())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => self.write_atomic(&path, data).map_err(io),
            Err(e) => Err(io(e)),
        }
    }
}

impl AuditSink for FileSink {
    fn write_tile(&mut self, tile: &TilePath, data: &[u8]) -> Result<(), SinkError> {
        self.put(&tile.to_path(), data)
    }
    fn write_entries(&mut self, bundle: &TilePath, data: &[u8]) -> Result<(), SinkError> {
        self.put(&bundle.to_path(), data)
    }
    fn sync(&mut self) -> Result<(), SinkError> {
        for d in std::mem::take(&mut self.dirty) {
            File::open(&d).and_then(|f| f.sync_all()).map_err(io)?;
        }
        Ok(())
    }
    fn publish_checkpoint(&mut self, _size: u64, note: &[u8]) -> Result<(), SinkError> {
        let p = self.root.join("checkpoint");
        self.write_atomic(&p, note).map_err(io)?;
        self.sync()
    }
}

#[derive(Debug)]
pub struct Auditor {
    log: Mutex<Log<FileSink>>,
    fips: FipsStatus,
    pub dir: PathBuf,
    seq: std::sync::atomic::AtomicU64,
}

impl Auditor {
    /// Default directory: `$STATE_DIRECTORY/audit` (systemd `StateDirectory=`).
    pub fn default_dir() -> Option<PathBuf> {
        std::env::var_os("STATE_DIRECTORY")
            .map(|s| PathBuf::from(s.to_string_lossy().split(':').next().unwrap_or_default().to_string()).join("audit"))
    }

    pub fn open(base: &Path, fips: &aegis_tls::FipsStatus) -> Result<Self, String> {
        let dir = base.join(format!("{}-{}", crate::util::unix_ms(), std::process::id()));
        let sink = FileSink::new(&dir).map_err(|e| format!("audit dir {}: {e}", dir.display()))?;
        let name = "aegis.audit";
        let signer = Ed25519NoteSigner::generate(name).map_err(|e| format!("audit key: {e}"))?;
        let cfg = LogConfig {
            origin: name.to_string(),
            max_pending: 1024,
            require_cosigner: false,
            policy: FailurePolicy::default(),
        };
        let log = Log::new(cfg, Box::new(signer), Vec::new(), sink).map_err(|e| format!("audit log: {e:?}"))?;
        let vkeys = log.vkeys().join("\n");
        fs::write(dir.join("vkey"), format!("{vkeys}\n")).map_err(|e| format!("audit vkey: {e}"))?;
        let fips = if fips.cmvp_claim {
            FipsStatus::Cmvp
        } else if fips.config_fips {
            FipsStatus::Floor
        } else {
            FipsStatus::None
        };
        Ok(Self { log: Mutex::new(log), fips, dir, seq: std::sync::atomic::AtomicU64::new(1) })
    }

    fn req_id(&self) -> [u8; 16] {
        let mut id = [0u8; 16];
        let n = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (a, b) = id.split_at_mut(8);
        a.copy_from_slice(&crate::util::unix_ms().to_be_bytes());
        b.copy_from_slice(&(u64::from(std::process::id()) << 32 | (n & 0xFFFF_FFFF)).to_be_bytes());
        id
    }

    /// Append one admin event durably (sequenced, synced, checkpoint published). `Err` ⇒ do not apply.
    pub fn admin(
        &self,
        action: &str,
        object: &str,
        outcome: Outcome,
        config_hash: [u8; 32],
        detail: &[(&str, DetailValue)],
    ) -> Result<u64, String> {
        let mut d = Detail::new();
        for (k, v) in detail {
            d.insert(DetailKey::new(k).map_err(|e| e.to_string())?, v.clone()).map_err(|e| e.to_string())?;
        }
        let ev = AuditEvent {
            class: EventClass::Admin,
            actor: Actor::system(),
            action: Action::new(action).map_err(|e| e.to_string())?,
            object: Untrusted::object(object.as_bytes()),
            outcome,
            req_id: self.req_id(),
            config_hash,
            fips_status: self.fips,
            detail: d,
        };
        let mut log = self.log.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        log.append_durable(&ev, crate::util::unix_ms()).map(|(seq, _)| seq).map_err(|e| format!("audit: {e:?}"))
    }
}

pub fn text(s: &str) -> DetailValue {
    DetailValue::text(s.as_bytes())
}
