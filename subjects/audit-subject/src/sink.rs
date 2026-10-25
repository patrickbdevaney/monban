//! File-backed `AuditSink` (subject only; the production sink belongs to aegis-state).
//!
//! Every resource is written to a temp file, fsynced, and renamed into place; an existing resource must have
//! identical bytes (full and partial tiles are both determined by the tree, so any difference is a fork and is
//! refused). `sync` fsyncs every directory touched since the last sync. The checkpoint is replaced atomically
//! and also kept as `history/<size>`.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use aegis_audit::{AuditSink, SinkError, TilePath};

#[derive(Debug)]
pub struct FileSink {
    root: PathBuf,
    dirty_dirs: BTreeSet<PathBuf>,
    tmp_counter: u64,
}

fn io(e: io::Error) -> SinkError {
    SinkError::Io(e.to_string())
}

impl FileSink {
    pub fn new(root: &Path) -> io::Result<Self> {
        fs::create_dir_all(root.join("history"))?;
        Ok(Self { root: root.to_path_buf(), dirty_dirs: BTreeSet::new(), tmp_counter: 0 })
    }

    fn mkdirs(&mut self, dir: &Path) -> io::Result<()> {
        let mut missing = Vec::new();
        let mut d = dir.to_path_buf();
        while !d.exists() {
            missing.push(d.clone());
            if !d.pop() {
                break;
            }
        }
        fs::create_dir_all(dir)?;
        for m in missing {
            if let Some(p) = m.parent() {
                self.dirty_dirs.insert(p.to_path_buf());
            }
            self.dirty_dirs.insert(m);
        }
        Ok(())
    }

    fn atomic_write(&mut self, path: &Path, data: &[u8]) -> io::Result<()> {
        let dir = path.parent().ok_or_else(|| io::Error::other("no parent"))?.to_path_buf();
        self.mkdirs(&dir)?;
        self.tmp_counter += 1;
        let tmp = dir.join(format!(".tmp-{}-{}", std::process::id(), self.tmp_counter));
        {
            let mut f = File::create(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)?;
        self.dirty_dirs.insert(dir);
        Ok(())
    }

    fn put(&mut self, rel: &str, data: &[u8]) -> Result<(), SinkError> {
        let path = self.root.join(rel);
        match fs::read(&path) {
            Ok(old) if old == data => return Ok(()),
            Ok(_) => return Err(SinkError::Conflict(rel.to_string())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(io(e)),
        }
        self.atomic_write(&path, data).map_err(io)
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
        for d in std::mem::take(&mut self.dirty_dirs) {
            File::open(&d).and_then(|f| f.sync_all()).map_err(io)?;
        }
        Ok(())
    }
    fn publish_checkpoint(&mut self, size: u64, note: &[u8]) -> Result<(), SinkError> {
        self.put(&format!("history/{size}"), note).or_else(|e| match e {
            // ML-DSA signatures are randomized: a republish of the same size yields different bytes.
            SinkError::Conflict(_) => self.atomic_write(&self.root.join(format!("history/{size}")), note).map_err(io),
            other => Err(other),
        })?;
        let root = self.root.clone();
        self.atomic_write(&root.join("checkpoint"), note).map_err(io)?;
        self.sync()
    }
}
