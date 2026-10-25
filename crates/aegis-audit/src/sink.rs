//! Storage boundary. The log only ever calls, in this order per checkpoint: `write_tile` / `write_entries` for
//! every resource the new tree size adds, then `sync`, and only if `sync` returned `Ok`, `publish_checkpoint`
//! (Audit I4). aegis-state (L4) provides the production implementation.

use crate::tile::TilePath;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SinkError {
    /// I/O failure (message for operators; never contains event content).
    Io(String),
    /// A full tile or bundle already exists with different bytes (Audit I3 violation attempt).
    Conflict(String),
}

impl std::fmt::Display for SinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(m) => write!(f, "sink I/O error: {m}"),
            Self::Conflict(m) => write!(f, "sink conflict (immutable resource differs): {m}"),
        }
    }
}
impl std::error::Error for SinkError {}

pub trait AuditSink {
    /// Store a Merkle tile (`tile.width` × 32 bytes). Full tiles are immutable: an implementation MUST refuse to
    /// replace an existing full tile with different bytes (identical bytes, from a retry, are fine).
    fn write_tile(&mut self, tile: &TilePath, data: &[u8]) -> Result<(), SinkError>;
    /// Store an entry bundle (big-endian u16 length-prefixed leaves). Same immutability rule.
    fn write_entries(&mut self, bundle: &TilePath, data: &[u8]) -> Result<(), SinkError>;
    /// Make every resource written so far durable (fsync files and directories). `Ok` is the acknowledgement
    /// that licenses publishing a checkpoint covering them.
    fn sync(&mut self) -> Result<(), SinkError>;
    /// Atomically replace `<prefix>/checkpoint` with `note` (tree size `size`).
    fn publish_checkpoint(&mut self, size: u64, note: &[u8]) -> Result<(), SinkError>;
}
