//! Log-level tests against an in-memory recording sink (Audit I1–I4, I6, I7).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use crate::*;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Tile(String),
    Entries(String),
    Sync,
    Publish(u64),
}

#[derive(Debug, Default)]
struct MemSink {
    files: BTreeMap<String, Vec<u8>>,
    calls: Vec<Call>,
    checkpoint: Option<Vec<u8>>,
    fail_sync: bool,
    fail_publish: bool,
}

impl MemSink {
    fn put(&mut self, p: &TilePath, data: &[u8]) -> Result<(), SinkError> {
        let path = p.to_path();
        if p.is_full()
            && let Some(old) = self.files.get(&path)
            && old != data
        {
            return Err(SinkError::Conflict(path));
        }
        self.files.insert(path, data.to_vec());
        Ok(())
    }
}

impl AuditSink for MemSink {
    fn write_tile(&mut self, t: &TilePath, d: &[u8]) -> Result<(), SinkError> {
        self.calls.push(Call::Tile(t.to_path()));
        self.put(t, d)
    }
    fn write_entries(&mut self, b: &TilePath, d: &[u8]) -> Result<(), SinkError> {
        self.calls.push(Call::Entries(b.to_path()));
        self.put(b, d)
    }
    fn sync(&mut self) -> Result<(), SinkError> {
        if self.fail_sync {
            return Err(SinkError::Io("injected".into()));
        }
        self.calls.push(Call::Sync);
        Ok(())
    }
    fn publish_checkpoint(&mut self, size: u64, note: &[u8]) -> Result<(), SinkError> {
        if self.fail_publish {
            return Err(SinkError::Io("injected".into()));
        }
        self.calls.push(Call::Publish(size));
        self.checkpoint = Some(note.to_vec());
        Ok(())
    }
}

const ORIGIN: &str = "audit.test/log";

fn cfg() -> LogConfig {
    LogConfig {
        origin: ORIGIN.into(),
        max_pending: 1_000_000,
        require_cosigner: false,
        policy: FailurePolicy::default(),
    }
}

fn log_with(cfg: LogConfig, pq: bool) -> Log<MemSink> {
    let ed = Box::new(Ed25519NoteSigner::from_seed(ORIGIN, &[1; 32]).unwrap());
    let co: Vec<Box<dyn NoteSigner>> =
        if pq { vec![Box::new(MlDsa87NoteSigner::from_seed(ORIGIN, &[2; 32]).unwrap())] } else { vec![] };
    Log::new(cfg, ed, co, MemSink::default()).unwrap()
}

fn event(i: u64, class: EventClass) -> AuditEvent {
    let mut detail = Detail::new();
    detail.insert(DetailKey::new("i").unwrap(), DetailValue::Int(i as i64)).unwrap();
    AuditEvent {
        class,
        actor: Actor::system(),
        action: Action::new("test.event").unwrap(),
        object: Untrusted::object(format!("/obj/{i}").as_bytes()),
        outcome: Outcome::Allow,
        req_id: [3; 16],
        config_hash: [4; 32],
        fips_status: FipsStatus::None,
        detail,
    }
}

/// Rebuild the root of `size` from the stored tiles only (level-0 tile hashes → higher levels), as a verifier
/// would, and check entries hash to the level-0 tiles.
fn root_from_tiles(files: &BTreeMap<String, Vec<u8>>, size: u64) -> Hash {
    let mut leaves = Vec::new();
    let mut n = 0u64;
    while n * 256 < size {
        let w = (size - n * 256).min(256);
        let p = TilePath { kind: TileKind::Hash(0), index: n, width: w as u16 }.to_path();
        let e = TilePath { kind: TileKind::Entries, index: n, width: w as u16 }.to_path();
        let tile = files.get(&p).unwrap_or_else(|| panic!("missing {p}"));
        assert_eq!(tile.len() as u64, w * 32);
        let bundle = files.get(&e).unwrap_or_else(|| panic!("missing {e}"));
        let mut off = 0usize;
        for k in 0..w as usize {
            let len = u16::from_be_bytes([bundle[off], bundle[off + 1]]) as usize;
            let leaf = &bundle[off + 2..off + 2 + len];
            assert_eq!(&leaf_hash(leaf)[..], &tile[k * 32..k * 32 + 32]);
            let s = std::str::from_utf8(leaf).unwrap();
            assert!(s.contains(&format!("\"seq\":{},", n * 256 + k as u64)), "gapless seq");
            off += 2 + len;
        }
        assert_eq!(off, bundle.len());
        for c in tile.chunks(32) {
            leaves.push(<Hash>::try_from(c).unwrap());
        }
        n += 1;
    }
    let mut s = MerkleStore::new();
    for h in leaves {
        s.push_leaf(h);
    }
    s.root(size).unwrap()
}

#[test]
fn gapless_tiles_rebuild_root_and_checkpoints_consistent() {
    let mut log = log_with(cfg(), true);
    let vkeys: Vec<NoteVerifier> = log.vkeys().iter().map(|v| NoteVerifier::parse(v).unwrap()).collect();
    let mut cps: Vec<SignedCheckpoint> = Vec::new();
    for (i, stop) in [1u64, 255, 256, 257, 600, 65_536, 65_537, 70_000].iter().enumerate() {
        while log.size() < *stop {
            let n = log.size();
            assert_eq!(
                log.append(&event(n, EventClass::DataPlane), 1_700_000_000_000 + n).unwrap(),
                Appended::Sequenced(n)
            );
        }
        let cp = log.checkpoint().unwrap();
        assert_eq!(cp.checkpoint.size(), *stop);
        let (text, ids) = open_note(&cp.note, &vkeys).unwrap();
        assert_eq!(ids.len(), 2, "Ed25519 + ML-DSA-87 both verify");
        assert_eq!(Checkpoint::parse(text).unwrap(), cp.checkpoint);
        assert_eq!(root_from_tiles(&log.sink().files, *stop), *cp.checkpoint.root(), "checkpoint {i}");
        cps.push(cp);
    }
    // I1: every pair of checkpoints is consistent.
    for a in &cps {
        for b in &cps {
            let (m, n) = (a.checkpoint.size(), b.checkpoint.size());
            if m <= n {
                let p = log.consistency_proof(m, n).unwrap();
                assert!(verify_consistency(m, n, a.checkpoint.root(), b.checkpoint.root(), &p));
            }
        }
    }
    let last = cps.last().unwrap();
    for i in (0..70_000).step_by(997) {
        let p = log.inclusion_proof(i, 70_000).unwrap();
        let s = log.sink();
        let w = (70_000 - i / 256 * 256).min(256) as u16;
        let tile = &s.files[&TilePath { kind: TileKind::Hash(0), index: i / 256, width: w }.to_path()];
        let lh: Hash = tile[(i % 256) as usize * 32..][..32].try_into().unwrap();
        assert!(verify_inclusion(i, 70_000, &lh, &p, last.checkpoint.root()));
    }
    // Spec example sizes: 70,000 → 273 full L0 tiles + .p/112, full L1 tile 0 + .p/17, L2 .p/1.
    let f = &log.sink().files;
    assert!(f.contains_key("tile/0/272") && f.contains_key("tile/0/273.p/112"));
    assert!(f.contains_key("tile/1/000") && f.contains_key("tile/1/001.p/17") && f.contains_key("tile/2/000.p/1"));
    assert!(!f.contains_key("tile/0/273"));
    // Proofs beyond the published size are refused.
    log.append(&event(70_000, EventClass::DataPlane), 0).unwrap();
    assert!(log.inclusion_proof(70_000, 70_001).is_none());
}

#[test]
fn full_tiles_written_once_and_sync_precedes_publish() {
    let mut log = log_with(cfg(), false);
    for k in 0..40u64 {
        for _ in 0..37 {
            let n = log.size();
            log.append(&event(n, EventClass::DataPlane), 0).unwrap();
        }
        if k % 3 == 0 {
            log.checkpoint().unwrap();
        }
    }
    log.checkpoint().unwrap();
    let calls = &log.sink().calls;
    // I3: each full tile/bundle path written exactly once (no retries happened here).
    let mut seen = std::collections::BTreeSet::new();
    for c in calls {
        if let Call::Tile(p) | Call::Entries(p) = c
            && !p.contains(".p/")
        {
            assert!(seen.insert(p.clone()), "full resource {p} rewritten");
        }
    }
    // I4: every publish is immediately preceded by a sync, and no write occurs between them.
    for (i, c) in calls.iter().enumerate() {
        if let Call::Publish(_) = c {
            assert_eq!(calls.get(i.wrapping_sub(1)), Some(&Call::Sync));
        }
    }
}

#[test]
fn sync_failure_blocks_publish_and_applies_failure_policy() {
    let mut log = log_with(cfg(), false);
    for n in 0..10 {
        log.append(&event(n, EventClass::DataPlane), 0).unwrap();
    }
    let good = log.checkpoint().unwrap();
    for n in 10..20 {
        log.append(&event(n, EventClass::DataPlane), 0).unwrap();
    }
    log.sink_mut().fail_sync = true;
    assert!(matches!(log.checkpoint(), Err(CommitError::Sink(_))));
    assert_eq!(log.sink().checkpoint.as_deref(), Some(good.note.as_bytes()), "I4: nothing published without fsync");
    assert_eq!(log.published_size(), 10);
    // I7: admin fails closed, data-plane drops with a counter and does not consume a seq.
    assert_eq!(log.append(&event(99, EventClass::Admin), 0), Err(AppendError(RejectReason::SinkUnavailable)));
    assert_eq!(log.append(&event(99, EventClass::DataPlane), 0), Ok(Appended::Dropped(RejectReason::SinkUnavailable)));
    assert_eq!(log.dropped(), 1);
    assert_eq!(log.size(), 20);
    assert!(matches!(log.append_durable(&event(99, EventClass::Admin), 0), Err(AdminError::Refused(_))));
    // Recovery: the retry rewrites identical bytes (no conflict) and publishes.
    log.sink_mut().fail_sync = false;
    let cp = log.checkpoint().unwrap();
    assert_eq!(cp.checkpoint.size(), 20);
    let (seq, cp2) = log.append_durable(&event(20, EventClass::Admin), 0).unwrap();
    assert_eq!((seq, cp2.checkpoint.size()), (20, 21));
    // Publish failure after a good sync: durable, not published; retry publishes without rewriting.
    log.append(&event(21, EventClass::DataPlane), 0).unwrap();
    log.sink_mut().fail_publish = true;
    assert!(log.checkpoint().is_err());
    assert_eq!(log.published_size(), 21);
    log.sink_mut().fail_publish = false;
    let before = log.sink().calls.len();
    assert_eq!(log.checkpoint().unwrap().checkpoint.size(), 22);
    assert_eq!(log.sink().calls[before..], [Call::Publish(22)]);
}

#[test]
fn backpressure_and_invalid_events() {
    let mut c = cfg();
    c.max_pending = 3;
    c.policy.data_plane = OnFailure::DropAndCount;
    let mut log = log_with(c, false);
    for n in 0..3 {
        log.append(&event(n, EventClass::DataPlane), 0).unwrap();
    }
    assert_eq!(log.append(&event(3, EventClass::DataPlane), 0), Ok(Appended::Dropped(RejectReason::Backpressure)));
    assert_eq!(log.append(&event(3, EventClass::Admin), 0), Err(AppendError(RejectReason::Backpressure)));
    log.checkpoint().unwrap();
    assert_eq!(log.append(&event(3, EventClass::DataPlane), 0), Ok(Appended::Sequenced(3)));
    // Out-of-range timestamp: invalid, never sequenced.
    assert_eq!(
        log.append(&event(4, EventClass::Admin), u64::MAX),
        Err(AppendError(RejectReason::Invalid(EventError::BadTimestamp)))
    );
    assert_eq!(log.size(), 4);
    assert_eq!(log.dropped(), 1);
}

#[test]
fn config_rules() {
    let mut c = cfg();
    c.require_cosigner = true;
    let ed = Box::new(Ed25519NoteSigner::from_seed(ORIGIN, &[1; 32]).unwrap());
    assert_eq!(Log::new(c, ed, vec![], MemSink::default()).err(), Some(ConfigError::MissingCosigner));
    let mut c = cfg();
    c.origin = "bad\norigin".into();
    let ed = Box::new(Ed25519NoteSigner::from_seed(ORIGIN, &[1; 32]).unwrap());
    assert_eq!(Log::new(c, ed, vec![], MemSink::default()).err(), Some(ConfigError::BadOrigin));
}

#[test]
fn empty_log_checkpoint() {
    let mut log = log_with(cfg(), false);
    let cp = log.checkpoint().unwrap();
    assert_eq!(cp.checkpoint.text(), format!("{ORIGIN}\n0\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n"));
    assert!(log.sink().files.is_empty());
}
