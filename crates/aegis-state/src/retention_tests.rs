//! IDEMP-R unit checks (P8-hardening-001; the randomized SIGKILL run is `oracles/state-props` case `retention`).
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::idem::{IDEM_SPACE, Record};
use crate::store::Op;
use crate::{Begin, Clock, IdemKey, Outcome, State, StateError, StateMutations};

struct Tmp(PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn tmp(name: &str) -> Result<Tmp, String> {
    let p = std::env::temp_dir().join(format!("aegis-state-retention-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).map_err(|e| e.to_string())?;
    Ok(Tmp(p))
}

type R = Result<(), Box<dyn std::error::Error>>;

fn open(t: &Tmp, now: &Arc<AtomicU64>, retention: Option<u64>, muts: StateMutations) -> Result<State, StateError> {
    let mut st = State::open_with(&t.0, muts)?;
    let n = Arc::clone(now);
    st.set_clock(Clock::new(move || n.load(Ordering::SeqCst)));
    st.set_retention(retention)?;
    Ok(st)
}

fn commit(st: &mut State, k: &IdemKey, d: &[u8], body: &[u8]) -> R {
    match st.begin(k, d)? {
        Begin::New(l) => {
            st.commit(l, Outcome { status: 201, body: body.to_vec() }, false)?;
            Ok(())
        }
        other => Err(format!("expected NEW, got {other:?}").into()),
    }
}

fn kind(b: &Begin) -> &'static str {
    match b {
        Begin::New(_) => "new",
        Begin::Replay(_) => "replay",
        Begin::Conflict => "conflict",
        Begin::InFlight => "inflight",
    }
}

fn probe(st: &mut State, k: &IdemKey, d: &[u8]) -> Result<&'static str, StateError> {
    let b = st.begin(k, d)?;
    let s = kind(&b);
    if let Begin::New(l) = b {
        st.abort(l);
    }
    Ok(s)
}

const T0: u64 = 1_800_000_000;

#[test]
fn window_replays_then_forgets_and_purges() -> R {
    let t = tmp("window")?;
    let now = Arc::new(AtomicU64::new(T0));
    let mut st = open(&t, &now, Some(60), StateMutations::NONE)?;
    let k = IdemKey::new(b"alice", b"k1")?;
    commit(&mut st, &k, b"d1", b"one")?;
    now.store(T0 + 59, Ordering::SeqCst);
    assert_eq!(probe(&mut st, &k, b"d1")?, "replay", "inside the window");
    assert_eq!(probe(&mut st, &k, b"d2")?, "conflict", "inside the window, other digest");
    assert!(st.outcome(&k)?.is_some());
    // Durable timestamp: a restart inside the window still replays and still expires on time.
    drop(st);
    let mut st = open(&t, &now, Some(60), StateMutations::NONE)?;
    assert_eq!(probe(&mut st, &k, b"d1")?, "replay", "after restart, inside the window");
    now.store(T0 + 60, Ordering::SeqCst);
    assert_eq!(probe(&mut st, &k, b"d1")?, "new", "window over");
    assert_eq!(probe(&mut st, &k, b"d2")?, "new", "expired record does not conflict");
    assert!(st.outcome(&k)?.is_none());
    assert_eq!(st.purge_expired()?, 1);
    assert_eq!(st.purge_expired()?, 0);
    assert!(st.store.get(IDEM_SPACE, &k.encode())?.is_none(), "purge deleted the record");
    // Re-use: a fresh outcome with a fresh window.
    commit(&mut st, &k, b"d3", b"three")?;
    now.store(T0 + 119, Ordering::SeqCst);
    assert_eq!(probe(&mut st, &k, b"d3")?, "replay");
    Ok(())
}

#[test]
fn absent_retention_never_expires_and_clock_skew_keeps() -> R {
    let t = tmp("absent")?;
    let now = Arc::new(AtomicU64::new(T0));
    let mut st = open(&t, &now, None, StateMutations::NONE)?;
    let k = IdemKey::new(b"bob", b"k")?;
    commit(&mut st, &k, b"d", b"x")?;
    now.store(T0 + 1_000_000_000, Ordering::SeqCst);
    assert_eq!(probe(&mut st, &k, b"d")?, "replay", "no retention: never expires");
    assert_eq!(st.purge_expired()?, 0);
    // The same store under a retention: expired by age, kept if the clock went back before the commit.
    drop(st);
    let mut st = open(&t, &now, Some(3600), StateMutations::NONE)?;
    now.store(T0 - 10, Ordering::SeqCst);
    assert_eq!(probe(&mut st, &k, b"d")?, "replay", "record from the future is kept");
    now.store(T0 + 3600, Ordering::SeqCst);
    assert_eq!(probe(&mut st, &k, b"d")?, "new");
    assert!(st.set_retention(Some(0)).is_err());
    Ok(())
}

#[test]
fn legacy_record_without_timestamp_never_expires() -> R {
    let t = tmp("legacy")?;
    let now = Arc::new(AtomicU64::new(T0));
    let mut st = open(&t, &now, Some(60), StateMutations::NONE)?;
    let k = IdemKey::new(b"carol", b"k")?;
    let legacy =
        Record { digest: b"d".to_vec(), outcome: Outcome { status: 200, body: b"old".to_vec() }, committed_at: None };
    // Pre-Phase-8 byte layout: no leading marker.
    let enc = legacy.encode();
    assert_eq!(enc.get(..4), Some(&[0u8, 0, 0, 1][..]));
    st.store.commit(&[Op::Put { space: IDEM_SPACE, key: k.encode(), value: enc }])?;
    now.store(T0 + 10_000_000, Ordering::SeqCst);
    assert_eq!(probe(&mut st, &k, b"d")?, "replay");
    assert_eq!(st.purge_expired()?, 0);
    Ok(())
}

#[test]
fn record_encoding_roundtrip_and_strictness() -> R {
    let r =
        Record { digest: b"dg".to_vec(), outcome: Outcome { status: 409, body: b"b".to_vec() }, committed_at: Some(7) };
    assert_eq!(Record::decode(&r.encode())?, r);
    let mut e = r.encode();
    e.truncate(10);
    assert!(Record::decode(&e).is_err(), "truncated timestamp");
    let over = [0u8, 0, 0, 65].iter().copied().chain(std::iter::repeat_n(0u8, 67)).collect::<Vec<u8>>();
    assert!(Record::decode(&over).is_err(), "digest over MAX_DIGEST_LEN");
    Ok(())
}

#[test]
fn held_key_is_not_purged_and_mutations_break_the_window() -> R {
    let t = tmp("held")?;
    let now = Arc::new(AtomicU64::new(T0));
    let mut st = open(&t, &now, Some(60), StateMutations::NONE)?;
    let k = IdemKey::new(b"dave", b"k")?;
    commit(&mut st, &k, b"d", b"x")?;
    now.store(T0 + 61, Ordering::SeqCst);
    let Begin::New(l) = st.begin(&k, b"d")? else { return Err("expected NEW after expiry".into()) };
    assert_eq!(st.purge_expired()?, 0, "the open lease's key is not purged");
    st.abort(l);
    assert_eq!(st.purge_expired()?, 1);
    drop(st);
    // Negative controls: each mutation is visible at the window edges.
    let t2 = tmp("muts")?;
    now.store(T0, Ordering::SeqCst);
    let ignored = StateMutations { retention_ignored: true, ..StateMutations::NONE };
    let mut st = open(&t2, &now, Some(60), ignored)?;
    commit(&mut st, &k, b"d", b"x")?;
    now.store(T0 + 60, Ordering::SeqCst);
    assert_eq!(probe(&mut st, &k, b"d")?, "replay", "retention_ignored keeps the key");
    drop(st);
    let early = StateMutations { retention_early: true, ..StateMutations::NONE };
    let mut st = open(&t2, &now, Some(60), early)?;
    now.store(T0 + 59, Ordering::SeqCst);
    assert_eq!(probe(&mut st, &k, b"d")?, "new", "retention_early forgets inside the window");
    Ok(())
}
