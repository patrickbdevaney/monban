//! monban-state idempotency / outbox / latch: INV-IDEMP, NC1, NC2, NC6 unit-level checks (the randomized SIGKILL
//! run is `oracles/state-props` through `subjects/state-subject`).
use std::path::PathBuf;

use monban_state::idem::USER_SPACE;
use monban_state::{Begin, DeliverError, Effect, IdemKey, Lease, Outcome, Reply, State, StateError};

struct Tmp(PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn tmp(name: &str) -> Result<Tmp, String> {
    let p = std::env::temp_dir().join(format!("monban-state-props-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).map_err(|e| e.to_string())?;
    Ok(Tmp(p))
}
fn ik(p: &str, k: &str) -> Result<IdemKey, StateError> {
    IdemKey::new(p.as_bytes(), k.as_bytes())
}
fn lease(b: Begin) -> Result<Lease, String> {
    match b {
        Begin::New(l) => Ok(l),
        other => Err(format!("expected NEW, got {other:?}")),
    }
}
fn out(status: u16, body: &[u8]) -> Outcome {
    Outcome { status, body: body.to_vec() }
}
fn drain(st: &mut State) -> Result<Vec<Effect>, String> {
    let mut seen = Vec::new();
    st.deliver(|e| {
        seen.push(e.clone());
        Ok::<(), ()>(())
    })
    .map_err(|e| format!("{e:?}"))?;
    Ok(seen)
}

type R = Result<(), Box<dyn std::error::Error>>;

#[test]
fn replay_conflict_inflight_and_principal_scope() -> R {
    let t = tmp("idem")?;
    let mut st = State::open(&t.0)?;
    let a = ik("alice", "k1")?;
    let mut l = lease(st.begin(&a, b"d1")?)?;
    l.write(b"r", b"v");
    assert!(matches!(st.begin(&a, b"d1")?, Begin::InFlight));
    assert!(matches!(st.begin(&a, b"d2")?, Begin::Conflict));
    // another principal's identical client key is independent, even while alice holds it
    let b = lease(st.begin(&ik("bob", "k1")?, b"d1")?)?;
    st.abort(b);
    assert_eq!(st.commit(l, out(201, b"ok"), false)?, Reply::Outcome(out(201, b"ok")));
    assert!(matches!(st.begin(&a, b"d1")?, Begin::Replay(o) if o == out(201, b"ok")));
    assert!(matches!(st.begin(&a, b"d2")?, Begin::Conflict));
    assert!(matches!(st.begin(&ik("bob", "k1")?, b"d1")?, Begin::New(_)));
    drop(st);
    let mut st = State::open(&t.0)?;
    assert!(matches!(st.begin(&a, b"d1")?, Begin::Replay(o) if o == out(201, b"ok")));
    assert_eq!(st.user_row(b"r")?, Some(b"v".to_vec()));
    Ok(())
}

#[test]
fn abort_and_restart_leave_nothing() -> R {
    let t = tmp("nc1")?;
    let k = ik("bob", "k3")?;
    {
        let mut st = State::open(&t.0)?;
        let mut l = lease(st.begin(&k, b"d")?)?;
        l.write(b"x", b"1");
        st.effect(&mut l, b"e")?;
        st.abort(l);
        assert!(drain(&mut st)?.is_empty());
        assert_eq!(st.held_count(), 0);
        let mut l = lease(st.begin(&k, b"d")?)?;
        l.write(b"x", b"2");
        st.effect(&mut l, b"e2")?;
        // dropped without commit: simulated crash before CP
    }
    let mut st = State::open(&t.0)?;
    assert!(matches!(st.begin(&k, b"d")?, Begin::New(_)));
    assert!(st.user_rows()?.is_empty());
    assert!(drain(&mut st)?.is_empty());
    assert_eq!(USER_SPACE, 17);
    Ok(())
}

#[test]
fn latch_202_keeps_outcome_retrievable() -> R {
    let t = tmp("nc2")?;
    let mut st = State::open(&t.0)?;
    let k = ik("alice", "k2")?;
    let l = lease(st.begin(&k, b"d")?)?;
    let r = st.commit(l, out(200, b"late"), true)?;
    assert_eq!(r, Reply::Accepted);
    assert_eq!(r.status(), 202);
    assert!(matches!(st.begin(&k, b"d")?, Begin::Replay(o) if o == out(200, b"late")));
    assert_eq!(st.outcome(&k)?.map(|r| r.outcome), Some(out(200, b"late")));
    Ok(())
}

#[test]
fn outbox_only_after_commit_and_stable_dedupe() -> R {
    let t = tmp("nc6")?;
    let first_dedupes;
    {
        let mut st = State::open(&t.0)?;
        let mut l = lease(st.begin(&ik("alice", "k1")?, b"d")?)?;
        let d0 = st.effect(&mut l, b"p0")?;
        let d1 = st.effect(&mut l, b"p1")?;
        assert_ne!(d0, d1);
        assert!(drain(&mut st)?.is_empty()); // NC6: nothing before CP
        st.commit(l, out(200, b"b"), false)?;
        // sink fails on the second effect: the first is delivered, the second stays pending
        let mut n = 0;
        let r = st.deliver(|_| {
            n += 1;
            if n == 2 { Err("down") } else { Ok(()) }
        });
        assert!(matches!(r, Err(DeliverError::Sink("down"))));
        first_dedupes = (d0, d1);
    }
    let mut st = State::open(&t.0)?;
    let again = drain(&mut st)?;
    assert_eq!(again.len(), 1);
    assert_eq!(again.first().map(|e| (e.dedupe, e.payload.clone())), Some((first_dedupes.1, b"p1".to_vec())));
    assert!(drain(&mut st)?.is_empty());
    // the same client key under another principal derives other dedupe keys
    let mut l = lease(st.begin(&ik("bob", "k1")?, b"d")?)?;
    assert_ne!(st.effect(&mut l, b"p0")?, first_dedupes.0);
    st.abort(l);
    Ok(())
}

#[test]
fn input_domain_refused() -> R {
    let t = tmp("dom")?;
    let mut st = State::open(&t.0)?;
    assert!(IdemKey::new(b"", b"k").is_err());
    assert!(IdemKey::new(b"p", b"").is_err());
    assert!(IdemKey::new(b"p", &[b'k'; 256]).is_err());
    let k = ik("p", "k")?;
    assert!(st.begin(&k, b"").is_err());
    let l = lease(st.begin(&k, b"d")?)?;
    assert!(st.commit(l, out(42, b""), false).is_err());
    // the refused commit released the key and wrote nothing
    assert!(matches!(st.begin(&k, b"d")?, Begin::New(_)));
    Ok(())
}
