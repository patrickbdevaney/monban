//! The supervisor's cordon table (PLAN-5 D1; INV-P2 P2-2): keyed by principal, never shared, bounded, idle reaping.
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::convert::Infallible;
use std::time::{Duration, Instant};

use monban_iso::cordon::{CordonId, Registry, RegistryError};

/// A stand-in cordon handle: the principal it was spawned for (the real one is `supervisor::Supervised`).
#[derive(Debug, PartialEq, Eq)]
struct Fake {
    spawned_for: &'static str,
    id: CordonId,
}

fn spawn_for(p: &'static str) -> impl FnOnce(CordonId) -> Result<Fake, Infallible> {
    move |id| Ok(Fake { spawned_for: p, id })
}

fn acquire(r: &mut Registry<&'static str, Fake>, p: &'static str, now: Instant) -> CordonId {
    match r.acquire(&p, now, spawn_for(p)) {
        Ok(Ok(a)) => a.id,
        other => panic!("acquire {p}: {other:?}"),
    }
}

#[test]
fn a_cordon_refuses_a_second_principal() {
    let t0 = Instant::now();
    let mut r: Registry<&'static str, Fake> = Registry::new(64, 300).unwrap();
    let a = acquire(&mut r, "alice", t0);
    // alice's second request reuses her cordon; spawn must not run.
    match r.acquire(&"alice", t0, |_| -> Result<Fake, Infallible> { panic!("respawned for the same principal") }) {
        Ok(Ok(x)) => assert!(x.id == a && !x.spawned),
        other => panic!("{other:?}"),
    }
    // bob gets his own cordon, never alice's.
    let b = acquire(&mut r, "bob", t0);
    assert_ne!(a, b);
    assert_eq!(r.get(b, &"bob").unwrap().spawned_for, "bob");
    assert_eq!(r.get(a, &"alice").unwrap().spawned_for, "alice");
    // Every id-based route of bob's request onto alice's cordon is refused.
    assert_eq!(r.get(a, &"bob").err(), Some(RegistryError::ForeignPrincipal(a)));
    assert_eq!(r.release(a, &"bob", t0).err(), Some(RegistryError::ForeignPrincipal(a)));
    assert_eq!(r.remove(a, &"bob").err(), Some(RegistryError::ForeignPrincipal(a)));
    // A principal with no cordon cannot address one either.
    assert_eq!(r.get(a, &"carol").err(), Some(RegistryError::ForeignPrincipal(a)));
    // Alice's cordon is untouched by the refused attempts.
    assert_eq!(r.get(a, &"alice").unwrap(), &Fake { spawned_for: "alice", id: a });
    // After removal the id is unknown, and a new cordon for alice gets a new id (no reuse of a generation).
    r.release(a, &"alice", t0).unwrap();
    r.release(a, &"alice", t0).unwrap();
    assert_eq!(r.remove(a, &"alice").unwrap().spawned_for, "alice");
    assert_eq!(r.get(a, &"alice").err(), Some(RegistryError::Unknown(a)));
    let a2 = acquire(&mut r, "alice", t0);
    assert!(a2 != a && a2 != b);
}

#[test]
fn the_table_is_bounded_and_never_shares_at_the_cap() {
    let t0 = Instant::now();
    let s = Duration::from_secs;
    let mut r: Registry<&'static str, Fake> = Registry::new(2, 300).unwrap();
    let a = acquire(&mut r, "alice", t0);
    let b = acquire(&mut r, "bob", t0 + s(1));
    // Both busy: carol is refused (503), not placed on a busy cordon.
    match r.acquire(&"carol", t0 + s(2), spawn_for("carol")) {
        Err(RegistryError::AtCapacity) => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(r.len(), 2);
    // bob goes idle, then alice: the least-recently-used idle cordon (bob, released earlier) is evicted.
    r.release(b, &"bob", t0 + s(3)).unwrap();
    r.release(a, &"alice", t0 + s(4)).unwrap();
    match r.acquire(&"carol", t0 + s(5), spawn_for("carol")) {
        Ok(Ok(x)) => {
            assert!(x.spawned);
            let (k, id, c) = x.evicted.expect("an idle cordon is evicted");
            assert_eq!((k, id, c.spawned_for), ("bob", b, "bob"));
            assert_eq!(r.get(x.id, &"carol").unwrap().spawned_for, "carol");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(r.len(), 2);
    assert_eq!(r.id_of(&"bob"), None);
}

#[test]
fn idle_cordons_are_reaped_busy_ones_never() {
    let t0 = Instant::now();
    let s = Duration::from_secs;
    let mut r: Registry<&'static str, Fake> = Registry::new(64, 300).unwrap();
    let a = acquire(&mut r, "alice", t0);
    let b = acquire(&mut r, "bob", t0);
    r.release(a, &"alice", t0 + s(10)).unwrap();
    assert!(r.reap_idle(t0 + s(309)).is_empty());
    let reaped = r.reap_idle(t0 + s(310));
    assert_eq!(reaped.len(), 1);
    assert_eq!((reaped[0].0, reaped[0].1), ("alice", a));
    // bob still has a request in flight long after the idle period: never reaped.
    assert!(r.reap_idle(t0 + s(10_000)).is_empty());
    assert_eq!(r.id_of(&"bob"), Some(b));
}

#[test]
fn bounds_are_refused_and_spawn_errors_leave_no_entry() {
    assert!(Registry::<u32, ()>::new(0, 300).is_err());
    assert!(Registry::<u32, ()>::new(4097, 300).is_err());
    assert!(Registry::<u32, ()>::new(64, 0).is_err());
    assert!(Registry::<u32, ()>::new(64, 86_401).is_err());
    let mut r: Registry<u32, ()> = Registry::new(1, 1).unwrap();
    match r.acquire(&7, Instant::now(), |_| Err::<(), &str>("exec failed")) {
        Ok(Err("exec failed")) => {}
        other => panic!("{other:?}"),
    }
    assert!(r.is_empty());
}
