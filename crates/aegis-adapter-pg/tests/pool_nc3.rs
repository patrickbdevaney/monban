//! Pool keying, bound, epoch retirement and the NC3 release path against a scripted session (the adapter's own
//! protocol mirror driven through `checkin::sim`). No sockets, deterministic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

use aegis_adapter_pg::checkin::sim::SimProto;
use aegis_adapter_pg::wire::{self, Backend, DbError, Expect, ProtoState, TxnStatus};
use aegis_adapter_pg::{
    AcquireError, Charge, ConnId, Nc3Observer, NoObserver, PgSession, Pool, PoolConfig, PoolKey, Pooled, Release,
    Released, TenantId,
};

/// Log shared by every session of a test: what reached the "wire".
type Log = Rc<RefCell<Vec<String>>>;

struct Scripted {
    name: u32,
    proto: SimProto,
    queue: VecDeque<(Backend, u64)>,
    txn: TxnStatus,
    generation: u64,
    log: Log,
    discard_fails: bool,
}

impl Scripted {
    fn new(name: u32, log: &Log) -> Scripted {
        Scripted {
            name,
            proto: SimProto::started(TxnStatus::Idle),
            queue: VecDeque::new(),
            txn: TxnStatus::Idle,
            generation: 0,
            log: Rc::clone(log),
            discard_fails: false,
        }
    }
    fn simple(&mut self, sql: &str, cost: u64) {
        self.proto.sent(Expect::Query);
        self.log.borrow_mut().push(format!("{}:{sql}", self.name));
        let mut fail = false;
        match sql {
            "BEGIN" => self.txn = TxnStatus::InTransaction,
            "COMMIT" | "ROLLBACK" => self.txn = TxnStatus::Idle,
            "DISCARD ALL" if self.txn != TxnStatus::Idle || self.discard_fails => {
                fail = true;
                if self.txn == TxnStatus::InTransaction {
                    self.txn = TxnStatus::Failed;
                }
            }
            _ => {}
        }
        if fail {
            let e = DbError {
                severity: "ERROR".into(),
                code: "25001".into(),
                message: "x".into(),
                detail: None,
                constraint: None,
            };
            self.queue.push_back((Backend::ErrorResponse(e), 0));
        } else {
            self.queue.push_back((Backend::CommandComplete("OK".into()), 0));
        }
        self.queue.push_back((Backend::ReadyForQuery(self.txn), cost));
    }
    fn parse(&mut self, name: &str) {
        self.proto.sent(Expect::Parse(name.into()));
        self.proto.sent(Expect::Sync);
        self.queue.push_back((Backend::ParseComplete, 0));
        self.queue.push_back((Backend::ReadyForQuery(self.txn), 0));
    }
    fn read_all(&mut self) {
        while self.proto.state().outstanding() > 0 {
            self.read_one(u64::MAX).unwrap();
        }
    }
}

impl Pooled for Scripted {
    fn close(mut self) {
        self.proto.closed();
        self.log.borrow_mut().push(format!("{}:TERMINATE", self.name));
    }
}

impl PgSession for Scripted {
    fn proto(&self) -> &ProtoState {
        self.proto.state()
    }
    fn read_one(&mut self, _left: u64) -> Result<u64, wire::Error> {
        let (m, c) = self.queue.pop_front().ok_or(wire::Error::Timeout)?;
        self.proto.on_backend(&m).map_err(wire::Error::Unrecoverable)?;
        Ok(c)
    }
    fn send_sync(&mut self, _left: u64) -> Result<u64, wire::Error> {
        self.proto.sent(Expect::Sync);
        self.queue.push_back((Backend::ReadyForQuery(self.txn), 0));
        Ok(0)
    }
    fn send_simple(&mut self, sql: &str, _left: u64) -> Result<u64, wire::Error> {
        self.simple(sql, 1);
        Ok(0)
    }
    fn send_close(&mut self, kind: u8, name: &str, _left: u64) -> Result<u64, wire::Error> {
        self.proto.sent(Expect::Close(kind, name.into()));
        self.proto.sent(Expect::Sync);
        self.log.borrow_mut().push(format!("{}:CLOSE {}", self.name, name));
        self.queue.push_back((Backend::CloseComplete, 0));
        self.queue.push_back((Backend::ReadyForQuery(self.txn), 0));
        Ok(0)
    }
    fn cancel_request(&mut self) -> Result<(), wire::Error> {
        self.log.borrow_mut().push(format!("{}:CANCELREQUEST", self.name));
        Ok(())
    }
    fn generation(&self) -> u64 {
        self.generation
    }
    fn bump_generation(&mut self) -> u64 {
        self.generation += 1;
        self.generation
    }
}

#[derive(Default)]
struct Rec(Vec<String>);

impl Nc3Observer<Scripted> for Rec {
    fn quarantine(&mut self, id: ConnId) {
        self.0.push(format!("quarantine {id}"));
    }
    fn cancel_request(&mut self, id: ConnId) {
        self.0.push(format!("cancel_request {id}"));
    }
    fn gen_bump(&mut self, id: ConnId, g: u64) {
        self.0.push(format!("gen_bump {id} {g}"));
    }
    fn charge(&mut self, cost: u64, why: Charge) {
        self.0.push(format!("charge {cost} {why:?}"));
    }
    fn recover(&mut self, id: ConnId, ticks: u64, ok: bool) {
        self.0.push(format!("recover {id} {ticks} {ok}"));
    }
    fn checkin(&mut self, id: ConnId, c: &Scripted) {
        assert!(c.proto().is_clean(), "checkin of an unclean connection");
        self.0.push(format!("checkin {id}"));
    }
    fn discard(&mut self, id: ConnId) {
        self.0.push(format!("discard {id}"));
    }
    fn closed(&mut self, id: ConnId) {
        self.0.push(format!("closed {id}"));
    }
}

fn key(p: &str, t: u64, epoch: u64) -> PoolKey {
    PoolKey::new(p.as_bytes(), TenantId::new(t).unwrap(), &format!("t_{t:016x}"), epoch).unwrap()
}

fn cfg() -> PoolConfig {
    PoolConfig { max_open: 4, max_idle_per_key: 1, acquire_timeout: Duration::from_millis(0) }
}

struct Fx {
    pool: Pool<Scripted>,
    log: Log,
    n: u32,
}

impl Fx {
    fn new(c: PoolConfig) -> Fx {
        Fx { pool: Pool::new(c), log: Rc::default(), n: 0 }
    }
    fn get(&mut self, k: &PoolKey) -> aegis_adapter_pg::Checkout<Scripted> {
        self.n += 1;
        let (n, log) = (self.n, Rc::clone(&self.log));
        self.pool.acquire(k, |_| Ok::<_, ()>(Scripted::new(n, &log))).unwrap()
    }
    fn wire(&self) -> Vec<String> {
        self.log.borrow().clone()
    }
}

#[test]
fn key_validation() {
    let t = TenantId::new(1).unwrap();
    assert!(PoolKey::new(b"", t, "r", 0).is_err());
    assert!(PoolKey::new(b"a", t, "", 0).is_err());
    assert!(PoolKey::new(b"a", t, &"r".repeat(64), 0).is_err());
    assert!(PoolKey::new(&[1u8; 513], t, "r", 0).is_err());
    assert!(PoolKey::new(b"a", t, "r", 0).is_ok());
}

#[test]
fn never_reused_across_principal_tenant_role_or_epoch() {
    let mut fx = Fx::new(PoolConfig { max_open: 16, ..cfg() });
    let base = key("alice", 1, 0);
    let co = fx.get(&base);
    let id = co.id();
    assert_eq!(fx.pool.release(co, Release::Completed, 5, &mut NoObserver), Released::CheckedIn);
    let others = [
        key("bob", 1, 0),
        key("alice", 2, 0),
        key("alice", 1, 1),
        PoolKey::new(b"alice", TenantId::new(1).unwrap(), "other_role", 0).unwrap(),
    ];
    for k in &others {
        let co = fx.get(k);
        assert_ne!(co.id(), id, "{k:?} reused a connection of {base:?}");
        assert!(!co.reused());
        drop(co);
    }
    let mut co = fx.get(&base);
    assert_eq!(co.id(), id);
    assert!(co.reused());
    // C8: a recycled connection is unreachable until its reset ran.
    assert!(co.needs_reset());
    assert!(co.session().is_err());
    assert!(co.reset_send(5).unwrap());
    assert!(co.session().is_err());
    assert_eq!(co.reset_finish(5).unwrap(), 1);
    assert!(co.session().is_ok());
    assert!(fx.wire().contains(&"1:DISCARD ALL".to_string()));
}

#[test]
fn epoch_retirement_closes_idle_and_refuses_stale() {
    let mut fx = Fx::new(cfg());
    let k0 = key("alice", 1, 0);
    let co = fx.get(&k0);
    let held = fx.get(&key("bob", 2, 0));
    assert_eq!(fx.pool.release(co, Release::Completed, 5, &mut NoObserver), Released::CheckedIn);
    assert_eq!(fx.pool.open(), 2);
    let closed = fx.pool.retire_before(1);
    assert_eq!(closed.len(), 1);
    assert_eq!(fx.pool.open(), 1);
    assert!(fx.wire().contains(&"1:TERMINATE".to_string()));
    assert!(!fx.wire().iter().any(|l| l.ends_with("CANCELREQUEST")), "idle close never sends a CancelRequest");
    assert!(matches!(fx.pool.acquire(&k0, |_| Ok::<_, ()>(Scripted::new(9, &fx.log))), Err(AcquireError::StaleEpoch)));
    // A connection checked out before the bump is closed at checkin, never kept.
    let mut rec = Rec::default();
    assert_eq!(fx.pool.release(held, Release::Completed, 5, &mut rec), Released::Closed);
    assert_eq!(fx.pool.open(), 0);
}

#[test]
fn bound_evicts_lru_idle_then_exhausts_and_drop_frees() {
    let mut fx = Fx::new(PoolConfig { max_open: 2, ..cfg() });
    let a = fx.get(&key("a", 1, 0));
    let b = fx.get(&key("b", 2, 0));
    assert!(matches!(
        fx.pool.acquire(&key("c", 3, 0), |_| Ok::<_, ()>(Scripted::new(9, &fx.log))),
        Err(AcquireError::Exhausted)
    ));
    fx.pool.release(a, Release::Completed, 5, &mut NoObserver);
    let c = fx.get(&key("c", 3, 0)); // evicts a's idle connection
    assert!(!c.reused());
    assert_eq!(fx.pool.idle_for(&key("a", 1, 0)), 0);
    drop(b); // a dropped checkout frees its slot and never returns to the pool
    assert_eq!(fx.pool.open(), 1);
    assert_eq!(fx.pool.idle_for(&key("b", 2, 0)), 0);
    drop(c);
    assert_eq!(fx.pool.open(), 0);
}

#[test]
fn cancelled_clean_connection_is_still_quarantined_and_reset() {
    let mut fx = Fx::new(cfg());
    let mut co = fx.get(&key("alice", 1, 0));
    co.session().unwrap().simple("SET app.x = 1", 0);
    co.session().unwrap().read_all();
    assert!(co.peek().proto().is_clean());
    let mut rec = Rec::default();
    let r = fx.pool.release(co, Release::Cancelled, 5, &mut rec);
    assert_eq!(r, Released::Recovered { ticks: 1 });
    assert_eq!(rec.0, ["quarantine 1", "gen_bump 1 1", "charge 1 Quarantine", "recover 1 1 true", "checkin 1"]);
    assert!(fx.wire().contains(&"1:DISCARD ALL".to_string()));
    // Recovered = already reset: the next checkout needs no reset.
    let mut co = fx.get(&key("alice", 1, 0));
    assert!(co.reused() && !co.needs_reset() && co.session().is_ok());
}

#[test]
fn handler_error_clean_is_ordinary_unclean_is_quarantined() {
    let mut fx = Fx::new(cfg());
    let co = fx.get(&key("alice", 1, 0));
    let mut rec = Rec::default();
    assert_eq!(fx.pool.release(co, Release::HandlerError, 5, &mut rec), Released::CheckedIn);
    assert_eq!(rec.0, ["checkin 1"]);

    // Left mid-protocol: open named statement (txn I, nothing outstanding) -> quarantine, DISCARD ALL closes it.
    let mut co = fx.get(&key("alice", 1, 0));
    co.reset_send(5).unwrap();
    co.reset_finish(5).unwrap();
    co.session().unwrap().parse("cached");
    co.session().unwrap().read_all();
    assert!(!co.peek().proto().is_clean());
    let mut rec = Rec::default();
    assert_eq!(fx.pool.release(co, Release::HandlerError, 5, &mut rec), Released::Recovered { ticks: 1 });
    assert_eq!(rec.0.first().map(String::as_str), Some("quarantine 1"));
    let w = fx.wire();
    assert_eq!(&w[w.len() - 2..], ["1:CLOSE cached", "1:DISCARD ALL"]);
}

#[test]
fn recovery_drains_without_cancelrequest_and_rolls_back() {
    let mut fx = Fx::new(cfg());
    let mut co = fx.get(&key("alice", 1, 0));
    let s = co.session().unwrap();
    s.simple("BEGIN", 0);
    s.read_all();
    s.simple("UPDATE t", 2); // written, reply outstanding (cancelled before the read)
    let mut rec = Rec::default();
    let r = fx.pool.release(co, Release::Cancelled, 5, &mut rec);
    assert_eq!(r, Released::Recovered { ticks: 4 }); // 2 (drain) + ROLLBACK 1 + DISCARD ALL 1
    let w = fx.wire();
    assert!(!w.iter().any(|l| l.ends_with("CANCELREQUEST")), "recovery must not send a CancelRequest: {w:?}");
    assert_eq!(&w[w.len() - 2..], ["1:ROLLBACK", "1:DISCARD ALL"]);
    assert_eq!(rec.0.last().map(String::as_str), Some("checkin 1"));
}

#[test]
fn over_budget_or_error_discards_with_cancelrequest_and_charges() {
    let mut fx = Fx::new(cfg());
    let mut co = fx.get(&key("alice", 1, 0));
    let s = co.session().unwrap();
    s.simple("BEGIN", 0);
    s.read_all();
    s.simple("SELECT slow", 3);
    let mut rec = Rec::default();
    assert_eq!(fx.pool.release(co, Release::Cancelled, 2, &mut rec), Released::Discarded);
    assert_eq!(
        rec.0,
        [
            "quarantine 1",
            "charge 2 Quarantine",
            "recover 1 2 false",
            "cancel_request 1",
            "discard 1",
            "charge 3 Discard"
        ]
    );
    let w = fx.wire();
    assert_eq!(&w[w.len() - 2..], ["1:CANCELREQUEST", "1:TERMINATE"]);
    assert_eq!(fx.pool.open(), 0);

    // DISCARD ALL failing => discard.
    let mut co = fx.get(&key("alice", 1, 0));
    co.session().unwrap().discard_fails = true;
    let mut rec = Rec::default();
    assert_eq!(fx.pool.release(co, Release::Cancelled, 5, &mut rec), Released::Discarded);
    assert!(rec.0.contains(&"recover 2 1 false".to_string()));
}

#[test]
fn completed_unclean_is_quarantined() {
    let mut fx = Fx::new(cfg());
    let mut co = fx.get(&key("alice", 1, 0));
    let s = co.session().unwrap();
    s.simple("BEGIN", 0);
    s.read_all();
    let mut rec = Rec::default();
    // A "completed" release with an open txn fails the predicate (left mid-protocol): quarantine + recovery.
    assert_eq!(fx.pool.release(co, Release::Completed, 5, &mut rec), Released::Recovered { ticks: 2 });
    assert_eq!(rec.0.first().map(String::as_str), Some("quarantine 1"));
    assert!(!fx.wire().iter().any(|l| l.ends_with("CANCELREQUEST")));
}

#[test]
fn unrecoverable_state_is_discarded_without_recovery() {
    let mut fx = Fx::new(cfg());
    let mut co = fx.get(&key("alice", 1, 0));
    let s = co.session().unwrap();
    s.proto.sent(Expect::Query);
    s.queue.push_back((Backend::CopyOutResponse, 0)); // COPY: NC3 always discard
    assert!(s.read_one(5).is_err());
    let mut rec = Rec::default();
    assert_eq!(fx.pool.release(co, Release::Cancelled, 5, &mut rec), Released::Discarded);
    assert!(!fx.wire().iter().any(|l| l.ends_with("ROLLBACK") || l.ends_with("DISCARD ALL")));
}

#[test]
fn checkout_and_pool_are_send_for_real_connections() {
    fn is_send<T: Send>() {}
    fn is_sync<T: Sync>() {}
    is_send::<Pool<aegis_adapter_pg::PgConn>>();
    is_sync::<Pool<aegis_adapter_pg::PgConn>>();
    is_send::<aegis_adapter_pg::Checkout<aegis_adapter_pg::PgConn>>();
}
