//! NC3 checkin, quarantine/recovery and discard; C8 reset on recycle (P4-pg-003).
//!
//! `spec/SPEC_INVARIANTS.md` INV-NOMUT-C NC3 (q3-008, widened): a connection that a cancelled request touched, or that
//! was left mid-protocol, is quarantined (never handed to another request; here: it is owned by [`Pool::release`]
//! and not in the idle set) and either recovered or discarded.
//!
//! * **Checkin predicate** ([`checkin_predicate`]): ReadyForQuery seen ∧ server-reported txn status `I` ∧ no
//!   outstanding replies ∧ no open named statements or portals ∧ not skipping to Sync ∧ recoverable
//!   ([`ProtoState::is_clean`]), plus the transport probe ([`PgSession::transport_idle`]).
//! * **Release** ([`Release`]): `Completed` and `HandlerError` take the ordinary checkin iff the predicate holds
//!   ("left mid-protocol" is the predicate failing); `Cancelled` is always quarantined, even when the predicate
//!   holds (session state such as a `SET` is invisible to it).
//! * **Recovery** within T_recover = the op budget: drain every outstanding reply **without** a CancelRequest
//!   (sending a Sync first if the server is skipping after an extended-mode error), ROLLBACK if the reported txn
//!   status is not `I`, Close of every named statement/portal the protocol mirror lists (so the mirror stays exact),
//!   DISCARD ALL, driver cache-generation bump. Any error, timeout, budget overrun or
//!   unrecoverable protocol state (desync, COPY, LISTEN, FATAL, IO) ⇒ discard.
//! * **Discard** sends a CancelRequest for the backend, then Terminate; the connection is consumed, so a
//!   CancelRequest is never sent on a connection that is checked back in.
//! * **NC4**: quarantine time (at least 1 unit) and a discard after quarantine ([`DISCARD_COST`]) are reported to the
//!   observer as charges against the releasing (cancelling) principal; the host debits its limiter.
//! * **C8 reset on recycle**: an ordinary checkin marks the connection for reset; the next checkout runs DISCARD ALL +
//!   generation bump ([`Checkout::reset_send`] / [`Checkout::reset_finish`], a host call with a cancellation point
//!   between write and read) before [`Checkout::session`] is reachable.
//!
//! Costs are in op-budget units chosen by the session: milliseconds for [`PgConn`], abstract ticks for a DST fake.

use std::fmt;
use std::time::{Duration, Instant};

use crate::pool::{Checkout, ConnId, Idled, Lease, Pool, PoolKey, PoolMutations, Pooled};
use crate::wire::{self, Connection, Pipeline, ProtoState, TxnStatus};

/// NC4 charge for a discarded connection (backend fork + auth of its replacement, q3-008), in charge units.
pub const DISCARD_COST: u64 = 3;
/// Bound on the CancelRequest connect + write of the discard path.
pub const CANCEL_REQUEST_TIMEOUT: Duration = Duration::from_millis(200);
/// Bound on the Terminate write when a connection is closed.
pub const TERMINATE_TIMEOUT: Duration = Duration::from_millis(200);

/// The statement that resets session state (C8, NC3 recovery).
pub const DISCARD_ALL: &str = "DISCARD ALL";
/// The statement that ends a transaction left open by a cancelled or failed request.
pub const ROLLBACK: &str = "ROLLBACK";

/// A PG session as the NC3 code needs it. The protocol truth is the client's exact mirror ([`ProtoState`]); costs
/// are in op-budget units; `left` is the budget that remains for the call (a call must fail rather than exceed it,
/// or report its true cost so the caller sees the overrun).
pub trait PgSession: Pooled {
    fn proto(&self) -> &ProtoState;
    /// Transport-level idleness (no unread bytes, no EOF). Default: nothing beyond the protocol state.
    fn transport_idle(&self) -> bool {
        true
    }
    /// Read and apply one backend message.
    fn read_one(&mut self, left: u64) -> Result<u64, wire::Error>;
    /// Write a Sync.
    fn send_sync(&mut self, left: u64) -> Result<u64, wire::Error>;
    /// Write one simple Query (recovery and reset statements only).
    fn send_simple(&mut self, sql: &str, left: u64) -> Result<u64, wire::Error>;
    /// Write Close(`kind` = `b'S'` statement | `b'P'` portal, `name`) + Sync (recovery: closes the named objects the
    /// protocol mirror lists, so the mirror stays exact; DISCARD ALL alone would close them unseen by it).
    fn send_close(&mut self, kind: u8, name: &str, left: u64) -> Result<u64, wire::Error>;
    /// CancelRequest for this backend over a separate connection (discard path only).
    fn cancel_request(&mut self) -> Result<(), wire::Error>;
    /// Driver-side statement/type cache generation.
    fn generation(&self) -> u64;
    /// Invalidate the driver-side caches; returns the new generation.
    fn bump_generation(&mut self) -> u64;
}

/// The NC3 checkin predicate on protocol truth (production form).
pub fn checkin_predicate(p: &ProtoState) -> bool {
    p.is_clean()
}

/// The predicate the pool applies (production: [`checkin_predicate`] ∧ transport idle).
fn reusable<C: PgSession>(c: &C, m: PoolMutations) -> bool {
    if m.always_reusable {
        return true;
    }
    let p = c.proto();
    if !m.checkin_ignores_txn && !m.checkin_ignores_objects {
        return checkin_predicate(p) && c.transport_idle();
    }
    let txn_ok = m.checkin_ignores_txn || p.txn_status() == Some(TxnStatus::Idle);
    let obj_ok =
        m.checkin_ignores_objects || (p.open_statements().next().is_none() && p.open_portals().next().is_none());
    p.unrecoverable().is_none()
        && p.outstanding() == 0
        && !p.skip_until_sync()
        && txn_ok
        && obj_ok
        && c.transport_idle()
}

/// How the request that held the connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Release {
    /// The handler finished (after its commit point, or read-only).
    Completed,
    /// The handler returned an error or a statement failed, before the commit point (NC3 "left mid-protocol"
    /// applies iff the predicate fails).
    HandlerError,
    /// The request was cancelled before its commit point (NC3 "touched by a cancelled request": always quarantined).
    Cancelled,
}

/// What became of a released connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Released {
    /// Ordinary checkin; marked for reset at its next checkout.
    CheckedIn,
    /// Quarantined, recovered within the budget, checked in (already reset).
    Recovered { ticks: u64 },
    /// Quarantined or failed the predicate, then discarded (CancelRequest + Terminate).
    Discarded,
    /// Passed, but closed instead of kept (retired epoch or idle cap); Terminate only.
    Closed,
}

/// NC4 charge reasons.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charge {
    /// Quarantine time, in op-budget units (at least 1).
    Quarantine,
    /// A discard after quarantine ([`DISCARD_COST`]).
    Discard,
}

/// Observation hooks of the release path (metrics, audit, oracle events). All default to no-ops.
pub trait Nc3Observer<C> {
    fn quarantine(&mut self, _id: ConnId) {}
    fn cancel_request(&mut self, _id: ConnId) {}
    fn gen_bump(&mut self, _id: ConnId, _gen: u64) {}
    /// Charge the releasing principal (NC4). The host must debit it.
    fn charge(&mut self, _cost: u64, _why: Charge) {}
    fn recover(&mut self, _id: ConnId, _ticks: u64, _completed: bool) {}
    /// The connection is about to become idle (called under the pool lock; must not re-enter the pool).
    fn checkin(&mut self, _id: ConnId, _conn: &C) {}
    fn discard(&mut self, _id: ConnId) {}
    /// Closed with Terminate after passing (retired epoch or idle cap).
    fn closed(&mut self, _id: ConnId) {}
}

/// An observer that records nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoObserver;

impl<C> Nc3Observer<C> for NoObserver {}

/// Run one recovery/reset statement to its ReadyForQuery. True iff it completed without a server error and the
/// running total stays within `budget`.
fn statement<C: PgSession>(c: &mut C, sql: &str, budget: u64, ticks: &mut u64) -> bool {
    round_trip(c, budget, ticks, |c, left| c.send_simple(sql, left))
}

/// Write one message group with `send`, then read through its ReadyForQuery. True iff no server error and the running
/// total stays within `budget`.
fn round_trip<C: PgSession>(
    c: &mut C,
    budget: u64,
    ticks: &mut u64,
    send: impl FnOnce(&mut C, u64) -> Result<u64, wire::Error>,
) -> bool {
    let errors = c.proto().errors();
    match send(c, budget.saturating_sub(*ticks)) {
        Ok(cost) => *ticks = ticks.saturating_add(cost),
        Err(_) => return false,
    }
    while c.proto().outstanding() > 0 {
        match c.read_one(budget.saturating_sub(*ticks)) {
            Ok(cost) => *ticks = ticks.saturating_add(cost),
            Err(_) => return false,
        }
    }
    c.proto().errors() == errors && *ticks <= budget
}

impl<C: PgSession> Pool<C> {
    /// Release a checkout under NC3. `op_budget` is the request's op budget (T_recover), in the session's units.
    pub fn release(&self, co: Checkout<C>, how: Release, op_budget: u64, obs: &mut dyn Nc3Observer<C>) -> Released {
        let m = self.muts();
        let (id, key, mut conn, lease) = co.into_parts();
        let clean = reusable(&conn, m);
        if clean && (how != Release::Cancelled || m.cancelled_session_no_discard) {
            return self.ordinary(id, &key, conn, lease, obs);
        }
        obs.quarantine(id);
        let budget = op_budget;
        let mut ticks: u64 = 0;
        let mut ok = conn.proto().unrecoverable().is_none();
        if m.reuse_after_cancelrequest && conn.cancel_request().is_ok() {
            obs.cancel_request(id);
        }
        // 1. Drain every outstanding reply, never with a CancelRequest.
        if ok && conn.proto().skip_until_sync() {
            match conn.send_sync(budget) {
                Ok(cost) => ticks = ticks.saturating_add(cost),
                Err(_) => ok = false,
            }
        }
        while ok && conn.proto().outstanding() > 0 {
            match conn.read_one(budget.saturating_sub(ticks)) {
                Ok(cost) => {
                    ticks = ticks.saturating_add(cost);
                    ok = ticks <= budget;
                }
                Err(_) => ok = false,
            }
        }
        // 2. ROLLBACK if the server-reported txn status is not I.
        if ok && conn.proto().txn_status() != Some(TxnStatus::Idle) {
            ok = statement(&mut conn, ROLLBACK, budget, &mut ticks);
        }
        // 3. One pipelined round trip: Close of every named statement/portal the mirror lists (txn is I now, so
        //    Close is accepted; this keeps the mirror exact), then DISCARD ALL (session GUCs, temp objects, advisory
        //    locks, and anything the mirror cannot see).
        if ok {
            let errors = conn.proto().errors();
            let mut objs: Vec<(u8, String)> = conn.proto().open_statements().map(|n| (b'S', n.to_owned())).collect();
            objs.extend(conn.proto().open_portals().map(|n| (b'P', n.to_owned())));
            for (kind, name) in objs {
                match conn.send_close(kind, &name, budget.saturating_sub(ticks)) {
                    Ok(cost) => ticks = ticks.saturating_add(cost),
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok && !m.recovery_no_discard_all {
                match conn.send_simple(DISCARD_ALL, budget.saturating_sub(ticks)) {
                    Ok(cost) => ticks = ticks.saturating_add(cost),
                    Err(_) => ok = false,
                }
            }
            while ok && conn.proto().outstanding() > 0 {
                match conn.read_one(budget.saturating_sub(ticks)) {
                    Ok(cost) => ticks = ticks.saturating_add(cost),
                    Err(_) => ok = false,
                }
            }
            ok = ok && conn.proto().errors() == errors && ticks <= budget;
        }
        // 4. Driver cache-generation bump.
        if ok {
            let g = conn.bump_generation();
            obs.gen_bump(id, g);
        }
        let charged = ticks.min(budget).max(1);
        if !m.quarantine_not_charged {
            obs.charge(charged, Charge::Quarantine);
        }
        obs.recover(id, charged, ok);
        if ok && reusable(&conn, m) {
            match self.idle_insert(id, &key, conn, lease, false, |c| obs.checkin(id, c)) {
                Idled::Kept => Released::Recovered { ticks: charged },
                Idled::Closed => {
                    obs.closed(id);
                    Released::Closed
                }
            }
        } else {
            Self::discard(id, conn, lease, obs);
            if !m.quarantine_not_charged {
                obs.charge(DISCARD_COST, Charge::Discard);
            }
            Released::Discarded
        }
    }

    fn ordinary(&self, id: ConnId, key: &PoolKey, conn: C, lease: Lease<C>, obs: &mut dyn Nc3Observer<C>) -> Released {
        if !reusable(&conn, self.muts()) {
            Self::discard(id, conn, lease, obs);
            return Released::Discarded;
        }
        match self.idle_insert(id, key, conn, lease, true, |c| obs.checkin(id, c)) {
            Idled::Kept => Released::CheckedIn,
            Idled::Closed => {
                obs.closed(id);
                Released::Closed
            }
        }
    }

    /// NC3 discard: CancelRequest so the orphan backend stops, then Terminate; the connection is consumed.
    fn discard(id: ConnId, mut conn: C, lease: Lease<C>, obs: &mut dyn Nc3Observer<C>) {
        if conn.cancel_request().is_ok() {
            obs.cancel_request(id);
        }
        conn.close();
        drop(lease);
        obs.discard(id);
    }
}

/// Why a recycle reset failed. The checkout stays unusable; release it with [`Release::HandlerError`].
#[derive(Debug)]
pub enum ResetError {
    Wire(wire::Error),
    /// DISCARD ALL answered with an error.
    Server,
    /// `reset_finish` without a reset in flight.
    NotSent,
}

impl fmt::Display for ResetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResetError::Wire(e) => write!(f, "recycle reset: {e}"),
            ResetError::Server => write!(f, "recycle reset: DISCARD ALL failed"),
            ResetError::NotSent => write!(f, "recycle reset: nothing in flight"),
        }
    }
}

impl std::error::Error for ResetError {}

impl<C: PgSession> Checkout<C> {
    /// C8 reset on recycle, step 1: write DISCARD ALL if this checkout needs a reset. `Ok(false)`: none needed.
    /// The host checks its cancel token between this and [`Checkout::reset_finish`].
    pub fn reset_send(&mut self, op_budget: u64) -> Result<bool, ResetError> {
        if !self.needs_reset || self.reset_in_flight.is_some() {
            return Ok(false);
        }
        let errors = self.conn.proto().errors();
        self.conn.send_simple(DISCARD_ALL, op_budget).map_err(ResetError::Wire)?;
        self.needs_reset = false;
        self.reset_in_flight = Some(errors);
        Ok(true)
    }

    /// C8 reset on recycle, step 2: read the reply, bump the cache generation, make the session reachable.
    pub fn reset_finish(&mut self, op_budget: u64) -> Result<u64, ResetError> {
        let errors = self.reset_in_flight.ok_or(ResetError::NotSent)?;
        let mut spent: u64 = 0;
        while self.conn.proto().outstanding() > 0 {
            let cost = self.conn.read_one(op_budget.saturating_sub(spent)).map_err(ResetError::Wire)?;
            spent = spent.saturating_add(cost);
        }
        if self.conn.proto().errors() != errors {
            return Err(ResetError::Server); // reset_in_flight stays set: the session remains unreachable
        }
        self.reset_in_flight = None;
        Ok(self.conn.bump_generation())
    }
}

// ------------------------------------------------------------------------------------------------ real session

/// A pooled PG v3 connection with its driver-side cache generation.
#[derive(Debug)]
pub struct PgConn {
    conn: Connection,
    generation: u64,
}

impl PgConn {
    pub fn new(conn: Connection) -> PgConn {
        PgConn { conn, generation: 0 }
    }
    pub fn connection(&mut self) -> &mut Connection {
        &mut self.conn
    }
    pub fn connection_ref(&self) -> &Connection {
        &self.conn
    }
}

fn deadline_ms(left: u64) -> Instant {
    Instant::now() + Duration::from_millis(left)
}

fn elapsed_ms(t0: Instant) -> u64 {
    u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX)
}

impl Pooled for PgConn {
    fn close(self) {
        self.conn.terminate(TERMINATE_TIMEOUT);
    }
}

impl PgSession for PgConn {
    fn proto(&self) -> &ProtoState {
        self.conn.state()
    }
    fn transport_idle(&self) -> bool {
        self.conn.is_reusable()
    }
    fn read_one(&mut self, left: u64) -> Result<u64, wire::Error> {
        let t0 = Instant::now();
        self.conn.read_event(deadline_ms(left))?;
        Ok(elapsed_ms(t0))
    }
    fn send_sync(&mut self, left: u64) -> Result<u64, wire::Error> {
        let t0 = Instant::now();
        let mut p = Pipeline::default();
        p.sync();
        self.conn.send(p, deadline_ms(left))?;
        Ok(elapsed_ms(t0))
    }
    fn send_simple(&mut self, sql: &str, left: u64) -> Result<u64, wire::Error> {
        let t0 = Instant::now();
        let mut p = Pipeline::default();
        p.query(sql)?;
        self.conn.send(p, deadline_ms(left))?;
        Ok(elapsed_ms(t0))
    }
    fn send_close(&mut self, kind: u8, name: &str, left: u64) -> Result<u64, wire::Error> {
        let t0 = Instant::now();
        let mut p = Pipeline::default();
        if kind == b'S' {
            p.close_statement(name)?;
        } else {
            p.close_portal(name)?;
        }
        p.sync();
        self.conn.send(p, deadline_ms(left))?;
        Ok(elapsed_ms(t0))
    }
    fn cancel_request(&mut self) -> Result<(), wire::Error> {
        let key = self.conn.cancel_key().ok_or(wire::Error::Usage("no BackendKeyData".into()))?;
        wire::send_cancel(key, CANCEL_REQUEST_TIMEOUT)
    }
    fn generation(&self) -> u64 {
        self.generation
    }
    fn bump_generation(&mut self) -> u64 {
        self.generation = self.generation.saturating_add(1);
        self.generation
    }
}

/// DST seam: a detached [`ProtoState`] driven by a simulated server (oracle subjects and tests only). It exercises
/// the same protocol mirror the real client uses; it never touches a [`Connection`].
#[doc(hidden)]
pub mod sim {
    use crate::wire::{Backend, Event, Expect, ProtoState, TxnStatus, Unrecoverable};

    #[derive(Clone, Debug, Default)]
    pub struct SimProto {
        st: ProtoState,
    }

    impl SimProto {
        /// A started session (startup ended with ReadyForQuery `s`).
        pub fn started(s: TxnStatus) -> SimProto {
            let mut st = ProtoState::default();
            st.started(s);
            SimProto { st }
        }
        /// A frontend message that expects `e` is about to be written.
        pub fn sent(&mut self, e: Expect) {
            self.st.sent(e);
        }
        /// One backend message arrived.
        pub fn on_backend(&mut self, m: &Backend) -> Result<Event, Unrecoverable> {
            self.st.on_backend(m)
        }
        /// Terminate was sent.
        pub fn closed(&mut self) {
            self.st.mark(Unrecoverable::Closed);
        }
        pub fn state(&self) -> &ProtoState {
            &self.st
        }
    }
}
