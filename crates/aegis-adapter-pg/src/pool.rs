//! Connection pool keyed by the whole connection scope (P4-pg-003; CRS C2/C3/C5/C8, R-DB-5).
//!
//! * **Key.** [`PoolKey`] = (principal, tenant, login role, epoch), `derive(Hash, Eq, Ord)` over every field. An idle
//!   connection is handed out only for a key equal to the one it was created for, so a connection is never reused
//!   across principals (C2), tenants (R-DB-5) or auth/config epochs (C5). [`Pool::retire_before`] closes idle
//!   connections of older epochs and refuses acquisitions and checkins at them.
//! * **Bound.** At most [`PoolConfig::max_open`] connections exist (checked out, quarantined or idle). An acquire at
//!   the bound evicts the least recently used idle connection of another key, else waits until
//!   [`PoolConfig::acquire_timeout`] (back-pressure, never an unbounded queue).
//! * **Leases.** A [`Checkout`] ends in exactly one of: the NC3 release (`Pool::release`, in [`crate::checkin`]),
//!   [`Pool::put_back`] for resources without protocol state ([`PlainReuse`]), or a drop. A dropped checkout closes
//!   its connection and frees its slot; it never returns a connection to the pool (fail closed).
//! * **Reset on recycle (C8).** A connection that goes idle after ordinary use is marked for reset; the next
//!   checkout of it must run the reset (DISCARD ALL + driver cache-generation bump, [`crate::checkin`]) before the
//!   session is reachable (`Checkout::session`). A connection that just passed NC3 recovery was reset already.
//!
//! The pool never sends anything on a connection by itself; protocol work (recovery, reset, discard with a
//! CancelRequest) is in [`crate::checkin`].

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use aegis_types::TenantId;

/// Auth/config epoch (CRS C5): bumped on every auth or config change.
pub type Epoch = u64;

/// Pool-assigned connection identity (unique per pool, never reused).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnId(u64);

impl ConnId {
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ConnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Longest principal identity accepted in a key (bytes).
pub const MAX_PRINCIPAL_LEN: usize = 512;
/// Longest login role accepted in a key (bytes; PG identifiers are at most 63).
pub const MAX_ROLE_LEN: usize = 63;

/// Everything that scopes an upstream connection. Two keys are equal iff every field is equal.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PoolKey {
    principal: Box<[u8]>,
    tenant: TenantId,
    role: Box<str>,
    epoch: Epoch,
}

impl fmt::Debug for PoolKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoolKey")
            .field("principal", &format_args!("<{} bytes>", self.principal.len()))
            .field("tenant", &self.tenant)
            .field("role", &self.role)
            .field("epoch", &self.epoch)
            .finish()
    }
}

/// Why a [`PoolKey`] was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    EmptyPrincipal,
    PrincipalTooLong,
    EmptyRole,
    RoleTooLong,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::EmptyPrincipal => write!(f, "empty principal in pool key"),
            KeyError::PrincipalTooLong => write!(f, "principal exceeds {MAX_PRINCIPAL_LEN} bytes"),
            KeyError::EmptyRole => write!(f, "empty login role in pool key"),
            KeyError::RoleTooLong => write!(f, "login role exceeds {MAX_ROLE_LEN} bytes"),
        }
    }
}

impl std::error::Error for KeyError {}

impl PoolKey {
    /// `principal` is the canonical identity bytes of the request's principal (the host derives them from the
    /// verified `Principal`); `role` is the per-tenant login role the connection authenticates as.
    pub fn new(principal: &[u8], tenant: TenantId, role: &str, epoch: Epoch) -> Result<PoolKey, KeyError> {
        if principal.is_empty() {
            return Err(KeyError::EmptyPrincipal);
        }
        if principal.len() > MAX_PRINCIPAL_LEN {
            return Err(KeyError::PrincipalTooLong);
        }
        if role.is_empty() {
            return Err(KeyError::EmptyRole);
        }
        if role.len() > MAX_ROLE_LEN {
            return Err(KeyError::RoleTooLong);
        }
        Ok(PoolKey { principal: principal.into(), tenant, role: role.into(), epoch })
    }
    pub fn principal(&self) -> &[u8] {
        &self.principal
    }
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub fn role(&self) -> &str {
        &self.role
    }
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }
}

/// Pool limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolConfig {
    /// Connections that may exist at once (checked out + quarantined + idle). At least 1.
    pub max_open: usize,
    /// Idle connections kept per key. 0 = never keep idle connections.
    pub max_idle_per_key: usize,
    /// Longest wait for a slot at the bound.
    pub acquire_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        PoolConfig { max_open: 16, max_idle_per_key: 2, acquire_timeout: Duration::from_millis(500) }
    }
}

/// Self-test mutations for `oracles/cancel-sweep` and `oracles/crs-diff` (subject `--mutate` / `--mutant`). Each one breaks a required property, so
/// production code must use [`Pool::new`], which is [`PoolMutations::NONE`].
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolMutations {
    /// The checkin predicate returns "reusable" for every connection.
    pub always_reusable: bool,
    /// The checkin predicate ignores the server-reported txn status (sqlx #4393 shape).
    pub checkin_ignores_txn: bool,
    /// The checkin predicate ignores open server objects (tokio-postgres #1374 shape).
    pub checkin_ignores_objects: bool,
    /// The epoch is dropped from the pool key (and so from epoch retirement).
    pub pool_key_no_epoch: bool,
    /// Recovery sends a CancelRequest to speed up the drain, then checks the connection back in.
    pub reuse_after_cancelrequest: bool,
    /// Recovery drains and rolls back but skips DISCARD ALL.
    pub recovery_no_discard_all: bool,
    /// Quarantine time and discards are not charged.
    pub quarantine_not_charged: bool,
    /// A cancelled connection that passes the checkin predicate gets the ordinary checkin (pre-widening NC3).
    pub cancelled_session_no_discard: bool,
    /// An ordinary checkin does not mark the connection for reset, so the next checkout skips the C8 recycle reset
    /// (DISCARD ALL + cache-generation bump); oracles/crs-diff `no-reset-on-recycle`.
    pub recycle_no_reset: bool,
}

impl PoolMutations {
    pub const NONE: PoolMutations = PoolMutations {
        always_reusable: false,
        checkin_ignores_txn: false,
        checkin_ignores_objects: false,
        pool_key_no_epoch: false,
        reuse_after_cancelrequest: false,
        recovery_no_discard_all: false,
        quarantine_not_charged: false,
        cancelled_session_no_discard: false,
        recycle_no_reset: false,
    };
}

/// A pooled resource that can be closed. For a PG session `close` sends Terminate (no CancelRequest: only idle,
/// clean connections are closed this way; the NC3 discard path is in [`crate::checkin`]).
pub trait Pooled {
    fn close(self);
}

/// Marker for resources with no protocol state, which may be returned to the pool as they are. PG sessions never
/// implement it: they go back only through the NC3 release.
pub trait PlainReuse: Pooled {}

/// Why a connection could not be acquired.
#[derive(Debug)]
pub enum AcquireError<E> {
    /// The key's epoch has been retired (an auth/config change happened since the request was admitted).
    StaleEpoch,
    /// No slot became free before the acquire timeout.
    Exhausted,
    /// Opening a new connection failed.
    Connect(E),
}

impl<E: fmt::Display> fmt::Display for AcquireError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AcquireError::StaleEpoch => write!(f, "pool key epoch retired"),
            AcquireError::Exhausted => write!(f, "connection pool exhausted"),
            AcquireError::Connect(e) => write!(f, "connect: {e}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for AcquireError<E> {}

/// What happened to a connection handed back with [`Pool::put_back`] or the NC3 idle insert.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Idled {
    /// Kept idle under its key.
    Kept,
    /// Closed: its epoch is retired, or the key already holds `max_idle_per_key` idle connections.
    Closed,
}

struct IdleConn<C> {
    id: ConnId,
    conn: C,
    needs_reset: bool,
    stamp: u64,
}

struct Inner<C> {
    idle: BTreeMap<PoolKey, Vec<IdleConn<C>>>,
    open: usize,
    min_epoch: Epoch,
    next_id: u64,
    clock: u64,
}

struct Shared<C> {
    cfg: PoolConfig,
    muts: PoolMutations,
    inner: Mutex<Inner<C>>,
    freed: Condvar,
}

impl<C> Shared<C> {
    fn lock(&self) -> MutexGuard<'_, Inner<C>> {
        // panic = "abort" in release: a poisoned lock cannot be observed there; in tests the state stays consistent
        // because no code path panics while holding it.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The pool (a cheap, clonable handle; `Send + Sync` when `C: Send`).
pub struct Pool<C> {
    shared: Arc<Shared<C>>,
}

impl<C> Clone for Pool<C> {
    fn clone(&self) -> Self {
        Pool { shared: Arc::clone(&self.shared) }
    }
}

impl<C> fmt::Debug for Pool<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let g = self.shared.lock();
        f.debug_struct("Pool")
            .field("cfg", &self.shared.cfg)
            .field("open", &g.open)
            .field("idle", &g.idle.values().map(Vec::len).sum::<usize>())
            .field("min_epoch", &g.min_epoch)
            .finish()
    }
}

/// The slot a checked-out connection holds. Dropping it frees the slot.
pub(crate) struct Lease<C> {
    shared: Arc<Shared<C>>,
    armed: bool,
}

impl<C> Drop for Lease<C> {
    fn drop(&mut self) {
        if self.armed {
            let mut g = self.shared.lock();
            g.open = g.open.saturating_sub(1);
            drop(g);
            self.shared.freed.notify_one();
        }
    }
}

impl<C> Lease<C> {
    /// The connection keeps its slot (it goes idle).
    fn disarm(mut self) {
        self.armed = false;
    }
}

/// A checked-out connection. It must end in exactly one release (see the module docs); dropping it closes the
/// connection (its own `Drop`) and frees the slot.
#[must_use = "a checkout must be released through the NC3 path (Pool::release) or put back"]
pub struct Checkout<C> {
    id: ConnId,
    key: PoolKey,
    reused: bool,
    pub(crate) needs_reset: bool,
    /// Error count of the session when the reset's DISCARD ALL was written (reply not read yet).
    pub(crate) reset_in_flight: Option<u64>,
    pub(crate) conn: C,
    lease: Lease<C>,
}

impl<C> fmt::Debug for Checkout<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Checkout")
            .field("id", &self.id)
            .field("key", &self.key)
            .field("reused", &self.reused)
            .field("needs_reset", &self.needs_reset)
            .finish_non_exhaustive()
    }
}

/// The session of a recycled connection is not reachable until its reset (C8) completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResetPending;

impl fmt::Display for ResetPending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "recycled connection not reset yet (C8)")
    }
}

impl std::error::Error for ResetPending {}

impl<C> Checkout<C> {
    pub fn id(&self) -> ConnId {
        self.id
    }
    pub fn key(&self) -> &PoolKey {
        &self.key
    }
    /// The connection came from the idle set (it was used before under the same key).
    pub fn reused(&self) -> bool {
        self.reused
    }
    /// A reset (C8) must run before the session is reachable.
    pub fn needs_reset(&self) -> bool {
        self.needs_reset || self.reset_in_flight.is_some()
    }
    /// The session, once any recycle reset has completed.
    pub fn session(&mut self) -> Result<&mut C, ResetPending> {
        if self.needs_reset() { Err(ResetPending) } else { Ok(&mut self.conn) }
    }
    /// Read-only view of the connection (inspection only; no protocol use).
    pub fn peek(&self) -> &C {
        &self.conn
    }
    pub(crate) fn into_parts(self) -> (ConnId, PoolKey, C, Lease<C>) {
        (self.id, self.key, self.conn, self.lease)
    }
}

impl<C: Pooled> Pool<C> {
    /// A pool with production behaviour.
    pub fn new(cfg: PoolConfig) -> Pool<C> {
        Pool::new_with(cfg, PoolMutations::NONE)
    }

    /// A pool with self-test mutations (oracle subjects only).
    #[doc(hidden)]
    pub fn new_with(cfg: PoolConfig, muts: PoolMutations) -> Pool<C> {
        let cfg = PoolConfig { max_open: cfg.max_open.max(1), ..cfg };
        Pool {
            shared: Arc::new(Shared {
                cfg,
                muts,
                inner: Mutex::new(Inner { idle: BTreeMap::new(), open: 0, min_epoch: 0, next_id: 0, clock: 0 }),
                freed: Condvar::new(),
            }),
        }
    }

    pub fn config(&self) -> PoolConfig {
        self.shared.cfg
    }

    pub(crate) fn muts(&self) -> PoolMutations {
        self.shared.muts
    }

    /// The key as the pool stores it (the epoch is part of it unless the self-test mutation removes it).
    fn stored_key(&self, key: &PoolKey) -> PoolKey {
        if self.shared.muts.pool_key_no_epoch { PoolKey { epoch: 0, ..key.clone() } } else { key.clone() }
    }

    fn retired(&self, g: &Inner<C>, key: &PoolKey) -> bool {
        !self.shared.muts.pool_key_no_epoch && key.epoch < g.min_epoch
    }

    /// Check out a connection for `key`: an idle one created for an equal key (most recently used first), else a
    /// new one from `connect` (called without the pool lock held). Blocks at most `acquire_timeout` at the bound.
    pub fn acquire<E>(
        &self,
        key: &PoolKey,
        connect: impl FnOnce(&PoolKey) -> Result<C, E>,
    ) -> Result<Checkout<C>, AcquireError<E>> {
        let deadline = Instant::now() + self.shared.cfg.acquire_timeout;
        let sk = self.stored_key(key);
        let mut g = self.shared.lock();
        loop {
            if self.retired(&g, key) {
                return Err(AcquireError::StaleEpoch);
            }
            let hit = g.idle.get_mut(&sk).and_then(Vec::pop);
            if g.idle.get(&sk).is_some_and(Vec::is_empty) {
                g.idle.remove(&sk);
            }
            if let Some(ic) = hit {
                drop(g);
                return Ok(Checkout {
                    id: ic.id,
                    key: key.clone(),
                    reused: true,
                    needs_reset: ic.needs_reset,
                    reset_in_flight: None,
                    conn: ic.conn,
                    lease: Lease { shared: Arc::clone(&self.shared), armed: true },
                });
            }
            if g.open < self.shared.cfg.max_open {
                g.open = g.open.saturating_add(1);
                g.next_id = g.next_id.saturating_add(1);
                let id = ConnId(g.next_id);
                drop(g);
                let lease = Lease { shared: Arc::clone(&self.shared), armed: true };
                return match connect(key) {
                    Ok(conn) => Ok(Checkout {
                        id,
                        key: key.clone(),
                        reused: false,
                        needs_reset: false,
                        reset_in_flight: None,
                        conn,
                        lease,
                    }),
                    Err(e) => Err(AcquireError::Connect(e)), // the lease drop frees the slot
                };
            }
            // At the bound: evict the least recently used idle connection (necessarily of another key).
            if let Some(victim) = Self::take_lru(&mut g) {
                g.open = g.open.saturating_sub(1);
                drop(g);
                victim.conn.close();
                g = self.shared.lock();
                continue;
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(AcquireError::Exhausted);
            }
            g = self
                .shared
                .freed
                .wait_timeout(g, deadline.saturating_duration_since(now))
                .map(|(g, _)| g)
                .unwrap_or_else(|p| p.into_inner().0);
        }
    }

    fn take_lru(g: &mut Inner<C>) -> Option<IdleConn<C>> {
        let (k, pos) = g
            .idle
            .iter()
            .flat_map(|(k, v)| v.iter().enumerate().map(move |(i, c)| (c.stamp, k, i)))
            .min_by_key(|(s, _, _)| *s)
            .map(|(_, k, i)| (k.clone(), i))?;
        let list = g.idle.get_mut(&k)?;
        let victim = if pos < list.len() { Some(list.remove(pos)) } else { None };
        if list.is_empty() {
            g.idle.remove(&k);
        }
        victim
    }

    /// Insert a connection that has passed the checkin predicate (or has no protocol state) into the idle set.
    /// `on_kept` runs under the pool lock just before the connection becomes visible to other acquirers (the checkin
    /// observation point); it must not call back into the pool.
    pub(crate) fn idle_insert(
        &self,
        id: ConnId,
        key: &PoolKey,
        conn: C,
        lease: Lease<C>,
        needs_reset: bool,
        on_kept: impl FnOnce(&C),
    ) -> Idled {
        let sk = self.stored_key(key);
        let mut g = self.shared.lock();
        let full = g.idle.get(&sk).map_or(0, Vec::len) >= self.shared.cfg.max_idle_per_key;
        if self.retired(&g, key) || full {
            drop(g);
            conn.close();
            drop(lease); // frees the slot
            return Idled::Closed;
        }
        g.clock = g.clock.saturating_add(1);
        let stamp = g.clock;
        on_kept(&conn);
        let needs_reset = needs_reset && !self.shared.muts.recycle_no_reset;
        g.idle.entry(sk).or_default().push(IdleConn { id, conn, needs_reset, stamp });
        drop(g);
        lease.disarm(); // the idle connection keeps its slot
        self.shared.freed.notify_one();
        Idled::Kept
    }

    /// Retire every epoch below `epoch` (CRS C5): idle connections created at an older epoch are closed, and later
    /// acquisitions and checkins at an older epoch are refused. Returns the closed connections' ids.
    pub fn retire_before(&self, epoch: Epoch) -> Vec<ConnId> {
        let mut g = self.shared.lock();
        if epoch > g.min_epoch {
            g.min_epoch = epoch;
        }
        if self.shared.muts.pool_key_no_epoch {
            return Vec::new(); // the stored keys carry no epoch: nothing can be told apart
        }
        let stale: Vec<PoolKey> = g.idle.keys().filter(|k| k.epoch < epoch).cloned().collect();
        let mut closed = Vec::new();
        for k in stale {
            if let Some(list) = g.idle.remove(&k) {
                for ic in list {
                    g.open = g.open.saturating_sub(1);
                    closed.push(ic);
                }
            }
        }
        drop(g);
        let ids = closed.iter().map(|c| c.id).collect();
        for c in closed {
            c.conn.close();
        }
        self.shared.freed.notify_all();
        ids
    }

    /// Connections that exist (checked out + quarantined + idle).
    pub fn open(&self) -> usize {
        self.shared.lock().open
    }

    /// Idle connections under `key`.
    pub fn idle_for(&self, key: &PoolKey) -> usize {
        let sk = self.stored_key(key);
        self.shared.lock().idle.get(&sk).map_or(0, Vec::len)
    }

    /// Close every idle connection (shutdown).
    pub fn close_idle(&self) {
        let mut g = self.shared.lock();
        let all = std::mem::take(&mut g.idle);
        let n: usize = all.values().map(Vec::len).sum();
        g.open = g.open.saturating_sub(n);
        drop(g);
        for c in all.into_values().flatten() {
            c.conn.close();
        }
        self.shared.freed.notify_all();
    }
}

impl<C: PlainReuse> Pool<C> {
    /// Return a resource without protocol state to the idle set under its key.
    pub fn put_back(&self, co: Checkout<C>) -> Idled {
        let (id, key, conn, lease) = co.into_parts();
        self.idle_insert(id, &key, conn, lease, false, |_| {})
    }
}
