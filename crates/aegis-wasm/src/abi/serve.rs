//! One F14 request in a fresh Store and instance, driven by the worker <-> supervisor frames (F14 Part 2).
//!
//! [`F14Worker`] is the per-process state of a zygote or cordon: the engine, the module resolved once against the
//! F14 Linker (`InstancePre`, no compiler state), and the boot ceilings. [`Session`] is one connection. Per request
//! [`Session::serve_one`] reads `request` and its `body-chunk`s, applies `min(frame limits, boot ceilings)`, builds a
//! new Store with a fresh handle table (new generation), the limiter at the request's memory cap, fuel and the epoch
//! deadline armed before instantiation (a start function runs under the same bounds), runs `handle()`, sends
//! `resp-end` and drops the Store. Nothing of a request survives it: handles die with the request.
//!
//! Frames out of order (anything but a well-formed `request` when idle, anything but a `body-chunk` or `cancel` for
//! the current req-id while the body arrives, anything but the expected `data-reply` or a `cancel` while a data_run
//! waits) end the session without a reply; the supervisor sees a worker death (F14: a decode failure kills the
//! worker). A `cancel` of the current request drops it and sends nothing more for it. Requests on one session are
//! served one at a time.
#![forbid(unsafe_code)]

use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicU64, Ordering};

use wasmtime::{InstancePre, Linker, Module, Store, Trap};

use super::frame::{self, End, FRAME_MAX_DEFAULT, FRAME_MAX_MAX, FRAME_MAX_MIN, Inbound, WireLimits};
use super::host::{self, Abort, Handles, Quotas, Recv, ReqState, Transport};
use super::mutant::{self, Mutant};
use crate::engine::{P2Engine, P2Limits, epoch_deadline_ticks};
use crate::store::{RequestLimits, TrapKind, WorkerError};

/// Largest request body the worker buffers (bytes). A larger body ends the session (decode failure). The F8
/// `max_body_bytes` maximum is larger; a P2 route needs a supervisor-side cap at or below this value.
pub const MAX_REQ_BODY: usize = 64 << 20;

/// Engine, pre-resolved module and boot ceilings of one zygote or cordon.
pub struct F14Worker {
    engine: P2Engine,
    pre: InstancePre<ReqState>,
    ceiling: P2Limits,
    frame_max: usize,
}

impl std::fmt::Debug for F14Worker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("F14Worker")
            .field("ceiling", &self.ceiling)
            .field("frame_max", &self.frame_max)
            .finish_non_exhaustive()
    }
}

impl F14Worker {
    /// Checks `module` against the F14 shape (again: the `.cwasm` was checked at compile) and resolves it against
    /// the F14 Linker once. `ceiling` holds the boot ceilings for fuel, wall and memory (the memory ceiling should be
    /// the engine's pooled slot size).
    pub fn new(engine: &P2Engine, module: &Module, ceiling: P2Limits) -> Result<Self, WorkerError> {
        super::check_module(module).map_err(|e| WorkerError::Link(e.to_string()))?;
        let mut linker = Linker::<ReqState>::new(engine.wasmtime());
        host::define(&mut linker).map_err(|e| WorkerError::Link(e.to_string()))?;
        let pre = linker.instantiate_pre(module).map_err(|e| WorkerError::Link(format!("{e:#}")))?;
        Ok(Self { engine: engine.clone(), pre, ceiling, frame_max: FRAME_MAX_DEFAULT })
    }

    /// Sets the frame cap (F8 `p2.frame_max_bytes`, bounded 4 KiB..=1 MiB; default 64 KiB).
    pub fn with_frame_max(mut self, n: usize) -> Result<Self, WorkerError> {
        if !(FRAME_MAX_MIN..=FRAME_MAX_MAX).contains(&n) {
            return Err(WorkerError::Link(format!("frame_max_bytes {n} outside {FRAME_MAX_MIN}..={FRAME_MAX_MAX}")));
        }
        self.frame_max = n;
        Ok(self)
    }

    /// The frame cap.
    pub fn frame_max(&self) -> usize {
        self.frame_max
    }

    /// The engine.
    pub fn engine(&self) -> &P2Engine {
        &self.engine
    }

    /// A session over one connection.
    pub fn session<T: Transport + 'static>(&self, io: T) -> Session<'_> {
        Session { worker: self, io: Some(Box::new(io)), prev_generation: 0, carry: None }
    }
}

/// Why a session ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Closed {
    /// The supervisor closed the connection between requests or mid-request.
    Eof,
    /// An I/O error, an oversized message, or a frame that could not be sent.
    Io,
    /// A frame that does not decode or is out of order (F14 decode failure).
    Decode,
    /// The request's fuel, wall or memory limit is outside the F8 bounds.
    Limits,
    /// The caller's pre-run step (e.g. arming the wall timer) failed.
    PreRun,
}

/// What one [`Session::serve_one`] call did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Served {
    /// The request ran and `resp-end` was sent.
    Answered {
        /// req-id.
        rid: u64,
        /// How it ended.
        end: End,
        /// Fuel consumed (untrusted report; accounting only).
        fuel_used: u64,
    },
    /// The supervisor cancelled the request; nothing more is sent for it.
    Cancelled {
        /// req-id.
        rid: u64,
    },
    /// The session is over; nothing was sent for the current request.
    Closed(Closed),
}

/// One connection to the supervisor.
pub struct Session<'w> {
    worker: &'w F14Worker,
    io: Option<Box<dyn Transport>>,
    prev_generation: u16,
    carry: Option<Handles>,
}

impl std::fmt::Debug for Session<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").field("open", &self.io.is_some()).finish_non_exhaustive()
    }
}

/// A per-request generation in 1..=65535, never equal to `prev` (the session's previous request).
fn draw_generation(prev: u16) -> u16 {
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let h = RandomState::new().hash_one((nanos, std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let g = u16::try_from(h & 0xffff).unwrap_or(1).max(1);
    if g != prev {
        g
    } else if g == u16::MAX {
        1
    } else {
        g.saturating_add(1)
    }
}

fn bits(x: i32) -> u32 {
    u32::from_ne_bytes(x.to_ne_bytes())
}

fn classify(e: &wasmtime::Error, limit_hit: bool) -> TrapKind {
    match e.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => TrapKind::Fuel,
        Some(Trap::Interrupt) => TrapKind::Wall,
        Some(_) => TrapKind::Wasm,
        None if limit_hit => TrapKind::Memory,
        None => TrapKind::Wasm,
    }
}

impl Session<'_> {
    /// Sends one frame (`ready`, `layout`) outside a request.
    pub fn send(&mut self, frame: &[u8]) -> bool {
        self.io.as_mut().is_some_and(|io| io.send(frame))
    }

    fn recv(&mut self) -> Result<Vec<u8>, Closed> {
        let max = self.worker.frame_max;
        match self.io.as_mut().map(|io| io.recv(max)) {
            Some(Recv::Frame(f)) => Ok(f),
            Some(Recv::Eof) => Err(Closed::Eof),
            Some(Recv::Bad) | None => Err(Closed::Io),
        }
    }

    /// Serves the next request. `pre_run` runs with the effective limits after the body has arrived and before
    /// the instance is created (the fork child arms `ITIMER_REAL` there); `false` ends the session.
    pub fn serve_one(&mut self, pre_run: impl FnOnce(&RequestLimits) -> bool) -> Served {
        match self.read_request() {
            Ok(Ok((rid, wl, head, body))) => self.run(rid, wl, head, body, pre_run),
            Ok(Err(rid)) => Served::Cancelled { rid },
            Err(c) => Served::Closed(c),
        }
    }

    /// Serves requests until the session ends (a cordon connection); returns why it ended.
    pub fn serve_all(&mut self) -> Closed {
        loop {
            if let Served::Closed(c) = self.serve_one(|_| true) {
                return c;
            }
        }
    }

    /// `request` + body: `Ok(Ok(..))`, a cancelled request `Ok(Err(rid))`, or the session ends.
    #[allow(clippy::type_complexity)]
    fn read_request(&mut self) -> Result<Result<(u64, WireLimits, Vec<u8>, Vec<u8>), u64>, Closed> {
        let (rid, wl, head) = loop {
            let f = self.recv()?;
            match frame::decode_s2w(&f) {
                Some(Inbound::Request { rid, limits, head }) => break (rid, limits, head.to_vec()),
                // A cancel that crossed the previous request's resp-end: nothing is live, nothing to do.
                Some(Inbound::Cancel { .. }) => {}
                _ => return Err(Closed::Decode),
            }
        };
        let mut body = Vec::new();
        loop {
            let f = self.recv()?;
            match frame::decode_s2w(&f) {
                Some(Inbound::BodyChunk { rid: r, chunk, last }) if r == rid => {
                    if body.len().saturating_add(chunk.len()) > MAX_REQ_BODY {
                        return Err(Closed::Decode);
                    }
                    body.extend_from_slice(chunk);
                    if last {
                        return Ok(Ok((rid, wl, head, body)));
                    }
                }
                Some(Inbound::Cancel { rid: r }) if r == rid => return Ok(Err(rid)),
                _ => return Err(Closed::Decode),
            }
        }
    }

    fn run(
        &mut self,
        rid: u64,
        wl: WireLimits,
        head: Vec<u8>,
        body: Vec<u8>,
        pre_run: impl FnOnce(&RequestLimits) -> bool,
    ) -> Served {
        let w = self.worker;
        let Some(requested) =
            u32::try_from(wl.memory_mib).ok().and_then(|m| P2Limits::new(wl.fuel, wl.wall_ms, m).ok())
        else {
            return Served::Closed(Closed::Limits);
        };
        let limits = RequestLimits::clamped(&requested, &w.ceiling);
        let max = WireLimits::F8_MAX;
        let quotas = Quotas {
            host_calls: wl.max_host_calls.min(max.max_host_calls),
            data_runs: wl.max_data_runs.min(max.max_data_runs),
            data_bytes: wl.max_data_bytes.min(max.max_data_bytes),
            resp_bytes: wl.max_resp_bytes.min(max.max_resp_bytes),
            log_bytes: wl.max_log_bytes.min(max.max_log_bytes),
        };
        if !pre_run(&limits) {
            return Served::Closed(Closed::PreRun);
        }
        let Some(io) = self.io.take() else { return Served::Closed(Closed::Io) };
        let handles = match (mutant::is(Mutant::HandleNotCleared), self.carry.take()) {
            (true, Some(h)) => h, // MUTANT handle-not-cleared: the previous request's table and generation
            _ => Handles::new(draw_generation(self.prev_generation)),
        };
        self.prev_generation = u16::try_from(handles.generation).unwrap_or(0);
        let state = ReqState {
            rid,
            quotas,
            memory_cap: usize::try_from(limits.memory_bytes()).unwrap_or(usize::MAX),
            limit_hit: false,
            head,
            body,
            body_off: 0,
            handles,
            calls: 0,
            data_runs: 0,
            data_bytes: 0,
            resp_bytes: 0,
            log_bytes: 0,
            resp_started: false,
            fault: None,
            abort: None,
            frame_max: w.frame_max,
            io,
        };
        let mut store = Store::new(w.engine.wasmtime(), state);
        store.limiter(|s| s);
        let unbounded = mutant::is(Mutant::NoFuelNoEpoch);
        // MUTANT no-fuel-no-epoch: practically unlimited fuel and no epoch deadline.
        let fuel = if unbounded { u64::MAX / 4 } else { limits.fuel() };
        let fuel_ok = store.set_fuel(fuel).is_ok();
        store.set_epoch_deadline(if unbounded { u64::MAX / 4 } else { epoch_deadline_ticks(limits.wall_ms()) });
        store.epoch_deadline_trap();
        let res = if fuel_ok {
            w.pre
                .instantiate(&mut store)
                .and_then(|inst| inst.get_typed_func::<(), i32>(&mut store, super::EXPORT_HANDLE)?.call(&mut store, ()))
        } else {
            Err(wasmtime::Error::msg("fuel could not be armed"))
        };
        let left = store.get_fuel().unwrap_or(0);
        let fuel_used = fuel.saturating_sub(left).min(limits.fuel());
        let st = store.into_data();
        let end = match (&res, st.abort, st.fault) {
            (_, Some(Abort::Cancelled), _) => {
                self.io = Some(st.io);
                return Served::Cancelled { rid };
            }
            (_, Some(Abort::Closed), _) => return Served::Closed(Closed::Io),
            (Ok(v), None, _) => End::Code(bits(*v)),
            (Err(_), None, Some(code)) => End::Trap(code),
            (Err(e), None, None) => End::Trap(classify(e, st.limit_hit).code()),
        };
        if mutant::is(Mutant::HandleNotCleared) {
            self.carry = Some(st.handles); // MUTANT handle-not-cleared
        }
        let mut io = st.io;
        if !io.send(&frame::resp_end(rid, end, fuel_used)) {
            return Served::Closed(Closed::Io);
        }
        self.io = Some(io);
        Served::Answered { rid, end, fuel_used }
    }
}
