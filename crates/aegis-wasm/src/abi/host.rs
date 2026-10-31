//! The F14 host functions (Part 1) and their per-request state: handle table, quotas, limiter, transport.
//!
//! Common rules, as F14 states them: every call counts against `max_host_calls` (breach: trap 6); a pointer range
//! outside memory 0 traps (7) and copies nothing; misuse traps (7); a forged, foreign, stale or zero handle traps
//! (5); a count or byte quota breach traps (6) before anything of that call is forwarded. There are no error codes a
//! module could probe with. The first trap code a call records is the one reported in `resp-end`.
//!
//! Quota accounting (I2): `max_data_bytes` counts the op bytes (checked before the `data-run` frame is sent) and the
//! reply bytes (checked when the reply arrives, before a handle is issued); `max_resp_bytes` and `max_log_bytes`
//! count the bytes of every call and are checked before that call forwards anything, so the supervisor never sees
//! more than the quota.
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use wasmtime::{Caller, Extern, Linker, Memory, ResourceLimiter};

use super::frame::{Enc, Inbound, decode_s2w, tag};
use super::headers::resp_headers_ok;
use super::mutant::{self, Mutant};
use super::{AbiError, IMPORT_MODULE};
use crate::store::MAX_TABLE_ELEMENTS;

/// F14 trap codes reported by the host functions (1..=4 come from wasmtime, see `serve`).
pub mod trap {
    /// Handle fault (forged, foreign, stale, zero).
    pub const HANDLE: u32 = 5;
    /// Host-call, data_run, data byte, response byte or log byte quota.
    pub const QUOTA: u32 = 6;
    /// ABI misuse (pointer out of range, resp_head twice, write before head, bad header, bad level, bad status).
    pub const MISUSE: u32 = 7;
    /// test-hooks `env.host_fault` with a code other than 1 or 2.
    pub const HOST_FAULT: u32 = 8;
}

/// One received frame, end of stream, or a failure (an oversized message, an I/O error).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recv {
    /// One complete frame of at most the frame cap.
    Frame(Vec<u8>),
    /// The peer closed the connection.
    Eof,
    /// Oversized or truncated message, or an I/O error.
    Bad,
}

/// The connection to the supervisor: one SOCK_SEQPACKET message per frame (`Send`: wasmtime requires store data
/// with a ResourceLimiter to be `Send`).
pub trait Transport: Send {
    /// Sends one frame; `false` if it could not be sent whole.
    fn send(&mut self, frame: &[u8]) -> bool;
    /// Receives one frame of at most `max` bytes.
    fn recv(&mut self, max: usize) -> Recv;
}

impl Transport for UnixStream {
    fn send(&mut self, frame: &[u8]) -> bool {
        loop {
            match self.write(frame) {
                Ok(n) => return n == frame.len(),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return false,
            }
        }
    }

    fn recv(&mut self, max: usize) -> Recv {
        // A SEQPACKET message longer than the buffer is truncated to the buffer: one spare byte detects it.
        let mut buf = vec![0u8; max.saturating_add(1)];
        loop {
            match self.read(&mut buf) {
                Ok(0) => return Recv::Eof,
                Ok(n) if n > max => return Recv::Bad,
                Ok(n) => {
                    buf.truncate(n);
                    return Recv::Frame(buf);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Recv::Bad,
            }
        }
    }
}

/// The per-request quotas after the worker's ceilings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Quotas {
    pub(crate) host_calls: u64,
    pub(crate) data_runs: u64,
    pub(crate) data_bytes: u64,
    pub(crate) resp_bytes: u64,
    pub(crate) log_bytes: u64,
}

/// Per-request handle table. A handle is `(generation << 16) | slot`; the generation is drawn per request in
/// 1..=65535 (never 0, so 0 is never a handle); the slot is the data_run ordinal and is never reused.
#[derive(Clone, Debug, Default)]
pub(crate) struct Handles {
    pub(crate) generation: u32,
    slots: Vec<Option<Vec<u8>>>,
}

impl Handles {
    pub(crate) fn new(generation: u16) -> Self {
        Self { generation: u32::from(generation.max(1)), slots: Vec::new() }
    }

    fn issue(&mut self, result: Vec<u8>) -> Option<u32> {
        let slot = u32::try_from(self.slots.len()).ok().filter(|s| *s <= 0xffff)?;
        self.slots.push(Some(result));
        Some((self.generation << 16) | slot)
    }

    fn slot(&self, h: u32) -> Option<usize> {
        let (generation, slot) = (h >> 16, usize::try_from(h & 0xffff).ok()?);
        if generation == 0 || generation != self.generation {
            return None;
        }
        matches!(self.slots.get(slot), Some(Some(_))).then_some(slot)
    }
}

/// Why a request ended without a `resp-end` (nothing more is sent for it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Abort {
    /// The supervisor cancelled the request.
    Cancelled,
    /// The connection failed or the supervisor sent a frame that does not belong here.
    Closed,
}

/// Store data of one request.
pub(crate) struct ReqState {
    pub(crate) rid: u64,
    pub(crate) quotas: Quotas,
    pub(crate) memory_cap: usize,
    pub(crate) limit_hit: bool,
    pub(crate) head: Vec<u8>,
    pub(crate) body: Vec<u8>,
    pub(crate) body_off: usize,
    pub(crate) handles: Handles,
    pub(crate) calls: u64,
    pub(crate) data_runs: u64,
    pub(crate) data_bytes: u64,
    pub(crate) resp_bytes: u64,
    pub(crate) log_bytes: u64,
    pub(crate) resp_started: bool,
    pub(crate) fault: Option<u32>,
    pub(crate) abort: Option<Abort>,
    pub(crate) frame_max: usize,
    pub(crate) io: Box<dyn Transport>,
}

impl std::fmt::Debug for ReqState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReqState").field("rid", &self.rid).field("fault", &self.fault).finish_non_exhaustive()
    }
}

impl ResourceLimiter for ReqState {
    fn memory_growing(&mut self, _current: usize, desired: usize, _maximum: Option<usize>) -> wasmtime::Result<bool> {
        if mutant::is(Mutant::NoLimiter) {
            return Ok(true); // MUTANT no-limiter
        }
        let ok = desired <= self.memory_cap;
        self.limit_hit |= !ok;
        Ok(ok)
    }
    fn table_growing(&mut self, _current: usize, desired: usize, _maximum: Option<usize>) -> wasmtime::Result<bool> {
        if mutant::is(Mutant::NoLimiter) {
            return Ok(true); // MUTANT no-limiter
        }
        let ok = desired <= MAX_TABLE_ELEMENTS;
        self.limit_hit |= !ok;
        Ok(ok)
    }
    fn instances(&self) -> usize {
        1
    }
    fn tables(&self) -> usize {
        1
    }
    fn memories(&self) -> usize {
        1
    }
}

type C<'a> = Caller<'a, ReqState>;
type R<T> = wasmtime::Result<T>;

fn bits(x: i32) -> u32 {
    u32::from_ne_bytes(x.to_ne_bytes())
}

fn to_i32(x: u32) -> i32 {
    i32::from_ne_bytes(x.to_ne_bytes())
}

fn len_i32(n: usize) -> i32 {
    to_i32(u32::try_from(n).unwrap_or(u32::MAX))
}

/// Records `code` (the first one wins) and returns the error that unwinds the guest.
fn fault(c: &mut C<'_>, code: u32) -> wasmtime::Error {
    let st = c.data_mut();
    if st.fault.is_none() && st.abort.is_none() {
        st.fault = Some(code);
    }
    wasmtime::Error::msg(format!("F14 trap {code}"))
}

/// Ends the request without a `resp-end`.
fn abort(c: &mut C<'_>, why: Abort) -> wasmtime::Error {
    let st = c.data_mut();
    if st.abort.is_none() {
        st.abort = Some(why);
    }
    wasmtime::Error::msg("F14 request aborted")
}

/// Every host call counts against `max_host_calls`.
fn count(c: &mut C<'_>) -> R<()> {
    let st = c.data_mut();
    st.calls = st.calls.saturating_add(1);
    if st.calls > st.quotas.host_calls && !mutant::is(Mutant::NoHostcallQuota) {
        return Err(fault(c, trap::QUOTA));
    }
    Ok(())
}

fn memory(c: &mut C<'_>) -> R<Memory> {
    match c.get_export(super::EXPORT_MEMORY) {
        Some(Extern::Memory(m)) => Ok(m),
        _ => Err(fault(c, trap::MISUSE)),
    }
}

fn range(ptr: i32, len: usize) -> Option<std::ops::Range<usize>> {
    let p = usize::try_from(bits(ptr)).ok()?;
    Some(p..p.checked_add(len)?)
}

fn read_guest(c: &mut C<'_>, ptr: i32, len: i32) -> R<Vec<u8>> {
    let m = memory(c)?;
    let n = usize::try_from(bits(len)).unwrap_or(usize::MAX);
    let got = range(ptr, n).and_then(|r| m.data(&*c).get(r)).map(<[u8]>::to_vec);
    got.ok_or_else(|| fault(c, trap::MISUSE))
}

/// Copies `f(state)` to guest memory at `ptr`; nothing is written unless the whole range is inside memory 0.
fn write_guest(c: &mut C<'_>, ptr: i32, f: impl FnOnce(&ReqState) -> &[u8]) -> R<()> {
    let m = memory(c)?;
    let (mem, st) = m.data_and_store_mut(&mut *c);
    let src = f(st);
    match range(ptr, src.len()).and_then(|r| mem.get_mut(r)) {
        Some(dst) => {
            dst.copy_from_slice(src);
            Ok(())
        }
        None => Err(fault(c, trap::MISUSE)),
    }
}

fn send(c: &mut C<'_>, frame: &[u8]) -> R<()> {
    if c.data_mut().io.send(frame) { Ok(()) } else { Err(abort(c, Abort::Closed)) }
}

/// Sends `data` as frames `[tag, rid, (level,) chunk]`, each within the frame cap.
fn send_chunked(c: &mut C<'_>, t: u64, level: Option<u64>, data: &[u8]) -> R<()> {
    let st = c.data();
    let (rid, step) = (st.rid, st.frame_max.saturating_sub(32).max(1));
    for chunk in data.chunks(step) {
        let e = Enc::new().u(t).u(rid);
        let e = match level {
            Some(l) => e.u(l),
            None => e,
        };
        send(c, &e.bytes(chunk).finish())?;
    }
    Ok(())
}

fn slot_bytes(st: &ReqState, s: usize) -> &[u8] {
    match st.handles.slots.get(s) {
        Some(Some(r)) => r.as_slice(),
        _ => &[],
    }
}

fn handle_slot(c: &mut C<'_>, h: i32) -> R<usize> {
    match c.data().handles.slot(bits(h)) {
        Some(s) => Ok(s),
        None => Err(fault(c, trap::HANDLE)),
    }
}

/// Blocks until the `data-reply` for (`rid`, `seq`). A `cancel` for the request aborts it; anything else (another
/// req-id, another tag, a malformed or oversized frame, EOF) closes the connection.
fn await_reply(c: &mut C<'_>, seq: u64) -> R<Vec<u8>> {
    let (rid, max) = (c.data().rid, c.data().frame_max);
    let got = c.data_mut().io.recv(max);
    let Recv::Frame(f) = got else { return Err(abort(c, Abort::Closed)) };
    match decode_s2w(&f) {
        Some(Inbound::DataReply { rid: r, seq: s, result }) if r == rid && s == seq => Ok(result.to_vec()),
        Some(Inbound::Cancel { rid: r }) if r == rid => Err(abort(c, Abort::Cancelled)),
        _ => Err(abort(c, Abort::Closed)),
    }
}

/// test-hooks `env.host_fault` corruption flag (code 2): every later response body of this process is wrong.
#[cfg(feature = "test-hooks")]
static HOST_CORRUPT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether a guest called `env.host_fault(2)` in this process (test-hooks builds only).
#[cfg(feature = "test-hooks")]
pub fn host_corrupted() -> bool {
    HOST_CORRUPT.load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(feature = "test-hooks")]
fn corrupt(mut b: Vec<u8>) -> Vec<u8> {
    if host_corrupted() {
        b.iter_mut().for_each(|x| *x = !*x);
    }
    b
}

#[cfg(not(feature = "test-hooks"))]
fn corrupt(b: Vec<u8>) -> Vec<u8> {
    b
}

fn wrap(e: wasmtime::Error) -> AbiError {
    AbiError::Import(format!("linker: {e:#}"))
}

/// Defines exactly the F14 allowlist (plus `env.host_fault` in test-hooks builds, or under the extra-import
/// mutant) on `l`.
pub(crate) fn define(l: &mut Linker<ReqState>) -> Result<(), AbiError> {
    let m = IMPORT_MODULE;
    l.func_wrap(m, "req_head", |mut c: C<'_>, dst: i32, cap: i32| -> R<i32> {
        count(&mut c)?;
        let len = c.data().head.len();
        if usize::try_from(bits(cap)).unwrap_or(usize::MAX) >= len {
            write_guest(&mut c, dst, |s| &s.head)?;
        }
        Ok(len_i32(len))
    })
    .map_err(wrap)?;
    l.func_wrap(m, "req_body_read", |mut c: C<'_>, dst: i32, cap: i32| -> R<i32> {
        count(&mut c)?;
        let (off, len) = (c.data().body_off, c.data().body.len());
        let n = usize::try_from(bits(cap)).unwrap_or(usize::MAX).min(len.saturating_sub(off));
        if n > 0 {
            write_guest(&mut c, dst, |s| s.body.get(off..off.saturating_add(n)).unwrap_or_default())?;
            c.data_mut().body_off = off.saturating_add(n);
        }
        Ok(len_i32(n))
    })
    .map_err(wrap)?;
    l.func_wrap(m, "resp_head", |mut c: C<'_>, status: i32, src: i32, len: i32| -> R<i32> {
        count(&mut c)?;
        if c.data().resp_started || !(200..=599).contains(&status) {
            return Err(fault(&mut c, trap::MISUSE));
        }
        let hb = read_guest(&mut c, src, len)?;
        if !resp_headers_ok(&hb) {
            return Err(fault(&mut c, trap::MISUSE));
        }
        let rid = c.data().rid;
        let e = Enc::new().u(tag::RESP_HEAD).u(rid).u(u64::from(bits(status))).raw(&hb);
        if e.len() > c.data().frame_max {
            return Err(fault(&mut c, trap::MISUSE));
        }
        c.data_mut().resp_started = true;
        send(&mut c, &e.finish())?;
        Ok(0)
    })
    .map_err(wrap)?;
    l.func_wrap(m, "resp_write", |mut c: C<'_>, src: i32, len: i32| -> R<i32> {
        count(&mut c)?;
        if !c.data().resp_started {
            return Err(fault(&mut c, trap::MISUSE));
        }
        let b = read_guest(&mut c, src, len)?;
        let st = c.data_mut();
        let total = st.resp_bytes.saturating_add(u64::try_from(b.len()).unwrap_or(u64::MAX));
        if total > st.quotas.resp_bytes {
            return Err(fault(&mut c, trap::QUOTA));
        }
        st.resp_bytes = total;
        send_chunked(&mut c, tag::RESP_BODY, None, &corrupt(b))?;
        Ok(0)
    })
    .map_err(wrap)?;
    l.func_wrap(m, "log", |mut c: C<'_>, level: i32, src: i32, len: i32| -> R<i32> {
        count(&mut c)?;
        let Ok(level) = u64::try_from(level) else { return Err(fault(&mut c, trap::MISUSE)) };
        if level > 4 {
            return Err(fault(&mut c, trap::MISUSE));
        }
        let b = read_guest(&mut c, src, len)?;
        let st = c.data_mut();
        let total = st.log_bytes.saturating_add(u64::try_from(b.len()).unwrap_or(u64::MAX));
        if total > st.quotas.log_bytes {
            return Err(fault(&mut c, trap::QUOTA));
        }
        st.log_bytes = total;
        send_chunked(&mut c, tag::LOG, Some(level), &b)?;
        Ok(0)
    })
    .map_err(wrap)?;
    l.func_wrap(m, "data_run", |mut c: C<'_>, src: i32, len: i32| -> R<i32> {
        count(&mut c)?;
        let op = read_guest(&mut c, src, len)?;
        let op_len = u64::try_from(op.len()).unwrap_or(u64::MAX);
        let st = c.data_mut();
        let bytes = st.data_bytes.saturating_add(op_len);
        if st.data_runs >= st.quotas.data_runs || bytes > st.quotas.data_bytes {
            return Err(fault(&mut c, trap::QUOTA));
        }
        let seq = st.data_runs;
        let e = Enc::new().u(tag::DATA_RUN).u(st.rid).u(seq).bytes(&op);
        if e.len() > st.frame_max {
            return Err(fault(&mut c, trap::MISUSE)); // an op that cannot travel in one frame
        }
        st.data_runs = seq.saturating_add(1);
        st.data_bytes = bytes;
        send(&mut c, &e.finish())?;
        let result = await_reply(&mut c, seq)?;
        let st = c.data_mut();
        st.data_bytes = st.data_bytes.saturating_add(u64::try_from(result.len()).unwrap_or(u64::MAX));
        if st.data_bytes > st.quotas.data_bytes {
            return Err(fault(&mut c, trap::QUOTA));
        }
        match st.handles.issue(result) {
            Some(h) => Ok(to_i32(h)),
            None => Err(fault(&mut c, trap::QUOTA)),
        }
    })
    .map_err(wrap)?;
    l.func_wrap(m, "result_read", |mut c: C<'_>, h: i32, dst: i32, cap: i32| -> R<i32> {
        count(&mut c)?;
        let s = handle_slot(&mut c, h)?;
        let len = slot_bytes(c.data(), s).len();
        if usize::try_from(bits(cap)).unwrap_or(usize::MAX) >= len {
            write_guest(&mut c, dst, |st| slot_bytes(st, s))?;
        }
        Ok(len_i32(len))
    })
    .map_err(wrap)?;
    l.func_wrap(m, "handle_drop", |mut c: C<'_>, h: i32| -> R<()> {
        count(&mut c)?;
        let s = handle_slot(&mut c, h)?;
        if let Some(slot) = c.data_mut().handles.slots.get_mut(s) {
            *slot = None;
        }
        Ok(())
    })
    .map_err(wrap)?;
    define_test_import(l)
}

/// test-hooks: `env.host_fault` (F14 Part 1): 1 aborts the process, 2 corrupts host state, anything else traps 8.
#[cfg(feature = "test-hooks")]
fn define_test_import(l: &mut Linker<ReqState>) -> Result<(), AbiError> {
    l.func_wrap("env", "host_fault", |mut c: C<'_>, code: i32| -> R<()> {
        count(&mut c)?;
        match code {
            // Stands in for a guest-triggerable host bug that takes the serving process down.
            1 => std::process::abort(),
            // Stands in for a guest-triggerable host bug that silently corrupts host state.
            2 => {
                HOST_CORRUPT.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }
            _ => Err(fault(&mut c, trap::HOST_FAULT)),
        }
    })
    .map(drop)
    .map_err(wrap)
}

/// Golden builds define no `env` module at all; the extra-import mutant leaks the test-only import into one.
#[cfg(not(feature = "test-hooks"))]
fn define_test_import(l: &mut Linker<ReqState>) -> Result<(), AbiError> {
    if !mutant::is(Mutant::ExtraImport) {
        return Ok(());
    }
    // MUTANT extra-import (as the oracle reference): code 3 is harmless, anything else traps 8.
    l.func_wrap("env", "host_fault", |mut c: C<'_>, code: i32| -> R<()> {
        count(&mut c)?;
        if code == 3 { Ok(()) } else { Err(fault(&mut c, trap::HOST_FAULT)) }
    })
    .map(drop)
    .map_err(wrap)
}
