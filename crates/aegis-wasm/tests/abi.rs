//! F14 guest ABI regressions (unit P5-wasm-002): the static import/export check, the frame codec, and every host
//! function rule driven end to end through `abi::Session` over an in-memory transport that plays the supervisor:
//! verbatim req-head and data_run op, generation-tagged handles (forged, zero, foreign, dropped, double drop, and a
//! handle from the previous request of the same session), the host-call / data_run / data byte / response byte / log
//! byte quotas (nothing above a quota is forwarded), ABI misuse (pointer range, double head, write before head,
//! status, I5 header rules, log level), fuel, epoch wall bound, limiter, cancel and out-of-order frames.
//!
//! Frames and guests are encoded here by hand, independently of `abi::frame` (a shared encoder would hide symmetric
//! bugs). The engine has no text parser, so guests are hand-assembled Wasm binaries.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_wasm::abi::{self, Closed, End, F14Worker, Recv, Served, Transport};
use aegis_wasm::{EngineSettings, EpochTicker, P2Engine, P2Limits};

// ------------------------------------------------------------------------------------------------ encoding

fn uleb(mut n: u64, out: &mut Vec<u8>) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn sleb(mut n: i64, out: &mut Vec<u8>) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        let done = (n == 0 && b & 0x40 == 0) || (n == -1 && b & 0x40 != 0);
        out.push(if done { b } else { b | 0x80 });
        if done {
            return;
        }
    }
}

fn lp(b: &[u8], out: &mut Vec<u8>) {
    uleb(b.len() as u64, out);
    out.extend_from_slice(b);
}

/// Postcard writer for frames and F14 values.
#[derive(Default, Clone)]
struct P(Vec<u8>);
impl P {
    fn u(mut self, n: u64) -> Self {
        uleb(n, &mut self.0);
        self
    }
    fn b(mut self, b: &[u8]) -> Self {
        lp(b, &mut self.0);
        self
    }
    fn raw(mut self, b: &[u8]) -> Self {
        self.0.extend_from_slice(b);
        self
    }
}

fn req_head_bytes() -> Vec<u8> {
    // method, path, opaque query, headers [(accept, */*)], body-len null
    P::default().b(b"GET").b(b"/x").u(0).b(b"n=1").u(1).b(b"accept").b(b"*/*").u(0).0
}

#[derive(Clone, Copy)]
struct Lim([u64; 8]);
const DEFAULT: Lim = Lim([15_000_000, 100, 16, 10_000, 64, 4_194_304, 1_048_576, 65_536]);
impl Lim {
    fn with(mut self, i: usize, v: u64) -> Self {
        self.0[i] = v;
        self
    }
}
const FUEL: usize = 0;
const WALL: usize = 1;
const MEM: usize = 2;
const CALLS: usize = 3;
const RUNS: usize = 4;
const DBYTES: usize = 5;
const RBYTES: usize = 6;
const LBYTES: usize = 7;

fn f_request(rid: u64, l: Lim, head: &[u8]) -> Vec<u8> {
    let mut p = P::default().u(0).u(rid);
    for v in l.0 {
        p = p.u(v);
    }
    p.raw(head).0
}

fn f_body(rid: u64, chunk: &[u8], last: bool) -> Vec<u8> {
    P::default().u(1).u(rid).b(chunk).raw(&[u8::from(last)]).0
}

fn f_cancel(rid: u64) -> Vec<u8> {
    P::default().u(3).u(rid).0
}

/// F10 result: rows [[ "row", "body" ]] (tag 0, 1 row, 2 cells, each Some(text)).
fn result_rows(cell: &[u8]) -> Vec<u8> {
    P::default().u(0).u(1).u(2).u(1).u(1).b(cell).u(1).u(1).b(b"body").0
}

/// A plausible F10 op (tenant, collection, kind select, filter tt, no writes, returning [1]).
fn op_bytes(tenant: u64) -> Vec<u8> {
    P::default().u(tenant).b(b"notes").u(0).u(0).u(0).u(1).u(1).0
}

fn resp_headers(hs: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut p = P::default().u(hs.len() as u64);
    for (n, v) in hs {
        p = p.b(n).b(v);
    }
    p.0
}

// ------------------------------------------------------------------------------------------------ decoding (test side)

#[derive(Debug, Clone, PartialEq)]
enum W2s {
    Ready(Vec<u8>),
    Head(u64, u64, Vec<u8>),
    Body(u64, Vec<u8>),
    End(u64, End, u64),
    DataRun(u64, u64, Vec<u8>),
    Log(u64, u64, Vec<u8>),
    Layout(u64, u64),
}

struct D<'a>(&'a [u8]);
impl D<'_> {
    fn u(&mut self) -> u64 {
        let mut v = 0u64;
        for k in 0..10 {
            let x = self.0[0];
            self.0 = &self.0[1..];
            v |= u64::from(x & 0x7f) << (7 * k);
            if x & 0x80 == 0 {
                return v;
            }
        }
        panic!("varint");
    }
    fn b(&mut self) -> Vec<u8> {
        let n = self.u() as usize;
        let (a, r) = self.0.split_at(n);
        self.0 = r;
        a.to_vec()
    }
}

fn dec(f: &[u8]) -> W2s {
    let mut d = D(f);
    let t = d.u();
    let r = match t {
        16 => {
            assert_eq!(d.u(), 0);
            assert_eq!(d.u(), 1);
            W2s::Ready(d.b())
        }
        17 => W2s::Head(d.u(), d.u(), d.0.to_vec()),
        18 => W2s::Body(d.u(), d.b()),
        19 => {
            let rid = d.u();
            let end = match d.u() {
                0 => End::Code(d.u() as u32),
                1 => End::Trap(d.u() as u32),
                x => panic!("end tag {x}"),
            };
            W2s::End(rid, end, d.u())
        }
        20 => W2s::DataRun(d.u(), d.u(), d.b()),
        21 => W2s::Log(d.u(), d.u(), d.b()),
        22 => {
            assert_eq!(d.u(), 0);
            W2s::Layout(d.u(), d.u())
        }
        x => panic!("unknown w2s tag {x}"),
    };
    if !matches!(r, W2s::Head(..)) {
        assert!(d.0.is_empty(), "trailing bytes in {r:?}");
    }
    r
}

// ------------------------------------------------------------------------------------------------ mock supervisor

#[derive(Clone, Copy, PartialEq)]
enum OnDataRun {
    Reply,
    Cancel,
    WrongSeq,
}

/// The supervisor side: an inbound queue, a log of every frame the worker sent, and the data_run answer policy.
struct Mock {
    inbox: VecDeque<Vec<u8>>,
    out: Arc<Mutex<Vec<Vec<u8>>>>,
    reply: Vec<u8>,
    on_data_run: OnDataRun,
    frame_max: usize,
}

impl Transport for Mock {
    fn send(&mut self, frame: &[u8]) -> bool {
        assert!(frame.len() <= self.frame_max, "worker sent a {} byte frame", frame.len());
        self.out.lock().unwrap().push(frame.to_vec());
        if let W2s::DataRun(rid, seq, _) = dec(frame) {
            let f = match self.on_data_run {
                OnDataRun::Reply => P::default().u(2).u(rid).u(seq).raw(&self.reply).0,
                OnDataRun::Cancel => f_cancel(rid),
                OnDataRun::WrongSeq => P::default().u(2).u(rid).u(seq + 1).raw(&self.reply).0,
            };
            self.inbox.push_front(f);
        }
        true
    }
    fn recv(&mut self, max: usize) -> Recv {
        match self.inbox.pop_front() {
            Some(f) if f.len() > max => Recv::Bad,
            Some(f) => Recv::Frame(f),
            None => Recv::Eof,
        }
    }
}

struct Run {
    served: Vec<Served>,
    frames: Vec<W2s>,
}

impl Run {
    fn end(&self, rid: u64) -> Option<End> {
        self.frames.iter().find_map(|f| match f {
            W2s::End(r, e, _) if *r == rid => Some(*e),
            _ => None,
        })
    }
    fn body(&self, rid: u64) -> Vec<u8> {
        self.frames
            .iter()
            .filter_map(|f| match f {
                W2s::Body(r, c) if *r == rid => Some(c.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }
    fn count(&self, pred: impl Fn(&W2s) -> bool) -> usize {
        self.frames.iter().filter(|f| pred(f)).count()
    }
    fn log_bytes(&self) -> usize {
        self.frames.iter().map(|f| if let W2s::Log(_, _, d) = f { d.len() } else { 0 }).sum()
    }
}

fn engine() -> P2Engine {
    P2Engine::new(EngineSettings::defaults(false)).unwrap()
}

fn worker(eng: &P2Engine, wasm: &[u8]) -> F14Worker {
    let m = wasmtime::Module::new(eng.wasmtime(), wasm).unwrap();
    F14Worker::new(eng, &m, P2Limits::new(1_000_000_000, 1_000, 16).unwrap()).unwrap()
}

/// Serves the given request frames (each followed by its body) on one session.
fn drive(w: &F14Worker, reqs: &[(u64, Lim, Vec<u8>)], reply: Vec<u8>, on: OnDataRun) -> Run {
    let mut inbox = VecDeque::new();
    for (rid, l, body) in reqs {
        inbox.push_back(f_request(*rid, *l, &req_head_bytes()));
        inbox.push_back(f_body(*rid, body, true));
    }
    drive_frames(w, inbox, reply, on, reqs.len())
}

fn drive_frames(w: &F14Worker, inbox: VecDeque<Vec<u8>>, reply: Vec<u8>, on: OnDataRun, n: usize) -> Run {
    let out = Arc::new(Mutex::new(Vec::new()));
    let mock = Mock { inbox, out: Arc::clone(&out), reply, on_data_run: on, frame_max: w.frame_max() };
    let mut s = w.session(mock);
    let mut served = Vec::new();
    for _ in 0..n {
        let r = s.serve_one(|_| true);
        let closed = matches!(r, Served::Closed(_));
        served.push(r);
        if closed {
            break;
        }
    }
    let frames = out.lock().unwrap().iter().map(|f| dec(f)).collect();
    Run { served, frames }
}

fn one(wasm: &[u8], l: Lim) -> Run {
    let eng = engine();
    drive(&worker(&eng, wasm), &[(7, l, Vec::new())], result_rows(b"row"), OnDataRun::Reply)
}

// ------------------------------------------------------------------------------------------------ guests

/// Import function indices (the eight F14 imports in allowlist order).
const REQ_HEAD: u32 = 0;
const REQ_BODY_READ: u32 = 1;
const RESP_HEAD: u32 = 2;
const RESP_WRITE: u32 = 3;
const LOG: u32 = 4;
const DATA_RUN: u32 = 5;
const RESULT_READ: u32 = 6;
const HANDLE_DROP: u32 = 7;

const BUF: i64 = 65536;

#[derive(Clone)]
enum Imp {
    Func(&'static str, &'static str, usize, usize),
    Mem(&'static str, &'static str),
    Global(&'static str, &'static str),
    Table(&'static str, &'static str),
}

fn f14_imports() -> Vec<Imp> {
    abi::IMPORTS.iter().map(|s| Imp::Func(s.module, s.name, s.params, s.results)).collect()
}

#[derive(Clone)]
struct Wasm {
    imports: Vec<Imp>,
    mem: Option<u32>,
    /// Defined functions: (params, results, body without the final end).
    funcs: Vec<(usize, usize, Vec<u8>)>,
    /// (name, kind, index): kind 0 func, 2 memory.
    exports: Vec<(&'static str, u8, u32)>,
    data: Vec<(u32, Vec<u8>)>,
}

impl Wasm {
    /// An F14 guest: the eight imports, memory (4 pages), `handle` = `body`, constants placed by `konst`.
    fn f14(body: Vec<u8>) -> Self {
        Self {
            imports: f14_imports(),
            mem: Some(4),
            funcs: vec![(0, 1, body)],
            exports: vec![("memory", 2, 0), ("handle", 0, 8)],
            data: vec![],
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut m = b"\0asm\x01\0\0\0".to_vec();
        let mut types = Vec::new();
        let mut ntypes = 0;
        let mut ty = |p: usize, r: usize, types: &mut Vec<u8>| {
            types.push(0x60);
            uleb(p as u64, types);
            types.extend(std::iter::repeat_n(0x7f, p));
            uleb(r as u64, types);
            types.extend(std::iter::repeat_n(0x7f, r));
            ntypes += 1;
            ntypes - 1
        };
        let mut imps = Vec::new();
        for i in &self.imports {
            match i {
                Imp::Func(md, nm, p, r) => {
                    let t = ty(*p, *r, &mut types);
                    lp(md.as_bytes(), &mut imps);
                    lp(nm.as_bytes(), &mut imps);
                    imps.push(0x00);
                    uleb(t, &mut imps);
                }
                Imp::Mem(md, nm) => {
                    lp(md.as_bytes(), &mut imps);
                    lp(nm.as_bytes(), &mut imps);
                    imps.extend([0x02, 0x00, 0x01]);
                }
                Imp::Global(md, nm) => {
                    lp(md.as_bytes(), &mut imps);
                    lp(nm.as_bytes(), &mut imps);
                    imps.extend([0x03, 0x7f, 0x00]);
                }
                Imp::Table(md, nm) => {
                    lp(md.as_bytes(), &mut imps);
                    lp(nm.as_bytes(), &mut imps);
                    imps.extend([0x01, 0x70, 0x00, 0x01]);
                }
            }
        }
        let mut fsec = Vec::new();
        for (p, r, _) in &self.funcs {
            let t = ty(*p, *r, &mut types);
            uleb(t, &mut fsec);
        }
        section(1, ntypes as usize, &types, &mut m);
        if !self.imports.is_empty() {
            section(2, self.imports.len(), &imps, &mut m);
        }
        section(3, self.funcs.len(), &fsec, &mut m);
        if let Some(p) = self.mem {
            let mut mem = vec![0x00];
            uleb(u64::from(p), &mut mem);
            section(5, 1, &mem, &mut m);
        }
        let mut ex = Vec::new();
        for (n, k, i) in &self.exports {
            lp(n.as_bytes(), &mut ex);
            ex.push(*k);
            uleb(u64::from(*i), &mut ex);
        }
        section(7, self.exports.len(), &ex, &mut m);
        let mut code = Vec::new();
        for (_, _, body) in &self.funcs {
            let mut f = vec![0x01, 0x03, 0x7f]; // 3 i32 locals
            f.extend_from_slice(body);
            f.push(0x0b);
            lp(&f, &mut code);
        }
        section(10, self.funcs.len(), &code, &mut m);
        if !self.data.is_empty() {
            let mut d = Vec::new();
            for (off, bytes) in &self.data {
                d.push(0x00);
                d.extend(i32c(i64::from(*off)));
                d.push(0x0b);
                lp(bytes, &mut d);
            }
            section(11, self.data.len(), &d, &mut m);
        }
        m
    }
}

fn section(id: u8, count: usize, items: &[u8], out: &mut Vec<u8>) {
    let mut body = Vec::new();
    uleb(count as u64, &mut body);
    body.extend_from_slice(items);
    out.push(id);
    lp(&body, out);
}

fn i32c(k: i64) -> Vec<u8> {
    let mut v = vec![0x41];
    sleb(k, &mut v);
    v
}

/// Guest body builder with a constants area at 1024.
struct G {
    data: Vec<(u32, Vec<u8>)>,
    next: u32,
    b: Vec<u8>,
}

impl G {
    fn new() -> Self {
        Self { data: vec![], next: 1024, b: vec![] }
    }
    fn konst(&mut self, bytes: &[u8]) -> (i64, i64) {
        let off = self.next;
        self.data.push((off, bytes.to_vec()));
        self.next += (bytes.len() as u32 + 15) & !15;
        (i64::from(off), bytes.len() as i64)
    }
    fn i(&mut self, k: i64) -> &mut Self {
        self.b.extend(i32c(k));
        self
    }
    fn op(&mut self, bytes: &[u8]) -> &mut Self {
        self.b.extend_from_slice(bytes);
        self
    }
    fn call(&mut self, f: u32) -> &mut Self {
        self.b.push(0x10);
        uleb(u64::from(f), &mut self.b);
        self
    }
    fn get(&mut self, l: u8) -> &mut Self {
        self.op(&[0x20, l])
    }
    fn set(&mut self, l: u8) -> &mut Self {
        self.op(&[0x21, l])
    }
    fn drop_(&mut self) -> &mut Self {
        self.op(&[0x1a])
    }
    fn head(&mut self, status: i64, hs: &[(&[u8], &[u8])]) -> &mut Self {
        let (p, n) = self.konst(&resp_headers(hs));
        self.i(status).i(p).i(n).call(RESP_HEAD).drop_()
    }
    fn write(&mut self, bytes: &[u8]) -> &mut Self {
        let (p, n) = self.konst(bytes);
        self.i(p).i(n).call(RESP_WRITE).drop_()
    }
    /// `data_run(op)` into local 0.
    fn data_run(&mut self, op: &[u8]) -> &mut Self {
        let (p, n) = self.konst(op);
        self.i(p).i(n).call(DATA_RUN).set(0)
    }
    /// A counted loop: `body` runs `n` times (local 1 is the counter).
    fn repeat(&mut self, n: i64, body: impl Fn(&mut G)) -> &mut Self {
        self.op(&[0x02, 0x40, 0x03, 0x40]);
        body(self);
        self.get(1).i(1).op(&[0x6a, 0x22, 0x01]).i(n).op(&[0x49, 0x0d, 0x00, 0x0b, 0x0b]);
        self
    }
    fn ret(&mut self, k: i64) -> Vec<u8> {
        self.i(k);
        let mut w = Wasm::f14(self.b.clone());
        w.data = self.data.clone();
        w.encode()
    }
}

// ------------------------------------------------------------------------------------------------ static check

fn compile(w: &Wasm) -> Result<(), String> {
    let eng = engine();
    aegis_wasm::engine::cwasm::compile(&eng, &w.encode()).map(drop).map_err(|e| e.to_string())
}

#[test]
fn static_check_accepts_exactly_the_f14_shape() {
    assert_eq!(compile(&Wasm::f14(i32c(0))), Ok(()));
    let refused = |name: &str, w: Wasm| {
        let r = compile(&w);
        assert!(r.is_err(), "{name}: compiled a module outside F14");
        // The worker's own check refuses it too, before any instantiation.
        let eng = engine();
        let m = wasmtime::Module::new(eng.wasmtime(), w.encode()).unwrap();
        assert!(abi::check_module(&m).is_err(), "{name}: check_module accepted it");
        assert!(F14Worker::new(&eng, &m, P2Limits::DEFAULT).is_err(), "{name}: F14Worker resolved it");
    };
    let with_import = |i: Imp| {
        let mut w = Wasm::f14(i32c(0));
        w.imports.push(i);
        w.exports = vec![("memory", 2, 0), ("handle", 0, 9)];
        w
    };
    if abi::TEST_IMPORTS.is_empty() {
        refused("env.host_fault in a golden build", with_import(Imp::Func("env", "host_fault", 1, 0)));
    }
    refused("wasi", with_import(Imp::Func("wasi_snapshot_preview1", "fd_write", 4, 1)));
    refused("unknown aegis name", with_import(Imp::Func("aegis", "fetch", 2, 1)));
    refused("context switch", with_import(Imp::Func("aegis", "set_principal", 1, 1)));
    let mut wrong = Wasm::f14(i32c(0));
    wrong.imports[LOG as usize] = Imp::Func("aegis", "log", 2, 1);
    refused("wrong type", wrong);
    let mut gl = Wasm::f14(i32c(0));
    gl.imports.push(Imp::Global("aegis", "tenant"));
    refused("global import", gl);
    let mut tb = Wasm::f14(i32c(0));
    tb.imports.push(Imp::Table("env", "table"));
    refused("table import", tb);
    let mut mi = Wasm::f14(i32c(0));
    mi.imports.push(Imp::Mem("aegis", "memory"));
    mi.mem = None;
    refused("memory import", mi);
    let mut nh = Wasm::f14(i32c(0));
    nh.exports = vec![("memory", 2, 0), ("run", 0, 8)];
    refused("no handle", nh);
    let mut ex = Wasm::f14(i32c(0));
    ex.exports.push(("other", 0, 8));
    refused("extra export", ex);
    let mut ht = Wasm::f14(i32c(0));
    ht.funcs = vec![(1, 1, i32c(0))];
    refused("handle with a parameter", ht);
    let mut nm = Wasm::f14(i32c(0));
    nm.mem = None;
    nm.exports = vec![("handle", 0, 8)];
    refused("no memory", nm);
}

#[test]
fn mutant_names_parse_and_golden_test_builds_select_none() {
    for m in abi::mutant::Mutant::ALL {
        assert_eq!(abi::mutant::Mutant::parse(m.name()), Some(m));
    }
    assert_eq!(abi::mutant::Mutant::parse("raw-passthrough"), None); // a supervisor mutant leaves the worker golden
    #[cfg(not(feature = "mutants"))]
    assert_eq!(abi::mutant::active(), None);
}

// ------------------------------------------------------------------------------------------------ frames

#[test]
fn frame_decoder_is_total_and_strict() {
    use abi::frame::{Inbound, decode_s2w};
    let head = req_head_bytes();
    let req = f_request(9, DEFAULT, &head);
    match decode_s2w(&req) {
        Some(Inbound::Request { rid: 9, limits, head: h }) => {
            assert_eq!(limits.fuel, 15_000_000);
            assert_eq!(limits.max_log_bytes, 65_536);
            assert_eq!(h, head.as_slice());
        }
        other => panic!("{other:?}"),
    }
    for cut in 0..req.len() {
        assert!(decode_s2w(&req[..cut]).is_none(), "truncated at {cut} decoded");
    }
    let mut trailing = req.clone();
    trailing.push(0);
    assert!(decode_s2w(&trailing).is_none());
    assert!(decode_s2w(&f_request(0, DEFAULT, &head)).is_none(), "req-id 0");
    let bad_query = P::default().b(b"GET").b(b"/").u(2).u(0).u(0).0;
    assert!(decode_s2w(&f_request(1, DEFAULT, &bad_query)).is_none());
    let bad_utf8 = P::default().b(b"G\xffT").b(b"/").u(0).b(b"").u(0).u(0).0;
    assert!(decode_s2w(&f_request(1, DEFAULT, &bad_utf8)).is_none());
    assert_eq!(decode_s2w(&f_body(4, b"ab", true)), Some(Inbound::BodyChunk { rid: 4, chunk: b"ab", last: true }));
    let mut bad_bool = f_body(4, b"ab", true);
    *bad_bool.last_mut().unwrap() = 2;
    assert!(decode_s2w(&bad_bool).is_none());
    assert!(decode_s2w(&P::default().u(2).u(4).u(0).0).is_none(), "data-reply without a result");
    assert_eq!(decode_s2w(&f_cancel(4)), Some(Inbound::Cancel { rid: 4 }));
    assert!(decode_s2w(&P::default().u(16).u(1).0).is_none(), "w2s tag on the s2w side");
    assert!(decode_s2w(&[0xff; 11]).is_none(), "overlong varint");
    assert_eq!(dec(&abi::frame::ready(&[7; 32])), W2s::Ready(vec![7; 32]));
    assert_eq!(dec(&abi::frame::layout(0x5555, 42)), W2s::Layout(0x5555, 42));
}

#[test]
fn i5_header_rules() {
    let ok = |hs: &[(&[u8], &[u8])]| abi::resp_headers_ok(&resp_headers(hs));
    assert!(ok(&[]));
    assert!(ok(&[(b"x-mod", b"1"), (b"content-type", b"text/plain; charset=utf-8")]));
    for (n, v) in [
        (&b"x-a"[..], &b"a\r\nx-injected: 1"[..]),
        (b"x-a", b"a\nb"),
        (b"x-a", b"a\0b"),
        (b"x-a", b"caf\xe9"),
        (b"x-a", b" lead"),
        (b"x-a", b"trail\t"),
        (b"X-Upper", b"v"),
        (b"x a", b"v"),
        (b"", b"v"),
        (b"content-length", b"1"),
        (b"transfer-encoding", b"chunked"),
        (b"connection", b"close"),
        (b"te", b"trailers"),
        (b"proxy-authorization", b"x"),
    ] {
        assert!(!ok(&[(n, v)]), "accepted {n:?}: {v:?}");
    }
    assert!(!ok(&[(&[b'a'; 65][..], b"v")]), "65-byte name");
    let many: Vec<(Vec<u8>, Vec<u8>)> = (0..257).map(|i| (format!("x-{i}").into_bytes(), b"v".to_vec())).collect();
    let refs: Vec<(&[u8], &[u8])> = many.iter().map(|(a, b)| (a.as_slice(), b.as_slice())).collect();
    assert!(!ok(&refs), "257 fields");
    assert!(!abi::resp_headers_ok(&[1, 1]), "truncated encoding");
    let mut trailing = resp_headers(&[(b"x-a", b"v")]);
    trailing.push(0);
    assert!(!abi::resp_headers_ok(&trailing));
}

// ------------------------------------------------------------------------------------------------ requests

#[test]
fn control_response_and_verbatim_req_head_and_body() {
    let eng = engine();
    // req_head(0, 0) sizes, req_head(BUF, L) copies; body = req-head || request body.
    let mut g = G::new();
    g.i(0).i(0).call(REQ_HEAD).set(2);
    g.i(BUF).get(2).call(REQ_HEAD).drop_();
    g.head(200, &[(b"x-mod", b"1")]);
    g.i(BUF).get(2).call(RESP_WRITE).drop_();
    g.i(BUF).i(4096).call(REQ_BODY_READ).set(2);
    g.i(BUF).get(2).call(RESP_WRITE).drop_();
    g.i(BUF).i(4096).call(REQ_BODY_READ).drop_(); // 0 at end of body
    let w = worker(&eng, &g.ret(0));
    let r = drive(&w, &[(5, DEFAULT, b"request-body".to_vec())], vec![], OnDataRun::Reply);
    assert_eq!(r.end(5), Some(End::Code(0)), "{:?}", r.frames);
    let mut want = req_head_bytes();
    want.extend_from_slice(b"request-body");
    assert_eq!(r.body(5), want);
    match &r.frames[0] {
        W2s::Head(5, 200, hs) => assert_eq!(hs, &resp_headers(&[(b"x-mod", b"1")])),
        other => panic!("first frame {other:?}"),
    }
    assert!(matches!(r.served[0], Served::Answered { rid: 5, end: End::Code(0), .. }));
}

#[test]
fn handle_codes_pass_through_as_untrusted_status() {
    for code in [1i64, 7, -1] {
        let r = one(&G::new().ret(code), DEFAULT);
        assert_eq!(r.end(7), Some(End::Code(code as u32)));
    }
}

#[test]
fn data_run_forwards_the_op_verbatim_and_result_read_returns_the_reply() {
    let op = op_bytes(4_294_967_295); // names another tenant: forwarded verbatim, never resolved here
    let mut g = G::new();
    g.data_run(&op);
    g.get(0).i(BUF).i(32768).call(RESULT_READ).set(2);
    g.get(0).call(HANDLE_DROP);
    g.head(200, &[]);
    g.i(BUF).get(2).call(RESP_WRITE).drop_();
    let r = one(&g.ret(0), DEFAULT);
    assert_eq!(r.end(7), Some(End::Code(0)), "{:?}", r.frames);
    assert_eq!(r.frames[0], W2s::DataRun(7, 0, op));
    assert_eq!(r.body(7), result_rows(b"row"));
}

fn handle_case(act: &str) -> Option<End> {
    let mut g = G::new();
    g.data_run(&op_bytes(1));
    match act {
        "forged" => g.get(0).i(1).op(&[0x6a]),
        "zero" => g.i(0),
        "foreign" => g.get(0).i(0x10000).op(&[0x73]),
        "valid" => g.get(0),
        _ => g.get(0),
    };
    match act {
        "dropped" => {
            g.get(0).call(HANDLE_DROP).drop_();
            g.get(0).i(0).i(0).call(RESULT_READ).drop_();
        }
        "double-drop" => {
            g.drop_().get(0).call(HANDLE_DROP);
            g.get(0).call(HANDLE_DROP);
        }
        _ => {
            g.i(0).i(0).call(RESULT_READ).drop_();
        }
    }
    g.head(200, &[]).write(b"HANDLE-READ");
    one(&g.ret(0), DEFAULT).end(7)
}

#[test]
fn handles_forged_zero_foreign_dropped_and_double_drop_trap_5() {
    assert_eq!(handle_case("valid"), Some(End::Code(0)));
    for act in ["forged", "zero", "foreign", "dropped", "double-drop"] {
        assert_eq!(handle_case(act), Some(End::Trap(abi::trap::HANDLE)), "{act}");
    }
}

fn mutant_handle_not_cleared() -> bool {
    abi::mutant::is(abi::mutant::Mutant::HandleNotCleared)
}

#[test]
fn a_handle_issued_earlier_on_the_same_session_traps_5() {
    // Request 1 emits its handle in its body; the mock hands that exact value to request 2 as its body.
    struct Relay {
        inner: Mock,
        stage: u8,
    }
    impl Transport for Relay {
        fn send(&mut self, frame: &[u8]) -> bool {
            if let W2s::Body(1, c) = dec(frame) {
                self.inner.inbox.push_back(f_request(2, DEFAULT, &req_head_bytes()));
                self.inner.inbox.push_back(f_body(2, &c, true));
                self.stage = 1;
            }
            self.inner.send(frame)
        }
        fn recv(&mut self, max: usize) -> Recv {
            self.inner.recv(max)
        }
    }
    let mut g = G::new();
    g.i(BUF).i(4).call(REQ_BODY_READ).op(&[0x45, 0x04, 0x40]);
    g.data_run(&op_bytes(1)).i(BUF).get(0).op(&[0x36, 0x02, 0x00]).head(200, &[]);
    g.i(BUF).i(4).call(RESP_WRITE).drop_();
    g.op(&[0x05]);
    g.i(BUF).op(&[0x28, 0x02, 0x00]).i(0).i(0).call(RESULT_READ).drop_();
    g.head(200, &[]).write(b"STALE-HANDLE-READ");
    g.op(&[0x0b]);
    let eng = engine();
    let w = worker(&eng, &g.ret(0));
    let out = Arc::new(Mutex::new(Vec::new()));
    let mut inbox = VecDeque::new();
    inbox.push_back(f_request(1, DEFAULT, &req_head_bytes()));
    inbox.push_back(f_body(1, &[], true));
    let mock = Mock {
        inbox,
        out: Arc::clone(&out),
        reply: result_rows(b"row"),
        on_data_run: OnDataRun::Reply,
        frame_max: w.frame_max(),
    };
    let mut s = w.session(Relay { inner: mock, stage: 0 });
    let a = s.serve_one(|_| true);
    let b = s.serve_one(|_| true);
    assert!(matches!(a, Served::Answered { rid: 1, end: End::Code(0), .. }), "{a:?}");
    if mutant_handle_not_cleared() {
        assert!(matches!(b, Served::Answered { rid: 2, end: End::Code(0), .. }), "mutant: {b:?}");
    } else {
        assert!(matches!(b, Served::Answered { rid: 2, end: End::Trap(5), .. }), "{b:?}");
    }
}

#[test]
fn host_call_quota_traps_6_at_the_limit() {
    let mut g = G::new();
    g.repeat(200_000, |g| {
        g.i(0).i(0).call(REQ_HEAD).drop_();
    });
    g.head(200, &[]).write(b"HOSTCALL-FLOOD-DONE");
    let wasm = g.ret(0);
    let r = one(&wasm, DEFAULT);
    assert_eq!(r.end(7), Some(End::Trap(abi::trap::QUOTA)));
    assert_eq!(r.count(|f| matches!(f, W2s::Head(..))), 0);
    // Exactly max_host_calls calls pass: 10 calls with a quota of 10 succeed, the 11th traps.
    let mut g = G::new();
    g.repeat(9, |g| {
        g.i(0).i(0).call(REQ_HEAD).drop_();
    });
    g.head(200, &[]);
    let wasm = g.ret(0);
    assert_eq!(one(&wasm, DEFAULT.with(CALLS, 10)).end(7), Some(End::Code(0)));
    assert_eq!(one(&wasm, DEFAULT.with(CALLS, 9)).end(7), Some(End::Trap(abi::trap::QUOTA)));
}

#[test]
fn data_run_count_and_byte_quotas() {
    let mut g = G::new();
    let (p, n) = g.konst(&op_bytes(1));
    g.repeat(100, |g| {
        g.i(p).i(n).call(DATA_RUN).drop_();
    });
    g.head(200, &[]).write(b"DATARUN-FLOOD-DONE");
    let wasm = g.ret(0);
    let r = one(&wasm, DEFAULT);
    assert_eq!(r.end(7), Some(End::Trap(abi::trap::QUOTA)));
    assert_eq!(r.count(|f| matches!(f, W2s::DataRun(..))), 64, "data-run frames beyond max_data_runs");
    // Replies of ~30 KB against max_data_bytes = 100,000: the 4th reply breaches; no 5th data-run frame.
    let eng = engine();
    let w = worker(&eng, &wasm);
    let big = result_rows(&vec![b'x'; 30_000]);
    let r = drive(&w, &[(3, DEFAULT.with(DBYTES, 100_000), vec![])], big, OnDataRun::Reply);
    assert_eq!(r.end(3), Some(End::Trap(abi::trap::QUOTA)));
    assert_eq!(r.count(|f| matches!(f, W2s::DataRun(..))), 4);
    // max_data_runs = 0: the first data_run traps before anything is forwarded.
    let r = one(&wasm, DEFAULT.with(RUNS, 0));
    assert_eq!(r.end(7), Some(End::Trap(abi::trap::QUOTA)));
    assert_eq!(r.count(|f| matches!(f, W2s::DataRun(..))), 0);
}

#[test]
fn response_and_log_byte_quotas_forward_nothing_above_the_quota() {
    let mut g = G::new();
    g.head(200, &[]);
    g.repeat(100, |g| {
        g.i(BUF).i(8192).call(RESP_WRITE).drop_();
    });
    let r = one(&g.ret(0), DEFAULT.with(RBYTES, 65_536));
    assert_eq!(r.end(7), Some(End::Trap(abi::trap::QUOTA)));
    assert_eq!(r.body(7).len(), 65_536);
    let mut g = G::new();
    g.repeat(100, |g| {
        g.i(2).i(BUF).i(1024).call(LOG).drop_();
    });
    let r = one(&g.ret(0), DEFAULT.with(LBYTES, 4096));
    assert_eq!(r.end(7), Some(End::Trap(abi::trap::QUOTA)));
    assert_eq!(r.log_bytes(), 4096);
    assert!(r.frames.iter().all(|f| !matches!(f, W2s::Log(_, l, _) if *l != 2)));
}

#[test]
fn large_writes_are_split_into_frames_within_the_cap() {
    let mut g = G::new();
    g.head(200, &[]);
    g.i(BUF).i(150_000).call(RESP_WRITE).drop_();
    g.i(1).i(BUF).i(60_000).call(LOG).drop_();
    let mut w = Wasm::f14(g.b.clone());
    w.data = g.data.clone();
    let mut body = g.b.clone();
    body.extend(i32c(0));
    w.funcs = vec![(0, 1, body)];
    w.mem = Some(8);
    let r = one(&w.encode(), DEFAULT);
    assert_eq!(r.end(7), Some(End::Code(0)));
    assert_eq!(r.body(7).len(), 150_000);
    assert_eq!(r.log_bytes(), 60_000);
    assert!(r.count(|f| matches!(f, W2s::Body(..))) >= 3);
}

#[test]
fn abi_misuse_traps_7_and_forwards_nothing_of_the_call() {
    // Pointer range outside memory 0.
    let mut g = G::new();
    g.head(200, &[]);
    g.i(0x7fff_ff00).i(4096).call(RESP_WRITE).drop_();
    let r = one(&g.ret(0), DEFAULT);
    assert_eq!(r.end(7), Some(End::Trap(abi::trap::MISUSE)));
    assert!(r.body(7).is_empty());
    // req_head into a range that ends past memory: nothing written, trap.
    let mut g = G::new();
    g.i(4 * 65536 - 4).i(4096).call(REQ_HEAD).drop_();
    assert_eq!(one(&g.ret(0), DEFAULT).end(7), Some(End::Trap(abi::trap::MISUSE)));
    // Write before head, head twice, status out of range, bad header, bad log level.
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("write before head", G::new().write(b"x").ret(0)),
        ("head twice", G::new().head(200, &[]).head(200, &[]).ret(0)),
        ("status 101", G::new().head(101, &[]).ret(0)),
        ("status 600", G::new().head(600, &[]).ret(0)),
        ("crlf header", G::new().head(200, &[(b"x-a", b"a\r\nx-injected: 1")]).ret(0)),
        ("framing header", G::new().head(200, &[(b"transfer-encoding", b"chunked")]).ret(0)),
        ("log level 9", {
            let mut g = G::new();
            let (p, n) = g.konst(b"log");
            g.i(9).i(p).i(n).call(LOG).drop_();
            g.ret(0)
        }),
        ("log level -1", {
            let mut g = G::new();
            let (p, n) = g.konst(b"log");
            g.i(-1).i(p).i(n).call(LOG).drop_();
            g.ret(0)
        }),
    ];
    for (name, wasm) in cases {
        let r = one(&wasm, DEFAULT);
        assert_eq!(r.end(7), Some(End::Trap(abi::trap::MISUSE)), "{name}: {:?}", r.frames);
        if name != "head twice" {
            assert_eq!(r.count(|f| matches!(f, W2s::Head(..))), 0, "{name}: a resp-head was forwarded");
        } else {
            assert_eq!(r.count(|f| matches!(f, W2s::Head(..))), 1, "{name}");
        }
    }
}

#[test]
fn fuel_memory_and_trap_classification() {
    // A finite 3M-iteration loop under 20,000 fuel: trap 1.
    let mut g = G::new();
    g.repeat(3_000_000, |_| {});
    g.head(200, &[]).write(b"FUEL-BURN-DONE");
    let r = one(&g.ret(0), DEFAULT.with(FUEL, 20_000));
    assert_eq!(r.end(7), Some(End::Trap(1)));
    let fuel = r.frames.iter().find_map(|f| if let W2s::End(_, _, u) = f { Some(*u) } else { None });
    assert_eq!(fuel, Some(20_000));
    // unreachable: trap 4.
    let mut g = G::new();
    g.op(&[0x00]);
    assert_eq!(one(&g.ret(0), DEFAULT).end(7), Some(End::Trap(4)));
    // memory.grow past memory_mib = 1 (16 pages) returns -1: the guest reports it.
    let mut g = G::new();
    g.i(20).op(&[0x40, 0x00]); // memory.grow 20 pages from 4 -> 24 > 16
    let mut w = Wasm::f14(g.b.clone());
    w.data = g.data.clone();
    assert!(matches!(one(&w.encode(), DEFAULT.with(MEM, 1)).end(7), Some(End::Code(u32::MAX))));
    // Initial memory above the cap (20 pages = 1.25 MiB > 1 MiB): never instantiated, trap 3.
    let mut w = Wasm::f14(i32c(0));
    w.mem = Some(20);
    assert_eq!(one(&w.encode(), DEFAULT.with(MEM, 1)).end(7), Some(End::Trap(3)));
    // Limits outside the F8 bounds end the session without a reply.
    let r = one(&Wasm::f14(i32c(0)).encode(), DEFAULT.with(FUEL, 1));
    assert_eq!(r.served, vec![Served::Closed(Closed::Limits)]);
    assert!(r.frames.is_empty());
}

#[test]
fn epoch_deadline_bounds_a_runaway_loop() {
    let eng = engine();
    let mut g = G::new();
    g.op(&[0x03, 0x40, 0x0c, 0x00, 0x0b]); // loop br 0 end
    let w = worker(&eng, &g.ret(0));
    let _ticker = EpochTicker::start(&eng).unwrap();
    let t = Instant::now();
    let r = drive(&w, &[(1, DEFAULT.with(FUEL, 1_000_000_000).with(WALL, 50), vec![])], vec![], OnDataRun::Reply);
    let took = t.elapsed();
    let load = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    eprintln!("epoch: {took:?} for wall_ms 50 (load {})", load.split_whitespace().next().unwrap_or("?"));
    assert_eq!(r.end(1), Some(End::Trap(2)));
    assert!(took < Duration::from_millis(1_000), "wall bound took {took:?}");
}

#[test]
fn cancel_and_out_of_order_frames() {
    let eng = engine();
    let mut g = G::new();
    g.data_run(&op_bytes(1)).head(200, &[]).write(b"x");
    let w = worker(&eng, &g.ret(0));
    // Cancel while data_run waits: nothing more is sent for the request.
    let r = drive(&w, &[(3, DEFAULT, vec![])], vec![], OnDataRun::Cancel);
    assert_eq!(r.served, vec![Served::Cancelled { rid: 3 }]);
    assert_eq!(r.count(|f| matches!(f, W2s::End(..) | W2s::Head(..))), 0);
    // A data-reply with the wrong seq: the session ends without a reply.
    let r = drive(&w, &[(3, DEFAULT, vec![])], result_rows(b"r"), OnDataRun::WrongSeq);
    assert_eq!(r.served, vec![Served::Closed(Closed::Io)]);
    assert_eq!(r.count(|f| matches!(f, W2s::End(..))), 0);
    // A cancel during the body: no request runs.
    let mut inbox = VecDeque::new();
    inbox.push_back(f_request(4, DEFAULT, &req_head_bytes()));
    inbox.push_back(f_body(4, b"a", false));
    inbox.push_back(f_cancel(4));
    let r = drive_frames(&w, inbox, vec![], OnDataRun::Reply, 1);
    assert_eq!(r.served, vec![Served::Cancelled { rid: 4 }]);
    assert!(r.frames.is_empty());
    // A body chunk for another req-id, a stray data-reply when idle, an undecodable frame: decode failure.
    for bad in [f_body(5, b"a", true), P::default().u(2).u(4).u(0).u(0).0, vec![0x7f]] {
        let mut inbox = VecDeque::new();
        if bad.first() == Some(&1) {
            inbox.push_back(f_request(4, DEFAULT, &req_head_bytes()));
        }
        inbox.push_back(bad);
        let r = drive_frames(&w, inbox, vec![], OnDataRun::Reply, 1);
        assert_eq!(r.served, vec![Served::Closed(Closed::Decode)]);
        assert!(r.frames.is_empty());
    }
    // An oversized frame (the transport reports it) and EOF.
    let mut inbox = VecDeque::new();
    inbox.push_back(vec![0; w.frame_max() + 1]);
    assert_eq!(drive_frames(&w, inbox, vec![], OnDataRun::Reply, 1).served, vec![Served::Closed(Closed::Io)]);
    assert_eq!(
        drive_frames(&w, VecDeque::new(), vec![], OnDataRun::Reply, 1).served,
        vec![Served::Closed(Closed::Eof)]
    );
}

#[test]
fn a_session_serves_many_requests_with_fresh_instances_and_generations() {
    let eng = engine();
    let mut g = G::new();
    g.data_run(&op_bytes(1)).i(BUF).get(0).op(&[0x36, 0x02, 0x00]).head(200, &[]);
    g.i(BUF).i(4).call(RESP_WRITE).drop_();
    let w = worker(&eng, &g.ret(0));
    let reqs: Vec<(u64, Lim, Vec<u8>)> = (1..=50).map(|rid| (rid, DEFAULT, vec![])).collect();
    let r = drive(&w, &reqs, result_rows(b"row"), OnDataRun::Reply);
    let mut prev = None;
    for rid in 1..=50u64 {
        assert_eq!(r.end(rid), Some(End::Code(0)), "request {rid}");
        let h = u32::from_le_bytes(r.body(rid).try_into().unwrap());
        assert_eq!(h & 0xffff, 0, "slot of the first data_run");
        let generation = h >> 16;
        assert_ne!(generation, 0);
        if !mutant_handle_not_cleared() {
            assert_ne!(Some(generation), prev, "generation repeated on consecutive requests");
        }
        prev = Some(generation);
        // seq restarts at 0 per request
        assert!(r.frames.contains(&W2s::DataRun(rid, 0, op_bytes(1))));
    }
}

#[cfg(feature = "test-hooks")]
#[test]
fn test_hooks_host_fault_codes() {
    let mut w = Wasm::f14(vec![]);
    w.imports.push(Imp::Func("env", "host_fault", 1, 0));
    w.exports = vec![("memory", 2, 0), ("handle", 0, 9)];
    let mut body = i32c(9);
    body.extend([0x10, 8]); // call env.host_fault(9)
    body.extend(i32c(0));
    w.funcs = vec![(0, 1, body)];
    assert_eq!(one(&w.encode(), DEFAULT).end(7), Some(End::Trap(abi::trap::HOST_FAULT)));
}
