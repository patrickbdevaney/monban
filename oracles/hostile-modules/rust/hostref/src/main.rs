// hostref: reference aegis-p2 worker for oracles/hostile-modules (F14 guest ABI + worker frames).
//
// It implements the worker command line that oracles/hostile-modules/README.md fixes for aegis-p2:
//   hostref compile --in <module.wasm> --out <module.cwasm>     exit 0 = compiled; 78 = refused (F14 static check)
//   hostref zygote  --module <module.cwasm> --sha256 <hex>      fd 3 = listening SOCK_SEQPACKET socket; fork per
//                                                               connection, one request per child (fork+Wasm)
//   hostref cordon  --module <module.cwasm> --sha256 <hex>      fd 3 = listening SOCK_SEQPACKET socket; one
//                                                               connection, many requests, fresh instance each
// Mutants (oracle negative controls) are selected by AEGIS_P2_MUTANT, the selector the real aegis-p2 `mutants`
// build reads: extra-import, handle-not-cleared, no-hostcall-quota, no-fuel-no-epoch, no-limiter.
// HOSTILE_ESCAPED=1 turns the worker into a compromised worker (it forwards whatever the module emits, without the
// worker-side I5 checks, and appends a late response after a trap). The host level uses it to judge the
// supervisor's own decoder (SPEC_INVARIANTS H: host decoders of module output are in the verified TCB).
//
// Not a product: no sandbox (that is oracles/syscall-negative), on-demand allocation, reference simplicity first.
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use wasmtime::*;

const EX_CONFIG: i32 = 78;
const FRAME_MAX: usize = 65536; // F8 p2.frame_max_bytes default
const CHUNK: usize = 32768; // resp-body chunk size (< FRAME_MAX with header room)
const EPOCH_TICK_MS: u64 = 5;
const TABLE_MAX: usize = 65536; // reference table bound under the limiter (README)
const MAX_HEADER_FIELDS: usize = 128; // F8 limits.max_header_fields default
const MAX_HEADER_LIST: usize = 16384; // F8 limits.max_header_list_size default
const GUEST_API_VERSION: u64 = 1;

static ESCAPED: AtomicBool = AtomicBool::new(false);

fn die(code: i32, msg: &str) -> ! {
    eprintln!("hostref: {msg}");
    std::process::exit(code)
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Mutant {
    None,
    ExtraImport,
    HandleNotCleared,
    NoHostcallQuota,
    NoFuelNoEpoch,
    NoLimiter,
}
fn mutant() -> Mutant {
    match std::env::var("AEGIS_P2_MUTANT").unwrap_or_default().as_str() {
        "" | "none" => Mutant::None,
        "extra-import" => Mutant::ExtraImport,
        "handle-not-cleared" => Mutant::HandleNotCleared,
        "no-hostcall-quota" => Mutant::NoHostcallQuota,
        "no-fuel-no-epoch" => Mutant::NoFuelNoEpoch,
        "no-limiter" => Mutant::NoLimiter,
        // unknown names (e.g. a host-level mutant name inherited from the supervisor) leave the worker golden
        _ => Mutant::None,
    }
}

// ------------------------------------------------------------------------------------------------ sha256
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
        0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
        0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] =
        [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    let mut m = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    m.push(0x80);
    while m.len() % 64 != 56 {
        m.push(0);
    }
    m.extend_from_slice(&bits.to_be_bytes());
    for blk in m.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([blk[4 * i], blk[4 * i + 1], blk[4 * i + 2], blk[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let mj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(mj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 32];
    for (i, x) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&x.to_be_bytes());
    }
    out
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ------------------------------------------------------------------------------------------------ postcard (F10 rule)
#[derive(Default)]
struct Enc(Vec<u8>);
impl Enc {
    fn u(&mut self, mut v: u64) -> &mut Self {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.0.push(b);
                return self;
            }
            self.0.push(b | 0x80);
        }
    }
    fn b(&mut self, s: &[u8]) -> &mut Self {
        self.u(s.len() as u64);
        self.0.extend_from_slice(s);
        self
    }
    fn raw(&mut self, s: &[u8]) -> &mut Self {
        self.0.extend_from_slice(s);
        self
    }
}
struct Dec<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> Dec<'a> {
    fn new(b: &'a [u8]) -> Self {
        Dec { b, i: 0 }
    }
    fn u(&mut self) -> Option<u64> {
        let mut v: u64 = 0;
        for k in 0..10 {
            let x = *self.b.get(self.i)?;
            self.i += 1;
            v |= u64::from(x & 0x7f) << (7 * k);
            if x & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = usize::try_from(self.u()?).ok()?;
        let end = self.i.checked_add(n)?;
        let s = self.b.get(self.i..end)?;
        self.i = end;
        Some(s)
    }
    fn byte(&mut self) -> Option<u8> {
        let x = *self.b.get(self.i)?;
        self.i += 1;
        Some(x)
    }
    fn rest(&mut self) -> &'a [u8] {
        let r = self.b.get(self.i..).unwrap_or(&[]);
        self.i = self.b.len();
        r
    }
    fn done(&self) -> bool {
        self.i == self.b.len()
    }
}

// ------------------------------------------------------------------------------------------------ socket io
fn send_frame(fd: i32, f: &[u8]) -> bool {
    let n = unsafe { libc::send(fd, f.as_ptr().cast(), f.len(), libc::MSG_NOSIGNAL) };
    n >= 0 && n as usize == f.len()
}
fn recv_frame(fd: i32) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; FRAME_MAX + 1];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if n <= 0 || n as usize > FRAME_MAX {
            return None;
        }
        buf.truncate(n as usize);
        return Some(buf);
    }
}
fn urandom_u16() -> u32 {
    let mut b = [0u8; 2];
    if std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).is_err() {
        die(70, "urandom");
    }
    u32::from(u16::from_le_bytes(b))
}

// ------------------------------------------------------------------------------------------------ per-request state
#[derive(Clone, Copy, Debug)]
struct Limits {
    fuel: u64,
    wall_ms: u64,
    memory_mib: u64,
    max_host_calls: u64,
    max_data_runs: u64,
    max_data_bytes: u64,
    max_resp_bytes: u64,
    max_log_bytes: u64,
}
// Boot ceilings: the F8 maxima. The worker applies min(frame value, ceiling) and never raises a limit.
const CEIL: Limits = Limits {
    fuel: 1_000_000_000,
    wall_ms: 1000,
    memory_mib: 256,
    max_host_calls: 1_000_000,
    max_data_runs: 1024,
    max_data_bytes: 67_108_864,
    max_resp_bytes: 16_777_216,
    max_log_bytes: 1_048_576,
};

#[derive(Default, Clone)]
struct HandleTable {
    gen: u32,
    slots: Vec<Option<Vec<u8>>>,
}

struct Req {
    fd: i32,
    rid: u64,
    lim: Limits,
    head: Vec<u8>,
    body: Vec<u8>,
    body_off: usize,
    ht: HandleTable,
    calls: u64,
    data_runs: u64,
    data_bytes: u64,
    resp_bytes: u64,
    log_bytes: u64,
    resp_started: bool,
    fault: Option<u64>,
    cancelled: bool,
    mutant: Mutant,
}
impl ResourceLimiter for Req {
    fn memory_growing(&mut self, _c: usize, desired: usize, _m: Option<usize>) -> Result<bool> {
        if self.mutant == Mutant::NoLimiter {
            return Ok(true); // MUTANT no-limiter
        }
        Ok(desired as u64 <= self.lim.memory_mib << 20)
    }
    fn table_growing(&mut self, _c: usize, desired: usize, _m: Option<usize>) -> Result<bool> {
        if self.mutant == Mutant::NoLimiter {
            return Ok(true); // MUTANT no-limiter
        }
        Ok(desired <= TABLE_MAX)
    }
}

fn fault(c: &mut Caller<'_, Req>, code: u64) -> Error {
    if c.data().fault.is_none() {
        c.data_mut().fault = Some(code);
    }
    Error::msg(format!("f14 trap {code}"))
}
fn count(c: &mut Caller<'_, Req>) -> Result<()> {
    c.data_mut().calls += 1;
    let d = c.data();
    if d.mutant != Mutant::NoHostcallQuota && d.calls > d.lim.max_host_calls {
        return Err(fault(c, 6));
    }
    Ok(())
}
fn memory(c: &mut Caller<'_, Req>) -> Result<Memory> {
    match c.get_export("memory") {
        Some(Extern::Memory(m)) => Ok(m),
        _ => Err(fault(c, 7)),
    }
}
fn read_guest(c: &mut Caller<'_, Req>, ptr: i32, len: i32) -> Result<Vec<u8>> {
    let m = memory(c)?;
    let (p, l) = (ptr as u32 as usize, len as u32 as usize);
    let data = m.data(&*c);
    match p.checked_add(l).and_then(|e| data.get(p..e)) {
        Some(s) => Ok(s.to_vec()),
        None => Err(fault(c, 7)),
    }
}
fn write_guest(c: &mut Caller<'_, Req>, ptr: i32, src: &[u8]) -> Result<()> {
    let m = memory(c)?;
    let p = ptr as u32 as usize;
    let data = m.data_mut(&mut *c);
    match p.checked_add(src.len()).and_then(|e| data.get_mut(p..e)) {
        Some(d) => {
            d.copy_from_slice(src);
            Ok(())
        }
        None => Err(fault(c, 7)),
    }
}
fn send(c: &mut Caller<'_, Req>, f: &[u8]) -> Result<()> {
    if send_frame(c.data().fd, f) {
        Ok(())
    } else {
        c.data_mut().cancelled = true;
        Err(Error::msg("supervisor gone"))
    }
}

// I5 header rules (F14): reject, never repair.
fn headers_ok(enc: &[u8]) -> bool {
    let mut d = Dec::new(enc);
    let Some(n) = d.u() else { return false };
    if n as usize > MAX_HEADER_FIELDS {
        return false;
    }
    let mut total = 0usize;
    for _ in 0..n {
        let (Some(name), Some(value)) = (d.bytes(), d.bytes()) else { return false };
        if name.is_empty() || name.len() > 64 || std::str::from_utf8(name).is_err() {
            return false;
        }
        let tchar = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&b);
        if !name.iter().all(|&b| tchar(b)) {
            return false;
        }
        let nm = std::str::from_utf8(name).unwrap_or("");
        let banned = ["content-length", "transfer-encoding", "connection", "keep-alive", "upgrade", "te", "trailer"];
        if banned.contains(&nm) || nm.starts_with("proxy-") {
            return false;
        }
        if !value.iter().all(|&b| b == b' ' || b == b'\t' || (0x21..=0x7e).contains(&b)) {
            return false;
        }
        if value.first().is_some_and(|&b| b == b' ' || b == b'\t') || value.last().is_some_and(|&b| b == b' ' || b == b'\t') {
            return false;
        }
        total += name.len() + value.len() + 32;
    }
    d.done() && total <= MAX_HEADER_LIST
}

fn linker(eng: &Engine, m: Mutant) -> Linker<Req> {
    let mut l = Linker::<Req>::new(eng);
    let r = (|| -> Result<()> {
        l.func_wrap("aegis", "req_head", |mut c: Caller<'_, Req>, dst: i32, cap: i32| -> Result<i32> {
            count(&mut c)?;
            let h = c.data().head.clone();
            if cap as u32 as usize >= h.len() {
                write_guest(&mut c, dst, &h)?;
            }
            Ok(h.len() as i32)
        })?;
        l.func_wrap("aegis", "req_body_read", |mut c: Caller<'_, Req>, dst: i32, cap: i32| -> Result<i32> {
            count(&mut c)?;
            let (off, len) = (c.data().body_off, c.data().body.len());
            let n = (cap as u32 as usize).min(len - off);
            let chunk = c.data().body[off..off + n].to_vec();
            write_guest(&mut c, dst, &chunk)?;
            c.data_mut().body_off += n;
            Ok(n as i32)
        })?;
        l.func_wrap("aegis", "resp_head", |mut c: Caller<'_, Req>, status: i32, src: i32, len: i32| -> Result<i32> {
            count(&mut c)?;
            let esc = ESCAPED.load(Ordering::Relaxed);
            if c.data().resp_started && !esc {
                return Err(fault(&mut c, 7));
            }
            if !esc && !(200..=599).contains(&status) {
                return Err(fault(&mut c, 7));
            }
            let hb = read_guest(&mut c, src, len)?;
            if !esc && !headers_ok(&hb) {
                return Err(fault(&mut c, 7));
            }
            c.data_mut().resp_started = true;
            let rid = c.data().rid;
            let mut e = Enc::default();
            e.u(17).u(rid).u(status as u32 as u64).raw(&hb);
            send(&mut c, &e.0)?;
            Ok(0)
        })?;
        l.func_wrap("aegis", "resp_write", |mut c: Caller<'_, Req>, src: i32, len: i32| -> Result<i32> {
            count(&mut c)?;
            if !c.data().resp_started {
                return Err(fault(&mut c, 7));
            }
            let b = read_guest(&mut c, src, len)?;
            c.data_mut().resp_bytes += b.len() as u64;
            if c.data().resp_bytes > c.data().lim.max_resp_bytes {
                return Err(fault(&mut c, 6));
            }
            let rid = c.data().rid;
            let step = if ESCAPED.load(Ordering::Relaxed) { usize::MAX } else { CHUNK };
            let mut off = 0;
            while off < b.len() {
                let end = b.len().min(off.saturating_add(step));
                let mut e = Enc::default();
                e.u(18).u(rid).b(&b[off..end]);
                send(&mut c, &e.0)?;
                off = end;
            }
            Ok(0)
        })?;
        l.func_wrap("aegis", "log", |mut c: Caller<'_, Req>, level: i32, src: i32, len: i32| -> Result<i32> {
            count(&mut c)?;
            if !(0..=4).contains(&level) {
                return Err(fault(&mut c, 7));
            }
            let b = read_guest(&mut c, src, len)?;
            c.data_mut().log_bytes += b.len() as u64;
            if c.data().log_bytes > c.data().lim.max_log_bytes {
                return Err(fault(&mut c, 6));
            }
            let rid = c.data().rid;
            let mut e = Enc::default();
            e.u(21).u(rid).u(level as u64).b(&b);
            send(&mut c, &e.0)?;
            Ok(0)
        })?;
        l.func_wrap("aegis", "data_run", |mut c: Caller<'_, Req>, src: i32, len: i32| -> Result<i32> {
            count(&mut c)?;
            let op = read_guest(&mut c, src, len)?;
            c.data_mut().data_runs += 1;
            c.data_mut().data_bytes += op.len() as u64;
            let d = c.data();
            if d.data_runs > d.lim.max_data_runs || d.data_bytes > d.lim.max_data_bytes || d.data_runs > 65536 {
                return Err(fault(&mut c, 6));
            }
            let seq = c.data().ht.slots.len() as u64;
            let rid = c.data().rid;
            let mut e = Enc::default();
            e.u(20).u(rid).u(seq).b(&op);
            send(&mut c, &e.0)?;
            // block until the matching data-reply (or cancel / EOF)
            let fd = c.data().fd;
            let result = loop {
                let Some(f) = recv_frame(fd) else {
                    c.data_mut().cancelled = true;
                    return Err(Error::msg("supervisor gone"));
                };
                let mut d = Dec::new(&f);
                match (d.u(), d.u()) {
                    (Some(2), Some(r)) if r == rid => {
                        if d.u() != Some(seq) {
                            c.data_mut().cancelled = true;
                            return Err(Error::msg("data-reply out of order"));
                        }
                        break d.rest().to_vec();
                    }
                    (Some(3), Some(r)) if r == rid => {
                        c.data_mut().cancelled = true;
                        return Err(Error::msg("cancelled"));
                    }
                    _ => {
                        c.data_mut().cancelled = true;
                        return Err(Error::msg("unexpected frame"));
                    }
                }
            };
            c.data_mut().data_bytes += result.len() as u64;
            if c.data().data_bytes > c.data().lim.max_data_bytes {
                return Err(fault(&mut c, 6));
            }
            let gen = c.data().ht.gen;
            c.data_mut().ht.slots.push(Some(result));
            Ok(((gen << 16) | (seq as u32 & 0xffff)) as i32)
        })?;
        fn slot(c: &mut Caller<'_, Req>, h: i32) -> Result<usize> {
            let h = h as u32;
            let (g, s) = (h >> 16, (h & 0xffff) as usize);
            let ht = &c.data().ht;
            if g == 0 || g != ht.gen || !matches!(ht.slots.get(s), Some(Some(_))) {
                return Err(fault(c, 5));
            }
            Ok(s)
        }
        l.func_wrap("aegis", "result_read", |mut c: Caller<'_, Req>, h: i32, dst: i32, cap: i32| -> Result<i32> {
            count(&mut c)?;
            let s = slot(&mut c, h)?;
            let r = c.data().ht.slots[s].clone().unwrap_or_default();
            if cap as u32 as usize >= r.len() {
                write_guest(&mut c, dst, &r)?;
            }
            Ok(r.len() as i32)
        })?;
        l.func_wrap("aegis", "handle_drop", |mut c: Caller<'_, Req>, h: i32| -> Result<()> {
            count(&mut c)?;
            let s = slot(&mut c, h)?;
            c.data_mut().ht.slots[s] = None;
            Ok(())
        })?;
        if m == Mutant::ExtraImport {
            // MUTANT extra-import: the test-only import leaks into a golden build's Linker (and allowlist)
            l.func_wrap("env", "host_fault", |mut c: Caller<'_, Req>, code: i32| -> Result<()> {
                count(&mut c)?;
                if code == 3 {
                    Ok(())
                } else {
                    Err(fault(&mut c, 8))
                }
            })?;
        }
        Ok(())
    })();
    if let Err(e) = r {
        die(70, &format!("linker: {e}"));
    }
    l
}

// ------------------------------------------------------------------------------------------------ engine + compile
fn engine() -> Engine {
    let mut c = Config::new();
    c.strategy(Strategy::Cranelift);
    c.wasm_memory64(false);
    c.consume_fuel(true);
    c.epoch_interruption(true);
    // default 4 GiB reservation + 32 MiB guard (never shrunk, R-ISO-2); on-demand allocation in the reference so
    // that only the ResourceLimiter bounds memory and tables (a pool bound would mask the no-limiter mutant)
    Engine::new(&c).unwrap_or_else(|e| die(70, &format!("engine: {e}")))
}

fn allowlist(m: Mutant) -> Vec<(&'static str, &'static str, Vec<ValType>, Vec<ValType>)> {
    use ValType::I32;
    let mut v = vec![
        ("aegis", "req_head", vec![I32, I32], vec![I32]),
        ("aegis", "req_body_read", vec![I32, I32], vec![I32]),
        ("aegis", "resp_head", vec![I32, I32, I32], vec![I32]),
        ("aegis", "resp_write", vec![I32, I32], vec![I32]),
        ("aegis", "log", vec![I32, I32, I32], vec![I32]),
        ("aegis", "data_run", vec![I32, I32], vec![I32]),
        ("aegis", "result_read", vec![I32, I32, I32], vec![I32]),
        ("aegis", "handle_drop", vec![I32], vec![]),
    ];
    if m == Mutant::ExtraImport {
        v.push(("env", "host_fault", vec![I32], vec![])); // MUTANT extra-import
    }
    v
}
fn vt_eq(a: &[ValType], b: &[ValType]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| matches!((x, y), (ValType::I32, ValType::I32)))
}

fn compile(args: &[String]) {
    let inp = arg(args, "in");
    let out = arg(args, "out");
    let eng = engine();
    let bytes = std::fs::read(&inp).unwrap_or_else(|e| die(EX_CONFIG, &format!("read {inp}: {e}")));
    let module = Module::new(&eng, &bytes).unwrap_or_else(|e| die(EX_CONFIG, &format!("refused (invalid): {e}")));
    let al = allowlist(mutant());
    for imp in module.imports() {
        let ok = match imp.ty() {
            ExternType::Func(ft) => al.iter().any(|(m, n, p, r)| {
                *m == imp.module() && *n == imp.name() && vt_eq(&ft.params().collect::<Vec<_>>(), p)
                    && vt_eq(&ft.results().collect::<Vec<_>>(), r)
            }),
            _ => false,
        };
        if !ok {
            die(EX_CONFIG, &format!("refused: import {}.{} not in the F14 allowlist", imp.module(), imp.name()));
        }
    }
    let mut seen = (false, false);
    for ex in module.exports() {
        match (ex.name(), ex.ty()) {
            ("memory", ExternType::Memory(mt)) if !mt.is_64() => seen.0 = true,
            ("handle", ExternType::Func(ft)) if ft.params().len() == 0 && vt_eq(&ft.results().collect::<Vec<_>>(), &[ValType::I32]) => {
                seen.1 = true
            }
            (n, _) => die(EX_CONFIG, &format!("refused: export {n} not in F14")),
        }
    }
    if seen != (true, true) {
        die(EX_CONFIG, "refused: exports must be exactly memory and handle() -> i32");
    }
    let ser = module.serialize().unwrap_or_else(|e| die(70, &format!("serialize: {e}")));
    let tmp = format!("{out}.tmp{}", std::process::id());
    if std::fs::write(&tmp, ser).and_then(|_| std::fs::rename(&tmp, &out)).is_err() {
        die(70, "write cwasm");
    }
}

fn arg(args: &[String], k: &str) -> String {
    let key = format!("--{k}");
    args.iter()
        .position(|a| *a == key)
        .and_then(|i| args.get(i + 1).cloned())
        .unwrap_or_else(|| die(EX_CONFIG, &format!("missing --{k}")))
}

fn load(args: &[String], eng: &Engine) -> (InstancePre<Req>, [u8; 32]) {
    let p = arg(args, "module");
    let want = arg(args, "sha256");
    let bytes = std::fs::read(&p).unwrap_or_else(|e| die(EX_CONFIG, &format!("read {p}: {e}")));
    let dig = sha256(&bytes);
    if hex(&dig) != want.to_ascii_lowercase() {
        die(EX_CONFIG, "cwasm digest mismatch: refusing to deserialize");
    }
    // SAFETY (oracle reference): the bytes were produced by `hostref compile` with this engine config and their
    // sha256 equals the digest the (mock) supervisor recorded for that compile (the D4 rule).
    let m = unsafe { Module::deserialize(eng, &bytes) }.unwrap_or_else(|e| die(EX_CONFIG, &format!("cwasm: {e}")));
    let l = linker(eng, mutant());
    let pre = l.instantiate_pre(&m).unwrap_or_else(|e| die(EX_CONFIG, &format!("instantiate_pre: {e}")));
    (pre, dig)
}

// ------------------------------------------------------------------------------------------------ serving
fn listen_fd() -> i32 {
    3
}
fn accept(l: i32) -> i32 {
    loop {
        let fd = unsafe { libc::accept4(l, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
        if fd >= 0 {
            return fd;
        }
        let e = std::io::Error::last_os_error().raw_os_error();
        if e == Some(libc::EINTR) || e == Some(libc::ECONNABORTED) {
            continue;
        }
        die(70, &format!("accept: {e:?}"));
    }
}

fn parse_limits(d: &mut Dec) -> Option<Limits> {
    let mut v = [0u64; 8];
    for x in v.iter_mut() {
        *x = d.u()?;
    }
    Some(Limits {
        fuel: v[0].min(CEIL.fuel),
        wall_ms: v[1].clamp(1, CEIL.wall_ms),
        memory_mib: v[2].min(CEIL.memory_mib),
        max_host_calls: v[3].min(CEIL.max_host_calls),
        max_data_runs: v[4].min(CEIL.max_data_runs),
        max_data_bytes: v[5].min(CEIL.max_data_bytes),
        max_resp_bytes: v[6].min(CEIL.max_resp_bytes),
        max_log_bytes: v[7].min(CEIL.max_log_bytes),
    })
}

enum End {
    Code(u32),
    Trap(u64),
}

/// Serves one request whose `request` frame is `f`. Returns false when the connection must close.
fn serve_request(fd: i32, eng: &Engine, pre: &InstancePre<Req>, f: &[u8], carry: &mut Option<HandleTable>, fork_child: bool) -> bool {
    let m = mutant();
    let mut d = Dec::new(f);
    let (Some(0), Some(rid)) = (d.u(), d.u()) else { return false };
    let Some(lim) = parse_limits(&mut d) else { return false };
    let head = d.rest().to_vec();
    // body chunks until last = true
    let mut body = Vec::new();
    loop {
        let Some(bf) = recv_frame(fd) else { return false };
        let mut d = Dec::new(&bf);
        match (d.u(), d.u()) {
            (Some(1), Some(r)) if r == rid => {
                let Some(c) = d.bytes() else { return false };
                body.extend_from_slice(c);
                match d.byte() {
                    Some(1) => break,
                    Some(0) => continue,
                    _ => return false,
                }
            }
            (Some(3), Some(r)) if r == rid => return true,
            _ => return false,
        }
    }
    let ht = match (m, carry.take()) {
        (Mutant::HandleNotCleared, Some(t)) => t, // MUTANT handle-not-cleared: previous request's table + generation
        _ => HandleTable { gen: urandom_u16().max(1), slots: Vec::new() },
    };
    let mut st = Store::new(
        eng,
        Req {
            fd,
            rid,
            lim,
            head,
            body,
            body_off: 0,
            ht,
            calls: 0,
            data_runs: 0,
            data_bytes: 0,
            resp_bytes: 0,
            log_bytes: 0,
            resp_started: false,
            fault: None,
            cancelled: false,
            mutant: m,
        },
    );
    st.limiter(|r| r);
    let nodeadline = m == Mutant::NoFuelNoEpoch;
    let fuel = if nodeadline { u64::MAX / 4 } else { lim.fuel }; // MUTANT no-fuel-no-epoch: unbounded fuel
    let _ = st.set_fuel(fuel);
    st.set_epoch_deadline(if nodeadline { u64::MAX / 4 } else { (lim.wall_ms / EPOCH_TICK_MS).max(1) });
    st.epoch_deadline_trap();
    if fork_child && !nodeadline {
        itimer(lim.wall_ms + 1000); // backstop: SIGALRM kills a child whose epoch trap did not fire
    }
    let res = pre.instantiate(&mut st).and_then(|i| {
        let h = i.get_typed_func::<(), i32>(&mut st, "handle")?;
        h.call(&mut st, ())
    });
    let instantiated_ok = res.is_ok();
    let end = match res {
        Ok(code) => End::Code(code as u32),
        Err(e) => {
            if st.data().cancelled {
                return false;
            }
            let code = st.data().fault.unwrap_or_else(|| match e.downcast_ref::<Trap>() {
                Some(Trap::OutOfFuel) => 1,
                Some(Trap::Interrupt) => 2,
                Some(_) => 4,
                None => 3, // instantiation refused by the limiter (initial memory/table over the cap)
            });
            End::Trap(code)
        }
    };
    let _ = instantiated_ok;
    let used = fuel.saturating_sub(st.get_fuel().unwrap_or(0));
    if m == Mutant::HandleNotCleared {
        *carry = Some(st.data().ht.clone());
    }
    let mut e = Enc::default();
    e.u(19).u(rid);
    let trapped = matches!(end, End::Trap(_));
    match end {
        End::Code(c) => e.u(0).u(u64::from(c)),
        End::Trap(t) => e.u(1).u(t),
    };
    e.u(used.min(lim.fuel));
    if !send_frame(fd, &e.0) {
        return false;
    }
    if trapped && ESCAPED.load(Ordering::Relaxed) {
        // compromised worker: a late response for the finished req-id (ext_proc CVE-2026-47207 pattern)
        let mut h = Enc::default();
        h.u(17).u(rid).u(200).u(1).b(b"x-late").b(b"1");
        let mut b = Enc::default();
        b.u(18).u(rid).b(b"LATE-SECRET");
        let mut z = Enc::default();
        z.u(19).u(rid).u(0).u(0).u(0);
        let _ = send_frame(fd, &h.0) && send_frame(fd, &b.0) && send_frame(fd, &z.0);
    }
    true
}

fn itimer(ms: u64) {
    unsafe {
        let t = libc::itimerval {
            it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
            it_value: libc::timeval { tv_sec: (ms / 1000) as i64, tv_usec: ((ms % 1000) * 1000) as i64 },
        };
        libc::setitimer(libc::ITIMER_REAL, &t, std::ptr::null_mut());
    }
}

fn ready(fd: i32, dig: &[u8; 32]) -> bool {
    let mut e = Enc::default();
    e.u(16).u(0).u(GUEST_API_VERSION).b(dig);
    send_frame(fd, &e.0)
}

fn ticker(eng: &Engine) {
    let e2 = eng.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(EPOCH_TICK_MS));
        e2.increment_epoch();
    });
}

fn zygote(args: &[String]) {
    let eng = engine();
    let (pre, dig) = load(args, &eng);
    let l = listen_fd();
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_IGN);
    }
    loop {
        let fd = accept(l);
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe {
                libc::close(l);
            }
            ticker(&eng); // the zygote is single-threaded; the child gets its own epoch ticker
            let mut carry = None;
            if ready(fd, &dig) {
                if let Some(f) = recv_frame(fd) {
                    serve_request(fd, &eng, &pre, &f, &mut carry, true);
                }
            }
            unsafe { libc::_exit(0) };
        }
        unsafe {
            libc::close(fd);
        }
    }
}

fn cordon(args: &[String]) {
    let eng = engine();
    let (pre, dig) = load(args, &eng);
    ticker(&eng);
    let l = listen_fd();
    let mut carry = None;
    loop {
        let fd = accept(l);
        if ready(fd, &dig) {
            while let Some(f) = recv_frame(fd) {
                if !serve_request(fd, &eng, &pre, &f, &mut carry, false) {
                    break;
                }
            }
        }
        unsafe {
            libc::close(fd);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if std::env::var("HOSTILE_ESCAPED").ok().as_deref() == Some("1") {
        ESCAPED.store(true, Ordering::Relaxed);
    }
    match args.get(1).map(String::as_str) {
        Some("compile") => compile(&args),
        Some("zygote") => zygote(&args),
        Some("cordon") => cordon(&args),
        _ => die(EX_CONFIG, "usage: hostref compile|zygote|cordon ..."),
    }
}
