//! AEGIS crash-harness tracing shim (LD_PRELOAD cdylib). Port of research round-002 `shim.c` to Rust, plus
//! fsync-EIO injection and protocol ack markers.
//!
//! Environment:
//!   AEGIS_LOG=<file>        trace output (text, one op per line; data hex-encoded)
//!   AEGIS_ROOT=<abs dir>    only paths under this directory are traced
//!   AEGIS_PROTO_FD=<n>      fd whose writes carry the subject protocol replies (default 1 = stdout).
//!                           A write starting with "OK <i>" logs `M <i>` (ack visible); "BEGUN <i>" logs `B <i>`.
//!   AEGIS_EIO_AT=<k>        the k-th (1-based) fsync/fdatasync on a traced path fails with EIO (logged `E <path>`)
//!   AEGIS_EIO_SWALLOW=1     self-test mutation: the injected failure is logged but reported to the caller as success
//!
//! Trace records: O path trunc | W path off len hex | S path [ds] (ds: O_DSYNC write, not an fsync call) | E path | T path len | A path mode off len |
//!   R from to | U path | X path (rmdir) | D path (mkdir) | M i | B i | MMAPW path len | MSYNC | Q op path (unmodelled op)
//!
//! Limits (see README): raw syscalls (rustix linux_raw, io_uring, static binaries) bypass LD_PRELOAD; mmap stores are
//! only flagged (MMAPW), not modelled. x86_64/aarch64 Linux glibc. The C-variadic `open/open64/openat/openat64`
//! live in `open_shim.c` (companion preload library built by build.rs) and call `aegis_shim_after_open`.
#![allow(clippy::missing_safety_doc)]
use libc::{c_char, c_int, c_uint, c_void, iovec, mode_t, off_t, size_t, ssize_t};
use std::cell::Cell;
use std::ffi::CStr;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering::*};
use std::sync::{Mutex, OnceLock};

struct St {
    log_fd: c_int,
    root: Vec<u8>,
    proto_fd: c_int,
    eio_at: u64,
    eio_swallow: bool,
}
static ST: OnceLock<Option<St>> = OnceLock::new();
static LOG_MU: Mutex<()> = Mutex::new(());
static SYNC_N: AtomicU64 = AtomicU64::new(0);
static FDSYNC: [AtomicU8; 65536] = [const { AtomicU8::new(0) }; 65536];
thread_local! { static BUSY: Cell<bool> = const { Cell::new(false) }; }

macro_rules! real {
    ($name:literal, $t:ty) => {{
        static P: AtomicUsize = AtomicUsize::new(0);
        let mut p = P.load(Relaxed);
        if p == 0 {
            p = unsafe { libc::dlsym(libc::RTLD_NEXT, concat!($name, "\0").as_ptr() as *const c_char) } as usize;
            P.store(p, Relaxed);
        }
        if p == 0 {
            unsafe { libc::abort() }
        }
        unsafe { std::mem::transmute::<usize, $t>(p) }
    }};
}

type WriteFn = unsafe extern "C" fn(c_int, *const c_void, size_t) -> ssize_t;
type OpenFn = unsafe extern "C" fn(*const c_char, c_int, c_uint) -> c_int;

fn st() -> Option<&'static St> {
    ST.get_or_init(|| {
        let log = std::env::var_os("AEGIS_LOG")?;
        let root = std::env::var_os("AEGIS_ROOT")?;
        use std::os::unix::ffi::OsStrExt;
        let mut lp = log.as_bytes().to_vec();
        lp.push(0);
        let ropen: OpenFn = real!("open", OpenFn);
        let fd = unsafe { ropen(lp.as_ptr() as *const c_char, libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND | libc::O_CLOEXEC, 0o644) };
        if fd < 0 {
            return None;
        }
        let env_u = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<i64>().ok());
        Some(St {
            log_fd: fd,
            root: root.as_bytes().to_vec(),
            proto_fd: env_u("AEGIS_PROTO_FD").unwrap_or(1) as c_int,
            eio_at: env_u("AEGIS_EIO_AT").unwrap_or(0).max(0) as u64,
            eio_swallow: std::env::var("AEGIS_EIO_SWALLOW").map(|v| v == "1").unwrap_or(false),
        })
    })
    .as_ref()
}

struct Guard;
impl Guard {
    fn enter() -> Option<Guard> {
        BUSY.with(|b| if b.get() { None } else { b.set(true); Some(Guard) })
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        BUSY.with(|b| b.set(false));
    }
}

fn emit(s: &St, rec: &[u8]) {
    let w: WriteFn = real!("write", WriteFn);
    let _g = LOG_MU.lock().unwrap_or_else(|e| e.into_inner());
    let mut off = 0;
    while off < rec.len() {
        let r = unsafe { w(s.log_fd, rec[off..].as_ptr() as *const c_void, rec.len() - off) };
        if r <= 0 {
            if r < 0 && unsafe { *libc::__errno_location() } == libc::EINTR {
                continue;
            }
            return;
        }
        off += r as usize;
    }
}

fn in_root(s: &St, p: &[u8]) -> bool {
    p.starts_with(&s.root) && (p.len() == s.root.len() || p[s.root.len()] == b'/')
}

fn readlink(p: &[u8]) -> Option<Vec<u8>> {
    let mut z = p.to_vec();
    z.push(0);
    let mut buf = vec![0u8; 4096];
    let k = unsafe { libc::readlink(z.as_ptr() as *const c_char, buf.as_mut_ptr() as *mut c_char, buf.len() - 1) };
    if k < 0 {
        return None;
    }
    buf.truncate(k as usize);
    Some(buf)
}

fn fdpath(s: &St, fd: c_int) -> Option<Vec<u8>> {
    if fd < 0 {
        return None;
    }
    let p = readlink(format!("/proc/self/fd/{fd}").as_bytes())?;
    if in_root(s, &p) { Some(p) } else { None }
}

fn absp(dirfd: c_int, p: *const c_char) -> Vec<u8> {
    let pb = unsafe { CStr::from_ptr(p) }.to_bytes();
    if pb.first() == Some(&b'/') {
        return pb.to_vec();
    }
    let base = if dirfd == libc::AT_FDCWD {
        let mut b = vec![0u8; 4096];
        let r = unsafe { libc::getcwd(b.as_mut_ptr() as *mut c_char, b.len()) };
        if r.is_null() {
            Vec::new()
        } else {
            let n = b.iter().position(|&c| c == 0).unwrap_or(0);
            b.truncate(n);
            b
        }
    } else {
        readlink(format!("/proc/self/fd/{dirfd}").as_bytes()).unwrap_or_default()
    };
    let mut out = base;
    out.push(b'/');
    out.extend_from_slice(pb);
    out
}

fn hex(out: &mut Vec<u8>, d: &[u8]) {
    const H: &[u8; 16] = b"0123456789abcdef";
    out.reserve(d.len() * 2);
    for &b in d {
        out.push(H[(b >> 4) as usize]);
        out.push(H[(b & 15) as usize]);
    }
}

fn rec_w(p: &[u8], off: i64, d: &[u8], sync_after: bool) -> Vec<u8> {
    let mut r = Vec::with_capacity(p.len() + 32 + d.len() * 2);
    r.extend_from_slice(b"W ");
    r.extend_from_slice(p);
    r.extend_from_slice(format!(" {} {} ", off, d.len()).as_bytes());
    hex(&mut r, d);
    r.push(b'\n');
    if sync_after {
        // O_DSYNC/O_SYNC write: durable on return. Tagged "ds" so it is not counted as an fsync call (EIO stage).
        r.extend_from_slice(b"S ");
        r.extend_from_slice(p);
        r.extend_from_slice(b" ds\n");
    }
    r
}

fn rec2(tag: &str, p: &[u8], tail: &str) -> Vec<u8> {
    let mut r = Vec::with_capacity(p.len() + tag.len() + tail.len() + 4);
    r.extend_from_slice(tag.as_bytes());
    r.push(b' ');
    r.extend_from_slice(p);
    r.extend_from_slice(tail.as_bytes());
    r.push(b'\n');
    r
}

fn fd_is_sync(fd: c_int) -> bool {
    (0..65536).contains(&fd) && FDSYNC[fd as usize].load(Relaxed) != 0
}

// ------------------------------------------------------------------ open family
fn after_open(dirfd: c_int, path: *const c_char, flags: c_int, rfd: c_int) -> c_int {
    if (0..65536).contains(&rfd) {
        FDSYNC[rfd as usize].store(((flags & (libc::O_DSYNC | libc::O_SYNC)) != 0) as u8, Relaxed);
    }
    if rfd < 0 || path.is_null() {
        return rfd;
    }
    let Some(_g) = Guard::enter() else { return rfd };
    let Some(s) = st() else { return rfd };
    let a = absp(dirfd, path);
    if in_root(s, &a) {
        emit(s, &rec2("O", &a, if flags & libc::O_TRUNC != 0 { " 1" } else { " 0" }));
    }
    rfd
}

/// Called by the C variadic `open*` entry points in `open_shim.c` (stable Rust cannot define C-variadics, and rustc
/// 1.99 rejects any fixed-arity definition of std's runtime `open` symbol), after the real call returned `rfd`.
#[unsafe(no_mangle)]
pub extern "C" fn aegis_shim_after_open(dirfd: c_int, path: *const c_char, flags: c_int, rfd: c_int) -> c_int {
    after_open(dirfd, path, flags, rfd)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn creat(path: *const c_char, mode: mode_t) -> c_int {
    {
        let f: OpenFn = real!("open", OpenFn);
        after_open(libc::AT_FDCWD, path, libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC, unsafe { f(path, libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC, mode) })
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn creat64(path: *const c_char, mode: mode_t) -> c_int {
    {
        let f: OpenFn = real!("open64", OpenFn);
        after_open(libc::AT_FDCWD, path, libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC, unsafe { f(path, libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC, mode) })
    }
}



// ------------------------------------------------------------------ data writes
fn proto_marker(s: &St, fd: c_int, b: *const c_void, r: ssize_t) {
    if fd != s.proto_fd || r <= 0 {
        return;
    }
    let d = unsafe { std::slice::from_raw_parts(b as *const u8, r as usize) };
    let line = d.split(|&c| c == b'\n').next().unwrap_or(&[]);
    let (tag, rest) = if let Some(x) = line.strip_prefix(b"OK ") {
        ("M", x)
    } else if let Some(x) = line.strip_prefix(b"BEGUN ") {
        ("B", x)
    } else {
        return;
    };
    let n: Vec<u8> = rest.iter().copied().take_while(u8::is_ascii_digit).collect();
    if !n.is_empty() {
        let mut v = format!("{tag} ").into_bytes();
        v.extend_from_slice(&n);
        v.push(b'\n');
        emit(s, &v);
    }
}

fn cur_off(fd: c_int) -> i64 {
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if fl >= 0 && fl & libc::O_APPEND != 0 {
        let mut stt: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stt) } == 0 {
            return stt.st_size;
        }
        return -1;
    }
    unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn write(fd: c_int, b: *const c_void, n: size_t) -> ssize_t {
    let f: WriteFn = real!("write", WriteFn);
    let g = Guard::enter();
    let s = if g.is_some() { st() } else { None };
    let traced = match s {
        Some(s) if fd > 2 || fd == s.proto_fd => fdpath(s, fd).map(|p| (p, cur_off(fd))),
        _ => None,
    };
    let r = unsafe { f(fd, b, n) };
    if let Some(s) = s {
        if let Some((p, off)) = traced {
            if r > 0 {
                let d = unsafe { std::slice::from_raw_parts(b as *const u8, r as usize) };
                emit(s, &rec_w(&p, off, d, fd_is_sync(fd)));
            }
        }
        proto_marker(s, fd, b, r);
    }
    r
}

type PwriteFn = unsafe extern "C" fn(c_int, *const c_void, size_t, off_t) -> ssize_t;
fn do_pwrite(f: PwriteFn, fd: c_int, b: *const c_void, n: size_t, off: off_t) -> ssize_t {
    let r = unsafe { f(fd, b, n, off) };
    if r > 0 {
        if let Some(_g) = Guard::enter() {
            if let Some(s) = st() {
                if let Some(p) = fdpath(s, fd) {
                    let d = unsafe { std::slice::from_raw_parts(b as *const u8, r as usize) };
                    emit(s, &rec_w(&p, off, d, fd_is_sync(fd)));
                }
            }
        }
    }
    r
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pwrite(fd: c_int, b: *const c_void, n: size_t, off: off_t) -> ssize_t {
    do_pwrite(real!("pwrite", PwriteFn), fd, b, n, off)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pwrite64(fd: c_int, b: *const c_void, n: size_t, off: off_t) -> ssize_t {
    do_pwrite(real!("pwrite64", PwriteFn), fd, b, n, off)
}

fn log_iov(s: &St, p: &[u8], v: *const iovec, c: c_int, mut off: i64, r: ssize_t, sync: bool) {
    let mut left = r as usize;
    let mut out = Vec::new();
    for i in 0..c.max(0) as usize {
        if left == 0 {
            break;
        }
        let io = unsafe { &*v.add(i) };
        let k = io.iov_len.min(left);
        let d = unsafe { std::slice::from_raw_parts(io.iov_base as *const u8, k) };
        out.extend(rec_w(p, off, d, false));
        off += k as i64;
        left -= k;
    }
    if sync {
        out.extend(rec2("S", p, " ds"));
    }
    emit(s, &out);
}
type WritevFn = unsafe extern "C" fn(c_int, *const iovec, c_int) -> ssize_t;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn writev(fd: c_int, v: *const iovec, c: c_int) -> ssize_t {
    let f: WritevFn = real!("writev", WritevFn);
    let g = Guard::enter();
    let s = if g.is_some() { st() } else { None };
    let traced = s.and_then(|s| if fd > 2 { fdpath(s, fd).map(|p| (p, cur_off(fd))) } else { None });
    let r = unsafe { f(fd, v, c) };
    if let (Some(s), Some((p, off))) = (s, traced) {
        if r > 0 {
            log_iov(s, &p, v, c, off, r, fd_is_sync(fd));
        }
    }
    r
}
type PwritevFn = unsafe extern "C" fn(c_int, *const iovec, c_int, off_t) -> ssize_t;
fn do_pwritev(r: ssize_t, fd: c_int, v: *const iovec, c: c_int, off: off_t, flags: c_int) -> ssize_t {
    if r > 0 {
        if let Some(_g) = Guard::enter() {
            if let Some(s) = st() {
                if let Some(p) = fdpath(s, fd) {
                    let off = if off == -1 { cur_off(fd) - r as i64 } else { off };
                    log_iov(s, &p, v, c, off, r, fd_is_sync(fd) || flags & (libc::RWF_DSYNC | libc::RWF_SYNC) != 0);
                }
            }
        }
    }
    r
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pwritev(fd: c_int, v: *const iovec, c: c_int, off: off_t) -> ssize_t {
    let f: PwritevFn = real!("pwritev", PwritevFn);
    do_pwritev(unsafe { f(fd, v, c, off) }, fd, v, c, off, 0)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pwritev64(fd: c_int, v: *const iovec, c: c_int, off: off_t) -> ssize_t {
    let f: PwritevFn = real!("pwritev64", PwritevFn);
    do_pwritev(unsafe { f(fd, v, c, off) }, fd, v, c, off, 0)
}
type Pwritev2Fn = unsafe extern "C" fn(c_int, *const iovec, c_int, off_t, c_int) -> ssize_t;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pwritev2(fd: c_int, v: *const iovec, c: c_int, off: off_t, fl: c_int) -> ssize_t {
    let f: Pwritev2Fn = real!("pwritev2", Pwritev2Fn);
    do_pwritev(unsafe { f(fd, v, c, off, fl) }, fd, v, c, off, fl)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pwritev64v2(fd: c_int, v: *const iovec, c: c_int, off: off_t, fl: c_int) -> ssize_t {
    let f: Pwritev2Fn = real!("pwritev64v2", Pwritev2Fn);
    do_pwritev(unsafe { f(fd, v, c, off, fl) }, fd, v, c, off, fl)
}

// ------------------------------------------------------------------ sync (with EIO injection)
type SyncFn = unsafe extern "C" fn(c_int) -> c_int;
fn do_sync(f: SyncFn, fd: c_int) -> c_int {
    let g = Guard::enter();
    let s = if g.is_some() { st() } else { None };
    let p = s.and_then(|s| fdpath(s, fd));
    if let (Some(s), Some(p)) = (s, p.as_ref()) {
        let k = SYNC_N.fetch_add(1, SeqCst) + 1;
        if s.eio_at != 0 && k == s.eio_at {
            // fsyncgate model: the kernel reports EIO and the dirty pages of this file may be dropped or marked clean.
            // The real fsync is NOT issued; the simulator treats this file's unsynced writes as limbo.
            emit(s, &rec2("E", p, ""));
            if s.eio_swallow {
                return 0;
            }
            unsafe { *libc::__errno_location() = libc::EIO };
            return -1;
        }
    }
    let r = unsafe { f(fd) };
    if let (Some(s), Some(p)) = (s, p) {
        if r == 0 {
            emit(s, &rec2("S", &p, ""));
        }
    }
    r
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsync(fd: c_int) -> c_int {
    do_sync(real!("fsync", SyncFn), fd)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fdatasync(fd: c_int) -> c_int {
    do_sync(real!("fdatasync", SyncFn), fd)
}

// ------------------------------------------------------------------ size changes
type FtruncFn = unsafe extern "C" fn(c_int, off_t) -> c_int;
fn do_ftrunc(f: FtruncFn, fd: c_int, len: off_t) -> c_int {
    let r = unsafe { f(fd, len) };
    if r == 0 {
        if let Some(_g) = Guard::enter() {
            if let Some(s) = st() {
                if let Some(p) = fdpath(s, fd) {
                    emit(s, &rec2("T", &p, &format!(" {len}")));
                }
            }
        }
    }
    r
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftruncate(fd: c_int, len: off_t) -> c_int {
    do_ftrunc(real!("ftruncate", FtruncFn), fd, len)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftruncate64(fd: c_int, len: off_t) -> c_int {
    do_ftrunc(real!("ftruncate64", FtruncFn), fd, len)
}
type TruncFn = unsafe extern "C" fn(*const c_char, off_t) -> c_int;
fn do_trunc(f: TruncFn, p: *const c_char, len: off_t) -> c_int {
    let r = unsafe { f(p, len) };
    if r == 0 {
        if let Some(_g) = Guard::enter() {
            if let Some(s) = st() {
                let a = absp(libc::AT_FDCWD, p);
                if in_root(s, &a) {
                    emit(s, &rec2("T", &a, &format!(" {len}")));
                }
            }
        }
    }
    r
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn truncate(p: *const c_char, len: off_t) -> c_int {
    do_trunc(real!("truncate", TruncFn), p, len)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn truncate64(p: *const c_char, len: off_t) -> c_int {
    do_trunc(real!("truncate64", TruncFn), p, len)
}
type FallocFn = unsafe extern "C" fn(c_int, c_int, off_t, off_t) -> c_int;
fn log_falloc(fd: c_int, mode: c_int, off: off_t, len: off_t) {
    if let Some(_g) = Guard::enter() {
        if let Some(s) = st() {
            if let Some(p) = fdpath(s, fd) {
                emit(s, &rec2("A", &p, &format!(" {mode} {off} {len}")));
            }
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fallocate(fd: c_int, mode: c_int, off: off_t, len: off_t) -> c_int {
    let f: FallocFn = real!("fallocate", FallocFn);
    let r = unsafe { f(fd, mode, off, len) };
    if r == 0 {
        log_falloc(fd, mode, off, len);
    }
    r
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fallocate64(fd: c_int, mode: c_int, off: off_t, len: off_t) -> c_int {
    let f: FallocFn = real!("fallocate64", FallocFn);
    let r = unsafe { f(fd, mode, off, len) };
    if r == 0 {
        log_falloc(fd, mode, off, len);
    }
    r
}
type PfallocFn = unsafe extern "C" fn(c_int, off_t, off_t) -> c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_fallocate(fd: c_int, off: off_t, len: off_t) -> c_int {
    let f: PfallocFn = real!("posix_fallocate", PfallocFn);
    let r = unsafe { f(fd, off, len) };
    if r == 0 {
        log_falloc(fd, 0, off, len);
    }
    r
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_fallocate64(fd: c_int, off: off_t, len: off_t) -> c_int {
    let f: PfallocFn = real!("posix_fallocate64", PfallocFn);
    let r = unsafe { f(fd, off, len) };
    if r == 0 {
        log_falloc(fd, 0, off, len);
    }
    r
}

// ------------------------------------------------------------------ namespace
fn log_ns(tag: &str, a: Vec<u8>, b: Option<Vec<u8>>) {
    if let Some(_g) = Guard::enter() {
        if let Some(s) = st() {
            if in_root(s, &a) || b.as_ref().is_some_and(|b| in_root(s, b)) {
                let mut r = Vec::new();
                r.extend_from_slice(tag.as_bytes());
                r.push(b' ');
                r.extend_from_slice(&a);
                if let Some(b) = b {
                    r.push(b' ');
                    r.extend_from_slice(&b);
                }
                r.push(b'\n');
                emit(s, &r);
            }
        }
    }
}
type RenameFn = unsafe extern "C" fn(*const c_char, *const c_char) -> c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rename(a: *const c_char, b: *const c_char) -> c_int {
    let f: RenameFn = real!("rename", RenameFn);
    let r = unsafe { f(a, b) };
    if r == 0 {
        log_ns("R", absp(libc::AT_FDCWD, a), Some(absp(libc::AT_FDCWD, b)));
    }
    r
}
type RenameAtFn = unsafe extern "C" fn(c_int, *const c_char, c_int, *const c_char) -> c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn renameat(d1: c_int, a: *const c_char, d2: c_int, b: *const c_char) -> c_int {
    let f: RenameAtFn = real!("renameat", RenameAtFn);
    let r = unsafe { f(d1, a, d2, b) };
    if r == 0 {
        log_ns("R", absp(d1, a), Some(absp(d2, b)));
    }
    r
}
type RenameAt2Fn = unsafe extern "C" fn(c_int, *const c_char, c_int, *const c_char, c_uint) -> c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn renameat2(d1: c_int, a: *const c_char, d2: c_int, b: *const c_char, fl: c_uint) -> c_int {
    let f: RenameAt2Fn = real!("renameat2", RenameAt2Fn);
    let r = unsafe { f(d1, a, d2, b, fl) };
    if r == 0 {
        // RENAME_EXCHANGE / RENAME_WHITEOUT are not modelled: flagged as Q so the simulator fails closed.
        log_ns(if fl == 0 || fl == libc::RENAME_NOREPLACE { "R" } else { "Q renameat2" }, absp(d1, a), Some(absp(d2, b)));
    }
    r
}
type UnlinkFn = unsafe extern "C" fn(*const c_char) -> c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unlink(p: *const c_char) -> c_int {
    let f: UnlinkFn = real!("unlink", UnlinkFn);
    let r = unsafe { f(p) };
    if r == 0 {
        log_ns("U", absp(libc::AT_FDCWD, p), None);
    }
    r
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rmdir(p: *const c_char) -> c_int {
    let f: UnlinkFn = real!("rmdir", UnlinkFn);
    let r = unsafe { f(p) };
    if r == 0 {
        log_ns("X", absp(libc::AT_FDCWD, p), None);
    }
    r
}
type UnlinkAtFn = unsafe extern "C" fn(c_int, *const c_char, c_int) -> c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unlinkat(d: c_int, p: *const c_char, fl: c_int) -> c_int {
    let f: UnlinkAtFn = real!("unlinkat", UnlinkAtFn);
    let r = unsafe { f(d, p, fl) };
    if r == 0 {
        log_ns(if fl & libc::AT_REMOVEDIR != 0 { "X" } else { "U" }, absp(d, p), None);
    }
    r
}
type MkdirFn = unsafe extern "C" fn(*const c_char, mode_t) -> c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mkdir(p: *const c_char, m: mode_t) -> c_int {
    let f: MkdirFn = real!("mkdir", MkdirFn);
    let r = unsafe { f(p, m) };
    if r == 0 {
        log_ns("D", absp(libc::AT_FDCWD, p), None);
    }
    r
}
type MkdirAtFn = unsafe extern "C" fn(c_int, *const c_char, mode_t) -> c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mkdirat(d: c_int, p: *const c_char, m: mode_t) -> c_int {
    let f: MkdirAtFn = real!("mkdirat", MkdirAtFn);
    let r = unsafe { f(d, p, m) };
    if r == 0 {
        log_ns("D", absp(d, p), None);
    }
    r
}
// Not modelled; logged so the simulator fails closed if a subject uses them under the root.
type LinkFn = unsafe extern "C" fn(*const c_char, *const c_char) -> c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn link(a: *const c_char, b: *const c_char) -> c_int {
    let f: LinkFn = real!("link", LinkFn);
    let r = unsafe { f(a, b) };
    if r == 0 {
        log_ns("Q link", absp(libc::AT_FDCWD, a), Some(absp(libc::AT_FDCWD, b)));
    }
    r
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn symlink(a: *const c_char, b: *const c_char) -> c_int {
    let f: LinkFn = real!("symlink", LinkFn);
    let r = unsafe { f(a, b) };
    if r == 0 {
        log_ns("Q symlink", absp(libc::AT_FDCWD, b), None);
    }
    r
}
type CopyFrFn = unsafe extern "C" fn(c_int, *mut i64, c_int, *mut i64, size_t, c_uint) -> ssize_t;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn copy_file_range(a: c_int, ao: *mut i64, b: c_int, bo: *mut i64, n: size_t, fl: c_uint) -> ssize_t {
    let f: CopyFrFn = real!("copy_file_range", CopyFrFn);
    let r = unsafe { f(a, ao, b, bo, n, fl) };
    if r > 0 {
        if let Some(_g) = Guard::enter() {
            if let Some(s) = st() {
                if let Some(p) = fdpath(s, b) {
                    emit(s, &rec2("Q copy_file_range", &p, ""));
                }
            }
        }
    }
    r
}

// ------------------------------------------------------------------ mmap (flagged only)
type MmapFn = unsafe extern "C" fn(*mut c_void, size_t, c_int, c_int, c_int, off_t) -> *mut c_void;
fn log_mmap(l: size_t, pr: c_int, fl: c_int, fd: c_int) {
    if fd >= 0 && pr & libc::PROT_WRITE != 0 && fl & libc::MAP_SHARED != 0 {
        if let Some(_g) = Guard::enter() {
            if let Some(s) = st() {
                if let Some(p) = fdpath(s, fd) {
                    emit(s, &rec2("MMAPW", &p, &format!(" {l}")));
                }
            }
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mmap(a: *mut c_void, l: size_t, pr: c_int, fl: c_int, fd: c_int, o: off_t) -> *mut c_void {
    let f: MmapFn = real!("mmap", MmapFn);
    let r = unsafe { f(a, l, pr, fl, fd, o) };
    if r != libc::MAP_FAILED {
        log_mmap(l, pr, fl, fd);
    }
    r
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mmap64(a: *mut c_void, l: size_t, pr: c_int, fl: c_int, fd: c_int, o: off_t) -> *mut c_void {
    let f: MmapFn = real!("mmap64", MmapFn);
    let r = unsafe { f(a, l, pr, fl, fd, o) };
    if r != libc::MAP_FAILED {
        log_mmap(l, pr, fl, fd);
    }
    r
}
type MsyncFn = unsafe extern "C" fn(*mut c_void, size_t, c_int) -> c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msync(a: *mut c_void, l: size_t, fl: c_int) -> c_int {
    let f: MsyncFn = real!("msync", MsyncFn);
    if let Some(_g) = Guard::enter() {
        if let Some(s) = st() {
            emit(s, b"MSYNC\n");
        }
    }
    unsafe { f(a, l, fl) }
}
