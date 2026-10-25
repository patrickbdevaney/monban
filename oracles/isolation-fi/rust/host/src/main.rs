// isofi: reference P2 isolation subjects + fault-injection driver for oracles/isolation-fi and spike q4-006.
//
// Ported (rewritten, not copied) from research/state/raw/round-004/04-work/fi/{fiwasm,finat,guest} (Wasmtime 48.0.7,
// round-004 blast-radius experiment). Differences: Wasmtime 49.0.3, fuel budget, fork+Wasm zygote, host-abort
// fault class, per-fault recovery metric, process-group cleanup, mutations for the oracle self-test.
//
// Subcommands:
//   isofi serve cordon   --guest G --data D [--threads 64] [--budget epoch|fuel:N|none] [--epoch-ms 100]
//                        [--mutation none|shared-store|recycle50] [--sandbox 1]
//       fresh Store+Instance per request from a 64-slot pooling allocator inside one sandboxed process (the
//       "fresh-Wasm cordon"). Listening socket = fd 3 (supervisor-held, socket activation).
//   isofi serve forkwasm --guest G --data D [--budget ...] [--epoch-ms 100] [--pool ondemand|pool]
//                        [--mutation none|no-fork] [--sandbox 1]
//       single-threaded zygote with Engine+Module+InstancePre loaded and Landlock+seccomp installed; fork per
//       request; child instantiates, runs, replies, _exit. Wall-clock bound = ITIMER_REAL in the child.
//   isofi drive --server '<cmd with {guest} {data}>' --fault F --rate R --n N --conc C --seed S --prefix P
//               --server-core C --client-cores a,b,c --guest G --data D
//       closed-loop client + supervisor (restart on exit, 2 s liveness watchdog). Prints one JSON line.
//   isofi calibrate --guest G       fuel per healthy request, fuel per ms of a looping guest
//   isofi forkcost --guest G --n N [--pool ondemand|pool] [--fuel N]   fork-from-zygote cost microbench
#[path = "../../work.rs"]
mod work;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use wasmtime::*;
use work::*;

const EPOCH_TICK_MS: u64 = 10;
// Host state that a guest-triggerable host bug can corrupt (fault class hostpoison). It lives as long as the host
// process: for the fork+Wasm path that is one request, for a cordon every later request it serves.
static HOST_CORRUPT: AtomicBool = AtomicBool::new(false);

fn die(msg: &str) -> ! {
    eprintln!("isofi: {msg}");
    std::process::exit(2)
}

struct Args {
    pos: Vec<String>,
    kv: HashMap<String, String>,
}
impl Args {
    fn parse() -> Args {
        let mut pos = Vec::new();
        let mut kv = HashMap::new();
        let mut it = std::env::args().skip(1);
        while let Some(a) = it.next() {
            if let Some(k) = a.strip_prefix("--") {
                kv.insert(k.to_string(), it.next().unwrap_or_default());
            } else {
                pos.push(a);
            }
        }
        Args { pos, kv }
    }
    fn s(&self, k: &str, d: &str) -> String {
        self.kv.get(k).cloned().unwrap_or_else(|| d.to_string())
    }
    fn req(&self, k: &str) -> String {
        self.kv.get(k).cloned().unwrap_or_else(|| die(&format!("missing --{k}")))
    }
    fn n<T: std::str::FromStr>(&self, k: &str, d: T) -> T {
        self.kv.get(k).and_then(|x| x.parse().ok()).unwrap_or(d)
    }
}

// ------------------------------------------------------------------------------------------------ wasm config
struct Lim;
impl ResourceLimiter for Lim {
    fn memory_growing(&mut self, _c: usize, desired: usize, _m: Option<usize>) -> Result<bool> {
        Ok(desired <= 16 << 20)
    }
    fn table_growing(&mut self, _c: usize, desired: usize, _m: Option<usize>) -> Result<bool> {
        Ok(desired <= 10_000)
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Budget {
    Epoch,
    Fuel(u64),
    None,
}
fn parse_budget(s: &str) -> Budget {
    match s {
        "epoch" => Budget::Epoch,
        "none" => Budget::None,
        x => match x.strip_prefix("fuel:").and_then(|n| n.parse().ok()) {
            Some(n) => Budget::Fuel(n),
            None => die("--budget epoch|fuel:N|none"),
        },
    }
}

fn engine(fuel: bool, epoch: bool, pool: bool) -> Engine {
    let mut c = Config::new();
    c.strategy(Strategy::Cranelift);
    c.wasm_memory64(false);
    c.consume_fuel(fuel);
    c.epoch_interruption(epoch);
    // Default 4 GiB reservation + 32 MiB guards are kept (ARCHITECTURE R-ISO-2: never density-tuned by guard shrinking).
    if pool {
        let mut p = PoolingAllocationConfig::default();
        p.total_core_instances(64);
        p.total_memories(64);
        p.total_tables(64);
        p.max_memory_size(16 << 20);
        c.allocation_strategy(InstanceAllocationStrategy::Pooling(p));
    }
    Engine::new(&c).unwrap_or_else(|e| die(&format!("engine: {e}")))
}

fn load(eng: &Engine, guest: &str) -> (InstancePre<Lim>, bool) {
    let mut compiled = true;
    // Restart cost: like the AEGIS design (locally precompiled .cwasm), a compiled artifact produced by this host
    // is cached next to the guest (ISOFI_CWASM_DIR) and reused on respawn; never bytes from elsewhere.
    let m = match std::env::var("ISOFI_CWASM_DIR") {
        Ok(dir) => {
            let h = eng.precompile_compatibility_hash();
            use std::hash::{Hash, Hasher};
            let mut hs = std::collections::hash_map::DefaultHasher::new();
            h.hash(&mut hs);
            std::fs::read(guest).unwrap_or_default().hash(&mut hs);
            let p = format!("{dir}/guest-{:016x}.cwasm", hs.finish());
            if !std::path::Path::new(&p).exists() {
                let m = Module::from_file(eng, guest).unwrap_or_else(|e| die(&format!("module: {e}")));
                if let Ok(b) = m.serialize() {
                    let tmp = format!("{p}.{}", std::process::id());
                    if std::fs::write(&tmp, b).is_ok() {
                        let _ = std::fs::rename(&tmp, &p);
                    }
                }
                m
            } else {
                compiled = false;
                // SAFETY: the file was written by this same binary/engine config (hash-keyed) in a private dir
                unsafe { Module::deserialize_file(eng, &p) }.unwrap_or_else(|e| die(&format!("cwasm: {e}")))
            }
        }
        Err(_) => Module::from_file(eng, guest).unwrap_or_else(|e| die(&format!("module: {e}"))),
    };
    let mut linker = Linker::<Lim>::new(eng);
    linker
        .func_wrap("env", "host_fault", |code: u32| {
            if code == 1 {
                // stands in for a guest-triggerable host/runtime bug that takes the host process down
                std::process::abort();
            }
            if code == 2 {
                // stands in for a guest-triggerable host bug that silently corrupts host state
                HOST_CORRUPT.store(true, Ordering::SeqCst);
            }
        })
        .unwrap_or_else(|e| die(&format!("linker: {e}")));
    (linker.instantiate_pre(&m).unwrap_or_else(|e| die(&format!("pre: {e}"))), compiled)
}

type Handle = TypedFunc<(u32, u32), u32>;
fn new_inst(eng: &Engine, pre: &InstancePre<Lim>) -> Result<(Store<Lim>, Handle)> {
    let mut st = Store::new(eng, Lim);
    st.limiter(|l| l);
    let i = pre.instantiate(&mut st)?;
    let f = i.get_typed_func::<(u32, u32), u32>(&mut st, "handle")?;
    Ok((st, f))
}
fn arm(st: &mut Store<Lim>, b: Budget, epoch_ticks: u64, epoch_on: bool) {
    if let Budget::Fuel(n) = b {
        let _ = st.set_fuel(n);
    }
    if epoch_on {
        st.set_epoch_deadline(if b == Budget::None { u64::MAX / 2 } else { epoch_ticks });
        st.epoch_deadline_trap();
    }
}

// ------------------------------------------------------------------------------------------------ io helpers
fn read_req(s: &mut UnixStream) -> std::io::Result<(u32, u32)> {
    let mut b = [0u8; 8];
    s.read_exact(&mut b)?;
    Ok((u32::from_le_bytes([b[0], b[1], b[2], b[3]]), u32::from_le_bytes([b[4], b[5], b[6], b[7]])))
}
fn reply(s: &mut UnixStream, id: u32, h: u32) -> std::io::Result<()> {
    let mut o = [0u8; 8];
    o[0..4].copy_from_slice(&id.to_le_bytes());
    let h = if HOST_CORRUPT.load(Ordering::SeqCst) { h ^ 0x5a5a } else { h };
    o[4..8].copy_from_slice(&h.to_le_bytes());
    s.write_all(&o)
}
fn host_io(p: &str) -> std::io::Result<usize> {
    let mut f = std::fs::File::open(p)?;
    let mut d = Vec::with_capacity(4096);
    f.read_to_end(&mut d)
}
fn listener(a: &Args) -> UnixListener {
    let sock = a.s("socket", "fd:3");
    if sock == "fd:3" {
        // SAFETY-equivalent: fd 3 is the supervisor-held listening socket (socket activation contract)
        unsafe { UnixListener::from_raw_fd(3) }
    } else {
        let _ = std::fs::remove_file(&sock);
        UnixListener::bind(&sock).unwrap_or_else(|e| die(&format!("bind: {e}")))
    }
}
fn proc_limits() {
    unsafe {
        let r = libc::rlimit { rlim_cur: 256, rlim_max: 256 };
        libc::setrlimit(libc::RLIMIT_NOFILE, &r);
        let r = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &r);
        // ARCHITECTURE R-ISO-5: dumpable=0 (avoids the apport core-pipe hang, r4i04.coredump-pipe-hang)
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

fn abs_path(p: &str) -> String {
    std::fs::canonicalize(p).ok().and_then(|x| x.to_str().map(|s| s.to_string())).unwrap_or_else(|| die("--data must exist"))
}

// ------------------------------------------------------------------------------------------------ sandbox
#[repr(C)]
struct LlRuleset {
    handled_access_fs: u64,
}
#[repr(C, packed)]
struct LlPathBeneath {
    allowed_access: u64,
    parent_fd: i32,
}
fn landlock(dir: &str) -> i64 {
    unsafe {
        let a = LlRuleset { handled_access_fs: (1 << 13) - 1 };
        let fd = libc::syscall(libc::SYS_landlock_create_ruleset, &a as *const _, std::mem::size_of::<LlRuleset>(), 0u32);
        if fd < 0 {
            return fd;
        }
        let c = std::ffi::CString::new(dir).unwrap_or_default();
        let d = libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC);
        let pb = LlPathBeneath { allowed_access: (1 << 2) | (1 << 3), parent_fd: d }; // READ_FILE|READ_DIR
        libc::syscall(libc::SYS_landlock_add_rule, fd as i32, 1u32, &pb as *const _, 0u32);
        libc::close(d);
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        let r = libc::syscall(libc::SYS_landlock_restrict_self, fd as i32, 0u32);
        libc::close(fd as i32);
        r
    }
}
fn seccomp(allow_fork: bool, tsync: bool) -> i64 {
    let mut l: Vec<i64> = vec![
        libc::SYS_read, libc::SYS_write, libc::SYS_close, libc::SYS_exit, libc::SYS_exit_group, libc::SYS_mmap,
        libc::SYS_munmap, libc::SYS_mprotect, libc::SYS_madvise, libc::SYS_brk, libc::SYS_mremap, libc::SYS_futex,
        libc::SYS_clock_gettime, libc::SYS_rt_sigaction, libc::SYS_rt_sigprocmask, libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack, libc::SYS_accept4, libc::SYS_accept, libc::SYS_recvfrom, libc::SYS_sendto,
        libc::SYS_openat, libc::SYS_fstat, libc::SYS_newfstatat, libc::SYS_statx, libc::SYS_lseek, libc::SYS_fcntl,
        libc::SYS_poll, libc::SYS_getrandom, libc::SYS_sched_yield, libc::SYS_gettid, libc::SYS_getpid,
        libc::SYS_tgkill, libc::SYS_setitimer, libc::SYS_prlimit64, libc::SYS_sched_getaffinity, libc::SYS_rseq,
        libc::SYS_set_robust_list, libc::SYS_nanosleep, libc::SYS_clock_nanosleep, libc::SYS_getuid,
        libc::SYS_wait4, libc::SYS_kill, libc::SYS_getppid, libc::SYS_membarrier, libc::SYS_memfd_create,
        libc::SYS_ftruncate, libc::SYS_pread64, libc::SYS_readlink,
    ];
    if allow_fork {
        l.push(libc::SYS_clone);
        l.push(libc::SYS_fork);
    }
    // clone3 is answered ENOSYS (ARCHITECTURE R-ISO-4) so libc falls back to filtered clone
    let st = |code: u16, k: u32| libc::sock_filter { code, jt: 0, jf: 0, k };
    let jeq = |k: u32, jt: u8, jf: u8| libc::sock_filter { code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16, jt, jf, k };
    let ret = (libc::BPF_RET | libc::BPF_K) as u16;
    let mut f: Vec<libc::sock_filter> = vec![
        st((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 4),
        jeq(0xc000_003e, 1, 0),
        st(ret, 0x8000_0000),
        st((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 0),
        jeq(libc::SYS_clone3 as u32, 0, 1),
        st(ret, 0x0005_0000 | libc::ENOSYS as u32),
    ];
    for &n in &l {
        f.push(jeq(n as u32, 0, 1));
        f.push(st(ret, 0x7fff_0000));
    }
    f.push(st(ret, 0x8000_0000)); // SECCOMP_RET_KILL_PROCESS
    let p = libc::sock_fprog { len: f.len() as u16, filter: f.as_mut_ptr() };
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        libc::syscall(libc::SYS_seccomp, 1u32, if tsync { 1u32 } else { 0u32 }, &p as *const _)
    }
}
fn sandbox(data: &str, allow_fork: bool, tsync: bool) {
    let dir = std::path::Path::new(data).parent().and_then(|p| p.to_str()).unwrap_or("/").to_string();
    let a = landlock(&dir);
    let b = seccomp(allow_fork, tsync);
    eprintln!("sandbox: landlock={a} seccomp={b}");
}

// ------------------------------------------------------------------------------------------------ serve: cordon
fn serve_cordon(a: &Args) {
    let guest = a.req("guest");
    // absolute path: Landlock is scoped to its parent directory (a relative path would yield an empty rule set)
    let data = abs_path(&a.req("data"));
    let threads: usize = a.n("threads", 64);
    let budget = parse_budget(&a.s("budget", "epoch"));
    let ticks = (a.n::<u64>("epoch-ms", 100) / EPOCH_TICK_MS).max(1);
    let mutation = a.s("mutation", "none");
    proc_limits();
    let eng = engine(matches!(budget, Budget::Fuel(_)), true, true);
    let (pre, _) = load(&eng, &guest);
    let e2 = eng.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(EPOCH_TICK_MS));
        e2.increment_epoch();
    });
    let l = listener(a);
    let (tx, rx) = mpsc::channel::<UnixStream>();
    let rx = Arc::new(Mutex::new(rx));
    let shared: Arc<Mutex<Option<(Store<Lim>, Handle)>>> = Arc::new(Mutex::new(None));
    let mut hs = Vec::new();
    for _ in 0..threads {
        let (rx, eng, pre, data, mutation, shared) =
            (rx.clone(), eng.clone(), pre.clone(), data.clone(), mutation.clone(), shared.clone());
        hs.push(std::thread::spawn(move || {
            let mut cached: Option<(Store<Lim>, Handle)> = None;
            let mut served = 0u64;
            loop {
                let s = { rx.lock().map(|r| r.recv()) };
                let Ok(Ok(mut s)) = s else { return };
                let Ok((id, fault)) = read_req(&mut s) else { continue };
                if host_io(&data).is_err() {
                    continue;
                }
                if mutation == "shared-store" {
                    // MUTATION: one Store/Instance shared by every request of the process
                    let mut g = match shared.lock() { Ok(g) => g, Err(p) => p.into_inner() };
                    if g.is_none() {
                        *g = new_inst(&eng, &pre).ok();
                    }
                    let Some((st, f)) = g.as_mut() else { continue };
                    arm(st, budget, ticks, true);
                    match f.call(&mut *st, (id, fault)) {
                        Ok(h) => {
                            let _ = reply(&mut s, id, h);
                        }
                        Err(_) => *g = None,
                    }
                    continue;
                }
                let reuse = mutation == "recycle50";
                if !reuse || cached.is_none() || served % 50 == 0 {
                    cached = new_inst(&eng, &pre).ok();
                }
                served += 1;
                let Some((st, f)) = cached.as_mut() else { continue };
                arm(st, budget, ticks, true);
                match f.call(&mut *st, (id, fault)) {
                    Ok(h) => {
                        let _ = reply(&mut s, id, h);
                    }
                    Err(_) => cached = None, // trap: discard instance; the connection closes
                }
                if !reuse {
                    cached = None;
                }
            }
        }));
    }
    if a.n::<u32>("sandbox", 1) == 1 {
        sandbox(&data, false, true);
    }
    for c in l.incoming().flatten() {
        let _ = tx.send(c);
    }
}

// ------------------------------------------------------------------------------------------------ serve: forkwasm
fn child_itimer(ms: u64) {
    unsafe {
        let t = libc::itimerval {
            it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
            it_value: libc::timeval { tv_sec: (ms / 1000) as i64, tv_usec: ((ms % 1000) * 1000) as i64 },
        };
        libc::setitimer(libc::ITIMER_REAL, &t, std::ptr::null_mut());
    }
}
fn serve_forkwasm(a: &Args) {
    let guest = a.req("guest");
    // absolute path: Landlock is scoped to its parent directory (a relative path would yield an empty rule set)
    let data = abs_path(&a.req("data"));
    let budget = parse_budget(&a.s("budget", "epoch"));
    let ms: u64 = a.n("epoch-ms", 100);
    let pool = a.s("pool", "ondemand") == "pool";
    let mutation = a.s("mutation", "none");
    let nofork = mutation == "no-fork";
    proc_limits();
    // zygote: single-threaded; Engine, compiled Module and InstancePre live here and are inherited by every child
    let eng = engine(matches!(budget, Budget::Fuel(_)), nofork, pool);
    let (pre, compiled) = load(&eng, &guest);
    if compiled && std::env::var("ISOFI_CWASM_DIR").is_ok() && std::env::var("ISOFI_REEXEC").is_err() {
        // In-process compilation leaves Cranelift heap in the zygote and every fork copies its page tables
        // (measured: ~40% slower forks). Re-exec once so the zygote starts from the cached precompiled module.
        use std::os::unix::process::CommandExt;
        let err = Command::new("/proc/self/exe").args(std::env::args().skip(1)).env("ISOFI_REEXEC", "1").exec();
        die(&format!("re-exec: {err}"));
    }
    if nofork {
        let e2 = eng.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(EPOCH_TICK_MS));
            e2.increment_epoch();
        });
    }
    let l = listener(a);
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_IGN); // auto-reap (teardown is part of the per-request cost)
    }
    if a.n::<u32>("sandbox", 1) == 1 {
        sandbox(&data, true, nofork);
    }
    let ticks = (ms / EPOCH_TICK_MS).max(1);
    loop {
        let fd = unsafe { libc::accept4(l.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
        if fd < 0 {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }
        if nofork {
            // MUTATION: the zygote serves the request in-process (fork+Wasm that forgot to fork)
            let mut s = unsafe { UnixStream::from_raw_fd(fd) };
            let Ok((id, fault)) = read_req(&mut s) else { continue };
            if host_io(&data).is_err() {
                continue;
            }
            if let Ok((mut st, f)) = new_inst(&eng, &pre) {
                arm(&mut st, budget, ticks, true);
                if let Ok(h) = f.call(&mut st, (id, fault)) {
                    let _ = reply(&mut s, id, h);
                }
            }
            continue;
        }
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            if budget != Budget::None {
                child_itimer(ms); // wall-clock bound: SIGALRM terminates the child
            }
            let mut s = unsafe { UnixStream::from_raw_fd(fd) };
            let code = (|| -> i32 {
                let Ok((id, fault)) = read_req(&mut s) else { return 3 };
                if host_io(&data).is_err() {
                    return 4;
                }
                let Ok((mut st, f)) = new_inst(&eng, &pre) else { return 5 };
                arm(&mut st, budget, ticks, false);
                match f.call(&mut st, (id, fault)) {
                    Ok(h) => {
                        if reply(&mut s, id, h).is_ok() {
                            0
                        } else {
                            6
                        }
                    }
                    Err(_) => 1,
                }
            })();
            unsafe { libc::_exit(code) };
        }
        unsafe {
            libc::close(fd);
        }
    }
}

// ------------------------------------------------------------------------------------------------ calibrate
fn calibrate(a: &Args) {
    let guest = a.req("guest");
    let eng = engine(true, false, true);
    let (pre, _) = load(&eng, &guest);
    let big = 1u64 << 40;
    let mut hf = Vec::new();
    let mut ht = Vec::new();
    for i in 0..2000u32 {
        let Ok((mut st, f)) = new_inst(&eng, &pre) else { die("inst") };
        let _ = st.set_fuel(big);
        let t = Instant::now();
        let _ = f.call(&mut st, (i, F_NONE));
        ht.push(t.elapsed().as_secs_f64() * 1e6);
        hf.push((big - st.get_fuel().unwrap_or(big)) as f64);
    }
    let lf = 200_000_000u64;
    let mut lt = Vec::new();
    for _ in 0..5 {
        let Ok((mut st, f)) = new_inst(&eng, &pre) else { die("inst") };
        let _ = st.set_fuel(lf);
        let t = Instant::now();
        let _ = f.call(&mut st, (0, F_LOOP));
        lt.push(t.elapsed().as_secs_f64() * 1e3);
    }
    let fpm = lf as f64 / pct(&mut lt, 0.5);
    println!(
        "{{\"healthy_fuel\":{:.0},\"healthy_call_us_p50\":{:.1},\"loop_fuel_per_ms\":{:.0},\"loop_ms_for_{}_fuel\":{:.2}}}",
        pct(&mut hf, 0.5),
        pct(&mut ht, 0.5),
        fpm,
        lf,
        pct(&mut lt, 0.5)
    );
}

// ------------------------------------------------------------------------------------------------ forkcost
fn proc_status(k: &str) -> String {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with(k))
        .map(|l| l.split_whitespace().nth(1).unwrap_or("0").to_string())
        .unwrap_or_default()
}
fn forkcost(a: &Args) {
    let guest = a.req("guest");
    let n: usize = a.n("n", 2000);
    let pool = a.s("pool", "ondemand") == "pool";
    let fuel: u64 = a.n("fuel", 0);
    let eng = engine(fuel > 0, false, pool);
    let (pre, compiled) = load(&eng, &guest);
    let b = if fuel > 0 { Budget::Fuel(fuel) } else { Budget::None };
    // warm the code paths and (for pool) one slot
    for i in 0..200u32 {
        if let Ok((mut st, f)) = new_inst(&eng, &pre) {
            arm(&mut st, b, 0, false);
            let _ = f.call(&mut st, (i, F_NONE));
        }
    }
    let us = |t: Instant| t.elapsed().as_secs_f64() * 1e6;
    let (mut inproc, mut fexit, mut fwasm) = (Vec::new(), Vec::new(), Vec::new());
    let mut bad = 0usize;
    for i in 0..n as u32 {
        // A: fresh instance in-process (the cordon's per-request isolation cost): instantiate + call + drop
        let t = Instant::now();
        if let Ok((mut st, f)) = new_inst(&eng, &pre) {
            arm(&mut st, b, 0, false);
            let _ = std::hint::black_box(f.call(&mut st, (i, F_NONE)));
        }
        inproc.push(us(t));
        // B: fork + child _exit + waitpid (pure fork/teardown of a zygote with the engine loaded)
        let t = Instant::now();
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe { libc::_exit(0) };
        }
        let mut stt = 0;
        unsafe { libc::waitpid(pid, &mut stt, 0) };
        fexit.push(us(t));
        // C: fork + child (instantiate + call + _exit) + waitpid (fork+Wasm per-request cost incl. teardown)
        let t = Instant::now();
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let ok = match new_inst(&eng, &pre) {
                Ok((mut st, f)) => {
                    arm(&mut st, b, 0, false);
                    f.call(&mut st, (i, F_NONE)).is_ok()
                }
                Err(_) => false,
            };
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        let mut stt = 0;
        unsafe { libc::waitpid(pid, &mut stt, 0) };
        fwasm.push(us(t));
        if stt != 0 {
            bad += 1;
        }
    }
    let p = |v: &mut Vec<f64>| format!("{{\"p50\":{:.1},\"p99\":{:.1}}}", pct(v, 0.5), pct(v, 0.99));
    let d50 = pct(&mut fwasm, 0.5) - pct(&mut inproc, 0.5);
    let d99 = pct(&mut fwasm, 0.99) - pct(&mut inproc, 0.99);
    let maps = std::fs::read_to_string("/proc/self/maps").map(|s| s.lines().count()).unwrap_or(0);
    println!(
        "{{\"n\":{n},\"pool\":{pool},\"fuel\":{fuel},\"compiled_in_zygote\":{compiled},\"inproc_fresh_instance_us\":{},\"fork_exit_wait_us\":{},\"fork_wasm_us\":{},\"fork_overhead_vs_fresh_us\":{{\"p50\":{d50:.1},\"p99\":{d99:.1}}},\"child_failures\":{bad},\"zygote_vmrss_kb\":{},\"zygote_vmsize_kb\":{},\"zygote_vmas\":{maps}}}",
        p(&mut inproc),
        p(&mut fexit),
        p(&mut fwasm),
        proc_status("VmRSS:"),
        proc_status("VmSize:")
    );
}

// ------------------------------------------------------------------------------------------------ drive
fn fault_code(s: &str) -> u32 {
    match s {
        "none" => F_NONE,
        "panic" => F_PANIC,
        "abort" => F_ABORT,
        "segv" => F_SEGV,
        "loop" => F_LOOP,
        "oom" => F_OOM,
        "poison" => F_POISON,
        "hostabort" => F_HOSTABORT,
        "hostpoison" => F_HOSTPOISON,
        _ => die("fault: none|panic|abort|segv|loop|oom|poison|hostabort|hostpoison"),
    }
}
fn splitmix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}
fn pct(v: &mut [f64], p: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let i = ((v.len() as f64 - 1.0) * p).round() as usize;
    v.get(i).copied().unwrap_or(f64::NAN)
}
static LFD: AtomicI32 = AtomicI32::new(-1);

fn spawn_server(cmd: &str, core: &str, log: &str) -> Child {
    let f = std::fs::OpenOptions::new().create(true).append(true).open(log).unwrap_or_else(|e| die(&format!("log: {e}")));
    let mut c = Command::new("taskset");
    c.arg("-c").arg(core).arg("/bin/sh").arg("-c").arg(format!("exec {cmd}"));
    c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::from(f));
    let lfd = LFD.load(Ordering::SeqCst);
    use std::os::unix::process::CommandExt;
    unsafe {
        c.pre_exec(move || {
            libc::setpgid(0, 0); // own process group: fork children are killed with the server
            if libc::dup2(lfd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let fl = libc::fcntl(3, libc::F_GETFD);
            libc::fcntl(3, libc::F_SETFD, fl & !libc::FD_CLOEXEC);
            Ok(())
        });
    }
    c.spawn().unwrap_or_else(|e| die(&format!("spawn server: {e}")))
}
fn kill_server(c: &mut Child) {
    unsafe {
        libc::kill(-(c.id() as i32), libc::SIGKILL);
    }
    let _ = c.kill();
    let _ = c.wait();
}
fn ping(sock: &str, data: &[u8], id: u32) -> bool {
    let Ok(mut s) = UnixStream::connect(sock) else { return false };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let mut b = [0u8; 8];
    b[0..4].copy_from_slice(&id.to_le_bytes());
    if s.write_all(&b).is_err() || s.read_exact(&mut b).is_err() {
        return false;
    }
    u32::from_le_bytes([b[4], b[5], b[6], b[7]]) == work(id, GOOD_SALT, data)
}

fn drive(a: &Args) {
    let guest = a.req("guest");
    let datap = a.req("data");
    let cmd = a.req("server").replace("{guest}", &guest).replace("{data}", &datap);
    let fname = a.s("fault", "none");
    let fault = fault_code(&fname);
    let rate: f64 = a.n("rate", 0.0);
    let n: usize = a.n("n", 3000);
    let conc: usize = a.n("conc", 16);
    let seed: u64 = a.n("seed", 1);
    let prefix = a.req("prefix");
    let core = a.s("server-core", "2");
    let ccores = a.s("client-cores", "4,5,6,7");
    let max_s: u64 = a.n("max-seconds", 120);
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        for c in ccores.split(',').filter_map(|c| c.parse::<usize>().ok()) {
            libc::CPU_SET(c, &mut set);
        }
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
    let data = std::fs::read(&datap).unwrap_or_else(|e| die(&format!("data: {e}")));
    let sockdir = a.s("sockdir", "/tmp/claude-1000");
    let _ = std::fs::create_dir_all(&sockdir);
    let sock = format!("{sockdir}/isofi-{}-{seed}.sock", std::process::id());
    let _ = std::fs::remove_file(&sock);
    let l = UnixListener::bind(&sock).unwrap_or_else(|e| die(&format!("bind: {e}")));
    unsafe {
        libc::listen(l.as_raw_fd(), 1024);
    }
    LFD.store(l.as_raw_fd(), Ordering::SeqCst);
    let srvlog = format!("{prefix}.srv.log");
    if std::env::var("ISOFI_CWASM_DIR").is_err() {
        std::env::set_var("ISOFI_CWASM_DIR", &sockdir); // reference subjects reuse a locally precompiled module
    }
    let child = Arc::new(Mutex::new(spawn_server(&cmd, &core, &srvlog)));
    // readiness + warmup (healthy)
    let tr = Instant::now();
    let mut ready = false;
    while tr.elapsed() < Duration::from_secs(20) {
        if ping(&sock, &data, 999_999) {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    if !ready {
        if let Ok(mut c) = child.lock() {
            kill_server(&mut c);
        }
        println!("{{\"substrate_cmd\":{:?},\"fault\":\"{fname}\",\"rate\":{rate},\"error\":\"server not ready\"}}", cmd);
        return;
    }
    for i in 0..200u32 {
        ping(&sock, &data, 1_000_000 + i);
    }
    let t0 = Instant::now();
    let us = move || t0.elapsed().as_micros() as u64;
    let stop = Arc::new(AtomicBool::new(false));
    let last_ok = Arc::new(AtomicU64::new(0));
    let events: Arc<Mutex<Vec<(u64, u64, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let sup = {
        let (child, stop, last_ok, events, cmd, core, srvlog) =
            (child.clone(), stop.clone(), last_ok.clone(), events.clone(), cmd.clone(), core.clone(), srvlog.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
                let Ok(mut c) = child.lock() else { return };
                let exited = c.try_wait().ok().flatten();
                let now = us();
                let stale = now > 2_000_000 && now.saturating_sub(last_ok.load(Ordering::SeqCst)) > 2_000_000;
                if exited.is_some() || stale {
                    let cause = match exited {
                        Some(st) => format!("exit:{st}"),
                        None => "watchdog".to_string(),
                    };
                    kill_server(&mut c); // also reaps the old process group
                    *c = spawn_server(&cmd, &core, &srvlog);
                    let up = us();
                    last_ok.store(up, Ordering::SeqCst);
                    events.lock().map(|mut e| e.push((now, up, cause))).ok();
                }
            }
        })
    };
    let next = Arc::new(AtomicUsize::new(0));
    // (i, fault, start_us, end_us, err) err: 0 ok, 1 connect, 2 write, 3 read/EOF, 4 timeout, 5 wrong answer
    let recs: Arc<Mutex<Vec<(usize, u32, u64, u64, u8)>>> = Arc::new(Mutex::new(Vec::with_capacity(n)));
    let mut hs = vec![];
    for _ in 0..conc {
        let (next, recs, sock, data, last_ok) = (next.clone(), recs.clone(), sock.clone(), data.clone(), last_ok.clone());
        hs.push(std::thread::spawn(move || {
            let mut local = Vec::new();
            loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                if i >= n || us() > max_s * 1_000_000 {
                    break;
                }
                let u = splitmix(seed ^ (i as u64).wrapping_mul(0x9E37)) as f64 / u64::MAX as f64;
                let fz = if fault != F_NONE && u < rate { fault } else { F_NONE };
                let ts = us();
                let err: u8 = match UnixStream::connect(&sock) {
                    Err(_) => 1,
                    Ok(mut s) => {
                        let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut b = [0u8; 8];
                        b[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                        b[4..8].copy_from_slice(&fz.to_le_bytes());
                        if s.write_all(&b).is_err() {
                            2
                        } else {
                            match s.read_exact(&mut b) {
                                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => 4,
                                Err(_) => 3,
                                Ok(()) => {
                                    let h = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
                                    if h == work(i as u32, GOOD_SALT, &data) {
                                        0
                                    } else {
                                        5
                                    }
                                }
                            }
                        }
                    }
                };
                let te = us();
                if err == 0 {
                    last_ok.fetch_max(te, Ordering::SeqCst);
                } else {
                    std::thread::sleep(Duration::from_millis(1));
                }
                local.push((i, fz, ts, te, err));
            }
            recs.lock().map(|mut r| r.extend(local)).ok();
        }));
    }
    for h in hs {
        let _ = h.join();
    }
    stop.store(true, Ordering::SeqCst);
    let _ = sup.join();
    if let Ok(mut c) = child.lock() {
        kill_server(&mut c);
    }
    let _ = std::fs::remove_file(&sock);
    let mut recs = recs.lock().map(|r| r.clone()).unwrap_or_default();
    recs.sort();
    let wall = recs.iter().map(|r| r.3).max().unwrap_or(1).max(1);
    if let Ok(mut f) = std::fs::File::create(format!("{prefix}.req.tsv")) {
        let _ = writeln!(f, "i\tfault\tstart_us\tend_us\terr");
        for r in &recs {
            let _ = writeln!(f, "{}\t{}\t{}\t{}\t{}", r.0, r.1, r.2, r.3, r.4);
        }
    }
    let injected: Vec<_> = recs.iter().filter(|r| r.1 != F_NONE).collect();
    let healthy: Vec<_> = recs.iter().filter(|r| r.1 == F_NONE).collect();
    let hfail = healthy.iter().filter(|r| r.4 != 0).count();
    let wrong = healthy.iter().filter(|r| r.4 == 5).count();
    let mut lat: Vec<f64> = healthy.iter().filter(|r| r.4 == 0).map(|r| (r.3 - r.2) as f64).collect();
    let p50 = pct(&mut lat, 0.5);
    let p99 = pct(&mut lat, 0.99);
    // recovery per injected fault: end of the faulting request -> next healthy success completing at/after it
    let oks: Vec<u64> = {
        let mut v: Vec<u64> = healthy.iter().filter(|r| r.4 == 0).map(|r| r.3).collect();
        v.sort();
        v
    };
    // censoring: a fault is only scored if some healthy request was issued after it ended (end-of-run tail excluded)
    let last_healthy_start = healthy.iter().map(|r| r.2).max().unwrap_or(0);
    let mut unrecovered = 0usize;
    let mut censored = 0usize;
    let mut rec: Vec<f64> = Vec::new();
    for r in &injected {
        if r.3 > last_healthy_start {
            censored += 1;
            continue;
        }
        let k = oks.partition_point(|&t| t < r.3);
        match oks.get(k) {
            Some(&t) => rec.push((t - r.3) as f64),
            None => unrecovered += 1,
        }
    }
    let rec_samples: Vec<u64> = rec.iter().map(|x| *x as u64).collect();
    let rec_p50 = pct(&mut rec, 0.5);
    let rec_p99 = pct(&mut rec, 0.99);
    let ev = events.lock().map(|e| e.clone()).unwrap_or_default();
    let mut rrec: Vec<f64> =
        ev.iter().filter_map(|e| oks.get(oks.partition_point(|&t| t < e.0)).map(|&t| (t - e.0) as f64)).collect();
    let wd = ev.iter().filter(|e| e.2 == "watchdog").count();
    let mut errs = [0usize; 6];
    for r in &healthy {
        if let Some(x) = errs.get_mut(r.4 as usize) {
            *x += 1;
        }
    }
    let inj_ok = injected.iter().filter(|r| r.4 == 0).count();
    let la = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let j = |x: f64| if x.is_finite() { format!("{x:.0}") } else { "null".to_string() };
    println!(
        "{{\"cmd\":{:?},\"fault\":\"{fname}\",\"rate\":{rate},\"seed\":{seed},\"issued\":{},\"injected\":{},\"injected_ok\":{inj_ok},\"healthy\":{},\"healthy_fail\":{hfail},\"healthy_wrong\":{wrong},\"blast_per_fault\":{:.4},\"p50_us\":{},\"p99_us\":{},\"recovery_p50_us\":{},\"recovery_p99_us\":{},\"unrecovered\":{unrecovered},\"censored\":{censored},\"recovery_us\":{:?},\"restarts\":{},\"watchdog\":{wd},\"restart_recovery_p99_us\":{},\"wall_us\":{wall},\"rps\":{:.0},\"err_hist\":{:?},\"loadavg\":\"{}\"}}",
        cmd,
        recs.len(),
        injected.len(),
        healthy.len(),
        if injected.is_empty() { 0.0 } else { hfail as f64 / injected.len() as f64 },
        j(p50),
        j(p99),
        j(rec_p50),
        j(rec_p99),
        rec_samples,
        ev.len(),
        j(pct(&mut rrec, 0.99)),
        recs.len() as f64 / (wall as f64 / 1e6),
        errs,
        la.trim()
    );
}

fn main() {
    let a = Args::parse();
    let sub = a.pos.first().cloned().unwrap_or_default();
    match sub.as_str() {
        "serve" => match a.pos.get(1).map(|s| s.as_str()) {
            Some("cordon") => serve_cordon(&a),
            Some("forkwasm") => serve_forkwasm(&a),
            _ => die("serve cordon|forkwasm"),
        },
        "drive" => drive(&a),
        "calibrate" => calibrate(&a),
        "forkcost" => forkcost(&a),
        _ => die("usage: isofi serve|drive|calibrate|forkcost (see header comment)"),
    }
}
