//! P2 isolation, supervisor side (feature `p2`; PLAN-5 D1, D2, D7, D8, D15, D17, D21; F8 `p2`, F14; SPEC
//! INV-P2): `{"wasm": <module-id>}` routes served by exec-spawned aegis-p2 workers. aegis-bin links no Wasm
//! engine (D3, gate no-wasmtime-in-bin): it compiles modules through the sandboxed `aegis-p2 compile`, holds their
//! digests, spawns zygotes and cordons by execve (aegis-iso supervisor), talks F14 frames to them ([`exchange`],
//! [`frame`]), keeps the per-principal crash budget (aegis-iso crash_budget) and the cordon table (aegis-iso
//! cordon::Registry), and re-serializes the module's answer ([`http`]).
//!
//! **Boot and reload** ([`Runtime::prepare`], fail closed): for each `p2.modules[]` entry, the `.wasm` file's sha256
//! must equal the configured digest; then `aegis-p2 compile --in <wasm> --out <cache>/<id>-g<generation>.cwasm
//! [--memory-mib N] [--mpk]` runs (the worker installs its compile sandbox and refuses below Landlock ABI 4, D2);
//! a refusal or a missing worker fails the boot with exit 78 before any socket is bound, or leaves the
//! last-known-good config serving on reload. The supervisor then hashes the `.cwasm` itself; that digest is the
//! only one a worker may load (D4) and the one its `ready` frame must carry. Every `AEGIS_P2_*` variable is passed
//! through to every worker (and nothing else of the environment).
//!
//! **Workers.** Each aegis-p2 process loads exactly one module (`zygote|cordon --module <c.cwasm> --sha256 <hex>`,
//! the worker command line of oracles/hostile-modules). The supervisor therefore runs:
//! - forkwasm (D1 default): one zygote per module, all of them started at boot/reload, each with a
//!   supervisor-held listening socket at fd 3. The zygotes of one config generation are supervised as one unit,
//!   **the zygote set**: when any member dies, every member is replaced by a fresh execve (D8). Replacing only the
//!   dead member would leave the other members' layouts unchanged, and the p2-e2e oracle judges the zygote as one
//!   process whose replacement changes the load base seen on every route. A zygote serves no request itself (D9);
//!   restarting the idle siblings costs one execve each and drops no request (connections queue on the listening
//!   sockets the supervisor keeps).
//! - cordon: one **cordon group** per principal, keyed by the principal in `aegis_iso::cordon::Registry`
//!   (bounded by `max_cordons`, idle reaping after `cordon_idle_s`, never shared: D1, P2-2). A group holds one
//!   cordon process per module that principal has used, each spawned on first use. A group is one fault domain:
//!   when any member dies (or is killed after a decode failure or timeout) the whole group is shut down and the
//!   principal's next request gets fresh execs (D8). Other principals' groups are never touched.
//!
//! **Requests** ([`Runtime::serve`]): penalty check (429 before dispatch, D7), then one F14 exchange on a new
//! connection (no pipelining, D21). Crash-attributable outcomes (trap, decode failure, abnormal exit or silence
//! past wall + grace, death of the principal's own cordon) are charged to the principal; Deny, Error codes and
//! anything caused by the supervisor or by a reload never are. A fault seen after the request's generation was
//! replaced, or on a cordon this supervisor tore down, is collateral and not charged.
//!
//! **The principal key.** `aegis_token::verify` mints a `Principal` whose subject is kid ‖ nonce, so every freshly
//! minted token is a new `Principal`. Keying the crash budget by it would let a client reset its budget with each
//! new token. The budget and the cordon table are keyed by the token's verified (tenant, issuer kid) instead
//! ([`Key`]): the stable identity behind the tokens.
//!
//! Decode failures on a fork child: the supervisor cannot learn the child's pid (the zygote forks it after
//! `accept`), so it closes the connection; the child dies at its next frame I/O or by its `ITIMER_REAL` wall
//! bound (at most `wall_ms`). A cordon is SIGKILLed with its group.
#![forbid(unsafe_code)]

pub mod exchange;
pub mod frame;
pub mod http;
pub mod mutant;

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use aegis_config::{Config, Isolation, RouteTarget};
use aegis_iso::cordon::{CordonId, Registry};
use aegis_iso::crash_budget::{CrashBudget, CrashKind, Failure, Params, Verdict};
use aegis_iso::supervisor::{self, WorkerCmd};
use aegis_token::KeyRing;

use exchange::{Job, Outcome};
use frame::{HeaderLimits, Limits};
use mutant::Mutant;

/// Liveness poll of zygotes and cordons.
const MONITOR_TICK: Duration = Duration::from_millis(50);
/// Least time between two replacements of the zygote set (a worker that refuses at start is not exec'd in a loop).
const ZYGOTE_RESTART_MIN: Duration = Duration::from_millis(200);
/// How long the supervisor waits for a cordon to be reaped after its connection ended without `resp-end`.
const DEATH_WAIT: Duration = Duration::from_millis(500);
/// Unix socket paths must fit `sockaddr_un.sun_path` (108 bytes with the NUL).
const MAX_SOCKET_PATH: usize = 100;

fn log(msg: &str) {
    eprintln!("aegis[{}]: p2: {msg}", std::process::id());
}

/// True iff the config routes at least one request to a P2 module.
pub fn has_wasm_routes(cfg: &Config) -> bool {
    cfg.vhosts().iter().flat_map(|v| v.routes.iter()).any(|r| matches!(r.to, RouteTarget::Wasm { .. }))
}

/// The crash-budget and cordon key: the verified token's tenant and issuer kid (see the module docs).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Key {
    tenant: u64,
    issuer: Vec<u8>,
}

impl Key {
    pub fn new(tenant: u64, issuer: Vec<u8>) -> Self {
        Self { tenant, issuer }
    }
    /// The one key every principal maps to under the `shared-cordon` / `global-crash-budget` mutants.
    fn constant() -> Self {
        Self { tenant: 0, issuer: Vec::new() }
    }
}

// ------------------------------------------------------------------------------------------------ processes

/// One exec'd worker process.
#[derive(Debug)]
struct ProcHandle {
    child: Mutex<Child>,
    /// Set when this supervisor killed the process while it was alive (not a death of its own).
    torn_down: AtomicBool,
}

impl ProcHandle {
    fn child(&self) -> MutexGuard<'_, Child> {
        self.child.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// Whether the process has exited (reaped here; a reaping error counts as exited).
    fn exited(&self) -> bool {
        !matches!(self.child().try_wait(), Ok(None))
    }
    fn pid(&self) -> u32 {
        self.child().id()
    }
    /// SIGKILL (explicit pid) and reap, if still alive.
    fn tear_down(&self) {
        let mut c = self.child();
        if matches!(c.try_wait(), Ok(None)) {
            self.torn_down.store(true, Ordering::Release);
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// A worker with its supervisor-held listening socket. Dropping it kills and reaps the process and removes the
/// socket file.
#[derive(Debug)]
struct Proc {
    cmd: WorkerCmd,
    listener: OwnedFd,
    path: PathBuf,
    h: Arc<ProcHandle>,
}

impl Proc {
    fn start(cmd: WorkerCmd, path: PathBuf) -> Result<Self, String> {
        let _ = std::fs::remove_file(&path);
        let listener =
            aegis_adapter_host::pdp_uds::listen_at(&path).map_err(|e| format!("listen on {}: {e}", path.display()))?;
        let child =
            supervisor::spawn(&cmd, listener.as_fd()).map_err(|e| format!("spawn {}: {e}", cmd.exe.display()))?;
        let h = Arc::new(ProcHandle { child: Mutex::new(child), torn_down: AtomicBool::new(false) });
        Ok(Self { cmd, listener, path, h })
    }

    /// Replaces the process by a fresh execve of the same command (D8: never a fork of a template); the listening
    /// socket stays, so connections queued meanwhile are served by the replacement.
    fn respawn(&mut self) -> Result<u32, String> {
        self.h.tear_down();
        let child = supervisor::spawn(&self.cmd, self.listener.as_fd())
            .map_err(|e| format!("respawn {}: {e}", self.cmd.exe.display()))?;
        self.h = Arc::new(ProcHandle { child: Mutex::new(child), torn_down: AtomicBool::new(false) });
        Ok(self.h.pid())
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        self.h.tear_down();
        let _ = std::fs::remove_file(&self.path);
    }
}

/// One principal's cordons, one process per module used (one fault domain; see the module docs).
#[derive(Debug, Default)]
struct Group {
    procs: HashMap<String, Proc>,
}

impl Group {
    fn any_exited(&self) -> bool {
        self.procs.values().any(|p| p.h.exited())
    }
}

// ------------------------------------------------------------------------------------------------ generations

/// One module as this generation serves it.
#[derive(Debug)]
struct ModRt {
    id: String,
    cwasm: PathBuf,
    digest: [u8; 32],
    limits: Limits,
    isolation: Isolation,
}

/// What one applied config gives the P2 runtime.
#[derive(Debug)]
struct Gen {
    id: u64,
    worker: PathBuf,
    mpk: bool,
    isolation: Isolation,
    cordon_slots: u64,
    max_cordons: usize,
    idle_s: u64,
    budget: Params,
    headers: HeaderLimits,
    modules: HashMap<String, Arc<ModRt>>,
    keyring: Option<Arc<KeyRing>>,
}

impl Gen {
    fn remove_files(&self) {
        for m in self.modules.values() {
            let _ = std::fs::remove_file(&m.cwasm);
        }
    }
}

/// A compiled but not yet installed generation (`None`: the config has no `p2` block). Dropping it uninstalled
/// removes its `.cwasm` files.
#[derive(Debug)]
pub struct Prepared {
    generation: Option<Gen>,
}

impl Drop for Prepared {
    fn drop(&mut self) {
        if let Some(g) = &self.generation {
            g.remove_files();
        }
    }
}

// ------------------------------------------------------------------------------------------------ runtime

#[derive(Debug)]
struct State {
    generation: Option<Arc<Gen>>,
    /// The zygote set of `generation`, by module id.
    zygotes: HashMap<String, Proc>,
    last_restart: Option<Instant>,
    cordons: Registry<Key, Group>,
    budget: CrashBudget<Key>,
    /// MUTANT no-reload-switch: P2 routes fail after a reload that changed the isolation path.
    broken: bool,
}

/// What [`Runtime::serve`] did.
#[derive(Debug)]
pub enum Served {
    /// The principal is in penalty (429, before dispatch).
    Penalty,
    /// No worker can take the request (no P2 generation, cordon table full with none idle): 503.
    Unavailable,
    /// The exchange ran (or was refused) with this outcome.
    Done(Outcome),
}

/// Where one request goes.
enum Target {
    Fork { path: PathBuf },
    Cordon { id: CordonId, path: PathBuf, h: Arc<ProcHandle> },
}

impl Target {
    fn path(&self) -> &Path {
        match self {
            Self::Fork { path } | Self::Cordon { path, .. } => path,
        }
    }
}

/// The P2 supervisor of one aegis process.
pub struct Runtime {
    state: Mutex<State>,
    rundir: PathBuf,
    keyring_path: Option<PathBuf>,
    next_gen: AtomicU64,
    next_sock: AtomicU64,
    stop: AtomicBool,
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runtime").field("rundir", &self.rundir).finish_non_exhaustive()
    }
}

/// Shuts the P2 workers down when the serving process leaves `serve::run` by any path.
#[derive(Debug)]
pub struct Guard(pub Option<Arc<Runtime>>);

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(rt) = &self.0 {
            rt.shutdown();
        }
    }
}

fn runtime_base(opt: Option<&Path>) -> PathBuf {
    opt.map(Path::to_path_buf)
        .or_else(|| std::env::var_os("RUNTIME_DIRECTORY").map(PathBuf::from))
        .or_else(|| std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from))
        .unwrap_or_else(std::env::temp_dir)
}

fn private_dir(p: &Path) -> Result<(), String> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(p)
        .and_then(|()| std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)))
        .map_err(|e| format!("p2 directory {}: {e}", p.display()))
}

/// Boots the P2 runtime before any socket is bound (exit 78 on `Err`): compiles every module of the config's `p2`
/// block, starts the zygote set and the liveness monitor. Returns a runtime even without a `p2` block, so a reload
/// can add one.
pub fn boot(cfg: &Config, keyring: Option<&Path>, runtime_dir: Option<&Path>) -> Result<Option<Arc<Runtime>>, String> {
    let _ = mutant::active(); // the negative-control banner, once, at boot
    let rundir = runtime_base(runtime_dir).join(format!("aegis-p2-{}", std::process::id()));
    if rundir.as_os_str().len() + 16 > MAX_SOCKET_PATH {
        return Err(format!("p2 runtime directory {} is too long for unix socket paths", rundir.display()));
    }
    private_dir(&rundir)?;
    let rt = Arc::new(Runtime {
        state: Mutex::new(State {
            generation: None,
            zygotes: HashMap::new(),
            last_restart: None,
            cordons: Registry::new(64, 300).map_err(|e| e.to_string())?,
            budget: CrashBudget::new(Params::DEFAULT),
            broken: false,
        }),
        rundir,
        keyring_path: keyring.map(Path::to_path_buf),
        next_gen: AtomicU64::new(1),
        next_sock: AtomicU64::new(1),
        stop: AtomicBool::new(false),
    });
    let installed = rt.prepare(cfg).and_then(|p| rt.install(p));
    if let Err(e) = installed {
        rt.shutdown();
        return Err(e);
    }
    let m = rt.clone();
    std::thread::Builder::new()
        .name("aegis-p2-monitor".into())
        .spawn(move || m.monitor())
        .map_err(|e| format!("p2 monitor thread: {e}"))?;
    Ok(Some(rt))
}

impl Runtime {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn socket_path(&self, prefix: &str) -> PathBuf {
        let n = self.next_sock.fetch_add(1, Ordering::Relaxed);
        self.rundir.join(format!("{prefix}{n}.sock"))
    }

    /// The Tier-L key ring of the current generation (`None` without wasm routes).
    pub fn keyring(&self) -> Option<Arc<KeyRing>> {
        self.lock().generation.as_ref().and_then(|g| g.keyring.clone())
    }

    /// Compiles the config's P2 modules (blocking; see the module docs). Nothing is served from the result until
    /// [`Runtime::install`].
    pub fn prepare(&self, cfg: &Config) -> Result<Prepared, String> {
        let Some(p2) = cfg.p2() else {
            if has_wasm_routes(cfg) {
                return Err("wasm routes need a p2 block".into()); // unreachable: aegis-config refuses it
            }
            return Ok(Prepared { generation: None });
        };
        let keyring = if has_wasm_routes(cfg) {
            let path = self.keyring_path.as_deref().ok_or("wasm routes need --token-keyring (F5 Tier-L key ring)")?;
            Some(Arc::new(crate::keyring::load(path)?))
        } else {
            None
        };
        let id = self.next_gen.fetch_add(1, Ordering::Relaxed);
        let lim = p2.limits();
        let cb = p2.crash_budget();
        let budget = Params::new(
            u32::try_from(cb.crashes).map_err(|_| "p2.crash_budget.crashes out of range")?,
            cb.window_s,
            cb.penalty_s,
        )
        .map_err(|e| e.to_string())?;
        let mut generation = Gen {
            id,
            worker: PathBuf::from(p2.worker()),
            mpk: p2.mpk(),
            isolation: p2.isolation(),
            cordon_slots: lim.cordon_slots,
            max_cordons: usize::try_from(lim.max_cordons).map_err(|_| "p2.max_cordons out of range")?,
            idle_s: lim.cordon_idle_s,
            budget,
            headers: HeaderLimits {
                max_fields: cfg.limits().max_header_fields,
                max_list_size: cfg.limits().max_header_list_size,
            },
            modules: HashMap::new(),
            keyring,
        };
        let cache = p2.cache_dir().map(PathBuf::from).unwrap_or_else(|| self.rundir.join("p2cache"));
        if !cache.is_dir() {
            private_dir(&cache)?;
        }
        for m in p2.modules() {
            let mid = m.id();
            let wasm = std::fs::read(m.path()).map_err(|e| format!("p2 module {mid}: {}: {e}", m.path()))?;
            if aegis_config::sha256(&wasm) != *m.sha256() {
                return Err(format!("p2 module {mid}: sha256 of {} does not match the configured digest", m.path()));
            }
            let out = cache.join(format!("{mid}-g{id}.cwasm"));
            let _ = std::fs::remove_file(&out);
            let mut args: Vec<OsString> = vec![
                "compile".into(),
                "--in".into(),
                m.path().into(),
                "--out".into(),
                out.clone().into(),
                "--memory-mib".into(),
                m.memory_mib().to_string().into(),
            ];
            if generation.mpk {
                args.push("--mpk".into());
            }
            let status = Command::new(&generation.worker)
                .args(&args)
                .env_clear()
                .envs(supervisor::passthrough_env(std::env::vars_os()))
                .stdin(Stdio::null())
                .status()
                .map_err(|e| format!("p2 worker {}: {e}", generation.worker.display()))?;
            if !status.success() {
                if mutant::is(Mutant::BootWithoutLandlockAccepted) {
                    // NEGATIVE CONTROL: the worker's refusal is ignored; the module is simply not served.
                    log(&format!("module {mid}: compile refused ({status}), ignored (negative control)"));
                    continue;
                }
                generation.remove_files();
                return Err(format!("p2 module {mid}: the sandboxed aegis-p2 compile refused it ({status})"));
            }
            let cw = match std::fs::read(&out) {
                Ok(b) => b,
                Err(e) => {
                    generation.remove_files();
                    return Err(format!("p2 module {mid}: {}: {e}", out.display()));
                }
            };
            let limits = Limits {
                fuel: m.fuel(),
                wall_ms: m.wall_ms(),
                memory_mib: m.memory_mib(),
                max_host_calls: lim.max_host_calls,
                max_data_runs: lim.max_data_runs,
                max_data_bytes: lim.max_data_bytes,
                max_resp_bytes: lim.max_resp_bytes,
                max_log_bytes: lim.max_log_bytes,
            };
            let rt = ModRt {
                id: mid.to_string(),
                cwasm: out,
                digest: aegis_config::sha256(&cw),
                limits,
                isolation: p2.isolation_for(m),
            };
            generation.modules.insert(mid.to_string(), Arc::new(rt));
        }
        Ok(Prepared { generation: Some(generation) })
    }

    fn worker_cmd(generation: &Gen, m: &ModRt, role: &str) -> WorkerCmd {
        let mut args: Vec<OsString> = vec![
            role.into(),
            "--module".into(),
            m.cwasm.clone().into(),
            "--sha256".into(),
            aegis_config::hex(&m.digest).into(),
            "--memory-mib".into(),
            m.limits.memory_mib.to_string().into(),
        ];
        if generation.mpk {
            args.push("--mpk".into());
        }
        if role == "cordon" {
            args.push("--pool-slots".into());
            args.push(generation.cordon_slots.to_string().into());
        }
        let cmd = WorkerCmd::new(generation.worker.clone(), args);
        if mutant::is(Mutant::ForkRespawn) {
            // NEGATIVE CONTROL: every worker starts with the same layout (ASLR off), the observable effect of a
            // replacement forked from a template.
            let mut a: Vec<OsString> =
                vec![std::env::consts::ARCH.into(), "-R".into(), generation.worker.clone().into()];
            a.extend(cmd.args);
            return WorkerCmd { exe: PathBuf::from("/usr/bin/setarch"), args: a, env: cmd.env };
        }
        cmd
    }

    /// Serves `prep` from now on: the previous generation's workers are shut down (zygote set and every cordon
    /// group), the new zygote set is started. The crash budget survives unless its parameters changed.
    pub fn install(&self, mut prep: Prepared) -> Result<(), String> {
        let generation = prep.generation.take().map(Arc::new);
        let mut st = self.lock();
        let old = st.generation.take();
        if mutant::is(Mutant::NoReloadSwitch)
            && let (Some(o), Some(n)) = (&old, &generation)
            && o.isolation != n.isolation
        {
            st.broken = true; // NEGATIVE CONTROL: the path switch breaks the routes
        }
        st.zygotes.clear();
        st.last_restart = None;
        let (max, idle) = generation.as_ref().map_or((64, 300), |g| (g.max_cordons, g.idle_s));
        st.cordons = Registry::new(max, idle).map_err(|e| e.to_string())?;
        if let Some(g) = &generation
            && *st.budget.params() != g.budget
        {
            st.budget = CrashBudget::new(g.budget);
        }
        st.generation = generation.clone();
        let mut started = Ok(());
        if let Some(g) = &generation {
            for m in g.modules.values().filter(|m| m.isolation == Isolation::ForkWasm) {
                match Proc::start(Self::worker_cmd(g, m, "zygote"), self.socket_path("z")) {
                    Ok(p) => {
                        st.zygotes.insert(m.id.clone(), p);
                    }
                    Err(e) => {
                        started = Err(format!("p2 zygote for module {}: {e}", m.id));
                        break;
                    }
                }
            }
        }
        drop(st);
        if let Some(o) = old {
            o.remove_files();
        }
        started
    }

    /// Kills every worker and removes the runtime directory. Idempotent.
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Release);
        let mut st = self.lock();
        st.zygotes.clear();
        if let Ok(r) = Registry::new(1, 1) {
            st.cordons = r;
        }
        if let Some(g) = st.generation.take() {
            g.remove_files();
        }
        drop(st);
        let _ = std::fs::remove_dir_all(&self.rundir);
    }

    /// The cordon for `key`'s request to `m`: the principal's group (created on first use, replaced whole if a
    /// member has died) and the module's process in it (spawned on first use).
    fn cordon_for(&self, st: &mut State, generation: &Gen, m: &ModRt, key: &Key, now: Instant) -> Option<Target> {
        for _ in 0..2 {
            let acq = match st.cordons.acquire(key, now, |_| Ok::<Group, ()>(Group::default())) {
                Ok(Ok(a)) => a,
                Ok(Err(())) => return None,
                Err(e) => {
                    log(&format!("cordon table: {e}"));
                    return None;
                }
            };
            drop(acq.evicted); // an evicted idle group of another principal: shut down
            let id = acq.id;
            let g = st.cordons.get(id, key).ok()?;
            if g.any_exited() {
                let _ = st.cordons.release(id, key, now);
                drop(st.cordons.remove(id, key));
                continue;
            }
            if !g.procs.contains_key(&m.id) {
                match Proc::start(Self::worker_cmd(generation, m, "cordon"), self.socket_path("c")) {
                    Ok(p) => {
                        g.procs.insert(m.id.clone(), p);
                    }
                    Err(e) => {
                        log(&format!("cordon for module {}: {e}", m.id));
                        let _ = st.cordons.release(id, key, now);
                        return None;
                    }
                }
            }
            let p = g.procs.get(&m.id)?;
            return Some(Target::Cordon { id, path: p.path.clone(), h: p.h.clone() });
        }
        None
    }

    /// One request of principal `key` to module `module` (blocking; run on the blocking pool).
    pub fn serve(&self, key: &Key, module: &str, head: &[u8], body: &[u8]) -> Served {
        let bkey = if mutant::is(Mutant::GlobalCrashBudget) { Key::constant() } else { key.clone() };
        let ckey = if mutant::is(Mutant::SharedCordon) { Key::constant() } else { key.clone() };
        let now = Instant::now();
        let (generation, m, target) = {
            let mut st = self.lock();
            if let Verdict::Penalty { .. } = st.budget.check(&bkey, now) {
                return Served::Penalty;
            }
            if st.broken {
                return Served::Done(Outcome::ErrorCode(u32::MAX));
            }
            let Some(generation) = st.generation.clone() else { return Served::Unavailable };
            let Some(m) = generation.modules.get(module).cloned() else {
                // A module not served by this generation (only under the boot-without-landlock negative control).
                return Served::Done(Outcome::ErrorCode(u32::MAX));
            };
            let target = match m.isolation {
                Isolation::ForkWasm => match st.zygotes.get(module) {
                    Some(z) => Target::Fork { path: z.path.clone() },
                    None => return Served::Unavailable,
                },
                Isolation::Cordon => match self.cordon_for(&mut st, &generation, &m, &ckey, now) {
                    Some(t) => t,
                    None => return Served::Unavailable,
                },
            };
            (generation, m, target)
        };
        let job =
            Job { socket: target.path(), digest: &m.digest, limits: m.limits, head, body, headers: generation.headers };
        let outcome = exchange::run(&job);
        let (failure, tear_down) = classify(&outcome, &target);
        match &outcome {
            Outcome::Decode(why) => log(&format!("module {}: F14 decode failure: {why}", m.id)),
            Outcome::Unready(why) => log(&format!("module {}: worker not ready: {why}", m.id)),
            Outcome::Timeout => log(&format!("module {}: no resp-end within wall_ms + grace", m.id)),
            _ => {}
        }
        let mut st = self.lock();
        let current = st.generation.as_ref().is_some_and(|g| g.id == generation.id);
        if let Target::Cordon { id, .. } = target {
            let _ = st.cordons.release(id, &ckey, Instant::now());
            if tear_down && current && st.cordons.id_of(&ckey) == Some(id) {
                drop(st.cordons.remove(id, &ckey)); // the whole group: kill and reap
            }
        }
        if let Some(f) = failure
            && current
            && !mutant::is(Mutant::NoCrashBudget)
        {
            st.budget.record(&bkey, f, Instant::now());
        }
        drop(st);
        Served::Done(outcome)
    }

    /// The liveness monitor: replaces the zygote set when a member died, shuts down a cordon group when a member
    /// died, reaps idle groups.
    fn monitor(self: Arc<Self>) {
        while !self.stop.load(Ordering::Acquire) {
            std::thread::sleep(MONITOR_TICK);
            let mut st = self.lock();
            if self.stop.load(Ordering::Acquire) {
                break;
            }
            let now = Instant::now();
            let dead: Vec<String> = st.zygotes.iter().filter(|(_, p)| p.h.exited()).map(|(k, _)| k.clone()).collect();
            if !dead.is_empty() && st.last_restart.is_none_or(|t| now.duration_since(t) >= ZYGOTE_RESTART_MIN) {
                log(&format!("zygote of {dead:?} died; replacing the zygote set by fresh execve"));
                for (mid, p) in st.zygotes.iter_mut() {
                    if let Err(e) = p.respawn() {
                        log(&format!("zygote {mid}: {e}"));
                    }
                }
                st.last_restart = Some(now);
            }
            let dead_groups: Vec<(Key, CordonId)> =
                st.cordons.iter_mut().filter(|(_, _, g)| g.any_exited()).map(|(k, id, _)| (k.clone(), id)).collect();
            for (k, id) in dead_groups {
                drop(st.cordons.remove(id, &k));
            }
            drop(st.cordons.reap_idle(now));
        }
    }
}

/// The crash-budget charge of an outcome (before the generation check) and whether a cordon group must go.
fn classify(o: &Outcome, t: &Target) -> (Option<Failure>, bool) {
    let crash = |k| Some(Failure::Crash(k));
    let cordon = matches!(t, Target::Cordon { .. });
    match o {
        Outcome::Allow { .. } | Outcome::ErrorCode(_) => (None, false),
        Outcome::Deny if mutant::is(Mutant::BudgetCountsHealthy) => (crash(CrashKind::Trap), false),
        Outcome::Deny => (None, false),
        Outcome::Trap(_) => (crash(CrashKind::Trap), false),
        Outcome::Decode(_) => (crash(CrashKind::DecodeFailure), cordon),
        Outcome::Timeout => (crash(CrashKind::AbnormalExit), cordon),
        Outcome::Unready(_) => (None, cordon),
        Outcome::Eof => match t {
            Target::Fork { .. } => (crash(CrashKind::AbnormalExit), false),
            Target::Cordon { h, .. } => (cordon_death(h), true),
        },
    }
}

/// A cordon connection ended without `resp-end`: charged as a cordon death only if the process died on its own
/// (not killed by this supervisor) within [`DEATH_WAIT`].
fn cordon_death(h: &ProcHandle) -> Option<Failure> {
    let until = Instant::now() + DEATH_WAIT;
    loop {
        if h.exited() {
            return (!h.torn_down.load(Ordering::Acquire)).then_some(Failure::Crash(CrashKind::CordonDeath));
        }
        if Instant::now() >= until {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
