//! The serving process: boot (fail closed), listeners, the control thread (SIGHUP reload, SIGUSR2 upgrade,
//! SIGTERM drain), sd-notify.
//!
//! Boot order: block lifecycle signals (before any thread exists) → read + validate config (CFG-1/2, exit 78) →
//! plan (exit 78) → native data plane (exit 78) → P2 supervisor: every module compiled by the sandboxed
//! `monban-p2 compile`, zygote set started (feature `p2`; exit 78) → certificates + TLS profiles (exit 78) → audit
//! log (exit 78) → audit `config.apply` durably (fail closed, Audit I7) → bind (or take over from the upgrading
//! parent, F11) → accept → READY. The P2 workers are shut down whenever the process leaves `run`.

use std::net::TcpListener as StdTcpListener;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use monban_audit::{DetailValue, Outcome};
use monban_config::{ConfigStore, MAX_CONFIG_BYTES};
use monban_ops::fdcheck::describe_tcp;
use monban_ops::handover::{self, LeakPolicy, Offered, ParentConfig, ParentHooks};
use monban_ops::notify::Notifier;
use monban_ops::signals::{Sig, Signals};
use monban_ops::stek::StekRing;
use monban_ops::wire::ListenerDesc;
use monban_transport::{Server, TlsAcceptor};
use tokio::net::{TcpListener, UnixListener};

use crate::audit::{Auditor, text};
use crate::cli::ServeOpts;
use crate::plan::{AdminBind, Plan, Snapshot, plan};
use crate::proxy::ProxyApp;
use crate::shared::{ConnGuard, Shared, bump};
use crate::tls::{CertPaths, Tls};
use crate::util::{Either, race};

pub const EX_CONFIG: u8 = 78;
const EX_SOFTWARE: u8 = 70;
const EX_OSERR: u8 = 71;
const EX_IOERR: u8 = 74;
/// `--front uring` without a usable io_uring (EX_UNAVAILABLE): refused before anything is bound.
#[cfg_attr(not(feature = "uring"), allow(dead_code))]
const EX_UNAVAILABLE: u8 = 69;
/// UP-4 drain deadline D (upgrade).
const DRAIN_DEADLINE: Duration = Duration::from_secs(10);
/// NC8: SIGTERM to exit within T_drain = 10 s (PLAN D16). Connections get 8 s, then in-flight app scopes (pool
/// tasks whose client already got its answer, e.g. a 504 before the commit point) the rest of 9 s.
const TERM_DRAIN: Duration = Duration::from_secs(8);
const TERM_SCOPES: Duration = Duration::from_secs(9);
const HANDOVER_TIMEOUT: Duration = Duration::from_secs(10);
/// Handover name of the admin listener (cannot collide: F8 listener names have no '.').
const ADMIN_NAME: &str = "admin.ctl";

fn log(msg: &str) {
    eprintln!("monban[{}]: {msg}", std::process::id());
}

/// Read a config file, bounded (parse_config enforces the 1 MiB cap on what it is given).
pub fn read_config(p: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let f = std::fs::File::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let mut v = Vec::new();
    f.take(u64::try_from(MAX_CONFIG_BYTES).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut v)
        .map_err(|e| format!("{}: {e}", p.display()))?;
    Ok(v)
}

fn fail_closed(msg: &str) -> ExitCode {
    log(&format!("{msg}; refusing to serve (fail-closed boot)"));
    ExitCode::from(EX_CONFIG)
}

/// The inbound server: monban-transport (h1 + h2 with the Monban wrapper) in front of the proxy.
pub type Srv = Server<ProxyApp>;

/// A public listener: the transport, its TLS acceptor and its Phase-7 front matter (PROXY, L4, MTC), if any.
#[derive(Clone)]
struct Public {
    srv: Arc<Srv>,
    acc: TlsAcceptor,
    #[cfg(any(feature = "proxy-protocol", feature = "l4", all(feature = "mtc", not(feature = "cmvp"))))]
    front: Option<Arc<crate::front::Front>>,
}

#[derive(Clone)]
enum Kind {
    Public(Public),
    Admin(Arc<monban_tls::FipsStatus>),
}

struct AcceptGuard(Arc<Shared>);
impl AcceptGuard {
    fn new(s: &Arc<Shared>) -> Self {
        s.accept_tasks.fetch_add(1, Ordering::AcqRel);
        Self(s.clone())
    }
}
impl Drop for AcceptGuard {
    fn drop(&mut self) {
        self.0.accept_tasks.fetch_sub(1, Ordering::AcqRel);
    }
}

async fn accept_tcp(shared: Arc<Shared>, l: TcpListener, kind: Kind) {
    let _g = AcceptGuard::new(&shared);
    loop {
        let notified = shared.stop_notify.notified();
        let mut notified = pin!(notified);
        notified.as_mut().enable();
        if shared.stop_accept.load(Ordering::Acquire) {
            break;
        }
        match race(l.accept(), notified).await {
            Either::Left(Ok((sock, addr))) => {
                let shared = shared.clone();
                match &kind {
                    Kind::Public(p) => {
                        let _ = sock.set_nodelay(true);
                        tokio::spawn(public_conn(shared, p.clone(), sock, addr));
                    }
                    Kind::Admin(f) => {
                        let f = f.clone();
                        tokio::spawn(async move {
                            let _c = ConnGuard::new(&shared);
                            crate::admin::handle(shared, f, sock).await;
                        });
                    }
                }
            }
            Either::Left(Err(_)) => tokio::time::sleep(Duration::from_millis(20)).await, // EMFILE etc.
            Either::Right(()) => break,
        }
    }
    drop(l); // closes this process's fd for the listener
}

async fn accept_unix(shared: Arc<Shared>, l: UnixListener, fips: Arc<monban_tls::FipsStatus>) {
    loop {
        let notified = shared.stop_notify.notified();
        let mut notified = pin!(notified);
        notified.as_mut().enable();
        if shared.stop_accept.load(Ordering::Acquire) {
            break;
        }
        match race(l.accept(), notified).await {
            Either::Left(Ok((sock, _))) => {
                tokio::spawn(crate::admin::handle(shared.clone(), fips.clone(), sock));
            }
            Either::Left(Err(_)) => tokio::time::sleep(Duration::from_millis(20)).await,
            Either::Right(()) => break,
        }
    }
}

/// The io_uring front's accept loop (feature `uring`; D-P7.3): accept and connection I/O go through the ring, the
/// listener and its connections are never registered with tokio's epoll. Same stop/drain handling as [`accept_tcp`].
#[cfg(feature = "uring")]
async fn accept_uring(shared: Arc<Shared>, l: monban_uring::UringListener, p: Public) {
    let _g = AcceptGuard::new(&shared);
    loop {
        let notified = shared.stop_notify.notified();
        let mut notified = pin!(notified);
        notified.as_mut().enable();
        if shared.stop_accept.load(Ordering::Acquire) {
            break;
        }
        match race(l.accept(), notified).await {
            Either::Left(Ok((sock, addr))) => {
                tokio::spawn(public_conn(shared.clone(), p.clone(), sock, addr));
            }
            Either::Left(Err(_)) => tokio::time::sleep(Duration::from_millis(20)).await, // EMFILE etc.
            Either::Right(()) => break,
        }
    }
    drop(l); // the ring driver closes the listener once its last stream is gone
}

async fn public_conn<IO>(shared: Arc<Shared>, p: Public, sock: IO, addr: std::net::SocketAddr)
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let _g = ConnGuard::new(&shared);
    #[cfg(any(feature = "proxy-protocol", feature = "l4", all(feature = "mtc", not(feature = "cmvp"))))]
    if let Some(f) = p.front {
        return crate::front::serve(shared, p.srv, f, sock, addr, p.acc).await;
    }
    p.srv.serve_tls_from(sock, p.acc, Some(addr)).await;
}

/// Upgrade hooks: the parent stops accepting and drains (UP-1/UP-4).
struct Hooks {
    shared: Arc<Shared>,
    srv: Arc<Srv>,
}

impl ParentHooks for Hooks {
    fn close_listeners(&mut self) {
        self.shared.stop_accept.store(true, Ordering::Release);
        self.shared.stop_notify.notify_waiters();
        let until = Instant::now() + Duration::from_secs(2);
        while self.shared.accept_tasks.load(Ordering::Acquire) > 0 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn drain(&mut self, deadline: Duration) -> u64 {
        drain(&self.shared, &self.srv, deadline)
    }
}

fn drain(shared: &Shared, srv: &Srv, deadline: Duration) -> u64 {
    shared.draining.store(true, Ordering::Release);
    srv.drain();
    let until = Instant::now() + deadline;
    while shared.live_conns.load(Ordering::Acquire) > 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
        srv.drain();
    }
    u64::try_from(shared.live_conns.load(Ordering::Acquire)).unwrap_or(u64::MAX)
}

struct Ctl {
    opts: ServeOpts,
    exe: PathBuf,
    store: ConfigStore,
    shared: Arc<Shared>,
    srv: Arc<Srv>,
    auditor: Arc<Auditor>,
    tls: Tls,
    certs: CertPaths,
    notifier: Notifier,
    descs: Vec<ListenerDesc>,
    offers: Vec<StdTcpListener>,
    ring: StekRing,
    /// F8 `runtime.worker_threads` the runtime was built with (a reload cannot resize it).
    workers: u64,
}

impl Ctl {
    fn audit(
        &self,
        action: &str,
        object: &str,
        outcome: Outcome,
        detail: &[(&str, DetailValue)],
    ) -> Result<u64, String> {
        let hash = self.shared.snapshot().hash;
        self.auditor.admin(action, object, outcome, hash, detail)
    }

    /// Serve a new routing table: the proxy's snapshot plus the transport's vhosts and limits.
    fn install(&self, snap: Snapshot) {
        self.srv.set_vhosts(snap.vhost_table());
        if let Err(e) = self.srv.set_limits(snap.plan.wl) {
            log(&format!("transport limits refused, previous limits kept: {e}"));
        }
        self.shared.install(snap);
    }

    /// CFG-3: a load that fails leaves the served config untouched and counts a last-known-good fallback.
    fn fallback(&self, action: &str, why: &str) {
        log(&format!("config reload refused: {why}; last-known-good keeps serving"));
        if self.shared.mutants.skip_lkg {
            // NEGATIVE CONTROL: drop the served config instead of keeping the last-known-good.
            #[cfg(feature = "e2e-mutants")]
            self.install(self.shared.snapshot().empty());
            return;
        }
        self.shared.registry.config_lkg_fallbacks.inc();
        let outcome = if action == "config.rollback" { Outcome::RolledBack } else { Outcome::Error };
        if let Err(e) = self.audit(action, &self.opts.config.display().to_string(), outcome, &[("reason", text(why))]) {
            log(&format!("audit of refused reload failed: {e}"));
        }
    }

    fn reload(&mut self) {
        let _ = self.notifier.reloading();
        let applied = read_config(&self.opts.config).and_then(|b| self.store.apply(&b).map_err(|e| e.to_string()));
        match applied {
            Err(e) => self.fallback("config.apply", &e),
            Ok(generation) => {
                let Some(cfg) = self.store.current().cloned() else {
                    return self.fallback("config.apply", "no current config after apply");
                };
                let cur = self.shared.snapshot();
                let candidate = plan(&cfg).and_then(|p| {
                    if !p.same_sockets(&cur.plan) {
                        return Err(
                            "listener or admin change: use the zero-downtime upgrade (SIGUSR2) after editing".into()
                        );
                    }
                    if !p.same_admission(&cur.plan) {
                        return Err("admission change: the limiter is built at start (restart or upgrade)".into());
                    }
                    if cfg.runtime().worker_threads != self.workers {
                        return Err(
                            "runtime.worker_threads change: the runtime is built at start (restart or upgrade)".into(),
                        );
                    }
                    // App routes are re-resolved against the schemas introspected at boot; a data plane that was
                    // not booted cannot serve them (restart or upgrade).
                    let bindings = match &self.shared.native {
                        Some(dp) => Arc::new(dp.bind(&cfg)?),
                        None if crate::native::has_app_routes(&cfg) || crate::native::has_data_wasm_routes(&cfg) => {
                            return Err("app routes need the data plane booted at start (restart or upgrade)".into());
                        }
                        None => Arc::default(),
                    };
                    // P2 modules are compiled (sandboxed) and digested before anything is applied; a refusal keeps
                    // the last-known-good config and its workers.
                    let p2 = match &self.shared.p2 {
                        Some(rt) => Some(rt.prepare(&cfg)?),
                        None if crate::p2::has_wasm_routes(&cfg) => {
                            return Err("wasm routes need the P2 supervisor (feature `p2`)".into());
                        }
                        None => None,
                    };
                    Ok((p, bindings, p2))
                });
                match candidate {
                    Err(e) => {
                        let _ = self.store.rollback();
                        self.fallback("config.rollback", &e);
                    }
                    Ok((p, bindings, p2)) => {
                        let hash = cfg.config_hash();
                        let detail = [
                            ("generation", DetailValue::Int(i64::try_from(generation.0).unwrap_or(i64::MAX))),
                            ("new_hash", text(&cfg.config_hash_hex())),
                        ];
                        if let Err(e) = self.audit(
                            "config.apply",
                            &self.opts.config.display().to_string(),
                            Outcome::Applied,
                            &detail,
                        ) {
                            let _ = self.store.rollback();
                            self.fallback("config.rollback", &format!("audit refused (fail closed): {e}"));
                        } else {
                            // CRS C5: a changed config is a new epoch; pooled upstream connections are dropped.
                            let epoch = if hash == cur.hash { cur.epoch } else { cur.epoch.saturating_add(1) };
                            let mut snap = Snapshot::new(generation.0, epoch, hash, p);
                            snap.native = bindings;
                            self.install(snap);
                            // The P2 generation: previous workers shut down, the new zygote set started (D1: a path
                            // switch is this reload, no rebuild).
                            if let (Some(rt), Some(prep)) = (&self.shared.p2, p2)
                                && let Err(e) = rt.install(prep)
                            {
                                log(&format!("p2: {e}"));
                            }
                            // CRS C5 on the data plane: pooled PG connections of older epochs are retired.
                            if let Some(dp) = &self.shared.native {
                                dp.bump_epoch(epoch);
                            }
                            bump(&self.shared.stats.config_reloads);
                            log(&format!("config generation {} applied ({})", generation.0, cfg.config_hash_hex()));
                        }
                    }
                }
            }
        }
        match self.tls.reinstall(&self.certs) {
            Ok(()) => {
                if let Some(i) = self.tls.current() {
                    self.shared.cert_not_after.store(i.report.not_after, Ordering::Relaxed);
                }
            }
            Err(e) => {
                log(&format!("certificate reload refused, previous certificate kept: {e}"));
                let _ = self.audit(
                    "cert.install",
                    &self.certs.cert.display().to_string(),
                    Outcome::Error,
                    &[("reason", text(&e))],
                );
            }
        }
        let _ = self.notifier.ready();
    }

    /// SIGUSR2: hand the listeners to a new process (F11). `true` = handed over, exit now.
    fn upgrade(&mut self) -> bool {
        self.ring.epoch = self.ring.epoch.wrapping_add(1);
        let runtime_dir = self
            .opts
            .runtime_dir
            .clone()
            .or_else(|| std::env::var_os("RUNTIME_DIRECTORY").map(PathBuf::from))
            .or_else(|| std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from))
            .unwrap_or_else(std::env::temp_dir);
        let cfg = ParentConfig {
            exe: self.exe.clone(),
            args: self.opts.args.clone(),
            runtime_dir,
            handover_timeout: HANDOVER_TIMEOUT,
            drain_deadline: DRAIN_DEADLINE,
            require_cloexec: true,
            notifier: self.notifier,
        };
        let offered: Vec<Offered<'_>> =
            self.descs.iter().zip(&self.offers).map(|(d, o)| Offered { desc: d, fd: o.as_fd() }).collect();
        let _ = self.audit("upgrade.start", &self.exe.display().to_string(), Outcome::Allow, &[]);
        let mut hooks = Hooks { shared: self.shared.clone(), srv: self.srv.clone() };
        match handover::upgrade(&cfg, &offered, &self.ring, &mut hooks) {
            Ok(h) => {
                self.shared.registry.upgrade_forced_closes.add(h.forced);
                let pid = i64::from(h.child_pid);
                let forced = i64::try_from(h.forced).unwrap_or(i64::MAX);
                let _ = self.audit(
                    "listener.stop",
                    "all",
                    Outcome::Applied,
                    &[
                        ("reason", text("upgrade handover")),
                        ("child_pid", DetailValue::Int(pid)),
                        ("forced_closes", DetailValue::Int(forced)),
                    ],
                );
                log(&format!("handed over to {}, forced closes {}", h.child_pid, h.forced));
                true
            }
            Err(e) => {
                log(&format!("{e}; still serving"));
                let _ = self.audit(
                    "upgrade.failed",
                    &self.exe.display().to_string(),
                    Outcome::Error,
                    &[("reason", text(&e.to_string()))],
                );
                false
            }
        }
    }

    fn terminate(&mut self) {
        let t0 = Instant::now();
        let _ = self.notifier.stopping();
        if self.shared.mutants.ack_then_drop
            && let Some(dp) = &self.shared.native
        {
            // NEGATIVE CONTROL (e2e-mutants only): fabricate successes for in-flight requests, exit uncommitted.
            dp.start_dropping();
            std::thread::sleep(Duration::from_millis(300));
            std::process::exit(0);
        }
        self.shared.stop_accept.store(true, Ordering::Release);
        self.shared.stop_notify.notify_waiters();
        self.offers.clear();
        let forced = drain(&self.shared, &self.srv, TERM_DRAIN);
        if let Some(dp) = &self.shared.native {
            while dp.active() > 0 && t0.elapsed() < TERM_SCOPES {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        if let Some(rt) = &self.shared.p2 {
            rt.shutdown(); // SIGTERM stops the workers too
        }
        let _ = self.audit(
            "listener.stop",
            "all",
            Outcome::Applied,
            &[
                ("reason", text("SIGTERM")),
                ("forced_closes", DetailValue::Int(i64::try_from(forced).unwrap_or(i64::MAX))),
            ],
        );
        log(&format!("terminated, forced closes {forced}"));
    }
}

fn bind_all(p: &Plan) -> Result<Vec<(String, StdTcpListener)>, String> {
    let mut v = Vec::new();
    for l in &p.listeners {
        let s = StdTcpListener::bind(l.addr).map_err(|e| format!("bind listener {} on {}: {e}", l.name, l.addr))?;
        v.push((l.name.clone(), s));
    }
    if let AdminBind::Tcp(a) = &p.admin {
        let s = StdTcpListener::bind(a).map_err(|e| format!("bind admin on {a}: {e}"))?;
        v.push((ADMIN_NAME.to_string(), s));
    }
    Ok(v)
}

pub fn run(opts: ServeOpts) -> ExitCode {
    // Before any thread exists, so only the control thread's sigwait sees SIGHUP / SIGUSR2 / SIGTERM.
    let signals = match Signals::block() {
        Ok(s) => s,
        Err(e) => {
            log(&format!("block signals: {e}"));
            return ExitCode::from(EX_OSERR);
        }
    };
    let bytes = match read_config(&opts.config) {
        Ok(b) => b,
        Err(e) => return fail_closed(&format!("config {e}")),
    };
    let mut store = ConfigStore::new();
    let generation = match store.apply(&bytes) {
        Ok(g) => g,
        Err(e) => return fail_closed(&format!("config {}: {e}", opts.config.display())),
    };
    let Some(cfg) = store.current().cloned() else { return fail_closed("config store empty") };
    let p = match plan(&cfg) {
        Ok(p) => p,
        Err(e) => return fail_closed(&format!("config {}: {e}", opts.config.display())),
    };
    for w in &p.warnings {
        log(&format!("warning: {w}"));
    }
    // The front of each listener: `--front` overrides F8 `listeners[].front` (FRONT-1). io_uring is probed before
    // anything is bound, and a refusal is final: there is no epoll fallback (D-P7.3).
    let fronts: Vec<(String, monban_config::Front)> =
        p.listeners.iter().map(|l| (l.name.clone(), opts.front.unwrap_or(l.front))).collect();
    if fronts.iter().any(|(_, f)| *f == monban_config::Front::Uring) {
        #[cfg(feature = "uring")]
        if let Err(e) = monban_uring::uring_available() {
            log(&format!("--front uring: {e}"));
            return ExitCode::from(EX_UNAVAILABLE);
        }
        #[cfg(not(feature = "uring"))]
        return fail_closed("front uring: this build has no feature `uring`");
    }
    // Native data plane (modes A/D): backends opened and introspected, endowments resolved, before any socket.
    let native = match crate::native::boot(&cfg, opts.token_keyring.as_deref(), crate::shared::Mutants::from_env()) {
        Ok(n) => n,
        Err(e) => return fail_closed(&e),
    };
    let bindings = match &native {
        Some(dp) => match dp.bind(&cfg) {
            Ok(b) => Arc::new(b),
            Err(e) => return fail_closed(&e),
        },
        None => Arc::default(),
    };
    // IDEMP-R (F8 `state.idempotency_retention_s`, P8-bin-002): expired idempotency outcomes are purged every
    // period while the data plane lives; absent = never expire (no thread).
    #[cfg(feature = "native")]
    let _purge = native.as_ref().and_then(|dp| crate::native::spawn_purge(dp, log));
    // P2 (feature `p2`): every module compiled by the sandboxed worker and the zygote set started, before any
    // socket. A worker that refuses (missing, digest mismatch, Landlock ABI < 4, D2) fails the boot.
    let p2 = match crate::p2::boot(&cfg, opts.token_keyring.as_deref(), opts.runtime_dir.as_deref()) {
        Ok(p) => p,
        Err(e) => return fail_closed(&e),
    };
    let _p2_guard = crate::p2::Guard(p2.clone());
    let certs = match CertPaths::resolve(opts.cert.as_deref(), opts.key.as_deref()) {
        Ok(c) => c,
        Err(e) => return fail_closed(&e),
    };
    let tls = match Tls::build(&p.listeners, &certs) {
        Ok(t) => t,
        Err(e) => return fail_closed(&e),
    };
    // MTC credential selectors (feature `mtc`): every credential loaded and checked before any socket.
    #[cfg(all(feature = "mtc", not(feature = "cmvp")))]
    let selectors = match crate::tls::selectors(&cfg, &p.listeners) {
        Ok(s) => s,
        Err(e) => return fail_closed(&e),
    };
    let Some(audit_base) = opts.audit_dir.clone().or_else(Auditor::default_dir) else {
        return fail_closed("no audit directory (--audit-dir or StateDirectory=); admin events fail closed");
    };
    let auditor = match Auditor::open(&audit_base, &tls.fips) {
        Ok(a) => Arc::new(a),
        Err(e) => return fail_closed(&e),
    };
    // P2 data_run decisions go to the same log (F14 I6-host: audit before every host-mediated effect).
    if let Some(rt) = &p2 {
        rt.set_auditor(Arc::clone(&auditor));
    }
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            log(&format!("current_exe: {e}"));
            return ExitCode::from(EX_OSERR);
        }
    };
    let hash = cfg.config_hash();
    let admin_bind = p.admin.clone();
    let mut snap0 = Snapshot::new(generation.0, 1, hash, p);
    snap0.native = bindings;
    let shared = Shared::new(snap0, native, p2);
    let srv = {
        let snap = shared.snapshot();
        match Server::new(ProxyApp { shared: shared.clone() }, snap.vhost_table(), snap.plan.wl) {
            Ok(s) => s,
            Err(e) => return fail_closed(&format!("transport limits: {e}")),
        }
    };
    shared.registry.set_fips_active(tls.fips.config_fips);
    if let Some(i) = tls.current() {
        shared.cert_not_after.store(i.report.not_after, Ordering::Relaxed);
    }
    let detail = [
        ("generation", DetailValue::Int(i64::try_from(generation.0).unwrap_or(i64::MAX))),
        ("new_hash", text(&cfg.config_hash_hex())),
    ];
    if let Err(e) = auditor.admin("config.apply", &opts.config.display().to_string(), Outcome::Applied, hash, &detail) {
        log(&format!("{e}; refusing to serve (admin audit fails closed)"));
        return ExitCode::from(EX_IOERR);
    }
    // F8 `runtime.worker_threads` (D-P8.3, R5): absent = 2, the constant this builder had before Phase 8, so every
    // timing gate runs unchanged; 1..=1024 is enforced by monban-config. Read at boot only: a reload (SIGHUP) cannot
    // resize the runtime, and an upgrade (new process) applies a new value.
    let workers = cfg.runtime().worker_threads;
    let threads = usize::try_from(workers).unwrap_or(2).max(1);
    let rt = match tokio::runtime::Builder::new_multi_thread().worker_threads(threads).enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            log(&format!("runtime: {e}"));
            return ExitCode::from(EX_OSERR);
        }
    };
    let _enter = rt.enter();

    // ---- sockets: take over from an upgrading parent, or bind
    let child = handover::is_upgrade_child();
    let (sockets, ring, takeover) = if child {
        match handover::child_takeover(hash, HANDOVER_TIMEOUT, LeakPolicy::Refuse) {
            Ok(mut t) => {
                let ls: Vec<(String, StdTcpListener)> = t.listeners.drain(..).map(|(d, l)| (d.name, l)).collect();
                let ring = t.stek.clone();
                (ls, ring, Some(t))
            }
            Err(e) => {
                log(&format!("{e}"));
                return ExitCode::from(EX_SOFTWARE);
            }
        }
    } else {
        let ls = match bind_all(&shared.snapshot().plan) {
            Ok(l) => l,
            Err(e) => {
                log(&e);
                return ExitCode::from(EX_OSERR);
            }
        };
        match StekRing::generate() {
            Ok(r) => (ls, r, None),
            Err(e) => {
                log(&format!("stek: {e}"));
                return ExitCode::from(EX_OSERR);
            }
        }
    };
    let fips = Arc::new(tls.fips.clone());
    let mut descs = Vec::new();
    let mut offers = Vec::new();
    let snap = shared.snapshot();
    let mut wanted: Vec<String> = snap.plan.listeners.iter().map(|l| l.name.clone()).collect();
    if matches!(admin_bind, AdminBind::Tcp(_)) {
        wanted.push(ADMIN_NAME.to_string());
    }
    for name in &wanted {
        let Some((_, l)) = sockets.iter().find(|(n, _)| n == name) else {
            log(&format!("listener {name} missing after takeover; the parent keeps serving"));
            return ExitCode::from(EX_SOFTWARE);
        };
        let uring = name != ADMIN_NAME && fronts.iter().any(|(n, f)| n == name && *f == monban_config::Front::Uring);
        let (desc, offer, mine) = match (|| -> std::io::Result<_> {
            let desc = describe_tcp(name, l)?;
            let offer = l.try_clone()?;
            let mine = l.try_clone()?;
            Ok((desc, offer, mine))
        })() {
            Ok(v) => v,
            Err(e) => {
                log(&format!("listener {name}: {e}"));
                return ExitCode::from(EX_OSERR);
            }
        };
        let kind = if name == ADMIN_NAME {
            Kind::Admin(fips.clone())
        } else {
            let Some((_, a)) = tls.acceptors.iter().find(|(n, _)| n == name) else {
                return fail_closed(&format!("no TLS acceptor for listener {name}"));
            };
            #[cfg(any(feature = "proxy-protocol", feature = "l4", all(feature = "mtc", not(feature = "cmvp"))))]
            let front = {
                #[cfg_attr(not(any(feature = "proxy-protocol", feature = "l4")), allow(unused_variables))]
                let lp = snap.plan.listeners.iter().find(|l| &l.name == name);
                let f = crate::front::Front {
                    name: name.clone(),
                    #[cfg(feature = "proxy-protocol")]
                    proxy: lp.and_then(|l| l.proxy.clone()),
                    #[cfg(feature = "l4")]
                    l4: lp.and_then(|l| l.l4.clone()),
                    #[cfg(all(feature = "mtc", not(feature = "cmvp")))]
                    selector: selectors.iter().find(|(n, _)| n == name).map(|(_, s)| Arc::clone(s)),
                    auditor: Arc::clone(&auditor),
                };
                f.active().then(|| Arc::new(f))
            };
            Kind::Public(Public {
                srv: srv.clone(),
                acc: a.clone(),
                #[cfg(any(feature = "proxy-protocol", feature = "l4", all(feature = "mtc", not(feature = "cmvp"))))]
                front,
            })
        };
        let addr = if uring {
            #[cfg(feature = "uring")]
            {
                let Kind::Public(p) = kind else { return fail_closed("the admin listener has no io_uring front") };
                let ul = match monban_uring::UringListener::bind(mine) {
                    Ok(u) => u,
                    Err(e) => {
                        log(&format!("listener {name}: {e}"));
                        return ExitCode::from(EX_UNAVAILABLE);
                    }
                };
                let addr = ul.local_addr().to_string();
                tokio::spawn(accept_uring(shared.clone(), ul, p));
                addr
            }
            #[cfg(not(feature = "uring"))]
            {
                drop((mine, kind));
                return fail_closed("front uring: this build has no feature `uring`");
            }
        } else {
            let tl = match mine.set_nonblocking(true).and_then(|()| TcpListener::from_std(mine)) {
                Ok(t) => t,
                Err(e) => {
                    log(&format!("listener {name}: {e}"));
                    return ExitCode::from(EX_OSERR);
                }
            };
            let addr = tl.local_addr().map(|a| a.to_string()).unwrap_or_default();
            tokio::spawn(accept_tcp(shared.clone(), tl, kind));
            addr
        };
        descs.push(desc);
        offers.push(offer);
        let _ = auditor.admin(
            "listener.start",
            name,
            Outcome::Applied,
            hash,
            &[("addr", text(&addr)), ("takeover", DetailValue::Bool(child))],
        );
    }
    drop(sockets); // the accept tasks and `offers` hold their own duplicates
    if let AdminBind::Unix(path) = &admin_bind {
        let _ = std::fs::remove_file(path);
        match UnixListener::bind(path) {
            Ok(u) => {
                tokio::spawn(accept_unix(shared.clone(), u, fips.clone()));
                let _ = auditor.admin(
                    "listener.start",
                    ADMIN_NAME,
                    Outcome::Applied,
                    hash,
                    &[("addr", text(&admin_bind.to_string()))],
                );
            }
            Err(e) => {
                log(&format!("bind admin {admin_bind}: {e}"));
                return ExitCode::from(EX_OSERR);
            }
        }
    }
    let notifier = Notifier::from_env();
    if let Some(t) = takeover {
        let main = t.ready(HANDOVER_TIMEOUT);
        let sh = shared.clone();
        std::thread::spawn(move || {
            if let Some(f) = main.wait_done(Duration::from_secs(120)) {
                sh.registry.upgrade_forced_closes.add(f);
            }
        });
    }
    let _ = notifier.ready();
    log(&format!(
        "serving {} listener(s), admin {admin_bind}, config {} (generation {}), audit {}",
        snap.plan.listeners.len(),
        cfg.config_hash_hex(),
        generation.0,
        auditor.dir.display()
    ));
    drop(snap);
    let mut ctl = Ctl { opts, exe, store, shared, srv, auditor, tls, certs, notifier, descs, offers, ring, workers };
    loop {
        match signals.wait() {
            Ok(Sig::Hup) => ctl.reload(),
            Ok(Sig::Usr2) => {
                if ctl.upgrade() {
                    return ExitCode::SUCCESS;
                }
            }
            Ok(Sig::Term) if ctl.shared.mutants.no_drain => {
                log("SIGTERM ignored (negative control no-drain)"); // e2e-mutants only
            }
            Ok(Sig::Term) => {
                ctl.terminate();
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                log(&format!("sigwait: {e}"));
                return ExitCode::from(EX_OSERR);
            }
        }
    }
}
