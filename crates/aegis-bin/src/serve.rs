//! The serving process: boot (fail closed), listeners, the control thread (SIGHUP reload, SIGUSR2 upgrade,
//! SIGTERM drain), sd-notify.
//!
//! Boot order: block lifecycle signals (before any thread exists) → read + validate config (CFG-1/2, exit 78) →
//! plan (exit 78) → certificates + TLS profiles (exit 78) → audit log (exit 78) → audit `config.apply` durably
//! (fail closed, Audit I7) → bind (or take over from the upgrading parent, F11) → accept → READY.

use std::net::TcpListener as StdTcpListener;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use aegis_audit::{DetailValue, Outcome};
use aegis_canon::Scheme;
use aegis_config::{ConfigStore, MAX_CONFIG_BYTES};
use aegis_ops::fdcheck::describe_tcp;
use aegis_ops::handover::{self, LeakPolicy, Offered, ParentConfig, ParentHooks};
use aegis_ops::notify::Notifier;
use aegis_ops::signals::{Sig, Signals};
use aegis_ops::stek::StekRing;
use aegis_ops::wire::ListenerDesc;
use aegis_transport::TlsAcceptor;
use tokio::net::{TcpListener, UnixListener};
use tokio::time::timeout;

use crate::audit::{Auditor, text};
use crate::cli::ServeOpts;
use crate::h1in::ConnMeta;
use crate::plan::{AdminBind, Plan, Snapshot, plan};
use crate::shared::{ConnGuard, Peer, Shared, bump};
use crate::tls::{CertPaths, Tls};
use crate::util::{Either, race};

pub const EX_CONFIG: u8 = 78;
const EX_SOFTWARE: u8 = 70;
const EX_OSERR: u8 = 71;
const EX_IOERR: u8 = 74;
/// UP-4 drain deadline D (upgrade and SIGTERM).
const DRAIN_DEADLINE: Duration = Duration::from_secs(10);
const HANDOVER_TIMEOUT: Duration = Duration::from_secs(10);
/// Handover name of the admin listener (cannot collide: F8 listener names have no '.').
const ADMIN_NAME: &str = "admin.ctl";

fn log(msg: &str) {
    eprintln!("aegis[{}]: {msg}", std::process::id());
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

static CONN_IDS: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
enum Kind {
    Public(TlsAcceptor),
    Admin(Arc<aegis_tls::FipsStatus>),
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
                    Kind::Public(acc) => {
                        tokio::spawn(public_conn(shared, sock, addr, acc.clone()));
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

async fn accept_unix(shared: Arc<Shared>, l: UnixListener, fips: Arc<aegis_tls::FipsStatus>) {
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

async fn public_conn(shared: Arc<Shared>, sock: tokio::net::TcpStream, addr: std::net::SocketAddr, acc: TlsAcceptor) {
    let _g = ConnGuard::new(&shared);
    let _ = sock.set_nodelay(true);
    let stall = Duration::from_millis(shared.snapshot().plan.wl.stall_timeout_ms);
    let Ok(Ok(tls)) = timeout(stall, acc.accept(sock)).await else { return };
    let (_, sc) = tls.get_ref();
    let meta = ConnMeta {
        scheme: Scheme::Https,
        sni: sc.server_name().map(|s| s.as_bytes().to_vec()),
        peer: Peer::new(Some(addr), CONN_IDS.fetch_add(1, Ordering::Relaxed)),
    };
    if sc.alpn_protocol() == Some(b"h2") {
        crate::h2in::serve(shared, tls, meta).await;
    } else {
        crate::h1in::serve(shared, tls, meta).await;
    }
}

/// Upgrade hooks: the parent stops accepting and drains (UP-1/UP-4).
struct Hooks {
    shared: Arc<Shared>,
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
        drain(&self.shared, deadline)
    }
}

fn drain(shared: &Shared, deadline: Duration) -> u64 {
    shared.draining.store(true, Ordering::Release);
    shared.drain_notify.notify_waiters();
    let until = Instant::now() + deadline;
    while shared.live_conns.load(Ordering::Acquire) > 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
        shared.drain_notify.notify_waiters();
    }
    u64::try_from(shared.live_conns.load(Ordering::Acquire)).unwrap_or(u64::MAX)
}

struct Ctl {
    opts: ServeOpts,
    exe: PathBuf,
    store: ConfigStore,
    shared: Arc<Shared>,
    auditor: Auditor,
    tls: Tls,
    certs: CertPaths,
    notifier: Notifier,
    descs: Vec<ListenerDesc>,
    offers: Vec<StdTcpListener>,
    ring: StekRing,
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

    /// CFG-3: a load that fails leaves the served config untouched and counts a last-known-good fallback.
    fn fallback(&self, action: &str, why: &str) {
        log(&format!("config reload refused: {why}; last-known-good keeps serving"));
        if self.shared.mutants.skip_lkg {
            // NEGATIVE CONTROL: drop the served config instead of keeping the last-known-good.
            #[cfg(feature = "e2e-mutants")]
            self.shared.install(self.shared.snapshot().empty());
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
                    if p.same_sockets(&cur.plan) {
                        Ok(p)
                    } else {
                        Err("listener or admin change: use the zero-downtime upgrade (SIGUSR2) after editing".into())
                    }
                });
                match candidate {
                    Err(e) => {
                        let _ = self.store.rollback();
                        self.fallback("config.rollback", &e);
                    }
                    Ok(p) => {
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
                            self.shared.install(Snapshot::new(generation.0, epoch, hash, p));
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
        let mut hooks = Hooks { shared: self.shared.clone() };
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
        let _ = self.notifier.stopping();
        self.shared.stop_accept.store(true, Ordering::Release);
        self.shared.stop_notify.notify_waiters();
        self.offers.clear();
        let forced = drain(&self.shared, DRAIN_DEADLINE);
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
    let certs = match CertPaths::resolve(opts.cert.as_deref(), opts.key.as_deref()) {
        Ok(c) => c,
        Err(e) => return fail_closed(&e),
    };
    let tls = match Tls::build(&p.listeners, &certs) {
        Ok(t) => t,
        Err(e) => return fail_closed(&e),
    };
    let Some(audit_base) = opts.audit_dir.clone().or_else(Auditor::default_dir) else {
        return fail_closed("no audit directory (--audit-dir or StateDirectory=); admin events fail closed");
    };
    let auditor = match Auditor::open(&audit_base, &tls.fips) {
        Ok(a) => a,
        Err(e) => return fail_closed(&e),
    };
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            log(&format!("current_exe: {e}"));
            return ExitCode::from(EX_OSERR);
        }
    };
    let hash = cfg.config_hash();
    let admin_bind = p.admin.clone();
    let shared = Shared::new(Snapshot::new(generation.0, 1, hash, p));
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
    let rt = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
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
        let (desc, offer, tl) = match (|| -> std::io::Result<_> {
            let desc = describe_tcp(name, l)?;
            let offer = l.try_clone()?;
            let mine = l.try_clone()?;
            mine.set_nonblocking(true)?;
            Ok((desc, offer, TcpListener::from_std(mine)?))
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
            match tls.acceptors.iter().find(|(n, _)| n == name) {
                Some((_, a)) => Kind::Public(a.clone()),
                None => return fail_closed(&format!("no TLS acceptor for listener {name}")),
            }
        };
        let addr = tl.local_addr().map(|a| a.to_string()).unwrap_or_default();
        tokio::spawn(accept_tcp(shared.clone(), tl, kind));
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
    let mut ctl = Ctl { opts, exe, store, shared, auditor, tls, certs, notifier, descs, offers, ring };
    loop {
        match signals.wait() {
            Ok(Sig::Hup) => ctl.reload(),
            Ok(Sig::Usr2) => {
                if ctl.upgrade() {
                    return ExitCode::SUCCESS;
                }
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
