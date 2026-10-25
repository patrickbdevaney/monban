//! upgrade-subject: tiny HTTP/1.1 server for `oracles/upgrade-harness`.
//!
//! ```text
//! upgrade-subject --listen 127.0.0.1:8080 [--listen 127.0.0.1:8081 ...] --pidfile /path/pid [--drain-ms 2000]
//!                 [--handover-ms 5000] [--runtime-dir DIR]
//! ```
//! `--listen` may repeat (1..=`MAX_HANDOVER_LISTENERS` listeners, served by one accept thread each).
//! SIGHUP or SIGUSR2: re-exec itself as the upgrade child through `aegis_ops::handover` (every listener handed over
//! by SCM_RIGHTS on the handover socket, never a second SO_REUSEPORT bind). The pidfile is (re)written atomically by
//! whichever process currently owns the listeners, once the handover is complete. SIGTERM/SIGINT: drain and exit.
//! Every response is `200 OK` with body `ok <pid>\n`; keep-alive is honoured until the drain starts.
#![forbid(unsafe_code)]

use aegis_ops::drain::{ConnGuard, ConnTracker, accept_loop};
use aegis_ops::fdcheck::describe_tcp;
use aegis_ops::handover::{self, LeakPolicy, MAX_HANDOVER_LISTENERS, Offered, ParentConfig, ParentHooks};
use aegis_ops::notify::Notifier;
use aegis_ops::signals::{Sig, Signals};
use aegis_ops::stek::StekRing;
use aegis_ops::wire::ListenerDesc;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const MAX_HEADER: usize = 8 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const TICK: Duration = Duration::from_millis(50);

#[derive(Debug, Clone)]
struct Opts {
    listen: Vec<String>,
    pidfile: PathBuf,
    drain: Duration,
    handover: Duration,
    runtime_dir: PathBuf,
}

fn parse_opts(args: &[OsString]) -> Result<Opts, String> {
    let mut listen = Vec::new();
    let mut pidfile = None;
    let mut drain = Duration::from_millis(2000);
    let mut handover = Duration::from_millis(5000);
    let mut runtime_dir = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    let mut it = args.iter();
    let ms = |v: Option<&OsString>| -> Result<Duration, String> {
        v.and_then(|s| s.to_str()).and_then(|s| s.parse::<u64>().ok()).map(Duration::from_millis).ok_or("bad ms".into())
    };
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("--listen") => {
                listen.push(it.next().and_then(|s| s.to_str()).map(str::to_string).ok_or("bad --listen")?)
            }
            Some("--pidfile") => pidfile = it.next().map(PathBuf::from),
            Some("--drain-ms") => drain = ms(it.next())?,
            Some("--handover-ms") => handover = ms(it.next())?,
            Some("--runtime-dir") => runtime_dir = it.next().map(PathBuf::from).ok_or("bad dir")?,
            _ => return Err(format!("unknown argument {a:?}")),
        }
    }
    if listen.is_empty() || listen.len() > MAX_HANDOVER_LISTENERS {
        return Err(format!("--listen required, 1..={MAX_HANDOVER_LISTENERS} times"));
    }
    Ok(Opts { listen, pidfile: pidfile.ok_or("--pidfile required")?, drain, handover, runtime_dir })
}

fn log(msg: &str) {
    eprintln!("upgrade-subject[{}]: {msg}", std::process::id());
}

fn write_pidfile(p: &Path) -> io::Result<()> {
    let tmp = p.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, format!("{}\n", std::process::id()))?;
    std::fs::rename(&tmp, p)
}

/// Serve one connection: HTTP/1.1 requests without bodies, keep-alive until the drain starts.
fn handle(mut s: TcpStream, tracker: &ConnTracker, guard: ConnGuard) {
    let _guard = guard;
    let _ = s.set_read_timeout(Some(TICK));
    let _ = s.set_nodelay(true);
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let mut idle_since = Instant::now();
    let mut served = 0u64;
    loop {
        // Serve every complete request in the buffer.
        while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(buf.get(..end).unwrap_or_default()).to_ascii_lowercase();
            buf.drain(..end + 4);
            let client_close = head.lines().any(|l| l.starts_with("connection:") && l.contains("close"));
            let close = client_close || tracker.is_draining();
            let body = format!("ok {}\n", std::process::id());
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: {}\r\n\r\n{body}",
                body.len(),
                if close { "close" } else { "keep-alive" }
            );
            if s.write_all(resp.as_bytes()).is_err() || close {
                return;
            }
            served += 1;
            idle_since = Instant::now();
        }
        if buf.len() > MAX_HEADER {
            let _ = s.write_all(
                b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            );
            return;
        }
        match s.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => buf.extend_from_slice(chunk.get(..n).unwrap_or_default()),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                // Phase 1 of the drain: an idle keep-alive connection (no partial request, at least one response
                // already sent) is closed. A connection accepted just before the listener closed whose first
                // request has not arrived yet is not idle: closing it would drop that request (EOF before any
                // response); it is served, bounded by the drain deadline and IDLE_TIMEOUT.
                let keepalive_idle = tracker.is_draining() && buf.is_empty() && served > 0;
                if keepalive_idle || idle_since.elapsed() > IDLE_TIMEOUT {
                    return;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

struct Server {
    stop: Arc<AtomicBool>,
    accept: Vec<JoinHandle<()>>,
    tracker: ConnTracker,
}

impl Server {
    /// One accept thread per listener; all share the stop flag and the connection tracker.
    fn start(ls: Vec<TcpListener>, tracker: ConnTracker) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let accept = ls.into_iter().map(|l| Self::spawn_accept(l, stop.clone(), tracker.clone())).collect();
        Self { stop, accept, tracker }
    }

    fn spawn_accept(l: TcpListener, st: Arc<AtomicBool>, tr: ConnTracker) -> JoinHandle<()> {
        std::thread::spawn(move || {
            let r = accept_loop(l, &st, TICK, |s| {
                // Register before handing off, so a drain can never miss a connection that is accepted but whose
                // thread has not started yet (that connection would be reset at process exit).
                let Ok(guard) = tr.register(&s) else { return };
                let tr = tr.clone();
                // A thread per connection; if spawning fails the stream is dropped (counted by the harness).
                let _ = std::thread::Builder::new().spawn(move || handle(s, &tr, guard));
            });
            if let Err(e) = r {
                log(&format!("accept loop error: {e}"));
            }
        })
    }
}

impl ParentHooks for Server {
    fn close_listeners(&mut self) {
        self.stop.store(true, Ordering::Release);
        for h in self.accept.drain(..) {
            let _ = h.join(); // each accept thread drops its listener fd on exit
        }
    }
    fn drain(&mut self, deadline: Duration) -> u64 {
        let r = self.tracker.drain(deadline);
        log(&format!("drained in {:?}, forced closes {}", r.elapsed, r.forced));
        r.forced
    }
}

fn run() -> Result<(), String> {
    // Block lifecycle signals before any thread exists so only sigwait sees them.
    let signals = Signals::block().map_err(|e| format!("block signals: {e}"))?;
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let opts = parse_opts(&args)?;
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let notifier = Notifier::from_env();
    let tracker = ConnTracker::new();

    let (listeners, mut ring, takeover) = if handover::is_upgrade_child() {
        let mut t = handover::child_takeover([0; 32], opts.handover, LeakPolicy::Refuse).map_err(|e| e.to_string())?;
        let ls: Vec<TcpListener> = t.listeners.drain(..).map(|(_, l)| l).collect();
        if ls.len() != opts.listen.len() {
            return Err(format!("claimed {} listeners, expected {}", ls.len(), opts.listen.len()));
        }
        let ring = t.stek.clone();
        (ls, ring, Some(t))
    } else {
        let mut ls = Vec::new();
        for a in &opts.listen {
            ls.push(TcpListener::bind(a).map_err(|e| format!("bind {a}: {e}"))?);
        }
        (ls, StekRing::generate().map_err(|e| format!("stek: {e}"))?, None)
    };
    let mut descs: Vec<ListenerDesc> = Vec::new();
    // This process's handles for offering the listeners to a future child; the accept threads own the others.
    let mut offers: Vec<TcpListener> = Vec::new();
    for (i, l) in listeners.iter().enumerate() {
        descs.push(describe_tcp(&format!("http{i}"), l).map_err(|e| e.to_string())?);
        offers.push(l.try_clone().map_err(|e| e.to_string())?);
    }
    let mut server = Server::start(listeners, tracker);

    if let Some(t) = takeover {
        let main = t.ready(opts.handover);
        log(&format!("took over {} listeners; parent drain deadline {:?} ms", descs.len(), main.drain_deadline_ms));
        std::thread::spawn(move || {
            if let Some(f) = main.wait_done(Duration::from_secs(120)) {
                log(&format!("parent done, forced closes {f}"));
            }
        });
    }
    write_pidfile(&opts.pidfile).map_err(|e| format!("pidfile: {e}"))?;
    let _ = notifier.ready();

    let cfg = ParentConfig {
        exe,
        args,
        runtime_dir: opts.runtime_dir.clone(),
        handover_timeout: opts.handover,
        drain_deadline: opts.drain,
        require_cloexec: true,
        notifier,
    };
    loop {
        match signals.wait().map_err(|e| format!("sigwait: {e}"))? {
            Sig::Hup | Sig::Usr2 => {
                ring.epoch = ring.epoch.wrapping_add(1);
                let offered: Vec<Offered<'_>> =
                    descs.iter().zip(&offers).map(|(d, o)| Offered { desc: d, fd: o.as_fd() }).collect();
                match handover::upgrade(&cfg, &offered, &ring, &mut server) {
                    Ok(h) => {
                        log(&format!("handed over to {}, forced closes {}", h.child_pid, h.forced));
                        return Ok(());
                    }
                    Err(e) => log(&format!("{e}; still serving")),
                }
            }
            Sig::Term => {
                let _ = notifier.stopping();
                server.close_listeners();
                drop(offers);
                let forced = server.drain(opts.drain);
                log(&format!("terminated, forced closes {forced}"));
                return Ok(());
            }
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log(&e);
            ExitCode::FAILURE
        }
    }
}
