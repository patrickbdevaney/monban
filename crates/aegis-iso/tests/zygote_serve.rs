//! The zygote loop and the supervisor spawn path on the real kernel (PLAN-5 D1, D5, D6, D8).
//!
//! `zygote::serve` needs a single-threaded, sandboxed process. A libtest process has several threads, so the test
//! forks: the forked child has exactly one thread, installs `Profile::zygote` and serves; the test thread is the
//! client and ends the zygote with SIGKILL to its explicit pid. The supervisor test spawns `/bin/sh` workers through
//! `supervisor::spawn`, the path aegis-bin uses for aegis-p2.
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use aegis_iso::sandbox::{self, Forked, Profile, install};
use aegis_iso::supervisor::{self, Event, Supervised, WorkerCmd};
use aegis_iso::zygote::{self, Spec};

/// Handler state the zygote never touches; a fork child starts from the zygote's copy every time.
static SERVED_IN_THIS_PROCESS: AtomicU32 = AtomicU32::new(0);

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("aegis-iso-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The zygote: runs in the forked, single-threaded child. Never returns.
fn zygote_main(listener: OwnedFd, allow: PathBuf) -> ! {
    if install(&Profile::zygote(vec![allow])).is_err() {
        sandbox::exit_now(92);
    }
    let handler = |conn: OwnedFd| -> i32 {
        let mut s = UnixStream::from(conn);
        let mut b = [0u8; 1];
        if s.read_exact(&mut b).is_err() {
            return 3;
        }
        let n = SERVED_IN_THIS_PROCESS.fetch_add(1, Ordering::SeqCst) + 1;
        match b {
            [b'A'] => std::process::abort(),
            [b'L'] => loop {
                std::hint::spin_loop();
            },
            _ => {}
        }
        let msg = format!("{} {} {}", std::process::id(), std::os::unix::process::parent_id(), n);
        let _ = s.write_all(msg.as_bytes());
        0
    };
    let _ = zygote::serve(listener, Spec::fork_per_connection(Duration::from_millis(200)), handler);
    sandbox::exit_now(93)
}

fn ask(path: &Path, b: u8) -> Option<String> {
    let mut s = UnixStream::connect(path).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    s.write_all(&[b]).ok()?;
    let mut out = String::new();
    s.read_to_string(&mut out).ok()?;
    Some(out)
}

fn landlock_ok() -> bool {
    sandbox::landlock::abi().is_some_and(|a| a >= sandbox::landlock::MIN_ABI)
}

#[test]
fn zygote_forks_a_fresh_sandboxed_child_per_connection_and_survives_faults() {
    if !landlock_ok() {
        eprintln!("skipped: Landlock ABI >= 4 unavailable on this host");
        return;
    }
    let dir = scratch("zygote");
    let sock = dir.join("z.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let zpid = match sandbox::fork().unwrap() {
        Forked::Child => zygote_main(OwnedFd::from(listener), dir.clone()),
        Forked::Parent(p) => u32::try_from(p).unwrap(),
    };
    drop(listener);
    let mut pids = std::collections::BTreeSet::new();
    for _ in 0..20 {
        let r = ask(&sock, b'h').unwrap();
        let v: Vec<u32> = r.split(' ').filter_map(|x| x.parse().ok()).collect();
        assert_eq!(v.len(), 3, "reply {r:?}");
        assert_eq!(v[1], zpid, "every request is served by a child of the zygote");
        assert_eq!(v[2], 1, "each child starts from the zygote's state: no request saw another's");
        assert_ne!(v[0], zpid, "the zygote never runs the handler");
        assert!(pids.insert(v[0]), "a fresh process per connection");
    }
    // A child that aborts loses only its own connection.
    assert_eq!(ask(&sock, b'A').unwrap_or_default(), "");
    // A child that never returns is ended by ITIMER_REAL (200 ms), not by the client's 5 s timeout.
    let t = Instant::now();
    assert_eq!(ask(&sock, b'L').unwrap_or_default(), "");
    let waited = t.elapsed();
    assert!(waited < Duration::from_secs(2), "wall bound did not fire: {waited:?}");
    assert!(ask(&sock, b'h').is_some_and(|r| !r.is_empty()), "zygote serves after faults");
    // The zygote is still the same, live process.
    let pid = rustix::process::Pid::from_raw(i32::try_from(zpid).unwrap()).unwrap();
    assert!(rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG).unwrap().is_none());
    rustix::process::kill_process(pid, rustix::process::Signal::KILL).unwrap();
    let st = rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty()).unwrap();
    assert!(st.is_some_and(|(_, s)| s.terminating_signal() == Some(9)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn supervisor_execs_workers_with_the_listener_at_fd3_and_respawns_by_execve() {
    let dir = scratch("supervisor");
    let sock = dir.join("s.sock");
    let listener = OwnedFd::from(UnixListener::bind(&sock).unwrap());
    let ino = std::fs::metadata(format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&listener)))
        .map(|m| m.ino())
        .unwrap();
    let out = dir.join("fd3");
    // The worker records the inode behind its fd 3 and the AEGIS_P2_* environment, then stays up.
    let script = format!("stat -L -c %i /proc/$$/fd/3 > {o}.$$; env > {o}.env.$$; exec sleep 30", o = out.display());
    let mut cmd = WorkerCmd::new(PathBuf::from("/bin/sh"), vec![supervisor::arg("-c"), supervisor::arg(&script)]);
    cmd.env =
        supervisor::passthrough_env([("AEGIS_P2_MUTANT".into(), "x".into()), ("HOME".into(), "/nonexistent".into())]);
    let mut sup = Supervised::start(cmd, listener).unwrap();
    let first = sup.pid();
    let read = |pid: u32, suffix: &str| -> String {
        let p = PathBuf::from(format!("{}{suffix}.{pid}", out.display()));
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(5) {
            if let Ok(s) = std::fs::read_to_string(&p)
                && !s.is_empty()
            {
                return s;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        String::new()
    };
    assert_eq!(read(first, "").trim(), ino.to_string(), "fd 3 of the worker is the supervisor's listener");
    let env = read(first, ".env");
    assert!(env.lines().any(|l| l == "AEGIS_P2_MUTANT=x"), "{env}");
    assert!(!env.lines().any(|l| l.starts_with("HOME=")), "only AEGIS_P2_* passes: {env}");
    assert!(matches!(sup.check().unwrap(), Event::Running));
    sup.kill().unwrap();
    let ev = sup.check().unwrap();
    assert!(matches!(ev, Event::Respawned { .. }), "{ev:?}");
    assert_ne!(sup.pid(), first, "replacement is a new process");
    assert_eq!(read(sup.pid(), "").trim(), ino.to_string(), "the replacement inherits the same listener");
    assert_eq!(sup.respawns(), 1);
    let _ = sup.listener().as_fd();
    drop(sup.shutdown());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn only_aegis_p2_variables_pass_through() {
    let vars = [("PATH", "/bin"), ("AEGIS_P2_MUTANT", "x"), ("HOME", "/root"), ("AEGIS_P2_TEST_LANDLOCK_ABI", "3")]
        .map(|(k, v)| (k.into(), v.into()));
    let got = supervisor::passthrough_env(vars);
    let keys: Vec<String> = got.iter().map(|(k, _)| k.to_string_lossy().into_owned()).collect();
    assert_eq!(keys, ["AEGIS_P2_MUTANT", "AEGIS_P2_TEST_LANDLOCK_ABI"]);
}
