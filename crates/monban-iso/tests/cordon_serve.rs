//! The cordon serving loop on the real kernel (PLAN-5 D1, D5): one sandboxed process, several serving threads that
//! inherit the cordon sandbox, concurrent connections, and no fork at all.
//!
//! `cordon::serve` needs a process that installed `Profile::cordon` while single-threaded. A libtest process has
//! several threads, so the test forks: the forked child has one thread, installs the profile and serves; the test
//! thread is the client and ends the cordon with SIGKILL to its explicit pid.
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use monban_iso::cordon;
use monban_iso::sandbox::{self, Forked, Profile, install};
use rustix::process::{Pid, Signal, WaitOptions};

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("monban-iso-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn landlock_ok() -> bool {
    sandbox::landlock::abi().is_some_and(|a| a >= sandbox::landlock::MIN_ABI)
}

/// The cordon: runs in the forked, single-threaded child. Never returns.
fn cordon_main(listener: OwnedFd, allow: PathBuf) -> ! {
    if install(&Profile::cordon(vec![allow])).is_err() {
        sandbox::exit_now(92);
    }
    let handler = |conn: OwnedFd| {
        let mut s = UnixStream::from(conn);
        let mut b = [0u8; 1];
        if s.read_exact(&mut b).is_err() {
            return;
        }
        match b {
            // A cordon has no fork: the filter kills the whole process (SIGSYS).
            [b'F'] => {
                let _ = sandbox::fork();
            }
            [b'S'] => std::thread::sleep(Duration::from_millis(300)),
            _ => {}
        }
        let name = std::thread::current().name().unwrap_or("?").to_string();
        let _ = s.write_all(format!("{} {name}", std::process::id()).as_bytes());
    };
    let _ = cordon::serve(listener, 4, handler);
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

#[test]
fn a_cordon_serves_concurrently_in_one_sandboxed_process_and_cannot_fork() {
    if !landlock_ok() {
        eprintln!("skipped: Landlock ABI >= 4 unavailable on this host");
        return;
    }
    let dir = scratch("cordon");
    let sock = dir.join("c.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let cpid = match sandbox::fork().unwrap() {
        Forked::Child => cordon_main(OwnedFd::from(listener), dir.clone()),
        Forked::Parent(p) => p,
    };
    drop(listener);
    // Four slow requests at once complete in about one request's time: four serving threads, one process.
    let t = Instant::now();
    let hs: Vec<_> = (0..4)
        .map(|_| {
            let sock = sock.clone();
            std::thread::spawn(move || ask(&sock, b'S').unwrap_or_default())
        })
        .collect();
    let replies: Vec<String> = hs.into_iter().map(|h| h.join().unwrap()).collect();
    let took = t.elapsed();
    let mut threads = std::collections::BTreeSet::new();
    for r in &replies {
        let (pid, name) = r.split_once(' ').unwrap_or_else(|| panic!("reply {r:?}"));
        assert_eq!(pid, cpid.to_string(), "served by the cordon process itself");
        assert!(name.starts_with("monban-cordon-"), "{name}");
        threads.insert(name.to_string());
    }
    assert_eq!(threads.len(), 4, "four distinct serving threads: {replies:?}");
    assert!(took < Duration::from_millis(1100), "requests were serialized: {took:?}");
    // The cordon cannot fork: the filter kills the process with SIGSYS (no reply).
    assert_eq!(ask(&sock, b'F').unwrap_or_default(), "");
    let pid = Pid::from_raw(cpid).unwrap();
    let st = rustix::process::waitpid(Some(pid), WaitOptions::empty()).unwrap();
    let sig = st.and_then(|(_, s)| s.terminating_signal());
    if sig != Some(31) {
        let _ = rustix::process::kill_process(pid, Signal::KILL);
    }
    assert_eq!(sig, Some(31), "fork in a cordon must die by SIGSYS");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn serve_refuses_a_thread_count_outside_the_bounds() {
    let dir = scratch("cordon-bounds");
    let l = OwnedFd::from(UnixListener::bind(dir.join("b.sock")).unwrap());
    let e = cordon::serve(l, 0, |_c| {});
    assert_eq!(e.raw_os_error(), Some(libc_einval()));
    let _ = std::fs::remove_dir_all(&dir);
}

fn libc_einval() -> i32 {
    22
}
