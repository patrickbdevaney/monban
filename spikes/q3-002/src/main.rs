//! q3-002 ipchop: round-trip cost of one out-of-process adapter hop (R-MOD-1) with postcard frames.
//! Port of research/state/raw/round-003/02-bench (treated as untrusted; re-written, only the UDS/pipe + postcard
//! path kept). Client = this process; server = a re-exec of this binary over an inherited socketpair or pipe pair.
//! Each side pins itself with sched_setaffinity, so "same" = both on one core, "cross" = two cores.
//!
//!   ipchop run --transport uds|pipe --client-core C --server-core S --size BYTES --n N --label L
//!
//! Output: one JSON line per run (p50/p90/p99/max/mean RTT ns, calls/s with one call in flight, and CPU µs per call
//! for client and server from getrusage).
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::time::Instant;

#[derive(Serialize, Deserialize)]
struct Req<'a> {
    op: u8,
    seq: u64,
    #[serde(borrow, with = "serde_bytes")]
    body: &'a [u8],
}
#[derive(Serialize, Deserialize)]
struct Resp<'a> {
    seq: u64,
    status: u8,
    #[serde(borrow, with = "serde_bytes")]
    body: &'a [u8],
}

fn frame<T: Serialize>(v: &T, buf: &mut Vec<u8>) {
    buf.clear();
    buf.extend_from_slice(&[0; 4]);
    let b = postcard::to_extend(v, std::mem::take(buf)).unwrap();
    *buf = b;
    let l = (buf.len() - 4) as u32;
    buf[..4].copy_from_slice(&l.to_le_bytes());
}
fn read_frame<R: Read>(s: &mut R, buf: &mut Vec<u8>) -> bool {
    let mut h = [0u8; 4];
    if s.read_exact(&mut h).is_err() {
        return false;
    }
    buf.resize(u32::from_le_bytes(h) as usize, 0);
    s.read_exact(buf).is_ok()
}

fn pin(core: usize) {
    // SAFETY: cpu_set_t is plain data; sched_setaffinity on self with a valid set.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(core, &mut set);
        assert_eq!(libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set), 0);
    }
}
fn rusage(who: i32) -> u64 {
    // SAFETY: valid out-pointer.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(who, &mut ru) };
    let tv = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
    tv(ru.ru_utime) + tv(ru.ru_stime)
}
fn nocloexec(fd: i32) {
    // SAFETY: fcntl on an fd we own.
    unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
}

/// Server: echo adapter (op 1 echoes the body, op 255 stops), like the round-3 `echoN` cases.
fn serve(rfd: i32, wfd: i32, core: usize) {
    pin(core);
    // SAFETY: fds were inherited from the parent and are owned by this process from here on.
    let mut r = unsafe { File::from_raw_fd(rfd) };
    let mut w = if wfd == rfd { r.try_clone().unwrap() } else { unsafe { File::from_raw_fd(wfd) } };
    let (mut rb, mut ob, mut wb) = (Vec::new(), Vec::new(), Vec::new());
    while read_frame(&mut r, &mut rb) {
        let q: Req = postcard::from_bytes(&rb).unwrap();
        if q.op == 255 {
            break;
        }
        ob.clear();
        if q.op == 1 {
            ob.extend_from_slice(q.body);
        }
        frame(&Resp { seq: q.seq, status: 0, body: &ob }, &mut wb);
        if w.write_all(&wb).is_err() {
            break;
        }
    }
}

fn arg(a: &[String], k: &str, d: &str) -> String {
    a.iter().position(|x| x == k).and_then(|i| a.get(i + 1)).cloned().unwrap_or_else(|| d.to_string())
}

fn run(a: &[String]) {
    let tr = arg(a, "--transport", "uds");
    let cc: usize = arg(a, "--client-core", "0").parse().unwrap();
    let sc: usize = arg(a, "--server-core", "0").parse().unwrap();
    let size: usize = arg(a, "--size", "64").parse().unwrap();
    let n: usize = arg(a, "--n", "20000").parse().unwrap();
    let label = arg(a, "--label", "");
    pin(cc);
    let exe = std::env::current_exe().unwrap();
    // (client read fd, client write fd, server read fd, server write fd)
    let (crf, cwf, srf, swf) = if tr == "uds" {
        let mut fds = [0i32; 2];
        // SAFETY: valid out array of 2 fds.
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()) }, 0);
        (fds[0], fds[0], fds[1], fds[1])
    } else {
        let (mut p1, mut p2) = ([0i32; 2], [0i32; 2]);
        // SAFETY: valid out arrays.
        unsafe {
            assert_eq!(libc::pipe2(p1.as_mut_ptr(), libc::O_CLOEXEC), 0);
            assert_eq!(libc::pipe2(p2.as_mut_ptr(), libc::O_CLOEXEC), 0);
        }
        // p1: client -> server, p2: server -> client
        (p2[0], p1[1], p1[0], p2[1])
    };
    nocloexec(srf);
    nocloexec(swf);
    let mut child = std::process::Command::new(exe)
        .args(["serve", &srf.to_string(), &swf.to_string(), &sc.to_string()])
        .spawn()
        .unwrap();
    // SAFETY: closing the server's ends in the parent; fds are valid and not used again here.
    unsafe {
        libc::close(srf);
        if swf != srf {
            libc::close(swf);
        }
    }
    let mut r = unsafe { File::from_raw_fd(crf) };
    let mut w = if cwf == crf { r.try_clone().unwrap() } else { unsafe { File::from_raw_fd(cwf) } };
    let body: Vec<u8> = (0..size as u32).map(|i| (i * 7) as u8).collect();
    let (mut wb, mut rb) = (Vec::new(), Vec::new());
    let mut seq = 0u64;
    let mut call = |r: &mut File, w: &mut File| {
        seq += 1;
        frame(&Req { op: 1, seq, body: &body }, &mut wb);
        w.write_all(&wb).unwrap();
        assert!(read_frame(r, &mut rb));
        let p: Resp = postcard::from_bytes(&rb).unwrap();
        assert_eq!(p.seq, seq);
        assert_eq!(p.body.len(), size);
    };
    for _ in 0..(n / 10).max(300) {
        call(&mut r, &mut w);
    }
    let mut lat = Vec::with_capacity(n);
    let (cu0, t0) = (rusage(libc::RUSAGE_SELF), Instant::now());
    for _ in 0..n {
        let s = Instant::now();
        call(&mut r, &mut w);
        lat.push(s.elapsed().as_nanos() as u64);
    }
    let tot = t0.elapsed().as_secs_f64();
    let cu = rusage(libc::RUSAGE_SELF) - cu0;
    frame(&Req { op: 255, seq: 0, body: &[] }, &mut wb);
    let _ = w.write_all(&wb);
    drop(w);
    let _ = child.wait();
    let su = rusage(libc::RUSAGE_CHILDREN); // whole child lifetime incl. warm-up; reported per measured+warm call
    lat.sort_unstable();
    let p = |q: f64| lat[((lat.len() as f64 * q) as usize).min(lat.len() - 1)];
    let mean = lat.iter().sum::<u64>() as f64 / n as f64;
    let total_calls = n + (n / 10).max(300);
    println!(
        "{{\"kind\":\"lat\",\"label\":\"{label}\",\"transport\":\"{tr}-postcard\",\"client_core\":{cc},\"server_core\":{sc},\"size\":{size},\"n\":{n},\"p50_ns\":{},\"p90_ns\":{},\"p99_ns\":{},\"max_ns\":{},\"mean_ns\":{mean:.0},\"calls_per_s\":{:.0},\"client_cpu_us_per_call\":{:.3},\"server_cpu_us_per_call\":{:.3},\"loadavg\":\"{}\"}}",
        p(0.5),
        p(0.9),
        p(0.99),
        lat[lat.len() - 1],
        n as f64 / tot,
        cu as f64 / n as f64,
        su as f64 / total_calls as f64,
        std::fs::read_to_string("/proc/loadavg").unwrap_or_default().trim()
    );
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(|s| s.as_str()) {
        Some("serve") => serve(a[2].parse().unwrap(), a[3].parse().unwrap(), a[4].parse().unwrap()),
        Some("run") => run(&a),
        _ => eprintln!("usage: ipchop run --transport uds|pipe --client-core C --server-core S --size B --n N"),
    }
}
