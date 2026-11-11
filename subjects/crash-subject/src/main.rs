//! crash-subject: the monban-state durable store over the crash-harness subject protocol
//! (`oracles/crash-harness/README.md`, "Subject protocol").
//!
//! Usage: `crash-subject <dir> [--ack-early] [--no-dirsync] [--no-mode-recheck]`
//!
//! The store is opened (with its INV-DURABLE bootstrap) at start; `READY` is printed only after that. Self-test
//! mutations: `--ack-early` replies `OK` before the commit runs; `--no-dirsync` skips the bootstrap directory
//! fsyncs; `--no-mode-recheck` skips the q2-007 journal_mode/synchronous re-read after the first write.
//! Every reply goes out as one write(2) on fd 1 (the tracer turns `OK <i>` / `BEGUN <i>` into ack markers): a
//! newline-terminated buffer written through `Stdout`'s line writer bypasses its buffer.
#![forbid(unsafe_code)]

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use monban_state::store::CrashMutations;
use monban_state::{CrashSubject, Store};

const MUTATIONS: &str = "ack-early,no-dirsync,no-mode-recheck";

fn reply(line: &str) -> Result<(), ()> {
    let mut b = Vec::with_capacity(line.len() + 1);
    b.extend_from_slice(line.as_bytes());
    b.push(b'\n');
    let out = std::io::stdout();
    let mut lock = out.lock();
    lock.write_all(&b).and_then(|()| lock.flush()).map_err(|_| ())
}

fn one_line(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes().chunks(2).map(|p| std::str::from_utf8(p).ok().and_then(|t| u8::from_str_radix(t, 16).ok())).collect()
}

fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        for n in [x >> 4, x & 0x0f] {
            if let Some(c) = D.get(usize::from(n)) {
                s.push(char::from(*c));
            }
        }
    }
    s
}

struct Args {
    dir: PathBuf,
    ack_early: bool,
    muts: CrashMutations,
}

fn parse_args() -> Result<Args, String> {
    let mut dir = None;
    let mut a = Args { dir: PathBuf::new(), ack_early: false, muts: CrashMutations::NONE };
    for x in std::env::args().skip(1) {
        match x.as_str() {
            "--ack-early" => a.ack_early = true,
            "--no-dirsync" => a.muts.no_dirsync = true,
            "--no-mode-recheck" => a.muts.no_mode_recheck = true,
            s if s.starts_with("--") => return Err(format!("unknown flag {s}")),
            s if dir.is_none() => dir = Some(PathBuf::from(s)),
            s => return Err(format!("unexpected argument {s}")),
        }
    }
    a.dir = dir.ok_or("usage: crash-subject <dir> [--ack-early] [--no-dirsync] [--no-mode-recheck]")?;
    Ok(a)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("crash-subject: {e}");
            return ExitCode::from(2);
        }
    };
    let opened = if args.muts == CrashMutations::NONE {
        <Store as CrashSubject>::open_bootstrap(&args.dir)
    } else {
        Store::open_with(&args.dir, args.muts)
    };
    let mut s = match opened {
        Ok(s) => s,
        Err(e) => {
            let _ = reply(&format!("ERR open {}", one_line(&e.to_string())));
            return ExitCode::from(3);
        }
    };
    if reply(&format!(
        "READY monban-state store sqlite={} mutations={MUTATIONS}",
        monban_state::store::sqlite_version()
    ))
    .is_err()
    {
        return ExitCode::from(4);
    }
    match serve(&mut s, args.ack_early) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => ExitCode::from(code),
    }
}

fn serve(s: &mut Store, ack_early: bool) -> Result<(), u8> {
    let mut puts: Vec<(u8, Vec<u8>, Vec<u8>)> = Vec::new();
    let mut poisoned = false;
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let mut it = line.split(' ');
        let r = match it.next().unwrap_or("") {
            "BEGIN" => {
                puts.clear();
                reply(&format!("BEGUN {}", it.next().unwrap_or("0")))
            }
            "PUT" => {
                let t: Option<u8> = it.next().and_then(|x| x.parse().ok()).filter(|t| *t < 2);
                match (t, it.next().and_then(unhex), it.next().and_then(unhex)) {
                    (Some(t), Some(k), Some(v)) => {
                        puts.push((t, k, v));
                        Ok(())
                    }
                    _ => {
                        let _ = reply("ERR proto bad PUT");
                        return Err(2);
                    }
                }
            }
            "COMMIT" => {
                let i = it.next().unwrap_or("0").to_string();
                let r = if poisoned {
                    reply(&format!("ERR {i} poisoned"))
                } else {
                    let early = if ack_early { reply(&format!("OK {i}")) } else { Ok(()) }; // MUTATION
                    match CrashSubject::commit(s, &puts) {
                        Ok(()) if ack_early => early,
                        Ok(()) => reply(&format!("OK {i}")),
                        Err(e) => {
                            poisoned = true; // fail-stop (the store is poisoned as well)
                            reply(&format!("ERR {i} {}", one_line(&e.to_string())))
                        }
                    }
                };
                puts.clear();
                r
            }
            "DUMP" => match CrashSubject::dump(s) {
                Ok(d) => {
                    let mut out = String::new();
                    for ((t, k), v) in d {
                        out.push_str(&format!("KV {t} {} {}\n", hex(&k), hex(&v)));
                    }
                    out.push_str("END");
                    reply(&out)
                }
                Err(e) => reply(&format!("ERR dump {}", one_line(&e.to_string()))),
            },
            "CHECK" => match s.check() {
                Ok(m) => reply(&format!("INTEGRITY ok {m}")),
                Err(e) => reply(&format!("INTEGRITY fail {}", one_line(&e.to_string()))),
            },
            "QUIT" => break,
            other => {
                let _ = reply(&format!("ERR proto unknown command {}", one_line(other)));
                return Err(2);
            }
        };
        if r.is_err() {
            return Err(4);
        }
    }
    Ok(())
}
