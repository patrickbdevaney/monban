//! mariadb-subject: drives `monban-adapter-mysql` for oracles/lowering-read, lowering-write and schema-gate
//! (`--engine mariadb`) over JSON lines. Never linked into monban.
//!
//! * `mariadb-subject lowering [--mutant drop-tenant]`: lowering-read / lowering-write protocol v2, dialect
//!   `mariadb`, through the production renderer (`monban_adapter_mysql::lower`, see `lowering.rs`).
//! * `mariadb-subject schema`: schema-gate protocol v1, `mariadb` mode through live `information_schema`
//!   introspection (`monban_adapter_mysql::check_live_schema`, see `gate.rs`).
//!
//! Unknown ops, unreadable lines and over-long lines (1 MiB) get a refusal; the subject never guesses an accept.
#![forbid(unsafe_code)]

mod gate;
mod json;
mod lowering;

use std::io::{BufRead, Read, Write};
use std::process::ExitCode;

const MAX_LINE: u64 = 1 << 20;

/// Read JSON lines from stdin and write `handle(Some(line))` (or `handle(None)` for a line over 1 MiB) as one line
/// each to stdout, flushed. Blank lines are skipped. Exit 0 at EOF, 2 on an I/O error.
pub(crate) fn serve_lines(mut handle: impl FnMut(Option<&str>) -> String) -> ExitCode {
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut out = std::io::stdout().lock();
    loop {
        let mut buf = Vec::new();
        match (&mut input).take(MAX_LINE).read_until(b'\n', &mut buf) {
            Ok(0) => return ExitCode::SUCCESS,
            Ok(_) => {}
            Err(_) => return ExitCode::from(2),
        }
        let over = buf.last() != Some(&b'\n') && buf.len() as u64 >= MAX_LINE;
        if over {
            // Discard the rest of the over-long line.
            let mut sink = Vec::new();
            if input.read_until(b'\n', &mut sink).is_err() {
                return ExitCode::from(2);
            }
        }
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let reply = handle(if over { None } else { Some(line) });
        if writeln!(out, "{reply}").and_then(|()| out.flush()).is_err() {
            return ExitCode::from(2);
        }
    }
}

fn main() -> ExitCode {
    let mode = std::env::args().nth(1);
    match mode.as_deref() {
        Some("lowering") => {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            match rest.as_slice() {
                [] => lowering::serve(false),
                [m, n] if m == "--mutant" && n == "drop-tenant" => lowering::serve(true),
                _ => {
                    eprintln!("usage: mariadb-subject lowering [--mutant drop-tenant]");
                    ExitCode::from(2)
                }
            }
        }
        Some("schema") => gate::serve(),
        _ => {
            eprintln!(
                "usage: mariadb-subject lowering [--mutant drop-tenant] | schema   (JSON lines on stdin/stdout; \
                 oracles/lowering-read + lowering-write, oracles/schema-gate)"
            );
            ExitCode::from(2)
        }
    }
}
