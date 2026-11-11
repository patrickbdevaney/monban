//! crdb-subject: drives `monban-adapter-pg` with the CockroachDB dialect (feature `crdb`) for oracles/lowering-read,
//! lowering-write and schema-gate (`--engine crdb`), over JSON lines on stdin/stdout.
//!
//! * `crdb-subject lowering [--mutant drop-tenant]`: protocol v2, `"dialect":"crdb"`, rendered by
//!   `monban_adapter_pg::lower::render_dialect(.., Dialect::Crdb)` (see `lowering.rs`).
//! * `crdb-subject schema`: schema-gate protocol v1, mode `crdb` through live introspection
//!   (`monban_adapter_pg::check_live_schema_dialect(.., Dialect::Crdb)`, version-gated connect
//!   `monban_adapter_pg::crdb::connect_admitted`; see `gate.rs`), plus `static`.
//!
//! Unknown modes exit 2 with a usage line; nothing is ever guessed as an accept.
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
                    let _ = writeln!(std::io::stderr(), "usage: crdb-subject lowering [--mutant drop-tenant]");
                    ExitCode::from(2)
                }
            }
        }
        Some("schema") => gate::serve(),
        _ => {
            let _ = writeln!(
                std::io::stderr(),
                "usage: crdb-subject lowering [--mutant drop-tenant] | schema   (JSON lines on stdin/stdout; \
                 oracles/lowering-read + lowering-write --engine crdb, oracles/schema-gate --engine crdb)"
            );
            ExitCode::from(2)
        }
    }
}
