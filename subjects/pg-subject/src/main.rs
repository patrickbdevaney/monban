//! pg-subject: drives `aegis-adapter-pg` (owned PG v3 client + pins-compiled version gate) over JSON lines.
//!
//! `pg-subject connect` speaks the oracles/pg-version-gate subject protocol on stdin/stdout:
//!
//! ```text
//! {"v":1,"id":7,"op":"connect","dsn":"postgresql://postgres:secret@127.0.0.1:5432/postgres"}
//! {"id":7,"ok":true,"server_version":"17.11"}          admitted (leading token of server_version)
//! {"id":7,"refuse":"major 19 blocked (R-DB-8 ...)"}    refused / failed
//! {"v":1,"id":8,"op":"hello"}  ->  {"id":8,"ok":true,"subject":"pg-subject"}
//! ```
//!
//! The subject keeps one connection per DSN for its lifetime. A pooled connection is reused while it is reusable
//! (clean protocol state and no unread bytes/EOF on the idle socket). Otherwise it is dropped and a new startup is
//! made; the new `server_version` token must equal the one admitted for that DSN, else the answer is a refusal and
//! the pool entry is removed (R-DB-1: recycle after a minor upgrade), so the next connect is a fresh admission.
//! Unknown ops, unreadable lines and over-long lines (1 MiB) get a refusal; the subject never guesses an accept.
#![forbid(unsafe_code)]

mod json;

use std::collections::HashMap;
use std::io::{BufRead, Read, Write};
use std::process::ExitCode;
use std::time::Duration;

use aegis_adapter_pg::{AdmittedVersion, ConnectConfig, ConnectError, Connection, connect_admitted};
use json::Json;

const MAX_LINE: u64 = 1 << 20;
const TERMINATE: Duration = Duration::from_millis(200);

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if u32::from(c) < 0x20 => o.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn emit(j: &Json) -> String {
    match j {
        Json::Null => "null".into(),
        Json::Bool(b) => b.to_string(),
        Json::Num(t) => t.clone(),
        Json::Str(s) => esc(s),
        Json::Arr(v) => format!("[{}]", v.iter().map(emit).collect::<Vec<_>>().join(",")),
        Json::Obj(m) => {
            format!("{{{}}}", m.iter().map(|(k, v)| format!("{}:{}", esc(k), emit(v))).collect::<Vec<_>>().join(","))
        }
    }
}

enum Reply {
    Ok(String),
    Refuse(String),
    Hello,
}

#[derive(Default)]
struct Subject {
    pool: HashMap<String, (Connection, AdmittedVersion)>,
}

impl Subject {
    fn connect(&mut self, dsn: &str) -> Reply {
        let cfg = match ConnectConfig::from_dsn(dsn) {
            Ok(c) => c,
            Err(e) => return Reply::Refuse(e.to_string()),
        };
        let pinned = match self.pool.remove(dsn) {
            Some((conn, adm)) if conn.is_reusable() => {
                let tok = adm.token().to_owned();
                self.pool.insert(dsn.to_owned(), (conn, adm));
                return Reply::Ok(tok);
            }
            Some((conn, adm)) => {
                conn.terminate(TERMINATE);
                Some(adm)
            }
            None => None,
        };
        match connect_admitted(&cfg, pinned.as_ref()) {
            Ok((conn, adm)) => {
                let tok = adm.token().to_owned();
                self.pool.insert(dsn.to_owned(), (conn, adm));
                Reply::Ok(tok)
            }
            Err(ConnectError::Refused(r)) => Reply::Refuse(r.to_string()),
            Err(ConnectError::Wire(e)) => Reply::Refuse(format!("connect failed: {e}")),
        }
    }

    fn handle(&mut self, line: &str) -> (Json, Reply) {
        let req = match json::parse(line) {
            Ok(j) => j,
            Err(e) => return (Json::Null, Reply::Refuse(format!("bad request: {e}"))),
        };
        let id = req.get("id").cloned().unwrap_or(Json::Null);
        let reply = match req.get("op").and_then(Json::str) {
            Some("connect") => match req.get("dsn").and_then(Json::str) {
                Some(dsn) => self.connect(dsn),
                None => Reply::Refuse("connect without dsn".into()),
            },
            Some("hello") => Reply::Hello,
            other => Reply::Refuse(format!("unknown op {other:?}")),
        };
        (id, reply)
    }
}

fn serve_connect() -> ExitCode {
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut out = std::io::stdout().lock();
    let mut subj = Subject::default();
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
        let (id, reply) =
            if over { (Json::Null, Reply::Refuse("request line too long".into())) } else { subj.handle(line) };
        let body = match reply {
            Reply::Ok(v) => format!("\"ok\":true,\"server_version\":{}", esc(&v)),
            Reply::Refuse(r) => format!("\"refuse\":{}", esc(&r)),
            Reply::Hello => "\"ok\":true,\"subject\":\"pg-subject\"".into(),
        };
        if writeln!(out, "{{\"id\":{},{body}}}", emit(&id)).and_then(|()| out.flush()).is_err() {
            return ExitCode::from(2);
        }
    }
}

fn main() -> ExitCode {
    let mode = std::env::args().nth(1);
    match mode.as_deref() {
        Some("connect") => serve_connect(),
        _ => {
            eprintln!("usage: pg-subject connect   (JSON lines on stdin/stdout; oracles/pg-version-gate/README.md)");
            ExitCode::from(2)
        }
    }
}
