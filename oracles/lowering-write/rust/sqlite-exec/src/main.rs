//! sqlite-exec: executes SQL for the AEGIS lowering oracles at the adapter's SQLite pin (bundled 3.54.1) instead of
//! Python's stdlib sqlite3. It never renders anything: the oracle sends the subject's SQL and parameters verbatim.
//!
//! Line protocol (stdin -> stdout, one request and one reply per line, byte strings hex-encoded):
//!   V                          -> OK <sqlite_version>
//!   O                          -> OK <handle>          (new private in-memory database, autocommit)
//!   C <h>                      -> OK                   (close)
//!   X <h> <sql_hex> <param>*   -> OK <ncols> <nrows> <colname_hex>{ncols} <cell>{ncols*nrows}
//!                              |  ER <message_hex>
//! param / cell: `n` NULL | `i<decimal i64>` | `r<16 hex digits: f64 bits>` | `t<hex utf-8>` | `b<hex>`.
//! One statement per X (a second statement in the same text is an error, as in Python's sqlite3).
use rusqlite::types::{Value, ValueRef};
use rusqlite::{Connection, params_from_iter};
use std::collections::HashMap;
use std::io::{BufRead, BufWriter, Write};

fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &c in b {
        s.push(char::from(D[usize::from(c >> 4)]));
        s.push(char::from(D[usize::from(c & 15)]));
    }
    s
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let nib = |c: u8| -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err("bad hex digit".into()),
        }
    };
    s.as_bytes()
        .chunks(2)
        .map(|p| match p {
            [h, l] => Ok((nib(*h)? << 4) | nib(*l)?),
            _ => Err("odd hex length".to_string()),
        })
        .collect()
}

fn param(tok: &str) -> Result<Value, String> {
    let (tag, rest) = tok.split_at_checked(1).ok_or("empty param")?;
    match tag {
        "n" if rest.is_empty() => Ok(Value::Null),
        "i" => rest.parse::<i64>().map(Value::Integer).map_err(|e| format!("int param: {e}")),
        "r" => u64::from_str_radix(rest, 16).map(|b| Value::Real(f64::from_bits(b))).map_err(|e| format!("real: {e}")),
        "t" => String::from_utf8(unhex(rest)?).map(Value::Text).map_err(|_| "text param not UTF-8".to_string()),
        "b" => unhex(rest).map(Value::Blob),
        _ => Err(format!("bad param tag {tag:?}")),
    }
}

fn cell(v: ValueRef<'_>) -> String {
    match v {
        ValueRef::Null => "n".into(),
        ValueRef::Integer(i) => format!("i{i}"),
        ValueRef::Real(f) => format!("r{:016x}", f.to_bits()),
        ValueRef::Text(t) => format!("t{}", hex(t)),
        ValueRef::Blob(b) => format!("b{}", hex(b)),
    }
}

fn exec(conn: &Connection, sql: &str, params: Vec<Value>) -> Result<String, String> {
    let mut stmt = conn.prepare_cached(sql).map_err(|e| e.to_string())?;
    let names: Vec<String> = stmt.column_names().map(|n| hex(n.as_bytes())).collect();
    let ncols = names.len();
    let mut cells: Vec<String> = Vec::new();
    let mut nrows = 0usize;
    {
        let mut rows = stmt.query(params_from_iter(params)).map_err(|e| e.to_string())?;
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            nrows += 1;
            for i in 0..ncols {
                cells.push(cell(row.get_ref(i).map_err(|e| e.to_string())?));
            }
        }
    }
    let mut out = format!("OK {ncols} {nrows}");
    for s in names.iter().chain(cells.iter()) {
        out.push(' ');
        out.push_str(s);
    }
    Ok(out)
}

fn handle(line: &str, conns: &mut HashMap<u64, Connection>, next: &mut u64) -> Result<String, String> {
    let mut it = line.split(' ');
    match it.next().unwrap_or("") {
        "V" => Ok(format!("OK {}", rusqlite::version())),
        "O" => {
            let c = Connection::open_in_memory().map_err(|e| e.to_string())?;
            c.set_prepared_statement_cache_capacity(256);
            *next += 1;
            conns.insert(*next, c);
            Ok(format!("OK {next}"))
        }
        "C" => {
            let h: u64 = it.next().ok_or("handle")?.parse().map_err(|_| "handle")?;
            conns.remove(&h);
            Ok("OK".into())
        }
        "X" => {
            let h: u64 = it.next().ok_or("handle")?.parse().map_err(|_| "handle")?;
            let sql = String::from_utf8(unhex(it.next().ok_or("sql")?)?).map_err(|_| "sql not UTF-8")?;
            let params = it.map(param).collect::<Result<Vec<_>, _>>()?;
            let conn = conns.get(&h).ok_or("unknown handle")?;
            exec(conn, &sql, params)
        }
        other => Err(format!("unknown command {other:?}")),
    }
}

fn main() {
    let stdin = std::io::stdin();
    let mut out = BufWriter::new(std::io::stdout().lock());
    let mut conns: HashMap<u64, Connection> = HashMap::new();
    let mut next = 0u64;
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let reply = match handle(line.trim_end(), &mut conns, &mut next) {
            Ok(s) => s,
            Err(e) => format!("ER {}", hex(e.as_bytes())),
        };
        if writeln!(out, "{reply}").and_then(|()| out.flush()).is_err() {
            break;
        }
    }
}
