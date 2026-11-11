//! redis-subject: exposes the KV renderer of `monban-adapter-redis` over the lowering oracles' subject protocol v2
//! (`oracles/lowering-read/README.md` "Subject protocol", `oracles/lowering-write/README.md`).
//!
//! ```text
//! redis-subject lowering [--mutant drop-tenant]
//! {"v":2,"id":1,"op":"kv_get","tenant":"0000000000acce55","collection":"notes","key_hex":"6b31"}
//! {"id":1,"v":2,"commands":[["474554","743a7b...6b31"]]}
//! ```
//!
//! Ops: `kv_key`, `kv_get`, `kv_set`, `kv_setnx`, `kv_setxx`, `kv_del`, `kv_scan` (all planned by
//! `monban_data_ir::kv_plan` through `monban_adapter_redis::plan`), `kv_acl` (the per-tenant ACL rules), `hello`.
//! Everything else (SQL ops, `merge`/`cte`/`replace`/`raw_sql`, RLS ops) is refused: this subject is KV-only. A
//! tenant that is not the D4 canonical text, a bad collection, a key or pattern over 1024 bytes, a non-UTF-8 key or
//! value, or a malformed request is refused; the subject never guesses an accept.
//!
//! `--mutant drop-tenant` (self-test negative control only) removes all tenant scoping: keys and patterns lose the
//! `t:{<hex>}:` prefix and the ACL key pattern becomes `~*`.
#![forbid(unsafe_code)]

mod json;

use std::io::{BufRead, Read, Write};
use std::process::ExitCode;

use json::Json;
use monban_adapter_redis::{KvOp, command_args, plan, tenant_acl_rules};
use monban_data_ir::{KvCommand, kv_key_prefix, parse_tenant_text};
use monban_types::TenantId;

const MAX_LINE: u64 = 1 << 20;
const PROTOCOL: u32 = 2;

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if u32::from(c) < 0x20 || u32::from(c) > 0x7e => {
                let mut b = [0u16; 2];
                for u in c.encode_utf16(&mut b) {
                    o.push_str(&format!("\\u{:04x}", u));
                }
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// Re-emit a request id exactly (numbers keep their source text).
fn emit_id(j: &Json) -> String {
    match j {
        Json::Num(t) => t.clone(),
        Json::Str(s) => esc(s),
        _ => "null".into(),
    }
}

fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(char::from(H.get(usize::from(x >> 4)).copied().unwrap_or(b'0')));
        s.push(char::from(H.get(usize::from(x & 15)).copied().unwrap_or(b'0')));
    }
    s
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let d = |c: u8| char::from(c).to_digit(16).and_then(|v| u8::try_from(v).ok());
    b.as_chunks::<2>().0.iter().map(|[h, l]| Some((d(*h)? << 4) | d(*l)?)).collect()
}

/// Hex field decoded to UTF-8 text (KV keys and values are `Value::Str`).
fn text_field(req: &Json, k: &str) -> Result<String, String> {
    let h = req.get(k).and_then(Json::str).ok_or_else(|| format!("missing {k}"))?;
    let b = unhex(h).ok_or_else(|| format!("{k} is not hex"))?;
    String::from_utf8(b).map_err(|_| format!("{k} is not UTF-8 text"))
}

struct Subject {
    drop_tenant: bool,
}

enum Out {
    Fields(String),
    Refuse(String),
}

impl Subject {
    /// Strip the tenant prefix (drop-tenant mutant only).
    fn mutate(&self, tenant: TenantId, s: String) -> String {
        if !self.drop_tenant {
            return s;
        }
        let p = kv_key_prefix(tenant);
        s.strip_prefix(p.as_str()).map(str::to_string).unwrap_or(s)
    }

    fn handle(&self, req: &Json) -> Result<String, String> {
        let op = req.get("op").and_then(Json::str).ok_or("missing op")?;
        if op == "hello" {
            return Ok(format!(
                "\"name\":\"redis-subject(monban-adapter-redis)\",\"protocol\":{PROTOCOL},\"mutants\":[{}]",
                if self.drop_tenant { "\"drop-tenant\"" } else { "" }
            ));
        }
        if !matches!(op, "kv_key" | "kv_get" | "kv_set" | "kv_setnx" | "kv_setxx" | "kv_del" | "kv_scan" | "kv_acl") {
            return Err(format!("op {op:?} is not served by this KV-only subject"));
        }
        let tenant = req
            .get("tenant")
            .and_then(Json::str)
            .and_then(parse_tenant_text)
            .ok_or("tenant handle is not the D4 canonical TenantId text (16 lower-case hex, non-zero)")?;
        if op == "kv_acl" {
            let mut rules = tenant_acl_rules(tenant);
            if self.drop_tenant {
                for r in rules.iter_mut().filter(|r| r.starts_with('~')) {
                    *r = "~*".into();
                }
            }
            let items: Vec<String> = rules.iter().map(|r| esc(r)).collect();
            return Ok(format!("\"rules\":[{}]", items.join(",")));
        }
        let coll = req.get("collection").and_then(Json::str).ok_or("missing collection")?;
        let key;
        let value;
        let prefix;
        let kop = match op {
            "kv_scan" => {
                prefix = match req.get("prefix_hex") {
                    None | Some(Json::Null) => None,
                    Some(_) => Some(text_field(req, "prefix_hex")?),
                };
                KvOp::Scan { prefix: prefix.as_deref() }
            }
            "kv_key" | "kv_get" => {
                key = text_field(req, "key_hex")?;
                KvOp::Get { key: &key }
            }
            "kv_del" => {
                key = text_field(req, "key_hex")?;
                KvOp::Del { key: &key }
            }
            _ => {
                key = text_field(req, "key_hex")?;
                value = text_field(req, "value_hex")?;
                match op {
                    "kv_set" => KvOp::Set { key: &key, value: &value },
                    "kv_setnx" => KvOp::SetNx { key: &key, value: &value },
                    _ => KvOp::SetXx { key: &key, value: &value },
                }
            }
        };
        let cmd = plan(tenant, coll, &kop).map_err(|e| format!("refused by kv_plan: {e:?}"))?;
        let cmd = match cmd {
            KvCommand::Get { key } => KvCommand::Get { key: self.mutate(tenant, key) },
            KvCommand::Scan { pattern } => KvCommand::Scan { pattern: self.mutate(tenant, pattern) },
            KvCommand::Set { key, value } => KvCommand::Set { key: self.mutate(tenant, key), value },
            KvCommand::SetNx { key, value } => KvCommand::SetNx { key: self.mutate(tenant, key), value },
            KvCommand::SetXx { key, value } => KvCommand::SetXx { key: self.mutate(tenant, key), value },
            KvCommand::Del { key } => KvCommand::Del { key: self.mutate(tenant, key) },
        };
        match (op, &cmd) {
            ("kv_key", KvCommand::Get { key }) => Ok(format!("\"key_hex\":\"{}\"", hex(key.as_bytes()))),
            ("kv_scan", KvCommand::Scan { pattern }) => Ok(format!("\"pattern_hex\":\"{}\"", hex(pattern.as_bytes()))),
            ("kv_key" | "kv_scan", _) => Err("internal: unexpected plan".into()),
            _ => {
                let args: Vec<String> = command_args(&cmd).iter().map(|a| format!("\"{}\"", hex(a))).collect();
                Ok(format!("\"commands\":[[{}]]", args.join(",")))
            }
        }
    }

    fn line(&self, line: &str) -> (Json, Out) {
        let req = match json::parse(line) {
            Ok(j) => j,
            Err(e) => return (Json::Null, Out::Refuse(format!("bad request: {e}"))),
        };
        let id = req.get("id").cloned().unwrap_or(Json::Null);
        match req.get("v") {
            None => {}
            Some(Json::Num(v)) if v == "2" => {}
            Some(v) => return (id, Out::Refuse(format!("protocol {v:?} not served (v2 only)"))),
        }
        match self.handle(&req) {
            Ok(f) => (id, Out::Fields(f)),
            Err(e) => (id, Out::Refuse(e)),
        }
    }
}

fn serve(subj: &Subject) -> ExitCode {
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
            // Discard the rest of the over-long line in bounded chunks.
            loop {
                let mut sink = Vec::new();
                match (&mut input).take(MAX_LINE).read_until(b'\n', &mut sink) {
                    Ok(0) => break,
                    Ok(_) if sink.last() == Some(&b'\n') => break,
                    Ok(_) => {}
                    Err(_) => return ExitCode::from(2),
                }
            }
        }
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (id, o) = if over { (Json::Null, Out::Refuse("request line too long".into())) } else { subj.line(line) };
        let body = match o {
            Out::Fields(f) => f,
            Out::Refuse(r) => format!("\"refuse\":{}", esc(&r)),
        };
        if writeln!(out, "{{\"id\":{},\"v\":{PROTOCOL},{body}}}", emit_id(&id)).and_then(|()| out.flush()).is_err() {
            return ExitCode::from(2);
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: redis-subject lowering [--mutant drop-tenant]   (JSON lines; oracles/lowering-read/README.md)");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut it = args.iter().map(String::as_str);
    if it.next() != Some("lowering") {
        return usage();
    }
    let mut subj = Subject { drop_tenant: false };
    while let Some(a) = it.next() {
        match (a, it.next()) {
            ("--mutant", Some("drop-tenant")) => subj.drop_tenant = true,
            _ => return usage(),
        }
    }
    serve(&subj)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(s: &Subject, line: &str) -> String {
        let (id, o) = s.line(line);
        match o {
            Out::Fields(f) => format!("{}|{f}", emit_id(&id)),
            Out::Refuse(r) => format!("{}|refuse:{r}", emit_id(&id)),
        }
    }

    #[test]
    fn protocol_examples() {
        let s = Subject { drop_tenant: false };
        let t = "0000000000acce55";
        let r = call(
            &s,
            &format!(r#"{{"v":2,"id":7,"op":"kv_key","tenant":"{t}","collection":"notes","key_hex":"6b31"}}"#),
        );
        assert_eq!(r, format!("7|\"key_hex\":\"{}\"", hex(b"t:{0000000000acce55}:notes:k1")));
        let r = call(
            &s,
            &format!(r#"{{"v":2,"id":8,"op":"kv_get","tenant":"{t}","collection":"notes","key_hex":"6b31"}}"#),
        );
        assert_eq!(r, format!("8|\"commands\":[[\"474554\",\"{}\"]]", hex(b"t:{0000000000acce55}:notes:k1")));
        let r = call(
            &s,
            &format!(r#"{{"v":2,"id":9,"op":"kv_scan","tenant":"{t}","collection":"notes","prefix_hex":"2a"}}"#),
        );
        assert_eq!(r, format!("9|\"pattern_hex\":\"{}\"", hex(b"t:{0000000000acce55}:notes:\\**")));
        let r = call(&s, &format!(r#"{{"v":2,"id":10,"op":"kv_acl","tenant":"{t}"}}"#));
        assert_eq!(
            r,
            "10|\"rules\":[\"resetkeys\",\"~t:{0000000000acce55}:*\",\"resetchannels\",\"-@all\",\"+get\",\"+set\",\"+del\"]"
        );
        let r = call(
            &s,
            &format!(
                r#"{{"v":2,"id":11,"op":"kv_setnx","tenant":"{t}","collection":"notes","key_hex":"6b","value_hex":"76"}}"#
            ),
        );
        assert_eq!(
            r,
            format!("11|\"commands\":[[\"534554\",\"{}\",\"76\",\"4e58\"]]", hex(b"t:{0000000000acce55}:notes:k"))
        );
        for bad in [
            r#"{"v":2,"id":1,"op":"kv_get","tenant":"0000000000ACCE55","collection":"notes","key_hex":"6b"}"#,
            r#"{"v":2,"id":1,"op":"kv_get","tenant":"0000000000000000","collection":"notes","key_hex":"6b"}"#,
            r#"{"v":2,"id":1,"op":"kv_get","tenant":12345,"collection":"notes","key_hex":"6b"}"#,
            r#"{"v":2,"id":1,"op":"kv_get","tenant":"0000000000acce55","collection":"a:b","key_hex":"6b"}"#,
            r#"{"v":2,"id":1,"op":"kv_get","tenant":"0000000000acce55","collection":"notes","key_hex":"ff"}"#,
            r#"{"v":2,"id":1,"op":"kv_get","tenant":"0000000000acce55","collection":"notes","key_hex":"6"}"#,
            r#"{"v":2,"id":1,"op":"kv_set","tenant":"0000000000acce55","collection":"notes","key_hex":"6b"}"#,
            r#"{"v":2,"id":1,"op":"merge","tenant":"0000000000acce55"}"#,
            r#"{"v":2,"id":1,"op":"raw_sql","tenant":"0000000000acce55"}"#,
            r#"{"v":2,"id":1,"op":"read","tenant":"0000000000acce55"}"#,
            r#"{"v":1,"id":1,"op":"kv_acl","tenant":"0000000000acce55"}"#,
            "not json",
        ] {
            assert!(call(&s, bad).contains("|refuse:"), "{bad}");
        }
        let long = hex(&[b'k'; 1100]);
        let r = call(
            &s,
            &format!(r#"{{"v":2,"id":1,"op":"kv_get","tenant":"{t}","collection":"notes","key_hex":"{long}"}}"#),
        );
        assert!(r.contains("|refuse:"));
    }

    #[test]
    fn drop_tenant_mutant() {
        let s = Subject { drop_tenant: true };
        let t = "0000000000acce55";
        let r = call(
            &s,
            &format!(r#"{{"v":2,"id":1,"op":"kv_key","tenant":"{t}","collection":"notes","key_hex":"6b31"}}"#),
        );
        assert_eq!(r, format!("1|\"key_hex\":\"{}\"", hex(b"notes:k1")));
        let r = call(&s, &format!(r#"{{"v":2,"id":2,"op":"kv_acl","tenant":"{t}"}}"#));
        assert!(r.contains("\"~*\"") && !r.contains("acce55"));
    }
}
