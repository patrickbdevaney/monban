//! Client tests: a scripted fake server (always run) and live engines (run under
//! `ci/engines.sh with valkey,redis -- ...`, which exports `AEGIS_ENGINE_VALKEY` / `AEGIS_ENGINE_REDIS`; skipped
//! with a note otherwise).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use monban_adapter_redis::render::{KvOp, KvOutcome, TenantUser, execute, plan, tenant_username};
use monban_adapter_redis::{ConnectConfig, Connection, Error, ExecError, KvKind, KvPins, VersionRefusal};
use monban_types::TenantId;

fn tid(v: u64) -> TenantId {
    TenantId::new(v).unwrap_or_else(|_| unreachable!())
}

fn bulk(s: &[u8]) -> Vec<u8> {
    let mut o = format!("${}\r\n", s.len()).into_bytes();
    o.extend_from_slice(s);
    o.extend_from_slice(b"\r\n");
    o
}

fn hello(server: &str, version: &str) -> Vec<u8> {
    let mut o = b"*6\r\n".to_vec();
    for f in [&b"server"[..], server.as_bytes(), b"version", version.as_bytes(), b"proto"] {
        o.extend(bulk(f));
    }
    o.extend_from_slice(b":2\r\n");
    o
}

/// Accept one connection, read whatever arrives, and answer each request with the next scripted reply.
fn fake(replies: Vec<Vec<u8>>) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|_| unreachable!());
    let addr = l.local_addr().unwrap_or_else(|_| unreachable!());
    thread::spawn(move || {
        if let Ok((mut s, _)) = l.accept() {
            let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
            for r in replies {
                let mut buf = [0u8; 4096];
                if s.read(&mut buf).unwrap_or(0) == 0 {
                    return;
                }
                if r.is_empty() {
                    thread::sleep(Duration::from_secs(3)); // stall
                    return;
                }
                let _ = s.write_all(&r);
            }
            thread::sleep(Duration::from_millis(200));
        }
    });
    format!("redis://{addr}")
}

fn cfg(url: &str) -> ConnectConfig {
    let mut c = ConnectConfig::from_url(url).unwrap_or_else(|_| unreachable!());
    c.connect_timeout = Duration::from_secs(2);
    c.io_timeout = Duration::from_millis(500);
    c
}

fn info(fields: &str) -> Vec<u8> {
    bulk(format!("# Server\r\n{fields}").as_bytes())
}

#[test]
fn fake_gate_admits_pins_and_refuses_unfixed() {
    let pins = KvPins::shipped();
    let ok = fake(vec![
        hello("valkey", "9.1.2"),
        info("redis_version:7.2.4\r\nserver_name:valkey\r\nvalkey_version:9.1.2\r\nvalkey_release_stage:ga\r\n"),
    ]);
    let c = Connection::connect(&cfg(&ok), &pins, None);
    assert!(matches!(&c, Ok(c) if c.admitted().kind == KvKind::Valkey), "{c:?}");

    // Valkey 9.0.2 lists no CVE-2025-67733 fix (9.0.3 does); its compatibility redis_version must not save it.
    let old = fake(vec![
        hello("valkey", "9.0.2"),
        info("redis_version:8.10.2\r\nserver_name:valkey\r\nvalkey_version:9.0.2\r\n"),
    ]);
    assert!(matches!(
        Connection::connect(&cfg(&old), &pins, None),
        Err(Error::Refused(VersionRefusal::BelowFix { .. }))
    ));
    // Redis 8.8.x shipped after the fix and is unfixed: branch not listed.
    let r88 = fake(vec![hello("redis", "8.8.4"), info("redis_version:8.8.4\r\n")]);
    assert!(matches!(
        Connection::connect(&cfg(&r88), &pins, None),
        Err(Error::Refused(VersionRefusal::BranchNotListed { .. }))
    ));
    // HELLO and INFO disagree.
    let liar = fake(vec![hello("redis", "8.10.2"), info("server_name:valkey\r\nvalkey_version:9.1.2\r\n")]);
    assert!(matches!(Connection::connect(&cfg(&liar), &pins, None), Err(Error::Refused(VersionRefusal::Identity(_)))));
    // First admission without INFO permission.
    let noinfo = fake(vec![hello("valkey", "9.1.2"), b"-NOPERM no info\r\n".to_vec()]);
    assert!(matches!(
        Connection::connect(&cfg(&noinfo), &pins, None),
        Err(Error::Refused(VersionRefusal::Identity(_)))
    ));
    // Wrong password.
    let auth = fake(vec![b"-WRONGPASS invalid username-password pair\r\n".to_vec()]);
    let mut c = cfg(&auth);
    c.username = Some("u".into());
    c.password = Some("p".into());
    assert!(matches!(Connection::connect(&c, &pins, None), Err(Error::Auth(_))));
}

#[test]
fn fake_hostile_replies_break_the_connection() {
    let pins = KvPins::shipped();
    let hs = || hello("redis", "8.10.2");
    let inf = || info("redis_version:8.10.2\r\n");
    // Oversized bulk header: refused on the header.
    let big = fake(vec![hs(), inf(), b"$999999999999\r\n".to_vec()]);
    let mut c = Connection::connect(&cfg(&big), &pins, None).unwrap_or_else(|e| unreachable!("{e}"));
    assert!(matches!(c.command(&[b"GET", b"k"]), Err(Error::Resp(_))));
    assert!(c.is_broken());
    assert!(matches!(c.command(&[b"GET", b"k"]), Err(Error::Broken)));
    // Deep nesting and RESP3.
    for bad in [b"*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n:1\r\n".to_vec(), b"%1\r\n+a\r\n+b\r\n".to_vec(), b"_\r\n".to_vec()] {
        let u = fake(vec![hs(), inf(), bad]);
        let mut c = Connection::connect(&cfg(&u), &pins, None).unwrap_or_else(|e| unreachable!("{e}"));
        assert!(matches!(c.command(&[b"GET", b"k"]), Err(Error::Resp(_))));
    }
    // A server that stalls: the per-command deadline fires and the connection is broken.
    let stall = fake(vec![hs(), inf(), vec![]]);
    let mut c = Connection::connect(&cfg(&stall), &pins, None).unwrap_or_else(|e| unreachable!("{e}"));
    let t0 = std::time::Instant::now();
    assert!(matches!(c.command(&[b"GET", b"k"]), Err(Error::Timeout)));
    assert!(t0.elapsed() < Duration::from_secs(2));
    assert!(c.is_broken());
    // A server that stalls in the handshake: connect_timeout bounds it.
    let hs_stall = fake(vec![vec![]]);
    let t0 = std::time::Instant::now();
    assert!(matches!(Connection::connect(&cfg(&hs_stall), &pins, None), Err(Error::Timeout)));
    assert!(t0.elapsed() < Duration::from_secs(3));
}

#[test]
fn fake_client_refuses_denylisted_and_non_data_commands_before_sending() {
    let pins = KvPins::shipped();
    let u = fake(vec![hello("redis", "8.10.2"), info("redis_version:8.10.2\r\n"), b"$-1\r\n".to_vec()]);
    let mut c = Connection::connect(&cfg(&u), &pins, None).unwrap_or_else(|e| unreachable!("{e}"));
    for cmd in [
        &[&b"EVAL"[..], b"return 1", b"0"][..],
        &[b"eval_ro", b"x", b"0"],
        &[b"FLUSHALL"],
        &[b"KEYS", b"*"],
        &[b"SWAPDB", b"0", b"1"],
        &[b"ACL", b"LIST"],
        &[b"CONFIG", b"GET", b"*"],
        &[b"SELECT", b"1"],
        &[b"INFO"],
        &[b"PING"],
        &[b"RESET"],
        &[b"HSET", b"k", b"f", b"v"],
        &[],
    ] {
        assert!(matches!(c.command(cmd), Err(Error::Usage(_))), "{cmd:?}");
    }
    assert!(!c.is_broken());
    // The scripted GET reply is still the next one: nothing was sent for the refused commands.
    assert!(matches!(c.command(&[b"get", b"k"]), Ok(monban_adapter_redis::Reply::Bulk(None))));
}

// ------------------------------------------------------------------------------------------------- live engines

fn live_urls() -> Vec<(String, String)> {
    let mut v = Vec::new();
    for name in ["VALKEY", "REDIS"] {
        if let Ok(u) = std::env::var(format!("AEGIS_ENGINE_{name}")) {
            v.push((name.to_lowercase(), u));
        }
    }
    if v.is_empty() {
        eprintln!("live tests skipped: run under `ci/engines.sh with valkey,redis -- ...`");
    }
    v
}

/// Raw RESP exchange for the hostile corpus (bypasses the client's allowlist on purpose: the point is what the
/// server refuses).
fn raw_cmd(s: &mut TcpStream, args: &[&[u8]]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", args.len()).into_bytes();
    for a in args {
        out.extend(bulk(a));
    }
    let _ = s.write_all(&out);
    let mut buf = vec![0u8; 65536];
    let mut got = Vec::new();
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    // Error replies are one line; that is all the corpus needs to read.
    while !got.ends_with(b"\r\n") {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(buf.get(..n).unwrap_or(&[])),
        }
    }
    got
}

fn host_port(url: &str) -> String {
    url.trim_start_matches("redis://").to_string()
}

#[test]
fn live_tenant_acl_user_end_to_end() {
    let pins = KvPins::shipped();
    for (name, url) in live_urls() {
        let mut admin = Connection::connect(&cfg(&url), &pins, None).unwrap_or_else(|e| unreachable!("{name}: {e}"));
        let want = if name == "valkey" { KvKind::Valkey } else { KvKind::Redis };
        assert_eq!(admin.admitted().kind, want, "{name}");
        let adm = *admin.admitted();
        eprintln!("{name}: admitted {} {}", adm.kind.name(), adm.version);

        let (ta, tb) = (tid(0xacce55), tid(0xacce5));
        let pw_a = "a".repeat(40);
        let ua = TenantUser::new(ta, pw_a.clone()).unwrap_or_else(|e| unreachable!("{e}"));
        let ub = TenantUser::new(tb, "b".repeat(40)).unwrap_or_else(|e| unreachable!("{e}"));
        admin.provision(&ua).unwrap_or_else(|e| unreachable!("{name}: {e}"));
        admin.provision(&ub).unwrap_or_else(|e| unreachable!("{name}: {e}"));

        let mut ca = cfg(&url);
        ca.username = Some(tenant_username(ta));
        ca.password = Some(pw_a.clone());
        // A tenant user cannot run INFO, so it cannot be a first admission; it re-checks against the admin's.
        assert!(matches!(Connection::connect(&ca, &pins, None), Err(Error::Refused(_))), "{name}");
        let mut a = Connection::connect(&ca, &pins, Some(&adm)).unwrap_or_else(|e| unreachable!("{name}: {e}"));
        assert!(a.is_reusable());

        // Data path under the ACL user, planned through kv_plan.
        let p = |op: KvOp<'_>| plan(ta, "notes", &op).unwrap_or_else(|e| unreachable!("{e:?}"));
        let ex = |c: &mut Connection, op| execute(c, ta, "notes", &p(op));
        let k = "k*?[]\\:}{\r\n";
        assert!(matches!(ex(&mut a, KvOp::Del { key: k }), Ok(KvOutcome::Deleted(_))));
        assert!(matches!(ex(&mut a, KvOp::SetXx { key: k, value: "x" }), Ok(KvOutcome::Written(false))));
        assert!(matches!(ex(&mut a, KvOp::SetNx { key: k, value: "v1" }), Ok(KvOutcome::Written(true))));
        assert!(matches!(ex(&mut a, KvOp::SetNx { key: k, value: "v2" }), Ok(KvOutcome::Written(false))));
        assert!(matches!(ex(&mut a, KvOp::SetXx { key: k, value: "v3" }), Ok(KvOutcome::Written(true))));
        assert!(matches!(ex(&mut a, KvOp::Set { key: k, value: "v4" }), Ok(KvOutcome::Written(true))));
        assert_eq!(ex(&mut a, KvOp::Get { key: k }).ok(), Some(KvOutcome::Value(Some(b"v4".to_vec()))));
        // D11: Select Tt/Pfx (SCAN) is refused by the executor before anything is sent, on any connection; the
        // server would refuse it too (no +scan), checked raw below and in the hostile corpus.
        let scan = ex(&mut a, KvOp::Scan { prefix: None });
        assert!(matches!(&scan, Err(ExecError::Unsupported)), "{name}: {scan:?}");
        assert!(matches!(
            execute(&mut admin, ta, "notes", &p(KvOp::Scan { prefix: Some("k") })),
            Err(ExecError::Unsupported)
        ));
        assert!(matches!(a.command(&[b"SCAN", b"0"]), Err(Error::Usage(_))));
        assert!(a.is_reusable());
        // Another tenant's planned command through tenant A's executor: refused client-side (W7), nothing sent.
        let foreign = plan(tb, "notes", &KvOp::Get { key: "k" }).unwrap_or_else(|e| unreachable!("{e:?}"));
        assert!(matches!(execute(&mut a, ta, "notes", &foreign), Err(ExecError::Foreign)));
        assert!(matches!(ex(&mut a, KvOp::Del { key: k }), Ok(KvOutcome::Deleted(true))));
        assert!(a.is_reusable());

        // Hostile corpus under tenant A's ACL user: every command must be refused by the server with NOPERM.
        let mut s = TcpStream::connect(host_port(&url)).unwrap_or_else(|e| unreachable!("{e}"));
        let auth = raw_cmd(&mut s, &[b"AUTH", tenant_username(ta).as_bytes(), pw_a.as_bytes()]);
        assert_eq!(auth, b"+OK\r\n", "{name}");
        let ua_name = tenant_username(ta);
        let fk = b"t:{00000000000acce5}:notes:k".as_slice();
        let own = b"t:{0000000000acce55}:notes:k".as_slice();
        let corpus: Vec<Vec<&[u8]>> = vec![
            vec![b"EVAL", b"return redis.call('GET', KEYS[1])", b"1", own],
            vec![b"EVAL_RO", b"return 1", b"0"],
            vec![b"EVALSHA", b"0000000000000000000000000000000000000000", b"0"],
            vec![b"FCALL", b"f", b"0"],
            vec![b"FUNCTION", b"LIST"],
            vec![b"SCRIPT", b"FLUSH"],
            vec![b"FLUSHALL"],
            vec![b"FLUSHDB"],
            vec![b"SWAPDB", b"0", b"1"],
            vec![b"KEYS", b"*"],
            vec![b"SCAN", b"0"],
            vec![b"SCAN", b"0", b"MATCH", b"t:*"],
            vec![b"SORT", own, b"BY", b"nosort", b"GET", b"*"],
            vec![b"SORT", own, b"STORE", fk],
            vec![b"SORT_RO", own],
            vec![b"MOVE", own, b"1"],
            vec![b"COPY", own, fk],
            vec![b"RENAME", own, fk],
            vec![b"RENAMENX", own, fk],
            vec![b"MIGRATE", b"127.0.0.1", b"1", own, b"0", b"10"],
            vec![b"SELECT", b"1"],
            vec![b"CLIENT", b"LIST"],
            vec![b"CLIENT", b"KILL", b"ID", b"1"],
            vec![b"ACL", b"WHOAMI"],
            vec![b"ACL", b"SETUSER", ua_name.as_bytes(), b"~*", b"+@all"],
            vec![b"CONFIG", b"GET", b"*"],
            vec![b"DEBUG", b"SLEEP", b"0"],
            vec![b"MODULE", b"LIST"],
            vec![b"MONITOR"],
            vec![b"INFO"],
            vec![b"PING"],
            vec![b"SUBSCRIBE", b"x"],
            vec![b"PUBLISH", b"x", b"y"],
            vec![b"GET", fk],
            vec![b"SET", fk, b"v"],
            vec![b"DEL", own, fk],
            vec![b"HSET", own, b"f", b"v"],
            vec![b"OBJECT", b"ENCODING", own],
            vec![b"DUMP", own],
            vec![b"EXISTS", fk],
            vec![b"MULTI"],
            vec![b"WAIT", b"0", b"0"],
            vec![b"SHUTDOWN", b"NOSAVE"],
        ];
        // Two checks per command: the live reply is a refusal (NOPERM; DEBUG/MODULE may be refused earlier by the
        // server's enable-*-command setting, which is still a refusal but not the ACL's), and `ACL DRYRUN` on an
        // admin socket confirms the ACL itself denies it.
        let mut adm_raw = TcpStream::connect(host_port(&url)).unwrap_or_else(|e| unreachable!("{e}"));
        for c in &corpus {
            let what = String::from_utf8_lossy(c.first().copied().unwrap_or(b"")).into_owned();
            let r = raw_cmd(&mut s, c);
            let config_gated = matches!(what.as_str(), "DEBUG" | "MODULE") && r.starts_with(b"-ERR");
            assert!(r.starts_with(b"-NOPERM") || config_gated, "{name}: {what} -> {:?}", String::from_utf8_lossy(&r));
            let mut dry: Vec<&[u8]> = vec![b"ACL", b"DRYRUN", ua_name.as_bytes()];
            dry.extend_from_slice(c);
            let d = raw_cmd(&mut adm_raw, &dry);
            assert!(
                !d.starts_with(b"+OK") && (d.starts_with(b"$") || d.starts_with(b"-")),
                "{name}: ACL DRYRUN {what} -> {:?}",
                String::from_utf8_lossy(&d)
            );
        }
        // Control: DRYRUN does say OK for the tenant's own key-bearing commands.
        for c in [vec![&b"GET"[..], own], vec![b"SET", own, b"v", b"NX"], vec![b"DEL", own]] {
            let mut dry: Vec<&[u8]> = vec![b"ACL", b"DRYRUN", ua_name.as_bytes()];
            dry.extend_from_slice(&c);
            assert_eq!(raw_cmd(&mut adm_raw, &dry), b"+OK\r\n", "{name}");
        }
        // The user can still do its own work on the same raw connection (the refusals were ACL, not breakage).
        assert_eq!(raw_cmd(&mut s, &[b"SET", own, b"v"]), b"+OK\r\n");
        assert_eq!(raw_cmd(&mut s, &[b"DEL", own]), b":1\r\n");

        assert!(admin.deprovision(&tenant_username(ta)).unwrap_or(false));
        assert!(admin.deprovision(&tenant_username(tb)).unwrap_or(false));
        assert!(matches!(admin.deprovision("default"), Err(Error::Usage(_))));

        // D12: the stock engine `default` user (on, nopass, +@all) must make the provisioning connection refuse.
        assert!(matches!(admin.check_default_user(), Err(Error::DefaultUserEnabled(_))), "{name}");
        assert!(matches!(Connection::connect_provisioning(&cfg(&url), &pins), Err(Error::DefaultUserEnabled(_))));
        // An operator admin user, then `default` off: provisioning (as the admin user) is accepted.
        let admin_pw = "z".repeat(40);
        let mk = raw_cmd(
            &mut adm_raw,
            &[
                b"ACL",
                b"SETUSER",
                b"monban-admin",
                b"reset",
                b"on",
                format!(">{admin_pw}").as_bytes(),
                b"~*",
                b"&*",
                b"+@all",
            ],
        );
        assert_eq!(mk, b"+OK\r\n", "{name}");
        let mut pc = cfg(&url);
        pc.username = Some("monban-admin".into());
        pc.password = Some(admin_pw.clone());
        // From here on, administer as monban-admin: `default` is about to lose its permissions.
        let mut op_raw = TcpStream::connect(host_port(&url)).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(raw_cmd(&mut op_raw, &[b"AUTH", b"monban-admin", admin_pw.as_bytes()]), b"+OK\r\n");
        let mut adm_raw = op_raw;
        assert_eq!(raw_cmd(&mut adm_raw, &[b"ACL", b"SETUSER", b"default", b"off"]), b"+OK\r\n");
        let prov = Connection::connect_provisioning(&pc, &pins);
        assert!(prov.is_ok(), "{name}: {prov:?}");
        // `default` on but without any permission: also accepted. With one command back: refused.
        assert_eq!(
            raw_cmd(&mut adm_raw, &[b"ACL", b"SETUSER", b"default", b"on", b"resetkeys", b"resetchannels", b"-@all"]),
            b"+OK\r\n"
        );
        assert!(Connection::connect_provisioning(&pc, &pins).is_ok(), "{name}");
        assert_eq!(raw_cmd(&mut adm_raw, &[b"ACL", b"SETUSER", b"default", b"+ping"]), b"+OK\r\n");
        assert!(matches!(Connection::connect_provisioning(&pc, &pins), Err(Error::DefaultUserEnabled(_))), "{name}");
        // Restore the throwaway engine's stock default for anything that runs after.
        assert_eq!(
            raw_cmd(&mut adm_raw, &[b"ACL", b"SETUSER", b"default", b"on", b"nopass", b"~*", b"&*", b"+@all"]),
            b"+OK\r\n"
        );
        assert_eq!(raw_cmd(&mut adm_raw, &[b"ACL", b"DELUSER", b"monban-admin"]), b":1\r\n");
    }
}
