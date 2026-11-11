//! Owned PG v3 client against scripted fake servers (std threads, 127.0.0.1): protocol-state tracking for NC3,
//! bounded reads (length cap, deadlines without framing loss), SCRAM-SHA-256 server verification, refused auth
//! methods, desync handling, and a no-panic sweep of the backend parser.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use aws_lc_rs::{digest, hmac, pbkdf2};
use monban_adapter_pg::auth::b64_encode;
use monban_adapter_pg::wire::{
    Backend, ConnectConfig, Connection, Error, Expect, Pipeline, TxnStatus, Unrecoverable, parse_backend,
};
use monban_adapter_pg::{ConnectError, VersionRefusal, connect_admitted};

fn be(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend_from_slice(&(body.len() as i32 + 4).to_be_bytes());
    v.extend_from_slice(body);
    v
}

fn auth(code: i32, rest: &[u8]) -> Vec<u8> {
    let mut b = code.to_be_bytes().to_vec();
    b.extend_from_slice(rest);
    be(b'R', &b)
}

fn ps(k: &str, v: &str) -> Vec<u8> {
    be(b'S', format!("{k}\0{v}\0").as_bytes())
}

fn z(s: u8) -> Vec<u8> {
    be(b'Z', &[s])
}

fn read_startup(s: &mut TcpStream) -> Vec<u8> {
    let mut l = [0u8; 4];
    s.read_exact(&mut l).unwrap();
    let mut b = vec![0u8; i32::from_be_bytes(l) as usize - 4];
    s.read_exact(&mut b).unwrap();
    b
}

fn read_fe(s: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut h = [0u8; 5];
    s.read_exact(&mut h).ok()?;
    let mut b = vec![0u8; i32::from_be_bytes([h[1], h[2], h[3], h[4]]) as usize - 4];
    s.read_exact(&mut b).ok()?;
    Some((h[0], b))
}

fn ready_banner(version: &str) -> Vec<u8> {
    let mut o = auth(0, &[]);
    o.extend(ps("client_encoding", "UTF8"));
    o.extend(ps("server_version", version));
    o.extend(be(b'K', &[0, 0, 0, 7, 1, 2, 3, 4]));
    o.extend(z(b'I'));
    o
}

/// One-connection fake: trust startup with `version`, then `script` drives the socket.
fn fake<F>(version: &'static str, script: F) -> (String, thread::JoinHandle<()>)
where
    F: FnOnce(&mut TcpStream) + Send + 'static,
{
    let ls = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = ls.local_addr().unwrap().port();
    let h = thread::spawn(move || {
        let (mut s, _) = ls.accept().unwrap();
        read_startup(&mut s);
        s.write_all(&ready_banner(version)).unwrap();
        script(&mut s);
    });
    (format!("postgresql://u:pw@127.0.0.1:{port}/db"), h)
}

fn cfg(dsn: &str) -> ConnectConfig {
    let mut c = ConnectConfig::from_dsn(dsn).unwrap();
    c.connect_timeout = Duration::from_secs(5);
    c
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

/// Answer one extended round (messages up to and including Sync); `fail_on_bind` errors at Bind and skips to Sync.
fn answer_extended(s: &mut TcpStream, fail_on_bind: bool) {
    let mut out = Vec::new();
    let mut skipping = false;
    loop {
        let Some((t, _)) = read_fe(s) else { return };
        if skipping && t != b'S' {
            continue;
        }
        match t {
            b'P' => out.extend(be(b'1', &[])),
            b'B' if fail_on_bind => {
                out.extend(be(b'E', b"SERROR\0VERROR\0C22P02\0Mbad input\0\0"));
                skipping = true;
            }
            b'B' => out.extend(be(b'2', &[])),
            b'D' => {
                let mut rd = 1i16.to_be_bytes().to_vec();
                rd.extend_from_slice(b"x\0");
                rd.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 255, 255, 255, 255, 255, 255, 0, 0]);
                out.extend(be(b'T', &rd));
            }
            b'E' => {
                let mut d = 1i16.to_be_bytes().to_vec();
                d.extend_from_slice(&2i32.to_be_bytes());
                d.extend_from_slice(b"hi");
                out.extend(be(b'D', &d));
                out.extend(be(b'C', b"SELECT 1\0"));
            }
            b'C' => out.extend(be(b'3', &[])),
            b'S' => {
                out.extend(z(b'I'));
                s.write_all(&out).unwrap();
                out.clear();
                return;
            }
            _ => return,
        }
    }
}

#[test]
fn extended_query_and_state() {
    let (dsn, h) = fake("17.11", |s| {
        answer_extended(s, false); // query()
        answer_extended(s, true); // query() with a server error
        answer_extended(s, false); // named statement parse (+ sync)
        answer_extended(s, false); // close (+ sync)
    });
    let (mut c, v) = connect_admitted(&cfg(&dsn), None).unwrap();
    assert_eq!(v.token(), "17.11");
    assert!(c.state().is_clean());
    assert_eq!(c.cancel_key().map(|k| k.pid), Some(7));

    let r = c.query("SELECT $1::text", &[Some("hi")], soon()).unwrap();
    assert_eq!(r.rows, vec![vec![Some("hi".to_string())]]);
    assert_eq!(r.tag, "SELECT 1");
    assert!(c.state().is_clean());

    match c.query("SELECT $1::int", &[Some("x")], soon()) {
        Err(Error::Db(e)) => assert_eq!(e.code, "22P02"),
        other => panic!("{other:?}"),
    }
    assert!(c.state().is_clean(), "error round ends synchronized: {:?}", c.state());
    assert_eq!(c.state().errors(), 1);

    let mut p = Pipeline::default();
    p.parse("s1", "SELECT 1", &[]).unwrap();
    p.sync();
    c.send(p, soon()).unwrap();
    assert_eq!(c.state().outstanding(), 2);
    assert_eq!(c.drain(soon()).unwrap(), TxnStatus::Idle);
    assert_eq!(c.state().open_statements().collect::<Vec<_>>(), vec!["s1"]);
    assert!(!c.state().is_clean(), "an open named statement blocks checkin");

    let mut p = Pipeline::default();
    p.close_statement("s1").unwrap();
    p.sync();
    c.send(p, soon()).unwrap();
    c.drain(soon()).unwrap();
    assert!(c.state().is_clean());
    c.terminate(Duration::from_millis(100));
    h.join().unwrap();
}

#[test]
fn error_skips_queued_messages_without_effect() {
    // Parse s2 fails; the server skips Bind/Execute up to Sync; s2 must not be recorded as open.
    let (dsn, h) = fake("18.6", |s| {
        let mut n = 0;
        loop {
            let Some((t, _)) = read_fe(s) else { return };
            n += 1;
            if t == b'P' {
                s.write_all(&be(b'E', b"SERROR\0VERROR\0C42601\0Msyntax\0\0")).unwrap();
            }
            if t == b'S' {
                s.write_all(&z(b'I')).unwrap();
                assert_eq!(n, 4);
                return;
            }
        }
    });
    let mut c = Connection::connect(&cfg(&dsn)).unwrap();
    let mut p = Pipeline::default();
    p.parse("s2", "SELEC", &[]).unwrap().bind("", "s2", &[]).unwrap().execute("", 0).unwrap().sync();
    c.send(p, soon()).unwrap();
    assert_eq!(c.drain(soon()).unwrap(), TxnStatus::Idle);
    assert_eq!(c.state().open_statements().count(), 0);
    assert!(c.state().is_clean());
    h.join().unwrap();
}

#[test]
fn txn_status_from_ready_for_query() {
    let (dsn, h) = fake("17.11", |s| {
        let _ = read_fe(s);
        s.write_all(&[be(b'C', b"BEGIN\0"), z(b'T')].concat()).unwrap();
        let _ = read_fe(s);
        s.write_all(&[be(b'E', b"SERROR\0VERROR\0C22012\0Mdiv\0\0"), z(b'E')].concat()).unwrap();
        let _ = read_fe(s);
        s.write_all(&[be(b'C', b"ROLLBACK\0"), z(b'I')].concat()).unwrap();
    });
    let mut c = Connection::connect(&cfg(&dsn)).unwrap();
    c.simple_query("BEGIN", soon()).unwrap();
    assert_eq!(c.state().txn_status(), Some(TxnStatus::InTransaction));
    assert!(!c.state().is_clean());
    assert!(matches!(c.simple_query("SELECT 1/0", soon()), Err(Error::Db(_))));
    assert_eq!(c.state().txn_status(), Some(TxnStatus::Failed));
    c.simple_query("ROLLBACK", soon()).unwrap();
    assert!(c.state().is_clean());
    h.join().unwrap();
}

#[test]
fn timeout_keeps_framing_and_drains_later() {
    let (dsn, h) = fake("17.11", |s| {
        let _ = read_fe(s);
        // Half a message, then a pause longer than the client's deadline, then the rest.
        let full = [be(b'C', b"SELECT 0\0"), z(b'I')].concat();
        s.write_all(&full[..3]).unwrap();
        s.flush().unwrap();
        thread::sleep(Duration::from_millis(400));
        s.write_all(&full[3..]).unwrap();
        thread::sleep(Duration::from_millis(200));
    });
    let mut c = Connection::connect(&cfg(&dsn)).unwrap();
    let r = c.simple_query("SELECT pg_sleep(1)", Instant::now() + Duration::from_millis(100));
    assert!(matches!(r, Err(Error::Timeout)), "{r:?}");
    assert!(c.state().unrecoverable().is_none());
    assert_eq!(c.state().pending_ready(), 1);
    assert_eq!(c.drain(soon()).unwrap(), TxnStatus::Idle);
    assert!(c.state().is_clean());
    h.join().unwrap();
}

#[test]
fn over_length_message_is_unrecoverable() {
    let (dsn, h) = fake("17.11", |s| {
        let _ = read_fe(s);
        let mut m = vec![b'D'];
        m.extend_from_slice(&(64i32 << 20).to_be_bytes());
        s.write_all(&m).unwrap();
        thread::sleep(Duration::from_millis(200));
    });
    let mut c = Connection::connect(&cfg(&dsn)).unwrap();
    let r = c.simple_query("SELECT 1", soon());
    assert!(matches!(r, Err(Error::Unrecoverable(Unrecoverable::Framing(_)))), "{r:?}");
    assert!(!c.state().is_clean());
    h.join().unwrap();
}

#[test]
fn desync_copy_listen_fatal_are_unrecoverable() {
    for (reply, want) in [
        (be(b'2', &[]), "desync"),
        (be(b'G', &[0, 0, 0]), "copy"),
        ([be(b'C', b"LISTEN\0"), z(b'I')].concat(), "listen"),
        (be(b'E', b"SFATAL\0VFATAL\0C57P01\0Mterminating\0\0"), "fatal"),
    ] {
        let (dsn, h) = fake("17.11", move |s| {
            let _ = read_fe(s);
            s.write_all(&reply).unwrap();
            thread::sleep(Duration::from_millis(100));
        });
        let mut c = Connection::connect(&cfg(&dsn)).unwrap();
        let r = c.simple_query("x", soon());
        let u = c.state().unrecoverable().cloned();
        let ok = match want {
            "desync" => matches!(u, Some(Unrecoverable::Desync(_))),
            "copy" => matches!(u, Some(Unrecoverable::Copy)),
            "listen" => matches!(u, Some(Unrecoverable::Listen)),
            _ => matches!(u, Some(Unrecoverable::Fatal(_))),
        };
        assert!(ok && r.is_err(), "{want}: {u:?} {r:?}");
        assert!(!c.is_reusable());
        h.join().unwrap();
    }
}

#[test]
fn idle_unsolicited_bytes_make_connection_non_reusable() {
    let (dsn, h) = fake("17.11", |s| {
        thread::sleep(Duration::from_millis(100));
        s.write_all(&be(b'E', b"SFATAL\0VFATAL\0C57P01\0Mterminating connection\0\0")).unwrap();
        s.shutdown(std::net::Shutdown::Both).unwrap();
    });
    let c = Connection::connect(&cfg(&dsn)).unwrap();
    assert!(c.is_reusable());
    h.join().unwrap();
    thread::sleep(Duration::from_millis(50));
    assert!(!c.is_reusable());
}

#[test]
fn version_gate_on_connect() {
    for (v, ok) in [("17.11", true), ("19rc1", false), ("19.0", false), ("17.10", false), ("18.6 (Debian)", true)] {
        let (dsn, h) = fake(v, |s| {
            let _ = read_fe(s);
        });
        let r = connect_admitted(&cfg(&dsn), None);
        assert_eq!(r.is_ok(), ok, "{v}");
        if let Err(e) = &r {
            assert!(matches!(e, ConnectError::Refused(_)), "{v}: {e}");
        }
        drop(r);
        h.join().unwrap();
    }
    // Recheck on a re-established pooled connection: same token admitted, different token refused.
    let (d1, h1) = fake("17.11", |_| {});
    let (_, a) = connect_admitted(&cfg(&d1), None).unwrap();
    h1.join().unwrap();
    let (d2, h2) = fake("17.12", |_| {});
    assert!(matches!(
        connect_admitted(&cfg(&d2), Some(&a)),
        Err(ConnectError::Refused(VersionRefusal::Changed { .. }))
    ));
    h2.join().unwrap();
}

// ------------------------------------------------------------------------------------------------- SCRAM

struct ScramServer {
    password: &'static str,
    corrupt_signature: bool,
    ok_before_final: bool,
}

fn scram_fake(srv: ScramServer) -> (String, thread::JoinHandle<()>) {
    let ls = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = ls.local_addr().unwrap().port();
    let h = thread::spawn(move || {
        let (mut s, _) = ls.accept().unwrap();
        read_startup(&mut s);
        s.write_all(&auth(10, b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0")).unwrap();
        let Some((_, init)) = read_fe(&mut s) else { return };
        // mechanism\0 len data
        let nul = init.iter().position(|&c| c == 0).unwrap();
        assert_eq!(&init[..nul], b"SCRAM-SHA-256");
        let data = std::str::from_utf8(&init[nul + 5..]).unwrap().to_string();
        let bare = data.strip_prefix("n,,").unwrap().to_string();
        let cnonce = bare.split(",r=").nth(1).unwrap().to_string();
        let salt = b"0123456789abcdef";
        let nonce = format!("{cnonce}srvnonce");
        let sf = format!("r={nonce},s={},i=4096", b64_encode(salt));
        s.write_all(&auth(11, sf.as_bytes())).unwrap();
        let Some((_, fin)) = read_fe(&mut s) else { return };
        let fin = String::from_utf8(fin).unwrap();
        let (cfwp, proof) = fin.rsplit_once(",p=").unwrap();
        let mut salted = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(4096).unwrap(),
            salt,
            srv.password.as_bytes(),
            &mut salted,
        );
        let sk = hmac::Key::new(hmac::HMAC_SHA256, &salted);
        let ck = hmac::sign(&sk, b"Client Key");
        let stored = digest::digest(&digest::SHA256, ck.as_ref());
        let am = format!("{bare},{sf},{cfwp}");
        let csig = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, stored.as_ref()), am.as_bytes());
        let want: Vec<u8> = ck.as_ref().iter().zip(csig.as_ref()).map(|(a, b)| a ^ b).collect();
        if proof != b64_encode(&want) {
            s.write_all(&be(b'E', b"SFATAL\0VFATAL\0C28P01\0Mpassword authentication failed\0\0")).unwrap();
            return;
        }
        if srv.ok_before_final {
            s.write_all(&ready_banner("17.11")).unwrap();
            return;
        }
        let server_key = hmac::sign(&sk, b"Server Key");
        let mut ssig =
            hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, server_key.as_ref()), am.as_bytes()).as_ref().to_vec();
        if srv.corrupt_signature {
            ssig[0] ^= 1;
        }
        let mut out = auth(12, format!("v={}", b64_encode(&ssig)).as_bytes());
        out.extend(ready_banner("17.11"));
        s.write_all(&out).unwrap();
        let _ = read_fe(&mut s);
    });
    (format!("postgresql://u:pencil@127.0.0.1:{port}/db"), h)
}

#[test]
fn scram_sha_256_exchange() {
    let (dsn, h) = scram_fake(ScramServer { password: "pencil", corrupt_signature: false, ok_before_final: false });
    let c = Connection::connect(&cfg(&dsn)).unwrap();
    assert_eq!(c.server_version(), Some("17.11"));
    assert!(c.state().is_clean());
    c.terminate(Duration::from_millis(100));
    h.join().unwrap();

    let (dsn, h) = scram_fake(ScramServer { password: "other", corrupt_signature: false, ok_before_final: false });
    assert!(matches!(Connection::connect(&cfg(&dsn)), Err(Error::Auth(_))));
    h.join().unwrap();

    let (dsn, h) = scram_fake(ScramServer { password: "pencil", corrupt_signature: true, ok_before_final: false });
    assert!(matches!(Connection::connect(&cfg(&dsn)), Err(Error::Scram(_))));
    h.join().unwrap();

    let (dsn, h) = scram_fake(ScramServer { password: "pencil", corrupt_signature: false, ok_before_final: true });
    assert!(matches!(Connection::connect(&cfg(&dsn)), Err(Error::Auth(_))), "AuthOk without server signature");
    h.join().unwrap();
}

#[test]
fn cleartext_and_md5_refused() {
    for req in [auth(3, &[]), auth(5, &[1, 2, 3, 4]), auth(7, &[])] {
        let ls = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = ls.local_addr().unwrap().port();
        let h = thread::spawn(move || {
            let (mut s, _) = ls.accept().unwrap();
            read_startup(&mut s);
            s.write_all(&req).unwrap();
            // The client must not answer with a password message.
            let mut b = [0u8; 1];
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let n = s.read(&mut b).unwrap_or(0);
            assert!(n == 0 || b[0] != b'p', "client sent a password message");
        });
        let r = Connection::connect(&cfg(&format!("postgresql://u:pw@127.0.0.1:{port}/db")));
        assert!(matches!(r, Err(Error::Auth(_))), "{r:?}");
        drop(r);
        h.join().unwrap();
    }
}

#[test]
fn nul_in_sql_or_names_refused_before_send() {
    let (dsn, h) = fake("17.11", |s| {
        s.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        assert!(read_fe(s).is_none(), "nothing may be sent");
    });
    let mut c = Connection::connect(&cfg(&dsn)).unwrap();
    assert!(matches!(c.query("SELECT 1\0; DROP TABLE t", &[], soon()), Err(Error::Usage(_))));
    let mut p = Pipeline::default();
    assert!(p.parse("a\0b", "SELECT 1", &[]).is_err());
    assert!(c.state().is_clean());
    h.join().unwrap();
    assert!(ConnectConfig::from_dsn("postgresql://u%00@h/d").is_err());
}

#[test]
fn backend_parser_never_panics() {
    // Deterministic xorshift sweep over every tag with random bodies, plus truncations of valid messages.
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..200_000 {
        let tag = (next() & 0xff) as u8;
        let len = (next() % 48) as usize;
        let body: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
        let _ = parse_backend(tag, &body);
    }
    let valid: Vec<(u8, Vec<u8>)> = vec![
        (b'T', {
            let mut rd = 1i16.to_be_bytes().to_vec();
            rd.extend_from_slice(b"x\0");
            rd.extend_from_slice(&[0; 18]);
            rd
        }),
        (b'D', [&1i16.to_be_bytes()[..], &2i32.to_be_bytes(), b"hi"].concat()),
        (b'E', b"SERROR\0C22P02\0Mm\0\0".to_vec()),
        (b'R', [&10i32.to_be_bytes()[..], b"SCRAM-SHA-256\0\0"].concat()),
        (b'A', [&1i32.to_be_bytes()[..], b"c\0p\0"].concat()),
    ];
    for (t, b) in valid {
        assert!(parse_backend(t, &b).is_ok(), "{}", t as char);
        for cut in 0..b.len() {
            assert!(parse_backend(t, &b[..cut]).is_err(), "{} cut {cut}", t as char);
        }
    }
    assert!(matches!(parse_backend(b'D', &[0, 1, 255, 255, 255, 255]), Ok(Backend::DataRow(v)) if v == vec![None]));
    assert!(parse_backend(b'D', &[0, 1, 0x7f, 255, 255, 255]).is_err(), "column length beyond body");
    assert!(parse_backend(b'D', &[255, 255]).is_err(), "negative column count");
}

#[test]
fn expected_reply_fifo_is_exposed() {
    let (dsn, h) = fake("17.11", |s| {
        let _ = read_fe(s);
        let _ = read_fe(s);
        let _ = read_fe(s);
        thread::sleep(Duration::from_millis(100));
    });
    let mut c = Connection::connect(&cfg(&dsn)).unwrap();
    let mut p = Pipeline::default();
    p.parse("", "SELECT 1", &[]).unwrap().describe_statement("").unwrap().sync();
    c.send(p, soon()).unwrap();
    let exp: Vec<Expect> = c.state().expected().cloned().collect();
    assert_eq!(exp, vec![Expect::Parse(String::new()), Expect::DescribeStatement { got_params: false }, Expect::Sync]);
    assert_eq!(c.state().pending_ready(), 1);
    assert!(!c.state().is_clean());
    h.join().unwrap();
}
