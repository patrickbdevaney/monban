//! Interop server shared by `lcx-server` (libcrux provider) and `awslc-server` (rustls aws-lc-rs provider).
//!
//!   <bin> --port P --cert CHAIN.pem --key KEY.pem [--group G] [--suite S] [--count N]
//!     G: x25519mlkem768 | x25519 | secp256r1 | all      (default all)
//!     S: aes128gcm | aes256gcm | chacha20 | all          (default all)
//!
//! TLS 1.3 only. Prints `listening <port>`, then per connection exactly one stderr line
//!   `interop: handshake ok group=0x<hex4> suite=0x<hex4> sig=<scheme>`
//! (or `interop: error <msg>`), echoes application data until the peer closes, and exits after N connections
//! (exit 0 only if every connection completed its handshake).
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{CipherSuite, NamedGroup, ServerConfig, ServerConnection};

struct Args {
    port: u16,
    cert: String,
    key: String,
    group: String,
    suite: String,
    count: u32,
}

fn parse() -> Result<Args, String> {
    let mut a = Args { port: 0, cert: String::new(), key: String::new(), group: "all".into(), suite: "all".into(), count: 1 };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let v = it.next().ok_or_else(|| format!("usage: missing value for {k}"))?;
        match k.as_str() {
            "--port" => a.port = v.parse().map_err(|_| "usage: bad --port".to_string())?,
            "--cert" => a.cert = v,
            "--key" => a.key = v,
            "--group" => a.group = v,
            "--suite" => a.suite = v,
            "--count" => a.count = v.parse().map_err(|_| "usage: bad --count".to_string())?,
            _ => return Err(format!("usage: unknown flag {k}")),
        }
    }
    if a.cert.is_empty() || a.key.is_empty() {
        return Err("usage: --cert and --key are required".into());
    }
    Ok(a)
}

pub fn group_named(name: &str) -> Option<NamedGroup> {
    match name {
        "x25519mlkem768" => Some(NamedGroup::X25519MLKEM768),
        "x25519" => Some(NamedGroup::X25519),
        "secp256r1" => Some(NamedGroup::secp256r1),
        _ => None,
    }
}

pub fn suite_named(name: &str) -> Option<CipherSuite> {
    match name {
        "aes128gcm" => Some(CipherSuite::TLS13_AES_128_GCM_SHA256),
        "aes256gcm" => Some(CipherSuite::TLS13_AES_256_GCM_SHA384),
        "chacha20" => Some(CipherSuite::TLS13_CHACHA20_POLY1305_SHA256),
        _ => None,
    }
}

/// Restrict a provider to one group and/or one suite (from the CLI names); errors if nothing is left.
pub fn restrict(mut p: CryptoProvider, group: &str, suite: &str) -> Result<CryptoProvider, String> {
    if group != "all" {
        let g = group_named(group).ok_or_else(|| format!("usage: unknown group {group}"))?;
        p.kx_groups.retain(|k| k.name() == g);
    }
    if suite != "all" {
        let s = suite_named(suite).ok_or_else(|| format!("usage: unknown suite {suite}"))?;
        p.cipher_suites.retain(|c| c.suite() == s);
    }
    p.cipher_suites.retain(|c| c.tls13().is_some());
    if p.kx_groups.is_empty() || p.cipher_suites.is_empty() {
        return Err("provider has no matching group or suite".into());
    }
    Ok(p)
}

pub fn server_config(p: CryptoProvider, cert: &str, key: &str) -> Result<Arc<ServerConfig>, String> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|e| format!("cert: {e}"))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("cert: {e}"))?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("key: {e}"))?;
    let cfg = ServerConfig::builder_with_provider(Arc::new(p))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("config: {e}"))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| format!("config: {e}"))?;
    Ok(Arc::new(cfg))
}

fn serve_one(cfg: &Arc<ServerConfig>, listener: &TcpListener) -> Result<(), String> {
    let (mut sock, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(20))).map_err(|e| e.to_string())?;
    let mut conn = ServerConnection::new(cfg.clone()).map_err(|e| e.to_string())?;
    while conn.is_handshaking() {
        if let Err(e) = conn.complete_io(&mut sock) {
            let _ = conn.write_tls(&mut sock);
            return Err(format!("handshake: {e}"));
        }
    }
    let group = conn.negotiated_key_exchange_group().map(|g| u16::from(g.name())).unwrap_or(0);
    let suite = conn.negotiated_cipher_suite().map(|s| u16::from(s.suite())).unwrap_or(0);
    let sig = conn.handshake_kind().map(|k| format!("{k:?}")).unwrap_or_default();
    eprintln!("interop: handshake ok group=0x{group:04x} suite=0x{suite:04x} kind={sig}");
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    let mut buf = [0u8; 4096];
    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let data = buf.get(..n).ok_or("read overflow")?;
                tls.write_all(data).map_err(|e| format!("write: {e}"))?;
                tls.flush().map_err(|e| format!("flush: {e}"))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    conn.send_close_notify();
    let _ = conn.complete_io(&mut sock);
    Ok(())
}

pub fn main_with(provider: CryptoProvider) -> ExitCode {
    let a = match parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let cfg = match restrict(provider, &a.group, &a.suite).and_then(|p| server_config(p, &a.cert, &a.key)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("interop: error {e}");
            return ExitCode::from(2);
        }
    };
    let listener = match TcpListener::bind(("127.0.0.1", a.port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("interop: error bind: {e}");
            return ExitCode::from(2);
        }
    };
    let port = listener.local_addr().map(|s| s.port()).unwrap_or(0);
    println!("listening {port}");
    let _ = std::io::stdout().flush();
    let mut failed = 0u32;
    for _ in 0..a.count {
        if let Err(e) = serve_one(&cfg, &listener) {
            eprintln!("interop: error {e}");
            failed += 1;
        }
    }
    if failed == 0 { ExitCode::SUCCESS } else { ExitCode::from(1) }
}
