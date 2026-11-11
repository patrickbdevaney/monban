//! In-memory TLS 1.3 handshake cost: server on the libcrux provider vs server on rustls' aws-lc-rs provider.
//! The client is the same in both (rustls + aws-lc-rs, verifying the server chain against the test CA).
//!
//!   lcx-bench --ca CA.pem --cert CHAIN.pem --key KEY.pem [--n 400] [--warmup 40]
//!
//! For each group and each server provider, prints one line
//!   bench group=<g> server=<lcx|awslc> n=<n> server_us_p50=<..> server_us_p90=<..> total_us_p50=<..>
//! "server" = CPU-side time spent inside the server's read_tls/process_new_packets/write_tls calls only.
//! Runs are interleaved (lcx, awslc, lcx, ...) so drift on a shared box hits both sides.
#![forbid(unsafe_code)]

#[path = "../../provider/src/serve.rs"]
#[allow(dead_code)]
mod serve;

use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

fn arg(name: &str, default: &str) -> String {
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        if k == name {
            return it.next().unwrap_or_default();
        }
    }
    default.to_string()
}

fn pump(from: &mut dyn FnMut(&mut Vec<u8>) -> std::io::Result<usize>, buf: &mut Vec<u8>) -> Result<(), String> {
    buf.clear();
    from(buf).map_err(|e| e.to_string())?;
    Ok(())
}

/// One handshake; returns (server time, total time).
fn handshake(ccfg: &Arc<ClientConfig>, scfg: &Arc<ServerConfig>) -> Result<(Duration, Duration), String> {
    let start = Instant::now();
    let name = ServerName::try_from("monban.test").map_err(|e| e.to_string())?;
    let mut c = ClientConnection::new(ccfg.clone(), name).map_err(|e| e.to_string())?;
    let mut s = ServerConnection::new(scfg.clone()).map_err(|e| e.to_string())?;
    let mut srv = Duration::ZERO;
    let mut buf = Vec::with_capacity(16384);
    for _ in 0..16 {
        if !c.is_handshaking() && !s.is_handshaking() {
            let total = start.elapsed();
            return Ok((srv, total));
        }
        pump(&mut |b| c.write_tls(b), &mut buf)?;
        if !buf.is_empty() {
            let t = Instant::now();
            let mut rd: &[u8] = &buf;
            while !rd.is_empty() {
                s.read_tls(&mut rd).map_err(|e| e.to_string())?;
                s.process_new_packets().map_err(|e| format!("server: {e}"))?;
            }
            let mut out = Vec::with_capacity(16384);
            while s.wants_write() {
                s.write_tls(&mut out).map_err(|e| e.to_string())?;
            }
            srv += t.elapsed();
            let mut rd: &[u8] = &out;
            while !rd.is_empty() {
                c.read_tls(&mut rd).map_err(|e| e.to_string())?;
                c.process_new_packets().map_err(|e| format!("client: {e}"))?;
            }
        }
    }
    Err("handshake did not finish".into())
}

fn pct(v: &mut [Duration], p: usize) -> u128 {
    v.sort();
    let i = (v.len().saturating_sub(1) * p) / 100;
    v.get(i).map(|d| d.as_micros()).unwrap_or(0)
}

fn main() -> ExitCode {
    let (ca, cert, key) = (arg("--ca", ""), arg("--cert", ""), arg("--key", ""));
    let n: usize = arg("--n", "400").parse().unwrap_or(400);
    let warm: usize = arg("--warmup", "40").parse().unwrap_or(40);
    let mut roots = RootCertStore::empty();
    match CertificateDer::pem_file_iter(&ca) {
        Ok(it) => {
            for c in it.flatten() {
                let _ = roots.add(c);
            }
        }
        Err(e) => {
            eprintln!("bench: ca: {e}");
            return ExitCode::from(2);
        }
    }
    let roots = Arc::new(roots);
    let mut ok = true;
    for group in ["x25519mlkem768", "x25519", "secp256r1"] {
        let client = serve::restrict(rustls::crypto::aws_lc_rs::default_provider(), group, "all")
            .map_err(|e| e.to_string())
            .and_then(|p| {
                ClientConfig::builder_with_provider(Arc::new(p))
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .map_err(|e| e.to_string())
            })
            .map(|b| Arc::new(b.with_root_certificates(roots.clone()).with_no_client_auth()));
        let servers: Vec<(&str, Result<Arc<ServerConfig>, String>)> = vec![
            ("lcx", serve::restrict(lcx::provider(), group, "aes128gcm").and_then(|p| serve::server_config(p, &cert, &key))),
            (
                "awslc",
                serve::restrict(rustls::crypto::aws_lc_rs::default_provider(), group, "aes128gcm")
                    .and_then(|p| serve::server_config(p, &cert, &key)),
            ),
        ];
        let Ok(client) = client else {
            eprintln!("bench: client config failed");
            return ExitCode::from(2);
        };
        let mut cfgs = Vec::new();
        for (name, s) in servers {
            match s {
                Ok(c) => cfgs.push((name, c)),
                Err(e) => {
                    eprintln!("bench: {name} server config: {e}");
                    return ExitCode::from(2);
                }
            }
        }
        let mut res: Vec<(Vec<Duration>, Vec<Duration>)> = vec![(Vec::new(), Vec::new()); cfgs.len()];
        for i in 0..(warm + n) {
            for (j, (name, scfg)) in cfgs.iter().enumerate() {
                match handshake(&client, scfg) {
                    Ok((s, t)) if i >= warm => {
                        if let Some(r) = res.get_mut(j) {
                            r.0.push(s);
                            r.1.push(t);
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("bench: {group} {name}: {e}");
                        ok = false;
                    }
                }
            }
        }
        for ((name, _), (mut s, mut t)) in cfgs.iter().zip(res) {
            println!(
                "bench group={group} server={name} n={} server_us_p50={} server_us_p90={} total_us_p50={}",
                s.len(),
                pct(&mut s, 50),
                pct(&mut s, 90),
                pct(&mut t, 50)
            );
        }
    }
    if ok { ExitCode::SUCCESS } else { ExitCode::from(1) }
}
