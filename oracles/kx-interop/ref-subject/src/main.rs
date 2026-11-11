//! kx-interop reference subject: implements the oracle's subject interop contract (README "Subject contract") on
//! plain rustls 0.23.46 + aws-lc-rs + the spike q4-026 0x11ED group, so the oracle's self-test has a subject that
//! can be green, and mutants of it that must be red. Never linked into Monban.
//!
//!   kx-ref [--mutant M] interop-server <PROFILE>
//!   kx-ref [--mutant M] interop-client <PROFILE> <CA_PEM> <NONCE>
//!
//! Profiles (written from ARCHITECTURE 3.2 / F12, independently of monban-tls): P-UNIVERSAL [0x11ED],
//! P-BSI-ALT [0x11ED, 0x11EB], P-CNSA [0x0202] (ML-DSA-87 credential), P-PUBLIC-WEB [0x11EC, 0x11EB, X25519, P-256].
//! Mutants: `order` (0x11ED combiner ML-KEM first), `x25519-fallback` (P-UNIVERSAL also accepts X25519),
//! `no-echo` (server: never echoes; client: never sends the nonce but still reports success), `bsi-11eb-first`
//! (P-BSI-ALT listed `[0x11EB, 0x11ED]`: the client shares 0x11EB up front, so no HRR happens; HRR liveness).
#![forbid(unsafe_code)]

mod kx;

use std::io::{Read, Write};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{self, KeyPair, PqdsaKeyPair};
use rustls::crypto::aws_lc_rs::{self as prov, kx_group};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, Connection, ServerConfig, ServerConnection};

type R<T> = Result<T, String>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mutant {
    None,
    Order,
    X25519Fallback,
    NoEcho,
    BsiSecondFirst,
}

fn groups(profile: &str, m: Mutant) -> R<Vec<&'static dyn SupportedKxGroup>> {
    let ed = kx::SECP384R1MLKEM1024;
    Ok(match profile {
        "P-UNIVERSAL" if m == Mutant::X25519Fallback => vec![ed, kx_group::X25519],
        "P-UNIVERSAL" => vec![ed],
        "P-BSI-ALT" if m == Mutant::BsiSecondFirst => vec![kx_group::SECP256R1MLKEM768, ed],
        "P-BSI-ALT" => vec![ed, kx_group::SECP256R1MLKEM768],
        "P-CNSA" => vec![kx_group::MLKEM1024],
        "P-PUBLIC-WEB" => {
            vec![kx_group::X25519MLKEM768, kx_group::SECP256R1MLKEM768, kx_group::X25519, kx_group::SECP256R1]
        }
        _ => return Err(format!("kx-ref: unknown profile {profile}")),
    })
}

fn provider(profile: &str, m: Mutant) -> R<Arc<CryptoProvider>> {
    Ok(Arc::new(CryptoProvider { kx_groups: groups(profile, m)?, ..prov::default_provider() }))
}

// ------------------------------------------------------------------------------------------------ credentials

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let n = content.len();
    if n < 0x80 {
        v.push(n as u8);
    } else {
        let bytes: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        v.push(0x80 | bytes.len() as u8);
        v.extend(bytes);
    }
    v.extend_from_slice(content);
    v
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

const OID_ML_DSA_87: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13];
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
const HOST: &[u8] = b"monban.test";

/// Self-signed ML-DSA-87 certificate (rcgen 0.14.10 has no ML-DSA signer without its unstable feature).
fn mldsa87() -> R<(Vec<u8>, Vec<u8>)> {
    let kp = PqdsaKeyPair::generate(&signature::ML_DSA_87_SIGNING).map_err(|e| format!("ml-dsa: {e}"))?;
    let spki = kp.public_key().as_der().map_err(|e| format!("ml-dsa spki: {e}"))?;
    let alg = seq(&[&tlv(0x06, OID_ML_DSA_87)]);
    let name = seq(&[&tlv(0x31, &seq(&[&tlv(0x06, OID_CN), &tlv(0x0c, HOST)]))]);
    let validity = seq(&[&tlv(0x17, b"260101000000Z"), &tlv(0x18, b"20991231235959Z")]);
    let san = seq(&[&tlv(0x82, HOST)]);
    let exts = tlv(0xa3, &seq(&[&seq(&[&tlv(0x06, OID_SAN), &tlv(0x04, &san)])]));
    let tbs =
        seq(&[&tlv(0xa0, &tlv(0x02, &[2])), &tlv(0x02, &[1]), &alg, &name, &validity, &name, spki.as_ref(), &exts]);
    let mut sig = vec![0u8; 4627];
    let n = kp.sign(&tbs, &mut sig).map_err(|e| format!("ml-dsa sign: {e}"))?;
    sig.truncate(n);
    let cert = seq(&[&tbs, &alg, &tlv(0x03, &[&[0u8][..], &sig].concat())]);
    let key = kp.to_pkcs8v1().map_err(|e| format!("ml-dsa pkcs8: {e}"))?;
    Ok((cert, key.as_ref().to_vec()))
}

fn ecdsa(alg: &'static rcgen::SignatureAlgorithm) -> R<(Vec<u8>, Vec<u8>)> {
    let kp = rcgen::KeyPair::generate_for(alg).map_err(|e| format!("ecdsa: {e}"))?;
    let params = rcgen::CertificateParams::new(vec!["monban.test".to_string()]).map_err(|e| format!("params: {e}"))?;
    let cert = params.self_signed(&kp).map_err(|e| format!("self_signed: {e}"))?;
    Ok((cert.der().to_vec(), kp.serialize_der()))
}

fn server_config(profile: &str, m: Mutant) -> R<Arc<ServerConfig>> {
    let (cert, key) = match profile {
        "P-CNSA" => mldsa87()?,
        "P-PUBLIC-WEB" => ecdsa(&rcgen::PKCS_ECDSA_P256_SHA256)?,
        _ => ecdsa(&rcgen::PKCS_ECDSA_P384_SHA384)?,
    };
    let mut cfg = ServerConfig::builder_with_provider(provider(profile, m)?)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert)], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))
        .map_err(|e| format!("credential: {e}"))?;
    // As monban-tls server_config (no resumption before P-PQ3).
    cfg.send_tls13_tickets = 0;
    Ok(Arc::new(cfg))
}

fn client_config(profile: &str, ca: &str, m: Mutant) -> R<Arc<ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(ca).map_err(|e| format!("ca {ca}: {e}"))? {
        roots.add(c.map_err(|e| format!("ca {ca}: {e}"))?).map_err(|e| format!("ca {ca}: {e}"))?;
    }
    let mut cfg = ClientConfig::builder_with_provider(provider(profile, m)?)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(cfg))
}

// ------------------------------------------------------------------------------------------------ stdio pump

fn report(c: &Connection) -> String {
    let g = c.negotiated_key_exchange_group().map(|g| u16::from(g.name())).unwrap_or(0);
    let v = c.protocol_version().map(u16::from).unwrap_or(0);
    let s = c.negotiated_cipher_suite().map(|s| u16::from(s.suite())).unwrap_or(0);
    format!("group=0x{g:04x} version=0x{v:04x} suite=0x{s:04x}")
}

fn flush(c: &mut Connection, out: &mut impl Write) -> R<()> {
    let mut buf = Vec::new();
    while c.wants_write() {
        c.write_tls(&mut buf).map_err(|e| e.to_string())?;
    }
    out.write_all(&buf).and_then(|_| out.flush()).map_err(|e| e.to_string())
}

/// Feed one stdin chunk into the connection. Returns Ok(false) on EOF.
fn ingest(c: &mut Connection, input: &mut impl Read, out: &mut impl Write) -> R<bool> {
    let mut buf = vec![0u8; 32768];
    let n = input.read(&mut buf).map_err(|e| e.to_string())?;
    let Some(mut rd) = buf.get(..n) else { return Err("read overflow".into()) };
    if rd.is_empty() {
        return Ok(false);
    }
    while !rd.is_empty() {
        if c.read_tls(&mut rd).map_err(|e| e.to_string())? == 0 {
            break;
        }
        if let Err(e) = c.process_new_packets() {
            let _ = flush(c, out);
            return Err(format!("tls: {e}"));
        }
    }
    Ok(true)
}

/// Drain readable plaintext; Ok(true) if the peer sent close_notify.
fn plaintext(c: &mut Connection, got: &mut Vec<u8>) -> R<bool> {
    let mut buf = vec![0u8; 16384];
    loop {
        match c.reader().read(&mut buf) {
            Ok(0) => return Ok(true),
            Ok(n) => got.extend_from_slice(buf.get(..n).unwrap_or_default()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) => return Err(e.to_string()),
        }
    }
}

fn serve(profile: &str, m: Mutant) -> R<()> {
    let mut c: Connection = ServerConnection::new(server_config(profile, m)?).map_err(|e| e.to_string())?.into();
    let (mut input, mut out) = (std::io::stdin().lock(), std::io::stdout().lock());
    let mut reported = false;
    loop {
        if !ingest(&mut c, &mut input, &mut out)? {
            return if reported { Ok(()) } else { Err("eof before handshake".into()) };
        }
        if !c.is_handshaking() && !reported {
            eprintln!("interop: handshake ok {}", report(&c));
            reported = true;
        }
        let mut got = Vec::new();
        let closed = plaintext(&mut c, &mut got)?;
        if !got.is_empty() && m != Mutant::NoEcho {
            c.writer().write_all(&got).map_err(|e| e.to_string())?;
        }
        if closed {
            c.send_close_notify();
            flush(&mut c, &mut out)?;
            return Ok(());
        }
        flush(&mut c, &mut out)?;
    }
}

fn client(profile: &str, ca: &str, nonce: &str, m: Mutant) -> R<()> {
    let name = ServerName::try_from("monban.test").map_err(|e| e.to_string())?;
    let mut c: Connection =
        ClientConnection::new(client_config(profile, ca, m)?, name).map_err(|e| e.to_string())?.into();
    let (mut input, mut out) = (std::io::stdin().lock(), std::io::stdout().lock());
    let want = format!("{nonce}\n");
    let (mut sent, mut got) = (false, Vec::new());
    flush(&mut c, &mut out)?;
    loop {
        if !ingest(&mut c, &mut input, &mut out)? {
            return Err("eof before echo".into());
        }
        if !c.is_handshaking() && !sent {
            eprintln!("interop: handshake ok {}", report(&c));
            if m == Mutant::NoEcho {
                eprintln!("interop: echo=ok");
                c.send_close_notify();
                return flush(&mut c, &mut out);
            }
            c.writer().write_all(want.as_bytes()).map_err(|e| e.to_string())?;
            sent = true;
        }
        let closed = plaintext(&mut c, &mut got)?;
        if sent && got.windows(want.len()).any(|w| w == want.as_bytes()) {
            eprintln!("interop: echo=ok");
            c.send_close_notify();
            return flush(&mut c, &mut out);
        }
        if closed {
            return Err("peer closed before echo".into());
        }
        flush(&mut c, &mut out)?;
    }
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut m = Mutant::None;
    if args.first().map(String::as_str) == Some("--mutant") {
        m = match args.get(1).map(String::as_str) {
            Some("order") => Mutant::Order,
            Some("x25519-fallback") => Mutant::X25519Fallback,
            Some("no-echo") => Mutant::NoEcho,
            Some("bsi-11eb-first") => Mutant::BsiSecondFirst,
            other => {
                eprintln!("kx-ref: unknown mutant {other:?}");
                return ExitCode::from(2);
            }
        };
        args.drain(..2);
    }
    if m == Mutant::Order {
        kx::ORDER_MUTANT.store(true, Ordering::Relaxed);
    }
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    let r = match a.as_slice() {
        ["interop-server", p] => serve(p, m),
        ["interop-client", p, ca, nonce] => client(p, ca, nonce, m),
        _ => {
            eprintln!("usage: kx-ref [--mutant M] interop-server PROFILE | interop-client PROFILE CA_PEM NONCE");
            return ExitCode::from(2);
        }
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("interop: error {e}");
            ExitCode::FAILURE
        }
    }
}
