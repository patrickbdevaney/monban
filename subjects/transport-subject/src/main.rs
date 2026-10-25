//! transport-subject: aegis-transport behind an aegis-tls PublicWeb listener, for oracles/transport-stall and h2spec.
//!
//!   transport-subject [subject] [--port N] [--plain] [--no-wrapper] [--body-mib N] [--stat-ms N]
//!
//! Prints `PID <pid>` and `READY <port> <tls|plain> wrapper=<on|off>` on stdout, then a `STAT <t_ms> k=v ...` line
//! of the transport counters on stderr every `--stat-ms` (default 500). Routes (any vhost below):
//! `/` 200 `aegis ok\n` (at least 5 bytes, so h2spec 6.9.2/2 runs instead of skipping); `/big` 200 with
//! `--body-mib` MiB (default 64) generated chunk by chunk; `/echo` 200 with the request body length.
//! Vhosts: `aegis.test`, `localhost`, `127.0.0.1`, each also with `:<port>`.
//!
//! Limits are `aegis_config::Limits::default()` (F8 golden) mapped by name onto `WrapperLimits`.
//! `--no-wrapper` is the oracle negative control (feature `negative-control`): the AEGIS wrapper layer is off.
//! The certificate is a self-signed ECDSA-P256 credential generated at start-up (SAN aegis.test, localhost).
#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis_canon::Canon;
use aegis_canon::kind::{Authority, RoutePath};
use aegis_tls::{Profile, server_config};
use aegis_transport::exchange::{ExchangeBudget, FrontEnd, Head, HeadVerdict, MessageVerdict, Method, Mode};
use aegis_transport::{App, Reply, ReplyBody, Server, TlsAcceptor, VhostTable, WrapperLimits};
use aegis_types::RouteId;
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self, EcdsaKeyPair, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::{CertifiedKey, SingleCertAndKey};

type R<T> = Result<T, String>;

// ------------------------------------------------------------------------------------------------ credential

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

const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];

fn credential() -> R<Arc<SingleCertAndKey>> {
    let kp = EcdsaKeyPair::generate(&signature::ECDSA_P256_SHA256_ASN1_SIGNING).map_err(|e| format!("ecdsa: {e}"))?;
    let spki = kp.public_key().as_der().map_err(|e| format!("spki: {e}"))?;
    let alg = seq(&[&tlv(0x06, OID_ECDSA_SHA256)]);
    let name = seq(&[&tlv(0x31, &seq(&[&tlv(0x06, OID_CN), &tlv(0x0c, b"aegis.test")]))]);
    let validity = seq(&[&tlv(0x17, b"260101000000Z"), &tlv(0x18, b"20991231235959Z")]);
    let san = seq(&[&tlv(0x82, b"aegis.test"), &tlv(0x82, b"localhost")]);
    let exts = tlv(0xa3, &seq(&[&seq(&[&tlv(0x06, OID_SAN), &tlv(0x04, &san)])]));
    let tbs =
        seq(&[&tlv(0xa0, &tlv(0x02, &[2])), &tlv(0x02, &[1]), &alg, &name, &validity, &name, spki.as_ref(), &exts]);
    let sig = kp.sign(&SystemRandom::new(), &tbs).map_err(|e| format!("sign: {e}"))?;
    let cert = seq(&[&tbs, &alg, &tlv(0x03, &[&[0u8][..], sig.as_ref()].concat())]);
    let key = kp.to_pkcs8v1().map_err(|e| format!("pkcs8: {e}"))?;
    let ck = CertifiedKey::from_der(
        vec![CertificateDer::from(cert)],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.as_ref().to_vec())),
        &rustls::crypto::aws_lc_rs::default_provider(),
    )
    .map_err(|e| format!("credential: {e}"))?;
    Ok(Arc::new(SingleCertAndKey::from(ck)))
}

// ------------------------------------------------------------------------------------------------ front end

struct Subject {
    big: u64,
}

const BUDGET: ExchangeBudget = ExchangeBudget {
    max_message_bytes: 1 << 20,
    max_frame_bytes: 16_384,
    max_messages: 1,
    max_total_bytes: 1 << 20,
    stall_ms: 10_000,
};

impl FrontEnd for Subject {
    fn on_head(&self, _head: &Head<'_>) -> HeadVerdict {
        HeadVerdict::Accept(Mode::Unary, BUDGET)
    }
    fn on_message(&self, _head: &Head<'_>, _message: &[u8]) -> MessageVerdict {
        MessageVerdict::Continue
    }
}

impl App for Subject {
    fn route(&self, _a: &Canon<Authority>, path: &Canon<RoutePath>, _m: Method) -> Option<RouteId> {
        match path.as_bytes() {
            b"/" => RouteId::new(1).ok(),
            b"/big" => RouteId::new(2).ok(),
            b"/echo" => RouteId::new(3).ok(),
            _ => None,
        }
    }
    fn respond(&self, head: &Head<'_>, message: &[u8]) -> Reply {
        match head.route.get() {
            2 => Reply::new(200, "application/octet-stream", ReplyBody::Fill { len: self.big, byte: 0xA5 }),
            3 => Reply::new(200, "text/plain", ReplyBody::Owned(message.len().to_string().into_bytes())),
            _ => Reply::new(200, "text/plain", ReplyBody::Static(b"aegis ok\n")),
        }
    }
}

// ------------------------------------------------------------------------------------------------ main

struct Opts {
    port: u16,
    plain: bool,
    wrapper: bool,
    body_mib: u64,
    stat_ms: u64,
}

fn opts() -> R<Opts> {
    let args: Vec<String> = std::env::args().skip(1).filter(|a| a != "subject").collect();
    let mut o = Opts { port: 0, plain: false, wrapper: true, body_mib: 64, stat_ms: 500 };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut num =
            |what: &str| -> R<u64> { it.next().and_then(|v| v.parse().ok()).ok_or(format!("{what} needs a number")) };
        match a.as_str() {
            "--port" => o.port = u16::try_from(num("--port")?).map_err(|e| e.to_string())?,
            "--body-mib" => o.body_mib = num("--body-mib")?,
            "--stat-ms" => o.stat_ms = num("--stat-ms")?.max(50),
            "--plain" => o.plain = true,
            "--no-wrapper" => o.wrapper = false,
            _ => return Err(format!("unknown argument {a}")),
        }
    }
    Ok(o)
}

fn limits() -> R<WrapperLimits> {
    let f8 = aegis_config::Limits::default();
    let mut l = WrapperLimits::GOLDEN;
    for (&(name, ..), v) in aegis_config::Limits::BOUNDS.iter().zip(f8.values()) {
        l.set_f8(name, v).map_err(|e| format!("limits.{name}: {e}"))?;
    }
    Ok(l)
}

async fn run(o: Opts) -> R<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", o.port)).await.map_err(|e| format!("bind: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let mut vhosts = VhostTable::new();
    // `127.0.0.1` is the address the listener is bound to: clients that address it directly (h2spec via
    // oracles/h2-conformance) must reach the routes, not a 421 that would end every stream before its request does.
    for h in ["aegis.test", "localhost", "127.0.0.1"] {
        vhosts.add(h.as_bytes(), &[]);
        vhosts.add(format!("{h}:{port}").as_bytes(), &[]);
    }
    let app = Subject { big: o.body_mib.saturating_mul(1 << 20) };
    let l = limits()?;
    let srv = if o.wrapper { Server::new(app, vhosts, l) } else { Server::new_without_wrapper(app, vhosts, l) }
        .map_err(|e| format!("limits: {e}"))?;
    let acceptor = if o.plain {
        None
    } else {
        let mut cfg = server_config(Profile::PublicWeb, credential()?).map_err(|e| format!("tls: {e}"))?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Some(TlsAcceptor::from(Arc::new(cfg)))
    };
    {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "PID {}", std::process::id());
        let _ = writeln!(
            out,
            "READY {port} {} wrapper={}",
            if o.plain { "plain" } else { "tls" },
            if o.wrapper { "on" } else { "off" }
        );
        let _ = out.flush();
    }
    let stats = srv.clone();
    let start = Instant::now();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(o.stat_ms)).await;
            let kv: Vec<String> = stats.counters().snapshot().iter().map(|(k, v)| format!("{k}={v}")).collect();
            eprintln!("STAT {} {}", start.elapsed().as_millis(), kv.join(" "));
        }
    });
    loop {
        let Ok((sock, _)) = listener.accept().await else { continue };
        let _ = sock.set_nodelay(true);
        let srv = srv.clone();
        match &acceptor {
            Some(a) => {
                tokio::spawn(srv.serve_tls(sock, a.clone()));
            }
            None => {
                tokio::spawn(srv.serve_plain(sock));
            }
        }
    }
}

fn main() -> ExitCode {
    let o = match opts() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("transport-subject: {e}");
            return ExitCode::from(2);
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("transport-subject: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(run(o)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("transport-subject: {e}");
            ExitCode::FAILURE
        }
    }
}
