//! q3-001 hsbench: TLS 1.3 handshake capacity of a single-threaded rustls/aws-lc-rs server on one core.
//!
//!   hsbench server --port P --group x25519|x25519mlkem768|p256mlkem768 --mode hs|reject --secs N [--tickets T]
//!   hsbench client --addr H:P --group G --mode hs|reject --resume 0|1 --threads N --secs N
//!
//! Server: one thread, nonblocking sockets + poll(2), many connections in flight, so the core is never idle waiting
//! for a client flight. `hs` = complete the handshake (incl. session tickets) then close_notify + close.
//! `reject` = complete the handshake, read one HTTP/1.1 request, answer `429` + close_notify, close
//! (the "reject-after-full-TLS" cost of an admission refusal). Server CPU is read with getrusage (single thread).
//! Client: blocking threads (pin them to other cores); accepts any certificate but verifies the handshake signature.
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, SupportedKxGroup, aws_lc_rs as prov};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, HandshakeKind, ServerConfig, ServerConnection,
    SignatureScheme,
};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const RESP_429: &[u8] =
    b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const REQ: &[u8] = b"GET / HTTP/1.1\r\nHost: monban.test\r\nUser-Agent: hsbench\r\n\r\n";

fn arg(a: &[String], k: &str, d: &str) -> String {
    a.iter().position(|x| x == k).and_then(|i| a.get(i + 1)).cloned().unwrap_or_else(|| d.to_string())
}

fn group(name: &str) -> &'static dyn SupportedKxGroup {
    match name {
        "x25519" => prov::kx_group::X25519,
        "x25519mlkem768" => prov::kx_group::X25519MLKEM768,
        "p256mlkem768" => prov::kx_group::SECP256R1MLKEM768,
        _ => panic!("unknown group {name}"),
    }
}

fn provider(g: &str) -> Arc<CryptoProvider> {
    let mut p = prov::default_provider();
    p.kx_groups = vec![group(g)];
    Arc::new(p)
}

fn cpu_us() -> u64 {
    let (u, s) = cpu_us_split();
    u + s
}
fn cpu_us_split() -> (u64, u64) {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: valid out-pointer.
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let tv = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
    (tv(ru.ru_utime), tv(ru.ru_stime))
}

// ------------------------------------------------------------------------------------------------ server
struct Conn {
    sock: TcpStream,
    tls: ServerConnection,
    req: Vec<u8>,
    counted: bool,
    closing: bool,
    dead: bool,
}

fn server(a: &[String]) {
    let port: u16 = arg(a, "--port", "8443").parse().unwrap();
    let g = arg(a, "--group", "x25519");
    let mode = arg(a, "--mode", "hs");
    let secs: u64 = arg(a, "--secs", "10").parse().unwrap();
    let warm: u64 = arg(a, "--warm", "2").parse().unwrap();
    let tickets: usize = arg(a, "--tickets", "2").parse().unwrap();
    let label = arg(a, "--label", "");

    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["monban.test".to_string()]).unwrap().self_signed(&kp).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(kp.serialize_der()));
    let mut cfg = ServerConfig::builder_with_provider(provider(&g))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert.der().to_vec())], key)
        .unwrap();
    cfg.ticketer = prov::Ticketer::new().unwrap();
    cfg.send_tls13_tickets = tickets;
    let cfg = Arc::new(cfg);

    let lst = TcpListener::bind(("0.0.0.0", port)).unwrap();
    lst.set_nonblocking(true).unwrap();
    let mut conns: Vec<Conn> = Vec::new();
    let mut pfds: Vec<libc::pollfd> = Vec::new();
    let (mut full, mut resumed, mut hrr, mut errs, mut accepted) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let t0 = Instant::now();
    let mut measuring = false;
    let (mut m_t, mut m_cpu, mut m_full, mut m_res) = (t0, 0u64, 0u64, 0u64);
    let mut m_split = (0u64, 0u64);
    let end = Duration::from_secs(warm + secs);
    let mut rbuf = [0u8; 4096];
    loop {
        let now = Instant::now();
        if !measuring && now - t0 >= Duration::from_secs(warm) {
            measuring = true;
            m_t = now;
            m_cpu = cpu_us();
            m_split = cpu_us_split();
            m_full = full;
            m_res = resumed;
        }
        if now - t0 >= end {
            break;
        }
        pfds.clear();
        pfds.push(libc::pollfd { fd: lst.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        for c in &conns {
            let mut ev = libc::POLLIN;
            if c.tls.wants_write() {
                ev |= libc::POLLOUT;
            }
            pfds.push(libc::pollfd { fd: c.sock.as_raw_fd(), events: ev, revents: 0 });
        }
        // SAFETY: pfds is a valid array of pollfd of the given length.
        let n = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, 50) };
        if n <= 0 {
            continue;
        }
        for (i, c) in conns.iter_mut().enumerate() {
            let re = pfds[i + 1].revents;
            if re == 0 {
                continue;
            }
            if re & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                loop {
                    match c.tls.read_tls(&mut c.sock) {
                        Ok(0) => {
                            c.dead = true;
                            break;
                        }
                        Ok(_) => {
                            if let Err(_) = c.tls.process_new_packets() {
                                errs += 1;
                                let _ = c.tls.write_tls(&mut c.sock);
                                c.dead = true;
                                break;
                            }
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => {
                            c.dead = true;
                            break;
                        }
                    }
                }
                if !c.dead && !c.tls.is_handshaking() {
                    if !c.counted {
                        c.counted = true;
                        match c.tls.handshake_kind() {
                            Some(HandshakeKind::Resumed) => resumed += 1,
                            Some(HandshakeKind::FullWithHelloRetryRequest) => {
                                hrr += 1;
                                full += 1
                            }
                            _ => full += 1,
                        }
                        if mode == "hs" {
                            c.tls.send_close_notify();
                            c.closing = true;
                        }
                    }
                    if mode == "reject" && !c.closing {
                        loop {
                            match c.tls.reader().read(&mut rbuf) {
                                Ok(0) => break,
                                Ok(k) => c.req.extend_from_slice(&rbuf[..k]),
                                Err(_) => break,
                            }
                        }
                        if c.req.windows(4).any(|w| w == b"\r\n\r\n") {
                            let _ = c.tls.writer().write_all(RESP_429);
                            c.tls.send_close_notify();
                            c.closing = true;
                        }
                    }
                }
            }
            if !c.dead {
                while c.tls.wants_write() {
                    match c.tls.write_tls(&mut c.sock) {
                        Ok(_) => {}
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => {
                            c.dead = true;
                            break;
                        }
                    }
                }
                if c.closing && !c.tls.wants_write() {
                    c.dead = true;
                }
            }
        }
        conns.retain(|c| !c.dead);
        if pfds[0].revents & libc::POLLIN != 0 {
            for _ in 0..256 {
                match lst.accept() {
                    Ok((s, _)) => {
                        s.set_nonblocking(true).unwrap();
                        let _ = s.set_nodelay(true);
                        accepted += 1;
                        conns.push(Conn {
                            sock: s,
                            tls: ServerConnection::new(cfg.clone()).unwrap(),
                            req: Vec::new(),
                            counted: false,
                            closing: false,
                            dead: false,
                        });
                    }
                    Err(_) => break,
                }
            }
        }
    }
    let wall = m_t.elapsed().as_secs_f64();
    let cpu = (cpu_us() - m_cpu) as f64;
    let (df, dr) = (full - m_full, resumed - m_res);
    let sp = cpu_us_split();
    let (du, ds) = (sp.0 - m_split.0, sp.1 - m_split.1);
    let hs = (df + dr) as f64;
    println!(
        "{{\"kind\":\"server\",\"label\":\"{label}\",\"group\":\"{g}\",\"mode\":\"{mode}\",\"tickets\":{tickets},\"secs\":{wall:.3},\"full\":{df},\"resumed\":{dr},\"hs_per_s\":{:.1},\"cpu_util\":{:.3},\"cpu_us_per_hs\":{:.2},\"user_us_per_hs\":{:.2},\"sys_us_per_hs\":{:.2},\"cap_hs_per_s_at_100pct\":{:.1},\"hrr_total\":{hrr},\"errs_total\":{errs},\"accepted_total\":{accepted},\"loadavg\":\"{}\"}}",
        hs / wall,
        cpu / 1e6 / wall,
        cpu / hs.max(1.0),
        du as f64 / hs.max(1.0),
        ds as f64 / hs.max(1.0),
        hs / (cpu / 1e6).max(1e-9),
        std::fs::read_to_string("/proc/loadavg").unwrap_or_default().trim()
    );
}

// ------------------------------------------------------------------------------------------------ client
#[derive(Debug)]
struct AnyCert(Arc<CryptoProvider>);
impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn client(a: &[String]) {
    let addr = arg(a, "--addr", "127.0.0.1:8443");
    let g = arg(a, "--group", "x25519");
    let mode = arg(a, "--mode", "hs");
    let resume = arg(a, "--resume", "0") == "1";
    let threads: usize = arg(a, "--threads", "16").parse().unwrap();
    let secs: u64 = arg(a, "--secs", "13").parse().unwrap();
    let p = provider(&g);
    let mut cfg = ClientConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(p)))
        .with_no_client_auth();
    cfg.resumption = if resume {
        rustls::client::Resumption::in_memory_sessions(4096)
    } else {
        rustls::client::Resumption::disabled()
    };
    let cfg = Arc::new(cfg);
    let stop = Arc::new(AtomicBool::new(false));
    let (ok, resumed, fail) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let mut hs = Vec::new();
    for _ in 0..threads {
        let (cfg, stop, ok, resumed, fail, addr, mode) =
            (cfg.clone(), stop.clone(), ok.clone(), resumed.clone(), fail.clone(), addr.clone(), mode.clone());
        hs.push(std::thread::spawn(move || {
            let mut sink = Vec::with_capacity(4096);
            while !stop.load(Ordering::Relaxed) {
                let r = (|| -> std::io::Result<bool> {
                    let sa: std::net::SocketAddr = addr.parse().map_err(std::io::Error::other)?;
                    let mut sock = TcpStream::connect_timeout(&sa, Duration::from_secs(2))?;
                    sock.set_nodelay(true)?;
                    sock.set_read_timeout(Some(Duration::from_secs(3)))?;
                    sock.set_write_timeout(Some(Duration::from_secs(3)))?;
                    let mut c = ClientConnection::new(cfg.clone(), ServerName::try_from("monban.test").unwrap())
                        .map_err(std::io::Error::other)?;
                    while c.is_handshaking() {
                        c.complete_io(&mut sock)?;
                    }
                    let res = c.handshake_kind() == Some(HandshakeKind::Resumed);
                    let mut s = rustls::Stream::new(&mut c, &mut sock);
                    if mode == "reject" {
                        s.write_all(REQ)?;
                    }
                    sink.clear();
                    match s.read_to_end(&mut sink) {
                        Ok(_) => {}
                        Err(e) if e.kind() == ErrorKind::UnexpectedEof => {}
                        Err(e) => return Err(e),
                    }
                    if mode == "reject" && !sink.starts_with(b"HTTP/1.1 429") {
                        return Err(std::io::Error::other("no 429"));
                    }
                    Ok(res)
                })();
                match r {
                    Ok(res) => {
                        ok.fetch_add(1, Ordering::Relaxed);
                        if res {
                            resumed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(e) => {
                        if fail.fetch_add(1, Ordering::Relaxed) < 3 && std::env::var("HS_DEBUG").is_ok() {
                            eprintln!("client error: {e:?}");
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        }));
    }
    std::thread::sleep(Duration::from_secs(secs));
    stop.store(true, Ordering::Relaxed);
    for h in hs {
        let _ = h.join();
    }
    println!(
        "{{\"kind\":\"client\",\"group\":\"{g}\",\"mode\":\"{mode}\",\"resume\":{resume},\"threads\":{threads},\"ok\":{},\"resumed\":{},\"fail\":{}}}",
        ok.load(Ordering::Relaxed),
        resumed.load(Ordering::Relaxed),
        fail.load(Ordering::Relaxed)
    );
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(|s| s.as_str()) {
        Some("server") => server(&a),
        Some("client") => client(&a),
        _ => eprintln!("usage: hsbench server|client ..."),
    }
}
