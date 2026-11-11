//! acme-subject: monban-ops ACME + CERT-1..4 over the oracles/acme-pebble `--subject` protocol.
//!
//!   acme-subject --directory URL --acme-ca PEM --domain NAME --https-addr IP:PORT --http01-addr IP:PORT
//!                [--profile P-PUBLIC-WEB] [--no-renew] [--ari-min-secs N] [--ari-max-secs N]
//!                [--poll-min-secs N] [--poll-max-secs N] [--tick-ms N] [--mutate NAME]...
//!
//! Obtains a certificate from the ACME directory (HTTP-01 answered on --http01-addr), installs it through the
//! CERT-3 preflight into the swappable `CertStore`, serves it over TLS on --https-addr (monban-tls `server_config`),
//! and renews when the injected clock reaches the RFC 9773 renewal time. One JSON object per stdout line.
//!
//! stdin commands (one per line): `offset <secs>` (set the injected clock offset), `advance <secs>`, `status`,
//! `quit`.
//!
//! `--mutate` (oracle self-test only): `wrong-jws-key`, `replay-nonce`, `tamper-order` (CSR names another domain),
//! `tamper-chain` (flip a byte of the leaf signature before install), `skip-preflight`, `silence-alerts`.
#![forbid(unsafe_code)]

use std::io::{BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use monban_ops::acme::json::quote;
use monban_ops::acme::{AcmeClient, AcmeConfig, AcmeError, AcmeEvent, Faults, Http01Tokens, Issued, PollBounds, ari};
use monban_ops::cert::time::format_rfc3339;
use monban_ops::cert::x509::{hex, parse_cert, pem_certificates};
use monban_ops::cert::{CertStore, Clock, ExpiryTracker, OffsetClock, PreflightReport, SystemClock};
use monban_tls::Profile;
use rustls::pki_types::CertificateDer;
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, ServerConnection, StreamOwned};

fn emit(line: &str) {
    let out = std::io::stdout();
    let mut l = out.lock();
    let _ = writeln!(l, "{line}");
    let _ = l.flush();
}

fn emit_error(stage: &str, e: &dyn std::fmt::Display) {
    let detail = e.to_string();
    emit(&format!(r#"{{"event":"error","stage":{},"detail":{}}}"#, quote(stage), quote(&detail)));
}

#[derive(Debug)]
struct Args {
    directory: String,
    acme_ca: String,
    domain: String,
    https_addr: String,
    http01_addr: String,
    profile: Profile,
    no_renew: bool,
    ari_min: u64,
    ari_max: u64,
    poll_min: u64,
    poll_max: u64,
    tick_ms: u64,
    mutate: Vec<String>,
}

const MUTATIONS: [&str; 6] =
    ["wrong-jws-key", "replay-nonce", "tamper-order", "tamper-chain", "skip-preflight", "silence-alerts"];

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        directory: String::new(),
        acme_ca: String::new(),
        domain: String::new(),
        https_addr: String::new(),
        http01_addr: String::new(),
        profile: Profile::PublicWeb,
        no_renew: false,
        ari_min: 60,
        ari_max: 86_400,
        poll_min: 1,
        poll_max: 30,
        tick_ms: 200,
        mutate: Vec::new(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut val = || it.next().ok_or(format!("{k} needs a value"));
        let num = |s: String| s.parse::<u64>().map_err(|_| format!("bad number {s}"));
        match k.as_str() {
            "--directory" => a.directory = val()?,
            "--acme-ca" => a.acme_ca = val()?,
            "--domain" => a.domain = val()?,
            "--https-addr" => a.https_addr = val()?,
            "--http01-addr" => a.http01_addr = val()?,
            "--profile" => {
                let n = val()?;
                a.profile = Profile::from_name(&n).ok_or(format!("unknown profile {n}"))?;
            }
            "--no-renew" => a.no_renew = true,
            "--ari-min-secs" => a.ari_min = num(val()?)?,
            "--ari-max-secs" => a.ari_max = num(val()?)?,
            "--poll-min-secs" => a.poll_min = num(val()?)?,
            "--poll-max-secs" => a.poll_max = num(val()?)?,
            "--tick-ms" => a.tick_ms = num(val()?)?.clamp(10, 10_000),
            "--mutate" => {
                let m = val()?;
                if !MUTATIONS.contains(&m.as_str()) {
                    return Err(format!("unknown mutation {m}"));
                }
                a.mutate.push(m);
            }
            _ => return Err(format!("unknown argument {k}")),
        }
    }
    if a.directory.is_empty()
        || a.acme_ca.is_empty()
        || a.domain.is_empty()
        || a.https_addr.is_empty()
        || a.http01_addr.is_empty()
    {
        return Err("required: --directory --acme-ca --domain --https-addr --http01-addr".into());
    }
    Ok(a)
}

// ------------------------------------------------------------------------------------------------ listeners

fn read_head<R: Read>(r: &mut R, cap: usize) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while buf.len() < cap {
        match r.read(&mut b) {
            Ok(1) => {
                buf.extend_from_slice(&b);
                if buf.ends_with(b"\r\n\r\n") {
                    return Some(buf);
                }
            }
            _ => return None,
        }
    }
    None
}

fn request_path(head: &[u8]) -> Option<String> {
    let line = head.split(|c| *c == b'\r').next()?;
    let s = std::str::from_utf8(line).ok()?;
    let mut p = s.split(' ');
    let (m, path, v) = (p.next()?, p.next()?, p.next()?);
    (m == "GET" && v.starts_with("HTTP/1.")).then(|| path.to_string())
}

fn serve_http01(l: TcpListener, tokens: Arc<Http01Tokens>) {
    let live = Arc::new(AtomicUsize::new(0));
    for s in l.incoming().flatten() {
        if live.load(Ordering::SeqCst) >= 64 {
            continue;
        }
        live.fetch_add(1, Ordering::SeqCst);
        let (tokens, live) = (tokens.clone(), live.clone());
        std::thread::spawn(move || {
            let mut s = s;
            let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
            let resp = match read_head(&mut s, 8192).and_then(|h| request_path(&h)).and_then(|p| tokens.respond(&p)) {
                Some(k) => format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{k}",
                    k.len()
                ),
                None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
            };
            let _ = s.write_all(resp.as_bytes());
            live.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

fn serve_https(l: TcpListener, cfg: Arc<ServerConfig>, store: Arc<CertStore>) {
    let live = Arc::new(AtomicUsize::new(0));
    for s in l.incoming().flatten() {
        if live.load(Ordering::SeqCst) >= 128 {
            continue;
        }
        live.fetch_add(1, Ordering::SeqCst);
        let (cfg, store, live) = (cfg.clone(), store.clone(), live.clone());
        std::thread::spawn(move || {
            https_conn(s, cfg, &store);
            live.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

fn https_conn(s: TcpStream, cfg: Arc<ServerConfig>, store: &CertStore) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(120)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(10)));
    let Ok(conn) = ServerConnection::new(cfg) else { return };
    let mut tls = StreamOwned::new(conn, s);
    // Keep-alive: answer requests until the peer closes (so the oracle can hold a connection across a swap).
    while read_head(&mut tls, 8192).is_some() {
        let (generation, serial) =
            store.current().map(|i| (i.generation, hex(&i.report.serial))).unwrap_or((0, String::new()));
        let body = format!(r#"{{"store_generation":{generation},"store_serial":"{serial}"}}"#);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        if tls.write_all(resp.as_bytes()).and_then(|_| tls.flush()).is_err() {
            return;
        }
    }
}

// ------------------------------------------------------------------------------------------------ lifecycle

struct Ctx {
    args: Args,
    client: AcmeClient,
    tokens: Arc<Http01Tokens>,
    store: Arc<CertStore>,
    clock: Arc<OffsetClock>,
    tracker: ExpiryTracker,
    renew_at: i64,
    ari_window: Option<(i64, i64)>,
    next_ari: Instant,
    backoff_until: Instant,
    renewals: u64,
    use_replaces: bool,
}

fn has(args: &Args, m: &str) -> bool {
    args.mutate.iter().any(|x| x == m)
}

fn flush_events(client: &mut AcmeClient) {
    for e in client.take_events() {
        if let AcmeEvent::BadNonceRetry { url } = e {
            emit(&format!(r#"{{"event":"bad_nonce_retry","url":{}}}"#, quote(&url)));
        }
    }
}

impl Ctx {
    fn obtain(&mut self, replaces: Option<&str>) -> Result<Issued, AcmeError> {
        let r = self.client.issue(std::slice::from_ref(&self.args.domain), self.tokens.as_ref(), replaces);
        flush_events(&mut self.client);
        r
    }

    /// Install through the CERT-3 preflight (or, under `skip-preflight`, without it).
    fn install(&mut self, mut issued: Issued) -> Result<(), String> {
        if has(&self.args, "tamper-chain")
            && let Some(leaf) = issued.chain.first_mut()
        {
            let mut v = leaf.as_ref().to_vec();
            if let Some(b) = v.last_mut() {
                *b ^= 0x01;
            }
            *leaf = CertificateDer::from(v);
        }
        let inst = if has(&self.args, "skip-preflight") {
            let key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&issued.key).map_err(|e| e.to_string())?;
            let (serial, nb, na) = issued
                .chain
                .first()
                .and_then(|c| parse_cert(c.as_ref()).ok().map(|i| (i.serial.to_vec(), i.not_before, i.not_after)))
                .unwrap_or_default();
            let report = PreflightReport {
                serial,
                not_before: nb,
                not_after: na,
                dns_names: Vec::new(),
                scheme: rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                seconds_to_expiry: na - self.clock.now(),
            };
            self.store.swap(Arc::new(CertifiedKey::new(issued.chain, key)), report)
        } else {
            match self.store.install_checked(issued.chain, &issued.key, self.args.profile, self.clock.as_ref(), &[]) {
                Ok(i) => i,
                Err(e) => {
                    emit(&format!(r#"{{"event":"preflight_rejected","detail":{}}}"#, quote(&e.to_string())));
                    return Err(e.to_string());
                }
            }
        };
        emit(&format!(
            r#"{{"event":"installed","generation":{},"serial":"{}","not_before":{},"not_after":{},"not_after_utc":"{}"}}"#,
            inst.generation,
            hex(&inst.report.serial),
            inst.report.not_before,
            inst.report.not_after,
            format_rfc3339(inst.report.not_after)
        ));
        Ok(())
    }

    fn leaf(&self) -> Option<Vec<u8>> {
        self.store.current().and_then(|i| i.key.cert.first().map(|c| c.as_ref().to_vec()))
    }

    /// Fetch ARI and pick the renewal time (RFC 9773 §4.3); fall back to 2/3 of the lifetime.
    fn refresh_ari(&mut self) {
        let Some(leaf) = self.leaf() else { return };
        let (nb, na) = parse_cert(&leaf).map(|c| (c.not_before, c.not_after)).unwrap_or((0, 0));
        let (renew_at, wait, src) = match self.client.renewal_info(&leaf) {
            Ok(Some(info)) => {
                let wait = ari::clamp_retry(info.retry_after, self.args.ari_min, self.args.ari_max, 6 * 3600);
                if self.ari_window == Some((info.start, info.end)) {
                    // Unchanged window: keep the time already drawn from it (RFC 9773 §4.3).
                    self.next_ari = Instant::now() + Duration::from_secs(wait);
                    return;
                }
                let t = ari::choose_renewal_time(&info, u64::from_le_bytes(rand8()));
                self.ari_window = Some((info.start, info.end));
                emit(&format!(
                    r#"{{"event":"ari","window_start":{},"window_end":{},"renew_at":{},"retry_after":{}}}"#,
                    info.start,
                    info.end,
                    t,
                    info.retry_after.map(|v| v.to_string()).unwrap_or_else(|| "null".into())
                ));
                (t, wait, "ari")
            }
            Ok(None) => (ari::fallback_renewal_time(nb, na), self.args.ari_max, "fallback"),
            Err(e) => {
                emit_error("ari", &e);
                (
                    ari::fallback_renewal_time(nb, na),
                    self.args.ari_max.min(60).max(self.args.ari_min.min(60)),
                    "fallback",
                )
            }
        };
        if src == "fallback" {
            self.ari_window = None;
            emit(&format!(r#"{{"event":"renewal_scheduled","source":"fallback","renew_at":{renew_at}}}"#));
        }
        self.renew_at = renew_at;
        self.next_ari = Instant::now() + Duration::from_secs(wait);
    }

    fn renew(&mut self) {
        let reason = if SystemClock.now() >= self.renew_at { "ari" } else { "clock" };
        emit(&format!(
            r#"{{"event":"renewing","reason":"{reason}","now":{},"renew_at":{}}}"#,
            self.clock.now(),
            self.renew_at
        ));
        let replaces = if self.use_replaces { self.leaf().and_then(|l| ari::cert_id(&l).ok()) } else { None };
        match self.obtain(replaces.as_deref()) {
            Ok(issued) => {
                if self.install(issued).is_ok() {
                    self.renewals += 1;
                    let i = self.store.current();
                    emit(&format!(
                        r#"{{"event":"swap","reason":"{reason}","generation":{},"serial":"{}","renewals":{}}}"#,
                        i.as_ref().map(|i| i.generation).unwrap_or(0),
                        i.as_ref().map(|i| hex(&i.report.serial)).unwrap_or_default(),
                        self.renewals
                    ));
                    self.use_replaces = true;
                    self.refresh_ari();
                } else {
                    self.backoff_until = Instant::now() + Duration::from_secs(5);
                }
            }
            Err(e) => {
                emit_error("renew", &e);
                if matches!(e, AcmeError::Problem { .. }) && replaces.is_some() {
                    // e.g. alreadyReplaced after a half-finished renewal: retry without `replaces`.
                    self.use_replaces = false;
                }
                self.backoff_until = Instant::now() + Duration::from_secs(5);
            }
        }
    }

    fn tick(&mut self) {
        if let Some(i) = self.store.current() {
            let o = self.tracker.observe(&i.report.serial, i.report.not_after, self.clock.now());
            if !has(&self.args, "silence-alerts") {
                for l in o.fired {
                    emit(&format!(
                        r#"{{"event":"alert","level":"{}","cert_seconds_to_expiry":{},"serial":"{}"}}"#,
                        l.name(),
                        o.seconds_to_expiry,
                        hex(&i.report.serial)
                    ));
                }
            }
        }
        if !self.args.no_renew && self.clock.now() >= self.renew_at && Instant::now() >= self.backoff_until {
            self.renew();
        }
        if Instant::now() >= self.next_ari {
            self.refresh_ari();
        }
    }

    fn status(&mut self) {
        let Some(i) = self.store.current() else { return };
        let now = self.clock.now();
        let secs = monban_ops::cert::seconds_to_expiry(i.report.not_after, now);
        let level = if has(&self.args, "silence-alerts") { "ok" } else { monban_ops::cert::alert_level(secs).name() };
        emit(&format!(
            r#"{{"event":"status","now":{now},"offset":{},"cert_seconds_to_expiry":{secs},"alert":"{level}","serial":"{}","generation":{},"renew_at":{},"renewals":{}}}"#,
            self.clock.offset(),
            hex(&i.report.serial),
            i.generation,
            self.renew_at,
            self.renewals
        ));
    }
}

fn rand8() -> [u8; 8] {
    use aws_lc_rs::rand::SecureRandom;
    let mut b = [0u8; 8];
    // On failure the window start is used (still inside the window).
    let _ = aws_lc_rs::rand::SystemRandom::new().fill(&mut b);
    b
}

fn run() -> Result<(), (u8, String)> {
    let args = parse_args().map_err(|e| (64, e))?;
    let ca_pem = std::fs::read_to_string(&args.acme_ca).map_err(|e| (66, format!("{}: {e}", args.acme_ca)))?;
    let roots: Vec<CertificateDer<'static>> = pem_certificates(&ca_pem)
        .filter(|v| !v.is_empty())
        .ok_or((66, "no certificate in --acme-ca".to_string()))?
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    let mut cfg = AcmeConfig::new(&args.directory, roots);
    cfg.poll = PollBounds {
        min_secs: args.poll_min,
        max_secs: args.poll_max,
        default_secs: args.poll_min.max(1),
        deadline_secs: 120,
    };
    cfg.faults = Faults {
        wrong_jws_key: has(&args, "wrong-jws-key"),
        replay_nonce: has(&args, "replay-nonce"),
        csr_wrong_identifier: has(&args, "tamper-order"),
    };
    let tokens = Arc::new(Http01Tokens::new());
    let h01 = TcpListener::bind(&args.http01_addr).map_err(|e| (69, format!("bind {}: {e}", args.http01_addr)))?;
    let https = TcpListener::bind(&args.https_addr).map_err(|e| (69, format!("bind {}: {e}", args.https_addr)))?;
    {
        let t = tokens.clone();
        std::thread::spawn(move || serve_http01(h01, t));
    }
    let client = AcmeClient::connect(cfg).map_err(|e| {
        emit_error("connect", &e);
        (2, e.to_string())
    })?;
    let store = Arc::new(CertStore::new());
    let mut ctx = Ctx {
        args,
        client,
        tokens,
        store: store.clone(),
        clock: Arc::new(OffsetClock::new()),
        tracker: ExpiryTracker::new(),
        renew_at: i64::MAX,
        ari_window: None,
        next_ari: Instant::now(),
        backoff_until: Instant::now(),
        renewals: 0,
        use_replaces: true,
    };
    let issued = ctx.obtain(None).map_err(|e| {
        emit_error("issue", &e);
        (2, e.to_string())
    })?;
    ctx.install(issued).map_err(|e| (3, e))?;
    let scfg = monban_tls::server_config(ctx.args.profile, store.clone()).map_err(|e| (70, e.to_string()))?;
    let scfg = Arc::new(scfg);
    std::thread::spawn(move || serve_https(https, scfg, store));
    emit(&format!(
        r#"{{"event":"ready","https_addr":{},"domain":{},"account":{}}}"#,
        quote(&ctx.args.https_addr),
        quote(&ctx.args.domain),
        quote(ctx.client.account_url().unwrap_or(""))
    ));
    ctx.refresh_ari();

    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(l) = line else { break };
            if tx.send(l).is_err() {
                break;
            }
        }
        let _ = tx.send("quit".into());
    });
    let tick = Duration::from_millis(ctx.args.tick_ms);
    loop {
        match rx.recv_timeout(tick) {
            Ok(cmd) => {
                let mut p = cmd.split_whitespace();
                match (p.next(), p.next().map(str::parse::<i64>)) {
                    (Some("offset"), Some(Ok(n))) => {
                        ctx.clock.set_offset(n);
                        emit(&format!(r#"{{"event":"clock","offset":{n}}}"#));
                        ctx.tick();
                    }
                    (Some("advance"), Some(Ok(n))) => {
                        ctx.clock.advance(n);
                        emit(&format!(r#"{{"event":"clock","offset":{}}}"#, ctx.clock.offset()));
                        ctx.tick();
                    }
                    (Some("status"), None) => {
                        ctx.tick();
                        ctx.status();
                    }
                    (Some("quit"), None) => break,
                    _ => emit(&format!(r#"{{"event":"error","stage":"command","detail":{}}}"#, quote(&cmd))),
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => ctx.tick(),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    emit(r#"{"event":"exit"}"#);
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, msg)) => {
            eprintln!("acme-subject: {msg}");
            ExitCode::from(code)
        }
    }
}
