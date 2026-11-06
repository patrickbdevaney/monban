//! aegis-otlp: out-of-process OTLP/HTTP JSON exporter (PREFLIGHT D-P7.6). No OpenTelemetry, prost or tonic crates.
//!
//! ```text
//! aegis-otlp --scrape <http://127.0.0.1:P/metrics | unix:/abs/path.sock> --endpoint <http(s)://host:port[/prefix]>
//!            --service-name S [--interval-ms N] [--resource-attr k=v]... [--once]
//!            [--ca-file roots.pem] [--tls-profile P-PUBLIC-WEB]
//! ```
//!
//! - Scrapes the admin listener's OpenMetrics text, parses it with a bounded parser ([`om`]) and POSTs
//!   `<endpoint>/v1/metrics`; an exposition without `# EOF` (or otherwise malformed) is rejected whole.
//! - Reads log lines on stdin (bounded lines, [`queue`]), maps them to OTLP log records ([`logs`]) and POSTs
//!   `<endpoint>/v1/logs`. The queue is bounded and drops the oldest record when full; the drop count is exported
//!   as the self-metric `aegis_otlp_dropped_log_records`.
//! - `--once`: read stdin to EOF, scrape exactly once, POST, exit 0 only if the scrape parsed and every POST got a
//!   2xx. Otherwise: scrape every `--interval-ms` (default 10000), flush logs every min(interval, 1 s).
//! - `https` endpoints use the aegis-tls client profile (`--tls-profile`, default `P-PUBLIC-WEB`) with the roots in
//!   `--ca-file` only (no platform trust store).
//!
//! The contract and mapping rules are oracles/otlp-export/README.md (gate `otlp-export`).
#![forbid(unsafe_code)]

mod jsonw;
mod logs;
mod net;
mod om;
mod otlp;
mod queue;

use std::io::Read as _;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use net::{Poster, Scrape};
use otlp::{Envelope, Times};
use queue::Shared;

/// Records per logs request.
const LOG_BATCH: usize = 512;
/// Encoded bytes per logs request (soft cap: one record may exceed it on its own).
const LOG_BATCH_BYTES: usize = 4 * 1024 * 1024;
/// Largest `--ca-file`.
const MAX_CA_FILE: u64 = 1024 * 1024;
/// Most `--resource-attr` flags.
const MAX_RESOURCE_ATTRS: usize = 64;

/// Wall-clock Unix nanoseconds (0 if the clock is before the epoch).
pub fn now_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)).unwrap_or(0)
}

#[derive(Debug)]
struct Args {
    scrape: Scrape,
    endpoint: String,
    service_name: String,
    interval_ms: u64,
    resource_attrs: Vec<(String, String)>,
    once: bool,
    ca_file: Option<String>,
    tls_profile: String,
}

const USAGE: &str = "usage: aegis-otlp --scrape <http://host:port/path | unix:/abs/path.sock> --endpoint <URL> \
--service-name <S> [--interval-ms <N>] [--resource-attr k=v]... [--once] [--ca-file <roots.pem>] [--tls-profile <name>]";

fn parse_args(argv: impl Iterator<Item = String>) -> Result<Args, String> {
    let (mut scrape, mut endpoint, mut service, mut ca_file) = (None, None, None, None);
    let (mut interval_ms, mut once, mut attrs, mut profile) = (10_000u64, false, Vec::new(), None);
    let mut it = argv;
    while let Some(a) = it.next() {
        let (flag, inline) = match a.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (a.clone(), None),
        };
        if flag == "--once" {
            once = true;
            continue;
        }
        if flag == "--help" || flag == "-h" {
            return Err(USAGE.to_string());
        }
        let mut val = || inline.clone().or_else(|| it.next()).ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--scrape" => scrape = Some(Scrape::parse(&val()?)?),
            "--endpoint" => endpoint = Some(val()?),
            "--service-name" => service = Some(val()?),
            "--interval-ms" => {
                interval_ms = val()?.parse().map_err(|_| "--interval-ms needs a positive integer".to_string())?;
            }
            "--resource-attr" => {
                let v = val()?;
                let (k, x) = v.split_once('=').ok_or("--resource-attr needs k=v")?;
                if k.is_empty() || attrs.len() >= MAX_RESOURCE_ATTRS {
                    return Err("--resource-attr: empty key or too many".into());
                }
                attrs.push((k.to_string(), x.to_string()));
            }
            "--ca-file" => ca_file = Some(val()?),
            "--tls-profile" => profile = Some(val()?),
            _ => return Err(format!("unknown argument {a}\n{USAGE}")),
        }
    }
    let service_name: String = service.ok_or("--service-name is required")?;
    if service_name.is_empty() {
        return Err("--service-name must not be empty".into());
    }
    Ok(Args {
        scrape: scrape.ok_or("--scrape is required")?,
        endpoint: endpoint.ok_or("--endpoint is required")?,
        service_name,
        interval_ms: interval_ms.clamp(50, 86_400_000),
        resource_attrs: attrs,
        once,
        ca_file,
        tls_profile: profile.unwrap_or_else(|| "P-PUBLIC-WEB".to_string()),
    })
}

struct Exporter {
    args: Args,
    poster: Poster,
    env: Envelope,
    start_ns: u64,
    shared: Arc<Shared>,
    failed_exports: AtomicU64,
}

impl Exporter {
    fn fail(&self, what: &str) {
        self.failed_exports.fetch_add(1, Ordering::Relaxed);
        eprintln!("aegis-otlp: {what}");
    }

    /// Scrape once and POST the metrics. `true` only if the scrape parsed and the POST got a 2xx.
    async fn export_metrics(&self) -> bool {
        let body = match net::scrape(&self.args.scrape).await {
            Ok(b) => b,
            Err(e) => {
                self.fail(&e);
                return false;
            }
        };
        let t = Times { now: now_ns(), start: self.start_ns };
        let mut ms = String::with_capacity(body.len().saturating_mul(2));
        let _n = match om::parse(&body).and_then(|fams| otlp::metrics(&mut ms, &fams, t)) {
            Ok(n) => n,
            Err(e) => {
                self.fail(&format!("scrape rejected: {e}"));
                return false;
            }
        };
        let dropped = self.shared.queue().dropped();
        let failed = self.failed_exports.load(Ordering::Relaxed);
        for (name, desc, v) in [
            ("aegis_otlp_dropped_log_records", "Log records dropped because the bounded queue was full.", dropped),
            ("aegis_otlp_failed_exports", "Scrapes rejected or OTLP requests that did not get a 2xx.", failed),
        ] {
            if !ms.is_empty() {
                ms.push(',');
            }
            otlp::self_counter(&mut ms, name, desc, t, v);
        }
        let req = self.env.metrics_request(&ms);
        match self.poster.post(&self.poster.metrics, req.as_bytes()).await {
            Ok(()) => true,
            Err(e) => {
                self.fail(&e);
                false
            }
        }
    }

    /// POST everything queued, in batches. `true` if every POST got a 2xx (or nothing was queued).
    async fn flush_logs(&self) -> bool {
        let recs = self.shared.queue().drain();
        let mut ok = true;
        let mut rest = recs.as_slice();
        while !rest.is_empty() {
            let mut n = 0usize;
            let mut bytes = 0usize;
            for r in rest.iter().take(LOG_BATCH) {
                if n > 0 && bytes.saturating_add(r.len()) > LOG_BATCH_BYTES {
                    break;
                }
                bytes = bytes.saturating_add(r.len());
                n += 1;
            }
            let (batch, tail) = rest.split_at(n.min(rest.len()));
            rest = tail;
            let req = self.env.logs_request(batch.iter());
            if let Err(e) = self.poster.post(&self.poster.logs, req.as_bytes()).await {
                self.fail(&e);
                ok = false;
            }
        }
        ok
    }

    async fn once(&self) -> bool {
        let m = self.export_metrics().await;
        let l = self.flush_logs().await;
        m && l
    }

    async fn run(&self, stop: &AtomicBool) {
        let interval = Duration::from_millis(self.args.interval_ms);
        let log_every = interval.min(Duration::from_secs(1));
        let tick = Duration::from_millis(50).min(log_every);
        let mut next_metrics = Instant::now();
        let mut next_logs = Instant::now() + log_every;
        while !stop.load(Ordering::SeqCst) {
            let now = Instant::now();
            if now >= next_metrics {
                self.export_metrics().await;
                next_metrics = (next_metrics + interval).max(Instant::now());
            }
            let full = self.shared.queue().len() >= LOG_BATCH;
            if now >= next_logs || full {
                self.flush_logs().await;
                next_logs = Instant::now() + log_every;
            }
            tokio::time::sleep(tick).await;
        }
        self.flush_logs().await;
    }
}

fn setup() -> Result<Exporter, String> {
    let args = parse_args(std::env::args().skip(1))?;
    let tls = if args.endpoint.starts_with("https://") {
        let path = args.ca_file.as_deref().ok_or("https --endpoint needs --ca-file (no implicit trust)")?;
        let f = std::fs::File::open(path).map_err(|e| format!("--ca-file {path}: {e}"))?;
        let mut pem = Vec::new();
        f.take(MAX_CA_FILE + 1).read_to_end(&mut pem).map_err(|e| format!("--ca-file {path}: {e}"))?;
        if pem.len() as u64 > MAX_CA_FILE {
            return Err(format!("--ca-file {path}: larger than {MAX_CA_FILE} bytes"));
        }
        Some(net::tls_config(&args.tls_profile, &pem)?)
    } else {
        None
    };
    let poster = Poster::new(&args.endpoint, tls)?;
    let env = Envelope::new(&args.service_name, &args.resource_attrs);
    Ok(Exporter {
        args,
        poster,
        env,
        start_ns: now_ns(),
        shared: Arc::new(Shared::default()),
        failed_exports: AtomicU64::new(0),
    })
}

fn main() -> ExitCode {
    let ex = match setup() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("aegis-otlp: {e}");
            return ExitCode::from(2);
        }
    };
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("aegis-otlp: runtime: {e}");
            return ExitCode::from(2);
        }
    };
    if ex.args.once {
        queue::pump(&ex.shared, &mut std::io::stdin().lock());
        return if rt.block_on(ex.once()) { ExitCode::SUCCESS } else { ExitCode::from(1) };
    }
    let shared = ex.shared.clone();
    let reader = std::thread::Builder::new()
        .name("aegis-otlp-stdin".into())
        .spawn(move || queue::pump(&shared, &mut std::io::stdin().lock()));
    if let Err(e) = reader {
        eprintln!("aegis-otlp: stdin reader: {e}");
        return ExitCode::from(2);
    }
    let stop = Arc::new(AtomicBool::new(false));
    // SIGTERM / SIGINT stop the loop; `run` flushes the queued logs before it returns, then exit 0.
    for kind in [tokio::signal::unix::SignalKind::terminate(), tokio::signal::unix::SignalKind::interrupt()] {
        let sig = {
            let _rt = rt.enter();
            tokio::signal::unix::signal(kind)
        };
        match sig {
            Ok(mut sig) => {
                let stop = stop.clone();
                rt.spawn(async move {
                    sig.recv().await;
                    stop.store(true, Ordering::SeqCst);
                });
            }
            Err(e) => {
                eprintln!("aegis-otlp: signal handler: {e}");
                return ExitCode::from(2);
            }
        }
    }
    rt.block_on(ex.run(&stop));
    ExitCode::SUCCESS
}
