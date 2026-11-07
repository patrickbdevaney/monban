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
//! - Each POST is retried on 429/502/503/504 and transport failures with bounded exponential backoff ([`retry`]);
//!   any other answer is final. A request given up is dropped and counted: its log records in
//!   `aegis_otlp_dropped_log_records`, its metric points in `aegis_otlp_dropped_metric_points`.
//! - Metrics and logs are exported by separate tasks, so a failing signal never stalls the other.
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
mod retry;

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
    /// Log records dropped after their request was given up (the queue's own drops are counted there).
    dropped_logs: AtomicU64,
    /// Metric points dropped after their request was given up.
    dropped_points: AtomicU64,
}

impl Exporter {
    fn fail(&self, what: &str) {
        self.failed_exports.fetch_add(1, Ordering::Relaxed);
        eprintln!("aegis-otlp: {what}");
    }

    /// POST with bounded retries; on a drop, add `items` to `counter`. `true` only if accepted.
    async fn post(
        &self,
        url: &aegis_egress::Url,
        body: &[u8],
        items: u64,
        counter: &AtomicU64,
        stop: &AtomicBool,
    ) -> bool {
        match retry::post(&self.poster, url, body, stop).await {
            retry::Outcome::Accepted => true,
            retry::Outcome::Dropped(n, e) => {
                counter.fetch_add(items, Ordering::Relaxed);
                self.fail(&format!("{e}; dropped after {n} attempt(s)"));
                false
            }
        }
    }

    /// Scrape once and POST the metrics (retried, never re-scraped). `true` only if the scrape parsed and the POST
    /// got a 2xx.
    async fn export_metrics(&self, stop: &AtomicBool) -> bool {
        let body = match net::scrape(&self.args.scrape).await {
            Ok(b) => b,
            Err(e) => {
                self.fail(&e);
                return false;
            }
        };
        let t = Times { now: now_ns(), start: self.start_ns };
        let mut ms = String::with_capacity(body.len().saturating_mul(2));
        let points =
            match om::parse(&body).and_then(|fams| otlp::metrics(&mut ms, &fams, t).map(|_| otlp::points(&fams))) {
                Ok(n) => n,
                Err(e) => {
                    self.fail(&format!("scrape rejected: {e}"));
                    return false;
                }
            };
        let dropped_logs = self.shared.queue().dropped().saturating_add(self.dropped_logs.load(Ordering::Relaxed));
        let dropped_points = self.dropped_points.load(Ordering::Relaxed);
        let failed = self.failed_exports.load(Ordering::Relaxed);
        for (name, desc, v) in [
            (
                "aegis_otlp_dropped_log_records",
                "Log records dropped: the bounded queue was full, or their request was given up after its retries.",
                dropped_logs,
            ),
            (
                "aegis_otlp_dropped_metric_points",
                "Metric points dropped: their request was given up after its retries.",
                dropped_points,
            ),
            ("aegis_otlp_failed_exports", "Scrapes rejected or OTLP requests that did not get a 2xx.", failed),
        ] {
            if !ms.is_empty() {
                ms.push(',');
            }
            otlp::self_counter(&mut ms, name, desc, t, v);
        }
        let req = self.env.metrics_request(&ms);
        self.post(&self.poster.metrics, req.as_bytes(), points.saturating_add(3), &self.dropped_points, stop).await
    }

    /// POST everything queued, in batches (each retried). `true` if every POST got a 2xx (or nothing was queued).
    async fn flush_logs(&self, stop: &AtomicBool) -> bool {
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
            let items = u64::try_from(batch.len()).unwrap_or(u64::MAX);
            ok &= self.post(&self.poster.logs, req.as_bytes(), items, &self.dropped_logs, stop).await;
        }
        ok
    }

    async fn once(&self) -> bool {
        let never = AtomicBool::new(false);
        let m = self.export_metrics(&never).await;
        let l = self.flush_logs(&never).await;
        m && l
    }

    /// Interval mode, metrics side: scrape and export every interval until `stop`.
    async fn metrics_loop(self: Arc<Self>, stop: Arc<AtomicBool>) {
        let interval = Duration::from_millis(self.args.interval_ms);
        let tick = Duration::from_millis(50);
        let mut next = Instant::now();
        while !stop.load(Ordering::SeqCst) {
            if Instant::now() >= next {
                self.export_metrics(&stop).await;
                next = (next + interval).max(Instant::now());
            }
            tokio::time::sleep(tick.min(next.saturating_duration_since(Instant::now())).max(Duration::from_millis(1)))
                .await;
        }
    }

    /// Interval mode, logs side: flush every min(interval, 1 s) (or when a batch is full) until `stop`, then flush
    /// what is queued once more (one attempt per request: `stop` is set).
    async fn logs_loop(self: Arc<Self>, stop: Arc<AtomicBool>) {
        let log_every = Duration::from_millis(self.args.interval_ms).min(Duration::from_secs(1));
        let tick = Duration::from_millis(50).min(log_every);
        let mut next = Instant::now() + log_every;
        while !stop.load(Ordering::SeqCst) {
            let full = self.shared.queue().len() >= LOG_BATCH;
            if Instant::now() >= next || full {
                self.flush_logs(&stop).await;
                next = Instant::now() + log_every;
            }
            tokio::time::sleep(tick).await;
        }
        self.flush_logs(&stop).await;
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
        dropped_logs: AtomicU64::new(0),
        dropped_points: AtomicU64::new(0),
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
    let ex = Arc::new(ex);
    let m = rt.spawn(ex.clone().metrics_loop(stop.clone()));
    let l = rt.spawn(ex.logs_loop(stop));
    rt.block_on(async move {
        let (m, l) = (m.await, l.await);
        for (what, r) in [("metrics", m), ("logs", l)] {
            if let Err(e) = r {
                eprintln!("aegis-otlp: {what} task: {e}");
            }
        }
    });
    ExitCode::SUCCESS
}
