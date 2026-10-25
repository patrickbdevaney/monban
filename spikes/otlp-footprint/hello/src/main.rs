//! otlp-footprint spike: representative AEGIS "hello" server.
//! base: tokio (multi-thread, 1 worker) + hyper 1.12 (h1+h2 via hyper-util auto) + rustls 0.23.46 / aws-lc-rs 1.18.2,
//!       TLS on 127.0.0.1:8443 (env HELLO_PORT), PQ-preferring default provider.
//! +metrics: hand-written OpenMetrics text endpoint on a separate loopback admin listener (127.0.0.1:9100).
//! +logs:    structured JSON logs via tracing-subscriber (one span + event per request).
//! +otlp:    opentelemetry 0.33 OTLP http/protobuf over hyper (traces via tracing-opentelemetry, metrics via
//!           a PeriodicReader), exporting to OTEL_EXPORTER_OTLP_ENDPOINT (default http://127.0.0.1:4318).
#![forbid(unsafe_code)]

use std::convert::Infallible;
use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;

type BoxErr = Box<dyn Error + Send + Sync>;

static CERT: &[u8] = include_bytes!("../certs/cert.pem");
static KEY: &[u8] = include_bytes!("../certs/key.pem");

#[derive(Debug, Default)]
struct Counters {
    requests: AtomicU64,
    tls_failures: AtomicU64,
}

static COUNTERS: Counters = Counters { requests: AtomicU64::new(0), tls_failures: AtomicU64::new(0) };

fn main() -> Result<(), BoxErr> {
    let workers = std::env::var("HELLO_WORKERS").ok().and_then(|s| s.parse().ok()).unwrap_or(1usize);
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(workers).enable_all().build()?;
    rt.block_on(run())
}

async fn run() -> Result<(), BoxErr> {
    #[cfg(any(feature = "otlp", feature = "otlp-grpc"))]
    let _otel = otel::init()?;
    #[cfg(all(feature = "logs", not(any(feature = "otlp", feature = "otlp-grpc"))))]
    tracing_subscriber::fmt().json().with_writer(std::io::stderr).init();

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let certs = CertificateDer::pem_slice_iter(CERT).collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(KEY)?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));

    #[cfg(feature = "metrics")]
    tokio::spawn(metrics::serve());

    let port = std::env::var("HELLO_PORT").unwrap_or_else(|_| "8443".into());
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    eprintln!("ready");
    loop {
        let (tcp, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(t) => t,
                Err(_) => {
                    COUNTERS.tls_failures.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };
            let svc = hyper::service::service_fn(hello);
            let _ = auto::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(tls), svc).await;
        });
    }
}

async fn hello(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    COUNTERS.requests.fetch_add(1, Ordering::Relaxed);
    #[cfg(feature = "logs")]
    let _g = tracing::info_span!("request", method = %req.method(), path = req.uri().path()).entered();
    #[cfg(feature = "logs")]
    tracing::info!(status = 200u16, "served");
    #[cfg(any(feature = "otlp", feature = "otlp-grpc"))]
    otel::count_request();
    let _ = &req;
    Ok(Response::new(Full::new(Bytes::from_static(b"hello\n"))))
}

#[cfg(feature = "metrics")]
mod metrics {
    //! Hand-written OpenMetrics 1.0 text exposition (no metrics crate).
    use super::*;
    use std::fmt::Write;

    fn render() -> String {
        let mut s = String::with_capacity(512);
        let _ = write!(
            s,
            "# TYPE aegis_requests counter\n# HELP aegis_requests Requests served.\naegis_requests_total {}\n\
             # TYPE aegis_tls_handshake_failures counter\naegis_tls_handshake_failures_total {}\n\
             # TYPE aegis_fips_status gauge\naegis_fips_status{{module=\"none\"}} 0\n\
             # TYPE aegis_config_generation info\naegis_config_generation_info{{hash=\"0000\"}} 1\n# EOF\n",
            COUNTERS.requests.load(Ordering::Relaxed),
            COUNTERS.tls_failures.load(Ordering::Relaxed),
        );
        s
    }

    async fn handle(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
        let mut r = Response::new(Full::new(Bytes::from(render())));
        r.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/openmetrics-text; version=1.0.0; charset=utf-8"),
        );
        Ok(r)
    }

    pub async fn serve() -> Result<(), BoxErr> {
        let l = TcpListener::bind("127.0.0.1:9100").await?;
        loop {
            let (tcp, _) = l.accept().await?;
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), hyper::service::service_fn(handle))
                    .await;
            });
        }
    }
}

#[cfg(any(feature = "otlp", feature = "otlp-grpc"))]
mod otel {
    use super::BoxErr;
    use opentelemetry::metrics::{Counter, MeterProvider as _};
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::metrics::SdkMeterProvider;
    use opentelemetry_sdk::metrics::periodic_reader_with_async_runtime::PeriodicReader;
    use opentelemetry_sdk::runtime::Tokio;
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use opentelemetry_sdk::trace::span_processor_with_async_runtime::BatchSpanProcessor;
    use std::sync::OnceLock;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    static REQS: OnceLock<Counter<u64>> = OnceLock::new();

    pub struct Guard(SdkTracerProvider, SdkMeterProvider);
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = self.0.shutdown();
            let _ = self.1.shutdown();
        }
    }

    pub fn count_request() {
        if let Some(c) = REQS.get() {
            c.add(1, &[]);
        }
    }

    pub fn init() -> Result<Guard, BoxErr> {
        let base = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:4318".into());
        #[cfg(feature = "otlp")]
        let (spans, mets) = (
            opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
                .with_endpoint(format!("{base}/v1/traces"))
                .build()?,
            opentelemetry_otlp::MetricExporter::builder()
                .with_http()
                .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
                .with_endpoint(format!("{base}/v1/metrics"))
                .build()?,
        );
        #[cfg(all(feature = "otlp-grpc", not(feature = "otlp")))]
        let (spans, mets) = (
            opentelemetry_otlp::SpanExporter::builder().with_tonic().with_endpoint(base.clone()).build()?,
            opentelemetry_otlp::MetricExporter::builder().with_tonic().with_endpoint(base).build()?,
        );
        let res = Resource::builder().with_service_name("aegis-hello").build();
        let tp = SdkTracerProvider::builder()
            .with_span_processor(BatchSpanProcessor::builder(spans, Tokio).build())
            .with_resource(res.clone())
            .build();
        let mp = SdkMeterProvider::builder()
            .with_reader(
                PeriodicReader::builder(mets, Tokio)
                    .with_interval(std::time::Duration::from_secs(
                        std::env::var("HELLO_OTLP_INTERVAL_S").ok().and_then(|s| s.parse().ok()).unwrap_or(60),
                    ))
                    .build(),
            )
            .with_resource(res)
            .build();
        let _ = REQS.set(mp.meter("aegis").u64_counter("aegis.requests").build());
        // INFO cap (as `fmt().init()` in the logs variant) also keeps the exporter's own hyper-client TRACE events out
        // of the pipeline (otherwise exports generate spans that get exported: a feedback loop seen in run 1).
        tracing_subscriber::registry()
            .with(tracing_subscriber::filter::LevelFilter::INFO)
            .with(tracing_subscriber::fmt::layer().json().with_writer(std::io::stderr))
            .with(tracing_opentelemetry::layer().with_tracer(tp.tracer("aegis")))
            .init();
        Ok(Guard(tp, mp))
    }
}
