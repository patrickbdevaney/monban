//! Transport: scrape the admin listener (HTTP/1.1 GET over loopback TCP or a unix socket) and POST OTLP JSON to
//! the collector (plain TCP, or TLS through the aegis-tls client profile and aegis-egress's handshake). Both use
//! aegis-egress's hand-written, capped HTTP/1.1 exchange (one request per connection).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aegis_egress::http1::{self, Method};
use aegis_egress::{Host, Scheme, TlsClient, Url};
use tokio::net::{TcpStream, UnixStream};

use crate::om::MAX_SCRAPE;

/// Per-exchange deadline (connect + request + response).
pub const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HEAD: usize = 16 * 1024;
const MAX_POST_RESPONSE: usize = 1024 * 1024;

/// Where to scrape.
#[derive(Clone, Debug)]
pub enum Scrape {
    /// `http://host:port/path`.
    Tcp(Url),
    /// `unix:/abs/path.sock` (path `/metrics`).
    Unix(PathBuf),
}

impl Scrape {
    /// Parse the `--scrape` value.
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Some(p) = s.strip_prefix("unix:") {
            if !p.starts_with('/') {
                return Err("--scrape unix: needs an absolute socket path".into());
            }
            return Ok(Self::Unix(PathBuf::from(p)));
        }
        let u = Url::parse(s).map_err(|e| format!("--scrape {s}: {e}"))?;
        if u.scheme() != Scheme::Http {
            return Err("--scrape must be http://host:port/path or unix:/path.sock".into());
        }
        Ok(Self::Tcp(u))
    }
}

async fn tcp(url: &Url) -> Result<TcpStream, String> {
    let r = match url.host() {
        Host::Name(n) => TcpStream::connect((n.as_str(), url.port())).await,
        h => match h.ip() {
            Some(ip) => TcpStream::connect(SocketAddr::new(ip, url.port())).await,
            None => return Err("no address".into()),
        },
    };
    let s = r.map_err(|e| format!("connect {}: {e}", url.host_header()))?;
    let _ = s.set_nodelay(true);
    Ok(s)
}

async fn scrape_inner(target: &Scrape) -> Result<Vec<u8>, String> {
    let accept = "Accept: application/openmetrics-text; version=1.0.0\r\nUser-Agent: aegis-otlp\r\n";
    let resp = match target {
        Scrape::Tcp(u) => {
            let head =
                format!("GET {} HTTP/1.1\r\nHost: {}\r\n{accept}Connection: close\r\n\r\n", u.path(), u.host_header());
            let mut s = tcp(u).await?;
            http1::exchange(&mut s, head.as_bytes(), &[], false, MAX_HEAD, MAX_SCRAPE).await
        }
        Scrape::Unix(p) => {
            let head = format!("GET /metrics HTTP/1.1\r\nHost: localhost\r\n{accept}Connection: close\r\n\r\n");
            let mut s = UnixStream::connect(p).await.map_err(|e| format!("connect {}: {e}", p.display()))?;
            http1::exchange(&mut s, head.as_bytes(), &[], false, MAX_HEAD, MAX_SCRAPE).await
        }
    }
    .map_err(|e| format!("scrape: {e}"))?;
    if resp.status != 200 {
        return Err(format!("scrape: HTTP {}", resp.status));
    }
    Ok(resp.body)
}

/// GET the exposition (status 200 required, body capped at [`MAX_SCRAPE`]).
pub async fn scrape(target: &Scrape) -> Result<Vec<u8>, String> {
    tokio::time::timeout(TIMEOUT, scrape_inner(target)).await.unwrap_or_else(|_| Err("scrape: timeout".into()))
}

/// The collector endpoints.
#[derive(Clone, Debug)]
pub struct Poster {
    /// `<base>/v1/metrics`.
    pub metrics: Url,
    /// `<base>/v1/logs`.
    pub logs: Url,
    tls: Option<TlsClient>,
}

impl Poster {
    /// `endpoint` is the OTLP/HTTP base URL (trailing `/` stripped, path prefix kept). `https` needs `tls`.
    pub fn new(endpoint: &str, tls: Option<Arc<rustls::ClientConfig>>) -> Result<Self, String> {
        let base = endpoint.trim_end_matches('/');
        if base.contains(['?', '#']) {
            return Err("--endpoint must not carry a query or fragment".into());
        }
        let parse = |p: &str| Url::parse(&format!("{base}{p}")).map_err(|e| format!("--endpoint {endpoint}: {e}"));
        let (metrics, logs) = (parse("/v1/metrics")?, parse("/v1/logs")?);
        let tls = match (metrics.scheme(), tls) {
            (Scheme::Http, _) => None,
            (Scheme::Https, Some(cfg)) => Some(TlsClient::from_config(cfg).map_err(|e| format!("tls: {e}"))?),
            (Scheme::Https, None) => return Err("https --endpoint needs --ca-file (no implicit trust)".into()),
        };
        Ok(Self { metrics, logs, tls })
    }

    async fn post_inner(&self, url: &Url, body: &[u8]) -> Result<u16, String> {
        let headers = [("Content-Type".to_string(), "application/json".to_string())];
        let head = http1::encode_head(Method::Post, url, &headers, body.len());
        let s = tcp(url).await?;
        let resp = match &self.tls {
            Some(t) => {
                let mut s = t.connect(url.host(), s).await.map_err(|e| e.to_string())?;
                http1::exchange(&mut s, &head, body, false, MAX_HEAD, MAX_POST_RESPONSE).await
            }
            None => {
                let mut s = s;
                http1::exchange(&mut s, &head, body, false, MAX_HEAD, MAX_POST_RESPONSE).await
            }
        };
        resp.map(|r| r.status).map_err(|e| e.to_string())
    }

    /// POST one JSON request within `timeout`; `Ok` only for a 2xx answer. A failure says whether the OTLP/HTTP
    /// specification ("Failures") allows a retry: 429, 502, 503, 504 and transport failures (connect, TLS, I/O,
    /// timeout) do; every other answer is final.
    pub async fn post(&self, url: &Url, body: &[u8], timeout: Duration) -> Result<(), PostError> {
        let r = tokio::time::timeout(timeout.min(TIMEOUT), self.post_inner(url, body))
            .await
            .unwrap_or_else(|_| Err("timeout".into()));
        match r {
            Ok(s) if (200..300).contains(&s) => Ok(()),
            Ok(s) => Err(PostError { msg: format!("POST {}: HTTP {s}", url.path()), retryable: retryable_status(s) }),
            Err(e) => Err(PostError { msg: format!("POST {}: {e}", url.path()), retryable: true }),
        }
    }
}

/// A failed POST.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostError {
    /// What went wrong (for the log).
    pub msg: String,
    /// Whether another attempt may be made.
    pub retryable: bool,
}

/// OTLP/HTTP "Failures": the status codes a client may retry.
pub fn retryable_status(s: u16) -> bool {
    matches!(s, 429 | 502 | 503 | 504)
}

/// Build the client config for an https collector: the aegis-tls client profile over the roots in `ca_pem`.
pub fn tls_config(profile: &str, ca_pem: &[u8]) -> Result<Arc<rustls::ClientConfig>, String> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let p = aegis_tls::Profile::from_name(profile).ok_or_else(|| format!("unknown --tls-profile {profile}"))?;
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(ca_pem) {
        let c = c.map_err(|e| format!("--ca-file: {e:?}"))?;
        roots.add(c).map_err(|e| format!("--ca-file: {e}"))?;
    }
    if roots.is_empty() {
        return Err("--ca-file holds no certificate".into());
    }
    aegis_tls::client_config(p, roots).map(Arc::new).map_err(|e| format!("tls profile {profile}: {e:?}"))
}
