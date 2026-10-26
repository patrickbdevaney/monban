//! The fetch loop: vet (allowlist, resolve once, classify every address), connect to the vetted address only,
//! follow redirects under the policy, each hop re-vetted.

use core::future::Future;
use core::pin::Pin;
use std::net::{IpAddr, SocketAddr};
use std::string::{String, ToString};
use std::vec::Vec;

use crate::addr::{AddrClass, classify};
use crate::error::EgressError;
use crate::http1::{self, Method, RawResponse};
use crate::policy::Policy;
use crate::url::{Host, Scheme, Url};

/// A boxed future (dyn-compatible async trait methods).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// At most this many vetted addresses are handed to the connector per hop.
pub const MAX_ADDRS: usize = 16;

/// Name resolution. Egress calls [`Resolver::resolve`] exactly once per hop for a named host and never for an IP
/// literal; the connector only ever sees the vetted answers (DNS-rebinding defence).
pub trait Resolver: Send + Sync {
    /// All addresses for `host` (a validated lowercase DNS name).
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>, EgressError>>;
}

/// The system resolver (tokio `lookup_host`, i.e. getaddrinfo on a blocking thread).
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>, EgressError>> {
        Box::pin(async move {
            let it = tokio::net::lookup_host((host, 0u16)).await.map_err(|e| EgressError::Resolve(e.to_string()))?;
            Ok(it.map(|sa| sa.ip()).collect())
        })
    }
}

/// An address that passed classification for the current policy. Only this crate constructs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VettedAddr(SocketAddr);

impl VettedAddr {
    /// The socket address to connect to.
    pub fn get(self) -> SocketAddr {
        self.0
    }
}

/// One hop handed to a [`Connector`].
#[derive(Debug)]
pub struct Hop<'a> {
    /// The hop URL: name for SNI and `Host`, path for the request line. Never to be resolved again.
    pub url: &'a Url,
    /// Vetted addresses, in resolver order. The connector connects to these and nothing else.
    pub addrs: &'a [VettedAddr],
    /// Method.
    pub method: Method,
    /// Caller headers (already validated).
    pub headers: &'a [(String, String)],
    /// Request body.
    pub body: &'a [u8],
    /// Response head cap.
    pub max_header_bytes: usize,
    /// Response body cap.
    pub max_response_bytes: usize,
}

/// What a connector returns for one hop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exchanged {
    /// The address actually connected to.
    pub peer: SocketAddr,
    /// The response.
    pub response: RawResponse,
}

/// Performs one request/response over a connection to one of the hop's vetted addresses.
pub trait Connector: Send + Sync {
    /// Exchange one request.
    fn exchange<'a>(&'a self, hop: Hop<'a>) -> BoxFuture<'a, Result<Exchanged, EgressError>>;
}

/// An outbound request.
#[derive(Clone, Debug)]
pub struct Request {
    /// Method.
    pub method: Method,
    /// URL (already parsed with [`Url::parse`]).
    pub url: Url,
    /// Extra headers. `Host`, framing and connection headers are owned by egress.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

impl Request {
    /// A GET.
    pub fn get(url: Url) -> Self {
        Self { method: Method::Get, url, headers: Vec::new(), body: Vec::new() }
    }
}

/// The final response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// Status.
    pub status: u16,
    /// Headers (lowercase names).
    pub headers: Vec<(String, Vec<u8>)>,
    /// Body.
    pub body: Vec<u8>,
    /// Final URL after redirects.
    pub url: Url,
    /// Address of every hop connected to, in order.
    pub peers: Vec<SocketAddr>,
}

/// Check one address against the policy.
pub fn check_addr(policy: &Policy, ip: IpAddr) -> Result<(), EgressError> {
    let class = classify(ip);
    if class == AddrClass::Public || (class.readmittable() && policy.readmit.iter().any(|p| p.contains(ip))) {
        Ok(())
    } else {
        Err(EgressError::ForbiddenAddress { addr: ip, class })
    }
}

/// Vet one hop: scheme, host allowlist, port, then resolve (once, names only) and classify every address. All
/// answers must pass; one forbidden answer rejects the hop.
pub async fn vet<R: Resolver + ?Sized>(
    policy: &Policy,
    url: &Url,
    resolver: &R,
) -> Result<Vec<VettedAddr>, EgressError> {
    if url.scheme() == Scheme::Http && !policy.allow_plain_http {
        return Err(EgressError::SchemeNotAllowed);
    }
    if !policy.host_allowed(url) {
        return Err(EgressError::HostNotAllowed);
    }
    if !policy.port_allowed(url) {
        return Err(EgressError::PortNotAllowed);
    }
    let ips = match url.host() {
        Host::Name(n) => resolver.resolve(n).await?,
        Host::V4(a) => Vec::from([IpAddr::V4(*a)]),
        Host::V6(a) => Vec::from([IpAddr::V6(*a)]),
    };
    if ips.is_empty() {
        return Err(EgressError::Resolve("no addresses".to_string()));
    }
    let mut out: Vec<VettedAddr> = Vec::new();
    for ip in ips {
        check_addr(policy, ip)?;
        let v = VettedAddr(SocketAddr::new(ip, url.port()));
        if !out.contains(&v) {
            out.push(v);
        }
    }
    out.truncate(MAX_ADDRS);
    Ok(out)
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

const CROSS_ORIGIN_STRIP: &[&str] = &["authorization", "cookie", "proxy-authorization"];

/// Outbound fetcher: a resolver plus a connector.
#[derive(Debug)]
pub struct Egress<R, C> {
    resolver: R,
    connector: C,
}

impl<R: Resolver, C: Connector> Egress<R, C> {
    /// A fetcher.
    pub fn new(resolver: R, connector: C) -> Self {
        Self { resolver, connector }
    }

    /// Fetch under `policy`, within `policy.deadline`.
    pub async fn fetch(&self, policy: &Policy, req: Request) -> Result<Response, EgressError> {
        match tokio::time::timeout(policy.deadline, self.fetch_inner(policy, req)).await {
            Ok(r) => r,
            Err(_) => Err(EgressError::Timeout),
        }
    }

    async fn fetch_inner(&self, policy: &Policy, req: Request) -> Result<Response, EgressError> {
        http1::check_headers(&req.headers)?;
        let Request { mut method, mut url, mut headers, mut body } = req;
        let mut peers = Vec::new();
        let mut redirects = 0u8;
        loop {
            let addrs = vet(policy, &url, &self.resolver).await?;
            let hop = Hop {
                url: &url,
                addrs: &addrs,
                method,
                headers: &headers,
                body: &body,
                max_header_bytes: policy.max_header_bytes,
                max_response_bytes: policy.max_response_bytes,
            };
            let ex = self.connector.exchange(hop).await?;
            if !addrs.iter().any(|a| a.get() == ex.peer) {
                // A connector that dialled anything but a vetted address is a bug; fail closed.
                return Err(EgressError::Connect("connector used an unvetted address".to_string()));
            }
            peers.push(ex.peer);
            let resp = ex.response;
            if !is_redirect(resp.status) {
                return Ok(Response { status: resp.status, headers: resp.headers, body: resp.body, url, peers });
            }
            if redirects >= policy.max_redirects {
                return Err(EgressError::TooManyRedirects);
            }
            redirects = redirects.saturating_add(1);
            let loc = resp.header("location").ok_or(EgressError::BadRedirect("no-location"))?;
            let loc = core::str::from_utf8(loc).map_err(|_| EgressError::BadRedirect("location-utf8"))?;
            let next = url.join(loc)?;
            if url.scheme() == Scheme::Https && next.scheme() == Scheme::Http {
                return Err(EgressError::SchemeDowngrade);
            }
            if !url.same_origin(&next) {
                if !policy.cross_origin_redirects {
                    return Err(EgressError::CrossOriginRedirect);
                }
                headers.retain(|(n, _)| !CROSS_ORIGIN_STRIP.contains(&n.to_ascii_lowercase().as_str()));
            }
            if resp.status == 303 || (matches!(resp.status, 301 | 302) && method == Method::Post) {
                if method != Method::Head {
                    method = Method::Get;
                }
                body = Vec::new();
            }
            url = next;
        }
    }
}

/// The network connector: TCP to a vetted address, TLS (feature `tls-client`) with SNI from the original name,
/// then one HTTP/1.1 exchange.
#[derive(Debug, Default)]
pub struct NetConnector {
    #[cfg(feature = "tls-client")]
    tls: Option<crate::tls::TlsClient>,
}

impl NetConnector {
    /// Plain-HTTP only connector (https fails with [`EgressError::TlsUnavailable`]).
    pub fn plain() -> Self {
        Self::default()
    }

    /// Connector with the PQ-preferring TLS client profile.
    #[cfg(feature = "tls-client")]
    pub fn with_tls(tls: crate::tls::TlsClient) -> Self {
        Self { tls: Some(tls) }
    }

    async fn run(&self, hop: Hop<'_>) -> Result<Exchanged, EgressError> {
        #[cfg(feature = "tls-client")]
        let tls_ready = self.tls.is_some();
        #[cfg(not(feature = "tls-client"))]
        let tls_ready = false;
        if hop.url.scheme() == Scheme::Https && !tls_ready {
            return Err(EgressError::TlsUnavailable);
        }
        let mut last = EgressError::Connect("no address".to_string());
        let mut conn = None;
        for a in hop.addrs {
            match tokio::net::TcpStream::connect(a.get()).await {
                Ok(s) => {
                    conn = Some((a.get(), s));
                    break;
                }
                Err(e) => last = EgressError::Connect(e.to_string()),
            }
        }
        let (peer, mut tcp) = conn.ok_or(last)?;
        let head = http1::encode_head(hop.method, hop.url, hop.headers, hop.body.len());
        let head_req = hop.method == Method::Head;
        let response = match hop.url.scheme() {
            Scheme::Http => {
                http1::exchange(&mut tcp, &head, hop.body, head_req, hop.max_header_bytes, hop.max_response_bytes)
                    .await?
            }
            #[cfg(feature = "tls-client")]
            Scheme::Https => {
                let tls = self.tls.as_ref().ok_or(EgressError::TlsUnavailable)?;
                let mut s = tls.connect(hop.url.host(), tcp).await?;
                http1::exchange(&mut s, &head, hop.body, head_req, hop.max_header_bytes, hop.max_response_bytes).await?
            }
            #[cfg(not(feature = "tls-client"))]
            Scheme::Https => return Err(EgressError::TlsUnavailable),
        };
        Ok(Exchanged { peer, response })
    }
}

impl Connector for NetConnector {
    fn exchange<'a>(&'a self, hop: Hop<'a>) -> BoxFuture<'a, Result<Exchanged, EgressError>> {
        Box::pin(self.run(hop))
    }
}
