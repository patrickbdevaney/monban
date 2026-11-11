//! Upstream side: connection pool and the two clients.
//!
//! * Pool key = the whole [`UpstreamConnConfig`] (target, framing, σ scope) plus the config epoch (CRS C3, C5):
//!   `derive(Hash, Eq)` over the struct, so no field can be forgotten. [`Pool::set_epoch`] drops every pooled
//!   connection, and a connection checked in under an old epoch is closed, never reused across a config change.
//! * HTTP/1.1 client (hand-written: hyper's client needs `want`, which is not in the lock): the request is
//!   serialized from canonical values only, `content-length` framing, never chunked, never raw client bytes
//!   (R-TLS-3, F1 H1 grammar (d)). The response parser is strict: a malformed status line or field, a duplicate
//!   or non-numeric Content-Length, CL+TE, a Transfer-Encoding other than `chunked`, or a body over
//!   [`MAX_RESPONSE_BYTES`] fails the exchange (502) and closes the connection (C8: close on framing error).
//! * HTTP/2 client (h2c, prior knowledge) over the `h2` crate; one connection per key, multiplexed.
//!
//! Every read and write is bounded by the stall deadline (TBI-8 analogue on the upstream side).

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::body::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UnixStream};
use tokio::time::timeout;

use crate::plan::{Target, UpFraming, UpstreamConnConfig};
use crate::shared::{Shared, bump};
use crate::util::{find_head_end, is_field_value, is_tchar, trim_ows};

/// Largest upstream response body buffered (bytes); above it the exchange fails with 502.
pub const MAX_RESPONSE_BYTES: usize = 8 << 20;
/// Largest upstream response head.
const MAX_RESPONSE_HEAD: usize = 64 << 10;
/// Idle HTTP/1.1 connections kept per key.
const MAX_IDLE_PER_KEY: usize = 32;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// What the upstream is asked, borrowed from an admitted (canonical) request.
#[derive(Debug)]
pub struct UpRequest<'a> {
    pub method: &'a http::Method,
    pub authority: &'a [u8],
    pub path_and_query: &'a [u8],
    pub headers: &'a [(Vec<u8>, Vec<u8>)],
    pub body: &'a [u8],
}

#[derive(Debug)]
pub struct UpResponse {
    pub status: u16,
    /// Lowercase names, validated values.
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub enum UpError {
    Connect(String),
    Io(String),
    Protocol(&'static str),
    Timeout,
    TooLarge,
}

impl std::fmt::Display for UpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "connect: {e}"),
            Self::Io(e) => write!(f, "i/o: {e}"),
            Self::Protocol(e) => write!(f, "protocol: {e}"),
            Self::Timeout => write!(f, "stall timeout"),
            Self::TooLarge => write!(f, "response over {MAX_RESPONSE_BYTES} bytes"),
        }
    }
}

fn io_err(e: std::io::Error) -> UpError {
    UpError::Io(e.to_string())
}

// ------------------------------------------------------------------------------------------------ stream

#[derive(Debug)]
pub enum Stream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Self::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Self::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

async fn connect(t: &Target) -> Result<Stream, UpError> {
    let fut = async {
        match t {
            Target::Tcp { host, port } => {
                let s = TcpStream::connect((host.as_str(), *port)).await?;
                let _ = s.set_nodelay(true);
                Ok::<Stream, std::io::Error>(Stream::Tcp(s))
            }
            Target::Unix(p) => Ok(Stream::Unix(UnixStream::connect(p).await?)),
        }
    };
    match timeout(CONNECT_TIMEOUT, fut).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(UpError::Connect(e.to_string())),
        Err(_) => Err(UpError::Connect("timeout".into())),
    }
}

// ------------------------------------------------------------------------------------------------ pool

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PoolKey {
    cfg: UpstreamConnConfig,
    epoch: u64,
}

#[derive(Debug)]
pub struct H1Conn {
    stream: Stream,
    buf: Vec<u8>,
}

#[derive(Debug, Default)]
struct Maps {
    idle: HashMap<PoolKey, Vec<H1Conn>>,
    h2: HashMap<PoolKey, h2::client::SendRequest<Bytes>>,
}

#[derive(Debug)]
pub struct Pool {
    epoch: AtomicU64,
    maps: Mutex<Maps>,
}

impl Pool {
    pub fn new(epoch: u64) -> Self {
        Self { epoch: AtomicU64::new(epoch), maps: Mutex::new(Maps::default()) }
    }

    fn maps(&self) -> std::sync::MutexGuard<'_, Maps> {
        self.maps.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// CRS C5: a new config epoch; every pooled connection is closed.
    pub fn set_epoch(&self, epoch: u64) {
        self.epoch.store(epoch, Ordering::Release);
        let mut m = self.maps();
        m.idle.clear();
        m.h2.clear();
    }

    fn key(&self, cfg: &UpstreamConnConfig) -> PoolKey {
        PoolKey { cfg: cfg.clone(), epoch: self.epoch.load(Ordering::Acquire) }
    }

    fn checkout(&self, key: &PoolKey) -> Option<H1Conn> {
        self.maps().idle.get_mut(key).and_then(Vec::pop)
    }

    fn checkin(&self, key: PoolKey, c: H1Conn) {
        if key.epoch != self.epoch.load(Ordering::Acquire) {
            return; // stale epoch: closed by drop
        }
        let mut m = self.maps();
        let v = m.idle.entry(key).or_default();
        if v.len() < MAX_IDLE_PER_KEY {
            v.push(c);
        }
    }

    /// One upstream exchange.
    pub async fn request(
        &self,
        shared: &Arc<Shared>,
        cfg: &UpstreamConnConfig,
        req: &UpRequest<'_>,
        stall_ms: u64,
    ) -> Result<UpResponse, UpError> {
        let stall = Duration::from_millis(stall_ms.max(1));
        let key = self.key(cfg);
        match cfg.framing {
            UpFraming::H1 => {
                if let Some(mut c) = self.checkout(&key) {
                    match h1_exchange(&mut c, req, stall).await {
                        Ok((resp, reusable)) => {
                            if reusable {
                                self.checkin(key, c);
                            }
                            return Ok(resp);
                        }
                        // A pooled connection the upstream closed before answering: retry once on a fresh one.
                        Err((_, false)) => {}
                        Err((e, true)) => return Err(e),
                    }
                }
                let stream = connect(&cfg.target).await?;
                bump(&shared.stats.upstream_connects);
                let mut c = H1Conn { stream, buf: Vec::new() };
                let (resp, reusable) = h1_exchange(&mut c, req, stall).await.map_err(|(e, _)| e)?;
                if reusable {
                    self.checkin(key, c);
                }
                Ok(resp)
            }
            UpFraming::H2 => {
                let existing = self.maps().h2.get(&key).cloned();
                let send = match existing {
                    Some(s) => s,
                    None => {
                        let stream = connect(&cfg.target).await?;
                        bump(&shared.stats.upstream_connects);
                        let (send, conn) = timeout(stall, h2::client::Builder::new().handshake::<_, Bytes>(stream))
                            .await
                            .map_err(|_| UpError::Timeout)?
                            .map_err(|e| UpError::Io(e.to_string()))?;
                        tokio::spawn(async move {
                            let _ = conn.await;
                        });
                        if key.epoch == self.epoch.load(Ordering::Acquire) {
                            self.maps().h2.insert(key.clone(), send.clone());
                        }
                        send
                    }
                };
                let r = h2_exchange(send, req, stall).await;
                if r.is_err() {
                    self.maps().h2.remove(&key);
                }
                r
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------ HTTP/1.1

/// Serialize the upstream request from canonical parts (CANON-4). Returns `None` if any part could inject framing
/// (cannot happen for canonical values; checked anyway).
pub fn serialize_h1(req: &UpRequest<'_>) -> Option<Vec<u8>> {
    let pq_ok =
        req.path_and_query.first() == Some(&b'/') && req.path_and_query.iter().all(|&b| (0x21..0x7F).contains(&b));
    if !pq_ok || !is_field_value(req.authority) || req.authority.is_empty() {
        return None;
    }
    let mut o = Vec::with_capacity(256usize.saturating_add(req.body.len()));
    o.extend_from_slice(req.method.as_str().as_bytes());
    o.push(b' ');
    o.extend_from_slice(req.path_and_query);
    o.extend_from_slice(b" HTTP/1.1\r\nhost: ");
    o.extend_from_slice(req.authority);
    o.extend_from_slice(b"\r\n");
    for (n, v) in req.headers {
        if n.is_empty() || !n.iter().all(|&b| is_tchar(b)) || !is_field_value(v) {
            return None;
        }
        o.extend_from_slice(n);
        o.extend_from_slice(b": ");
        o.extend_from_slice(v);
        o.extend_from_slice(b"\r\n");
    }
    let has_body_semantics = matches!(*req.method, http::Method::POST | http::Method::PUT | http::Method::PATCH);
    if !req.body.is_empty() || has_body_semantics {
        o.extend_from_slice(format!("content-length: {}\r\n", req.body.len()).as_bytes());
    }
    o.extend_from_slice(b"\r\n");
    o.extend_from_slice(req.body);
    Some(o)
}

impl H1Conn {
    /// Read more bytes into the buffer; `Ok(0)` is EOF.
    async fn fill(&mut self, stall: Duration) -> Result<usize, UpError> {
        let mut chunk = [0u8; 16 * 1024];
        let n = timeout(stall, self.stream.read(&mut chunk)).await.map_err(|_| UpError::Timeout)?.map_err(io_err)?;
        self.buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
        Ok(n)
    }

    async fn line(&mut self, stall: Duration, cap: usize) -> Result<Vec<u8>, UpError> {
        loop {
            if let Some(i) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let l = self.buf.get(..i).unwrap_or(&[]).to_vec();
                self.buf.drain(..i.saturating_add(2).min(self.buf.len()));
                return Ok(l);
            }
            if self.buf.len() > cap {
                return Err(UpError::Protocol("line too long"));
            }
            if self.fill(stall).await? == 0 {
                return Err(UpError::Protocol("eof in line"));
            }
        }
    }

    async fn exact(&mut self, n: usize, stall: Duration, out: &mut Vec<u8>) -> Result<(), UpError> {
        while self.buf.len() < n {
            if self.fill(stall).await? == 0 {
                return Err(UpError::Protocol("eof in body"));
            }
        }
        out.extend_from_slice(self.buf.get(..n).unwrap_or(&[]));
        self.buf.drain(..n.min(self.buf.len()));
        Ok(())
    }
}

/// Parsed response head.
struct RespHead {
    status: u16,
    http10: bool,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
}

fn parse_resp_head(h: &[u8]) -> Result<RespHead, UpError> {
    let bad = UpError::Protocol;
    let mut lines = h.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let status_line = lines.next().ok_or(bad("empty head"))?;
    if h.windows(2).any(|w| matches!(w, [a, b'\n'] if *a != b'\r')) || h.first() == Some(&b'\n') {
        return Err(bad("bare LF"));
    }
    let (http10, rest) = if let Some(r) = status_line.strip_prefix(b"HTTP/1.1 ") {
        (false, r)
    } else if let Some(r) = status_line.strip_prefix(b"HTTP/1.0 ") {
        (true, r)
    } else {
        return Err(bad("status line"));
    };
    let code = rest.get(..3).ok_or(bad("status code"))?;
    if !code.iter().all(u8::is_ascii_digit) || !matches!(rest.get(3), None | Some(b' ')) {
        return Err(bad("status code"));
    }
    let status = std::str::from_utf8(code).ok().and_then(|s| s.parse::<u16>().ok()).ok_or(bad("status code"))?;
    if !(100..=599).contains(&status) {
        return Err(bad("status range"));
    }
    let mut headers = Vec::new();
    for l in lines {
        let colon = l.iter().position(|&b| b == b':').ok_or(bad("field without colon"))?;
        let (n, v) = (l.get(..colon).unwrap_or(b""), trim_ows(l.get(colon.saturating_add(1)..).unwrap_or(b"")));
        if n.is_empty() || !n.iter().all(|&b| is_tchar(b)) || !is_field_value(v) {
            return Err(bad("bad field"));
        }
        headers.push((n.to_ascii_lowercase(), v.to_vec()));
    }
    Ok(RespHead { status, http10, headers })
}

#[derive(Debug, PartialEq, Eq)]
enum BodyFraming {
    None,
    Length(usize),
    Chunked,
    Eof,
}

fn body_framing(head: &RespHead, method: &http::Method) -> Result<BodyFraming, UpError> {
    let get = |n: &[u8]| -> Vec<&[u8]> {
        head.headers.iter().filter(|(k, _)| k.as_slice() == n).map(|(_, v)| v.as_slice()).collect()
    };
    let cls = get(b"content-length");
    let tes = get(b"transfer-encoding");
    if *method == http::Method::HEAD || head.status == 204 || head.status == 304 || head.status < 200 {
        return Ok(BodyFraming::None);
    }
    match (cls.as_slice(), tes.as_slice()) {
        ([], []) => Ok(BodyFraming::Eof),
        ([cl], []) => {
            if cl.is_empty() || cl.len() > 18 || !cl.iter().all(u8::is_ascii_digit) {
                return Err(UpError::Protocol("bad content-length"));
            }
            let n: u64 = std::str::from_utf8(cl)
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or(UpError::Protocol("bad content-length"))?;
            let n = usize::try_from(n).map_err(|_| UpError::TooLarge)?;
            if n > MAX_RESPONSE_BYTES {
                return Err(UpError::TooLarge);
            }
            Ok(BodyFraming::Length(n))
        }
        ([], [te]) if te.eq_ignore_ascii_case(b"chunked") => Ok(BodyFraming::Chunked),
        ([], [_]) => Err(UpError::Protocol("transfer-encoding other than chunked")),
        _ => Err(UpError::Protocol("duplicate content-length / transfer-encoding, or CL+TE")),
    }
}

/// `Err((e, response_started))`: `response_started == false` means no response byte arrived (safe to retry a
/// pooled connection once).
async fn h1_exchange(
    c: &mut H1Conn,
    req: &UpRequest<'_>,
    stall: Duration,
) -> Result<(UpResponse, bool), (UpError, bool)> {
    let wire = serialize_h1(req).ok_or((UpError::Protocol("unserializable request"), true))?;
    match timeout(stall, c.stream.write_all(&wire)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err((io_err(e), false)),
        Err(_) => return Err((UpError::Timeout, true)),
    }
    let mut started = false;
    let head = loop {
        let end = loop {
            if let Some(e) = find_head_end(&c.buf) {
                break e;
            }
            if c.buf.len() > MAX_RESPONSE_HEAD {
                return Err((UpError::Protocol("response head too large"), true));
            }
            match c.fill(stall).await {
                Ok(0) => return Err((UpError::Protocol("upstream closed"), started)),
                Ok(_) => started = true,
                Err(e) => return Err((e, started)),
            }
        };
        let raw = c.buf.get(..end).unwrap_or(&[]).to_vec();
        c.buf.drain(..end.saturating_add(4).min(c.buf.len()));
        let h = parse_resp_head(&raw).map_err(|e| (e, true))?;
        match h.status {
            101 => return Err((UpError::Protocol("unexpected 101"), true)),
            100..=199 => continue, // interim responses are not forwarded
            _ => break h,
        }
    };
    let framing = body_framing(&head, req.method).map_err(|e| (e, true))?;
    let mut body = Vec::new();
    let reusable_framing = match framing {
        BodyFraming::None => true,
        BodyFraming::Length(n) => {
            c.exact(n, stall, &mut body).await.map_err(|e| (e, true))?;
            true
        }
        BodyFraming::Chunked => {
            loop {
                let line = c.line(stall, 4096).await.map_err(|e| (e, true))?;
                let size_part = line.split(|&b| b == b';').next().unwrap_or(b"");
                let size_part = trim_ows(size_part);
                if size_part.is_empty() || size_part.len() > 15 || !size_part.iter().all(u8::is_ascii_hexdigit) {
                    return Err((UpError::Protocol("bad chunk size"), true));
                }
                let n = std::str::from_utf8(size_part)
                    .ok()
                    .and_then(|s| usize::from_str_radix(s, 16).ok())
                    .ok_or((UpError::Protocol("bad chunk size"), true))?;
                if n == 0 {
                    // trailers (dropped) up to the empty line
                    loop {
                        let t = c.line(stall, 8192).await.map_err(|e| (e, true))?;
                        if t.is_empty() {
                            break;
                        }
                    }
                    break;
                }
                if body.len().saturating_add(n) > MAX_RESPONSE_BYTES {
                    return Err((UpError::TooLarge, true));
                }
                c.exact(n, stall, &mut body).await.map_err(|e| (e, true))?;
                let crlf = c.line(stall, 2).await.map_err(|e| (e, true))?;
                if !crlf.is_empty() {
                    return Err((UpError::Protocol("chunk not followed by CRLF"), true));
                }
            }
            true
        }
        BodyFraming::Eof => {
            loop {
                if c.buf.len() > MAX_RESPONSE_BYTES {
                    return Err((UpError::TooLarge, true));
                }
                if c.fill(stall).await.map_err(|e| (e, true))? == 0 {
                    break;
                }
            }
            body = std::mem::take(&mut c.buf);
            false
        }
    };
    let close = head.http10
        || head.headers.iter().any(|(n, v)| {
            n == b"connection" && v.split(|&b| b == b',').any(|t| trim_ows(t).eq_ignore_ascii_case(b"close"))
        });
    let reusable = reusable_framing && !close && c.buf.is_empty();
    Ok((UpResponse { status: head.status, headers: head.headers, body }, reusable))
}

// ------------------------------------------------------------------------------------------------ HTTP/2

async fn h2_exchange(
    send: h2::client::SendRequest<Bytes>,
    req: &UpRequest<'_>,
    stall: Duration,
) -> Result<UpResponse, UpError> {
    fn proto<E>(_: E) -> UpError {
        UpError::Protocol("h2 request build")
    }
    let mut send =
        timeout(stall, send.ready()).await.map_err(|_| UpError::Timeout)?.map_err(|e| UpError::Io(e.to_string()))?;
    let uri = http::Uri::builder()
        .scheme("http")
        .authority(req.authority)
        .path_and_query(req.path_and_query)
        .build()
        .map_err(proto)?;
    let mut b = http::Request::builder().method(req.method.clone()).uri(uri);
    for (n, v) in req.headers {
        let name = http::HeaderName::from_bytes(n).map_err(proto)?;
        let value = http::HeaderValue::from_bytes(v).map_err(proto)?;
        b = b.header(name, value);
    }
    if !req.body.is_empty() || matches!(*req.method, http::Method::POST | http::Method::PUT | http::Method::PATCH) {
        b = b.header(http::header::CONTENT_LENGTH, req.body.len());
    }
    let r = b.body(()).map_err(proto)?;
    let (fut, mut stream) = send.send_request(r, req.body.is_empty()).map_err(|e| UpError::Io(e.to_string()))?;
    if !req.body.is_empty() {
        stream.send_data(Bytes::copy_from_slice(req.body), true).map_err(|e| UpError::Io(e.to_string()))?;
    }
    let resp = timeout(stall, fut).await.map_err(|_| UpError::Timeout)?.map_err(|e| UpError::Io(e.to_string()))?;
    let (parts, mut recv) = resp.into_parts();
    let mut body = Vec::new();
    while let Some(chunk) = timeout(stall, recv.data()).await.map_err(|_| UpError::Timeout)? {
        let chunk = chunk.map_err(|e| UpError::Io(e.to_string()))?;
        let _ = recv.flow_control().release_capacity(chunk.len());
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(UpError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    let mut headers = Vec::new();
    for (n, v) in &parts.headers {
        if !is_field_value(v.as_bytes()) {
            return Err(UpError::Protocol("bad field value"));
        }
        headers.push((n.as_str().as_bytes().to_vec(), v.as_bytes().to_vec()));
    }
    Ok(UpResponse { status: parts.status.as_u16(), headers, body })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn serializes_from_canonical_parts() {
        let h = vec![(b"x-a".to_vec(), b"1".to_vec())];
        let r = UpRequest {
            method: &http::Method::POST,
            authority: b"monban.test",
            path_and_query: b"/a?b=1",
            headers: &h,
            body: b"hi",
        };
        assert_eq!(
            serialize_h1(&r).unwrap(),
            b"POST /a?b=1 HTTP/1.1\r\nhost: monban.test\r\nx-a: 1\r\ncontent-length: 2\r\n\r\nhi".to_vec()
        );
        let bad = vec![(b"x-a".to_vec(), b"1\r\nx: y".to_vec())];
        let r2 = UpRequest { headers: &bad, ..r };
        assert!(serialize_h1(&r2).is_none());
    }

    #[test]
    fn response_head_strict() {
        let h = parse_resp_head(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Y:  z ").unwrap();
        assert_eq!(h.status, 200);
        assert_eq!(h.headers, vec![(b"content-length".to_vec(), b"5".to_vec()), (b"x-y".to_vec(), b"z".to_vec())]);
        assert!(parse_resp_head(b"HTTP/1.1 200 OK\nX: y").is_err());
        assert!(parse_resp_head(b"HTTP/2 200").is_err());
        assert!(parse_resp_head(b"HTTP/1.1 200 OK\r\nX y: z").is_err());
        let two = parse_resp_head(b"HTTP/1.1 200 OK\r\ncontent-length: 1\r\ncontent-length: 1").unwrap();
        assert!(body_framing(&two, &http::Method::GET).is_err());
        let te = parse_resp_head(b"HTTP/1.1 200 OK\r\ntransfer-encoding: gzip").unwrap();
        assert!(body_framing(&te, &http::Method::GET).is_err());
    }
}
