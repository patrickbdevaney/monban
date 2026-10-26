//! Minimal strict HTTP/1.1 client exchange over an already-connected stream (hyper's client needs `want`, which is
//! not in the lock). One request per connection (`Connection: close`). Caps: response head and body sizes.

use std::string::{String, ToString};
use std::vec::Vec;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::EgressError;
use crate::url::Url;

/// Request method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// GET.
    Get,
    /// HEAD.
    Head,
    /// POST.
    Post,
    /// PUT.
    Put,
    /// PATCH.
    Patch,
    /// DELETE.
    Delete,
}

impl Method {
    /// Method token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

/// Headers the caller may not set: egress owns framing, the connection and the Host (taken from the URL).
const RESERVED: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "expect",
    "proxy-connection",
];

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Validate caller headers (names are tokens, values have no CR/LF/NUL, no reserved names).
pub fn check_headers(headers: &[(String, String)]) -> Result<(), EgressError> {
    for (n, v) in headers {
        if n.is_empty() || !n.bytes().all(is_tchar) {
            return Err(EgressError::BadRequest("header-name"));
        }
        if !v.bytes().all(|b| b == b'\t' || (0x20..=0x7e).contains(&b)) {
            return Err(EgressError::BadRequest("header-value"));
        }
        if RESERVED.contains(&n.to_ascii_lowercase().as_str()) {
            return Err(EgressError::BadRequest("reserved-header"));
        }
    }
    Ok(())
}

/// Serialize the request head. `Host` is the URL's original name (never the connected address).
pub fn encode_head(method: Method, url: &Url, headers: &[(String, String)], body_len: usize) -> Vec<u8> {
    let mut h = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", method.as_str(), url.path(), url.host_header());
    h.push_str("User-Agent: aegis-egress\r\nAccept-Encoding: identity\r\nConnection: close\r\n");
    if body_len > 0 || matches!(method, Method::Post | Method::Put | Method::Patch) {
        h.push_str(&format!("Content-Length: {body_len}\r\n"));
    }
    for (n, v) in headers {
        h.push_str(n);
        h.push_str(": ");
        h.push_str(v);
        h.push_str("\r\n");
    }
    h.push_str("\r\n");
    h.into_bytes()
}

/// A raw response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawResponse {
    /// Status code.
    pub status: u16,
    /// Header fields in order; names lowercased.
    pub headers: Vec<(String, Vec<u8>)>,
    /// Body (de-chunked).
    pub body: Vec<u8>,
}

impl RawResponse {
    /// First value of a header (name lowercase).
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_slice())
    }
}

struct Rd<'a, S> {
    s: &'a mut S,
    buf: Vec<u8>,
    eof: bool,
}

impl<S: AsyncRead + Unpin> Rd<'_, S> {
    /// Read more bytes; false at EOF.
    async fn fill(&mut self) -> Result<bool, EgressError> {
        if self.eof {
            return Ok(false);
        }
        let mut chunk = [0u8; 8192];
        let n = match self.s.read(&mut chunk).await {
            Ok(n) => n,
            // TLS peers that close without close_notify: treated as EOF; framed bodies still detect truncation.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(EgressError::Io(e.to_string())),
        };
        if n == 0 {
            self.eof = true;
            return Ok(false);
        }
        self.buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
        Ok(true)
    }

    /// Take bytes up to and including CRLF (returned without it); at most `max` bytes.
    async fn line(&mut self, max: usize, too_long: EgressError) -> Result<Vec<u8>, EgressError> {
        loop {
            if let Some(i) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let mut l: Vec<u8> = self.buf.drain(..i.saturating_add(2)).collect();
                l.truncate(i);
                return Ok(l);
            }
            if self.buf.len() > max {
                return Err(too_long);
            }
            if !self.fill().await? {
                return Err(EgressError::BadResponse("truncated"));
            }
        }
    }

    async fn take(&mut self, n: usize) -> Result<Vec<u8>, EgressError> {
        while self.buf.len() < n {
            if !self.fill().await? {
                return Err(EgressError::BadResponse("truncated"));
            }
        }
        Ok(self.buf.drain(..n).collect())
    }
}

fn parse_status(line: &[u8]) -> Result<u16, EgressError> {
    let rest = line
        .strip_prefix(b"HTTP/1.1 ")
        .or_else(|| line.strip_prefix(b"HTTP/1.0 "))
        .ok_or(EgressError::BadResponse("status-line"))?;
    let code = rest.get(..3).ok_or(EgressError::BadResponse("status-line"))?;
    if !code.iter().all(u8::is_ascii_digit) || !(rest.len() == 3 || rest.get(3) == Some(&b' ')) {
        return Err(EgressError::BadResponse("status-line"));
    }
    let n = code.iter().fold(0u16, |a, &d| a.saturating_mul(10).saturating_add(u16::from(d - b'0')));
    if !(100..=599).contains(&n) {
        return Err(EgressError::BadResponse("status-line"));
    }
    Ok(n)
}

fn parse_field(line: &[u8]) -> Result<(String, Vec<u8>), EgressError> {
    let colon = line.iter().position(|&b| b == b':').ok_or(EgressError::BadResponse("header"))?;
    let name = line.get(..colon).unwrap_or(&[]);
    if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
        return Err(EgressError::BadResponse("header"));
    }
    let value = line.get(colon.saturating_add(1)..).unwrap_or(&[]);
    if value.iter().any(|&b| b == 0 || b == b'\r' || b == b'\n') {
        return Err(EgressError::BadResponse("header"));
    }
    let is_ws = |b: &u8| *b == b' ' || *b == b'\t';
    let start = value.iter().position(|b| !is_ws(b)).unwrap_or(value.len());
    let end = value.iter().rposition(|b| !is_ws(b)).map_or(start, |i| i.saturating_add(1));
    let name = String::from_utf8_lossy(name).to_ascii_lowercase();
    Ok((name, value.get(start..end).unwrap_or(&[]).to_vec()))
}

/// Send one request and read one response, with the given caps.
pub async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    head: &[u8],
    body: &[u8],
    head_request: bool,
    max_header_bytes: usize,
    max_body_bytes: usize,
) -> Result<RawResponse, EgressError> {
    let io = |e: std::io::Error| EgressError::Io(e.to_string());
    s.write_all(head).await.map_err(io)?;
    s.write_all(body).await.map_err(io)?;
    s.flush().await.map_err(io)?;

    let mut rd = Rd { s, buf: Vec::new(), eof: false };
    let mut interim = 0u8;
    let (status, headers) = loop {
        let mut used = 0usize;
        let status_line = rd.line(max_header_bytes, EgressError::HeadersTooLarge).await?;
        used = used.saturating_add(status_line.len());
        let status = parse_status(&status_line)?;
        let mut headers = Vec::new();
        loop {
            let budget = max_header_bytes.saturating_sub(used);
            let l = rd.line(budget, EgressError::HeadersTooLarge).await?;
            used = used.saturating_add(l.len()).saturating_add(2);
            if used > max_header_bytes {
                return Err(EgressError::HeadersTooLarge);
            }
            if l.is_empty() {
                break;
            }
            if l.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
                return Err(EgressError::BadResponse("obs-fold"));
            }
            headers.push(parse_field(&l)?);
            if headers.len() > 128 {
                return Err(EgressError::HeadersTooLarge);
            }
        }
        if status == 101 {
            return Err(EgressError::BadResponse("unexpected-101"));
        }
        if (100..200).contains(&status) {
            interim = interim.saturating_add(1);
            if interim > 4 {
                return Err(EgressError::BadResponse("too-many-interim"));
            }
            continue;
        }
        break (status, headers);
    };

    let resp = |body| RawResponse { status, headers: headers.clone(), body };
    if head_request || status == 204 || status == 304 {
        return Ok(resp(Vec::new()));
    }
    let te: Vec<&Vec<u8>> = headers.iter().filter(|(n, _)| n == "transfer-encoding").map(|(_, v)| v).collect();
    let cl: Vec<&Vec<u8>> = headers.iter().filter(|(n, _)| n == "content-length").map(|(_, v)| v).collect();
    if !te.is_empty() {
        if !cl.is_empty() {
            return Err(EgressError::BadResponse("te-and-cl"));
        }
        if te.len() != 1 || !te.first().is_some_and(|v| v.eq_ignore_ascii_case(b"chunked")) {
            return Err(EgressError::BadResponse("transfer-encoding"));
        }
        let mut out = Vec::new();
        loop {
            let l = rd.line(1024, EgressError::BadResponse("chunk-size")).await?;
            let hex = l.split(|&b| b == b';').next().unwrap_or(&[]);
            if hex.is_empty() || hex.len() > 15 || !hex.iter().all(u8::is_ascii_hexdigit) {
                return Err(EgressError::BadResponse("chunk-size"));
            }
            let size = hex.iter().fold(0usize, |a, &d| {
                let v = match d {
                    b'0'..=b'9' => d - b'0',
                    b'a'..=b'f' => d - b'a' + 10,
                    _ => d.saturating_sub(b'A').saturating_add(10),
                };
                a.saturating_mul(16).saturating_add(usize::from(v))
            });
            if size == 0 {
                let mut trailer = 0usize;
                loop {
                    let t = rd.line(max_header_bytes, EgressError::HeadersTooLarge).await?;
                    trailer = trailer.saturating_add(t.len());
                    if trailer > max_header_bytes {
                        return Err(EgressError::HeadersTooLarge);
                    }
                    if t.is_empty() {
                        return Ok(resp(out));
                    }
                }
            }
            if out.len().saturating_add(size) > max_body_bytes {
                return Err(EgressError::ResponseTooLarge);
            }
            out.extend(rd.take(size).await?);
            if rd.take(2).await? != b"\r\n" {
                return Err(EgressError::BadResponse("chunk-crlf"));
            }
        }
    }
    if let Some(first) = cl.first() {
        if !cl.iter().all(|v| v == first)
            || first.is_empty()
            || first.len() > 19
            || !first.iter().all(u8::is_ascii_digit)
        {
            return Err(EgressError::BadResponse("content-length"));
        }
        let n = first.iter().fold(0usize, |a, &d| a.saturating_mul(10).saturating_add(usize::from(d - b'0')));
        if n > max_body_bytes {
            return Err(EgressError::ResponseTooLarge);
        }
        return Ok(resp(rd.take(n).await?));
    }
    // Close-delimited.
    loop {
        if rd.buf.len() > max_body_bytes {
            return Err(EgressError::ResponseTooLarge);
        }
        if !rd.fill().await? {
            return Ok(resp(core::mem::take(&mut rd.buf)));
        }
    }
}
