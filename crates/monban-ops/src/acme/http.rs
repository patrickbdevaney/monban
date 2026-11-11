//! Minimal HTTPS/1.1 client for ACME (RFC 8555 §6.1: HTTPS only). One request per connection (`Connection:
//! close`), blocking std sockets wrapped in a rustls client stream, every read bounded: status line + headers
//! ≤ [`Limits::max_header`], body ≤ [`Limits::max_body`], chunk-size lines bounded, socket timeouts.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::string::String;
use std::sync::Arc;
use std::time::Duration;
use std::vec::Vec;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use super::AcmeError;

/// Size and time bounds for one exchange.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Status line + header block bytes.
    pub max_header: usize,
    /// Body bytes.
    pub max_body: usize,
    /// Connect / read / write timeout.
    pub timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self { max_header: 16 * 1024, max_body: 256 * 1024, timeout: Duration::from_secs(15) }
    }
}

/// A parsed `https://` URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    /// Host (DNS name or IP literal, brackets stripped).
    pub host: String,
    /// Port (default 443).
    pub port: u16,
    /// Path and query, starting with `/`.
    pub path: String,
    authority: String,
}

impl Url {
    /// Parse; only `https` with no userinfo or fragment.
    pub fn parse(s: &str) -> Result<Self, AcmeError> {
        let bad = || AcmeError::BadUrl(s.chars().take(200).collect());
        if s.len() > 2048 || s.bytes().any(|b| !(0x21..0x7f).contains(&b)) {
            return Err(bad());
        }
        let rest = s.strip_prefix("https://").ok_or_else(bad)?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (rest.get(..i).ok_or_else(bad)?, rest.get(i..).ok_or_else(bad)?),
            None => (rest, "/"),
        };
        if authority.is_empty() || authority.contains('@') || path.contains('#') {
            return Err(bad());
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, after) = v6.split_once(']').ok_or_else(bad)?;
            let port = match after.strip_prefix(':') {
                Some(p) => p.parse::<u16>().map_err(|_| bad())?,
                None if after.is_empty() => 443,
                None => return Err(bad()),
            };
            (h, port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h, p.parse::<u16>().map_err(|_| bad())?),
                None => (authority, 443),
            }
        };
        if host.is_empty() || port == 0 {
            return Err(bad());
        }
        Ok(Self { host: host.into(), port, path: path.into(), authority: authority.into() })
    }
}

/// One HTTP response.
#[derive(Clone, Debug, Default)]
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Header fields (names lowercased), in order.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

impl Response {
    /// First value of a header (name compared case-insensitively).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// Perform one request over TLS.
pub fn request(
    tls: &Arc<ClientConfig>,
    method: &str,
    url: &Url,
    extra_headers: &[(&str, &str)],
    body: &[u8],
    limits: &Limits,
) -> Result<Response, AcmeError> {
    let addrs: Vec<_> =
        (url.host.as_str(), url.port).to_socket_addrs().map_err(|e| AcmeError::Io(e.to_string()))?.collect();
    let mut last = AcmeError::Io(String::from("no address"));
    let mut sock = None;
    for a in addrs.iter().take(8) {
        match TcpStream::connect_timeout(a, limits.timeout) {
            Ok(s) => {
                sock = Some(s);
                break;
            }
            Err(e) => last = AcmeError::Io(e.to_string()),
        }
    }
    let sock = sock.ok_or(last)?;
    sock.set_read_timeout(Some(limits.timeout)).map_err(|e| AcmeError::Io(e.to_string()))?;
    sock.set_write_timeout(Some(limits.timeout)).map_err(|e| AcmeError::Io(e.to_string()))?;
    let name = ServerName::try_from(url.host.clone()).map_err(|_| AcmeError::BadUrl(url.host.clone()))?;
    let conn = ClientConnection::new(tls.clone(), name).map_err(|e| AcmeError::Tls(e.to_string()))?;
    let mut stream = StreamOwned::new(conn, sock);
    exchange(&mut stream, method, url, extra_headers, body, limits)
}

/// Write the request and read the response on an established stream (separate for tests).
pub fn exchange<S: Read + Write>(
    stream: &mut S,
    method: &str,
    url: &Url,
    extra_headers: &[(&str, &str)],
    body: &[u8],
    limits: &Limits,
) -> Result<Response, AcmeError> {
    let mut req = std::format!(
        "{method} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: monban-acme\r\nConnection: close\r\n",
        url.path,
        url.authority
    );
    for (n, v) in extra_headers {
        if n.bytes().chain(v.bytes()).any(|b| b == b'\r' || b == b'\n') {
            return Err(AcmeError::Protocol("header injection"));
        }
        req.push_str(&std::format!("{n}: {v}\r\n"));
    }
    if method != "GET" && method != "HEAD" {
        req.push_str(&std::format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    let mut out = req.into_bytes();
    out.extend_from_slice(body);
    stream.write_all(&out).map_err(|e| AcmeError::Io(e.to_string()))?;
    stream.flush().map_err(|e| AcmeError::Io(e.to_string()))?;
    read_response(stream, method == "HEAD", limits)
}

struct Buf<'a, R: Read> {
    r: &'a mut R,
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
}

impl<R: Read> Buf<'_, R> {
    fn fill(&mut self) -> Result<(), AcmeError> {
        if self.pos > 0 {
            self.buf.drain(..self.pos.min(self.buf.len()));
            self.pos = 0;
        }
        let mut tmp = [0u8; 8192];
        match self.r.read(&mut tmp) {
            Ok(0) => {
                self.eof = true;
                Ok(())
            }
            Ok(n) => {
                self.buf.extend_from_slice(tmp.get(..n).unwrap_or(&[]));
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => Ok(()),
            Err(e) => Err(AcmeError::Io(e.to_string())),
        }
    }

    fn avail(&self) -> &[u8] {
        self.buf.get(self.pos..).unwrap_or(&[])
    }

    /// A CRLF-terminated line (CRLF stripped), at most `cap` bytes.
    fn line(&mut self, cap: usize) -> Result<Vec<u8>, AcmeError> {
        loop {
            if let Some(i) = self.avail().windows(2).position(|w| w == b"\r\n") {
                if i > cap {
                    return Err(AcmeError::TooLarge("header line"));
                }
                let l = self.avail().get(..i).unwrap_or(&[]).to_vec();
                self.pos = self.pos.saturating_add(i + 2);
                return Ok(l);
            }
            if self.avail().len() > cap {
                return Err(AcmeError::TooLarge("header line"));
            }
            if self.eof {
                return Err(AcmeError::Protocol("truncated response"));
            }
            self.fill()?;
        }
    }

    fn take(&mut self, n: usize, out: &mut Vec<u8>) -> Result<(), AcmeError> {
        let mut need = n;
        while need > 0 {
            if self.avail().is_empty() {
                if self.eof {
                    return Err(AcmeError::Protocol("truncated body"));
                }
                self.fill()?;
                continue;
            }
            let k = need.min(self.avail().len());
            out.extend_from_slice(self.avail().get(..k).unwrap_or(&[]));
            self.pos = self.pos.saturating_add(k);
            need -= k;
        }
        Ok(())
    }
}

/// Parse a response from `r`.
pub fn read_response<R: Read>(r: &mut R, head: bool, limits: &Limits) -> Result<Response, AcmeError> {
    let mut b = Buf { r, buf: Vec::new(), pos: 0, eof: false };
    let status_line = b.line(limits.max_header)?;
    let mut used = status_line.len();
    let sl = core::str::from_utf8(&status_line).map_err(|_| AcmeError::Protocol("status line"))?;
    let mut parts = sl.splitn(3, ' ');
    let ver = parts.next().unwrap_or("");
    let code = parts.next().unwrap_or("");
    if ver != "HTTP/1.1" && ver != "HTTP/1.0" || code.len() != 3 {
        return Err(AcmeError::Protocol("status line"));
    }
    let status: u16 = code.parse().map_err(|_| AcmeError::Protocol("status code"))?;
    if !(100..=599).contains(&status) || (100..200).contains(&status) {
        return Err(AcmeError::Protocol("unexpected status class"));
    }
    let mut headers = Vec::new();
    loop {
        let l = b.line(limits.max_header)?;
        used = used.saturating_add(l.len() + 2);
        if used > limits.max_header || headers.len() > 100 {
            return Err(AcmeError::TooLarge("header block"));
        }
        if l.is_empty() {
            break;
        }
        let s = core::str::from_utf8(&l).map_err(|_| AcmeError::Protocol("header encoding"))?;
        let (n, v) = s.split_once(':').ok_or(AcmeError::Protocol("header syntax"))?;
        if n.is_empty() || n.bytes().any(|c| !c.is_ascii_graphic()) || s.starts_with([' ', '\t']) {
            return Err(AcmeError::Protocol("header syntax"));
        }
        headers.push((n.to_ascii_lowercase(), v.trim_matches([' ', '\t']).to_string()));
    }
    let mut resp = Response { status, headers, body: Vec::new() };
    if head || status == 204 || status == 304 {
        return Ok(resp);
    }
    let chunked = resp.header("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
    if resp.header("transfer-encoding").is_some() && !chunked {
        return Err(AcmeError::Protocol("unsupported transfer-encoding"));
    }
    let cls: Vec<&str> = resp.headers.iter().filter(|(n, _)| n == "content-length").map(|(_, v)| v.as_str()).collect();
    if chunked && !cls.is_empty() {
        return Err(AcmeError::Protocol("both content-length and chunked"));
    }
    let mut body = Vec::new();
    if chunked {
        loop {
            let l = b.line(64)?;
            let s = core::str::from_utf8(&l).map_err(|_| AcmeError::Protocol("chunk size"))?;
            let hex = s.split(';').next().unwrap_or("").trim();
            if hex.is_empty() || hex.len() > 8 {
                return Err(AcmeError::Protocol("chunk size"));
            }
            let n = usize::from_str_radix(hex, 16).map_err(|_| AcmeError::Protocol("chunk size"))?;
            if n == 0 {
                // Trailers (bounded) until the empty line.
                let mut t = 0usize;
                while !b.line(limits.max_header)?.is_empty() {
                    t += 1;
                    if t > 32 {
                        return Err(AcmeError::TooLarge("trailers"));
                    }
                }
                break;
            }
            if body.len().saturating_add(n) > limits.max_body {
                return Err(AcmeError::TooLarge("body"));
            }
            b.take(n, &mut body)?;
            if !b.line(2)?.is_empty() {
                return Err(AcmeError::Protocol("chunk terminator"));
            }
        }
    } else if let Some(first) = cls.first() {
        if cls.iter().any(|c| c != first) {
            return Err(AcmeError::Protocol("conflicting content-length"));
        }
        if first.is_empty() || first.len() > 12 || !first.bytes().all(|c| c.is_ascii_digit()) {
            return Err(AcmeError::Protocol("content-length"));
        }
        let n: usize = first.parse().map_err(|_| AcmeError::Protocol("content-length"))?;
        if n > limits.max_body {
            return Err(AcmeError::TooLarge("body"));
        }
        b.take(n, &mut body)?;
    } else {
        loop {
            let k = b.avail().len();
            if body.len().saturating_add(k) > limits.max_body {
                return Err(AcmeError::TooLarge("body"));
            }
            body.extend_from_slice(b.avail());
            b.pos = b.pos.saturating_add(k);
            if b.eof {
                break;
            }
            b.fill()?;
        }
    }
    resp.body = body;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    fn parse(raw: &[u8]) -> Result<Response, AcmeError> {
        let lim = Limits { max_header: 1024, max_body: 64, timeout: Duration::from_secs(1) };
        read_response(&mut &raw[..], false, &lim)
    }

    #[test]
    fn content_length_and_chunked() {
        let r = parse(b"HTTP/1.1 201 Created\r\nLocation: https://x/acct/1\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!((r.status, r.body.as_slice(), r.header("location")), (201, &b"{}"[..], Some("https://x/acct/1")));
        let r = parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n2\r\nde\r\n0\r\n\r\n")
            .unwrap();
        assert_eq!(r.body, b"abcde");
        let r = parse(b"HTTP/1.1 200 OK\r\n\r\nuntil-eof").unwrap();
        assert_eq!(r.body, b"until-eof");
    }

    #[test]
    fn caps_and_malformed() {
        assert!(matches!(parse(b"HTTP/1.1 200 OK\r\nContent-Length: 65\r\n\r\n"), Err(AcmeError::TooLarge(_))));
        let big = [b"HTTP/1.1 200 OK\r\n\r\n".as_slice(), &[b'a'; 65]].concat();
        assert!(matches!(parse(&big), Err(AcmeError::TooLarge(_))));
        assert!(matches!(
            parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n41\r\n"),
            Err(AcmeError::TooLarge(_))
        ));
        let hdr = [b"HTTP/1.1 200 OK\r\nX: ".as_slice(), &[b'a'; 2000], b"\r\n\r\n"].concat();
        assert!(matches!(parse(&hdr), Err(AcmeError::TooLarge(_))));
        assert!(parse(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab").is_err());
        assert!(parse(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab").is_err());
        assert!(parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n").is_err());
        assert!(parse(b"HTTP/2 200\r\n\r\n").is_err());
        assert!(parse(b"HTTP/1.1 200 OK\r\n folded\r\n\r\n").is_err());
        assert!(parse(b"garbage").is_err());
    }

    #[test]
    fn total_on_random_input() {
        let mut x: u64 = 88172645463325252;
        let alphabet = b"HTP/1.0 2\r\n:;aContent-Length";
        for _ in 0..20_000 {
            let mut v = Vec::new();
            for _ in 0..(x % 80) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                v.push(alphabet[(x % alphabet.len() as u64) as usize]);
            }
            let _ = parse(&[b"HTTP/1.1 200 OK\r\n".as_slice(), &v].concat());
            let _ = parse(&v);
        }
    }

    #[test]
    fn url_parse() {
        let u = Url::parse("https://127.0.0.1:14000/dir").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.path.as_str()), ("127.0.0.1", 14000, "/dir"));
        let u = Url::parse("https://[::1]/x?y").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.path.as_str()), ("::1", 443, "/x?y"));
        assert_eq!(Url::parse("https://acme.test").unwrap().path, "/");
        for bad in [
            "http://x/",
            "https://",
            "https://u@x/",
            "https://x:0/",
            "https://x:99999/",
            "https://x/a b",
            "https://x/#f",
        ] {
            assert!(Url::parse(bad).is_err(), "{bad}");
        }
    }
}
