//! Blocking RESP2 connection over TCP or a Unix socket (std::net / std::os::unix; DEVIATIONS X-10).
//!
//! Every read is bounded: the [`Limits`] caps (bulk length, array length and depth, line length, reply size, value
//! count) are checked on each header before the body is awaited, and every command runs under a deadline that is
//! turned into the socket read/write timeout before each syscall. RESP2 has no resynchronization point, so a
//! timeout, a protocol error or a cap hit marks the connection broken: it refuses further commands and must be
//! dropped (never returned to a pool).
//!
//! Command surface: [`Connection::command`] sends only the data commands the KV renderer emits (`GET`, `SET`,
//! `DEL`; SCAN is refused per PLAN D11), and additionally refuses anything on the shared RESP denylist (R-DB-3/4). The connection
//! handshake (`HELLO 2 [AUTH]`, `INFO server`) and per-tenant user provisioning (`ACL SETUSER/DELUSER`) are
//! separate, fixed-shape methods; there is no raw-command escape hatch.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use monban_data_ir::{EngineFamily, denied};

use crate::resp::{self, DEFAULT_LIMITS, EncodeError, Limits, Reply, RespError};
use crate::version::{AdmittedVersion, KvPins, ServerReport, VersionRefusal, admit_report, recheck};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Endpoint {
    Tcp { host: String, port: u16 },
    Unix { path: PathBuf },
}

/// Everything needed to open one connection. `Debug` redacts the password.
#[derive(Clone, PartialEq, Eq)]
pub struct ConnectConfig {
    pub endpoint: Endpoint,
    /// ACL user; `None` = the `default` user.
    pub username: Option<String>,
    pub password: Option<String>,
    /// Bound on TCP connect plus the whole handshake (HELLO, INFO, version gate).
    pub connect_timeout: Duration,
    /// Bound on each command (write + full reply).
    pub io_timeout: Duration,
    pub limits: Limits,
}

impl fmt::Debug for ConnectConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectConfig")
            .field("endpoint", &self.endpoint)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("connect_timeout", &self.connect_timeout)
            .field("io_timeout", &self.io_timeout)
            .field("limits", &self.limits)
            .finish()
    }
}

pub const DEFAULT_PORT: u16 = 6379;
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_URL: usize = 4096;
/// Largest command we send (one key ≤ 1024 bytes plus one value ≤ `max_bulk`, plus framing).
const CMD_OVERHEAD: usize = 4096;
const CHUNK: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlError(pub String);

impl fmt::Display for UrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bad URL: {}", self.0)
    }
}

impl std::error::Error for UrlError {}

fn bad<T>(m: &str) -> Result<T, UrlError> {
    Err(UrlError(m.into()))
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Strict percent-decoding to UTF-8 without NUL, CR, LF or spaces (they would break nothing in RESP, but no
/// legitimate credential needs them and they are a classic injection shape).
fn pct(s: &str) -> Result<String, UrlError> {
    let mut out = Vec::with_capacity(s.len());
    let mut it = s.bytes();
    while let Some(c) = it.next() {
        if c == b'%' {
            let (Some(h), Some(l)) = (it.next().and_then(hexval), it.next().and_then(hexval)) else {
                return bad("bad percent escape");
            };
            out.push(h * 16 + l);
        } else {
            out.push(c);
        }
    }
    if out.iter().any(|b| b.is_ascii_control() || *b == b' ') {
        return bad("control byte or space in URL component");
    }
    String::from_utf8(out).or_else(|_| bad("URL component not UTF-8"))
}

impl ConnectConfig {
    /// `redis://[user[:password]@]host[:port][/0]` or `unix:///path/to/socket`. TLS (`rediss://`), a database other
    /// than 0 (it would need SELECT, which is denylisted) and query parameters are refused. Pure: nothing opened.
    pub fn from_url(url: &str) -> Result<ConnectConfig, UrlError> {
        if url.len() > MAX_URL {
            return bad("too long");
        }
        let base = |endpoint| ConnectConfig {
            endpoint,
            username: None,
            password: None,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            io_timeout: DEFAULT_IO_TIMEOUT,
            limits: DEFAULT_LIMITS,
        };
        if let Some(path) = url.strip_prefix("unix://") {
            if !path.starts_with('/') || path.contains('?') || path.contains('#') {
                return bad("unix:// needs an absolute path and no query");
            }
            return Ok(base(Endpoint::Unix { path: PathBuf::from(pct(path)?) }));
        }
        if url.starts_with("rediss://") {
            return bad("TLS (rediss://) is not supported by this client; refused rather than downgraded");
        }
        let rest = url.strip_prefix("redis://").ok_or(UrlError("scheme must be redis:// or unix://".into()))?;
        if rest.contains('?') || rest.contains('#') {
            return bad("query or fragment");
        }
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        if !(path.is_empty() || path == "0") {
            return bad("only database 0 (SELECT is denylisted)");
        }
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
            let (h, after) = v6.split_once(']').ok_or(UrlError("unterminated [".into()))?;
            let port = match after {
                "" => DEFAULT_PORT,
                p => parse_port(p.strip_prefix(':').ok_or(UrlError("port".into()))?)?,
            };
            (h.to_string(), port)
        } else {
            match hostport.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), parse_port(p)?),
                None => (hostport.to_string(), DEFAULT_PORT),
            }
        };
        if host.is_empty() || host.bytes().any(|b| !(b.is_ascii_alphanumeric() || b".-:_".contains(&b))) {
            return bad("host");
        }
        let mut cfg = base(Endpoint::Tcp { host, port });
        if let Some(ui) = userinfo {
            let (u, p) = match ui.split_once(':') {
                Some((u, p)) => (u, Some(p)),
                None => (ui, None),
            };
            cfg.username = if u.is_empty() { None } else { Some(pct(u)?) };
            cfg.password = p.map(pct).transpose()?;
        }
        Ok(cfg)
    }
}

fn parse_port(s: &str) -> Result<u16, UrlError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return bad("port");
    }
    match s.parse::<u16>() {
        Ok(p) if p != 0 => Ok(p),
        _ => bad("port"),
    }
}

#[derive(Debug)]
pub enum Error {
    Url(UrlError),
    /// Socket connect failed.
    Connect(String),
    /// The deadline passed; the connection is now broken.
    Timeout,
    /// I/O error or EOF; the connection is now broken.
    Io(String),
    /// Protocol violation or cap hit; the connection is now broken.
    Resp(RespError),
    /// The connection broke earlier; drop it.
    Broken,
    /// HELLO/AUTH refused (wrong credentials, no RESP2 HELLO).
    Auth(String),
    /// The version gate refused the server; the connection was closed.
    Refused(VersionRefusal),
    /// Refused before sending: not an allowed command, denylisted, or not encodable within the caps.
    Usage(String),
    /// A reply of an unexpected shape for the command (the connection stays in sync but the caller must not trust
    /// the result).
    Unexpected(String),
    /// PLAN D12: the `default` user is enabled with permissions (RESET would log a tenant connection into it).
    DefaultUserEnabled(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Url(e) => write!(f, "{e}"),
            Error::Connect(e) => write!(f, "connect failed: {e}"),
            Error::Timeout => write!(f, "timeout"),
            Error::Io(e) => write!(f, "i/o: {e}"),
            Error::Resp(e) => write!(f, "{e}"),
            Error::Broken => write!(f, "connection broken"),
            Error::Auth(e) => write!(f, "authentication failed: {e}"),
            Error::Refused(r) => write!(f, "{r}"),
            Error::Usage(e) => write!(f, "usage: {e}"),
            Error::Unexpected(e) => write!(f, "unexpected reply: {e}"),
            Error::DefaultUserEnabled(e) => write!(f, "refusing to start: `default` user {e} (PLAN D12)"),
        }
    }
}

impl std::error::Error for Error {}

impl From<EncodeError> for Error {
    fn from(e: EncodeError) -> Self {
        Error::Usage(e.to_string())
    }
}

#[derive(Debug)]
enum Stream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Stream {
    fn set_timeouts(&self, d: Duration) -> io::Result<()> {
        match self {
            Stream::Tcp(s) => s.set_read_timeout(Some(d)).and_then(|_| s.set_write_timeout(Some(d))),
            Stream::Unix(s) => s.set_read_timeout(Some(d)).and_then(|_| s.set_write_timeout(Some(d))),
        }
    }
    fn fd(&self) -> BorrowedFd<'_> {
        match self {
            Stream::Tcp(s) => s.as_fd(),
            Stream::Unix(s) => s.as_fd(),
        }
    }
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.read(b),
            Stream::Unix(s) => s.read(b),
        }
    }
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.write(b),
            Stream::Unix(s) => s.write(b),
        }
    }
}

fn remaining(deadline: Instant) -> Result<Duration, Error> {
    let r = deadline.saturating_duration_since(Instant::now());
    if r.is_zero() { Err(Error::Timeout) } else { Ok(r) }
}

fn open(ep: &Endpoint, deadline: Instant) -> Result<Stream, Error> {
    match ep {
        Endpoint::Tcp { host, port } => {
            let addrs: Vec<SocketAddr> = (host.as_str(), *port)
                .to_socket_addrs()
                .map_err(|e| Error::Connect(format!("resolve: {e}")))?
                .collect();
            let mut last = String::from("no address");
            for a in addrs {
                match TcpStream::connect_timeout(&a, remaining(deadline)?) {
                    Ok(s) => {
                        let _ = s.set_nodelay(true);
                        return Ok(Stream::Tcp(s));
                    }
                    Err(e) => last = e.to_string(),
                }
            }
            Err(Error::Connect(last))
        }
        Endpoint::Unix { path } => {
            UnixStream::connect(path).map(Stream::Unix).map_err(|e| Error::Connect(e.to_string()))
        }
    }
}

/// Data commands [`Connection::command`] may send: exactly what the KV renderer emits (`monban_data_ir::KvCommand`).
/// SCAN is excluded (PLAN D11: listing is refused under per-tenant ACL users).
pub const DATA_COMMANDS: &[&str] = &["GET", "SET", "DEL"];

/// One authenticated, version-admitted RESP2 connection. Not shared across tenants (R-DB-5): open one per ACL user.
pub struct Connection {
    raw: Raw,
    endpoint: Endpoint,
    username: Option<String>,
    io_timeout: Duration,
    broken: bool,
    admitted: AdmittedVersion,
    report: ServerReport,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("endpoint", &self.endpoint)
            .field("username", &self.username)
            .field("admitted", &self.admitted)
            .field("broken", &self.broken)
            .finish_non_exhaustive()
    }
}

/// Socket + read buffer + caps (shared by the handshake and the admitted connection).
#[derive(Debug)]
struct Raw {
    stream: Stream,
    rbuf: Vec<u8>,
    limits: Limits,
}

impl Raw {
    fn send(&mut self, args: &[&[u8]], deadline: Instant) -> Result<(), Error> {
        let bytes = resp::encode(args, self.limits.max_bulk.saturating_add(CMD_OVERHEAD))?;
        let mut off = 0;
        while off < bytes.len() {
            self.stream.set_timeouts(remaining(deadline)?).map_err(|e| Error::Io(e.to_string()))?;
            let chunk = bytes.get(off..).unwrap_or(&[]);
            match self.stream.write(chunk) {
                Ok(0) => return Err(Error::Io("write returned 0".into())),
                Ok(n) => off = off.saturating_add(n),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                    return Err(Error::Timeout);
                }
                Err(e) => return Err(Error::Io(e.to_string())),
            }
        }
        Ok(())
    }

    fn recv(&mut self, deadline: Instant) -> Result<Reply, Error> {
        let mut chunk = [0u8; CHUNK];
        loop {
            if let Some((reply, used)) = resp::parse(&self.rbuf, &self.limits).map_err(Error::Resp)? {
                self.rbuf.drain(..used.min(self.rbuf.len()));
                return Ok(reply);
            }
            self.stream.set_timeouts(remaining(deadline)?).map_err(|e| Error::Io(e.to_string()))?;
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err(Error::Io("connection closed by server".into())),
                Ok(n) => self.rbuf.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                    return Err(Error::Timeout);
                }
                Err(e) => return Err(Error::Io(e.to_string())),
            }
        }
    }

    fn call(&mut self, args: &[&[u8]], deadline: Instant) -> Result<Reply, Error> {
        self.send(args, deadline)?;
        self.recv(deadline)
    }
}

fn utf8(b: &[u8]) -> Option<String> {
    String::from_utf8(b.to_vec()).ok()
}

/// HELLO 2 reply: a flat array of alternating field names and values.
fn parse_hello(r: &Reply) -> Result<(Option<String>, Option<String>), Error> {
    let Reply::Array(Some(items)) = r else {
        return Err(Error::Unexpected("HELLO reply is not an array".into()));
    };
    if items.len() % 2 != 0 {
        return Err(Error::Unexpected("HELLO reply has odd length".into()));
    }
    let (mut server, mut version) = (None, None);
    for pair in items.as_chunks::<2>().0 {
        if let [Reply::Bulk(Some(k)), v] = pair {
            let val = match v {
                Reply::Bulk(Some(b)) | Reply::Simple(b) => utf8(b),
                _ => None,
            };
            match k.as_slice() {
                b"server" => server = val,
                b"version" => version = val,
                _ => {}
            }
        }
    }
    Ok((server, version))
}

/// `INFO server` body: `key:value` lines; section headers and blank lines skipped.
fn parse_info(body: &[u8]) -> Vec<(String, String)> {
    String::from_utf8_lossy(body)
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

impl Connection {
    /// Open, `HELLO 2 [AUTH user pass]`, `INFO server` (if the user may run it), then gate the server against the
    /// pins. `pinned = None` is a first admission and needs INFO (use an admin/provisioning connection);
    /// `pinned = Some(a)` (a per-tenant ACL user re-connecting to an admitted endpoint) needs HELLO to report
    /// exactly `a`. A refused connection is closed, never returned.
    pub fn connect(cfg: &ConnectConfig, pins: &KvPins, pinned: Option<&AdmittedVersion>) -> Result<Connection, Error> {
        let deadline = Instant::now() + cfg.connect_timeout;
        let stream = open(&cfg.endpoint, deadline)?;
        let mut raw = Raw { stream, rbuf: Vec::new(), limits: cfg.limits };
        let mut hello: Vec<&[u8]> = vec![b"HELLO", b"2"];
        let user = cfg.username.as_deref().unwrap_or("default");
        if let Some(p) = cfg.password.as_deref() {
            hello.extend_from_slice(&[b"AUTH", user.as_bytes(), p.as_bytes()]);
        } else if cfg.username.is_some() {
            return Err(Error::Usage("username without password".into()));
        }
        let r = raw.call(&hello, deadline)?;
        if let Some(e) = r.error_text() {
            return Err(Error::Auth(String::from_utf8_lossy(e).into_owned()));
        }
        let (hello_server, hello_version) = parse_hello(&r)?;
        let info = match raw.call(&[b"INFO", b"server"], deadline)? {
            Reply::Bulk(Some(body)) => Some(parse_info(&body)),
            r if r.is_noperm() => None,
            other => return Err(Error::Unexpected(format!("INFO server: {other:?}"))),
        };
        let report = ServerReport { hello_server, hello_version, info };
        let verdict = match pinned {
            None => admit_report(pins, &report),
            Some(a) => recheck(pins, a, &report),
        };
        let admitted = verdict.map_err(Error::Refused)?;
        Ok(Connection {
            raw,
            endpoint: cfg.endpoint.clone(),
            username: cfg.username.clone(),
            io_timeout: cfg.io_timeout,
            broken: false,
            admitted,
            report,
        })
    }

    pub fn admitted(&self) -> &AdmittedVersion {
        &self.admitted
    }
    pub fn server_report(&self) -> &ServerReport {
        &self.report
    }
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    pub fn is_broken(&self) -> bool {
        self.broken
    }

    /// Idle-socket probe for pooled reuse: not broken, nothing buffered, and the socket has neither unread bytes nor
    /// EOF pending (non-blocking `MSG_PEEK`). Unsolicited bytes on an idle RESP2 connection make it non-reusable.
    pub fn is_reusable(&self) -> bool {
        if self.broken || !self.raw.rbuf.is_empty() {
            return false;
        }
        let mut b = [0u8; 1];
        match rustix::net::recv(
            self.raw.stream.fd(),
            &mut b,
            rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
        ) {
            Err(e) => e == rustix::io::Errno::AGAIN || e == rustix::io::Errno::WOULDBLOCK,
            Ok(_) => false,
        }
    }

    fn exchange(&mut self, args: &[&[u8]]) -> Result<Reply, Error> {
        if self.broken {
            return Err(Error::Broken);
        }
        let deadline = Instant::now() + self.io_timeout;
        let out = self.raw.call(args, deadline);
        match out {
            Err(Error::Usage(e)) => Err(Error::Usage(e)),
            Err(e) => {
                self.broken = true;
                Err(e)
            }
            Ok(r) => Ok(r),
        }
    }

    /// Send one data command (`GET`/`SET`/`DEL`, case-insensitive) and read its reply. Anything else, or
    /// anything on the RESP denylist, is refused before a byte is written. A server error reply is returned as
    /// `Ok(Reply::Error(..))` (the connection is still in sync).
    pub fn command(&mut self, args: &[&[u8]]) -> Result<Reply, Error> {
        let name = args.first().ok_or(Error::Usage("empty command".into()))?;
        let name = std::str::from_utf8(name).map_err(|_| Error::Usage("command name not UTF-8".into()))?;
        let family = match self.admitted.kind {
            crate::version::KvKind::Valkey => EngineFamily::Valkey,
            crate::version::KvKind::Redis => EngineFamily::Redis,
        };
        if let Some(d) = denied(family, name) {
            return Err(Error::Usage(format!("{} is denylisted: {}", d.item, d.trace)));
        }
        if !DATA_COMMANDS.iter().any(|c| c.eq_ignore_ascii_case(name)) {
            return Err(Error::Usage(format!("{name:?} is not a KV data command")));
        }
        self.exchange(args)
    }

    /// `ACL SETUSER <user> reset on ><password> <rules...>` for a per-tenant user (see
    /// [`crate::render::TenantUser`]); the rules are the renderer's, not caller text. Needs an admin connection.
    pub fn provision(&mut self, u: &crate::render::TenantUser) -> Result<(), Error> {
        let pass = format!(">{}", u.password());
        let mut args: Vec<&[u8]> = vec![b"ACL", b"SETUSER", u.username().as_bytes(), b"reset", b"on", pass.as_bytes()];
        let rules = u.rules();
        args.extend(rules.iter().map(|r| r.as_bytes()));
        match self.exchange(&args)? {
            Reply::Simple(s) if s == b"OK" => Ok(()),
            other => Err(Error::Unexpected(format!("ACL SETUSER: {other:?}"))),
        }
    }

    /// `ACL DELUSER <user>` for a per-tenant user name ([`crate::render::tenant_username`] shape only).
    pub fn deprovision(&mut self, username: &str) -> Result<bool, Error> {
        if !crate::render::is_tenant_username(username) {
            return Err(Error::Usage("not a per-tenant user name".into()));
        }
        match self.exchange(&[b"ACL", b"DELUSER", username.as_bytes()])? {
            Reply::Int(n) => Ok(n > 0),
            other => Err(Error::Unexpected(format!("ACL DELUSER: {other:?}"))),
        }
    }

    /// PLAN D12 boot check, on the provisioning connection: `ACL GETUSER default` must show the user `off`, or `on`
    /// with no permissions at all (`-@all`, no key pattern, no channel, no selector). `RESET` (never ACL-checked)
    /// re-authenticates a connection as `default`, so an enabled, permitted `default` would undo the per-tenant user.
    pub fn check_default_user(&mut self) -> Result<(), Error> {
        let r = self.exchange(&[b"ACL", b"GETUSER", b"default"])?;
        default_user_verdict(&r).map_err(Error::DefaultUserEnabled)
    }

    /// First admission plus the D12 check: the only way the adapter should open its provisioning connection at
    /// boot. Refuses to return a connection if either fails.
    pub fn connect_provisioning(cfg: &ConnectConfig, pins: &KvPins) -> Result<Connection, Error> {
        let mut c = Connection::connect(cfg, pins, None)?;
        c.check_default_user()?;
        Ok(c)
    }

    /// Best-effort `QUIT` within `timeout`, then close.
    pub fn close(mut self, timeout: Duration) {
        if !self.broken {
            self.io_timeout = timeout;
            let _ = self.exchange(&[b"QUIT"]);
        }
    }
}

/// Verdict on an `ACL GETUSER default` reply (RESP2 flat field/value array). `Ok` iff the user is `off`, or has
/// exactly `commands = -@all`, empty `keys`, empty `channels` and no selectors. Anything unreadable is refused.
pub fn default_user_verdict(r: &Reply) -> Result<(), String> {
    let items = match r {
        Reply::Array(Some(v)) if v.len() % 2 == 0 => v,
        Reply::Array(None) | Reply::Bulk(None) => return Err("does not exist? (unexpected nil)".into()),
        other => return Err(format!("unreadable ACL GETUSER reply {other:?}")),
    };
    let field = |name: &[u8]| {
        items
            .as_chunks::<2>()
            .0
            .iter()
            .find(|[k, _]| matches!(k, Reply::Bulk(Some(b)) if b.as_slice() == name))
            .map(|[_, v]| v)
    };
    let text = |v: Option<&Reply>| match v {
        Some(Reply::Bulk(Some(b))) => Some(b.clone()),
        _ => None,
    };
    let flags: Vec<Vec<u8>> = match field(b"flags") {
        Some(Reply::Array(Some(fs))) => fs
            .iter()
            .filter_map(|f| match f {
                Reply::Bulk(Some(b)) | Reply::Simple(b) => Some(b.clone()),
                _ => None,
            })
            .collect(),
        _ => return Err("no readable flags".into()),
    };
    if flags.iter().any(|f| f == b"off") {
        return Ok(());
    }
    if !flags.iter().any(|f| f == b"on") {
        return Err("neither on nor off".into());
    }
    let commands = text(field(b"commands"));
    let keys = text(field(b"keys"));
    let channels = text(field(b"channels"));
    let no_selectors = matches!(field(b"selectors"), Some(Reply::Array(Some(s))) if s.is_empty());
    if commands.as_deref() == Some(b"-@all".as_slice())
        && keys.as_deref() == Some(b"".as_slice())
        && channels.as_deref() == Some(b"".as_slice())
        && no_selectors
    {
        return Ok(());
    }
    Err(format!(
        "is on with commands {:?}, keys {:?}, channels {:?}",
        commands.map(|c| String::from_utf8_lossy(&c).into_owned()),
        keys.map(|c| String::from_utf8_lossy(&c).into_owned()),
        channels.map(|c| String::from_utf8_lossy(&c).into_owned())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let c = ConnectConfig::from_url("redis://127.0.0.1:6380");
        assert!(matches!(&c, Ok(c) if c.endpoint == Endpoint::Tcp { host: "127.0.0.1".into(), port: 6380 }));
        let c = ConnectConfig::from_url("redis://u%40x:p%3Aw@h/0");
        assert!(matches!(&c, Ok(c) if c.username.as_deref() == Some("u@x") && c.password.as_deref() == Some("p:w")
                && c.endpoint == Endpoint::Tcp { host: "h".into(), port: 6379 }));
        assert!(matches!(ConnectConfig::from_url("redis://[::1]:7000"),
            Ok(c) if c.endpoint == Endpoint::Tcp { host: "::1".into(), port: 7000 }));
        assert!(matches!(ConnectConfig::from_url("unix:///run/valkey.sock"),
            Ok(c) if c.endpoint == Endpoint::Unix { path: "/run/valkey.sock".into() }));
        for bad in [
            "rediss://h",
            "redis://h/1",
            "redis://h:0",
            "redis://h:99999",
            "redis://h?x=1",
            "redis://:p%0d%0aFLUSHALL@h",
            "redis://h/%00",
            "http://h",
            "redis://",
            "unix://rel",
            "redis://h h",
        ] {
            assert!(ConnectConfig::from_url(bad).is_err(), "{bad}");
        }
        let dbg = format!("{:?}", ConnectConfig::from_url("redis://u:secret@h"));
        assert!(!dbg.contains("secret"));
    }

    fn getuser(flags: &[&str], commands: &str, keys: &str, channels: &str, selectors: usize) -> Reply {
        let b = |s: &str| Reply::Bulk(Some(s.as_bytes().to_vec()));
        Reply::Array(Some(vec![
            b("flags"),
            Reply::Array(Some(flags.iter().map(|f| b(f)).collect())),
            b("passwords"),
            Reply::Array(Some(vec![])),
            b("commands"),
            b(commands),
            b("keys"),
            b(keys),
            b("channels"),
            b(channels),
            b("selectors"),
            Reply::Array(Some((0..selectors).map(|_| Reply::Array(Some(vec![]))).collect())),
        ]))
    }

    #[test]
    fn default_user_d12() {
        // Stock engine default: on, nopass, +@all ~* &* -> refuse.
        assert!(default_user_verdict(&getuser(&["on", "nopass"], "+@all", "~*", "&*", 0)).is_err());
        assert!(default_user_verdict(&getuser(&["off", "nopass"], "+@all", "~*", "&*", 0)).is_ok());
        assert!(default_user_verdict(&getuser(&["on", "nopass"], "-@all", "", "", 0)).is_ok());
        for (cmds, keys, chans, sel) in
            [("-@all +ping", "", "", 0), ("-@all", "~x", "", 0), ("-@all", "", "&*", 0), ("-@all", "", "", 1)]
        {
            assert!(default_user_verdict(&getuser(&["on"], cmds, keys, chans, sel)).is_err(), "{cmds} {keys} {chans}");
        }
        assert!(default_user_verdict(&getuser(&["nopass"], "-@all", "", "", 0)).is_err());
        assert!(default_user_verdict(&Reply::Error(b"ERR".to_vec())).is_err());
        assert!(default_user_verdict(&Reply::Array(None)).is_err());
    }

    #[test]
    fn hello_and_info_parse() {
        let r = Reply::Array(Some(vec![
            Reply::Bulk(Some(b"server".to_vec())),
            Reply::Bulk(Some(b"valkey".to_vec())),
            Reply::Bulk(Some(b"version".to_vec())),
            Reply::Bulk(Some(b"9.1.2".to_vec())),
            Reply::Bulk(Some(b"proto".to_vec())),
            Reply::Int(2),
        ]));
        assert!(matches!(parse_hello(&r), Ok((Some(s), Some(v))) if s == "valkey" && v == "9.1.2"));
        assert!(parse_hello(&Reply::Int(1)).is_err());
        let info = parse_info(b"# Server\r\nredis_version:7.2.4\r\nserver_name:valkey\r\nvalkey_version:9.1.2\r\n");
        assert!(info.contains(&("valkey_version".into(), "9.1.2".into())));
        assert!(info.contains(&("redis_version".into(), "7.2.4".into())));
    }
}
