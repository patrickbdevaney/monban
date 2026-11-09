//! Blocking PG v3 connection over TCP or a Unix socket (std::net / std::os::unix; DEVIATIONS X-10).
//!
//! Every read is bounded: a per-message length cap ([`ConnectConfig::max_message`]), a caller deadline turned into
//! the socket read timeout before each read, a cap on startup chatter, and result caps (rows, bytes) on the
//! collecting helpers. Reads are buffered so that a timeout never loses framing: after `Error::Timeout` the
//! [`ProtoState`] still knows every outstanding reply and [`Connection::drain`] can finish them (NC3 recovery
//! without CancelRequest). Writes are all-or-nothing from the state's point of view: a failed or timed-out write
//! marks the connection unrecoverable.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use super::dsn::{ConnectConfig, Endpoint};
use super::msg::{self, Auth, Backend, CodecError, DbError, FieldDesc, TxnStatus};
use super::state::{Event, Expect, ProtoState, Unrecoverable};
use crate::auth::{MECHANISM, ScramAwaitFinal, ScramClient, ScramError};

/// Startup: at most this many messages between StartupMessage and ReadyForQuery.
const MAX_STARTUP_MESSAGES: usize = 512;
/// Read chunk size.
const CHUNK: usize = 16 * 1024;
/// Default result caps for the collecting helpers.
pub const DEFAULT_MAX_ROWS: usize = 1_000_000;
pub const DEFAULT_MAX_RESULT_BYTES: usize = 64 << 20;

#[derive(Debug)]
pub enum Error {
    Dsn(super::dsn::DsnError),
    /// Socket connect failed (nothing was started).
    Connect(String),
    /// The deadline passed. If the state is still recoverable, outstanding replies can be drained.
    Timeout,
    /// The connection is (now) unusable: discard it.
    Unrecoverable(Unrecoverable),
    /// Startup/authentication refused or failed.
    Auth(String),
    Scram(ScramError),
    /// Server error in response to a statement; the connection is synchronized again (ReadyForQuery seen).
    Db(DbError),
    /// The caller asked for something invalid (NUL in SQL, wrong state); nothing was sent.
    Usage(String),
    /// A result exceeded the caller's row/byte cap. Replies are still outstanding; `drain` them or discard.
    ResultTooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Dsn(e) => write!(f, "{e}"),
            Error::Connect(e) => write!(f, "connect failed: {e}"),
            Error::Timeout => write!(f, "timeout"),
            Error::Unrecoverable(u) => write!(f, "{u}"),
            Error::Auth(e) => write!(f, "authentication failed: {e}"),
            Error::Scram(e) => write!(f, "{e}"),
            Error::Db(e) => write!(f, "{e}"),
            Error::Usage(e) => write!(f, "usage: {e}"),
            Error::ResultTooLarge => write!(f, "result exceeds cap"),
        }
    }
}

impl std::error::Error for Error {}

impl From<ScramError> for Error {
    fn from(e: ScramError) -> Self {
        Error::Scram(e)
    }
}

#[derive(Debug)]
enum Stream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Stream {
    fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        match self {
            Stream::Tcp(s) => s.set_read_timeout(d),
            Stream::Unix(s) => s.set_read_timeout(d),
        }
    }
    fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        match self {
            Stream::Tcp(s) => s.set_write_timeout(d),
            Stream::Unix(s) => s.set_write_timeout(d),
        }
    }
    fn fd(&self) -> BorrowedFd<'_> {
        match self {
            Stream::Tcp(s) => s.as_fd(),
            Stream::Unix(s) => s.as_fd(),
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.read(buf),
            Stream::Unix(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.write(buf),
            Stream::Unix(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Tcp(s) => s.flush(),
            Stream::Unix(s) => s.flush(),
        }
    }
}

/// Key for CancelRequest (BackendKeyData).
#[derive(Clone, PartialEq, Eq)]
pub struct CancelKey {
    pub endpoint: Endpoint,
    pub pid: i32,
    secret: Vec<u8>,
}

impl fmt::Debug for CancelKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CancelKey").field("endpoint", &self.endpoint).field("pid", &self.pid).finish_non_exhaustive()
    }
}

/// Collected result of one statement.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryResult {
    pub columns: Vec<FieldDesc>,
    /// Text-format values; `None` = SQL NULL.
    pub rows: Vec<Vec<Option<String>>>,
    /// CommandComplete tag (`"SELECT 3"`, `"INSERT 0 1"`); empty for an empty query or a suspended portal.
    pub tag: String,
}

/// Caps applied by the collecting helpers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResultLimits {
    pub max_rows: usize,
    pub max_bytes: usize,
}

impl Default for ResultLimits {
    fn default() -> Self {
        ResultLimits { max_rows: DEFAULT_MAX_ROWS, max_bytes: DEFAULT_MAX_RESULT_BYTES }
    }
}

/// One started PG v3 session.
pub struct Connection {
    stream: Stream,
    endpoint: Endpoint,
    rbuf: Vec<u8>,
    max_message: usize,
    params: BTreeMap<String, String>,
    cancel: Option<CancelKey>,
    state: ProtoState,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("endpoint", &self.endpoint)
            .field("server_version", &self.server_version())
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

fn remaining(deadline: Instant) -> Result<Duration, Error> {
    let r = deadline.saturating_duration_since(Instant::now());
    if r.is_zero() { Err(Error::Timeout) } else { Ok(r) }
}

fn open(cfg: &ConnectConfig, deadline: Instant) -> Result<Stream, Error> {
    match &cfg.endpoint {
        Endpoint::Tcp { host, port } => {
            let addrs: Vec<SocketAddr> = (host.as_str(), *port)
                .to_socket_addrs()
                .map_err(|e| Error::Connect(format!("resolve: {e}")))?
                .collect();
            let mut last = String::from("no address");
            for a in addrs {
                let t = remaining(deadline)?;
                match TcpStream::connect_timeout(&a, t) {
                    Ok(s) => {
                        s.set_nodelay(true).map_err(|e| Error::Connect(e.to_string()))?;
                        return Ok(Stream::Tcp(s));
                    }
                    Err(e) => last = format!("{a}: {e}"),
                }
            }
            Err(Error::Connect(last))
        }
        Endpoint::Unix { path } => connect_unix(path, deadline).map(Stream::Unix),
    }
}

/// Unix-socket connect bounded by `deadline` (PREFLIGHT R14). `UnixStream::connect` has no timeout, and on Linux an
/// AF_UNIX stream connect blocks while the listener's backlog is full (a stalled or overloaded server). The kernel
/// bounds that wait by the socket's send timeout (`unix_stream_connect` sleeps `sock_sndtimeo`, then `EAGAIN`), so
/// the socket is created with `SO_SNDTIMEO` = the time left, connected, and the timeout cleared again (later writes
/// set their own). A full backlog past the deadline is [`Error::Timeout`]; `EINTR` retries within the deadline.
fn connect_unix(path: &std::path::Path, deadline: Instant) -> Result<UnixStream, Error> {
    use rustix::net::sockopt::{Timeout, set_socket_timeout};
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
    let ctx = |e: rustix::io::Errno| Error::Connect(format!("{}: {e}", path.display()));
    let addr = SocketAddrUnix::new(path).map_err(ctx)?;
    let fd =
        rustix::net::socket_with(AddressFamily::UNIX, SocketType::STREAM, SocketFlags::CLOEXEC, None).map_err(ctx)?;
    loop {
        set_socket_timeout(&fd, Timeout::Send, Some(remaining(deadline)?)).map_err(ctx)?;
        match rustix::net::connect(&fd, &addr) {
            Ok(()) => break,
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) if e == rustix::io::Errno::AGAIN || e == rustix::io::Errno::WOULDBLOCK => {
                return Err(if Instant::now() >= deadline { Error::Timeout } else { ctx(e) });
            }
            Err(e) => return Err(ctx(e)),
        }
    }
    set_socket_timeout(&fd, Timeout::Send, None).map_err(ctx)?;
    Ok(UnixStream::from(fd))
}

/// Send a CancelRequest for `key` on a fresh connection (NC3 discard path only: never for a connection that will be
/// checked back in). Best effort: success means the request was written.
pub fn send_cancel(key: &CancelKey, timeout: Duration) -> Result<(), Error> {
    let deadline = Instant::now() + timeout;
    let cfg_like = ConnectConfig {
        endpoint: key.endpoint.clone(),
        user: String::new(),
        password: None,
        dbname: String::new(),
        application_name: None,
        statement_timeout_ms: None,
        connect_timeout: timeout,
        max_message: msg::DEFAULT_MAX_MESSAGE,
    };
    let mut s = open(&cfg_like, deadline)?;
    let pkt = msg::cancel_request(key.pid, &key.secret).map_err(|e| Error::Usage(e.to_string()))?;
    s.set_write_timeout(Some(remaining(deadline)?)).map_err(|e| Error::Connect(e.to_string()))?;
    s.write_all(&pkt).map_err(|e| Error::Connect(e.to_string()))
}

impl Connection {
    /// Open, start up and authenticate (trust or SCRAM-SHA-256; cleartext, MD5 and anything else refused). No
    /// version gate here: use [`crate::connect_admitted`] for that.
    pub fn connect(cfg: &ConnectConfig) -> Result<Connection, Error> {
        let deadline = Instant::now() + cfg.connect_timeout;
        let stream = open(cfg, deadline)?;
        let mut c = Connection {
            stream,
            endpoint: cfg.endpoint.clone(),
            rbuf: Vec::new(),
            max_message: cfg.max_message.clamp(1024, msg::HARD_MAX_MESSAGE),
            params: BTreeMap::new(),
            cancel: None,
            state: ProtoState::default(),
        };
        c.startup(cfg, deadline)?;
        Ok(c)
    }

    fn startup(&mut self, cfg: &ConnectConfig, deadline: Instant) -> Result<(), Error> {
        let stmt_to = cfg.statement_timeout_ms.map(|ms| ms.to_string());
        let mut params: Vec<(&str, &str)> = vec![
            ("user", cfg.user.as_str()),
            ("database", cfg.dbname.as_str()),
            ("client_encoding", "UTF8"),
            ("DateStyle", "ISO"),
        ];
        if let Some(a) = &cfg.application_name {
            params.push(("application_name", a.as_str()));
        }
        if let Some(t) = &stmt_to {
            params.push(("statement_timeout", t.as_str()));
        }
        let mut out = Vec::new();
        msg::startup(&mut out, &params).map_err(|e| Error::Usage(e.to_string()))?;
        self.write_raw(&out, deadline)?;

        let mut scram: Option<ScramClient> = None;
        let mut await_final: Option<ScramAwaitFinal> = None;
        let mut verified = false;
        let mut authed = false;
        for _ in 0..MAX_STARTUP_MESSAGES {
            let (tag, body) = self.next_frame(deadline)?;
            let m = msg::parse_backend(tag, &body).map_err(|e| self.framing(e))?;
            match m {
                Backend::Authentication(a) => {
                    if authed {
                        return Err(self.fail("authentication message after AuthenticationOk"));
                    }
                    match a {
                        Auth::Ok => {
                            // Trust is accepted; a SCRAM exchange that started must have been verified first.
                            if (scram.is_some() || await_final.is_some()) && !verified {
                                return Err(self.fail("AuthenticationOk before the SCRAM server signature"));
                            }
                            authed = true;
                        }
                        Auth::Sasl(mechs) => {
                            if scram.is_some() || await_final.is_some() || verified {
                                return Err(self.fail("repeated SASL request"));
                            }
                            if !mechs.iter().any(|m| m == MECHANISM) {
                                return Err(self.fail(&format!("server offers no {MECHANISM}: {mechs:?}")));
                            }
                            let pw = cfg.password.as_deref().ok_or(Error::Auth("password required".into()))?;
                            let (client, first) = ScramClient::new(pw)?;
                            let mut out = Vec::new();
                            msg::sasl_initial(&mut out, MECHANISM, first.as_bytes())
                                .map_err(|e| Error::Usage(e.to_string()))?;
                            self.write_raw(&out, deadline)?;
                            scram = Some(client);
                        }
                        Auth::SaslContinue(data) => {
                            let client = scram.take().ok_or(Error::Auth("SASL continue out of order".into()))?;
                            let (fin, reply) = client.server_first(&data)?;
                            let mut out = Vec::new();
                            msg::sasl_response(&mut out, reply.as_bytes()).map_err(|e| Error::Usage(e.to_string()))?;
                            self.write_raw(&out, deadline)?;
                            await_final = Some(fin);
                        }
                        Auth::SaslFinal(data) => {
                            let fin = await_final.take().ok_or(Error::Auth("SASL final out of order".into()))?;
                            fin.server_final(&data)?;
                            verified = true;
                        }
                        Auth::CleartextPassword => return Err(self.fail("server asks for a cleartext password")),
                        Auth::Md5Password => return Err(self.fail("server asks for MD5 (refused)")),
                        Auth::Other(code) => return Err(self.fail(&format!("unsupported auth method {code}"))),
                    }
                }
                Backend::ErrorResponse(e) => {
                    self.state.mark(Unrecoverable::Fatal(e.to_string()));
                    return Err(Error::Auth(e.to_string()));
                }
                Backend::NoticeResponse(_) => {}
                Backend::NegotiateProtocolVersion { .. } => {
                    return Err(self.fail("server downgraded the protocol (NegotiateProtocolVersion)"));
                }
                Backend::ParameterStatus { name, value } if authed => {
                    if self.params.len() >= 256 && !self.params.contains_key(&name) {
                        return Err(self.fail("too many ParameterStatus messages"));
                    }
                    self.params.insert(name, value);
                }
                Backend::BackendKeyData { pid, secret } if authed => {
                    self.cancel = Some(CancelKey { endpoint: self.endpoint.clone(), pid, secret });
                }
                Backend::ReadyForQuery(s) if authed => {
                    if let Some(enc) = self.params.get("client_encoding").cloned()
                        && !enc.eq_ignore_ascii_case("UTF8")
                    {
                        return Err(self.fail(&format!("client_encoding {enc} (UTF8 required)")));
                    }
                    self.state.started(s);
                    return Ok(());
                }
                other => return Err(self.fail(&format!("unexpected startup message {other:?}"))),
            }
        }
        Err(self.fail("startup did not finish within the message cap"))
    }

    fn fail(&mut self, m: &str) -> Error {
        self.state.mark(Unrecoverable::Desync(m.to_owned()));
        Error::Auth(m.to_owned())
    }

    fn framing(&mut self, e: CodecError) -> Error {
        let u = Unrecoverable::Framing(e.to_string());
        self.state.mark(u.clone());
        Error::Unrecoverable(u)
    }

    fn io(&mut self, e: &io::Error) -> Error {
        let u = Unrecoverable::Io(e.to_string());
        self.state.mark(u.clone());
        Error::Unrecoverable(u)
    }

    fn write_raw(&mut self, data: &[u8], deadline: Instant) -> Result<(), Error> {
        if let Some(u) = self.state.unrecoverable() {
            return Err(Error::Unrecoverable(u.clone()));
        }
        let t = remaining(deadline)?; // a timeout here wrote nothing: state unchanged
        if let Err(e) = self.stream.set_write_timeout(Some(t)) {
            return Err(self.io(&e));
        }
        if let Err(e) = self.stream.write_all(data) {
            return Err(self.io(&e));
        }
        Ok(())
    }

    /// Next complete frame from the buffer, reading as needed until `deadline`. Framing errors are unrecoverable;
    /// a timeout leaves the buffer (and the state) intact.
    fn next_frame(&mut self, deadline: Instant) -> Result<(u8, Vec<u8>), Error> {
        if let Some(u) = self.state.unrecoverable() {
            return Err(Error::Unrecoverable(u.clone()));
        }
        loop {
            let header = self.rbuf.split_first_chunk::<5>().map(|(h, _)| *h);
            if let Some([tag, l0, l1, l2, l3]) = header {
                let body_len = msg::body_len(tag, [l0, l1, l2, l3], self.max_message).map_err(|e| self.framing(e))?;
                let total = body_len.saturating_add(5);
                if self.rbuf.len() >= total {
                    let mut frame: Vec<u8> = self.rbuf.drain(..total).collect();
                    let body = frame.split_off(5);
                    return Ok((tag, body));
                }
            }
            let t = remaining(deadline)?;
            if let Err(e) = self.stream.set_read_timeout(Some(t)) {
                return Err(self.io(&e));
            }
            let mut chunk = [0u8; CHUNK];
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    let u = Unrecoverable::Io("EOF".into());
                    self.state.mark(u.clone());
                    return Err(Error::Unrecoverable(u));
                }
                Ok(n) => self.rbuf.extend_from_slice(chunk.get(..n).unwrap_or_default()),
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                    return Err(Error::Timeout);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(self.io(&e)),
            }
        }
    }

    // --------------------------------------------------------------------------------------------- inspection

    /// Exact protocol state (NC3 input).
    pub fn state(&self) -> &ProtoState {
        &self.state
    }
    /// The full `server_version` ParameterStatus, if reported.
    pub fn server_version(&self) -> Option<&str> {
        self.params.get("server_version").map(String::as_str)
    }
    /// Latest value of a ParameterStatus.
    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(String::as_str)
    }
    pub fn cancel_key(&self) -> Option<&CancelKey> {
        self.cancel.as_ref()
    }
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Idle-socket liveness probe for pooled reuse: true iff the state is clean and the socket has neither unread
    /// bytes nor EOF pending (a non-blocking `MSG_PEEK`). Unsolicited bytes on an idle connection (FATAL 57P01 on
    /// shutdown, a notice) make it non-reusable: fail closed.
    pub fn is_reusable(&self) -> bool {
        if !self.state.is_clean() || !self.rbuf.is_empty() {
            return false;
        }
        let mut b = [0u8; 1];
        match rustix::net::recv(
            self.stream.fd(),
            &mut b,
            rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
        ) {
            Err(e) => e == rustix::io::Errno::AGAIN || e == rustix::io::Errno::WOULDBLOCK,
            Ok(_) => false,
        }
    }

    // --------------------------------------------------------------------------------------------- pipelined API

    fn check_usable(&self) -> Result<(), Error> {
        match self.state.unrecoverable() {
            Some(u) => Err(Error::Unrecoverable(u.clone())),
            None => Ok(()),
        }
    }

    /// Send a pipeline built with [`Pipeline`]; the expected replies are recorded before the write.
    pub fn send(&mut self, p: Pipeline, deadline: Instant) -> Result<(), Error> {
        self.check_usable()?;
        remaining(deadline)?;
        for e in p.expect {
            self.state.sent(e);
        }
        self.write_raw(&p.buf, deadline)
    }

    /// Read and apply one backend message. Errors other than `Timeout` leave the connection unrecoverable.
    pub fn read_event(&mut self, deadline: Instant) -> Result<(Event, Backend), Error> {
        let (tag, body) = self.next_frame(deadline)?;
        let m = msg::parse_backend(tag, &body).map_err(|e| self.framing(e))?;
        let ev = self.state.on_backend(&m).map_err(Error::Unrecoverable)?;
        if let Backend::ParameterStatus { name, value } = &m
            && (self.params.len() < 256 || self.params.contains_key(name))
        {
            self.params.insert(name.clone(), value.clone());
        }
        Ok((ev, m))
    }

    /// Read until no reply is outstanding, discarding results (NC3 recovery drain; never sends CancelRequest).
    /// Returns the final txn status. Bounded by `deadline` and the message cap.
    pub fn drain(&mut self, deadline: Instant) -> Result<TxnStatus, Error> {
        self.check_usable()?;
        if self.state.skip_until_sync() {
            let mut p = Pipeline::default();
            p.sync();
            self.send(p, deadline)?;
        }
        while self.state.outstanding() > 0 {
            self.read_event(deadline)?;
        }
        self.state.txn_status().ok_or(Error::Usage("no ReadyForQuery yet".into()))
    }

    /// Collect replies up to and including the next ReadyForQuery into per-statement results. A server error is
    /// returned as `Error::Db` after ReadyForQuery (the connection is synchronized again).
    fn collect(&mut self, deadline: Instant, lim: ResultLimits) -> Result<Vec<QueryResult>, Error> {
        let mut results = Vec::new();
        let mut cur = QueryResult::default();
        let mut bytes = 0usize;
        let mut rows = 0usize;
        let mut err: Option<DbError> = None;
        loop {
            let (ev, m) = self.read_event(deadline)?;
            match m {
                Backend::RowDescription(cols) => cur.columns = cols,
                Backend::DataRow(vals) => {
                    rows += 1;
                    if rows > lim.max_rows {
                        return Err(Error::ResultTooLarge);
                    }
                    let mut row = Vec::with_capacity(vals.len());
                    for v in vals {
                        match v {
                            None => row.push(None),
                            Some(b) => {
                                bytes = bytes.saturating_add(b.len());
                                if bytes > lim.max_bytes {
                                    return Err(Error::ResultTooLarge);
                                }
                                match String::from_utf8(b) {
                                    Ok(s) => row.push(Some(s)),
                                    Err(_) => return Err(Error::Usage("non-UTF-8 text value".into())),
                                }
                            }
                        }
                    }
                    cur.rows.push(row);
                }
                Backend::CommandComplete(tag) => {
                    cur.tag = tag;
                    results.push(std::mem::take(&mut cur));
                }
                Backend::EmptyQueryResponse | Backend::PortalSuspended => {
                    results.push(std::mem::take(&mut cur));
                }
                Backend::ErrorResponse(e) => {
                    if err.is_none() {
                        err = Some(e);
                    }
                    cur = QueryResult::default();
                }
                _ => {}
            }
            if let Event::Ready(_) = ev {
                return match err {
                    Some(e) => Err(Error::Db(e)),
                    None => Ok(results),
                };
            }
        }
    }

    /// Extended query with text parameters on the unnamed statement and portal: Parse, Bind, Describe(portal),
    /// Execute, Sync. Returns the single statement's result.
    pub fn query(&mut self, sql: &str, params: &[Option<&str>], deadline: Instant) -> Result<QueryResult, Error> {
        self.query_limited(sql, params, deadline, ResultLimits::default())
    }

    pub fn query_limited(
        &mut self,
        sql: &str,
        params: &[Option<&str>],
        deadline: Instant,
        lim: ResultLimits,
    ) -> Result<QueryResult, Error> {
        if self.state.outstanding() > 0 {
            return Err(Error::Usage("replies outstanding; drain first".into()));
        }
        let mut p = Pipeline::default();
        p.parse("", sql, &[])?;
        p.bind("", "", params)?;
        p.describe_portal("")?;
        p.execute("", 0)?;
        p.sync();
        self.send(p, deadline)?;
        let mut rs = self.collect(deadline, lim)?;
        if rs.len() > 1 {
            return Err(Error::Usage("more than one result".into()));
        }
        Ok(rs.pop().unwrap_or_default())
    }

    /// Simple Query protocol (no parameters). Every statement's result in order.
    pub fn simple_query(&mut self, sql: &str, deadline: Instant) -> Result<Vec<QueryResult>, Error> {
        if self.state.outstanding() > 0 {
            return Err(Error::Usage("replies outstanding; drain first".into()));
        }
        let mut p = Pipeline::default();
        p.query(sql)?;
        self.send(p, deadline)?;
        self.collect(deadline, ResultLimits::default())
    }

    /// Per-op statement budget: `set_config('statement_timeout', ms, is_local => true)`, which lasts until the end
    /// of the current transaction (outside an explicit transaction it covers nothing later; use the startup GUC).
    pub fn set_local_statement_timeout(&mut self, ms: u32, deadline: Instant) -> Result<(), Error> {
        let v = format!("{ms}ms");
        self.query("SELECT pg_catalog.set_config('statement_timeout', $1, true)", &[Some(&v)], deadline).map(|_| ())
    }

    /// Send Terminate and drop the socket (best effort, bounded by `timeout`).
    pub fn terminate(mut self, timeout: Duration) {
        let mut out = Vec::new();
        msg::terminate(&mut out);
        let _ = self.write_raw(&out, Instant::now() + timeout);
        self.state.mark(Unrecoverable::Closed);
    }
}

/// A batch of frontend messages with their expected replies, sent in one write.
#[derive(Debug, Default)]
pub struct Pipeline {
    buf: Vec<u8>,
    expect: Vec<Expect>,
}

fn usage(e: CodecError) -> Error {
    Error::Usage(e.to_string())
}

impl Pipeline {
    pub fn parse(&mut self, stmt: &str, sql: &str, param_types: &[u32]) -> Result<&mut Self, Error> {
        msg::parse(&mut self.buf, stmt, sql, param_types).map_err(usage)?;
        self.expect.push(Expect::Parse(stmt.to_owned()));
        Ok(self)
    }
    pub fn bind(&mut self, portal: &str, stmt: &str, params: &[Option<&str>]) -> Result<&mut Self, Error> {
        msg::bind(&mut self.buf, portal, stmt, params).map_err(usage)?;
        self.expect.push(Expect::Bind(portal.to_owned()));
        Ok(self)
    }
    pub fn describe_statement(&mut self, stmt: &str) -> Result<&mut Self, Error> {
        msg::describe(&mut self.buf, b'S', stmt).map_err(usage)?;
        self.expect.push(Expect::DescribeStatement { got_params: false });
        Ok(self)
    }
    pub fn describe_portal(&mut self, portal: &str) -> Result<&mut Self, Error> {
        msg::describe(&mut self.buf, b'P', portal).map_err(usage)?;
        self.expect.push(Expect::DescribePortal);
        Ok(self)
    }
    pub fn execute(&mut self, portal: &str, max_rows: u32) -> Result<&mut Self, Error> {
        msg::execute(&mut self.buf, portal, max_rows).map_err(usage)?;
        self.expect.push(Expect::Execute);
        Ok(self)
    }
    pub fn close_statement(&mut self, stmt: &str) -> Result<&mut Self, Error> {
        msg::close(&mut self.buf, b'S', stmt).map_err(usage)?;
        self.expect.push(Expect::Close(b'S', stmt.to_owned()));
        Ok(self)
    }
    pub fn close_portal(&mut self, portal: &str) -> Result<&mut Self, Error> {
        msg::close(&mut self.buf, b'P', portal).map_err(usage)?;
        self.expect.push(Expect::Close(b'P', portal.to_owned()));
        Ok(self)
    }
    pub fn sync(&mut self) -> &mut Self {
        msg::sync(&mut self.buf);
        self.expect.push(Expect::Sync);
        self
    }
    pub fn flush(&mut self) -> &mut Self {
        msg::flush(&mut self.buf);
        self
    }
    pub fn query(&mut self, sql: &str) -> Result<&mut Self, Error> {
        msg::query(&mut self.buf, sql).map_err(usage)?;
        self.expect.push(Expect::Query);
        Ok(self)
    }
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

#[cfg(test)]
mod unix_connect_tests {
    use super::*;
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

    /// A listener with backlog 0 that never accepts: the first connect fills the queue, later ones would block in
    /// the kernel forever without a bound.
    #[test]
    fn unix_connect_to_a_full_backlog_times_out() -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!("aegis-pg-uds-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(".s.PGSQL.5432");
        let l = rustix::net::socket_with(AddressFamily::UNIX, SocketType::STREAM, SocketFlags::CLOEXEC, None)
            .map_err(|e| e.to_string())?;
        rustix::net::bind(&l, &SocketAddrUnix::new(&path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        rustix::net::listen(&l, 0).map_err(|e| e.to_string())?;
        // Fill the queue with non-blocking connects until the kernel says it is full.
        let mut fill = Vec::new();
        for _ in 0..64 {
            let c = rustix::net::socket_with(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
                None,
            )
            .map_err(|e| e.to_string())?;
            match rustix::net::connect(&c, &SocketAddrUnix::new(&path).map_err(|e| e.to_string())?) {
                Ok(()) => fill.push(c),
                Err(_) => break,
            }
        }
        let t0 = Instant::now();
        let r = connect_unix(&path, t0 + Duration::from_millis(300));
        let took = t0.elapsed();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(r, Err(Error::Timeout)), "full backlog must time out, got {:?}", r.map(|_| ()));
        assert!(took >= Duration::from_millis(250) && took < Duration::from_secs(5), "bounded wait, took {took:?}");
        // A live listener still connects.
        let ok_dir = std::env::temp_dir().join(format!("aegis-pg-uds-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ok_dir);
        std::fs::create_dir_all(&ok_dir).map_err(|e| e.to_string())?;
        let ok_path = ok_dir.join("s");
        let _lis = std::os::unix::net::UnixListener::bind(&ok_path).map_err(|e| e.to_string())?;
        let s = connect_unix(&ok_path, Instant::now() + Duration::from_secs(2));
        let _ = std::fs::remove_dir_all(&ok_dir);
        assert!(s.is_ok(), "connect to a listening socket: {:?}", s.map(|_| ()));
        // Missing socket: an immediate connect error, not a timeout.
        let missing = connect_unix(
            std::path::Path::new("/nonexistent/aegis/.s.PGSQL.1"),
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(missing, Err(Error::Connect(_))));
        drop(fill);
        Ok(())
    }
}
