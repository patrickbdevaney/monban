//! The owned MySQL/MariaDB wire client: one blocking TCP connection (loopback only, see [`crate::dsn`]).
//!
//! * Handshake v10, `HandshakeResponse41` with [`packet::CLIENT_CAPS`] (no multi-statements, no LOCAL INFILE, no
//!   SSL flag), `mysql_native_password` including the AuthSwitchRequest path; `caching_sha2_password` refused
//!   ([`crate::auth`]). At most [`MAX_AUTH_ROUNDS`] auth round trips.
//! * Commands are **only** `COM_STMT_PREPARE` / `COM_STMT_EXECUTE` (binary protocol, parameters bound, never
//!   interpolated into SQL text) / `COM_STMT_CLOSE` / `COM_QUIT`. There is no `COM_QUERY` in this client; session
//!   setup (`SET SESSION sql_mode`), `BEGIN` / `COMMIT` / `ROLLBACK` and catalog reads are prepared statements too.
//! * Every packet's sequence id is checked; a logical packet larger than `max_packet` is refused; result sets are
//!   capped by [`Limits`] (columns, rows, bytes). Connect and every read/write run under a deadline (socket
//!   timeouts set from it).
//! * Any I/O, framing or protocol error marks the connection broken: it is never reused (fail closed). A server ERR
//!   packet ends its response cleanly, so it is returned as [`MysqlError::Server`] and the connection stays usable.
//! * After connect the session is pinned (q4-005 denylist): `sql_mode = 'STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION,
//!   ERROR_FOR_DIVISION_BY_ZERO'` (a too-long tenant is an error, never a silent truncation), and the connection
//!   character set is checked to be utf8mb4 (the renderer's byte-length prefix test assumes UTF-8).

use std::io::{BufReader, ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

use crate::auth::{self, CACHING_SHA2, NATIVE};
use crate::dsn::ConnectConfig;
use crate::packet::{
    self, AuthReply, CHARSET_UTF8MB4_GENERAL_CI, CLIENT_CAPS, CLIENT_CONNECT_WITH_DB,
    CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA, Cell, ColumnDef, OkPacket, SERVER_MORE_RESULTS_EXISTS,
    SERVER_STATUS_IN_TRANS, parse_auth_reply, parse_handshake,
};
use crate::{MysqlError, version};

/// The session SQL mode every connection pins (q4-005: strict, so truncation is an error).
pub const SESSION_SQL_MODE: &str = "STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION,ERROR_FOR_DIVISION_BY_ZERO";
/// Most auth round trips after the handshake response (one switch is all mysql_native_password ever needs).
pub const MAX_AUTH_ROUNDS: usize = 3;
/// Most parameters one prepared statement can carry (the protocol's u16 count).
pub const MAX_PARAMS: usize = 65_535;
const MAX_PAYLOAD_CHUNK: usize = 0xff_ffff;
const TERMINATE: Duration = Duration::from_millis(200);

/// A bound parameter (binary protocol: LONGLONG or VAR_STRING; never NULL).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Param {
    Int(i64),
    Text(String),
}

/// Caps on one result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_columns: usize,
    pub max_rows: usize,
    /// Sum of row payload bytes.
    pub max_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_columns: 4096, max_rows: 1_000_000, max_bytes: 64 << 20 }
    }
}

/// One statement's outcome: the first result set (or none, for a statement without rows) and the final OK.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct QueryResult {
    pub columns: Vec<ColumnDef>,
    pub rows: Vec<Vec<Cell>>,
    pub affected_rows: u64,
    pub last_insert_id: u64,
}

/// An open, authenticated, session-pinned, version-admitted connection.
#[derive(Debug)]
pub struct Connection {
    rd: BufReader<TcpStream>,
    seq: u8,
    server_version: String,
    admitted: version::MariaVersion,
    connection_id: u32,
    status: u16,
    broken: bool,
    max_packet: usize,
    io_timeout: Duration,
    limits: Limits,
}

fn remaining(deadline: Instant) -> Result<Duration, MysqlError> {
    let r = deadline.saturating_duration_since(Instant::now());
    if r.is_zero() { Err(MysqlError::Timeout) } else { Ok(r) }
}

fn io_err(e: &std::io::Error) -> MysqlError {
    match e.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => MysqlError::Timeout,
        ErrorKind::UnexpectedEof => MysqlError::Io("connection closed by the server".into()),
        _ => MysqlError::Io(e.to_string()),
    }
}

impl Connection {
    /// Connect, authenticate, admit the server version ([`crate::version`]) and pin the session. Everything runs
    /// within `cfg.connect_timeout`.
    pub fn connect(cfg: &ConnectConfig) -> Result<Connection, MysqlError> {
        let deadline = Instant::now() + cfg.connect_timeout;
        if !crate::dsn::is_loopback(cfg.addr.ip()) {
            return Err(MysqlError::NotLoopback(cfg.addr.ip().to_string()));
        }
        let stream = TcpStream::connect_timeout(&cfg.addr, remaining(deadline)?)
            .map_err(|e| MysqlError::Connect(format!("{}: {e}", cfg.addr)))?;
        stream.set_nodelay(true).map_err(|e| MysqlError::Connect(e.to_string()))?;
        let mut c = Connection {
            rd: BufReader::with_capacity(64 << 10, stream),
            seq: 0,
            server_version: String::new(),
            admitted: version::MariaVersion { major: 0, minor: 0, patch: 0 },
            connection_id: 0,
            status: 0,
            broken: false,
            max_packet: cfg.max_packet,
            io_timeout: cfg.io_timeout,
            limits: Limits::default(),
        };
        match c.startup(cfg, deadline) {
            Ok(()) => Ok(c),
            Err(e) => {
                c.terminate(TERMINATE);
                Err(e)
            }
        }
    }

    fn startup(&mut self, cfg: &ConnectConfig, deadline: Instant) -> Result<(), MysqlError> {
        let hs = parse_handshake(&self.read_packet(deadline)?)?;
        self.server_version = hs.server_version.clone();
        self.connection_id = hs.connection_id;
        self.status = hs.status;
        // Admit the version before sending any credential.
        self.admitted = version::admit_server_version(&hs.server_version)?;
        let caps = CLIENT_CAPS & (hs.caps | CLIENT_CONNECT_WITH_DB);
        let caps = if cfg.database.is_empty() { caps & !CLIENT_CONNECT_WITH_DB } else { caps };
        // Whatever the server's default plugin, answer with mysql_native_password over the handshake scramble; a
        // user on another plugin gets an AuthSwitchRequest, handled (or refused) below.
        let scramble = auth::native_scramble(cfg.password.as_bytes(), &hs.salt);
        let mut resp = Vec::with_capacity(128);
        resp.extend_from_slice(&caps.to_le_bytes());
        resp.extend_from_slice(&(self.max_packet as u32).to_le_bytes());
        resp.push(CHARSET_UTF8MB4_GENERAL_CI);
        resp.extend_from_slice(&[0u8; 23]);
        resp.extend_from_slice(cfg.user.as_bytes());
        resp.push(0);
        if caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
            packet::enc_lenenc(scramble.len(), &mut resp);
        } else {
            resp.push(scramble.len() as u8);
        }
        resp.extend_from_slice(&scramble);
        if caps & CLIENT_CONNECT_WITH_DB != 0 {
            resp.extend_from_slice(cfg.database.as_bytes());
            resp.push(0);
        }
        resp.extend_from_slice(NATIVE.as_bytes());
        resp.push(0);
        self.write_packet(&resp, deadline)?;
        self.auth_loop(cfg, deadline)?;
        self.pin_session(deadline)
    }

    fn auth_loop(&mut self, cfg: &ConnectConfig, deadline: Instant) -> Result<(), MysqlError> {
        for _ in 0..MAX_AUTH_ROUNDS {
            match parse_auth_reply(&self.read_packet(deadline)?)? {
                AuthReply::Ok => return Ok(()),
                AuthReply::Err(e) => return Err(MysqlError::Server(e)),
                AuthReply::Switch { plugin, data } => {
                    if plugin == CACHING_SHA2 {
                        return Err(MysqlError::CachingSha2Refused);
                    }
                    if plugin != NATIVE {
                        return Err(MysqlError::Auth(format!("auth plugin {plugin:?} is not supported")));
                    }
                    if data.len() != 20 {
                        return Err(MysqlError::Protocol(format!("auth switch scramble of {} bytes", data.len())));
                    }
                    let s = auth::native_scramble(cfg.password.as_bytes(), &data);
                    self.write_packet(&s, deadline)?;
                }
                AuthReply::MoreData(_) => {
                    // Only caching_sha2_password (or another multi-round plugin) sends AuthMoreData.
                    return Err(MysqlError::CachingSha2Refused);
                }
            }
        }
        Err(MysqlError::Auth("too many auth round trips".into()))
    }

    fn pin_session(&mut self, deadline: Instant) -> Result<(), MysqlError> {
        self.execute_until(&format!("SET SESSION sql_mode = '{SESSION_SQL_MODE}'"), &[], deadline)?;
        let r = self.execute_until(
            "SELECT @@SESSION.sql_mode, @@SESSION.character_set_client, @@SESSION.character_set_connection, \
             @@SESSION.character_set_results",
            &[],
            deadline,
        )?;
        let row = r.rows.first().ok_or_else(|| MysqlError::Session("no session row".into()))?;
        let s = |i: usize| row.get(i).and_then(Cell::as_str).unwrap_or("");
        let mode: Vec<&str> = s(0).split(',').collect();
        if !mode.contains(&"STRICT_ALL_TABLES") {
            return Err(MysqlError::Session(format!("sql_mode {:?} is not strict", s(0))));
        }
        for i in 1..=3 {
            if s(i) != "utf8mb4" {
                return Err(MysqlError::Session(format!("session character set {:?} is not utf8mb4", s(i))));
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------------------------------------ framing

    fn fail<T>(&mut self, e: MysqlError) -> Result<T, MysqlError> {
        self.broken = true;
        Err(e)
    }

    fn read_exact(&mut self, buf: &mut [u8], deadline: Instant) -> Result<(), MysqlError> {
        let t = match remaining(deadline) {
            Ok(t) => t,
            Err(e) => return self.fail(e),
        };
        if let Err(e) = self.rd.get_ref().set_read_timeout(Some(t)) {
            return self.fail(io_err(&e));
        }
        match self.rd.read_exact(buf) {
            Ok(()) => Ok(()),
            Err(e) => self.fail(io_err(&e)),
        }
    }

    /// Read one logical packet (joining 0xffffff continuation chunks), checking sequence ids and the size cap.
    fn read_packet(&mut self, deadline: Instant) -> Result<Vec<u8>, MysqlError> {
        let mut out = Vec::new();
        loop {
            let mut h = [0u8; 4];
            self.read_exact(&mut h, deadline)?;
            let [a, b, c, seq] = h;
            let n = usize::from(a) | usize::from(b) << 8 | usize::from(c) << 16;
            if seq != self.seq {
                return self.fail(MysqlError::Protocol(format!("sequence id {seq}, expected {}", self.seq)));
            }
            self.seq = self.seq.wrapping_add(1);
            let total = out.len().saturating_add(n);
            if total > self.max_packet {
                return self.fail(MysqlError::PacketTooLarge(total));
            }
            let mut tmp = vec![0u8; n];
            self.read_exact(&mut tmp, deadline)?;
            out.extend_from_slice(&tmp);
            if n < MAX_PAYLOAD_CHUNK {
                break;
            }
        }
        if out.is_empty() {
            return self.fail(MysqlError::Protocol("empty packet".into()));
        }
        Ok(out)
    }

    fn write_packet(&mut self, payload: &[u8], deadline: Instant) -> Result<(), MysqlError> {
        if payload.len() > self.max_packet {
            return Err(MysqlError::PacketTooLarge(payload.len()));
        }
        let mut out = Vec::with_capacity(payload.len().saturating_add(8));
        let mut rest = payload;
        loop {
            let n = rest.len().min(MAX_PAYLOAD_CHUNK);
            let (chunk, tail) = rest.split_at(n);
            let [a, b, c, _] = (n as u32).to_le_bytes();
            out.extend_from_slice(&[a, b, c, self.seq]);
            out.extend_from_slice(chunk);
            self.seq = self.seq.wrapping_add(1);
            rest = tail;
            if n < MAX_PAYLOAD_CHUNK {
                break;
            }
        }
        let t = match remaining(deadline) {
            Ok(t) => t,
            Err(e) => return self.fail(e),
        };
        if let Err(e) = self.rd.get_ref().set_write_timeout(Some(t)) {
            return self.fail(io_err(&e));
        }
        if let Err(e) = self.rd.get_mut().write_all(&out) {
            return self.fail(io_err(&e));
        }
        Ok(())
    }

    fn command(&mut self, payload: &[u8], deadline: Instant) -> Result<(), MysqlError> {
        if self.broken {
            return Err(MysqlError::Broken);
        }
        self.seq = 0;
        self.write_packet(payload, deadline)
    }

    // ------------------------------------------------------------------------------------------- statements

    fn read_coldefs(&mut self, n: usize, deadline: Instant) -> Result<Vec<ColumnDef>, MysqlError> {
        if n > self.limits.max_columns {
            return self.fail(MysqlError::ResultTooLarge(format!("{n} columns")));
        }
        let mut cols = Vec::with_capacity(n);
        for _ in 0..n {
            let b = self.read_packet(deadline)?;
            match packet::parse_coldef(&b) {
                Ok(c) => cols.push(c),
                Err(e) => return self.fail(e),
            }
        }
        if n > 0 {
            let b = self.read_packet(deadline)?;
            if packet::eof_status(&b).ok().flatten().is_none() {
                return self.fail(MysqlError::Protocol("expected EOF after column definitions".into()));
            }
        }
        Ok(cols)
    }

    /// Read one result (OK, ERR or a result set). Returns the result and whether more results follow.
    fn read_result(&mut self, deadline: Instant) -> Result<(QueryResult, bool), MysqlError> {
        let b = self.read_packet(deadline)?;
        match b.first() {
            Some(0xff) => {
                return match packet::parse_err(&b) {
                    Ok(e) => Err(MysqlError::Server(e)),
                    Err(e) => self.fail(e),
                };
            }
            Some(0x00) => {
                let ok: OkPacket = match packet::parse_ok(&b) {
                    Ok(o) => o,
                    Err(e) => return self.fail(e),
                };
                self.status = ok.status;
                let r = QueryResult {
                    affected_rows: ok.affected_rows,
                    last_insert_id: ok.last_insert_id,
                    ..QueryResult::default()
                };
                return Ok((r, ok.status & SERVER_MORE_RESULTS_EXISTS != 0));
            }
            Some(0xfb) => return self.fail(MysqlError::Protocol("LOCAL INFILE request refused".into())),
            _ => {}
        }
        let n = match packet::Rd::new(&b).lenenc_int() {
            Ok(Some(n)) => usize::try_from(n).unwrap_or(usize::MAX),
            _ => return self.fail(MysqlError::Protocol("bad column count".into())),
        };
        if n == 0 {
            return self.fail(MysqlError::Protocol("result set with 0 columns".into()));
        }
        let columns = self.read_coldefs(n, deadline)?;
        let mut rows = Vec::new();
        let mut bytes = 0usize;
        loop {
            let b = self.read_packet(deadline)?;
            if b.first() == Some(&0xff) {
                return match packet::parse_err(&b) {
                    Ok(e) => Err(MysqlError::Server(e)),
                    Err(e) => self.fail(e),
                };
            }
            match packet::eof_status(&b) {
                Ok(Some(st)) => {
                    self.status = st;
                    let r = QueryResult { columns, rows, affected_rows: 0, last_insert_id: 0 };
                    return Ok((r, st & SERVER_MORE_RESULTS_EXISTS != 0));
                }
                Ok(None) => {}
                Err(e) => return self.fail(e),
            }
            bytes = bytes.saturating_add(b.len());
            if rows.len() >= self.limits.max_rows || bytes > self.limits.max_bytes {
                return self.fail(MysqlError::ResultTooLarge(format!("over {} rows / {bytes} bytes", rows.len())));
            }
            match packet::parse_binary_row(&b, &columns) {
                Ok(r) => rows.push(r),
                Err(e) => return self.fail(e),
            }
        }
    }

    fn close_stmt(&mut self, id: u32, deadline: Instant) {
        let mut p = vec![0x19u8];
        p.extend_from_slice(&id.to_le_bytes());
        let _ = self.command(&p, deadline);
    }

    /// Prepare `sql`, execute it once with `params` bound (binary protocol), close it. The result is the first
    /// result set (or the OK of a statement without rows); further results are drained.
    pub fn execute(&mut self, sql: &str, params: &[Param]) -> Result<QueryResult, MysqlError> {
        let deadline = Instant::now() + self.io_timeout;
        self.execute_until(sql, params, deadline)
    }

    /// [`Connection::execute`] under an explicit deadline.
    pub fn execute_until(&mut self, sql: &str, params: &[Param], deadline: Instant) -> Result<QueryResult, MysqlError> {
        if params.len() > MAX_PARAMS {
            return Err(MysqlError::Params { expected: MAX_PARAMS, given: params.len() });
        }
        let mut p = Vec::with_capacity(sql.len().saturating_add(1));
        p.push(0x16);
        p.extend_from_slice(sql.as_bytes());
        self.command(&p, deadline)?;
        let b = self.read_packet(deadline)?;
        if b.first() == Some(&0xff) {
            return match packet::parse_err(&b) {
                Ok(e) => Err(MysqlError::Server(e)),
                Err(e) => self.fail(e),
            };
        }
        let (id, ncol, npar) = match packet::parse_prepare_ok(&b) {
            Ok(x) => x,
            Err(e) => return self.fail(e),
        };
        self.read_coldefs(usize::from(npar), deadline)?;
        self.read_coldefs(usize::from(ncol), deadline)?;
        if usize::from(npar) != params.len() {
            self.close_stmt(id, deadline);
            return Err(MysqlError::Params { expected: usize::from(npar), given: params.len() });
        }
        let mut e = Vec::with_capacity(64);
        e.push(0x17);
        e.extend_from_slice(&id.to_le_bytes());
        e.push(0x00); // CURSOR_TYPE_NO_CURSOR
        e.extend_from_slice(&1u32.to_le_bytes()); // iteration count
        if !params.is_empty() {
            e.extend(std::iter::repeat_n(0u8, params.len().div_ceil(8))); // NULL bitmap: no NULL parameter
            e.push(0x01); // new-params-bound flag: types follow
            for p in params {
                e.extend_from_slice(match p {
                    Param::Int(_) => &[0x08, 0x00],  // LONGLONG, signed
                    Param::Text(_) => &[0xfd, 0x00], // VAR_STRING (connection charset utf8mb4)
                });
            }
            for p in params {
                match p {
                    Param::Int(i) => e.extend_from_slice(&i.to_le_bytes()),
                    Param::Text(s) => {
                        packet::enc_lenenc(s.len(), &mut e);
                        e.extend_from_slice(s.as_bytes());
                    }
                }
            }
        }
        let out = self.command(&e, deadline).and_then(|()| self.drain(deadline));
        if !self.broken {
            self.close_stmt(id, deadline);
        }
        out
    }

    fn drain(&mut self, deadline: Instant) -> Result<QueryResult, MysqlError> {
        let (mut first, mut more) = self.read_result(deadline)?;
        let mut err = None;
        while more {
            match self.read_result(deadline) {
                Ok((r, m)) => {
                    if first.columns.is_empty() && !r.columns.is_empty() {
                        first = r;
                    }
                    more = m;
                }
                Err(e) => {
                    err = Some(e);
                    more = false;
                }
            }
        }
        match err {
            Some(e) => Err(e),
            None => Ok(first),
        }
    }

    /// `BEGIN` (prepared). The returning-select emulation needs an open transaction ([`Connection::run`]).
    pub fn begin(&mut self) -> Result<(), MysqlError> {
        self.execute("BEGIN", &[]).map(|_| ())
    }
    pub fn commit(&mut self) -> Result<(), MysqlError> {
        self.execute("COMMIT", &[]).map(|_| ())
    }
    pub fn rollback(&mut self) -> Result<(), MysqlError> {
        self.execute("ROLLBACK", &[]).map(|_| ())
    }

    /// Run one rendered op. For an UPDATE with a requested RETURNING the renderer emits a `returning_select`
    /// (`SELECT <post-image> .. FOR UPDATE`); it runs first and its rows are the RETURNING rows. That emulation is
    /// exact only inside a transaction (the rows are locked until the UPDATE), so without one it is refused.
    pub fn run(&mut self, r: &crate::lower::Rendered) -> Result<QueryResult, MysqlError> {
        match &r.returning_select {
            None => self.execute(&r.stmt.sql, &r.stmt.params),
            Some(rs) => {
                if !self.in_transaction() {
                    return Err(MysqlError::NotInTransaction);
                }
                let sel = self.execute(&rs.sql, &rs.params)?;
                let upd = self.execute(&r.stmt.sql, &r.stmt.params)?;
                Ok(QueryResult { affected_rows: upd.affected_rows, ..sel })
            }
        }
    }

    // ------------------------------------------------------------------------------------------------ state

    /// The server's version string as sent in the handshake.
    pub fn server_version(&self) -> &str {
        &self.server_version
    }
    /// The admitted (gated) version.
    pub fn version(&self) -> version::MariaVersion {
        self.admitted
    }
    pub fn connection_id(&self) -> u32 {
        self.connection_id
    }
    /// The server reported an open transaction in its last OK / EOF.
    pub fn in_transaction(&self) -> bool {
        self.status & SERVER_STATUS_IN_TRANS != 0
    }
    pub fn is_broken(&self) -> bool {
        self.broken
    }
    pub fn set_limits(&mut self, l: Limits) {
        self.limits = l;
    }

    /// Reusable for another op: not broken, no open transaction, nothing buffered, and the idle socket has
    /// neither unread bytes nor EOF (a server that closed or sent something unsolicited is not reused).
    pub fn is_reusable(&mut self) -> bool {
        if self.broken || self.in_transaction() || !self.rd.buffer().is_empty() {
            return false;
        }
        let s = self.rd.get_ref();
        if s.set_nonblocking(true).is_err() {
            return false;
        }
        let mut one = [0u8; 1];
        let idle = matches!(s.peek(&mut one), Err(e) if e.kind() == ErrorKind::WouldBlock);
        s.set_nonblocking(false).is_ok() && idle
    }

    /// Send COM_QUIT (bounded by `timeout`) and close the socket.
    pub fn terminate(mut self, timeout: Duration) {
        if !self.broken {
            let _ = self.command(&[0x01], Instant::now() + timeout);
        }
        let _ = self.rd.get_ref().shutdown(Shutdown::Both);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    //! Fake-server tests (loopback listener in a thread): auth switch to caching_sha2 refused, a reply over the
    //! packet cap refused, a wrong sequence id refused, a hung server times out.
    use super::*;
    use std::net::TcpListener;

    fn pkt(seq: u8, body: &[u8]) -> Vec<u8> {
        let n = body.len() as u32;
        let mut v = n.to_le_bytes()[..3].to_vec();
        v.push(seq);
        v.extend_from_slice(body);
        v
    }

    fn handshake(version: &str) -> Vec<u8> {
        let mut b = vec![10u8];
        b.extend_from_slice(version.as_bytes());
        b.push(0);
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(b"abcdefgh\0");
        let caps = CLIENT_CAPS;
        b.extend_from_slice(&((caps & 0xffff) as u16).to_le_bytes());
        b.push(45);
        b.extend_from_slice(&2u16.to_le_bytes());
        b.extend_from_slice(&((caps >> 16) as u16).to_le_bytes());
        b.push(21);
        b.extend_from_slice(&[0u8; 10]);
        b.extend_from_slice(b"ijklmnopqrst\0mysql_native_password\0");
        b
    }

    fn read_one(s: &mut TcpStream) -> Vec<u8> {
        let mut h = [0u8; 4];
        s.read_exact(&mut h).unwrap();
        let n = u32::from_le_bytes([h[0], h[1], h[2], 0]) as usize;
        let mut b = vec![0u8; n];
        s.read_exact(&mut b).unwrap();
        b
    }

    fn serve(script: impl FnOnce(TcpStream) + Send + 'static) -> ConnectConfig {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((s, _)) = l.accept() {
                script(s);
            }
        });
        let mut c = ConnectConfig::from_dsn(&format!("mysql://root:pw@127.0.0.1:{}/monban", addr.port())).unwrap();
        c.connect_timeout = Duration::from_secs(2);
        c
    }

    #[test]
    fn caching_sha2_switch_refused() {
        let cfg = serve(|mut s| {
            s.write_all(&pkt(0, &handshake("11.8.9-MariaDB"))).unwrap();
            let _ = read_one(&mut s);
            let mut sw = vec![0xfeu8];
            sw.extend_from_slice(b"caching_sha2_password\0abcdefghijklmnopqrst\0");
            s.write_all(&pkt(2, &sw)).unwrap();
            let _ = s.read(&mut [0u8; 64]);
        });
        let e = Connection::connect(&cfg).err();
        assert_eq!(e, Some(MysqlError::CachingSha2Refused));
        assert!(e.unwrap().to_string().contains("caching_sha2_password"));
    }

    #[test]
    fn unknown_plugin_refused() {
        let cfg = serve(|mut s| {
            s.write_all(&pkt(0, &handshake("11.8.9-MariaDB"))).unwrap();
            let _ = read_one(&mut s);
            let mut sw = vec![0xfeu8];
            sw.extend_from_slice(b"mysql_clear_password\0");
            s.write_all(&pkt(2, &sw)).unwrap();
            let _ = s.read(&mut [0u8; 64]);
        });
        assert!(matches!(Connection::connect(&cfg), Err(MysqlError::Auth(_))));
    }

    #[test]
    fn version_below_floor_refused_before_credentials() {
        let cfg = serve(|mut s| {
            s.write_all(&pkt(0, &handshake("11.8.8-MariaDB"))).unwrap();
            // The client must not send a HandshakeResponse (with the scramble) to a refused server.
            let mut b = [0u8; 4];
            let n = s.read(&mut b).unwrap_or(0);
            assert_eq!(n, 0, "client sent bytes to a refused server");
        });
        assert!(matches!(Connection::connect(&cfg), Err(MysqlError::VersionRefused(_))));
    }

    #[test]
    fn oversized_and_bad_sequence_refused() {
        let cfg = serve(|mut s| {
            // a 3-byte length of 0xffffff would announce 16 MiB; with a 1 KiB cap the client must refuse at once.
            s.write_all(&[0xff, 0xff, 0xff, 0]).unwrap();
            let _ = s.read(&mut [0u8; 8]);
        });
        let mut cfg2 = cfg.clone();
        cfg2.max_packet = 1024;
        assert!(matches!(Connection::connect(&cfg2), Err(MysqlError::PacketTooLarge(_))));
        let cfg = serve(|mut s| {
            s.write_all(&pkt(5, &handshake("11.8.9-MariaDB"))).unwrap();
            let _ = s.read(&mut [0u8; 8]);
        });
        assert!(matches!(Connection::connect(&cfg), Err(MysqlError::Protocol(_))));
    }

    #[test]
    fn hung_server_times_out() {
        let mut cfg = serve(|s| {
            std::thread::sleep(Duration::from_millis(1500));
            drop(s);
        });
        cfg.connect_timeout = Duration::from_millis(300);
        let t = Instant::now();
        assert_eq!(Connection::connect(&cfg).err(), Some(MysqlError::Timeout));
        assert!(t.elapsed() < Duration::from_millis(1200));
    }
}
