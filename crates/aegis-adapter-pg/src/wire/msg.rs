//! PG v3 message codec. Backend parsing is a pure function over `(tag, body)` that never panics and never indexes
//! (fuzz target shape: any byte string in, `Ok` or `Err` out). Frontend encoders refuse NUL inside C strings (an
//! embedded NUL would truncate SQL text or a startup value on the server side) and any length that does not fit the
//! protocol's integer fields.

use std::fmt;

/// Protocol 3.0.
pub const PROTOCOL_3_0: i32 = 196_608;
pub const CANCEL_REQUEST_CODE: i32 = 80_877_102;
/// Default cap on one backend message (length field, including itself).
pub const DEFAULT_MAX_MESSAGE: usize = 4 << 20;
/// Hard ceiling for any configured cap (the server's own limit for most messages is 1 GB; we never go near it).
pub const HARD_MAX_MESSAGE: usize = 256 << 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// A backend message violated the protocol grammar.
    Malformed { tag: u8, what: &'static str },
    /// Declared length below 4 or above the configured cap.
    BadLength { tag: u8, len: i64, cap: usize },
    /// A frontend string contained NUL, or a frontend length overflowed its field.
    Encode(&'static str),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::Malformed { tag, what } => {
                write!(f, "malformed backend message {:?}: {what}", char::from(*tag))
            }
            CodecError::BadLength { tag, len, cap } => {
                write!(f, "backend message {:?} length {len} outside [4, {cap}]", char::from(*tag))
            }
            CodecError::Encode(w) => write!(f, "cannot encode frontend message: {w}"),
        }
    }
}

impl std::error::Error for CodecError {}

/// Transaction status byte of ReadyForQuery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxnStatus {
    /// `I`: not in a transaction block.
    Idle,
    /// `T`: in a transaction block.
    InTransaction,
    /// `E`: in a failed transaction block (queries rejected until rollback).
    Failed,
}

impl TxnStatus {
    pub const fn byte(self) -> u8 {
        match self {
            TxnStatus::Idle => b'I',
            TxnStatus::InTransaction => b'T',
            TxnStatus::Failed => b'E',
        }
    }
}

/// Fields of ErrorResponse / NoticeResponse that the adapter uses.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DbError {
    /// Non-localized severity (`V`), falling back to `S`.
    pub severity: String,
    /// SQLSTATE (`C`).
    pub code: String,
    /// Primary message (`M`).
    pub message: String,
    pub detail: Option<String>,
    pub constraint: Option<String>,
}

impl DbError {
    /// FATAL or PANIC: the server closes the session after this.
    pub fn is_fatal(&self) -> bool {
        matches!(self.severity.as_str(), "FATAL" | "PANIC")
    }
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.severity, self.code, self.message)
    }
}

/// Column metadata from RowDescription.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDesc {
    pub name: String,
    pub table_oid: u32,
    pub column: i16,
    pub type_oid: u32,
    pub type_len: i16,
    pub type_mod: i32,
    pub format: i16,
}

/// Authentication request subcodes the client understands; everything else is `Other` (refused by the caller).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Auth {
    Ok,
    CleartextPassword,
    Md5Password,
    Sasl(Vec<String>),
    SaslContinue(Vec<u8>),
    SaslFinal(Vec<u8>),
    Other(i32),
}

/// One parsed backend message (owned).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Backend {
    Authentication(Auth),
    BackendKeyData {
        pid: i32,
        secret: Vec<u8>,
    },
    ParameterStatus {
        name: String,
        value: String,
    },
    ReadyForQuery(TxnStatus),
    ParseComplete,
    BindComplete,
    CloseComplete,
    NoData,
    PortalSuspended,
    EmptyQueryResponse,
    ParameterDescription(Vec<u32>),
    RowDescription(Vec<FieldDesc>),
    /// Column values (None = SQL NULL), raw bytes in the result format.
    DataRow(Vec<Option<Vec<u8>>>),
    CommandComplete(String),
    ErrorResponse(DbError),
    NoticeResponse(DbError),
    NotificationResponse {
        pid: i32,
        channel: String,
        payload: String,
    },
    NegotiateProtocolVersion {
        newest_minor: i32,
        unrecognized: Vec<String>,
    },
    CopyInResponse,
    CopyOutResponse,
    CopyBothResponse,
    CopyData(Vec<u8>),
    CopyDone,
}

/// Bounded, non-panicking reader over a message body.
struct Cur<'a> {
    b: &'a [u8],
    tag: u8,
}

impl<'a> Cur<'a> {
    fn err(&self, what: &'static str) -> CodecError {
        CodecError::Malformed { tag: self.tag, what }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let (head, rest) = self.b.split_at_checked(n).ok_or(self.err("truncated"))?;
        self.b = rest;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, CodecError> {
        let (&x, rest) = self.b.split_first().ok_or(self.err("truncated"))?;
        self.b = rest;
        Ok(x)
    }
    fn i16(&mut self) -> Result<i16, CodecError> {
        let (h, rest) = self.b.split_first_chunk::<2>().ok_or(self.err("truncated"))?;
        self.b = rest;
        Ok(i16::from_be_bytes(*h))
    }
    fn i32(&mut self) -> Result<i32, CodecError> {
        let (h, rest) = self.b.split_first_chunk::<4>().ok_or(self.err("truncated"))?;
        self.b = rest;
        Ok(i32::from_be_bytes(*h))
    }
    fn u32(&mut self) -> Result<u32, CodecError> {
        self.i32().map(|v| u32::from_be_bytes(v.to_be_bytes()))
    }
    /// NUL-terminated UTF-8 string.
    fn cstr(&mut self) -> Result<&'a str, CodecError> {
        let end = self.b.iter().position(|&c| c == 0).ok_or(self.err("unterminated string"))?;
        let s = self.take(end)?;
        self.take(1)?;
        std::str::from_utf8(s).map_err(|_| self.err("string not UTF-8"))
    }
    fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.b)
    }
    fn end(&self) -> Result<(), CodecError> {
        if self.b.is_empty() { Ok(()) } else { Err(self.err("trailing bytes")) }
    }
    fn count(&mut self) -> Result<usize, CodecError> {
        usize::try_from(self.i16()?).map_err(|_| self.err("negative count"))
    }
}

/// Maximum columns/parameters per message (PostgreSQL's own limit is 1664 result columns, 65535 parameters).
const MAX_FIELDS: usize = 65_535;

fn fields(c: &mut Cur<'_>) -> Result<DbError, CodecError> {
    let mut e = DbError::default();
    let mut s_sev = String::new();
    loop {
        let code = c.u8()?;
        if code == 0 {
            break;
        }
        let v = c.cstr()?;
        match code {
            b'V' => e.severity = v.to_owned(),
            b'S' => s_sev = v.to_owned(),
            b'C' => e.code = v.to_owned(),
            b'M' => e.message = v.to_owned(),
            b'D' => e.detail = Some(v.to_owned()),
            b'n' => e.constraint = Some(v.to_owned()),
            _ => {}
        }
    }
    if e.severity.is_empty() {
        e.severity = s_sev;
    }
    c.end()?;
    Ok(e)
}

/// Parse one backend message body. Never panics; any grammar violation is `Err`.
pub fn parse_backend(tag: u8, body: &[u8]) -> Result<Backend, CodecError> {
    let mut c = Cur { b: body, tag };
    let empty = |c: &Cur<'_>, m: Backend| c.end().map(|()| m);
    match tag {
        b'R' => {
            let code = c.i32()?;
            let a = match code {
                0 => {
                    c.end()?;
                    Auth::Ok
                }
                3 => {
                    c.end()?;
                    Auth::CleartextPassword
                }
                5 => Auth::Md5Password,
                10 => {
                    let mut mechs = Vec::new();
                    loop {
                        let m = c.cstr()?;
                        if m.is_empty() {
                            break;
                        }
                        if mechs.len() >= 16 {
                            return Err(c.err("too many SASL mechanisms"));
                        }
                        mechs.push(m.to_owned());
                    }
                    c.end()?;
                    Auth::Sasl(mechs)
                }
                11 => Auth::SaslContinue(c.rest().to_vec()),
                12 => Auth::SaslFinal(c.rest().to_vec()),
                other => Auth::Other(other),
            };
            Ok(Backend::Authentication(a))
        }
        b'K' => {
            let pid = c.i32()?;
            let secret = c.rest();
            if !(4..=256).contains(&secret.len()) {
                return Err(c.err("cancel key length"));
            }
            Ok(Backend::BackendKeyData { pid, secret: secret.to_vec() })
        }
        b'S' => {
            let name = c.cstr()?.to_owned();
            let value = c.cstr()?.to_owned();
            c.end()?;
            Ok(Backend::ParameterStatus { name, value })
        }
        b'Z' => {
            let s = match c.u8()? {
                b'I' => TxnStatus::Idle,
                b'T' => TxnStatus::InTransaction,
                b'E' => TxnStatus::Failed,
                _ => return Err(c.err("unknown transaction status")),
            };
            c.end()?;
            Ok(Backend::ReadyForQuery(s))
        }
        b'1' => empty(&c, Backend::ParseComplete),
        b'2' => empty(&c, Backend::BindComplete),
        b'3' => empty(&c, Backend::CloseComplete),
        b'n' => empty(&c, Backend::NoData),
        b's' => empty(&c, Backend::PortalSuspended),
        b'I' => empty(&c, Backend::EmptyQueryResponse),
        b'c' => empty(&c, Backend::CopyDone),
        b't' => {
            let n = usize::from(u16::from_be_bytes(c.i16()?.to_be_bytes()));
            let mut oids = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                oids.push(c.u32()?);
            }
            c.end()?;
            Ok(Backend::ParameterDescription(oids))
        }
        b'T' => {
            let n = c.count()?;
            if n > MAX_FIELDS {
                return Err(c.err("too many fields"));
            }
            let mut out = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                out.push(FieldDesc {
                    name: c.cstr()?.to_owned(),
                    table_oid: c.u32()?,
                    column: c.i16()?,
                    type_oid: c.u32()?,
                    type_len: c.i16()?,
                    type_mod: c.i32()?,
                    format: c.i16()?,
                });
            }
            c.end()?;
            Ok(Backend::RowDescription(out))
        }
        b'D' => {
            let n = c.count()?;
            let mut vals = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                let len = c.i32()?;
                if len == -1 {
                    vals.push(None);
                } else {
                    let l = usize::try_from(len).map_err(|_| c.err("negative column length"))?;
                    vals.push(Some(c.take(l)?.to_vec()));
                }
            }
            c.end()?;
            Ok(Backend::DataRow(vals))
        }
        b'C' => {
            let t = c.cstr()?.to_owned();
            c.end()?;
            Ok(Backend::CommandComplete(t))
        }
        b'E' => Ok(Backend::ErrorResponse(fields(&mut c)?)),
        b'N' => Ok(Backend::NoticeResponse(fields(&mut c)?)),
        b'A' => {
            let pid = c.i32()?;
            let channel = c.cstr()?.to_owned();
            let payload = c.cstr()?.to_owned();
            c.end()?;
            Ok(Backend::NotificationResponse { pid, channel, payload })
        }
        b'v' => {
            let newest_minor = c.i32()?;
            let n = usize::try_from(c.i32()?).map_err(|_| c.err("negative count"))?;
            let mut unrecognized = Vec::new();
            for _ in 0..n {
                if unrecognized.len() >= 64 {
                    return Err(c.err("too many options"));
                }
                unrecognized.push(c.cstr()?.to_owned());
            }
            c.end()?;
            Ok(Backend::NegotiateProtocolVersion { newest_minor, unrecognized })
        }
        b'G' => {
            c.rest();
            Ok(Backend::CopyInResponse)
        }
        b'H' => {
            c.rest();
            Ok(Backend::CopyOutResponse)
        }
        b'W' => {
            c.rest();
            Ok(Backend::CopyBothResponse)
        }
        b'd' => Ok(Backend::CopyData(c.rest().to_vec())),
        _ => Err(CodecError::Malformed { tag, what: "unknown message type" }),
    }
}

/// Validate a backend header: returns the body length.
pub fn body_len(tag: u8, len_field: [u8; 4], cap: usize) -> Result<usize, CodecError> {
    let len = i32::from_be_bytes(len_field);
    let bad = CodecError::BadLength { tag, len: i64::from(len), cap };
    let l = usize::try_from(len).map_err(|_| bad.clone())?;
    if l < 4 || l > cap.min(HARD_MAX_MESSAGE) {
        return Err(bad);
    }
    Ok(l - 4)
}

// ------------------------------------------------------------------------------------------------- frontend

fn put_cstr(out: &mut Vec<u8>, s: &str) -> Result<(), CodecError> {
    if s.as_bytes().contains(&0) {
        return Err(CodecError::Encode("NUL in string"));
    }
    out.extend_from_slice(s.as_bytes());
    out.push(0);
    Ok(())
}

fn put_i32_len(out: &mut Vec<u8>, n: usize) -> Result<(), CodecError> {
    let v = i32::try_from(n).map_err(|_| CodecError::Encode("length overflows i32"))?;
    out.extend_from_slice(&v.to_be_bytes());
    Ok(())
}

/// Frame `tag + len + body` (len counts itself).
fn frame(out: &mut Vec<u8>, tag: u8, body: &[u8]) -> Result<(), CodecError> {
    out.push(tag);
    put_i32_len(out, body.len().checked_add(4).ok_or(CodecError::Encode("length overflow"))?)?;
    out.extend_from_slice(body);
    Ok(())
}

/// StartupMessage (no tag). `params` are name/value pairs; `user` must be among them.
pub fn startup(out: &mut Vec<u8>, params: &[(&str, &str)]) -> Result<(), CodecError> {
    let mut body = PROTOCOL_3_0.to_be_bytes().to_vec();
    for (k, v) in params {
        if k.is_empty() {
            return Err(CodecError::Encode("empty startup parameter name"));
        }
        put_cstr(&mut body, k)?;
        put_cstr(&mut body, v)?;
    }
    body.push(0);
    if body.len() > 10_000 - 4 {
        return Err(CodecError::Encode("startup packet too long"));
    }
    put_i32_len(out, body.len() + 4)?;
    out.extend_from_slice(&body);
    Ok(())
}

/// CancelRequest packet (sent on a fresh connection).
pub fn cancel_request(pid: i32, secret: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut body = CANCEL_REQUEST_CODE.to_be_bytes().to_vec();
    body.extend_from_slice(&pid.to_be_bytes());
    body.extend_from_slice(secret);
    let mut out = Vec::new();
    put_i32_len(&mut out, body.len() + 4)?;
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn sasl_initial(out: &mut Vec<u8>, mechanism: &str, data: &[u8]) -> Result<(), CodecError> {
    let mut body = Vec::new();
    put_cstr(&mut body, mechanism)?;
    put_i32_len(&mut body, data.len())?;
    body.extend_from_slice(data);
    frame(out, b'p', &body)
}

pub fn sasl_response(out: &mut Vec<u8>, data: &[u8]) -> Result<(), CodecError> {
    frame(out, b'p', data)
}

/// Parse with `param_types` (0 = let the server infer).
pub fn parse(out: &mut Vec<u8>, stmt: &str, sql: &str, param_types: &[u32]) -> Result<(), CodecError> {
    let mut body = Vec::new();
    put_cstr(&mut body, stmt)?;
    put_cstr(&mut body, sql)?;
    let n = u16::try_from(param_types.len()).map_err(|_| CodecError::Encode("too many parameter types"))?;
    body.extend_from_slice(&n.to_be_bytes());
    for t in param_types {
        body.extend_from_slice(&t.to_be_bytes());
    }
    frame(out, b'P', &body)
}

/// Bind with all parameters and results in text format. `None` = SQL NULL.
pub fn bind(out: &mut Vec<u8>, portal: &str, stmt: &str, params: &[Option<&str>]) -> Result<(), CodecError> {
    let mut body = Vec::new();
    put_cstr(&mut body, portal)?;
    put_cstr(&mut body, stmt)?;
    body.extend_from_slice(&0u16.to_be_bytes()); // parameter formats: none = all text
    let n = u16::try_from(params.len()).map_err(|_| CodecError::Encode("too many parameters"))?;
    body.extend_from_slice(&n.to_be_bytes());
    for p in params {
        match p {
            None => body.extend_from_slice(&(-1i32).to_be_bytes()),
            Some(v) => {
                put_i32_len(&mut body, v.len())?;
                body.extend_from_slice(v.as_bytes());
            }
        }
    }
    body.extend_from_slice(&0u16.to_be_bytes()); // result formats: none = all text
    frame(out, b'B', &body)
}

/// Describe: `kind` is `b'S'` (statement) or `b'P'` (portal).
pub fn describe(out: &mut Vec<u8>, kind: u8, name: &str) -> Result<(), CodecError> {
    if kind != b'S' && kind != b'P' {
        return Err(CodecError::Encode("describe kind"));
    }
    let mut body = vec![kind];
    put_cstr(&mut body, name)?;
    frame(out, b'D', &body)
}

/// Execute; `max_rows` 0 = no limit.
pub fn execute(out: &mut Vec<u8>, portal: &str, max_rows: u32) -> Result<(), CodecError> {
    let mut body = Vec::new();
    put_cstr(&mut body, portal)?;
    let m = i32::try_from(max_rows).map_err(|_| CodecError::Encode("max_rows overflows i32"))?;
    body.extend_from_slice(&m.to_be_bytes());
    frame(out, b'E', &body)
}

/// Close: `kind` is `b'S'` or `b'P'`.
pub fn close(out: &mut Vec<u8>, kind: u8, name: &str) -> Result<(), CodecError> {
    if kind != b'S' && kind != b'P' {
        return Err(CodecError::Encode("close kind"));
    }
    let mut body = vec![kind];
    put_cstr(&mut body, name)?;
    frame(out, b'C', &body)
}

pub fn sync(out: &mut Vec<u8>) {
    out.extend_from_slice(&[b'S', 0, 0, 0, 4]);
}

pub fn flush(out: &mut Vec<u8>) {
    out.extend_from_slice(&[b'H', 0, 0, 0, 4]);
}

pub fn terminate(out: &mut Vec<u8>) {
    out.extend_from_slice(&[b'X', 0, 0, 0, 4]);
}

/// Simple Query.
pub fn query(out: &mut Vec<u8>, sql: &str) -> Result<(), CodecError> {
    let mut body = Vec::new();
    put_cstr(&mut body, sql)?;
    frame(out, b'Q', &body)
}
