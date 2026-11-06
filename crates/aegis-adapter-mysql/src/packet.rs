//! Pure codec for the MySQL/MariaDB client/server protocol: a bounds-checked cursor over one packet payload, the
//! length-encoded integers and strings, the initial handshake (protocol v10), OK / ERR / EOF packets, column
//! definitions (protocol 41) and binary-protocol result rows.
//!
//! Nothing here indexes a slice: every read goes through [`Rd`], which returns [`MysqlError::Protocol`] on a short
//! payload, so hostile server bytes can never panic the parser (unit tests feed it random and truncated input).

use crate::MysqlError;

/// Client capability flags (protocol constants).
pub const CLIENT_LONG_PASSWORD: u32 = 0x1;
pub const CLIENT_LONG_FLAG: u32 = 0x4;
pub const CLIENT_CONNECT_WITH_DB: u32 = 0x8;
pub const CLIENT_LOCAL_FILES: u32 = 0x80;
pub const CLIENT_PROTOCOL_41: u32 = 0x200;
pub const CLIENT_SSL: u32 = 0x800;
pub const CLIENT_TRANSACTIONS: u32 = 0x2000;
pub const CLIENT_SECURE_CONNECTION: u32 = 0x8000;
pub const CLIENT_MULTI_STATEMENTS: u32 = 0x1_0000;
pub const CLIENT_MULTI_RESULTS: u32 = 0x2_0000;
pub const CLIENT_PS_MULTI_RESULTS: u32 = 0x4_0000;
pub const CLIENT_PLUGIN_AUTH: u32 = 0x8_0000;
pub const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x20_0000;
pub const CLIENT_DEPRECATE_EOF: u32 = 0x100_0000;

/// What this client may ever ask for. Never `CLIENT_MULTI_STATEMENTS` (one statement per command), never
/// `CLIENT_LOCAL_FILES` (LOAD DATA LOCAL lets a server read client files), never `CLIENT_SSL` (no TLS path yet),
/// never `CLIENT_DEPRECATE_EOF` (the result parser expects EOF packets).
pub const CLIENT_CAPS: u32 = CLIENT_LONG_PASSWORD
    | CLIENT_LONG_FLAG
    | CLIENT_CONNECT_WITH_DB
    | CLIENT_PROTOCOL_41
    | CLIENT_TRANSACTIONS
    | CLIENT_SECURE_CONNECTION
    | CLIENT_MULTI_RESULTS
    | CLIENT_PS_MULTI_RESULTS
    | CLIENT_PLUGIN_AUTH
    | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA;

/// Server capabilities this client cannot work without.
pub const REQUIRED_SERVER_CAPS: u32 = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;

/// Server status flags.
pub const SERVER_STATUS_IN_TRANS: u16 = 0x0001;
pub const SERVER_MORE_RESULTS_EXISTS: u16 = 0x0008;

/// Column flag: UNSIGNED.
pub const UNSIGNED_FLAG: u16 = 0x20;
/// Character set number of `binary` (VARBINARY / BLOB / CAST(.. AS BINARY) results).
pub const BINARY_CHARSET: u16 = 63;
/// utf8mb4_general_ci, the connection character set this client announces (as the reference client does).
pub const CHARSET_UTF8MB4_GENERAL_CI: u8 = 45;

/// Longest server version string accepted in the handshake.
const MAX_VERSION_LEN: usize = 256;
/// Longest auth plugin name accepted.
const MAX_PLUGIN_LEN: usize = 64;

pub(crate) fn proto<T>(m: impl Into<String>) -> Result<T, MysqlError> {
    Err(MysqlError::Protocol(m.into()))
}

/// Bounds-checked little-endian cursor over one payload.
#[derive(Debug)]
pub(crate) struct Rd<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Rd<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Rd { b, i: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.i)
    }
    pub fn rest(&self) -> &'a [u8] {
        self.b.get(self.i..).unwrap_or(&[])
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], MysqlError> {
        let end = self.i.checked_add(n).ok_or_else(|| MysqlError::Protocol("length overflow".into()))?;
        match self.b.get(self.i..end) {
            Some(s) => {
                self.i = end;
                Ok(s)
            }
            None => proto(format!("truncated packet (need {n} bytes at {}, have {})", self.i, self.remaining())),
        }
    }
    pub fn u8(&mut self) -> Result<u8, MysqlError> {
        match self.take(1)? {
            [b] => Ok(*b),
            _ => proto("truncated packet"),
        }
    }
    pub fn u16(&mut self) -> Result<u16, MysqlError> {
        match self.take(2)? {
            [a, b] => Ok(u16::from_le_bytes([*a, *b])),
            _ => proto("truncated packet"),
        }
    }
    pub fn u24(&mut self) -> Result<u32, MysqlError> {
        match self.take(3)? {
            [a, b, c] => Ok(u32::from_le_bytes([*a, *b, *c, 0])),
            _ => proto("truncated packet"),
        }
    }
    pub fn u32(&mut self) -> Result<u32, MysqlError> {
        let s = self.take(4)?;
        let a: [u8; 4] = s.try_into().map_err(|_| MysqlError::Protocol("truncated packet".into()))?;
        Ok(u32::from_le_bytes(a))
    }
    pub fn u64(&mut self) -> Result<u64, MysqlError> {
        let s = self.take(8)?;
        let a: [u8; 8] = s.try_into().map_err(|_| MysqlError::Protocol("truncated packet".into()))?;
        Ok(u64::from_le_bytes(a))
    }
    /// Length-encoded integer. `0xfb` (NULL) is `None`; `0xff` is never a valid length.
    pub fn lenenc_int(&mut self) -> Result<Option<u64>, MysqlError> {
        Ok(Some(match self.u8()? {
            c @ 0..=0xfa => u64::from(c),
            0xfb => return Ok(None),
            0xfc => u64::from(self.u16()?),
            0xfd => u64::from(self.u24()?),
            0xfe => self.u64()?,
            0xff => return proto("0xff is not a length-encoded integer"),
        }))
    }
    /// Length-encoded string (`None` for NULL). Its length is bounded by the payload, never trusted.
    pub fn lenenc_bytes(&mut self) -> Result<Option<&'a [u8]>, MysqlError> {
        match self.lenenc_int()? {
            None => Ok(None),
            Some(n) => {
                let n = usize::try_from(n).map_err(|_| MysqlError::Protocol("string length overflow".into()))?;
                if n > self.remaining() {
                    return proto(format!("string of {n} bytes in a payload with {} left", self.remaining()));
                }
                self.take(n).map(Some)
            }
        }
    }
    /// NUL-terminated string (the NUL is consumed, not returned).
    pub fn nul_str(&mut self) -> Result<&'a [u8], MysqlError> {
        let rest = self.rest();
        let n = rest.iter().position(|b| *b == 0).ok_or_else(|| MysqlError::Protocol("unterminated string".into()))?;
        let s = self.take(n)?;
        self.take(1)?;
        Ok(s)
    }
}

/// Length-encoded integer encoding.
pub fn enc_lenenc(n: usize, out: &mut Vec<u8>) {
    let n64 = n as u64;
    if n64 < 0xfb {
        out.push(n64 as u8);
    } else if n64 < 1 << 16 {
        out.push(0xfc);
        out.extend_from_slice(&(n64 as u16).to_le_bytes());
    } else if n64 < 1 << 24 {
        out.push(0xfd);
        let [a, b, c, _] = (n64 as u32).to_le_bytes();
        out.extend_from_slice(&[a, b, c]);
    } else {
        out.push(0xfe);
        out.extend_from_slice(&n64.to_le_bytes());
    }
}

/// A server ERR packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerError {
    pub code: u16,
    pub state: String,
    pub message: String,
}

/// Parse an ERR packet (first byte 0xff).
pub fn parse_err(b: &[u8]) -> Result<ServerError, MysqlError> {
    let mut r = Rd::new(b);
    if r.u8()? != 0xff {
        return proto("not an ERR packet");
    }
    let code = r.u16()?;
    let mut state = "HY000".to_string();
    if r.rest().first() == Some(&b'#') {
        r.take(1)?;
        state = String::from_utf8_lossy(r.take(5)?).into_owned();
    }
    let message = String::from_utf8_lossy(r.rest()).chars().take(512).collect();
    Ok(ServerError { code, state, message })
}

/// The server's initial handshake (protocol v10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handshake {
    pub server_version: String,
    pub connection_id: u32,
    pub caps: u32,
    pub status: u16,
    /// The 20-byte scramble (auth-plugin-data parts 1 and 2).
    pub salt: Vec<u8>,
    pub plugin: String,
}

/// Parse the initial handshake. A server ERR (e.g. too many connections, host blocked) is
/// [`MysqlError::Server`]; any protocol other than 10, or a server without protocol 41 / secure connection /
/// plugin auth, is refused.
pub fn parse_handshake(b: &[u8]) -> Result<Handshake, MysqlError> {
    if b.first() == Some(&0xff) {
        return Err(MysqlError::Server(parse_err(b)?));
    }
    let mut r = Rd::new(b);
    let protocol = r.u8()?;
    if protocol != 10 {
        return proto(format!("handshake protocol {protocol} (only v10 is spoken)"));
    }
    let v = r.nul_str()?;
    if v.len() > MAX_VERSION_LEN {
        return proto("server version string too long");
    }
    let server_version = String::from_utf8_lossy(v).into_owned();
    let connection_id = r.u32()?;
    let mut salt = r.take(8)?.to_vec();
    r.u8()?; // filler
    let caps_low = u32::from(r.u16()?);
    if r.remaining() == 0 {
        return proto("pre-4.1 handshake (no protocol 41)");
    }
    r.u8()?; // server default character set (the client announces its own)
    let status = r.u16()?;
    let caps = caps_low | (u32::from(r.u16()?) << 16);
    let auth_len = r.u8()?;
    r.take(10)?; // reserved (MariaDB: 6 filler + 4 extended capability bytes)
    if caps & REQUIRED_SERVER_CAPS != REQUIRED_SERVER_CAPS {
        return proto(format!("server capabilities {caps:#x} lack protocol 41 / secure connection / plugin auth"));
    }
    let n2 = usize::from(auth_len).saturating_sub(8).max(13);
    let part2 = r.take(n2.min(r.remaining()))?;
    let part2 = match part2.iter().position(|b| *b == 0) {
        Some(n) => part2.get(..n).unwrap_or(&[]),
        None => part2,
    };
    salt.extend_from_slice(part2);
    if salt.len() < 20 {
        return proto(format!("scramble of {} bytes (need 20)", salt.len()));
    }
    salt.truncate(20);
    // Some servers omit the plugin name's terminating NUL.
    let rest = r.rest();
    let name = match rest.iter().position(|b| *b == 0) {
        Some(n) => rest.get(..n).unwrap_or(&[]),
        None => rest,
    };
    if name.len() > MAX_PLUGIN_LEN {
        return proto("auth plugin name too long");
    }
    let plugin = String::from_utf8_lossy(name).into_owned();
    Ok(Handshake { server_version, connection_id, caps, status, salt, plugin })
}

/// An OK packet's fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OkPacket {
    pub affected_rows: u64,
    pub last_insert_id: u64,
    pub status: u16,
    pub warnings: u16,
}

/// Parse an OK packet (first byte 0x00, or 0xfe for an OK sent in place of EOF).
pub fn parse_ok(b: &[u8]) -> Result<OkPacket, MysqlError> {
    let mut r = Rd::new(b);
    let h = r.u8()?;
    if h != 0x00 && h != 0xfe {
        return proto("not an OK packet");
    }
    let affected_rows = r.lenenc_int()?.unwrap_or(0);
    let last_insert_id = r.lenenc_int()?.unwrap_or(0);
    let status = r.u16()?;
    let warnings = r.u16()?;
    Ok(OkPacket { affected_rows, last_insert_id, status, warnings })
}

/// Whether `b` is an EOF packet (0xfe and shorter than 9 bytes), and if so its status flags.
pub fn eof_status(b: &[u8]) -> Result<Option<u16>, MysqlError> {
    if b.first() != Some(&0xfe) || b.len() >= 9 {
        return Ok(None);
    }
    let mut r = Rd::new(b);
    r.u8()?;
    r.u16()?; // warnings
    Ok(Some(r.u16()?))
}

/// One column of a result set (Protocol::ColumnDefinition41, the fields this client uses).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColumnDef {
    pub name: String,
    pub charset: u16,
    pub column_type: u8,
    pub flags: u16,
}

pub fn parse_coldef(b: &[u8]) -> Result<ColumnDef, MysqlError> {
    let mut r = Rd::new(b);
    for _ in 0..4 {
        r.lenenc_bytes()?; // catalog, schema, table, org_table
    }
    let name = String::from_utf8_lossy(r.lenenc_bytes()?.unwrap_or(&[])).into_owned();
    r.lenenc_bytes()?; // org_name
    r.lenenc_int()?; // length of the fixed fields (0x0c)
    let charset = r.u16()?;
    r.u32()?; // column length
    let column_type = r.u8()?;
    let flags = r.u16()?;
    Ok(ColumnDef { name, charset, column_type, flags })
}

/// A value of a binary-protocol row.
#[derive(Clone, Debug, PartialEq)]
pub enum Cell {
    Null,
    Int(i64),
    UInt(u64),
    Float(f64),
    /// A string column in a non-binary character set, valid UTF-8.
    Text(String),
    /// A binary-charset string (VARBINARY, BLOB), a non-UTF-8 string, DECIMAL text, BIT, ...
    Bytes(Vec<u8>),
    /// DATE / DATETIME / TIMESTAMP / TIME in the binary protocol's packed form.
    Temporal(Vec<u8>),
}

impl Cell {
    /// The value as text: a Text cell, or a Bytes cell that is valid UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Cell::Text(s) => Some(s),
            Cell::Bytes(b) => std::str::from_utf8(b).ok(),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Cell::Int(i) => Some(*i),
            Cell::UInt(u) => i64::try_from(*u).ok(),
            _ => None,
        }
    }
    pub fn is_null(&self) -> bool {
        matches!(self, Cell::Null)
    }
}

/// Column types (enum_field_types).
mod ty {
    pub const TINY: u8 = 0x01;
    pub const SHORT: u8 = 0x02;
    pub const LONG: u8 = 0x03;
    pub const FLOAT: u8 = 0x04;
    pub const DOUBLE: u8 = 0x05;
    pub const NULL: u8 = 0x06;
    pub const TIMESTAMP: u8 = 0x07;
    pub const LONGLONG: u8 = 0x08;
    pub const INT24: u8 = 0x09;
    pub const DATE: u8 = 0x0a;
    pub const TIME: u8 = 0x0b;
    pub const DATETIME: u8 = 0x0c;
    pub const YEAR: u8 = 0x0d;
}

/// Decode one binary-protocol row (`0x00`, NULL bitmap with a 2-bit offset, values).
pub fn parse_binary_row(b: &[u8], cols: &[ColumnDef]) -> Result<Vec<Cell>, MysqlError> {
    let mut r = Rd::new(b);
    if r.u8()? != 0x00 {
        return proto("binary row without the 0x00 header");
    }
    let nb = cols.len().saturating_add(9) / 8;
    let bitmap = r.take(nb)?;
    let mut row = Vec::with_capacity(cols.len());
    for (i, c) in cols.iter().enumerate() {
        let bit = i.saturating_add(2);
        let byte = bitmap.get(bit / 8).copied().unwrap_or(0);
        if byte & (1u8 << (bit % 8)) != 0 {
            row.push(Cell::Null);
            continue;
        }
        let unsigned = c.flags & UNSIGNED_FLAG != 0;
        let cell = match c.column_type {
            ty::TINY => {
                let v = r.u8()?;
                if unsigned { Cell::UInt(u64::from(v)) } else { Cell::Int(i64::from(v as i8)) }
            }
            ty::SHORT | ty::YEAR => {
                let v = r.u16()?;
                if unsigned { Cell::UInt(u64::from(v)) } else { Cell::Int(i64::from(v as i16)) }
            }
            ty::LONG | ty::INT24 => {
                let v = r.u32()?;
                if unsigned { Cell::UInt(u64::from(v)) } else { Cell::Int(i64::from(v as i32)) }
            }
            ty::LONGLONG => {
                let v = r.u64()?;
                if unsigned { Cell::UInt(v) } else { Cell::Int(v as i64) }
            }
            ty::FLOAT => Cell::Float(f64::from(f32::from_bits(r.u32()?))),
            ty::DOUBLE => Cell::Float(f64::from_bits(r.u64()?)),
            ty::NULL => Cell::Null,
            ty::TIMESTAMP | ty::DATE | ty::DATETIME | ty::TIME => {
                let n = usize::from(r.u8()?);
                Cell::Temporal(r.take(n)?.to_vec())
            }
            _ => {
                let raw =
                    r.lenenc_bytes()?.ok_or_else(|| MysqlError::Protocol("NULL length in a binary row".into()))?;
                if c.charset == BINARY_CHARSET {
                    Cell::Bytes(raw.to_vec())
                } else {
                    match std::str::from_utf8(raw) {
                        Ok(s) => Cell::Text(s.to_owned()),
                        Err(_) => Cell::Bytes(raw.to_vec()),
                    }
                }
            }
        };
        row.push(cell);
    }
    if r.remaining() != 0 {
        return proto("trailing bytes after a binary row");
    }
    Ok(row)
}

/// Prepare-OK header: (statement id, columns, params).
pub fn parse_prepare_ok(b: &[u8]) -> Result<(u32, u16, u16), MysqlError> {
    let mut r = Rd::new(b);
    if r.u8()? != 0x00 {
        return proto("not a COM_STMT_PREPARE OK");
    }
    let id = r.u32()?;
    let ncol = r.u16()?;
    let npar = r.u16()?;
    Ok((id, ncol, npar))
}

/// An auth-phase server packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthReply {
    Ok,
    Err(ServerError),
    /// AuthSwitchRequest: plugin name and its scramble (trailing NUL removed).
    Switch {
        plugin: String,
        data: Vec<u8>,
    },
    /// AuthMoreData (caching_sha2_password and other multi-round plugins).
    MoreData(Vec<u8>),
}

pub fn parse_auth_reply(b: &[u8]) -> Result<AuthReply, MysqlError> {
    let mut r = Rd::new(b);
    match r.u8()? {
        0x00 => Ok(AuthReply::Ok),
        0xff => Ok(AuthReply::Err(parse_err(b)?)),
        0xfe => {
            if r.remaining() == 0 {
                return Err(MysqlError::Auth("old (pre-4.1) password switch requested".into()));
            }
            let name = r.nul_str()?;
            if name.len() > MAX_PLUGIN_LEN {
                return proto("auth plugin name too long");
            }
            let mut data = r.rest().to_vec();
            if data.last() == Some(&0) {
                data.pop();
            }
            Ok(AuthReply::Switch { plugin: String::from_utf8_lossy(name).into_owned(), data })
        }
        0x01 => Ok(AuthReply::MoreData(r.rest().to_vec())),
        h => proto(format!("unexpected auth packet {h:#04x}")),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn lcg(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *seed >> 33
    }

    fn handshake_bytes() -> Vec<u8> {
        let mut b = vec![10u8];
        b.extend_from_slice(b"11.8.9-MariaDB-ubu2404\0");
        b.extend_from_slice(&7u32.to_le_bytes());
        b.extend_from_slice(b"abcdefgh\0");
        let caps = CLIENT_CAPS | CLIENT_SSL;
        b.extend_from_slice(&((caps & 0xffff) as u16).to_le_bytes());
        b.push(45);
        b.extend_from_slice(&2u16.to_le_bytes());
        b.extend_from_slice(&((caps >> 16) as u16).to_le_bytes());
        b.push(21);
        b.extend_from_slice(&[0u8; 10]);
        b.extend_from_slice(b"ijklmnopqrst\0");
        b.extend_from_slice(b"mysql_native_password\0");
        b
    }

    #[test]
    fn handshake_parses() {
        let h = parse_handshake(&handshake_bytes());
        let h = match h {
            Ok(h) => h,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(h.server_version, "11.8.9-MariaDB-ubu2404");
        assert_eq!(h.connection_id, 7);
        assert_eq!(h.salt, b"abcdefghijklmnopqrst".to_vec());
        assert_eq!(h.plugin, "mysql_native_password");
    }

    #[test]
    fn handshake_refusals() {
        let mut b = handshake_bytes();
        b[0] = 9;
        assert!(parse_handshake(&b).is_err());
        let err = [0xffu8, 0x10, 0x04, b'#', b'0', b'8', b'S', b'0', b'1', b'x'];
        assert!(matches!(parse_handshake(&err), Err(MysqlError::Server(e)) if e.code == 1040 && e.state == "08S01"));
    }

    #[test]
    fn truncations_never_panic() {
        let full = handshake_bytes();
        for n in 0..full.len() {
            let _ = parse_handshake(full.get(..n).unwrap_or(&[]));
        }
    }

    #[test]
    fn random_input_never_panics() {
        let mut seed = 0x5eed_u64;
        let cols = vec![
            ColumnDef { name: "a".into(), charset: 45, column_type: 0x08, flags: 0 },
            ColumnDef { name: "b".into(), charset: 63, column_type: 0xfd, flags: 0 },
            ColumnDef { name: "c".into(), charset: 45, column_type: 0x0c, flags: 0 },
            ColumnDef { name: "d".into(), charset: 45, column_type: 0x01, flags: UNSIGNED_FLAG },
        ];
        for _ in 0..20_000 {
            let n = (lcg(&mut seed) % 64) as usize;
            let mut b: Vec<u8> = (0..n).map(|_| lcg(&mut seed) as u8).collect();
            let flip = lcg(&mut seed).is_multiple_of(2);
            if flip && let Some(x) = b.first_mut() {
                *x = [0x00u8, 0xfe, 0xff, 0x01, 10][(lcg(&mut seed) % 5) as usize];
            }
            let _ = parse_handshake(&b);
            let _ = parse_ok(&b);
            let _ = parse_err(&b);
            let _ = eof_status(&b);
            let _ = parse_coldef(&b);
            let _ = parse_binary_row(&b, &cols);
            let _ = parse_prepare_ok(&b);
            let _ = parse_auth_reply(&b);
        }
    }

    #[test]
    fn lenenc_roundtrip() {
        for n in [0usize, 1, 250, 251, 65535, 65536, (1 << 24) - 1, 1 << 24, 1 << 40] {
            let mut out = Vec::new();
            enc_lenenc(n, &mut out);
            let mut r = Rd::new(&out);
            assert_eq!(r.lenenc_int().ok().flatten(), Some(n as u64), "{n}");
            assert_eq!(r.remaining(), 0);
        }
        // A declared string length larger than the payload is refused, not trusted.
        let b = [0xfcu8, 0xff, 0xff, b'a'];
        assert!(Rd::new(&b).lenenc_bytes().is_err());
    }

    #[test]
    fn binary_row_decodes() {
        let cols = vec![
            ColumnDef { name: "id".into(), charset: 63, column_type: 0x08, flags: 0 },
            ColumnDef { name: "t".into(), charset: 45, column_type: 0xfd, flags: 0 },
            ColumnDef { name: "n".into(), charset: 45, column_type: 0xfd, flags: 0 },
            ColumnDef { name: "v".into(), charset: 63, column_type: 0xfd, flags: 0 },
        ];
        // null bitmap: column 2 (bit 4) NULL
        let mut b = vec![0x00u8, 0b0001_0000];
        b.extend_from_slice(&(-5i64).to_le_bytes());
        b.extend_from_slice(&[3, b'a', 0, b'b']);
        b.extend_from_slice(&[1, 0xff]);
        let row = parse_binary_row(&b, &cols);
        assert_eq!(row.ok(), Some(vec![Cell::Int(-5), Cell::Text("a\0b".into()), Cell::Null, Cell::Bytes(vec![0xff])]));
        b.push(0);
        assert!(parse_binary_row(&b, &cols).is_err(), "trailing byte");
    }
}
