//! RESP2 codec, sans IO (DEVIATIONS X-10: owned client, RESP2 subset only).
//!
//! The parser is a pure function over a byte buffer: [`parse`] returns `Ok(None)` while the reply is incomplete and
//! never allocates past the [`Limits`]. Every length is checked against its cap as soon as its header line is read,
//! before any byte of the body is awaited, so a hostile `$9999999999` or `*9999999999` header fails immediately
//! instead of making the caller buffer. RESP3 type bytes (`_ , ( # = % ~ | >`), negative lengths other than the
//! RESP2 null (`-1`), non-canonical integers (`+1`, `--1`, empty, overflow) and bare CR/LF inside a line are all
//! protocol errors: the connection that produced them is discarded, never resynchronized.

use std::fmt;

/// Caps applied to every reply. All are inclusive maxima.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Longest bulk string body.
    pub max_bulk: usize,
    /// Most elements in one array.
    pub max_array: usize,
    /// Deepest array nesting (a top-level array has depth 1). Our commands need 1 (SCAN keys sit at depth 2;
    /// HELLO's module list at depth 3).
    pub max_depth: usize,
    /// Longest simple-string / error / integer / length line (without CRLF).
    pub max_line: usize,
    /// Most bytes one reply may occupy on the wire (also the most the reader buffers while waiting for it).
    pub max_reply: usize,
    /// Most values (of any type, nested included) in one reply.
    pub max_values: usize,
}

/// Defaults: 4 MiB values, 64Ki-element arrays, depth 4, 64 KiB lines, 16 MiB replies, 256Ki values per reply.
pub const DEFAULT_LIMITS: Limits = Limits {
    max_bulk: 4 << 20,
    max_array: 64 << 10,
    max_depth: 4,
    max_line: 64 << 10,
    max_reply: 16 << 20,
    max_values: 256 << 10,
};

impl Default for Limits {
    fn default() -> Self {
        DEFAULT_LIMITS
    }
}

/// One RESP2 reply.
#[derive(Clone, PartialEq, Eq)]
pub enum Reply {
    /// `+...`
    Simple(Vec<u8>),
    /// `-...` (the server refused the command; the connection stays in sync).
    Error(Vec<u8>),
    /// `:...`
    Int(i64),
    /// `$n` body, or `$-1` (`None`).
    Bulk(Option<Vec<u8>>),
    /// `*n` elements, or `*-1` (`None`).
    Array(Option<Vec<Reply>>),
}

impl fmt::Debug for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reply::Simple(s) => write!(f, "Simple({:?})", String::from_utf8_lossy(s)),
            Reply::Error(s) => write!(f, "Error({:?})", String::from_utf8_lossy(s)),
            Reply::Int(i) => write!(f, "Int({i})"),
            Reply::Bulk(None) => write!(f, "Bulk(nil)"),
            Reply::Bulk(Some(b)) => write!(f, "Bulk({} bytes)", b.len()),
            Reply::Array(None) => write!(f, "Array(nil)"),
            Reply::Array(Some(v)) => f.debug_list().entries(v).finish(),
        }
    }
}

impl Reply {
    /// The error text, if this is an error reply.
    pub fn error_text(&self) -> Option<&[u8]> {
        match self {
            Reply::Error(e) => Some(e),
            _ => None,
        }
    }
    /// True for `-NOPERM ...` (ACL refusal).
    pub fn is_noperm(&self) -> bool {
        self.error_text().is_some_and(|e| e.starts_with(b"NOPERM"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RespError {
    /// Unknown or RESP3 type byte.
    BadType(u8),
    /// Malformed line, integer or length, or missing CRLF after a bulk body.
    Malformed(&'static str),
    BulkTooLong,
    ArrayTooLong,
    TooDeep,
    LineTooLong,
    ReplyTooLarge,
    TooManyValues,
}

impl fmt::Display for RespError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RespError::BadType(b) => write!(f, "RESP: unsupported type byte 0x{b:02x}"),
            RespError::Malformed(w) => write!(f, "RESP: malformed {w}"),
            RespError::BulkTooLong => write!(f, "RESP: bulk string exceeds cap"),
            RespError::ArrayTooLong => write!(f, "RESP: array exceeds cap"),
            RespError::TooDeep => write!(f, "RESP: nesting exceeds cap"),
            RespError::LineTooLong => write!(f, "RESP: line exceeds cap"),
            RespError::ReplyTooLarge => write!(f, "RESP: reply exceeds cap"),
            RespError::TooManyValues => write!(f, "RESP: too many values in reply"),
        }
    }
}

impl std::error::Error for RespError {}

/// Parse one reply from the front of `buf`. `Ok(Some((reply, used)))` consumed `used` bytes; `Ok(None)` means more
/// bytes are needed (and `buf` is still within `max_reply`); `Err` means the stream is unusable. Total: never panics.
pub fn parse(buf: &[u8], lim: &Limits) -> Result<Option<(Reply, usize)>, RespError> {
    let mut p = Parser { buf, pos: 0, lim, values: 0 };
    match p.value(0) {
        Ok(v) => {
            if p.pos > lim.max_reply {
                return Err(RespError::ReplyTooLarge);
            }
            Ok(Some((v, p.pos)))
        }
        Err(Step::Incomplete) => {
            if buf.len() > lim.max_reply {
                Err(RespError::ReplyTooLarge)
            } else {
                Ok(None)
            }
        }
        Err(Step::Bad(e)) => Err(e),
    }
}

enum Step {
    Incomplete,
    Bad(RespError),
}

impl From<RespError> for Step {
    fn from(e: RespError) -> Self {
        Step::Bad(e)
    }
}

struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
    lim: &'a Limits,
    values: usize,
}

impl Parser<'_> {
    /// The line starting at `pos` (without CRLF). CR or LF anywhere else in the line is an error.
    fn line(&mut self) -> Result<&[u8], Step> {
        let rest = self.buf.get(self.pos..).unwrap_or(&[]);
        let window = rest.len().min(self.lim.max_line.saturating_add(2));
        let scan = rest.get(..window).unwrap_or(&[]);
        match scan.iter().position(|&b| b == b'\r' || b == b'\n') {
            Some(i) if i > self.lim.max_line => Err(RespError::LineTooLong.into()),
            Some(i) => {
                if scan.get(i) != Some(&b'\r') {
                    return Err(RespError::Malformed("line (bare LF)").into());
                }
                match rest.get(i.saturating_add(1)) {
                    None => Err(Step::Incomplete),
                    Some(b'\n') => {
                        let line = rest.get(..i).ok_or(Step::Bad(RespError::Malformed("line")))?;
                        self.pos = self.pos.saturating_add(i).saturating_add(2);
                        Ok(line)
                    }
                    Some(_) => Err(RespError::Malformed("line (bare CR)").into()),
                }
            }
            None if rest.len() > self.lim.max_line => Err(RespError::LineTooLong.into()),
            None => Err(Step::Incomplete),
        }
    }

    fn value(&mut self, depth: usize) -> Result<Reply, Step> {
        self.values = self.values.saturating_add(1);
        if self.values > self.lim.max_values {
            return Err(RespError::TooManyValues.into());
        }
        let t = *self.buf.get(self.pos).ok_or(Step::Incomplete)?;
        self.pos = self.pos.saturating_add(1);
        match t {
            b'+' => Ok(Reply::Simple(self.line()?.to_vec())),
            b'-' => Ok(Reply::Error(self.line()?.to_vec())),
            b':' => {
                let l = self.line()?;
                Ok(Reply::Int(parse_i64(l).ok_or(Step::Bad(RespError::Malformed("integer")))?))
            }
            b'$' => {
                let l = self.line()?;
                match parse_len(l)? {
                    None => Ok(Reply::Bulk(None)),
                    Some(n) => {
                        if n > self.lim.max_bulk {
                            return Err(RespError::BulkTooLong.into());
                        }
                        let end = self.pos.checked_add(n).ok_or(Step::Bad(RespError::BulkTooLong))?;
                        if end > self.lim.max_reply {
                            return Err(RespError::ReplyTooLarge.into());
                        }
                        let body = self.buf.get(self.pos..end).ok_or(Step::Incomplete)?;
                        match (self.buf.get(end), self.buf.get(end.saturating_add(1))) {
                            (Some(b'\r'), Some(b'\n')) => {}
                            (None, _) | (Some(b'\r'), None) => return Err(Step::Incomplete),
                            _ => return Err(RespError::Malformed("bulk terminator").into()),
                        }
                        let body = body.to_vec();
                        self.pos = end.saturating_add(2);
                        Ok(Reply::Bulk(Some(body)))
                    }
                }
            }
            b'*' => {
                let l = self.line()?;
                match parse_len(l)? {
                    None => Ok(Reply::Array(None)),
                    Some(n) => {
                        if n > self.lim.max_array {
                            return Err(RespError::ArrayTooLong.into());
                        }
                        let d = depth.saturating_add(1);
                        if d > self.lim.max_depth {
                            return Err(RespError::TooDeep.into());
                        }
                        // Each element needs at least 3 bytes on the wire; do not reserve more than the bytes seen.
                        let mut v = Vec::with_capacity(n.min(self.buf.len().saturating_sub(self.pos) / 3));
                        for _ in 0..n {
                            v.push(self.value(d)?);
                        }
                        Ok(Reply::Array(Some(v)))
                    }
                }
            }
            other => Err(RespError::BadType(other).into()),
        }
    }
}

/// Strict decimal i64: optional `-`, at least one digit, no `+`, no leading zeros (except `0`), no `-0`.
fn parse_i64(l: &[u8]) -> Option<i64> {
    let (neg, digits) = match l.split_first() {
        Some((b'-', rest)) => (true, rest),
        _ => (false, l),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if digits.len() > 1 && digits.first() == Some(&b'0') {
        return None;
    }
    if neg && digits == b"0" {
        return None;
    }
    // Accumulate negatively so i64::MIN parses.
    let mut acc: i64 = 0;
    for &c in digits {
        acc = acc.checked_mul(10)?.checked_sub(i64::from(c - b'0'))?;
    }
    if neg { Some(acc) } else { acc.checked_neg() }
}

/// RESP2 length: `-1` is null, any other negative is malformed.
fn parse_len(l: &[u8]) -> Result<Option<usize>, Step> {
    match parse_i64(l) {
        Some(-1) => Ok(None),
        Some(n) if n >= 0 => usize::try_from(n).map(Some).map_err(|_| Step::Bad(RespError::BulkTooLong)),
        _ => Err(RespError::Malformed("length").into()),
    }
}

/// Most arguments in one command we ever send (`SET k v NX` = 4, `ACL SETUSER` ≈ 16, SCAN = 6).
pub const MAX_ARGS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    NoArgs,
    TooManyArgs,
    TooLarge,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::NoArgs => write!(f, "empty command"),
            EncodeError::TooManyArgs => write!(f, "too many arguments"),
            EncodeError::TooLarge => write!(f, "command exceeds size cap"),
        }
    }
}

impl std::error::Error for EncodeError {}

/// Encode a command as a RESP2 array of bulk strings (binary-safe). `max_bytes` caps the encoded size.
pub fn encode(args: &[&[u8]], max_bytes: usize) -> Result<Vec<u8>, EncodeError> {
    if args.is_empty() {
        return Err(EncodeError::NoArgs);
    }
    if args.len() > MAX_ARGS {
        return Err(EncodeError::TooManyArgs);
    }
    let payload = args.iter().try_fold(0usize, |acc, a| acc.checked_add(a.len()));
    match payload {
        Some(n) if n <= max_bytes => {}
        _ => return Err(EncodeError::TooLarge),
    }
    let mut out = Vec::with_capacity(payload.unwrap_or(0).saturating_add(16 * args.len() + 16));
    out.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
    for a in args {
        out.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
        out.extend_from_slice(a);
        out.extend_from_slice(b"\r\n");
    }
    if out.len() > max_bytes {
        return Err(EncodeError::TooLarge);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(b: &[u8]) -> Result<Option<(Reply, usize)>, RespError> {
        parse(b, &DEFAULT_LIMITS)
    }

    #[test]
    fn parses_each_type() {
        assert_eq!(p(b"+OK\r\n"), Ok(Some((Reply::Simple(b"OK".to_vec()), 5))));
        assert_eq!(p(b"-ERR x\r\n"), Ok(Some((Reply::Error(b"ERR x".to_vec()), 8))));
        assert_eq!(p(b":-9223372036854775808\r\n").map(|o| o.map(|x| x.0)), Ok(Some(Reply::Int(i64::MIN))));
        assert_eq!(p(b"$-1\r\n"), Ok(Some((Reply::Bulk(None), 5))));
        assert_eq!(p(b"$3\r\na\r\n\r\n"), Ok(Some((Reply::Bulk(Some(b"a\r\n".to_vec())), 9))));
        assert_eq!(p(b"$0\r\n\r\n"), Ok(Some((Reply::Bulk(Some(vec![])), 6))));
        assert_eq!(p(b"*-1\r\n"), Ok(Some((Reply::Array(None), 5))));
        let scan = b"*2\r\n$1\r\n0\r\n*2\r\n$1\r\na\r\n$1\r\nb\r\n";
        assert_eq!(
            p(scan),
            Ok(Some((
                Reply::Array(Some(vec![
                    Reply::Bulk(Some(b"0".to_vec())),
                    Reply::Array(Some(vec![Reply::Bulk(Some(b"a".to_vec())), Reply::Bulk(Some(b"b".to_vec()))])),
                ])),
                scan.len()
            )))
        );
    }

    #[test]
    fn every_prefix_is_incomplete_not_error() {
        let full: &[u8] = b"*3\r\n$5\r\nhello\r\n:42\r\n*2\r\n+x\r\n$-1\r\n";
        for i in 0..full.len() {
            assert_eq!(p(full.get(..i).unwrap_or(&[])), Ok(None), "prefix {i}");
        }
        assert!(matches!(p(full), Ok(Some((_, n))) if n == full.len()));
    }

    #[test]
    fn rejects_hostile_input() {
        for bad in [
            &b"_\r\n"[..],
            b"%1\r\n",
            b",1.0\r\n",
            b">2\r\n",
            b"#t\r\n",
            b"(1\r\n",
            b"=3\r\n",
            b"~1\r\n",
            b"|1\r\n",
            b"x\r\n",
            b":+1\r\n",
            b":01\r\n",
            b":-0\r\n",
            b":\r\n",
            b":9223372036854775808\r\n",
            b"$-2\r\n",
            b"*-2\r\n",
            b"$1\r\nab\r\n",
            b"+a\nb\r\n",
            b"+a\rb\r\n",
            b"$1\r\naXY",
        ] {
            assert!(p(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn caps_fail_on_the_header() {
        let lim = Limits { max_bulk: 10, max_array: 3, max_depth: 2, max_line: 8, max_reply: 64, max_values: 6 };
        assert_eq!(parse(b"$11\r\n", &lim), Err(RespError::BulkTooLong));
        let wide = Limits { max_line: 32, ..lim };
        assert_eq!(parse(b"$99999999999999999\r\n", &wide), Err(RespError::BulkTooLong));
        assert_eq!(parse(b"*4\r\n", &lim), Err(RespError::ArrayTooLong));
        assert_eq!(parse(b"*1\r\n*1\r\n*1\r\n", &lim), Err(RespError::TooDeep));
        assert_eq!(parse(b"+123456789", &lim), Err(RespError::LineTooLong));
        assert_eq!(parse(b"+123456789\r\n", &lim), Err(RespError::LineTooLong));
        assert_eq!(parse(b"*3\r\n*3\r\n:1\r\n:1\r\n:1\r\n*3\r\n", &lim), Err(RespError::TooManyValues));
        let big = [b'+'; 80];
        assert!(parse(&big, &lim).is_err());
        // Within caps: fine.
        assert!(matches!(parse(b"$10\r\n0123456789\r\n", &lim), Ok(Some(_))));
    }

    #[test]
    fn deep_nesting_does_not_recurse_unbounded() {
        let mut b = Vec::new();
        for _ in 0..100_000 {
            b.extend_from_slice(b"*1\r\n");
        }
        assert_eq!(p(&b), Err(RespError::TooDeep));
    }

    #[test]
    fn encodes_binary_safe() {
        assert_eq!(encode(&[b"GET", b"a\r\nb"], 1024), Ok(b"*2\r\n$3\r\nGET\r\n$4\r\na\r\nb\r\n".to_vec()));
        assert_eq!(encode(&[], 1024), Err(EncodeError::NoArgs));
        let many: Vec<&[u8]> = vec![b"x"; 65];
        assert_eq!(encode(&many, 1 << 20), Err(EncodeError::TooManyArgs));
        assert_eq!(encode(&[&[0u8; 100]], 50), Err(EncodeError::TooLarge));
    }
}
