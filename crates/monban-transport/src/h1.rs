//! Strict HTTP/1.1 request framing (F1 H1 grammar (c)), checked before hyper sees a byte.
//!
//! hyper/httparse accept bare LF line ends, resolve CL+TE by preferring TE, and accept repeated equal
//! Content-Length values; F1 requires all of these rejected. [`H1Validator`] is a sans-IO byte-stream filter: it
//! buffers each request head until it is complete and valid, then forwards it unchanged, and tracks body framing
//! (fixed length or chunked, with chunk-size lines, extensions and trailers checked) so the next head on a
//! keep-alive connection is found at the same offset hyper will use. Invalid input is never forwarded: the stream
//! ends at the last valid message boundary and the caller answers with the reject status.
//!
//! Rejected (400 unless stated): bare LF or bare CR anywhere in a head, chunk line or trailer; obs-fold; leading
//! empty lines; request line not exactly `token SP target SP HTTP/1.x`; absolute-form / authority-form targets;
//! field names that are not tokens (incl. whitespace before the colon); CTL, DEL or non-ASCII in field values;
//! duplicate Content-Length (even equal); Content-Length not 1..19 DIGITs; duplicate Transfer-Encoding;
//! Transfer-Encoding other than exactly `chunked`; Transfer-Encoding on HTTP/1.0; CL together with TE; Expect on a
//! bodyless method or a request without a body; Expect other than `100-continue` (417); head or field block over
//! TBI-1 bounds (431).

use crate::fields::FieldBlock;

/// A framing reject: HTTP status and a static reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct H1Reject {
    pub status: u16,
    pub reason: &'static str,
}

const fn bad(reason: &'static str) -> H1Reject {
    H1Reject { status: 400, reason }
}

/// Body framing of an accepted request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    Fixed(u64),
    Chunked,
}

/// Bounds the validator applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadLimits {
    pub max_head_bytes: u64,
    pub max_field_bytes: u64,
    pub max_fields: u64,
}

/// RFC 9110 `tchar`.
pub fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn is_field_vchar(b: u8) -> bool {
    (0x21..=0x7E).contains(&b) || b == b' ' || b == b'\t'
}

fn trim_ows(v: &[u8]) -> &[u8] {
    let start = v.iter().position(|&b| b != b' ' && b != b'\t').unwrap_or(v.len());
    let end = v.iter().rposition(|&b| b != b' ' && b != b'\t').map_or(start, |e| e.saturating_add(1));
    v.get(start..end).unwrap_or(b"")
}

const BODYLESS: [&[u8]; 6] = [b"GET", b"HEAD", b"DELETE", b"OPTIONS", b"TRACE", b"CONNECT"];

/// Validate one complete request head (ending in CRLF CRLF). Returns the body framing.
pub fn validate_head(head: &[u8], lim: &HeadLimits) -> Result<Framing, H1Reject> {
    if u64::try_from(head.len()).unwrap_or(u64::MAX) > lim.max_head_bytes {
        return Err(H1Reject { status: 431, reason: "request head too large" });
    }
    let mut prev = 0u8;
    for &b in head {
        if b == b'\n' && prev != b'\r' {
            return Err(bad("bare LF"));
        }
        if prev == b'\r' && b != b'\n' {
            return Err(bad("bare CR"));
        }
        prev = b;
    }
    let Some(body) = head.strip_suffix(b"\r\n\r\n") else {
        return Err(bad("unterminated head"));
    };
    // Every CR is followed by LF (checked above), so splitting on CR and dropping the LF that starts each later
    // piece yields exactly the CRLF-delimited lines.
    let mut lines =
        body.split(|&b| b == b'\r').enumerate().map(|(i, l)| if i == 0 { l } else { l.get(1..).unwrap_or(b"") });
    let request_line = lines.next().unwrap_or(b"");
    if request_line.is_empty() {
        return Err(bad("leading empty line"));
    }
    let mut parts = request_line.split(|&b| b == b' ');
    let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad("malformed request line"));
    };
    if method.is_empty() || !method.iter().all(|&b| is_tchar(b)) {
        return Err(bad("bad method"));
    }
    if target.is_empty() || !target.iter().all(|b| (0x21..=0x7E).contains(b)) {
        return Err(bad("bad request-target"));
    }
    if !(target.first() == Some(&b'/') || (target == b"*" && method == b"OPTIONS")) {
        return Err(bad("request-target not origin-form"));
    }
    let http10 = match version {
        b"HTTP/1.1" => false,
        b"HTTP/1.0" => true,
        _ => return Err(bad("bad HTTP version")),
    };

    let mut fb = FieldBlock::new();
    let (mut cl_count, mut te_count) = (0u32, 0u32);
    let mut cl: u64 = 0;
    let mut te_chunked = false;
    let mut expect: Option<&[u8]> = None;
    for line in lines {
        match line.first() {
            None => return Err(bad("empty field line")),
            Some(b' ' | b'\t') => return Err(bad("obs-fold")),
            Some(_) => {}
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return Err(bad("field line without colon"));
        };
        let name = line.get(..colon).unwrap_or(b"");
        let value = trim_ows(line.get(colon.saturating_add(1)..).unwrap_or(b""));
        if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
            return Err(bad("bad field name"));
        }
        if !value.iter().all(|&b| is_field_vchar(b)) {
            return Err(bad("bad field value octet"));
        }
        fb.add(name, value);
        if name.eq_ignore_ascii_case(b"content-length") {
            cl_count = cl_count.saturating_add(1);
            if value.is_empty() || value.len() > 19 || !value.iter().all(u8::is_ascii_digit) {
                return Err(bad("bad Content-Length"));
            }
            cl = value.iter().fold(0u64, |a, &d| a.saturating_mul(10).saturating_add(u64::from(d - b'0')));
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            te_count = te_count.saturating_add(1);
            te_chunked = value.eq_ignore_ascii_case(b"chunked");
        } else if name.eq_ignore_ascii_case(b"expect") {
            if expect.is_some() {
                return Err(bad("duplicate Expect"));
            }
            expect = Some(value);
        }
    }
    if !fb.within(lim.max_field_bytes, lim.max_fields) {
        return Err(H1Reject { status: 431, reason: "field block over TBI-1 bounds" });
    }
    if cl_count > 1 {
        return Err(bad("duplicate Content-Length"));
    }
    if te_count > 1 {
        return Err(bad("duplicate Transfer-Encoding"));
    }
    if te_count == 1 && cl_count == 1 {
        return Err(bad("Content-Length with Transfer-Encoding"));
    }
    if te_count == 1 && !te_chunked {
        return Err(bad("Transfer-Encoding is not exactly chunked"));
    }
    if te_count == 1 && http10 {
        return Err(bad("Transfer-Encoding on HTTP/1.0"));
    }
    let framing = if te_count == 1 { Framing::Chunked } else { Framing::Fixed(cl) };
    if let Some(v) = expect {
        if framing == Framing::Fixed(0) || BODYLESS.contains(&method) {
            return Err(bad("Expect on a bodyless request"));
        }
        if !v.eq_ignore_ascii_case(b"100-continue") {
            return Err(H1Reject { status: 417, reason: "unsupported expectation" });
        }
    }
    Ok(framing)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Chunk {
    Size { digits: u8, val: u64 },
    Ext { val: u64 },
    SizeLf { val: u64 },
    Data(u64),
    DataCr,
    DataLf,
    TrailerLineStart,
    TrailerLine,
    TrailerLineLf,
    TrailerEndLf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum St {
    Head,
    Fixed(u64),
    Chunked(Chunk),
    Dead(H1Reject),
}

/// Sans-IO strict framing filter over one HTTP/1.1 connection's request byte stream.
#[derive(Debug)]
pub struct H1Validator {
    lim: HeadLimits,
    st: St,
    head: Vec<u8>,
    prev: u8,
    /// Chunk-extension and trailer bytes of the current message (bounded by `max_field_bytes`).
    aux: u64,
    /// The reject hit a message whose (valid) head was already forwarded, i.e. inside its body.
    dead_in_body: bool,
    /// Request heads forwarded so far (each one is a request the downstream parser must answer).
    heads: u64,
}

fn hex(b: u8) -> Option<u64> {
    match b {
        b'0'..=b'9' => Some(u64::from(b - b'0')),
        b'a'..=b'f' => Some(u64::from(b - b'a') + 10),
        b'A'..=b'F' => Some(u64::from(b - b'A') + 10),
        _ => None,
    }
}

impl H1Validator {
    pub fn new(lim: HeadLimits) -> Self {
        Self { lim, st: St::Head, head: Vec::new(), prev: 0, aux: 0, dead_in_body: false, heads: 0 }
    }

    /// A head is partially buffered (TBI-8: the head deadline runs).
    pub fn head_partial(&self) -> bool {
        self.st == St::Head && !self.head.is_empty()
    }

    /// Inside a message (partial head or unfinished body).
    pub fn mid_message(&self) -> bool {
        match self.st {
            St::Head => !self.head.is_empty(),
            St::Fixed(_) | St::Chunked(_) => true,
            St::Dead(_) => false,
        }
    }

    /// The reject that stopped the stream, if any.
    pub fn rejected(&self) -> Option<H1Reject> {
        match self.st {
            St::Dead(r) => Some(r),
            _ => None,
        }
    }

    /// `true` when the stream was rejected inside a message body: that message's head was forwarded, so the
    /// downstream parser has a request to answer (R6: it answers, with the reject status, and the caller must not
    /// add a second response). `false` for a head-level reject (nothing of the bad message was forwarded) and
    /// while the stream is alive.
    pub fn rejected_in_body(&self) -> bool {
        self.rejected().is_some() && self.dead_in_body
    }

    /// Number of request heads forwarded so far.
    pub fn heads_forwarded(&self) -> u64 {
        self.heads
    }

    fn die(&mut self, r: H1Reject) -> Result<(), H1Reject> {
        self.dead_in_body = matches!(self.st, St::Fixed(_) | St::Chunked(_));
        self.st = St::Dead(r);
        self.head = Vec::new();
        Err(r)
    }

    fn aux_byte(&mut self) -> Result<(), H1Reject> {
        self.aux = self.aux.saturating_add(1);
        if self.aux > self.lim.max_field_bytes {
            return Err(H1Reject { status: 431, reason: "chunk extensions / trailers over TBI-1 bounds" });
        }
        Ok(())
    }

    /// One chunk-framing octet (not chunk data). Returns the next state.
    fn chunk_byte(&mut self, c: Chunk, b: u8) -> Result<St, H1Reject> {
        Ok(match c {
            Chunk::Size { digits, val } => match (b, hex(b)) {
                (_, Some(d)) => {
                    if digits >= 16 {
                        return Err(bad("chunk size too long"));
                    }
                    let val = val.checked_mul(16).and_then(|v| v.checked_add(d)).ok_or(bad("chunk size overflow"))?;
                    St::Chunked(Chunk::Size { digits: digits.saturating_add(1), val })
                }
                (b';', None) if digits > 0 => {
                    self.aux_byte()?;
                    St::Chunked(Chunk::Ext { val })
                }
                (b'\r', None) if digits > 0 => St::Chunked(Chunk::SizeLf { val }),
                _ => return Err(bad("bad chunk size line")),
            },
            Chunk::Ext { val } => match b {
                b'\r' => St::Chunked(Chunk::SizeLf { val }),
                b'\n' => return Err(bad("bare LF in chunk line")),
                _ if is_field_vchar(b) => {
                    self.aux_byte()?;
                    St::Chunked(Chunk::Ext { val })
                }
                _ => return Err(bad("bad chunk extension octet")),
            },
            Chunk::SizeLf { val } => match b {
                b'\n' if val == 0 => St::Chunked(Chunk::TrailerLineStart),
                b'\n' => St::Chunked(Chunk::Data(val)),
                _ => return Err(bad("bare CR in chunk line")),
            },
            Chunk::DataCr => match b {
                b'\r' => St::Chunked(Chunk::DataLf),
                _ => return Err(bad("chunk data not followed by CRLF")),
            },
            Chunk::DataLf => match b {
                b'\n' => St::Chunked(Chunk::Size { digits: 0, val: 0 }),
                _ => return Err(bad("bare CR after chunk data")),
            },
            Chunk::TrailerLineStart => match b {
                b'\r' => St::Chunked(Chunk::TrailerEndLf),
                b' ' | b'\t' => return Err(bad("obs-fold in trailer")),
                b'\n' => return Err(bad("bare LF in trailer")),
                _ if is_field_vchar(b) => {
                    self.aux_byte()?;
                    St::Chunked(Chunk::TrailerLine)
                }
                _ => return Err(bad("bad trailer octet")),
            },
            Chunk::TrailerLine => match b {
                b'\r' => St::Chunked(Chunk::TrailerLineLf),
                b'\n' => return Err(bad("bare LF in trailer")),
                _ if is_field_vchar(b) => {
                    self.aux_byte()?;
                    St::Chunked(Chunk::TrailerLine)
                }
                _ => return Err(bad("bad trailer octet")),
            },
            Chunk::TrailerLineLf => match b {
                b'\n' => St::Chunked(Chunk::TrailerLineStart),
                _ => return Err(bad("bare CR in trailer")),
            },
            Chunk::TrailerEndLf => match b {
                b'\n' => {
                    self.aux = 0;
                    St::Head
                }
                _ => return Err(bad("bare CR in trailer")),
            },
            // Data is consumed in slices by `feed`; never reached here.
            Chunk::Data(_) => return Err(bad("internal: chunk data")),
        })
    }

    /// Feed received bytes; append the bytes that may be forwarded to `out`. On a reject nothing from the bad
    /// message is forwarded and every later call returns the same reject.
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), H1Reject> {
        let mut rest = input;
        while let Some((&b, tail)) = rest.split_first() {
            match self.st {
                St::Dead(r) => return Err(r),
                St::Head => {
                    rest = tail;
                    if b == b'\n' && self.prev != b'\r' {
                        return self.die(bad("bare LF"));
                    }
                    if self.prev == b'\r' && b != b'\n' {
                        return self.die(bad("bare CR"));
                    }
                    self.prev = b;
                    self.head.push(b);
                    if u64::try_from(self.head.len()).unwrap_or(u64::MAX) > self.lim.max_head_bytes {
                        return self.die(H1Reject { status: 431, reason: "request head too large" });
                    }
                    if self.head.ends_with(b"\r\n\r\n") {
                        match validate_head(&self.head, &self.lim) {
                            Ok(f) => {
                                out.extend_from_slice(&self.head);
                                self.heads = self.heads.saturating_add(1);
                                self.head.clear();
                                self.prev = 0;
                                self.aux = 0;
                                self.st = match f {
                                    Framing::Fixed(0) => St::Head,
                                    Framing::Fixed(n) => St::Fixed(n),
                                    Framing::Chunked => St::Chunked(Chunk::Size { digits: 0, val: 0 }),
                                };
                            }
                            Err(r) => return self.die(r),
                        }
                    }
                }
                St::Fixed(n) | St::Chunked(Chunk::Data(n)) => {
                    let take = usize::try_from(n).unwrap_or(usize::MAX).min(rest.len());
                    let (now, later) = rest.split_at(take);
                    out.extend_from_slice(now);
                    rest = later;
                    let left = n.saturating_sub(u64::try_from(take).unwrap_or(u64::MAX));
                    self.st = match (self.st, left) {
                        (St::Fixed(_), 0) => St::Head,
                        (St::Fixed(_), l) => St::Fixed(l),
                        (_, 0) => St::Chunked(Chunk::DataCr),
                        (_, l) => St::Chunked(Chunk::Data(l)),
                    };
                }
                St::Chunked(c) => {
                    rest = tail;
                    match self.chunk_byte(c, b) {
                        Ok(next) => {
                            out.push(b);
                            self.st = next;
                        }
                        Err(r) => return self.die(r),
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    const LIM: HeadLimits = HeadLimits { max_head_bytes: 24_592, max_field_bytes: 16_384, max_fields: 128 };

    fn run(input: &[u8]) -> (Vec<u8>, Result<(), H1Reject>) {
        let mut v = H1Validator::new(LIM);
        let mut out = Vec::new();
        let r = v.feed(input, &mut out);
        (out, r)
    }

    fn run_bytewise(input: &[u8]) -> (Vec<u8>, Result<(), H1Reject>) {
        let mut v = H1Validator::new(LIM);
        let mut out = Vec::new();
        for b in input {
            if let Err(e) = v.feed(std::slice::from_ref(b), &mut out) {
                return (out, Err(e));
            }
        }
        (out, Ok(()))
    }

    fn rejects(input: &[u8]) -> u16 {
        let (out, r) = run(input);
        let (out2, r2) = run_bytewise(input);
        assert_eq!(r, r2, "split-invariance for {:?}", String::from_utf8_lossy(input));
        assert_eq!(out, out2);
        match r {
            Err(e) => {
                assert!(out.is_empty(), "nothing of a bad first message is forwarded");
                e.status
            }
            Ok(()) => 0,
        }
    }

    #[test]
    fn accepts_valid_and_forwards_unchanged() {
        let reqs: &[&[u8]] = &[
            b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
            b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc",
            b"POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3;e=1\r\nabc\r\n0\r\nT: v\r\n\r\n",
            b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nExpect: 100-continue\r\n\r\nz",
            b"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n",
        ];
        for r in reqs {
            let (out, res) = run(r);
            assert_eq!(res, Ok(()), "{:?}", String::from_utf8_lossy(r));
            assert_eq!(&out[..], *r);
            let (out2, res2) = run_bytewise(r);
            assert_eq!(res2, Ok(()));
            assert_eq!(&out2[..], *r);
        }
        // pipelined: two messages back to back are both forwarded
        let two = b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhiGET / HTTP/1.1\r\nHost: a\r\n\r\n";
        let (out, res) = run(two);
        assert_eq!(res, Ok(()));
        assert_eq!(&out[..], &two[..]);
    }

    #[test]
    fn f1_h1_grammar_rejects() {
        let cases: &[(&[u8], u16)] = &[
            (b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n", 400),
            (b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc", 400),
            (b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3, 3\r\n\r\nabc", 400),
            (b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +3\r\n\r\nabc", 400),
            (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", 400),
            (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n", 400),
            (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: xchunked\r\n\r\n", 400),
            (b"POST / HTTP/1.0\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n", 400),
            (b"GET / HTTP/1.1\nHost: a\r\n\r\n", 400),
            (b"GET / HTTP/1.1\r\nHost: a\n\r\n", 400),
            (b"GET / HTTP/1.1\r\nHost: a\rX: b\r\n\r\n", 400),
            (b"GET / HTTP/1.1\r\nHost: a\r\nX: b\r\n c\r\n\r\n", 400),
            (b"GET / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\n\r\n", 400),
            (b"POST / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\n\r\n", 400),
            (b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nExpect: 200-ok\r\n\r\nz", 417),
            (b"\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n", 400),
            (b"GET  / HTTP/1.1\r\nHost: a\r\n\r\n", 400),
            (b"GET http://a/ HTTP/1.1\r\nHost: a\r\n\r\n", 400),
            (b"GET / HTTP/2.0\r\nHost: a\r\n\r\n", 400),
            (b"GET / HTTP/1.1\r\nHost : a\r\n\r\n", 400),
            (b"GET / HTTP/1.1\r\nHost: a\x00b\r\n\r\n", 400),
            (b"GET / HTTP/1.1\r\nHost: a\xffb\r\n\r\n", 400),
            (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\nabc\r\n0\r\n\r\n", 400),
            (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcX0\r\n\r\n", 400),
            (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n 3\r\nabc\r\n0\r\n\r\n", 400),
            (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nT: v\n\r\n", 400),
            (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n folded\r\n\r\n", 400),
            (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n11111111111111111\r\n", 400),
        ];
        for (input, status) in cases {
            let got = run(input);
            // Body-level rejects forward the (valid) head first; head-level rejects forward nothing.
            let st = match got.1 {
                Err(e) => e.status,
                Ok(()) => 0,
            };
            assert_eq!(st, *status, "{:?}", String::from_utf8_lossy(input));
            let st2 = match run_bytewise(input).1 {
                Err(e) => e.status,
                Ok(()) => 0,
            };
            assert_eq!(st2, *status, "bytewise {:?}", String::from_utf8_lossy(input));
        }
        assert_eq!(rejects(b"GET / HTTP/1.1\r\nHost: a\r\nX: b\r\n c\r\n\r\n"), 400);
    }

    #[test]
    fn tbi1_bounds() {
        let mut many = b"GET / HTTP/1.1\r\nHost: a\r\n".to_vec();
        for i in 0..128 {
            many.extend_from_slice(format!("x{i}: v\r\n").as_bytes());
        }
        many.extend_from_slice(b"\r\n");
        assert_eq!(rejects(&many), 431);
        let crumbs: Vec<String> = (0..128).map(|i| format!("c{i}=1")).collect();
        let req = format!("GET / HTTP/1.1\r\nHost: a\r\nCookie: {}\r\n\r\n", crumbs.join("; "));
        assert_eq!(rejects(req.as_bytes()), 431);
        let big = format!("GET / HTTP/1.1\r\nHost: a\r\nX: {}\r\n\r\n", "v".repeat(16_400));
        assert_eq!(rejects(big.as_bytes()), 431);
        let huge = format!("GET / HTTP/1.1\r\nHost: a\r\nX: {}", "v".repeat(30_000));
        assert_eq!(run(huge.as_bytes()).1.err().map(|e| e.status), Some(431));
    }

    /// R6: a body-level reject is flagged as such (the head went downstream), a head-level one is not, also when
    /// the bad head follows a complete pipelined message in the same read.
    #[test]
    fn reject_in_body_vs_head() {
        let body: &[&[u8]] = &[
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n0\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\nhello\r\n0\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcX",
        ];
        for input in body {
            for split in [false, true] {
                let mut v = H1Validator::new(LIM);
                let mut out = Vec::new();
                let r = if split {
                    input.iter().try_for_each(|b| v.feed(std::slice::from_ref(b), &mut out))
                } else {
                    v.feed(input, &mut out)
                };
                assert_eq!(r.err().map(|e| e.status), Some(400), "{:?}", String::from_utf8_lossy(input));
                assert!(v.rejected_in_body(), "{:?}", String::from_utf8_lossy(input));
                assert!(out.starts_with(b"POST / HTTP/1.1\r\n"), "the valid head went downstream");
            }
        }
        let head: &[&[u8]] = &[
            b"GET / HTTP/1.1\nHost: a\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhiGET / HTTP/1.1\nHost: a\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET / HTTP/1.1\nHost: a\r\n\r\n",
        ];
        for input in head {
            let mut v = H1Validator::new(LIM);
            let mut out = Vec::new();
            assert!(v.feed(input, &mut out).is_err());
            assert!(!v.rejected_in_body(), "{:?}", String::from_utf8_lossy(input));
        }
        let v = H1Validator::new(LIM);
        assert!(!v.rejected_in_body());
        let mut v = H1Validator::new(LIM);
        let mut out = Vec::new();
        assert!(v.feed(head[1], &mut out).is_err());
        assert_eq!(v.heads_forwarded(), 1, "the pipelined CL message was forwarded, the bad head was not");
        let mut v = H1Validator::new(LIM);
        assert!(v.feed(body[0], &mut out).is_err());
        assert_eq!(v.heads_forwarded(), 1);
    }

    #[test]
    fn dead_stays_dead_and_partial_tracking() {
        let mut v = H1Validator::new(LIM);
        let mut out = Vec::new();
        assert_eq!(v.feed(b"GET / HT", &mut out), Ok(()));
        assert!(v.head_partial() && v.mid_message() && out.is_empty());
        assert!(v.feed(b"TP/1.1\nHost: a\r\n\r\n", &mut out).is_err());
        assert!(v.rejected().is_some());
        assert!(v.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", &mut out).is_err());
        assert!(out.is_empty());
    }
}
