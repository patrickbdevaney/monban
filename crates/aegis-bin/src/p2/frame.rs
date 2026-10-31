//! F14 Part 2 frames, supervisor side: encoders of the supervisor -> worker frames and the total decoder of the
//! worker -> supervisor frames, plus the supervisor's independent re-check of the I5 `resp-headers` rules
//! (`interfaces/F14-p2-guest-abi.cddl`; SPEC_INVARIANTS §H: the host decoders of module output are in the
//! verified TCB).
//!
//! aegis-bin never links aegis-wasm (PLAN-5 D3, gate no-wasmtime-in-bin), so this is a second implementation of the
//! F10 encoding rule (postcard positional: unsigned LEB128 varints, length-prefixed bstr/tstr and arrays, a choice
//! as a varint discriminant, bool one byte 0/1, option 0 | 1 value), written from the CDDL. It agrees with the
//! worker's `aegis_wasm::abi::frame` on every frame both sides use; the tests below pin the byte layout.
//!
//! Every decoder is total: malformed input (truncation, an overlong varint, trailing bytes, an unknown tag, a wrong
//! req-id, invalid UTF-8, a bool other than 0/1, a value out of its CDDL range) gives `None`, never a panic.
#![forbid(unsafe_code)]

/// The frame cap: aegis-p2 sizes its frames by the F8 `p2.frame_max_bytes` default and has no flag to change it
/// (`F14Worker::with_frame_max` exists but the worker command line does not reach it), so the supervisor sends and
/// accepts frames of at most this size and refuses a configured value other than it (plan.rs, fail closed).
pub const FRAME_MAX: usize = 64 << 10;
/// Room left in a frame for its tag, req-id, length prefix and flag.
const FRAME_OVERHEAD: usize = 32;
/// Largest body chunk per `body-chunk` frame.
pub const BODY_CHUNK: usize = FRAME_MAX - FRAME_OVERHEAD;
/// F14 `guest-api-version`.
pub const GUEST_API_VERSION: u64 = 1;

/// Frame tags (F14 Part 2).
mod tag {
    pub const REQUEST: u64 = 0;
    pub const BODY_CHUNK: u64 = 1;
    pub const DATA_REPLY: u64 = 2;
    pub const READY: u64 = 16;
    pub const RESP_HEAD: u64 = 17;
    pub const RESP_BODY: u64 = 18;
    pub const RESP_END: u64 = 19;
    pub const DATA_RUN: u64 = 20;
    pub const LOG: u64 = 21;
    pub const LAYOUT: u64 = 22;
}

// ------------------------------------------------------------------------------------------------ encoding

/// Writer for one frame.
#[derive(Debug, Default)]
pub struct Enc(Vec<u8>);

impl Enc {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn u(mut self, mut n: u64) -> Self {
        loop {
            let b = u8::try_from(n & 0x7f).unwrap_or(0);
            n >>= 7;
            if n == 0 {
                self.0.push(b);
                return self;
            }
            self.0.push(b | 0x80);
        }
    }
    pub fn len_of(self, n: usize) -> Self {
        self.u(u64::try_from(n).unwrap_or(u64::MAX))
    }
    pub fn bytes(self, b: &[u8]) -> Self {
        let mut s = self.len_of(b.len());
        s.0.extend_from_slice(b);
        s
    }
    pub fn raw(mut self, b: &[u8]) -> Self {
        self.0.extend_from_slice(b);
        self
    }
    pub fn boolean(mut self, v: bool) -> Self {
        self.0.push(u8::from(v));
        self
    }
    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// The eight per-request limits of a `request` frame (F14 `limits`, F8 effective values for the route's module).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub fuel: u64,
    pub wall_ms: u64,
    pub memory_mib: u64,
    pub max_host_calls: u64,
    pub max_data_runs: u64,
    pub max_data_bytes: u64,
    pub max_resp_bytes: u64,
    pub max_log_bytes: u64,
}

/// The F14 `query` of a `req-head`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Query {
    /// `[0, bstr]`: the canonical query bytes (F8 `canon.query = "opaque"`).
    Opaque(Vec<u8>),
    /// `[1, [* [name, value]]]`: decoded parameters in order (F8 `canon.query = "typed"`).
    Typed(Vec<(String, String)>),
}

/// F14 `req-head`, built only from canonical values (I5: the module never sees raw request bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReqHead {
    pub method: String,
    pub path: String,
    pub query: Query,
    /// Allowlisted fields only ([`REQ_HEADER_ALLOW`]), lower-case names.
    pub headers: Vec<(String, Vec<u8>)>,
    pub body_len: Option<u64>,
}

/// F14 request header allowlist (fixed, not configurable).
pub const REQ_HEADER_ALLOW: &[&str] = &[
    "accept",
    "accept-language",
    "content-type",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-unmodified-since",
    "range",
];

impl ReqHead {
    /// The `req-head` encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new().bytes(self.method.as_bytes()).bytes(self.path.as_bytes());
        e = match &self.query {
            Query::Opaque(q) => e.u(0).bytes(q),
            Query::Typed(ps) => {
                let mut e = e.u(1).len_of(ps.len());
                for (n, v) in ps {
                    e = e.bytes(n.as_bytes()).bytes(v.as_bytes());
                }
                e
            }
        };
        e = e.len_of(self.headers.len());
        for (n, v) in &self.headers {
            e = e.bytes(n.as_bytes()).bytes(v);
        }
        match self.body_len {
            None => e.u(0),
            Some(n) => e.u(1).u(n),
        }
        .finish()
    }
}

/// `request = [0, req-id, limits, req-head]`.
pub fn request(rid: u64, l: &Limits, head: &[u8]) -> Vec<u8> {
    Enc::new()
        .u(tag::REQUEST)
        .u(rid)
        .u(l.fuel)
        .u(l.wall_ms)
        .u(l.memory_mib)
        .u(l.max_host_calls)
        .u(l.max_data_runs)
        .u(l.max_data_bytes)
        .u(l.max_resp_bytes)
        .u(l.max_log_bytes)
        .raw(head)
        .finish()
}

/// `body-chunk = [1, req-id, chunk, last]`.
pub fn body_chunk(rid: u64, chunk: &[u8], last: bool) -> Vec<u8> {
    Enc::new().u(tag::BODY_CHUNK).u(rid).bytes(chunk).boolean(last).finish()
}

/// `data-reply = [2, req-id, seq, result]` with the F10 `result` [1, error-code] (the uniform denial, W6).
pub fn data_reply_denied(rid: u64, seq: u64, code: u8) -> Vec<u8> {
    Enc::new().u(tag::DATA_REPLY).u(rid).u(seq).u(1).u(u64::from(code)).finish()
}

// ------------------------------------------------------------------------------------------------ decoding

/// Total reader over one frame.
#[derive(Debug)]
pub struct Dec<'a> {
    b: &'a [u8],
}

impl<'a> Dec<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b }
    }
    pub fn u(&mut self) -> Option<u64> {
        let mut v: u64 = 0;
        for k in 0..10u32 {
            let (&x, rest) = self.b.split_first()?;
            self.b = rest;
            let part = u64::from(x & 0x7f);
            if k == 9 && part > 1 {
                return None; // past 64 bits
            }
            v |= part << (7 * k);
            if x & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }
    pub fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = usize::try_from(self.u()?).ok()?;
        if n > self.b.len() {
            return None;
        }
        let (s, rest) = self.b.split_at(n);
        self.b = rest;
        Some(s)
    }
    pub fn text(&mut self) -> Option<&'a str> {
        std::str::from_utf8(self.bytes()?).ok()
    }
    pub fn remaining(&self) -> usize {
        self.b.len()
    }
    pub fn done(&self) -> bool {
        self.b.is_empty()
    }
}

/// How a request ended (F14 `end`): the worker's report, untrusted (it classifies a fault, it never turns a
/// request into a success).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// `[0, code]`: `handle()` returned `code` (0 Allow, 1 Deny, anything else Error).
    Code(u32),
    /// `[1, trap]`: the request trapped (1..=8).
    Trap(u8),
}

/// Response header fields as decoded (name, value).
pub type Fields = Vec<(Vec<u8>, Vec<u8>)>;

/// One decoded worker -> supervisor frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum W2s<'a> {
    /// `[16, 0, guest-api-version, module-sha256]`.
    Ready { digest: &'a [u8] },
    /// `[17, req-id, status, resp-headers]`; `headers` is the validated encoding's decoded fields.
    RespHead { rid: u64, status: u16, headers: Fields },
    /// `[18, req-id, chunk]`.
    RespBody { rid: u64, chunk: &'a [u8] },
    /// `[19, req-id, end, fuel-used]`.
    RespEnd { rid: u64, end: End, fuel_used: u64 },
    /// `[20, req-id, seq, op]`; `op` the F10 `op` bytes as the guest passed them.
    DataRun { rid: u64, seq: u64, op: &'a [u8] },
    /// `[21, req-id, level, data]`; `data` is module-authored and never parsed.
    Log { rid: u64, level: u8, data: &'a [u8] },
    /// `[22, 0, load-base, pid]` (test-hooks builds only, D8; no authority).
    Layout { load_base: u64, pid: u64 },
}

/// The configured header limits the supervisor re-checks a `resp-head` against (F8 `limits`; the worker only
/// bounds them by their F8 maxima because it is not told the configured values).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderLimits {
    pub max_fields: u64,
    pub max_list_size: u64,
}

/// Longest header name (F14 I5 rules).
const MAX_NAME: usize = 64;
/// Framing and hop-by-hop fields a module may never set (plus every `proxy-*` field).
const BANNED: &[&[u8]] =
    &[b"content-length", b"transfer-encoding", b"connection", b"keep-alive", b"upgrade", b"te", b"trailer"];

fn tchar(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn name_ok(n: &[u8]) -> bool {
    !n.is_empty()
        && n.len() <= MAX_NAME
        && n.iter().all(|&b| tchar(b))
        && !BANNED.contains(&n)
        && !n.starts_with(b"proxy-")
}

fn value_ok(v: &[u8]) -> bool {
    let ws = |b: &u8| *b == b' ' || *b == b'\t';
    v.iter().all(|&b| b == b' ' || b == b'\t' || (0x21..=0x7e).contains(&b))
        && !v.first().is_some_and(ws)
        && !v.last().is_some_and(ws)
}

/// Decodes `resp-headers` (`[* [name: tstr, value: bstr]]`) from `d` and applies the I5 rules against `lim`. Reject,
/// never repair (CANON-2).
fn resp_headers(d: &mut Dec<'_>, lim: &HeaderLimits) -> Option<Fields> {
    let n = d.u()?;
    if n > lim.max_fields || n > u64::try_from(d.remaining()).unwrap_or(0) {
        return None;
    }
    let mut out = Vec::new();
    let mut total: u64 = 0;
    for _ in 0..n {
        let name = d.text()?.as_bytes();
        let value = d.bytes()?;
        if !name_ok(name) || !value_ok(value) {
            return None;
        }
        let field = u64::try_from(name.len().saturating_add(value.len()).saturating_add(32)).unwrap_or(u64::MAX);
        total = total.saturating_add(field);
        if total > lim.max_list_size {
            return None;
        }
        out.push((name.to_vec(), value.to_vec()));
    }
    Some(out)
}

fn rid(d: &mut Dec<'_>) -> Option<u64> {
    let r = d.u()?;
    (r != 0).then_some(r)
}

/// Decodes one worker -> supervisor frame completely (no trailing bytes). `lim` bounds a `resp-head`.
pub fn decode_w2s<'a>(frame: &'a [u8], lim: &HeaderLimits) -> Option<W2s<'a>> {
    if frame.len() > FRAME_MAX {
        return None;
    }
    let mut d = Dec::new(frame);
    let v = match d.u()? {
        tag::READY => {
            if d.u()? != 0 || d.u()? != GUEST_API_VERSION {
                return None;
            }
            let digest = d.bytes()?;
            if digest.len() != 32 {
                return None;
            }
            W2s::Ready { digest }
        }
        tag::RESP_HEAD => {
            let rid = rid(&mut d)?;
            let status = u16::try_from(d.u()?).ok().filter(|s| (200..=599).contains(s))?;
            let headers = resp_headers(&mut d, lim)?;
            W2s::RespHead { rid, status, headers }
        }
        tag::RESP_BODY => {
            let rid = rid(&mut d)?;
            W2s::RespBody { rid, chunk: d.bytes()? }
        }
        tag::RESP_END => {
            let rid = rid(&mut d)?;
            let end = match d.u()? {
                0 => End::Code(u32::try_from(d.u()?).ok()?),
                1 => End::Trap(u8::try_from(d.u()?).ok().filter(|t| (1..=8).contains(t))?),
                _ => return None,
            };
            W2s::RespEnd { rid, end, fuel_used: d.u()? }
        }
        tag::DATA_RUN => {
            let rid = rid(&mut d)?;
            let seq = d.u()?;
            W2s::DataRun { rid, seq, op: d.bytes()? }
        }
        tag::LOG => {
            let rid = rid(&mut d)?;
            let level = u8::try_from(d.u()?).ok().filter(|l| *l <= 4)?;
            W2s::Log { rid, level, data: d.bytes()? }
        }
        tag::LAYOUT => {
            if d.u()? != 0 {
                return None;
            }
            W2s::Layout { load_base: d.u()?, pid: d.u()? }
        }
        _ => return None,
    };
    d.done().then_some(v)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    const LIM: HeaderLimits = HeaderLimits { max_fields: 128, max_list_size: 16_384 };

    fn resp_head(rid: u64, status: u64, hs: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut e = Enc::new().u(tag::RESP_HEAD).u(rid).u(status).len_of(hs.len());
        for (n, v) in hs {
            e = e.bytes(n).bytes(v);
        }
        e.finish()
    }

    #[test]
    fn layouts_match_the_worker_codec() {
        // aegis_wasm::abi::frame::ready / layout / resp_end, byte for byte.
        let d = [7u8; 32];
        let ready = Enc::new().u(16).u(0).u(1).bytes(&d).finish();
        assert_eq!(decode_w2s(&ready, &LIM), Some(W2s::Ready { digest: &d }));
        assert_eq!(decode_w2s(&[22, 0, 0x80, 0x01, 5], &LIM), Some(W2s::Layout { load_base: 128, pid: 5 }));
        assert_eq!(decode_w2s(&[19, 1, 0, 0, 7], &LIM), Some(W2s::RespEnd { rid: 1, end: End::Code(0), fuel_used: 7 }));
        assert_eq!(decode_w2s(&[19, 1, 1, 4, 0], &LIM), Some(W2s::RespEnd { rid: 1, end: End::Trap(4), fuel_used: 0 }));
        // request: tag, rid, 8 limits, then the req-head bytes verbatim.
        let l = Limits {
            fuel: 1,
            wall_ms: 2,
            memory_mib: 3,
            max_host_calls: 4,
            max_data_runs: 5,
            max_data_bytes: 6,
            max_resp_bytes: 7,
            max_log_bytes: 8,
        };
        assert_eq!(request(9, &l, &[0xaa]), vec![0, 9, 1, 2, 3, 4, 5, 6, 7, 8, 0xaa]);
        assert_eq!(body_chunk(9, b"x", true), vec![1, 9, 1, b'x', 1]);
        assert_eq!(data_reply_denied(9, 0, 1), vec![2, 9, 0, 1, 1]);
    }

    #[test]
    fn req_head_encoding() {
        let h = ReqHead {
            method: "GET".into(),
            path: "/a/x".into(),
            query: Query::Opaque(b"n=1".to_vec()),
            headers: vec![("accept".into(), b"text/plain".to_vec())],
            body_len: Some(0),
        };
        let mut want = vec![3];
        want.extend_from_slice(b"GET");
        want.push(4);
        want.extend_from_slice(b"/a/x");
        want.extend_from_slice(&[0, 3]);
        want.extend_from_slice(b"n=1");
        want.extend_from_slice(&[1, 6]);
        want.extend_from_slice(b"accept");
        want.push(10);
        want.extend_from_slice(b"text/plain");
        want.extend_from_slice(&[1, 0]);
        assert_eq!(h.encode(), want);
        let t = ReqHead { query: Query::Typed(vec![("n".into(), "1".into())]), body_len: None, ..h };
        let e = t.encode();
        assert_eq!(&e[9..15], &[1, 1, 1, b'n', 1, b'1']);
        assert_eq!(*e.last().unwrap(), 0);
    }

    #[test]
    fn resp_head_rules_are_rechecked() {
        let ok = resp_head(1, 200, &[(b"content-type", b"text/plain"), (b"x-a", b"1 2")]);
        assert!(
            matches!(decode_w2s(&ok, &LIM), Some(W2s::RespHead { status: 200, ref headers, .. }) if headers.len() == 2)
        );
        for bad in [
            resp_head(1, 199, &[]),
            resp_head(1, 600, &[]),
            resp_head(0, 200, &[]),
            resp_head(1, 200, &[(b"Content-Type", b"x")]),
            resp_head(1, 200, &[(b"content-length", b"1")]),
            resp_head(1, 200, &[(b"proxy-x", b"1")]),
            resp_head(1, 200, &[(b"x", b" lead")]),
            resp_head(1, 200, &[(b"x", b"a\r\nb")]),
            resp_head(1, 200, &[(b"x", b"\x80")]),
            resp_head(1, 200, &[(b"", b"v")]),
            resp_head(1, 200, &[(&[b'a'; 65], b"v")]),
        ] {
            assert_eq!(decode_w2s(&bad, &LIM), None, "{bad:?}");
        }
        // The configured limits, not the F8 maxima: 9 fields against max_fields 8.
        let hs: Vec<(&[u8], &[u8])> = (0..9).map(|_| (&b"x-a"[..], &b"v"[..])).collect();
        let tight = HeaderLimits { max_fields: 8, max_list_size: 16_384 };
        assert!(decode_w2s(&resp_head(1, 200, &hs[..8]), &tight).is_some());
        assert_eq!(decode_w2s(&resp_head(1, 200, &hs), &tight), None);
        let small = HeaderLimits { max_fields: 128, max_list_size: 40 };
        assert_eq!(decode_w2s(&resp_head(1, 200, &[(b"x-a", b"0123456")]), &small), None);
    }

    #[test]
    fn decoder_is_total() {
        assert_eq!(decode_w2s(&[], &LIM), None);
        assert_eq!(decode_w2s(&[99, 0], &LIM), None); // unknown tag
        assert_eq!(decode_w2s(&[19, 1, 0, 0, 7, 0], &LIM), None); // trailing byte
        assert_eq!(decode_w2s(&[19, 1, 1, 9, 0], &LIM), None); // trap out of range
        assert_eq!(decode_w2s(&[21, 1, 5, 0], &LIM), None); // log level out of range
        assert_eq!(decode_w2s(&[18, 1, 5, 1], &LIM), None); // truncated chunk
        assert_eq!(decode_w2s(&[16, 0, 2, 0], &LIM), None); // wrong api version
        assert_eq!(decode_w2s(&[16, 0, 1, 1, 0], &LIM), None); // digest of the wrong size
        assert_eq!(decode_w2s(&[0xff; 12], &LIM), None); // overlong varint
        assert_eq!(decode_w2s(&vec![18; FRAME_MAX + 1], &LIM), None); // oversized
        // Every prefix of a valid frame is refused, never a panic.
        let ok = resp_head(3, 200, &[(b"x-a", b"v")]);
        for i in 0..ok.len() {
            assert_eq!(decode_w2s(&ok[..i], &LIM), None);
        }
    }
}
