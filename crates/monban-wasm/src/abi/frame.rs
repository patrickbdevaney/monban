//! F14 Part 2 worker <-> supervisor frames in the F10 encoding rule (postcard positional: unsigned LEB128 varints,
//! length-prefixed bstr/tstr and arrays, a choice as a varint discriminant, bool one byte 0/1, option 0 | 1 value).
//!
//! Decoders are total: every function returns `None` on malformed input (truncation, overlong varint, trailing
//! bytes, unknown tag, req-id 0, invalid UTF-8 in a tstr, a bool other than 0/1). Encoders build exactly one frame.
#![forbid(unsafe_code)]

/// F8 `p2.frame_max_bytes` default (64 KiB): the frame cap of a worker started without another value.
pub const FRAME_MAX_DEFAULT: usize = 64 << 10;
/// F8 `p2.frame_max_bytes` minimum.
pub const FRAME_MAX_MIN: usize = 4 << 10;
/// F8 `p2.frame_max_bytes` maximum.
pub const FRAME_MAX_MAX: usize = 1 << 20;

/// Frame tags (F14 Part 2).
pub mod tag {
    /// s2w `request`.
    pub const REQUEST: u64 = 0;
    /// s2w `body-chunk`.
    pub const BODY_CHUNK: u64 = 1;
    /// s2w `data-reply`.
    pub const DATA_REPLY: u64 = 2;
    /// s2w `cancel`.
    pub const CANCEL: u64 = 3;
    /// w2s `ready`.
    pub const READY: u64 = 16;
    /// w2s `resp-head`.
    pub const RESP_HEAD: u64 = 17;
    /// w2s `resp-body`.
    pub const RESP_BODY: u64 = 18;
    /// w2s `resp-end`.
    pub const RESP_END: u64 = 19;
    /// w2s `data-run`.
    pub const DATA_RUN: u64 = 20;
    /// w2s `log`.
    pub const LOG: u64 = 21;
    /// w2s `layout` (test-hooks builds only, D8).
    pub const LAYOUT: u64 = 22;
}

/// Writer for one frame.
#[derive(Debug, Default)]
pub(crate) struct Enc(Vec<u8>);

impl Enc {
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }
    pub(crate) fn u(mut self, mut n: u64) -> Self {
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
    pub(crate) fn bytes(self, b: &[u8]) -> Self {
        let mut s = self.u(u64::try_from(b.len()).unwrap_or(u64::MAX));
        s.0.extend_from_slice(b);
        s
    }
    pub(crate) fn raw(mut self, b: &[u8]) -> Self {
        self.0.extend_from_slice(b);
        self
    }
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
    pub(crate) fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// Total reader over one frame.
#[derive(Debug)]
pub(crate) struct Dec<'a> {
    b: &'a [u8],
}

impl<'a> Dec<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Self { b }
    }
    pub(crate) fn u(&mut self) -> Option<u64> {
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
    pub(crate) fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = usize::try_from(self.u()?).ok()?;
        if n > self.b.len() {
            return None;
        }
        let (s, rest) = self.b.split_at(n);
        self.b = rest;
        Some(s)
    }
    pub(crate) fn text(&mut self) -> Option<&'a str> {
        std::str::from_utf8(self.bytes()?).ok()
    }
    pub(crate) fn boolean(&mut self) -> Option<bool> {
        let (&x, rest) = self.b.split_first()?;
        self.b = rest;
        match x {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.b)
    }
    pub(crate) fn remaining(&self) -> usize {
        self.b.len()
    }
    pub(crate) fn done(&self) -> bool {
        self.b.is_empty()
    }
}

/// A list length that cannot exceed the bytes left (every element takes at least one byte).
fn bounded(n: u64, d: &Dec<'_>) -> Option<u64> {
    (n <= u64::try_from(d.remaining()).unwrap_or(0)).then_some(n)
}

/// The eight per-request limits of a `request` frame, as sent (before the worker's ceilings apply).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireLimits {
    /// Fuel units.
    pub fuel: u64,
    /// Wall bound in ms.
    pub wall_ms: u64,
    /// Linear-memory cap in MiB.
    pub memory_mib: u64,
    /// Host calls of every kind.
    pub max_host_calls: u64,
    /// `data_run` calls (also the handle-table size).
    pub max_data_runs: u64,
    /// Summed encoded size of `data_run` ops and replies.
    pub max_data_bytes: u64,
    /// Response body bytes.
    pub max_resp_bytes: u64,
    /// Log bytes.
    pub max_log_bytes: u64,
}

impl WireLimits {
    /// The F8 `p2` defaults.
    pub const F8_DEFAULT: Self = Self {
        fuel: 15_000_000,
        wall_ms: 100,
        memory_mib: 16,
        max_host_calls: 10_000,
        max_data_runs: 64,
        max_data_bytes: 4_194_304,
        max_resp_bytes: 1_048_576,
        max_log_bytes: 65_536,
    };

    /// The F8 `p2` maxima: the worker's boot ceilings for the five quotas.
    pub const F8_MAX: Self = Self {
        fuel: 1_000_000_000,
        wall_ms: 1_000,
        memory_mib: 256,
        max_host_calls: 1_000_000,
        max_data_runs: 1_024,
        max_data_bytes: 67_108_864,
        max_resp_bytes: 16_777_216,
        max_log_bytes: 1_048_576,
    };

    fn decode(d: &mut Dec<'_>) -> Option<Self> {
        Some(Self {
            fuel: d.u()?,
            wall_ms: d.u()?,
            memory_mib: d.u()?,
            max_host_calls: d.u()?,
            max_data_runs: d.u()?,
            max_data_bytes: d.u()?,
            max_resp_bytes: d.u()?,
            max_log_bytes: d.u()?,
        })
    }
}

/// One decoded supervisor -> worker frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inbound<'a> {
    /// `[0, req-id, limits, req-head]`; `head` is the validated req-head encoding, verbatim.
    Request {
        /// req-id (never 0).
        rid: u64,
        /// Limits as sent.
        limits: WireLimits,
        /// The req-head bytes.
        head: &'a [u8],
    },
    /// `[1, req-id, chunk, last]`.
    BodyChunk {
        /// req-id.
        rid: u64,
        /// Body bytes.
        chunk: &'a [u8],
        /// Last chunk.
        last: bool,
    },
    /// `[2, req-id, seq, result]`; `result` is the F10 `result` encoding, verbatim (never empty).
    DataReply {
        /// req-id.
        rid: u64,
        /// The data-run's seq.
        seq: u64,
        /// The F10 result bytes.
        result: &'a [u8],
    },
    /// `[3, req-id]`.
    Cancel {
        /// req-id.
        rid: u64,
    },
}

/// Validates an F14 `req-head` encoding (method, path, query, allowlisted headers, body-len): the whole slice.
pub fn check_req_head(b: &[u8]) -> bool {
    let mut d = Dec::new(b);
    req_head(&mut d).is_some() && d.done()
}

fn req_head(d: &mut Dec<'_>) -> Option<()> {
    d.text()?; // method
    d.text()?; // path
    match d.u()? {
        0 => {
            d.bytes()?;
        }
        1 => {
            let n = bounded(d.u()?, d)?;
            for _ in 0..n {
                d.text()?;
                d.text()?;
            }
        }
        _ => return None,
    }
    let n = bounded(d.u()?, d)?;
    for _ in 0..n {
        d.text()?;
        d.bytes()?;
    }
    match d.u()? {
        0 => {}
        1 => {
            d.u()?;
        }
        _ => return None,
    }
    Some(())
}

fn rid(d: &mut Dec<'_>) -> Option<u64> {
    let r = d.u()?;
    (r != 0).then_some(r)
}

/// Decodes one supervisor -> worker frame completely.
pub fn decode_s2w(frame: &[u8]) -> Option<Inbound<'_>> {
    let mut d = Dec::new(frame);
    let t = d.u()?;
    let r = rid(&mut d)?;
    let v = match t {
        tag::REQUEST => {
            let limits = WireLimits::decode(&mut d)?;
            let head = d.rest();
            if !check_req_head(head) {
                return None;
            }
            Inbound::Request { rid: r, limits, head }
        }
        tag::BODY_CHUNK => {
            let chunk = d.bytes()?;
            let last = d.boolean()?;
            Inbound::BodyChunk { rid: r, chunk, last }
        }
        tag::DATA_REPLY => {
            let seq = d.u()?;
            let result = d.rest();
            if result.is_empty() {
                return None;
            }
            Inbound::DataReply { rid: r, seq, result }
        }
        tag::CANCEL => Inbound::Cancel { rid: r },
        _ => return None,
    };
    d.done().then_some(v)
}

/// `ready = [16, 0, guest-api-version, module-sha256]`.
pub fn ready(digest: &[u8; 32]) -> Vec<u8> {
    Enc::new().u(tag::READY).u(0).u(u64::from(super::GUEST_API_VERSION)).bytes(digest).finish()
}

/// `layout = [22, 0, load-base, pid]` (test-hooks builds only, D8).
pub fn layout(load_base: u64, pid: u64) -> Vec<u8> {
    Enc::new().u(tag::LAYOUT).u(0).u(load_base).u(pid).finish()
}

/// How a request ended (F14 `end`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// `[0, code]`: `handle()` returned this status (the i32 read as u32).
    Code(u32),
    /// `[1, trap]`: the request trapped with this F14 trap code (1..=8).
    Trap(u32),
}

/// `resp-end = [19, req-id, end, fuel-used]`.
pub fn resp_end(rid: u64, end: End, fuel_used: u64) -> Vec<u8> {
    let e = Enc::new().u(tag::RESP_END).u(rid);
    let e = match end {
        End::Code(c) => e.u(0).u(u64::from(c)),
        End::Trap(t) => e.u(1).u(u64::from(t)),
    };
    e.u(fuel_used).finish()
}
