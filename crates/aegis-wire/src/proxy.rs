//! PROXY protocol v2 header parser (F1 PROXY-1..3; haproxy proxy-protocol.txt §2.2).
//!
//! The receiver rules are `oracles/proxy-l4/README.md` "PROXY v2 acceptance rules" (the oracle is the contract):
//! - v1 (`PROXY ...`, or any prefix of it) is refused, never parsed (PROXY-3);
//! - version nibble 2, command LOCAL or PROXY, family <= UNIX, protocol <= DGRAM, else refused;
//! - a declared length over [`MAX_DECLARED_LEN`] is refused as soon as the 16-byte fixed part is in, without waiting
//!   for the body (PROXY-3);
//! - consumed = exactly 16 + declared length; bytes after it are never looked at;
//! - LOCAL, and PROXY with an UNSPEC family or protocol: accepted, the block (addresses and TLVs) is skipped unparsed;
//! - PROXY with INET/INET6/UNIX: the block must hold the address (12/36/216 bytes), and the TLVs after it must tile the
//!   rest exactly, with CRC32C (len 4, at most once, must match), UNIQUE_ID (<= 128), AUTHORITY (UTF-8) and SSL (>= 5
//!   bytes, sub-TLVs tile) checked; every other type is bounded and ignored.
//!
//! DGRAM headers parse; refusing them on a stream listener is policy in aegis-bin ([`Header::stream_accept`]). Trust
//! (PROXY-1: only from configured source CIDRs) is decided by the caller on the TCP peer, never here.
//!
//! No allocation; every borrowed field is a sub-slice of the declared header.

use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::rd::Rd;

/// The 12-byte v2 signature (proxy-protocol.txt §2.2).
pub const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";

/// The largest declared address+TLV length accepted (F1 PROXY-3); anything larger closes the connection.
pub const MAX_DECLARED_LEN: usize = 536;

/// The fixed part of a v2 header: signature, version/command, family/protocol, length.
pub const FIXED_LEN: usize = 16;

/// The largest number of bytes [`parse_v2`] ever consumes.
pub const MAX_HEADER_LEN: usize = FIXED_LEN + MAX_DECLARED_LEN;

/// TLV type codes (proxy-protocol.txt §2.2.1..2.2.8).
pub mod tlv {
    pub const ALPN: u8 = 0x01;
    pub const AUTHORITY: u8 = 0x02;
    pub const CRC32C: u8 = 0x03;
    pub const NOOP: u8 = 0x04;
    pub const UNIQUE_ID: u8 = 0x05;
    pub const SSL: u8 = 0x20;
    pub const NETNS: u8 = 0x30;
}

const V1_PREFIX: &[u8; 5] = b"PROXY";
const INET_LEN: usize = 12;
const INET6_LEN: usize = 36;
const UNIX_LEN: usize = 216;
const UNIX_PATH: usize = 108;
const UNIQUE_ID_MAX: usize = 128;
const SSL_FIXED: usize = 5;

/// The v2 command nibble.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// LOCAL: the connection was made by the proxy itself (health check); the real peer address is kept.
    Local,
    /// PROXY: the addresses below are the original client's.
    Proxy,
}

/// The address family nibble.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Unspec,
    Inet,
    Inet6,
    Unix,
}

/// The transport protocol nibble.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Unspec,
    Stream,
    Dgram,
}

/// The address block of a v2 header, as parsed. LOCAL and UNSPEC headers carry [`Addresses::Unspec`] whatever their
/// block held (the block is discarded unparsed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Addresses<'a> {
    /// No address used: LOCAL, or an UNSPEC family or protocol.
    Unspec,
    /// TCP or UDP over IPv4 / IPv6.
    Inet { src: SocketAddr, dst: SocketAddr },
    /// AF_UNIX: the two raw 108-byte path fields (NUL padded). Not used for admission.
    Unix { src: &'a [u8], dst: &'a [u8] },
}

/// A parsed v2 header. TLVs stay in the input; the parser validates them and [`Header::tlvs`] walks them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header<'a> {
    pub command: Command,
    pub family: Family,
    pub transport: Transport,
    pub addresses: Addresses<'a>,
    /// The validated TLV region (empty unless PROXY with a concrete family and protocol).
    tlvs: &'a [u8],
}

impl<'a> Header<'a> {
    /// The peer address admission and audit must use instead of the TCP peer: `Some` only for a PROXY command over
    /// TCP4/TCP6 (README rule 8). `None` means "use the TCP peer" (LOCAL, UNSPEC, UNIX, DGRAM).
    pub fn source(&self) -> Option<SocketAddr> {
        match (self.command, self.transport, self.addresses) {
            (Command::Proxy, Transport::Stream, Addresses::Inet { src, .. }) => Some(src),
            _ => None,
        }
    }

    /// False when the header announces a datagram flow with addresses (PROXY + DGRAM over INET/INET6/UNIX), which a
    /// stream listener refuses by policy.
    pub fn stream_accept(&self) -> bool {
        !(self.command == Command::Proxy && self.family != Family::Unspec && self.transport == Transport::Dgram)
    }

    /// The top-level TLVs after the address block, in order.
    pub fn tlvs(&self) -> Tlvs<'a> {
        walk(self.tlvs)
    }
}

/// One TLV.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub kind: u8,
    pub value: &'a [u8],
}

/// Iterator over a validated TLV region (see [`Header::tlvs`]).
#[derive(Clone, Copy, Debug)]
pub struct Tlvs<'a> {
    rd: Rd<'a>,
}

impl<'a> Iterator for Tlvs<'a> {
    type Item = Tlv<'a>;

    fn next(&mut self) -> Option<Tlv<'a>> {
        let kind = self.rd.u8()?;
        let value = self.rd.vec16()?;
        Some(Tlv { kind, value })
    }
}

/// Why a header was not accepted. Every variant except [`ProxyError::Incomplete`] closes the connection (F1 PROXY-1,
/// PROXY-3); `Incomplete` means "read more, within the deadline" and becomes a close at EOF or the deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyError {
    /// Fewer bytes than the header declares (or than the fixed part).
    Incomplete,
    /// A v1 (text) header, or a prefix of one: refused, never parsed.
    V1Refused,
    /// Declared length over [`MAX_DECLARED_LEN`].
    TooLong,
    /// Anything else that is not a well-formed v2 header.
    Malformed,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ProxyError::Incomplete => "PROXY v2 header incomplete",
            ProxyError::V1Refused => "PROXY v1 header refused",
            ProxyError::TooLong => "PROXY v2 declared length over 536",
            ProxyError::Malformed => "malformed PROXY v2 header",
        })
    }
}

/// True if `input` could begin a PROXY header (a non-empty prefix of the v2 signature or of `PROXY`). A listener uses
/// it on an untrusted source to refuse a header it will not parse (README rule 1).
pub fn looks_like_proxy(input: &[u8]) -> bool {
    let k = input.len().min(SIGNATURE.len());
    let m = input.len().min(V1_PREFIX.len());
    k > 0 && (input.get(..k) == SIGNATURE.get(..k) || input.get(..m) == V1_PREFIX.get(..m))
}

/// Parse one v2 header at the start of `input`. On success, returns the header and the number of bytes it occupies
/// (`16 + declared length`, never more than `input.len()` or [`MAX_HEADER_LEN`]). Bytes after that are not read.
pub fn parse_v2(input: &[u8]) -> Result<(Header<'_>, usize), ProxyError> {
    let k = input.len().min(SIGNATURE.len());
    if input.get(..k) != SIGNATURE.get(..k) {
        let m = input.len().min(V1_PREFIX.len());
        if m > 0 && input.get(..m) == V1_PREFIX.get(..m) {
            return Err(ProxyError::V1Refused);
        }
        return Err(ProxyError::Malformed);
    }
    let mut fixed = match input.get(..FIXED_LEN) {
        Some(f) => Rd::new(f),
        None => return Err(ProxyError::Incomplete),
    };
    fixed.take(SIGNATURE.len()).ok_or(ProxyError::Incomplete)?;
    let vc = fixed.u8().ok_or(ProxyError::Incomplete)?;
    let fp = fixed.u8().ok_or(ProxyError::Incomplete)?;
    let n = usize::from(fixed.u16().ok_or(ProxyError::Incomplete)?);
    if vc >> 4 != 2 {
        return Err(ProxyError::Malformed);
    }
    let command = match vc & 0x0f {
        0 => Command::Local,
        1 => Command::Proxy,
        _ => return Err(ProxyError::Malformed),
    };
    let family = match fp >> 4 {
        0 => Family::Unspec,
        1 => Family::Inet,
        2 => Family::Inet6,
        3 => Family::Unix,
        _ => return Err(ProxyError::Malformed),
    };
    let transport = match fp & 0x0f {
        0 => Transport::Unspec,
        1 => Transport::Stream,
        2 => Transport::Dgram,
        _ => return Err(ProxyError::Malformed),
    };
    if n > MAX_DECLARED_LEN {
        return Err(ProxyError::TooLong);
    }
    let consumed = FIXED_LEN + n;
    let hdr = input.get(..consumed).ok_or(ProxyError::Incomplete)?;
    let block = hdr.get(FIXED_LEN..).ok_or(ProxyError::Incomplete)?;
    let skipped = Header { command, family, transport, addresses: Addresses::Unspec, tlvs: &[] };
    if command == Command::Local || family == Family::Unspec || transport == Transport::Unspec {
        // LOCAL: "discard the protocol block including the family"; UNSPEC: address information ignored.
        return Ok((skipped, consumed));
    }
    let mut rd = Rd::new(block);
    let addresses = match family {
        Family::Inet => {
            let a = rd.take(INET_LEN).ok_or(ProxyError::Malformed)?;
            let mut a = Rd::new(a);
            let src = v4(a.take(4))?;
            let dst = v4(a.take(4))?;
            let sp = a.u16().ok_or(ProxyError::Malformed)?;
            let dp = a.u16().ok_or(ProxyError::Malformed)?;
            Addresses::Inet { src: SocketAddr::new(src.into(), sp), dst: SocketAddr::new(dst.into(), dp) }
        }
        Family::Inet6 => {
            let a = rd.take(INET6_LEN).ok_or(ProxyError::Malformed)?;
            let mut a = Rd::new(a);
            let src = v6(a.take(16))?;
            let dst = v6(a.take(16))?;
            let sp = a.u16().ok_or(ProxyError::Malformed)?;
            let dp = a.u16().ok_or(ProxyError::Malformed)?;
            Addresses::Inet { src: SocketAddr::new(src.into(), sp), dst: SocketAddr::new(dst.into(), dp) }
        }
        Family::Unix => {
            let a = rd.take(UNIX_LEN).ok_or(ProxyError::Malformed)?;
            let (src, dst) = a.split_at_checked(UNIX_PATH).ok_or(ProxyError::Malformed)?;
            Addresses::Unix { src, dst }
        }
        Family::Unspec => return Ok((skipped, consumed)),
    };
    let region = rd.rest();
    let tlv_start = consumed - region.len();
    check_tlvs(hdr, tlv_start, region)?;
    Ok((Header { command, family, transport, addresses, tlvs: region }, consumed))
}

fn v4(b: Option<&[u8]>) -> Result<Ipv4Addr, ProxyError> {
    let a: [u8; 4] = b.and_then(|b| b.try_into().ok()).ok_or(ProxyError::Malformed)?;
    Ok(Ipv4Addr::from(a))
}

fn v6(b: Option<&[u8]>) -> Result<Ipv6Addr, ProxyError> {
    let a: [u8; 16] = b.and_then(|b| b.try_into().ok()).ok_or(ProxyError::Malformed)?;
    Ok(Ipv6Addr::from(a))
}

/// The TLV iterator over a region [`check_tlvs`] accepted.
pub(crate) fn walk(region: &[u8]) -> Tlvs<'_> {
    Tlvs { rd: Rd::new(region) }
}

/// Where the TLV walk is: about to read a type byte, the two length bytes, or `left` value bytes of `kind`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Type,
    Len1(u8),
    Len2(u8, u8),
    Value { kind: u8, left: usize },
}

/// Where the SSL sub-TLV walk is, after the 5-byte fixed part.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sub {
    Type,
    Len1,
    Len2(u8),
    Value(usize),
}

impl Sub {
    fn step(self, b: u8) -> Sub {
        match self {
            Sub::Type => Sub::Len1,
            Sub::Len1 => Sub::Len2(b),
            Sub::Len2(hi) => match usize::from(u16::from_be_bytes([hi, b])) {
                0 => Sub::Type,
                n => Sub::Value(n),
            },
            Sub::Value(1) => Sub::Type,
            Sub::Value(left) => Sub::Value(left.saturating_sub(1)),
        }
    }
}

/// An incremental well-formed-UTF-8 check (Unicode Table 3-7): `need` continuation bytes still due, the next one in
/// `lo..=hi`. The same acceptance as `core::str::from_utf8` (checked exhaustively in the tests).
#[derive(Clone, Copy, PartialEq, Eq)]
struct Utf8 {
    need: u8,
    lo: u8,
    hi: u8,
}

impl Utf8 {
    const START: Utf8 = Utf8 { need: 0, lo: 0x80, hi: 0xBF };

    /// Feed one byte; `None` if the sequence is ill-formed.
    fn step(self, b: u8) -> Option<Utf8> {
        if self.need > 0 {
            if b < self.lo || b > self.hi {
                return None;
            }
            return Some(Utf8 { need: self.need - 1, lo: 0x80, hi: 0xBF });
        }
        let (need, lo, hi) = match b {
            0x00..=0x7F => return Some(Utf8::START),
            0xC2..=0xDF => (1, 0x80, 0xBF),
            0xE0 => (2, 0xA0, 0xBF),
            0xE1..=0xEC | 0xEE..=0xEF => (2, 0x80, 0xBF),
            0xED => (2, 0x80, 0x9F),
            0xF0 => (3, 0x90, 0xBF),
            0xF1..=0xF3 => (3, 0x80, 0xBF),
            0xF4 => (3, 0x80, 0x8F),
            _ => return None,
        };
        Some(Utf8 { need, lo, hi })
    }
}

/// Well-formed UTF-8, one byte at a time (see [`Utf8`]): the tests run the DFA through this against `core::str`.
#[cfg(test)]
fn valid_utf8(b: &[u8]) -> bool {
    let mut u = Utf8::START;
    for &c in b {
        match u.step(c) {
            Some(n) => u = n,
            None => return false,
        }
    }
    u.need == 0
}

/// Validate the TLV region `region`, which starts at byte `start` of the declared header `hdr` (README rule 9).
///
/// One flat pass over the region, a byte at a time, with no nested loop: the TLV framing, the AUTHORITY UTF-8 check
/// and the SSL sub-TLV framing are state machines fed the same byte. The trip count is the region length, which
/// keeps Kani's unwinding linear. The CRC32C, when present, is checked after the pass (one more pass over `hdr`).
pub(crate) fn check_tlvs(hdr: &[u8], start: usize, region: &[u8]) -> Result<(), ProxyError> {
    const M: ProxyError = ProxyError::Malformed;
    let mut st = Field::Type;
    let mut crc: Option<(usize, [u8; 4])> = None;
    let mut utf8 = Utf8::START;
    let mut ssl_fixed = 0usize;
    let mut sub = Sub::Type;
    for (i, &b) in region.iter().enumerate() {
        st = match st {
            Field::Type => Field::Len1(b),
            Field::Len1(kind) => Field::Len2(kind, b),
            Field::Len2(kind, hi) => {
                let n = usize::from(u16::from_be_bytes([hi, b]));
                match kind {
                    tlv::CRC32C => {
                        if n != 4 || crc.is_some() {
                            return Err(M);
                        }
                        crc = Some((start + i + 1, [0; 4]));
                    }
                    tlv::UNIQUE_ID if n > UNIQUE_ID_MAX => return Err(M),
                    tlv::AUTHORITY => utf8 = Utf8::START,
                    tlv::SSL => {
                        if n < SSL_FIXED {
                            return Err(M);
                        }
                        ssl_fixed = SSL_FIXED;
                        sub = Sub::Type;
                    }
                    _ => {}
                }
                // An empty value closes at once (only AUTHORITY can be empty among the checked kinds; it is valid).
                if n == 0 { Field::Type } else { Field::Value { kind, left: n } }
            }
            Field::Value { kind, left } => {
                match kind {
                    tlv::CRC32C => {
                        if let Some((at, v)) = crc.as_mut() {
                            let k = (start + i).wrapping_sub(*at);
                            if let Some(slot) = v.get_mut(k) {
                                *slot = b;
                            }
                        }
                    }
                    tlv::AUTHORITY => utf8 = utf8.step(b).ok_or(M)?,
                    tlv::SSL => {
                        if ssl_fixed > 0 {
                            ssl_fixed -= 1;
                        } else {
                            sub = sub.step(b);
                        }
                    }
                    _ => {}
                }
                if left > 1 {
                    Field::Value { kind, left: left - 1 }
                } else {
                    // The value is complete: its inner framing must be complete too.
                    if kind == tlv::AUTHORITY && utf8.need != 0 {
                        return Err(M);
                    }
                    if kind == tlv::SSL && (ssl_fixed != 0 || sub != Sub::Type) {
                        return Err(M);
                    }
                    Field::Type
                }
            }
        };
    }
    if st != Field::Type {
        return Err(M); // a TLV header or value runs past the declared length
    }
    if let Some((at, want)) = crc
        && crc32c_zeroed(hdr, at) != Some(u32::from_be_bytes(want))
    {
        return Err(M);
    }
    Ok(())
}

/// CRC32c (Castagnoli, RFC 4960 App. B) of `hdr` with the four bytes at `at` taken as zero. `None` if they do not fit.
///
/// One pass over the whole header, zeroing by position: the trip count is the header length (fixed once the declared
/// length is read), not the symbolic split point, which keeps Kani's unwinding linear.
fn crc32c_zeroed(hdr: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    if end > hdr.len() {
        return None;
    }
    let mut c = 0xFFFF_FFFFu32;
    for (i, &b) in hdr.iter().enumerate() {
        c = crc32c_byte(c, if i >= at && i < end { 0 } else { b });
    }
    Some(c ^ 0xFFFF_FFFF)
}

fn crc32c_byte(mut c: u32, b: u8) -> u32 {
    c ^= u32::from(b);
    for _ in 0..8 {
        c = if c & 1 == 1 { (c >> 1) ^ 0x82F6_3B78 } else { c >> 1 };
    }
    c
}

#[cfg(test)]
mod tests {
    use super::valid_utf8;

    /// Same verdict as `core::str::from_utf8` on every 1-, 2- and 3-byte input, and on every 4-byte input whose last
    /// two bytes come from a boundary set (ASCII, continuation-range edges, lead bytes, non-UTF-8 bytes).
    #[test]
    fn valid_utf8_matches_core() {
        let same = |b: &[u8]| assert_eq!(valid_utf8(b), core::str::from_utf8(b).is_ok(), "{b:02x?}");
        for a in 0..=255u8 {
            same(&[a]);
            for b in 0..=255u8 {
                same(&[a, b]);
                for c in 0..=255u8 {
                    same(&[a, b, c]);
                }
            }
        }
        let edge =
            [0x00, 0x41, 0x7F, 0x80, 0x8F, 0x90, 0x9F, 0xA0, 0xBF, 0xC0, 0xC2, 0xE0, 0xED, 0xF0, 0xF4, 0xF5, 0xFF];
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                for c in edge {
                    for d in edge {
                        same(&[a, b, c, d]);
                    }
                }
            }
        }
    }

    #[test]
    fn crc32c_check_value() {
        // RFC 3720 / iSCSI check value.
        let c = b"123456789".iter().fold(0xFFFF_FFFF, |c, &b| super::crc32c_byte(c, b));
        assert_eq!(c ^ 0xFFFF_FFFF, 0xE306_9283);
        // The zeroed form: the check value with four zero bytes spliced in, against a plain pass over the same bytes.
        let spliced = [b"1234".as_slice(), &[0; 4], b"789"].concat();
        let plain = spliced.iter().fold(0xFFFF_FFFF, |c, &b| super::crc32c_byte(c, b)) ^ 0xFFFF_FFFF;
        assert_eq!(super::crc32c_zeroed(b"1234WXYZ789", 4), Some(plain));
        assert_eq!(super::crc32c_zeroed(b"1234WXY", 4), None);
    }
}
