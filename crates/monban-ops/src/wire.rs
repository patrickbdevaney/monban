//! F11 handover wire codec (`interfaces/F11-upgrade-handover.cddl`).
//!
//! Encoding: a deterministic CBOR subset (RFC 8949 §4.2.1 core deterministic encoding) implemented in-crate.
//! Only the four major types the CDDL needs are accepted: 0 (uint), 2 (bstr), 3 (tstr, UTF-8 checked) and
//! 4 (array). Every length is definite and in shortest form; indefinite lengths, tags, maps, floats, simple values,
//! non-shortest heads and trailing bytes are rejected, so every accepted frame has exactly one encoding and
//! `encode(decode(b)) == b`.
//!
//! The decoder is total (UP-7): it never panics, never indexes, never allocates more than the input length, caps
//! nesting at the depth the CDDL needs, and rejects any frame over [`MAX_FRAME`] bytes before looking at it.

use std::fmt;

/// Every frame is at most 64 KiB (F11).
pub const MAX_FRAME: usize = 64 * 1024;
/// SCM_RIGHTS carries at most 253 fds (SCM_MAX_FD); a `listeners` array is matched 1:1 to the fd array.
pub const MAX_LISTENERS: usize = 253;
/// `stek` key size (F11 `bstr .size 80`).
pub const STEK_KEY_LEN: usize = 80;
/// `stek` carries 1..=4 keys.
pub const MAX_STEK_KEYS: usize = 4;
/// `abort` reason is `tstr .size (0..256)`.
pub const MAX_ABORT_REASON: usize = 256;
/// `hello` config-hash is `bstr .size 32`.
pub const CONFIG_HASH_LEN: usize = 32;
/// The only protocol version (F11 `version: 1`).
pub const VERSION: u64 = 1;

/// Why a frame was rejected. Never carries attacker bytes beyond small integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// Frame longer than [`MAX_FRAME`].
    TooLong,
    /// Input ended inside an item.
    Truncated,
    /// Bytes left after the message.
    Trailing,
    /// A head used a longer form than necessary (non-deterministic).
    NonShortest,
    /// Indefinite length or reserved additional-info value.
    Indefinite,
    /// A major type the CDDL does not use where an item was expected.
    UnexpectedType,
    /// Unknown message tag or wrong array arity for the tag.
    BadShape,
    /// Text string not valid UTF-8.
    BadUtf8,
    /// A value outside the CDDL range (version, family, proto, sizes, counts).
    OutOfRange,
    /// The encoder was handed a message the CDDL does not allow.
    Unencodable,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::TooLong => "frame too long",
            Self::Truncated => "truncated",
            Self::Trailing => "trailing bytes",
            Self::NonShortest => "non-shortest encoding",
            Self::Indefinite => "indefinite or reserved length",
            Self::UnexpectedType => "unexpected major type",
            Self::BadShape => "bad message shape",
            Self::BadUtf8 => "invalid utf-8",
            Self::OutOfRange => "value out of range",
            Self::Unencodable => "message not encodable under F11",
        };
        f.write_str(s)
    }
}

impl std::error::Error for WireError {}

/// Listener address family (F11 `family: 0..2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// AF_INET; addr = 4 address bytes + 2 port bytes (big endian).
    Inet,
    /// AF_INET6; addr = 16 address bytes + 2 port bytes (big endian).
    Inet6,
    /// AF_UNIX; addr = path bytes.
    Unix,
}

impl Family {
    fn code(self) -> u64 {
        match self {
            Self::Inet => 0,
            Self::Inet6 => 1,
            Self::Unix => 2,
        }
    }
    fn from_code(c: u64) -> Result<Self, WireError> {
        match c {
            0 => Ok(Self::Inet),
            1 => Ok(Self::Inet6),
            2 => Ok(Self::Unix),
            _ => Err(WireError::OutOfRange),
        }
    }
}

/// Listener transport (F11 `proto: 0..1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    /// SOCK_STREAM, must be listening (SO_ACCEPTCONN).
    Tcp,
    /// SOCK_DGRAM, bound.
    Udp,
}

impl Proto {
    fn code(self) -> u64 {
        match self {
            Self::Tcp => 0,
            Self::Udp => 1,
        }
    }
    fn from_code(c: u64) -> Result<Self, WireError> {
        match c {
            0 => Ok(Self::Tcp),
            1 => Ok(Self::Udp),
            _ => Err(WireError::OutOfRange),
        }
    }
}

/// One entry of `listeners`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerDesc {
    /// Operator-visible listener name, echoed back in `ready`.
    pub name: String,
    /// Address family.
    pub family: Family,
    /// Address bytes in the family's encoding (see [`Family`]).
    pub addr: Vec<u8>,
    /// Transport.
    pub proto: Proto,
}

/// One session-ticket key. `Debug` never prints key bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct StekKey(pub [u8; STEK_KEY_LEN]);

impl fmt::Debug for StekKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StekKey(<redacted>)")
    }
}

/// An F11 message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    /// `[0, 1, child-pid, config-hash]` child → parent.
    Hello {
        /// The child's pid as it sees it; must match SO_PEERCRED.
        child_pid: u64,
        /// Hash of the child's effective configuration.
        config_hash: [u8; CONFIG_HASH_LEN],
    },
    /// `[1, [* listener]]` parent → child; order matches the fd array.
    Listeners(Vec<ListenerDesc>),
    /// `[2, epoch, [1*4 key]]` parent → child, by pipe only (UP-5).
    Stek {
        /// Key-ring epoch.
        epoch: u64,
        /// 1..=4 keys.
        keys: Vec<StekKey>,
    },
    /// `[3, [* name]]` child → parent: listeners the child claimed.
    Ready {
        /// Claimed listener names.
        claimed: Vec<String>,
    },
    /// `[4, deadline-ms]` parent → child: parent stopped accepting and drains until the deadline.
    Drain {
        /// Drain deadline in milliseconds.
        deadline_ms: u64,
    },
    /// `[5, forced-closes]` parent → child: drain finished.
    Done {
        /// Connections force-closed at the deadline (UP-4).
        forced_closes: u64,
    },
    /// `[6, reason]` either way: handover abandoned.
    Abort {
        /// Short reason, at most 256 bytes.
        reason: String,
    },
}

// ---------------------------------------------------------------- encoder

fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= 0xff {
        out.push(m | 24);
        out.push(arg as u8);
    } else if arg <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

fn uint(out: &mut Vec<u8>, v: u64) {
    head(out, 0, v);
}
fn bstr(out: &mut Vec<u8>, b: &[u8]) {
    head(out, 2, b.len() as u64);
    out.extend_from_slice(b);
}
fn tstr(out: &mut Vec<u8>, s: &str) {
    head(out, 3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}
fn array(out: &mut Vec<u8>, n: usize) {
    head(out, 4, n as u64);
}

/// Encode a message. Fails (never panics) on a message the CDDL forbids or one over [`MAX_FRAME`].
pub fn encode(msg: &Msg) -> Result<Vec<u8>, WireError> {
    let mut o = Vec::with_capacity(64);
    match msg {
        Msg::Hello { child_pid, config_hash } => {
            array(&mut o, 4);
            uint(&mut o, 0);
            uint(&mut o, VERSION);
            uint(&mut o, *child_pid);
            bstr(&mut o, config_hash);
        }
        Msg::Listeners(ls) => {
            if ls.len() > MAX_LISTENERS {
                return Err(WireError::Unencodable);
            }
            array(&mut o, 2);
            uint(&mut o, 1);
            array(&mut o, ls.len());
            for l in ls {
                array(&mut o, 4);
                tstr(&mut o, &l.name);
                uint(&mut o, l.family.code());
                bstr(&mut o, &l.addr);
                uint(&mut o, l.proto.code());
            }
        }
        Msg::Stek { epoch, keys } => {
            if keys.is_empty() || keys.len() > MAX_STEK_KEYS {
                return Err(WireError::Unencodable);
            }
            array(&mut o, 3);
            uint(&mut o, 2);
            uint(&mut o, *epoch);
            array(&mut o, keys.len());
            for k in keys {
                bstr(&mut o, &k.0);
            }
        }
        Msg::Ready { claimed } => {
            array(&mut o, 2);
            uint(&mut o, 3);
            array(&mut o, claimed.len());
            for c in claimed {
                tstr(&mut o, c);
            }
        }
        Msg::Drain { deadline_ms } => {
            array(&mut o, 2);
            uint(&mut o, 4);
            uint(&mut o, *deadline_ms);
        }
        Msg::Done { forced_closes } => {
            array(&mut o, 2);
            uint(&mut o, 5);
            uint(&mut o, *forced_closes);
        }
        Msg::Abort { reason } => {
            if reason.len() > MAX_ABORT_REASON {
                return Err(WireError::Unencodable);
            }
            array(&mut o, 2);
            uint(&mut o, 6);
            tstr(&mut o, reason);
        }
    }
    if o.len() > MAX_FRAME {
        return Err(WireError::TooLong);
    }
    Ok(o)
}

/// Truncate a reason to at most [`MAX_ABORT_REASON`] bytes on a char boundary.
pub fn clamp_reason(s: &str) -> String {
    let mut end = s.len().min(MAX_ABORT_REASON);
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).unwrap_or_default().to_string()
}

// ---------------------------------------------------------------- decoder

struct Cur<'a> {
    b: &'a [u8],
}

impl<'a> Cur<'a> {
    fn byte(&mut self) -> Result<u8, WireError> {
        let (&first, rest) = self.b.split_first().ok_or(WireError::Truncated)?;
        self.b = rest;
        Ok(first)
    }

    fn take(&mut self, n: u64) -> Result<&'a [u8], WireError> {
        let n = usize::try_from(n).map_err(|_| WireError::Truncated)?;
        if n > self.b.len() {
            return Err(WireError::Truncated);
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }

    fn be(&mut self, n: u64) -> Result<u64, WireError> {
        let bytes = self.take(n)?;
        Ok(bytes.iter().fold(0u64, |acc, &x| (acc << 8) | u64::from(x)))
    }

    /// One head: (major type, argument), rejecting non-shortest and indefinite forms.
    fn head(&mut self) -> Result<(u8, u64), WireError> {
        let ib = self.byte()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        let arg = match ai {
            0..=23 => u64::from(ai),
            24 => {
                let v = self.be(1)?;
                if v < 24 {
                    return Err(WireError::NonShortest);
                }
                v
            }
            25 => {
                let v = self.be(2)?;
                if v <= 0xff {
                    return Err(WireError::NonShortest);
                }
                v
            }
            26 => {
                let v = self.be(4)?;
                if v <= 0xffff {
                    return Err(WireError::NonShortest);
                }
                v
            }
            27 => {
                let v = self.be(8)?;
                if v <= 0xffff_ffff {
                    return Err(WireError::NonShortest);
                }
                v
            }
            _ => return Err(WireError::Indefinite),
        };
        Ok((major, arg))
    }

    fn expect(&mut self, major: u8) -> Result<u64, WireError> {
        let (m, a) = self.head()?;
        if m != major {
            return Err(WireError::UnexpectedType);
        }
        Ok(a)
    }

    fn uint(&mut self) -> Result<u64, WireError> {
        self.expect(0)
    }

    fn bytes(&mut self) -> Result<&'a [u8], WireError> {
        let n = self.expect(2)?;
        self.take(n)
    }

    fn text(&mut self) -> Result<String, WireError> {
        let n = self.expect(3)?;
        let b = self.take(n)?;
        std::str::from_utf8(b).map(str::to_owned).map_err(|_| WireError::BadUtf8)
    }

    /// Array head with its element count; the count can never exceed the remaining input (each element ≥ 1 byte),
    /// so a hostile length cannot drive an allocation.
    fn array(&mut self) -> Result<usize, WireError> {
        let n = self.expect(4)?;
        let n = usize::try_from(n).map_err(|_| WireError::Truncated)?;
        if n > self.b.len() {
            return Err(WireError::Truncated);
        }
        Ok(n)
    }
}

/// Decode one frame. Total: returns `Err` for every input that is not exactly one F11 message in deterministic
/// encoding; never panics.
pub fn decode(frame: &[u8]) -> Result<Msg, WireError> {
    if frame.len() > MAX_FRAME {
        return Err(WireError::TooLong);
    }
    let mut c = Cur { b: frame };
    let n = c.array()?;
    if n == 0 {
        return Err(WireError::BadShape);
    }
    let tag = c.uint()?;
    let msg = match (tag, n) {
        (0, 4) => {
            if c.uint()? != VERSION {
                return Err(WireError::OutOfRange);
            }
            let child_pid = c.uint()?;
            let h = c.bytes()?;
            let config_hash: [u8; CONFIG_HASH_LEN] = h.try_into().map_err(|_| WireError::OutOfRange)?;
            Msg::Hello { child_pid, config_hash }
        }
        (1, 2) => {
            let k = c.array()?;
            if k > MAX_LISTENERS {
                return Err(WireError::OutOfRange);
            }
            let mut ls = Vec::with_capacity(k);
            for _ in 0..k {
                if c.array()? != 4 {
                    return Err(WireError::BadShape);
                }
                let name = c.text()?;
                let family = Family::from_code(c.uint()?)?;
                let addr = c.bytes()?.to_vec();
                let proto = Proto::from_code(c.uint()?)?;
                ls.push(ListenerDesc { name, family, addr, proto });
            }
            Msg::Listeners(ls)
        }
        (2, 3) => {
            let epoch = c.uint()?;
            let k = c.array()?;
            if k == 0 || k > MAX_STEK_KEYS {
                return Err(WireError::OutOfRange);
            }
            let mut keys = Vec::with_capacity(k);
            for _ in 0..k {
                let b = c.bytes()?;
                let key: [u8; STEK_KEY_LEN] = b.try_into().map_err(|_| WireError::OutOfRange)?;
                keys.push(StekKey(key));
            }
            Msg::Stek { epoch, keys }
        }
        (3, 2) => {
            let k = c.array()?;
            let mut claimed = Vec::with_capacity(k);
            for _ in 0..k {
                claimed.push(c.text()?);
            }
            Msg::Ready { claimed }
        }
        (4, 2) => Msg::Drain { deadline_ms: c.uint()? },
        (5, 2) => Msg::Done { forced_closes: c.uint()? },
        (6, 2) => {
            let reason = c.text()?;
            if reason.len() > MAX_ABORT_REASON {
                return Err(WireError::OutOfRange);
            }
            Msg::Abort { reason }
        }
        _ => return Err(WireError::BadShape),
    };
    if !c.b.is_empty() {
        return Err(WireError::Trailing);
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// xorshift64*: deterministic, dependency-free.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
        fn below(&mut self, n: u64) -> u64 {
            if n == 0 { 0 } else { self.next() % n }
        }
    }

    fn samples() -> Vec<Msg> {
        vec![
            Msg::Hello { child_pid: 4242, config_hash: [7; 32] },
            Msg::Hello { child_pid: u64::MAX, config_hash: [0; 32] },
            Msg::Listeners(vec![]),
            Msg::Listeners(vec![
                ListenerDesc {
                    name: "https".into(),
                    family: Family::Inet,
                    addr: vec![127, 0, 0, 1, 1, 187],
                    proto: Proto::Tcp,
                },
                ListenerDesc { name: "quic".into(), family: Family::Inet6, addr: vec![0; 18], proto: Proto::Udp },
                ListenerDesc {
                    name: "ctl".into(),
                    family: Family::Unix,
                    addr: b"/run/x.sock".to_vec(),
                    proto: Proto::Tcp,
                },
            ]),
            Msg::Stek { epoch: 9, keys: vec![StekKey([1; 80])] },
            Msg::Stek {
                epoch: 300,
                keys: vec![StekKey([1; 80]), StekKey([2; 80]), StekKey([3; 80]), StekKey([4; 80])],
            },
            Msg::Ready { claimed: vec![] },
            Msg::Ready { claimed: vec!["https".into(), "ünï".into()] },
            Msg::Drain { deadline_ms: 30_000 },
            Msg::Done { forced_closes: 0 },
            Msg::Done { forced_closes: 70_000 },
            Msg::Abort { reason: String::new() },
            Msg::Abort { reason: "x".repeat(256) },
        ]
    }

    #[test]
    fn roundtrip_and_canonical() {
        for m in samples() {
            let b = encode(&m).unwrap_or_default();
            assert!(!b.is_empty(), "{m:?} encodes");
            assert_eq!(decode(&b), Ok(m.clone()));
        }
    }

    #[test]
    fn known_vectors() {
        // [4, 30000] = 0x82 0x04 0x19 0x75 0x30
        assert_eq!(encode(&Msg::Drain { deadline_ms: 30_000 }), Ok(vec![0x82, 0x04, 0x19, 0x75, 0x30]));
        // [6, ""] = 0x82 0x06 0x60
        assert_eq!(decode(&[0x82, 0x06, 0x60]), Ok(Msg::Abort { reason: String::new() }));
    }

    #[test]
    fn rejects_noncanonical_and_out_of_range() {
        // non-shortest uint (24 used for 4)
        assert_eq!(decode(&[0x82, 0x18, 0x04, 0x00]), Err(WireError::NonShortest));
        // indefinite array
        assert_eq!(decode(&[0x9f, 0x04, 0x00, 0xff]), Err(WireError::Indefinite));
        // trailing byte
        assert_eq!(decode(&[0x82, 0x05, 0x00, 0x00]), Err(WireError::Trailing));
        // unknown tag 7
        assert_eq!(decode(&[0x82, 0x07, 0x00]), Err(WireError::BadShape));
        // wrong version in hello
        let mut h = encode(&Msg::Hello { child_pid: 1, config_hash: [0; 32] }).unwrap_or_default();
        if let Some(v) = h.get_mut(2) {
            *v = 2;
        }
        assert_eq!(decode(&h), Err(WireError::OutOfRange));
        // abort reason 257 bytes
        let mut a = vec![0x82, 0x06, 0x79, 0x01, 0x01];
        a.extend(std::iter::repeat_n(b'a', 257));
        assert_eq!(decode(&a), Err(WireError::OutOfRange));
        assert_eq!(encode(&Msg::Abort { reason: "a".repeat(257) }), Err(WireError::Unencodable));
        // stek with 5 keys / 0 keys / short key
        assert_eq!(encode(&Msg::Stek { epoch: 0, keys: vec![] }), Err(WireError::Unencodable));
        let mut s = vec![0x83, 0x02, 0x00, 0x81, 0x58, 79];
        s.extend([0u8; 79]);
        assert_eq!(decode(&s), Err(WireError::OutOfRange));
        // family 3
        assert_eq!(decode(&[0x82, 0x01, 0x81, 0x84, 0x60, 0x03, 0x40, 0x00]), Err(WireError::OutOfRange));
        // bad utf-8
        assert_eq!(decode(&[0x82, 0x06, 0x61, 0xff]), Err(WireError::BadUtf8));
        // huge declared array length is not an allocation
        assert_eq!(decode(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), Err(WireError::Truncated));
        // over-long frame
        assert_eq!(decode(&vec![0u8; MAX_FRAME + 1]), Err(WireError::TooLong));
        // a map (major 5) is not a message
        assert_eq!(decode(&[0xa0]), Err(WireError::UnexpectedType));
    }

    #[test]
    fn clamp_reason_respects_char_boundaries() {
        let s = "é".repeat(200); // 400 bytes
        let c = clamp_reason(&s);
        assert!(c.len() <= MAX_ABORT_REASON);
        assert!(encode(&Msg::Abort { reason: c }).is_ok());
    }

    /// Fuzz-style totality: 150k random byte strings plus 150k mutations of valid frames. The decoder must return
    /// (never panic), and anything it accepts must re-encode to the identical bytes (determinism).
    #[test]
    fn random_bytes_never_panic() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut accepted = 0u64;
        for _ in 0..150_000 {
            let len = rng.below(600) as usize;
            let mut b = Vec::with_capacity(len);
            // Bias the first byte toward small arrays so the decoder gets past the first head often.
            for i in 0..len {
                let x = rng.next() as u8;
                b.push(if i == 0 && rng.below(2) == 0 { 0x80 | (x & 0x07) } else { x });
            }
            if let Ok(m) = decode(&b) {
                accepted += 1;
                assert_eq!(encode(&m).ok().as_deref(), Some(b.as_slice()));
            }
        }
        let valid: Vec<Vec<u8>> = samples().iter().filter_map(|m| encode(m).ok()).collect();
        for _ in 0..150_000 {
            let Some(base) = valid.get(rng.below(valid.len() as u64) as usize) else { continue };
            let mut b = base.clone();
            match rng.below(4) {
                0 => {
                    let i = rng.below(b.len() as u64) as usize;
                    if let Some(x) = b.get_mut(i) {
                        *x ^= 1 << rng.below(8);
                    }
                }
                1 => b.truncate(rng.below(b.len() as u64) as usize),
                2 => b.push(rng.next() as u8),
                _ => {
                    let i = rng.below(b.len() as u64) as usize;
                    if let Some(x) = b.get_mut(i) {
                        *x = rng.next() as u8;
                    }
                }
            }
            if let Ok(m) = decode(&b) {
                accepted += 1;
                assert_eq!(encode(&m).ok().as_deref(), Some(b.as_slice()));
            }
        }
        // Sanity: the mutation pass does reach the accept path sometimes (bit flips inside payload bytes).
        assert!(accepted > 0);
    }
}
