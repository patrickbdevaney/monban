//! Bounded TLS ClientHello peek (F1 L4-1; the `trust_anchors` input of SEL-1, PREFLIGHT D-P7.4).
//!
//! The rules are `oracles/proxy-l4/README.md` "ClientHello peek rules" (the oracle is the contract):
//! - the first record is a handshake record (0x16), record version 0x0301..0x0303, length 1..[`MAX_RECORD`];
//! - that one record holds exactly one complete ClientHello (handshake type 1): a hello continuing into a second
//!   record, or bytes after the hello inside its record, is refused (L4-1: at most one record);
//! - the hello body: legacy_version, random, session_id <= 32, cipher_suites even and non-empty, compression
//!   non-empty, then either nothing or an extensions block that exactly fills the rest;
//! - extensions: no duplicate type; server_name is exactly one host_name entry holding an LDH DNS name; ALPN,
//!   supported_versions, signature_algorithms, supported_groups and trust_anchors (codepoint [`EXT_TRUST_ANCHORS`],
//!   draft-ietf-tls-trust-anchor-ids-07 §5.1) must be well formed; other types are bounded and ignored.
//!
//! consumed = 5 + record length; records after the first are not read. No allocation: every field borrows from the
//! input, and the duplicate check uses a fixed 8 KiB bitmap on the stack (linear in the number of extensions).

use core::fmt;

use crate::rd::Rd;

/// The largest TLS record body the peek reads (F1 L4-1: at most one ClientHello record, <= 16 KiB).
pub const MAX_RECORD: usize = 16 * 1024;

/// The TLS record header length.
pub const RECORD_HEADER: usize = 5;

/// Extension codepoints the peek reads.
pub const EXT_SERVER_NAME: u16 = 0;
pub const EXT_SUPPORTED_GROUPS: u16 = 10;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
pub const EXT_ALPN: u16 = 16;
pub const EXT_SUPPORTED_VERSIONS: u16 = 43;
/// trust_anchors: IANA has not assigned the codepoint (2026-11-06); 0xCA34 is the deployed experimental one
/// (BoringSSL `TLSEXT_TYPE_trust_anchors`, Chrome's MTC experiment). Any other codepoint is an unknown extension.
pub const EXT_TRUST_ANCHORS: u16 = 0xCA34;

const CONTENT_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const RANDOM_LEN: usize = 32;
const SESSION_ID_MAX: usize = 32;
const HOST_MAX: usize = 253;
const LABEL_MAX: usize = 63;
const TRUST_ANCHOR_ID_MAX: usize = 32;

/// What the peek extracts. Each field borrows the validated list body from the input (no allocation); an absent
/// extension is `None`. The iterator methods walk the lists (empty when absent).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peek<'a> {
    /// server_name: the host_name bytes of the single name entry (an LDH DNS name, case as sent).
    pub sni: Option<&'a [u8]>,
    /// application_layer_protocol_negotiation: the ProtocolNameList body (non-empty, every name non-empty).
    pub alpn: Option<&'a [u8]>,
    /// supported_versions: the version list body (even length, >= 2).
    pub versions: Option<&'a [u8]>,
    /// signature_algorithms: the SignatureSchemeList body (even length, >= 2).
    pub sigalgs: Option<&'a [u8]>,
    /// supported_groups: the NamedGroupList body (even length, >= 2).
    pub groups: Option<&'a [u8]>,
    /// trust_anchors (draft-ietf-tls-trust-anchor-ids-07): the RequestedTrustAnchorList body (may be empty; every
    /// TrustAnchorID 1..32 bytes).
    pub trust_anchors: Option<&'a [u8]>,
    /// Bytes the ClientHello record occupies: 5 + record length. Never more than the input or 5 + [`MAX_RECORD`].
    pub consumed: usize,
}

impl<'a> Peek<'a> {
    /// The ALPN protocol names, in order.
    pub fn alpn_protocols(&self) -> Vec8List<'a> {
        Vec8List { rd: Rd::new(self.alpn.unwrap_or(&[])) }
    }

    /// The supported_versions entries, in order.
    pub fn version_list(&self) -> U16List<'a> {
        U16List { rd: Rd::new(self.versions.unwrap_or(&[])) }
    }

    /// The signature_algorithms entries, in order.
    pub fn sigalg_list(&self) -> U16List<'a> {
        U16List { rd: Rd::new(self.sigalgs.unwrap_or(&[])) }
    }

    /// The supported_groups entries, in order.
    pub fn group_list(&self) -> U16List<'a> {
        U16List { rd: Rd::new(self.groups.unwrap_or(&[])) }
    }

    /// The requested TrustAnchorIDs, in order.
    pub fn trust_anchor_ids(&self) -> Vec8List<'a> {
        Vec8List { rd: Rd::new(self.trust_anchors.unwrap_or(&[])) }
    }
}

/// Iterator over a validated list of big-endian u16 values.
#[derive(Clone, Copy, Debug)]
pub struct U16List<'a> {
    rd: Rd<'a>,
}

impl Iterator for U16List<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<u16> {
        self.rd.u16()
    }
}

/// Iterator over a validated list of one-byte-length-prefixed byte strings.
#[derive(Clone, Copy, Debug)]
pub struct Vec8List<'a> {
    rd: Rd<'a>,
}

impl<'a> Iterator for Vec8List<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        self.rd.vec8()
    }
}

/// Why a peek failed. Every variant except [`PeekError::Incomplete`] closes the connection (F1 L4-1: never a default
/// upstream); `Incomplete` means "read more, within the stall deadline".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeekError {
    /// Fewer bytes than the record header or the declared record length.
    Incomplete,
    /// Record length over [`MAX_RECORD`].
    TooLong,
    /// Not a handshake record (content type, record version) or not a ClientHello (handshake type).
    NotClientHello,
    /// Anything else that is not a well-formed single-record ClientHello.
    Malformed,
}

impl fmt::Display for PeekError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PeekError::Incomplete => "ClientHello record incomplete",
            PeekError::TooLong => "ClientHello record over 16 KiB",
            PeekError::NotClientHello => "not a TLS ClientHello",
            PeekError::Malformed => "malformed ClientHello",
        })
    }
}

const M: PeekError = PeekError::Malformed;

/// Peek at the ClientHello record at the start of `input`. Reads at most `5 + record length` bytes.
///
/// Three stages, each total on its own input (and each bounded separately in kani_proofs.rs): `record` (the
/// record header and declared body), `hello_body` (handshake header and the fixed hello fields), `extensions`.
pub fn client_hello(input: &[u8]) -> Result<Peek<'_>, PeekError> {
    client_hello_with(input, &mut BitSet::new())
}

/// [`client_hello`] with the duplicate-extension set supplied: the public entry point uses [`BitSet`]; the Kani
/// harnesses instantiate the same code with a small exact set (an 8 KiB bitmap is beyond CBMC's memory bound).
pub(crate) fn client_hello_with<'a, S: TypeSet>(input: &'a [u8], seen: &mut S) -> Result<Peek<'a>, PeekError> {
    let (payload, consumed) = record(input)?;
    let block = hello_body(payload)?;
    extensions(block.unwrap_or(&[]), consumed, seen)
}

/// A set of extension types (the duplicate check).
pub(crate) trait TypeSet {
    /// Record `t`; true iff it was not recorded before.
    fn insert(&mut self, t: u16) -> bool;
}

/// The 65 536-bit set of extension types: constant time per extension, so a 16 KiB block of 4096 extensions costs
/// a linear pass, not a quadratic rescan.
pub(crate) struct BitSet {
    words: [u64; 1024],
}

impl BitSet {
    pub(crate) const fn new() -> BitSet {
        BitSet { words: [0; 1024] }
    }
}

impl TypeSet for BitSet {
    fn insert(&mut self, t: u16) -> bool {
        // t >> 6 < 1024 always; a miss (impossible) reports "seen", which refuses the hello (fail closed).
        let Some(word) = self.words.get_mut(usize::from(t >> 6)) else { return false };
        let bit = 1u64 << (t & 63);
        let fresh = *word & bit == 0;
        *word |= bit;
        fresh
    }
}

/// The record header (type 0x16, version 0x0301..=0x0303, length 1..=MAX_RECORD) and its body. Returns the body and
/// 5 + length; `Incomplete` until the header and the whole body are in.
pub(crate) fn record(input: &[u8]) -> Result<(&[u8], usize), PeekError> {
    let mut hdr = match input.get(..RECORD_HEADER) {
        Some(h) => Rd::new(h),
        None => {
            return match input.first() {
                Some(&t) if t != CONTENT_HANDSHAKE => Err(PeekError::NotClientHello),
                _ => Err(PeekError::Incomplete),
            };
        }
    };
    if hdr.u8() != Some(CONTENT_HANDSHAKE) {
        return Err(PeekError::NotClientHello);
    }
    match hdr.u16() {
        Some(0x0301..=0x0303) => {}
        _ => return Err(PeekError::NotClientHello),
    }
    let n = usize::from(hdr.u16().ok_or(PeekError::Incomplete)?);
    if n == 0 {
        return Err(M);
    }
    if n > MAX_RECORD {
        return Err(PeekError::TooLong);
    }
    let consumed = RECORD_HEADER + n;
    let record = input.get(..consumed).ok_or(PeekError::Incomplete)?;
    let payload = record.get(RECORD_HEADER..).ok_or(PeekError::Incomplete)?;
    Ok((payload, consumed))
}

/// The handshake header and the fixed ClientHello fields of a record body. Returns the extensions block (`None` if
/// the hello ends after compression_methods).
pub(crate) fn hello_body(payload: &[u8]) -> Result<Option<&[u8]>, PeekError> {
    let mut p = Rd::new(payload);
    let ht = p.u8().ok_or(M)?; // fewer than 4 bytes: a handshake header split across records
    let hl = p.u24().ok_or(M)?;
    if ht != HANDSHAKE_CLIENT_HELLO {
        return Err(PeekError::NotClientHello);
    }
    // Exactly one complete hello in this record: longer = continues into another record, shorter = trailing bytes.
    if hl != p.rest().len() {
        return Err(M);
    }
    let mut r = Rd::new(p.rest());
    r.take(2).ok_or(M)?; // legacy_version
    r.take(RANDOM_LEN).ok_or(M)?;
    let sid = r.vec8().ok_or(M)?;
    if sid.len() > SESSION_ID_MAX {
        return Err(M);
    }
    let cs = r.vec16().ok_or(M)?;
    if cs.is_empty() || cs.len() & 1 != 0 {
        return Err(M);
    }
    let comp = r.vec8().ok_or(M)?;
    if comp.is_empty() {
        return Err(M);
    }
    if r.is_empty() {
        return Ok(None);
    }
    let block = r.vec16().ok_or(M)?;
    if !r.is_empty() {
        return Err(M);
    }
    Ok(Some(block))
}

/// The extensions block: no duplicate type, the read extensions well formed. `consumed` is passed through.
///
/// One flat pass over the block, a byte at a time, with no nested loop: the extension framing and each read
/// extension's inner format are state machines fed the same byte (`j` = the byte's index inside the extension data,
/// `n` = the data length). The trip count is the block length, which keeps Kani's unwinding linear. Inner formats:
/// - server_name: list length = n - 2, name_type 0, name length = n - 5 (exactly one entry), the name LDH ([`Ldh`]);
/// - ALPN: list length = n - 2 >= 1, then names of 1..=255 bytes that exactly fill it;
/// - supported_versions: list length (1 byte) = n - 1, even, >= 2;
/// - signature_algorithms, supported_groups: list length = n - 2, even, >= 2;
/// - trust_anchors: list length = n - 2 (may be 0), then TrustAnchorIDs of 1..=32 bytes that exactly fill it.
pub(crate) fn extensions<'a, S: TypeSet>(
    block: &'a [u8],
    consumed: usize,
    seen: &mut S,
) -> Result<Peek<'a>, PeekError> {
    let mut out =
        Peek { sni: None, alpn: None, versions: None, sigalgs: None, groups: None, trust_anchors: None, consumed };
    let mut st = Ext::Type1;
    // Inner state of the current extension: the high byte of a 2-byte length, the bytes left in the current
    // ALPN name / TrustAnchorID, and the server_name LDH state.
    let mut hi = 0u8;
    let mut rem = 0usize;
    let mut ldh = Ldh::START;
    for (i, &b) in block.iter().enumerate() {
        st = match st {
            Ext::Type1 => Ext::Type2(b),
            Ext::Type2(t1) => {
                let t = u16::from_be_bytes([t1, b]);
                if !seen.insert(t) {
                    return Err(M); // duplicate extension
                }
                Ext::Len1(t)
            }
            Ext::Len1(t) => Ext::Len2(t, b),
            Ext::Len2(t, h) => {
                let n = usize::from(u16::from_be_bytes([h, b]));
                rem = 0;
                ldh = Ldh::START;
                if n == 0 {
                    finish(&mut out, block, t, i + 1, 0, rem, ldh)?;
                    Ext::Type1
                } else {
                    Ext::Data { t, n, j: 0, at: i + 1 }
                }
            }
            Ext::Data { t, n, j, at } => {
                match (t, j) {
                    (
                        EXT_SERVER_NAME
                        | EXT_ALPN
                        | EXT_TRUST_ANCHORS
                        | EXT_SIGNATURE_ALGORITHMS
                        | EXT_SUPPORTED_GROUPS,
                        0,
                    ) => {
                        hi = b;
                    }
                    (EXT_SERVER_NAME, 1) | (EXT_ALPN, 1) | (EXT_TRUST_ANCHORS, 1) => {
                        if usize::from(u16::from_be_bytes([hi, b])) + 2 != n {
                            return Err(M);
                        }
                    }
                    (EXT_SIGNATURE_ALGORITHMS, 1) | (EXT_SUPPORTED_GROUPS, 1) => {
                        let l = usize::from(u16::from_be_bytes([hi, b]));
                        if l + 2 != n || l < 2 || l & 1 != 0 {
                            return Err(M);
                        }
                    }
                    (EXT_SUPPORTED_VERSIONS, 0) => {
                        let l = usize::from(b);
                        if l + 1 != n || l < 2 || l & 1 != 0 {
                            return Err(M);
                        }
                    }
                    (EXT_SERVER_NAME, 2) => {
                        if b != 0 {
                            return Err(M); // name_type must be host_name
                        }
                    }
                    (EXT_SERVER_NAME, 3) => hi = b,
                    (EXT_SERVER_NAME, 4) => {
                        if usize::from(u16::from_be_bytes([hi, b])) + 5 != n {
                            return Err(M); // exactly one entry, filling the list
                        }
                    }
                    (EXT_SERVER_NAME, _) => ldh = ldh.step(b).ok_or(M)?,
                    (EXT_ALPN, _) | (EXT_TRUST_ANCHORS, _) => {
                        if rem == 0 {
                            let max = if t == EXT_ALPN { 255 } else { TRUST_ANCHOR_ID_MAX };
                            if b == 0 || usize::from(b) > max {
                                return Err(M);
                            }
                            rem = usize::from(b);
                        } else {
                            rem -= 1;
                        }
                    }
                    _ => {}
                }
                if j + 1 < n {
                    Ext::Data { t, n, j: j + 1, at }
                } else {
                    finish(&mut out, block, t, at, n, rem, ldh)?;
                    Ext::Type1
                }
            }
        };
    }
    if st != Ext::Type1 {
        return Err(M); // an extension header or body runs past the block
    }
    Ok(out)
}

/// Where the extensions walk is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ext {
    Type1,
    Type2(u8),
    Len1(u16),
    Len2(u16, u8),
    /// Inside the data of extension `t` (`n` bytes starting at block offset `at`), at byte `j`.
    Data {
        t: u16,
        n: usize,
        j: usize,
        at: usize,
    },
}

/// Close extension `t` whose `n` data bytes start at `block[at]`: check that its inner format ended on a boundary and
/// record the field. The per-byte checks already ran.
fn finish<'a>(
    out: &mut Peek<'a>,
    block: &'a [u8],
    t: u16,
    at: usize,
    n: usize,
    rem: usize,
    ldh: Ldh,
) -> Result<(), PeekError> {
    let field = |skip: usize| block.get(at + skip..at + n).ok_or(M);
    match t {
        EXT_SERVER_NAME => {
            if n < 6 || n - 5 > HOST_MAX || !ldh.done() {
                return Err(M);
            }
            out.sni = Some(field(5)?);
        }
        EXT_ALPN => {
            if n < 3 || rem != 0 {
                return Err(M);
            }
            out.alpn = Some(field(2)?);
        }
        EXT_SUPPORTED_VERSIONS => {
            if n < 3 {
                return Err(M);
            }
            out.versions = Some(field(1)?);
        }
        EXT_SIGNATURE_ALGORITHMS | EXT_SUPPORTED_GROUPS => {
            if n < 4 {
                return Err(M);
            }
            let f = Some(field(2)?);
            if t == EXT_SIGNATURE_ALGORITHMS {
                out.sigalgs = f;
            } else {
                out.groups = f;
            }
        }
        EXT_TRUST_ANCHORS => {
            if n < 2 || rem != 0 {
                return Err(M);
            }
            out.trust_anchors = Some(field(2)?);
        }
        _ => {}
    }
    Ok(())
}

/// An incremental LDH DNS-name check: `label` bytes in the current label, `prev` the previous byte (`.` at the start).
#[derive(Clone, Copy, PartialEq, Eq)]
struct Ldh {
    label: usize,
    prev: u8,
}

impl Ldh {
    const START: Ldh = Ldh { label: 0, prev: b'.' };

    fn step(self, c: u8) -> Option<Ldh> {
        if c == b'.' {
            if self.label == 0 || self.prev == b'-' {
                return None;
            }
            return Some(Ldh { label: 0, prev: c });
        }
        if !(c.is_ascii_alphanumeric() || c == b'-') || (self.label == 0 && c == b'-') || self.label >= LABEL_MAX {
            return None;
        }
        Some(Ldh { label: self.label + 1, prev: c })
    }

    fn done(self) -> bool {
        self.label != 0 && self.prev != b'-'
    }
}

/// An LDH DNS name: 1..253 bytes, no leading or trailing dot, labels 1..63 of [A-Za-z0-9-] not starting or ending
/// with '-' (the [`Ldh`] machine the peek runs; the tests check it against the split-based definition).
#[cfg(test)]
fn valid_host(b: &[u8]) -> bool {
    if b.is_empty() || b.len() > HOST_MAX {
        return false;
    }
    let mut l = Ldh::START;
    for &c in b {
        match l.step(c) {
            Some(n) => l = n,
            None => return false,
        }
    }
    l.done()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]
    use super::{BitSet, HOST_MAX, LABEL_MAX, TypeSet, valid_host};
    use std::vec::Vec;

    /// BitSet is an exact set of u16: inserting all 65 536 values in turn, each is new (so the value-to-bit map is
    /// injective), and every value inserted again is refused (so insert records it). Insert-true-iff-new for any
    /// sequence follows. Also in an order that differs in the low and high bits.
    #[test]
    fn bitset_is_an_exact_set() {
        let mut s = BitSet::new();
        for t in 0..=u16::MAX {
            assert!(s.insert(t), "{t} reported seen");
        }
        for t in 0..=u16::MAX {
            assert!(!s.insert(t), "{t} not recorded");
        }
        let mut s = BitSet::new();
        for t in (0..=u16::MAX).map(|t| t.rotate_left(7) ^ 0xA5A5) {
            assert!(s.insert(t), "{t} reported seen");
            assert!(!s.insert(t), "{t} not recorded");
        }
    }

    /// The split-based definition the one-pass `valid_host` replaces (README "ClientHello peek rules").
    fn spec(b: &[u8]) -> bool {
        !b.is_empty()
            && b.len() <= HOST_MAX
            && b.split(|&c| c == b'.').all(|l| {
                !l.is_empty()
                    && l.len() <= LABEL_MAX
                    && l.first() != Some(&b'-')
                    && l.last() != Some(&b'-')
                    && l.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'-')
            })
    }

    #[test]
    fn valid_host_matches_spec() {
        // Every string of length 0..=7 over an alphabet with each character class, plus length edges.
        let alpha = [b'a', b'Z', b'0', b'-', b'.', b'_', 0x80];
        let mut cur: Vec<Vec<u8>> = std::vec![Vec::new()];
        for _ in 0..=7 {
            let mut next = Vec::new();
            for s in &cur {
                assert_eq!(valid_host(s), spec(s), "{s:?}");
                for &c in &alpha {
                    let mut t = s.clone();
                    t.push(c);
                    next.push(t);
                }
            }
            cur = next;
        }
        for n in [62, 63, 64] {
            let l = std::vec![b'a'; n];
            assert_eq!(valid_host(&l), spec(&l), "label {n}");
        }
        for n in [252, 253, 254] {
            let mut h: Vec<u8> = (0..n).map(|i| if i % 50 == 49 { b'.' } else { b'b' }).collect();
            h[n - 1] = b'c';
            assert_eq!(valid_host(&h), spec(&h), "host {n}");
        }
    }
}
