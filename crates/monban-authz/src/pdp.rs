//! Pure client side of the out-of-process Cedar PDP (DEVIATIONS X-8): the PDP-1 wire codec, the
//! [`PdpTransport`] seam and [`PdpClient`], which maps every channel failure to [`Decision::Error`].
//!
//! This module does no I/O (monban-authz is L2). A transport (a SOCK_SEQPACKET UDS or an inherited socketpair end)
//! lives in an effects layer and implements [`PdpTransport`]; the server (`monban-pdp`, L5) uses the same codec.
//!
//! # PDP-1 wire (framing as F10: SOCK_SEQPACKET, one message per packet, length-capped, request ids)
//!
//! Every frame starts with an 11-byte header: `0xCD` (magic), `0x01` (version), kind (`0` request, `1` reply),
//! then the request id as a big-endian `u64`. Request id `0` is reserved and never valid.
//!
//! * **Request** (kind 0), at most [`MAX_REQUEST`] bytes in total. Body, in this order, with nothing after it:
//!   `principal: uid`, `action: uid`, `resource: uid`, `context: record`, `entities: u16 n, n × entity`.
//!   * `str`   = `u16` big-endian byte length + UTF-8 bytes.
//!   * `uid`   = `type: str` (a Cedar entity type name, e.g. `App::User`) + `id: str` (any UTF-8).
//!   * `entity`= `uid` + `attrs: record` + `parents: u16 n, n × uid`.
//!   * `value` = tag byte, then: `0x00` false · `0x01` true · `0x02` long (`i64` big-endian) · `0x03` string (`str`)
//!     · `0x04` entity reference (`uid`) · `0x05` set (`u16 n, n × value`) · `0x06` record (`u16 n, n × (str, value)`).
//!   * `record` = a `0x06` value. Nesting of sets/records is at most [`MAX_DEPTH`] levels.
//! * **Reply** (kind 1): header + one decision byte (`0` Allow, `1` Deny, `2` Error); exactly [`REPLY_LEN`] bytes.
//!
//! **Determinism.** The encoding is canonical: record keys are strictly ascending (bytewise) and unique; set
//! elements, entity parents and entities are strictly ascending by their own encoded bytes and unique. The encoder
//! sorts; the decoder rejects any non-canonical, truncated, over-long or over-deep frame and any trailing byte. So
//! one logical request has exactly one encoding.
//!
//! **Fail-closed host mapping (INV-FAILCLOSED).** [`PdpClient::decide`] returns `Allow`/`Deny` only for a reply that
//! is exactly [`REPLY_LEN`] bytes, carries the right magic/version/kind, echoes the request id just sent and has a
//! decision byte in range. A transport timeout, EOF (PDP crash), I/O error, garbage, truncated or oversized frame
//! or wrong request id is `Decision::Error`, which [`crate::combine`] turns into Deny. After any such fault the
//! client resets the transport, so a late reply can never be read as the answer to a later request.

use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::{Decision, PolicyStage};

/// Frame magic byte.
pub const MAGIC: u8 = 0xCD;
/// Wire version.
pub const VERSION: u8 = 1;
/// Header length: magic, version, kind, request id.
pub const HEADER_LEN: usize = 11;
/// Exact reply length.
pub const REPLY_LEN: usize = HEADER_LEN + 1;
/// Request size cap (the F10 64 KiB default).
pub const MAX_REQUEST: usize = 64 * 1024;
/// Maximum set/record nesting depth inside a value.
pub const MAX_DEPTH: usize = 8;
/// Kind byte of a request frame.
pub const KIND_REQUEST: u8 = 0;
/// Kind byte of a reply frame.
pub const KIND_REPLY: u8 = 1;

const T_FALSE: u8 = 0x00;
const T_TRUE: u8 = 0x01;
const T_LONG: u8 = 0x02;
const T_STR: u8 = 0x03;
const T_ENTITY: u8 = 0x04;
const T_SET: u8 = 0x05;
const T_RECORD: u8 = 0x06;

/// A Cedar entity reference.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uid {
    /// Entity type name, e.g. `App::User`.
    pub ty: String,
    /// Entity id.
    pub id: String,
}

impl Uid {
    pub fn new(ty: &str, id: &str) -> Self {
        Self { ty: ty.into(), id: id.into() }
    }
}

/// A Cedar value restricted to what the PDP accepts as data (no extension values).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Bool(bool),
    Long(i64),
    Str(String),
    Entity(Uid),
    Set(Vec<Value>),
    Record(Vec<(String, Value)>),
}

/// One entity in the request's entity slice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntityData {
    pub uid: Uid,
    pub attrs: Vec<(String, Value)>,
    pub parents: Vec<Uid>,
}

/// One authorization request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdpRequest {
    pub principal: Uid,
    pub action: Uid,
    pub resource: Uid,
    pub context: Vec<(String, Value)>,
    pub entities: Vec<EntityData>,
}

/// Why a frame could not be encoded or decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// Frame shorter than its contents claim.
    Truncated,
    /// Frame (or one string/list) exceeds a cap.
    TooLarge,
    /// Bad magic, version or kind byte, or request id 0.
    BadHeader,
    /// Unknown value tag.
    BadTag,
    /// A string is not UTF-8.
    BadUtf8,
    /// Nesting deeper than [`MAX_DEPTH`].
    TooDeep,
    /// Keys/elements not strictly ascending, or a duplicate.
    NonCanonical,
    /// Bytes left after the body.
    Trailing,
}

// ------------------------------------------------------------------------------------------------ encoding

struct Enc {
    out: Vec<u8>,
}

impl Enc {
    fn u16_len(&mut self, n: usize) -> Result<(), WireError> {
        let n = u16::try_from(n).map_err(|_| WireError::TooLarge)?;
        self.out.extend_from_slice(&n.to_be_bytes());
        Ok(())
    }
    fn str(&mut self, s: &str) -> Result<(), WireError> {
        self.u16_len(s.len())?;
        self.out.extend_from_slice(s.as_bytes());
        Ok(())
    }
    fn uid(&mut self, u: &Uid) -> Result<(), WireError> {
        self.str(&u.ty)?;
        self.str(&u.id)
    }
    fn record(&mut self, fields: &[(String, Value)], depth: usize) -> Result<(), WireError> {
        if depth > MAX_DEPTH {
            return Err(WireError::TooDeep);
        }
        let mut sorted: Vec<&(String, Value)> = fields.iter().collect();
        sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        if sorted.windows(2).any(|w| matches!(w, [a, b] if a.0 == b.0)) {
            return Err(WireError::NonCanonical);
        }
        self.out.push(T_RECORD);
        self.u16_len(sorted.len())?;
        for (k, v) in sorted {
            self.str(k)?;
            self.value(v, depth)?;
        }
        Ok(())
    }
    fn value(&mut self, v: &Value, depth: usize) -> Result<(), WireError> {
        match v {
            Value::Bool(false) => self.out.push(T_FALSE),
            Value::Bool(true) => self.out.push(T_TRUE),
            Value::Long(n) => {
                self.out.push(T_LONG);
                self.out.extend_from_slice(&n.to_be_bytes());
            }
            Value::Str(s) => {
                self.out.push(T_STR);
                self.str(s)?;
            }
            Value::Entity(u) => {
                self.out.push(T_ENTITY);
                self.uid(u)?;
            }
            Value::Set(items) => {
                if depth + 1 > MAX_DEPTH {
                    return Err(WireError::TooDeep);
                }
                let enc = sorted_unique(items.iter().map(|i| encode_one(|e| e.value(i, depth + 1))))?;
                self.out.push(T_SET);
                self.u16_len(enc.len())?;
                enc.iter().for_each(|b| self.out.extend_from_slice(b));
            }
            Value::Record(fields) => self.record(fields, depth + 1)?,
        }
        Ok(())
    }
}

fn encode_one(f: impl FnOnce(&mut Enc) -> Result<(), WireError>) -> Result<Vec<u8>, WireError> {
    let mut e = Enc { out: Vec::new() };
    f(&mut e)?;
    Ok(e.out)
}

/// Encode each item separately, sort by bytes, reject duplicates (sets are sets).
fn sorted_unique(items: impl Iterator<Item = Result<Vec<u8>, WireError>>) -> Result<Vec<Vec<u8>>, WireError> {
    let mut v = items.collect::<Result<Vec<_>, _>>()?;
    v.sort();
    if v.windows(2).any(|w| matches!(w, [a, b] if a == b)) {
        return Err(WireError::NonCanonical);
    }
    Ok(v)
}

fn header(out: &mut Vec<u8>, kind: u8, id: u64) {
    out.push(MAGIC);
    out.push(VERSION);
    out.push(kind);
    out.extend_from_slice(&id.to_be_bytes());
}

/// Canonical request body (everything after the header).
pub fn encode_request_body(req: &PdpRequest) -> Result<Vec<u8>, WireError> {
    let mut e = Enc { out: Vec::new() };
    e.uid(&req.principal)?;
    e.uid(&req.action)?;
    e.uid(&req.resource)?;
    e.record(&req.context, 1)?;
    let ents = sorted_unique(req.entities.iter().map(|ent| {
        encode_one(|e| {
            e.uid(&ent.uid)?;
            e.record(&ent.attrs, 1)?;
            let ps = sorted_unique(ent.parents.iter().map(|p| encode_one(|e| e.uid(p))))?;
            e.u16_len(ps.len())?;
            ps.iter().for_each(|b| e.out.extend_from_slice(b));
            Ok(())
        })
    }))?;
    // Two entities with the same uid but different data would sort apart; the uid must be unique too.
    let mut uids: Vec<&Uid> = req.entities.iter().map(|x| &x.uid).collect();
    uids.sort();
    if uids.windows(2).any(|w| matches!(w, [a, b] if a == b)) {
        return Err(WireError::NonCanonical);
    }
    e.u16_len(ents.len())?;
    ents.iter().for_each(|b| e.out.extend_from_slice(b));
    if e.out.len() + HEADER_LEN > MAX_REQUEST {
        return Err(WireError::TooLarge);
    }
    Ok(e.out)
}

/// Full canonical request frame with request id `id` (must be non-zero).
pub fn encode_request(id: u64, req: &PdpRequest) -> Result<Vec<u8>, WireError> {
    if id == 0 {
        return Err(WireError::BadHeader);
    }
    let body = encode_request_body(req)?;
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    header(&mut out, KIND_REQUEST, id);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Reply frame.
pub fn encode_reply(id: u64, d: Decision) -> [u8; REPLY_LEN] {
    let mut out = [0u8; REPLY_LEN];
    let mut v = Vec::with_capacity(REPLY_LEN);
    header(&mut v, KIND_REPLY, id);
    v.push(match d {
        Decision::Allow => 0,
        Decision::Deny => 1,
        Decision::Error => 2,
    });
    out.iter_mut().zip(v).for_each(|(o, b)| *o = b);
    out
}

// ------------------------------------------------------------------------------------------------ decoding

struct Dec<'a> {
    b: &'a [u8],
}

impl<'a> Dec<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.b.len() < n {
            return Err(WireError::Truncated);
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }
    fn u8(&mut self) -> Result<u8, WireError> {
        self.take(1)?.first().copied().ok_or(WireError::Truncated)
    }
    fn u16(&mut self) -> Result<usize, WireError> {
        let s = self.take(2)?;
        let a: [u8; 2] = s.try_into().map_err(|_| WireError::Truncated)?;
        Ok(usize::from(u16::from_be_bytes(a)))
    }
    fn str(&mut self) -> Result<String, WireError> {
        let n = self.u16()?;
        let s = self.take(n)?;
        core::str::from_utf8(s).map(String::from).map_err(|_| WireError::BadUtf8)
    }
    fn uid(&mut self) -> Result<Uid, WireError> {
        Ok(Uid { ty: self.str()?, id: self.str()? })
    }
    /// Decode one item and also return its exact encoded bytes (for the canonical-order check).
    fn spanned<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T, WireError>) -> Result<(T, &'a [u8]), WireError> {
        let start = self.b;
        let v = f(self)?;
        let used = start.len() - self.b.len();
        Ok((v, start.get(..used).ok_or(WireError::Truncated)?))
    }
    fn record_body(&mut self, depth: usize) -> Result<Vec<(String, Value)>, WireError> {
        if depth > MAX_DEPTH {
            return Err(WireError::TooDeep);
        }
        let n = self.u16()?;
        let mut out: Vec<(String, Value)> = Vec::new();
        for _ in 0..n {
            let k = self.str()?;
            if let Some((prev, _)) = out.last()
                && prev.as_bytes() >= k.as_bytes()
            {
                return Err(WireError::NonCanonical);
            }
            let v = self.value(depth)?;
            out.push((k, v));
        }
        Ok(out)
    }
    fn record(&mut self, depth: usize) -> Result<Vec<(String, Value)>, WireError> {
        if self.u8()? != T_RECORD {
            return Err(WireError::BadTag);
        }
        self.record_body(depth)
    }
    fn value(&mut self, depth: usize) -> Result<Value, WireError> {
        Ok(match self.u8()? {
            T_FALSE => Value::Bool(false),
            T_TRUE => Value::Bool(true),
            T_LONG => {
                let a: [u8; 8] = self.take(8)?.try_into().map_err(|_| WireError::Truncated)?;
                Value::Long(i64::from_be_bytes(a))
            }
            T_STR => Value::Str(self.str()?),
            T_ENTITY => Value::Entity(self.uid()?),
            T_SET => {
                if depth + 1 > MAX_DEPTH {
                    return Err(WireError::TooDeep);
                }
                let n = self.u16()?;
                let mut out = Vec::new();
                let mut prev: Option<&[u8]> = None;
                for _ in 0..n {
                    let (v, bytes) = self.spanned(|d| d.value(depth + 1))?;
                    if prev.is_some_and(|p| p >= bytes) {
                        return Err(WireError::NonCanonical);
                    }
                    prev = Some(bytes);
                    out.push(v);
                }
                Value::Set(out)
            }
            T_RECORD => Value::Record(self.record_body(depth + 1)?),
            _ => return Err(WireError::BadTag),
        })
    }
}

/// Parse and check a header; returns `(kind, request id)`.
pub fn decode_header(frame: &[u8]) -> Result<(u8, u64), WireError> {
    let mut d = Dec { b: frame };
    if d.u8()? != MAGIC || d.u8()? != VERSION {
        return Err(WireError::BadHeader);
    }
    let kind = d.u8()?;
    let id: [u8; 8] = d.take(8)?.try_into().map_err(|_| WireError::Truncated)?;
    let id = u64::from_be_bytes(id);
    if id == 0 || (kind != KIND_REQUEST && kind != KIND_REPLY) {
        return Err(WireError::BadHeader);
    }
    Ok((kind, id))
}

/// Decode a request body (the bytes after the header). Rejects anything non-canonical.
pub fn decode_request_body(body: &[u8]) -> Result<PdpRequest, WireError> {
    if body.len() + HEADER_LEN > MAX_REQUEST {
        return Err(WireError::TooLarge);
    }
    let mut d = Dec { b: body };
    let principal = d.uid()?;
    let action = d.uid()?;
    let resource = d.uid()?;
    let context = d.record(1)?;
    let n = d.u16()?;
    let mut entities = Vec::new();
    let mut prev: Option<&[u8]> = None;
    for _ in 0..n {
        let (ent, bytes) = d.spanned(|d| {
            let uid = d.uid()?;
            let attrs = d.record(1)?;
            let np = d.u16()?;
            let mut parents = Vec::new();
            let mut pprev: Option<&[u8]> = None;
            for _ in 0..np {
                let (p, pb) = d.spanned(Dec::uid)?;
                if pprev.is_some_and(|x| x >= pb) {
                    return Err(WireError::NonCanonical);
                }
                pprev = Some(pb);
                parents.push(p);
            }
            Ok(EntityData { uid, attrs, parents })
        })?;
        if prev.is_some_and(|p| p >= bytes) {
            return Err(WireError::NonCanonical);
        }
        prev = Some(bytes);
        entities.push(ent);
    }
    if !d.b.is_empty() {
        return Err(WireError::Trailing);
    }
    let mut uids: Vec<&Uid> = entities.iter().map(|x| &x.uid).collect();
    uids.sort();
    if uids.windows(2).any(|w| matches!(w, [a, b] if a == b)) {
        return Err(WireError::NonCanonical);
    }
    Ok(PdpRequest { principal, action, resource, context, entities })
}

/// Decode a full request frame; returns the request id and the body result separately, so a server can answer
/// `Error` under the right id when only the body is bad.
pub fn decode_request(frame: &[u8]) -> Result<(u64, Result<PdpRequest, WireError>), WireError> {
    let (kind, id) = decode_header(frame)?;
    if kind != KIND_REQUEST {
        return Err(WireError::BadHeader);
    }
    if frame.len() > MAX_REQUEST {
        return Ok((id, Err(WireError::TooLarge)));
    }
    Ok((id, decode_request_body(frame.get(HEADER_LEN..).unwrap_or_default())))
}

/// Interpret a reply to request `expected_id`. `true_len` is the packet's real length as reported by the
/// transport (it may exceed `frame.len()` when the packet was truncated into a small buffer). Anything but an
/// exact, well-formed reply to `expected_id` is `Error`.
pub fn decode_reply(frame: &[u8], true_len: usize, expected_id: u64) -> Decision {
    if true_len != REPLY_LEN || frame.len() < REPLY_LEN {
        return Decision::Error;
    }
    let Some(frame) = frame.get(..REPLY_LEN) else { return Decision::Error };
    match decode_header(frame) {
        Ok((KIND_REPLY, id)) if id == expected_id => match frame.get(HEADER_LEN) {
            Some(0) => Decision::Allow,
            Some(1) => Decision::Deny,
            _ => Decision::Error,
        },
        _ => Decision::Error,
    }
}

// ------------------------------------------------------------------------------------------------ client

/// Why a transport exchange failed. The client maps every variant to `Decision::Error`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportFault {
    /// No reply within the transport's deadline.
    Timeout,
    /// The PDP closed the channel (crash, EOF) or could not be reached.
    Closed,
    /// Any other I/O failure.
    Io,
}

/// One request/reply exchange over a message-preserving channel. The transport owns the deadline: `exchange`
/// must return within it (`Err(Timeout)` otherwise). It writes at most `reply.len()` bytes and returns the reply
/// packet's **true** length, which may exceed `reply.len()` for an oversized packet.
pub trait PdpTransport {
    fn exchange(&mut self, request: &[u8], reply: &mut [u8]) -> Result<usize, TransportFault>;
    /// Drop the current connection; the next `exchange` uses a fresh one. Called after every fault so a late or
    /// duplicated reply can never be consumed by a later request.
    fn reset(&mut self);
}

/// Fail-closed PDP client. Request ids are per client, strictly increasing, never 0.
#[derive(Debug)]
pub struct PdpClient<T> {
    transport: T,
    last_id: u64,
}

impl<T: PdpTransport> PdpClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport, last_id: 0 }
    }

    /// The request id the next `decide` will use.
    pub fn next_id(&self) -> u64 {
        self.last_id.checked_add(1).unwrap_or(1)
    }

    /// Ask the PDP. Returns `Allow`/`Deny` only for an exact, matching reply; everything else is `Error`.
    pub fn decide(&mut self, req: &PdpRequest) -> Decision {
        let id = self.next_id();
        self.last_id = id;
        let Ok(frame) = encode_request(id, req) else { return Decision::Error };
        // Larger than any legal reply, so an oversized packet is visible through the true length.
        let mut buf = [0u8; 4 * REPLY_LEN];
        let d = match self.transport.exchange(&frame, &mut buf) {
            Ok(n) => decode_reply(buf.get(..n.min(buf.len())).unwrap_or_default(), n, id),
            Err(_) => Decision::Error,
        };
        if d == Decision::Error {
            self.transport.reset();
        }
        d
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

/// [`PolicyStage`] adapter for a PDP client (stages take `&self`). A re-entrant call is `Error`.
#[derive(Debug)]
pub struct PdpStage<T> {
    client: RefCell<PdpClient<T>>,
}

impl<T: PdpTransport> PdpStage<T> {
    pub fn new(transport: T) -> Self {
        Self { client: RefCell::new(PdpClient::new(transport)) }
    }
}

impl<T: PdpTransport> PolicyStage for PdpStage<T> {
    type Request = PdpRequest;
    fn decide(&self, req: &PdpRequest) -> Decision {
        match self.client.try_borrow_mut() {
            Ok(mut c) => c.decide(req),
            Err(_) => Decision::Error,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::combine;
    use alloc::vec;

    fn sample() -> PdpRequest {
        PdpRequest {
            principal: Uid::new("App::User", "alice"),
            action: Uid::new("App::Action", "read"),
            resource: Uid::new("App::Doc", "d1"),
            context: vec![
                ("mfa".into(), Value::Bool(true)),
                ("amount".into(), Value::Long(-7)),
                ("tags".into(), Value::Set(vec![Value::Str("b".into()), Value::Str("a".into())])),
            ],
            entities: vec![
                EntityData {
                    uid: Uid::new("App::User", "alice"),
                    attrs: vec![
                        ("tenant".into(), Value::Entity(Uid::new("App::Tenant", "t1"))),
                        (
                            "meta".into(),
                            Value::Record(vec![("z".into(), Value::Long(1)), ("a".into(), Value::Long(2))]),
                        ),
                    ],
                    parents: vec![Uid::new("App::Role", "viewer"), Uid::new("App::Role", "admin")],
                },
                EntityData { uid: Uid::new("App::Doc", "d1"), attrs: vec![], parents: vec![] },
            ],
        }
    }

    /// Canonical form of `sample()` (what decoding an encoding yields).
    fn canonical(mut r: PdpRequest) -> PdpRequest {
        fn canon_v(v: &mut Value) {
            match v {
                Value::Set(xs) => {
                    xs.iter_mut().for_each(canon_v);
                    xs.sort_by_key(|x| encode_one(|e| e.value(x, 1)).unwrap_or_default());
                }
                Value::Record(fs) => canon_r(fs),
                _ => {}
            }
        }
        fn canon_r(fs: &mut [(String, Value)]) {
            fs.iter_mut().for_each(|(_, v)| canon_v(v));
            fs.sort_by(|a, b| a.0.cmp(&b.0));
        }
        canon_r(&mut r.context);
        for e in &mut r.entities {
            canon_r(&mut e.attrs);
            e.parents.sort_by_key(|p| encode_one(|e| e.uid(p)).unwrap_or_default());
        }
        r.entities.sort_by_key(|e| encode_one(|x| x.uid(&e.uid)).unwrap_or_default());
        r
    }

    #[test]
    fn round_trip_is_canonical() {
        let f = encode_request(42, &sample()).unwrap();
        let (id, body) = decode_request(&f).unwrap();
        assert_eq!(id, 42);
        let got = body.unwrap();
        assert_eq!(got, canonical(sample()));
        // Re-encoding the decoded request yields the same bytes (determinism).
        assert_eq!(encode_request(42, &got).unwrap(), f);
    }

    #[test]
    fn rejects_non_canonical_and_malformed() {
        let f = encode_request(1, &sample()).unwrap();
        // Every strict prefix is rejected.
        for n in 0..f.len() {
            assert!(decode_request(&f[..n]).map(|(_, b)| b.is_err()).unwrap_or(true), "prefix {n}");
        }
        // Trailing byte.
        let mut t = f.clone();
        t.push(0);
        assert_eq!(decode_request(&t).unwrap().1, Err(WireError::Trailing));
        // Bad header.
        let mut h = f.clone();
        h[0] ^= 1;
        assert_eq!(decode_request(&h), Err(WireError::BadHeader));
        let mut z = f.clone();
        z[3..11].copy_from_slice(&0u64.to_be_bytes());
        assert_eq!(decode_request(&z), Err(WireError::BadHeader));
        // Duplicate record keys and duplicate set elements cannot be encoded.
        let mut r = sample();
        r.context.push(("mfa".into(), Value::Bool(false)));
        assert_eq!(encode_request(1, &r), Err(WireError::NonCanonical));
        let mut r = sample();
        r.context.push(("s".into(), Value::Set(vec![Value::Long(1), Value::Long(1)])));
        assert_eq!(encode_request(1, &r), Err(WireError::NonCanonical));
        let mut r = sample();
        r.entities.push(EntityData {
            uid: Uid::new("App::Doc", "d1"),
            attrs: vec![("x".into(), Value::Long(1))],
            parents: vec![],
        });
        assert_eq!(encode_request(1, &r), Err(WireError::NonCanonical));
        // Hand-built unsorted record: {"b": true, "a": true}.
        let mut body = Vec::new();
        for s in ["T", "p", "T", "a", "T", "r"] {
            body.extend_from_slice(&(s.len() as u16).to_be_bytes());
            body.extend_from_slice(s.as_bytes());
        }
        body.extend_from_slice(&[T_RECORD, 0, 2, 0, 1, b'b', T_TRUE, 0, 1, b'a', T_TRUE, 0, 0]);
        assert_eq!(decode_request_body(&body), Err(WireError::NonCanonical));
        body[23] = b'a';
        body[27] = b'b';
        assert!(decode_request_body(&body).is_ok());
    }

    #[test]
    fn depth_and_size_caps() {
        let mut v = Value::Long(0);
        for _ in 0..MAX_DEPTH + 1 {
            v = Value::Set(vec![v]);
        }
        let mut r = sample();
        r.context = vec![("deep".into(), v)];
        assert_eq!(encode_request(1, &r), Err(WireError::TooDeep));
        let mut r = sample();
        r.context =
            vec![("big".into(), Value::Str("x".repeat(60_000))), ("big2".into(), Value::Str("y".repeat(10_000)))];
        assert_eq!(encode_request(1, &r), Err(WireError::TooLarge));
    }

    #[test]
    fn reply_decoding_is_exact() {
        for d in [Decision::Allow, Decision::Deny, Decision::Error] {
            let r = encode_reply(9, d);
            assert_eq!(decode_reply(&r, REPLY_LEN, 9), d);
            assert_eq!(decode_reply(&r, REPLY_LEN, 8), Decision::Error, "wrong id");
            assert_eq!(decode_reply(&r, REPLY_LEN + 1, 9), Decision::Error, "oversized");
            assert_eq!(decode_reply(&r[..REPLY_LEN - 1], REPLY_LEN - 1, 9), Decision::Error, "truncated");
        }
        let mut r = encode_reply(9, Decision::Allow);
        r[HEADER_LEN] = 3;
        assert_eq!(decode_reply(&r, REPLY_LEN, 9), Decision::Error);
        let mut r = encode_reply(9, Decision::Allow);
        r[2] = KIND_REQUEST;
        assert_eq!(decode_reply(&r, REPLY_LEN, 9), Decision::Error);
    }

    /// Scripted transport: each exchange pops one behaviour.
    enum Act {
        Reply(Decision),
        ReplyId(u64, Decision),
        Raw(Vec<u8>, usize),
        Fail(TransportFault),
    }
    struct Mock {
        acts: Vec<Act>,
        resets: usize,
    }
    impl PdpTransport for Mock {
        fn exchange(&mut self, request: &[u8], reply: &mut [u8]) -> Result<usize, TransportFault> {
            let (_, id) = decode_header(request).map_err(|_| TransportFault::Io)?;
            let act = if self.acts.is_empty() { Act::Fail(TransportFault::Closed) } else { self.acts.remove(0) };
            let (bytes, n) = match act {
                Act::Reply(d) => (encode_reply(id, d).to_vec(), REPLY_LEN),
                Act::ReplyId(other, d) => (encode_reply(other, d).to_vec(), REPLY_LEN),
                Act::Raw(b, n) => (b, n),
                Act::Fail(f) => return Err(f),
            };
            reply.iter_mut().zip(bytes.iter()).for_each(|(o, b)| *o = *b);
            Ok(n)
        }
        fn reset(&mut self) {
            self.resets += 1;
        }
    }

    #[test]
    fn every_channel_fault_is_error_and_combines_to_deny() {
        let allow_bytes = encode_reply(1, Decision::Allow).to_vec();
        let mut oversized = allow_bytes.clone();
        oversized.extend_from_slice(&[0; 40]);
        let faults = vec![
            Act::Fail(TransportFault::Timeout),
            Act::Fail(TransportFault::Closed),
            Act::Fail(TransportFault::Io),
            Act::ReplyId(1, Decision::Allow), // stale id (request ids here start at 2)
            Act::ReplyId(u64::MAX, Decision::Allow),
            Act::Raw(allow_bytes[..6].to_vec(), 6),
            Act::Raw(vec![], 0),
            Act::Raw(oversized.clone(), oversized.len()),
            Act::Raw(vec![0xFF; REPLY_LEN], REPLY_LEN),
        ];
        let n = faults.len();
        let mut acts = vec![Act::Reply(Decision::Allow)];
        acts.extend(faults);
        acts.push(Act::Reply(Decision::Allow));
        let mut c = PdpClient::new(Mock { acts, resets: 0 });
        assert_eq!(c.decide(&sample()), Decision::Allow);
        for i in 0..n {
            let d = c.decide(&sample());
            assert_eq!(d, Decision::Error, "fault {i}");
            assert_eq!(combine(&[Decision::Allow, d]), Decision::Deny);
        }
        assert_eq!(c.transport_mut().resets, n);
        assert_eq!(c.decide(&sample()), Decision::Allow, "recovers after faults");
    }

    #[test]
    fn stage_adapter() {
        let s = PdpStage::new(Mock {
            acts: vec![Act::Reply(Decision::Deny), Act::Fail(TransportFault::Timeout)],
            resets: 0,
        });
        assert_eq!(s.decide(&sample()), Decision::Deny);
        assert_eq!(combine(&[s.decide(&sample())]), Decision::Deny);
    }
}
