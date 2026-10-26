//! Caveats (F5 `caveat`), the request they are judged against, and their semantics, transcribed from
//! `spec/AegisIR/Token.lean` (`ArgCon.sat`, `argsOk`, `sat`, `denote`, `effExp`, `effDepth`, `depthOk`) plus the
//! F5 mint-shape check. Every function here is pure; `now` is a field of the request, never read from a clock.

use crate::cbor::{self, CborError, Dec};

/// Wire limits from F5.
pub const MAX_CAVEATS: usize = 64;
pub const MAX_AUD: usize = 255;
pub const MAX_SEGMENTS: usize = 16;
pub const MAX_SEGMENT: usize = 255;
pub const MAX_TOOL: usize = 128;
pub const MAX_ARGKEY: usize = 64;
pub const MAX_ONE_OF: usize = 32;
pub const MAX_OPS: u8 = 31;
pub const MAX_DEPTH: u8 = 16;

/// An argument value (`ArgVal`). The F5 `any` is restricted to these two kinds; other CBOR values are rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArgVal {
    Int(i64),
    Str(String),
}

/// An argument predicate (F5 `argpred`; Lean `ArgCon` plus the wire's str-prefix).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArgPred {
    /// `[0, v]`: equal to `v` (an Int never equals a Str).
    Eq(ArgVal),
    /// `[1, [v...]]`: one of 1..32 values.
    OneOf(Vec<ArgVal>),
    /// `[2, lo, hi]`: an Int in `lo..=hi`.
    Range(i64, i64),
    /// `[3, p]`: a Str starting with `p` (F5 wire extension; not in Token.lean's `ArgCon`).
    StrPrefix(String),
}

impl ArgPred {
    /// `ArgCon.sat`.
    pub fn sat(&self, x: &ArgVal) -> bool {
        match (self, x) {
            (ArgPred::Eq(v), x) => x == v,
            (ArgPred::Range(lo, hi), ArgVal::Int(x)) => lo <= x && x <= hi,
            (ArgPred::Range(..), ArgVal::Str(_)) => false,
            (ArgPred::OneOf(vs), x) => vs.contains(x),
            (ArgPred::StrPrefix(p), ArgVal::Str(s)) => s.starts_with(p.as_str()),
            (ArgPred::StrPrefix(_), ArgVal::Int(_)) => false,
        }
    }
}

/// A caveat (F5 `caveat`, Lean `Caveat`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caveat {
    Aud(String),
    Exp(u64),
    Nbf(u64),
    /// Op bitmask over {select=1, insert=2, update=4, delete=8, upsert=16}.
    Ops(u8),
    /// Resource segment prefix (D1).
    Res(Vec<String>),
    /// RFC 7638 JWK thumbprint of the holder key.
    Cnf([u8; 32]),
    Tenant(u64),
    Tool(String, Vec<(String, ArgPred)>),
    Depth(u8),
}

/// The request a token is judged against (Lean `Req`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Req {
    pub aud: String,
    /// Requested op set as a bitmask.
    pub ops: u64,
    /// Canonical path segments (see [`path_segments`]).
    pub res: Vec<String>,
    pub tenant: u64,
    /// Holder key thumbprint proven for this request (empty if none).
    pub holder: Vec<u8>,
    /// Tool name ("" if the request is not a tool call).
    pub tool: String,
    pub args: Vec<(String, ArgVal)>,
    /// Verifier clock, seconds since epoch. A parameter, never read from a clock here.
    pub now: u64,
}

/// Splits a canonical absolute path into segments: "/" → [], "/a/b" → ["a", "b"]. Returns `None` for a path that
/// is not absolute or has an empty segment ("//", trailing "/"), so the split is unambiguous (D1).
pub fn path_segments(path: &str) -> Option<Vec<String>> {
    let rest = path.strip_prefix('/')?;
    if rest.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for s in rest.split('/') {
        if s.is_empty() {
            return None;
        }
        out.push(String::from(s));
    }
    Some(out)
}

fn str_len_ok(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max
}

impl Caveat {
    /// Wire-shape constraints from F5 (sizes and ranges). Encoders refuse caveats that fail this.
    pub fn is_well_formed(&self) -> bool {
        match self {
            Caveat::Aud(a) => str_len_ok(a, MAX_AUD),
            Caveat::Exp(_) | Caveat::Nbf(_) | Caveat::Cnf(_) => true,
            Caveat::Ops(m) => *m <= MAX_OPS,
            Caveat::Res(segs) => {
                !segs.is_empty() && segs.len() <= MAX_SEGMENTS && segs.iter().all(|s| str_len_ok(s, MAX_SEGMENT))
            }
            Caveat::Tenant(t) => *t > 0,
            Caveat::Tool(name, cons) => {
                str_len_ok(name, MAX_TOOL)
                    && cons.iter().all(|(k, p)| {
                        str_len_ok(k, MAX_ARGKEY)
                            && match p {
                                ArgPred::OneOf(vs) => !vs.is_empty() && vs.len() <= MAX_ONE_OF,
                                ArgPred::Eq(_) | ArgPred::Range(..) | ArgPred::StrPrefix(_) => true,
                            }
                    })
            }
            Caveat::Depth(d) => *d <= MAX_DEPTH,
        }
    }

    /// Deterministic CBOR encoding (the MAC input `enc c`).
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Caveat::Aud(a) => {
                cbor::put_array(out, 2);
                cbor::put_uint(out, 0);
                cbor::put_tstr(out, a);
            }
            Caveat::Exp(e) => {
                cbor::put_array(out, 2);
                cbor::put_uint(out, 1);
                cbor::put_uint(out, *e);
            }
            Caveat::Nbf(n) => {
                cbor::put_array(out, 2);
                cbor::put_uint(out, 2);
                cbor::put_uint(out, *n);
            }
            Caveat::Ops(m) => {
                cbor::put_array(out, 2);
                cbor::put_uint(out, 3);
                cbor::put_uint(out, u64::from(*m));
            }
            Caveat::Res(segs) => {
                cbor::put_array(out, 2);
                cbor::put_uint(out, 4);
                cbor::put_array(out, segs.len());
                for s in segs {
                    cbor::put_tstr(out, s);
                }
            }
            Caveat::Cnf(j) => {
                cbor::put_array(out, 2);
                cbor::put_uint(out, 5);
                cbor::put_bstr(out, j);
            }
            Caveat::Tenant(t) => {
                cbor::put_array(out, 2);
                cbor::put_uint(out, 6);
                cbor::put_uint(out, *t);
            }
            Caveat::Tool(name, cons) => {
                cbor::put_array(out, 3);
                cbor::put_uint(out, 7);
                cbor::put_tstr(out, name);
                cbor::put_array(out, cons.len());
                for (k, p) in cons {
                    cbor::put_array(out, 2);
                    cbor::put_tstr(out, k);
                    encode_pred(out, p);
                }
            }
            Caveat::Depth(d) => {
                cbor::put_array(out, 2);
                cbor::put_uint(out, 8);
                cbor::put_uint(out, u64::from(*d));
            }
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.encode_into(&mut v);
        v
    }

    /// Decodes exactly one caveat from `bytes` (no trailing data).
    pub fn decode(bytes: &[u8]) -> Result<Caveat, CborError> {
        let mut d = Dec::new(bytes);
        let c = decode_caveat(&mut d)?;
        d.finish()?;
        Ok(c)
    }
}

fn encode_val(out: &mut Vec<u8>, v: &ArgVal) {
    match v {
        ArgVal::Int(i) => cbor::put_int(out, *i),
        ArgVal::Str(s) => cbor::put_tstr(out, s),
    }
}

fn encode_pred(out: &mut Vec<u8>, p: &ArgPred) {
    match p {
        ArgPred::Eq(v) => {
            cbor::put_array(out, 2);
            cbor::put_uint(out, 0);
            encode_val(out, v);
        }
        ArgPred::OneOf(vs) => {
            cbor::put_array(out, 2);
            cbor::put_uint(out, 1);
            cbor::put_array(out, vs.len());
            for v in vs {
                encode_val(out, v);
            }
        }
        ArgPred::Range(lo, hi) => {
            cbor::put_array(out, 3);
            cbor::put_uint(out, 2);
            cbor::put_int(out, *lo);
            cbor::put_int(out, *hi);
        }
        ArgPred::StrPrefix(s) => {
            cbor::put_array(out, 2);
            cbor::put_uint(out, 3);
            cbor::put_tstr(out, s);
        }
    }
}

fn tstr_bounded(d: &mut Dec<'_>, max: usize) -> Result<String, CborError> {
    let s = d.tstr()?;
    if str_len_ok(&s, max) { Ok(s) } else { Err(CborError) }
}

fn decode_val(d: &mut Dec<'_>) -> Result<ArgVal, CborError> {
    match d.peek_major()? {
        cbor::MAJ_UINT | cbor::MAJ_NINT => Ok(ArgVal::Int(d.int()?)),
        cbor::MAJ_TSTR => Ok(ArgVal::Str(d.tstr()?)),
        _ => Err(CborError),
    }
}

fn decode_pred(d: &mut Dec<'_>) -> Result<ArgPred, CborError> {
    let n = d.array()?;
    let kind = d.uint()?;
    match (kind, n) {
        (0, 2) => Ok(ArgPred::Eq(decode_val(d)?)),
        (1, 2) => {
            let k = d.array()?;
            if k == 0 || k > MAX_ONE_OF {
                return Err(CborError);
            }
            let mut vs = Vec::with_capacity(k);
            for _ in 0..k {
                vs.push(decode_val(d)?);
            }
            Ok(ArgPred::OneOf(vs))
        }
        (2, 3) => {
            let lo = d.int()?;
            let hi = d.int()?;
            Ok(ArgPred::Range(lo, hi))
        }
        (3, 2) => Ok(ArgPred::StrPrefix(d.tstr()?)),
        _ => Err(CborError),
    }
}

pub(crate) fn decode_caveat(d: &mut Dec<'_>) -> Result<Caveat, CborError> {
    let n = d.array()?;
    let kind = d.uint()?;
    let c = match (kind, n) {
        (0, 2) => Caveat::Aud(tstr_bounded(d, MAX_AUD)?),
        (1, 2) => Caveat::Exp(d.uint()?),
        (2, 2) => Caveat::Nbf(d.uint()?),
        (3, 2) => {
            let m = d.uint()?;
            if m > u64::from(MAX_OPS) {
                return Err(CborError);
            }
            Caveat::Ops(m as u8)
        }
        (4, 2) => {
            let k = d.array()?;
            if k == 0 || k > MAX_SEGMENTS {
                return Err(CborError);
            }
            let mut segs = Vec::with_capacity(k);
            for _ in 0..k {
                segs.push(tstr_bounded(d, MAX_SEGMENT)?);
            }
            Caveat::Res(segs)
        }
        (5, 2) => {
            let b = d.bstr()?;
            Caveat::Cnf(b.try_into().map_err(|_| CborError)?)
        }
        (6, 2) => {
            let t = d.uint()?;
            if t == 0 {
                return Err(CborError);
            }
            Caveat::Tenant(t)
        }
        (7, 3) => {
            let name = tstr_bounded(d, MAX_TOOL)?;
            let k = d.array()?;
            let mut cons = Vec::with_capacity(k);
            for _ in 0..k {
                if d.array()? != 2 {
                    return Err(CborError);
                }
                let key = tstr_bounded(d, MAX_ARGKEY)?;
                cons.push((key, decode_pred(d)?));
            }
            Caveat::Tool(name, cons)
        }
        (8, 2) => {
            let v = d.uint()?;
            if v > u64::from(MAX_DEPTH) {
                return Err(CborError);
            }
            Caveat::Depth(v as u8)
        }
        _ => return Err(CborError),
    };
    Ok(c)
}

// ------------------------------------------------------------------------------------------ semantics

/// `argsOk` (D4: a constraint on an absent argument denies). Lookup takes the first matching key, as `List.lookup`.
pub fn args_ok(r: &Req, cons: &[(String, ArgPred)]) -> bool {
    cons.iter().all(|(k, c)| match r.args.iter().find(|(rk, _)| rk == k) {
        Some((_, v)) => c.sat(v),
        None => false,
    })
}

/// `sat`.
pub fn sat(r: &Req, c: &Caveat) -> bool {
    match c {
        Caveat::Aud(a) => r.aud == *a,
        Caveat::Exp(e) => r.now < *e,
        Caveat::Nbf(n) => *n <= r.now,
        Caveat::Ops(m) => r.ops & u64::from(*m) == r.ops, // D2
        Caveat::Res(p) => r.res.starts_with(p),           // D1: segment-wise prefix
        Caveat::Cnf(j) => r.holder.as_slice() == j.as_slice(),
        Caveat::Tenant(t) => r.tenant == *t,
        Caveat::Tool(n, cons) => r.tool == *n && args_ok(r, cons),
        Caveat::Depth(_) => true, // structural; see `depth_ok`
    }
}

/// `denote`: the conjunction of EVERY caveat (never leaf-only).
pub fn denote(cs: &[Caveat], r: &Req) -> bool {
    cs.iter().all(|c| sat(r, c))
}

/// `effExp`: minimum over all exp caveats.
pub fn eff_exp(cs: &[Caveat]) -> Option<u64> {
    cs.iter().filter_map(|c| if let Caveat::Exp(e) = c { Some(*e) } else { None }).min()
}

/// `effDepth`: minimum over all depth caveats.
pub fn eff_depth(cs: &[Caveat]) -> Option<u8> {
    cs.iter().filter_map(|c| if let Caveat::Depth(d) = c { Some(*d) } else { None }).min()
}

/// `depthOk` (D3): caveats.len() ≤ 3 + effective depth; no depth caveat at all fails.
pub fn depth_ok(cs: &[Caveat]) -> bool {
    match eff_depth(cs) {
        Some(d) => cs.len() <= 3 + usize::from(d),
        None => false,
    }
}

/// F5 mint-shape check: the first three caveats are exactly [aud, exp, depth_left] (replaces `WellMinted`).
pub fn mint_shape_ok(cs: &[Caveat]) -> bool {
    matches!(cs, [Caveat::Aud(_), Caveat::Exp(_), Caveat::Depth(_), ..])
}
