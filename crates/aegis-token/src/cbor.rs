//! The deterministic CBOR subset F5 needs (RFC 8949 §4.2.1 core deterministic encoding).
//!
//! Supported: major types 0 (uint), 1 (nint), 2 (bstr), 3 (tstr, UTF-8 checked), 4 (array), 5 (map, length only),
//! 6 (tag number only). Everything is definite-length and shortest-form; the decoder rejects non-minimal heads,
//! indefinite lengths, reserved additional-info values, simple values and floats. Every read is bounds-checked
//! against the remaining input before any allocation, so the decoder is total: it returns `Err` on every input it
//! does not accept and never panics.

/// Decoder failure. Deliberately carries no detail: callers map it to a single fail-closed rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CborError;

pub(crate) const MAJ_UINT: u8 = 0;
pub(crate) const MAJ_NINT: u8 = 1;
pub(crate) const MAJ_BSTR: u8 = 2;
pub(crate) const MAJ_TSTR: u8 = 3;
pub(crate) const MAJ_ARRAY: u8 = 4;
pub(crate) const MAJ_MAP: u8 = 5;
pub(crate) const MAJ_TAG: u8 = 6;

/// Appends a definite-length head in shortest form.
pub(crate) fn put_head(out: &mut Vec<u8>, major: u8, v: u64) {
    let m = major << 5;
    if v < 24 {
        out.push(m | v as u8);
    } else if v <= u64::from(u8::MAX) {
        out.push(m | 24);
        out.push(v as u8);
    } else if v <= u64::from(u16::MAX) {
        out.push(m | 25);
        out.extend_from_slice(&(v as u16).to_be_bytes());
    } else if v <= u64::from(u32::MAX) {
        out.push(m | 26);
        out.extend_from_slice(&(v as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&v.to_be_bytes());
    }
}

pub(crate) fn put_uint(out: &mut Vec<u8>, v: u64) {
    put_head(out, MAJ_UINT, v);
}

pub(crate) fn put_int(out: &mut Vec<u8>, v: i64) {
    if v >= 0 {
        put_head(out, MAJ_UINT, v as u64);
    } else {
        // -1 - v without overflow: !v == -1 - v for two's complement.
        put_head(out, MAJ_NINT, !v as u64);
    }
}

pub(crate) fn put_bstr(out: &mut Vec<u8>, b: &[u8]) {
    put_head(out, MAJ_BSTR, b.len() as u64);
    out.extend_from_slice(b);
}

pub(crate) fn put_tstr(out: &mut Vec<u8>, s: &str) {
    put_head(out, MAJ_TSTR, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

pub(crate) fn put_array(out: &mut Vec<u8>, n: usize) {
    put_head(out, MAJ_ARRAY, n as u64);
}

/// A cursor over untrusted bytes.
#[derive(Debug)]
pub(crate) struct Dec<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Dec<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Fails unless every byte was consumed (no trailing data).
    pub(crate) fn finish(&self) -> Result<(), CborError> {
        if self.is_empty() { Ok(()) } else { Err(CborError) }
    }

    fn byte(&mut self) -> Result<u8, CborError> {
        let b = *self.buf.get(self.pos).ok_or(CborError)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        let end = self.pos.checked_add(n).ok_or(CborError)?;
        let s = self.buf.get(self.pos..end).ok_or(CborError)?;
        self.pos = end;
        Ok(s)
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Major type of the next item without consuming it.
    pub(crate) fn peek_major(&self) -> Result<u8, CborError> {
        self.buf.get(self.pos).map(|b| b >> 5).ok_or(CborError)
    }

    /// Reads a head, enforcing shortest form. Returns (major, argument).
    pub(crate) fn head(&mut self) -> Result<(u8, u64), CborError> {
        let ib = self.byte()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        let v = match ai {
            0..=23 => u64::from(ai),
            24 => {
                let v = u64::from(self.byte()?);
                if v < 24 {
                    return Err(CborError);
                }
                v
            }
            25 => {
                let s = self.take(2)?;
                let v = u64::from(u16::from_be_bytes(s.try_into().map_err(|_| CborError)?));
                if v <= u64::from(u8::MAX) {
                    return Err(CborError);
                }
                v
            }
            26 => {
                let s = self.take(4)?;
                let v = u64::from(u32::from_be_bytes(s.try_into().map_err(|_| CborError)?));
                if v <= u64::from(u16::MAX) {
                    return Err(CborError);
                }
                v
            }
            27 => {
                let s = self.take(8)?;
                let v = u64::from_be_bytes(s.try_into().map_err(|_| CborError)?);
                if v <= u64::from(u32::MAX) {
                    return Err(CborError);
                }
                v
            }
            _ => return Err(CborError), // 28..30 reserved, 31 indefinite
        };
        // Major 7 (floats, simple values) is outside the subset.
        if major == 7 {
            return Err(CborError);
        }
        Ok((major, v))
    }

    fn expect(&mut self, want: u8) -> Result<u64, CborError> {
        let (m, v) = self.head()?;
        if m == want { Ok(v) } else { Err(CborError) }
    }

    pub(crate) fn uint(&mut self) -> Result<u64, CborError> {
        self.expect(MAJ_UINT)
    }

    /// An integer restricted to the i64 range (the F5 subset for argument values).
    pub(crate) fn int(&mut self) -> Result<i64, CborError> {
        let (m, v) = self.head()?;
        match m {
            MAJ_UINT => i64::try_from(v).map_err(|_| CborError),
            MAJ_NINT => {
                let n = i64::try_from(v).map_err(|_| CborError)?;
                Ok(-1 - n)
            }
            _ => Err(CborError),
        }
    }

    pub(crate) fn bstr(&mut self) -> Result<&'a [u8], CborError> {
        let n = self.expect(MAJ_BSTR)?;
        let n = usize::try_from(n).map_err(|_| CborError)?;
        if n > self.remaining() {
            return Err(CborError);
        }
        self.take(n)
    }

    pub(crate) fn tstr(&mut self) -> Result<String, CborError> {
        let n = self.expect(MAJ_TSTR)?;
        let n = usize::try_from(n).map_err(|_| CborError)?;
        if n > self.remaining() {
            return Err(CborError);
        }
        let b = self.take(n)?;
        core::str::from_utf8(b).map(String::from).map_err(|_| CborError)
    }

    /// Array length, capped by the remaining input (each element needs at least one byte).
    pub(crate) fn array(&mut self) -> Result<usize, CborError> {
        let n = self.expect(MAJ_ARRAY)?;
        let n = usize::try_from(n).map_err(|_| CborError)?;
        if n > self.remaining() {
            return Err(CborError);
        }
        Ok(n)
    }

    pub(crate) fn map(&mut self) -> Result<usize, CborError> {
        let n = self.expect(MAJ_MAP)?;
        let n = usize::try_from(n).map_err(|_| CborError)?;
        if n.saturating_mul(2) > self.remaining() {
            return Err(CborError);
        }
        Ok(n)
    }

    pub(crate) fn tag(&mut self) -> Result<u64, CborError> {
        self.expect(MAJ_TAG)
    }
}
