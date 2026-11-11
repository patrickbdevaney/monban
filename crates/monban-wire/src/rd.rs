//! A bounds-checked forward reader over a byte slice (no indexing, no panics, no allocation).
//!
//! Every read either returns the bytes it promised or `None`, and never looks past the slice it was given. The parsers
//! hand it exactly the declared region (PROXY header, TLS record body, extension body), so "no read past the declared
//! length" holds by construction: the reader cannot see beyond it.

#[derive(Clone, Copy, Debug)]
pub(crate) struct Rd<'a> {
    rest: &'a [u8],
}

impl<'a> Rd<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Rd { rest: b }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// The bytes not read yet.
    pub(crate) fn rest(&self) -> &'a [u8] {
        self.rest
    }

    pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.rest.split_at_checked(n)?;
        self.rest = tail;
        Some(head)
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        let (&b, tail) = self.rest.split_first()?;
        self.rest = tail;
        Some(b)
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        let a: [u8; 2] = b.try_into().ok()?;
        Some(u16::from_be_bytes(a))
    }

    pub(crate) fn u24(&mut self) -> Option<usize> {
        let b = self.take(3)?;
        let a: [u8; 3] = b.try_into().ok()?;
        let [x, y, z] = a;
        Some((usize::from(x) << 16) | (usize::from(y) << 8) | usize::from(z))
    }

    /// A vector with a one-byte length prefix.
    pub(crate) fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()?;
        self.take(usize::from(n))
    }

    /// A vector with a two-byte length prefix.
    pub(crate) fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.take(usize::from(n))
    }
}
