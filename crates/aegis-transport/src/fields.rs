//! TBI-1: decoded field block ≤ `max_header_list_size` RFC bytes and ≤ `max_header_fields` fields, cookie
//! crumbs counted individually (RFC 9113 §8.2.3 allows a client to split `cookie` into crumbs, and an h1 client
//! can pack the same crumbs into one line; both count the same here).

/// RFC 9113 §6.5.2 per-field overhead.
pub const FIELD_OVERHEAD: u64 = 32;

/// Running size of one field block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FieldBlock {
    bytes: u64,
    count: u64,
}

/// Number of cookie crumbs in one `cookie` value (`;`-separated, empty crumbs ignored, at least one).
pub fn cookie_crumbs(value: &[u8]) -> u64 {
    let n = value.split(|&b| b == b';').filter(|c| c.iter().any(|&b| b != b' ' && b != b'\t')).count();
    u64::try_from(n.max(1)).unwrap_or(u64::MAX)
}

impl FieldBlock {
    pub const fn new() -> Self {
        Self { bytes: 0, count: 0 }
    }

    /// Account one field (pseudo-fields included, names as sent).
    pub fn add(&mut self, name: &[u8], value: &[u8]) {
        let len = u64::try_from(name.len().saturating_add(value.len())).unwrap_or(u64::MAX);
        self.bytes = self.bytes.saturating_add(len).saturating_add(FIELD_OVERHEAD);
        let n = if name.eq_ignore_ascii_case(b"cookie") { cookie_crumbs(value) } else { 1 };
        self.count = self.count.saturating_add(n);
    }

    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    pub const fn count(&self) -> u64 {
        self.count
    }

    /// `true` iff within both TBI-1 bounds.
    pub const fn within(&self, max_bytes: u64, max_fields: u64) -> bool {
        self.bytes <= max_bytes && self.count <= max_fields
    }
}

/// Field block of an `http` request head (h2: pseudo-fields are rebuilt from the parsed URI and method).
pub(crate) fn request_block<B>(req: &http::Request<B>, include_pseudo: bool) -> FieldBlock {
    let mut fb = FieldBlock::new();
    if include_pseudo {
        fb.add(b":method", req.method().as_str().as_bytes());
        if let Some(s) = req.uri().scheme_str() {
            fb.add(b":scheme", s.as_bytes());
        }
        if let Some(a) = req.uri().authority() {
            fb.add(b":authority", a.as_str().as_bytes());
        }
        let pq = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("");
        fb.add(b":path", pq.as_bytes());
    }
    for (name, value) in req.headers() {
        fb.add(name.as_str().as_bytes(), value.as_bytes());
    }
    fb
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn crumbs_and_bounds() {
        assert_eq!(cookie_crumbs(b"a=1"), 1);
        assert_eq!(cookie_crumbs(b"a=1; b=2;c=3"), 3);
        assert_eq!(cookie_crumbs(b""), 1);
        assert_eq!(cookie_crumbs(b"a=1; ; "), 1);
        let mut fb = FieldBlock::new();
        fb.add(b"Cookie", b"a=1; b=2");
        fb.add(b"x", b"y");
        assert_eq!(fb.count(), 3);
        assert_eq!(fb.bytes(), (6 + 8 + 32) + (1 + 1 + 32));
        assert!(fb.within(16_384, 3));
        assert!(!fb.within(16_384, 2));
        assert!(!fb.within(79, 128));
    }

    /// 129 single-crumb cookies in one h1 line exceed the 128-field cap although the block is tiny.
    #[test]
    fn crumb_line_counts_like_split_fields() {
        let v: Vec<u8> = (0..129).map(|i| format!("c{i}=1")).collect::<Vec<_>>().join("; ").into_bytes();
        let mut packed = FieldBlock::new();
        packed.add(b"cookie", &v);
        assert_eq!(packed.count(), 129);
        assert!(packed.bytes() < 16_384);
        assert!(!packed.within(16_384, 128));
    }
}
