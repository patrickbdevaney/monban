//! c2sp.org/tlog-tiles@v1 resource paths: `tile/<L>/<N>[.p/<W>]` and `tile/entries/<N>[.p/<W>]`.

/// Tile height (hashes per full tile = 2^8).
pub const TILE_HEIGHT: u32 = 8;
/// Hashes (or entries) per full tile.
pub const TILE_WIDTH: u64 = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TileKind {
    /// Merkle tree tile at tile level `L` (0..=63).
    Hash(u8),
    /// Entry bundle.
    Entries,
}

/// One immutable resource. `width == 256` is a full tile; 1..=255 a partial one (`.p/<W>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TilePath {
    pub kind: TileKind,
    pub index: u64,
    pub width: u16,
}

impl TilePath {
    pub fn is_full(&self) -> bool {
        u64::from(self.width) == TILE_WIDTH
    }

    /// Relative path, e.g. `tile/0/x001/x234/067.p/12`.
    pub fn to_path(&self) -> String {
        let mut s = String::from("tile/");
        match self.kind {
            TileKind::Hash(l) => s.push_str(&l.to_string()),
            TileKind::Entries => s.push_str("entries"),
        }
        s.push('/');
        s.push_str(&encode_index(self.index));
        if !self.is_full() {
            s.push_str(&format!(".p/{}", self.width));
        }
        s
    }
}

/// Zero-padded 3-digit groups, all but the last prefixed with `x`: 1234067 → `x001/x234/067`.
pub fn encode_index(n: u64) -> String {
    let mut groups = Vec::new();
    let mut v = n;
    loop {
        groups.push(v % 1000);
        v /= 1000;
        if v == 0 {
            break;
        }
    }
    let mut out = String::new();
    for (i, g) in groups.iter().rev().enumerate() {
        if i > 0 {
            out.push('/');
        }
        if i + 1 < groups.len() {
            out.push('x');
        }
        out.push_str(&format!("{g:03}"));
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(encode_index(1_234_067), "x001/x234/067");
        assert_eq!(encode_index(0), "000");
        assert_eq!(encode_index(1000), "x001/000");
        let t = TilePath { kind: TileKind::Hash(1), index: 5, width: 17 };
        assert_eq!(t.to_path(), "tile/1/005.p/17");
        let e = TilePath { kind: TileKind::Entries, index: 273, width: 256 };
        assert_eq!(e.to_path(), "tile/entries/273");
    }
}
