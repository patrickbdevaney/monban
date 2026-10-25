//! RFC 6962 §2.1 Merkle tree hashing (leaf prefix 0x00, node prefix 0x01, SHA-256), the hash store behind the
//! tiles, and inclusion / consistency proofs (generation per RFC 6962 §2.1.1–2.1.2, verification per RFC 9162
//! §2.1.3.2 and §2.1.4.2).

use aws_lc_rs::digest;

/// A SHA-256 Merkle tree hash.
pub type Hash = [u8; 32];

fn finish(ctx: digest::Context) -> Hash {
    let d = ctx.finish();
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// `SHA-256(0x00 || leaf)`.
pub fn leaf_hash(leaf: &[u8]) -> Hash {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(&[0x00]);
    ctx.update(leaf);
    finish(ctx)
}

/// `SHA-256(0x01 || left || right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(&[0x01]);
    ctx.update(left);
    ctx.update(right);
    finish(ctx)
}

/// MTH of the empty tree: `SHA-256("")`.
pub fn empty_root() -> Hash {
    finish(digest::Context::new(&digest::SHA256))
}

/// Largest power of two strictly less than `n` (`n >= 2`).
fn split(n: u64) -> u64 {
    1u64 << (63 - (n - 1).leading_zeros())
}

/// Every complete-subtree hash of the tree: `level(k)[i] = MTH(D[i·2^k : (i+1)·2^k])`. Level 8·L holds exactly
/// the hashes of tile level L. Memory is about 2 × 32 bytes per leaf.
#[derive(Clone, Debug, Default)]
pub struct MerkleStore {
    levels: Vec<Vec<Hash>>,
}

impl MerkleStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of leaves.
    pub fn size(&self) -> u64 {
        self.levels.first().map_or(0, |l| l.len() as u64)
    }

    /// Appends a leaf hash and completes every subtree it closes.
    pub fn push_leaf(&mut self, h: Hash) {
        let mut carry = h;
        let mut level = 0usize;
        loop {
            if self.levels.len() <= level {
                self.levels.push(Vec::new());
            }
            let Some(row) = self.levels.get_mut(level) else { return };
            row.push(carry);
            if row.len() % 2 != 0 {
                return;
            }
            let (Some(r), Some(l)) = (row.last(), row.len().checked_sub(2).and_then(|i| row.get(i))) else {
                return;
            };
            carry = node_hash(l, r);
            level += 1;
        }
    }

    /// Hashes `[start, end)` of merkle level `level` (all present), for building tiles.
    pub fn level_range(&self, level: usize, start: u64, end: u64) -> Option<&[Hash]> {
        let row = self.levels.get(level)?;
        row.get(usize::try_from(start).ok()?..usize::try_from(end).ok()?)
    }

    fn get(&self, level: u32, index: u64) -> Option<Hash> {
        self.levels.get(level as usize)?.get(usize::try_from(index).ok()?).copied()
    }

    /// `MTH(D[start:end])`; `None` if the range is empty or beyond the current size.
    pub fn subtree(&self, start: u64, end: u64) -> Option<Hash> {
        if start >= end || end > self.size() {
            return None;
        }
        let n = end - start;
        if n.is_power_of_two() && start.is_multiple_of(n) {
            return self.get(n.trailing_zeros(), start >> n.trailing_zeros());
        }
        let k = split(n);
        Some(node_hash(&self.subtree(start, start + k)?, &self.subtree(start + k, end)?))
    }

    /// Root hash of the tree of `size` leaves (any `size <= self.size()`).
    pub fn root(&self, size: u64) -> Option<Hash> {
        if size == 0 { Some(empty_root()) } else { self.subtree(0, size) }
    }

    fn path(&self, m: u64, start: u64, end: u64, out: &mut Vec<Hash>) -> Option<()> {
        let n = end - start;
        if n <= 1 {
            return Some(());
        }
        let k = split(n);
        if m < k {
            self.path(m, start, start + k, out)?;
            out.push(self.subtree(start + k, end)?);
        } else {
            self.path(m - k, start + k, end, out)?;
            out.push(self.subtree(start, start + k)?);
        }
        Some(())
    }

    /// RFC 6962 `PATH(index, D[0:size])`.
    pub fn inclusion_proof(&self, index: u64, size: u64) -> Option<Vec<Hash>> {
        if index >= size || size > self.size() {
            return None;
        }
        let mut out = Vec::new();
        self.path(index, 0, size, &mut out)?;
        Some(out)
    }

    fn subproof(&self, m: u64, start: u64, end: u64, complete: bool, out: &mut Vec<Hash>) -> Option<()> {
        let n = end - start;
        if m == n {
            if !complete {
                out.push(self.subtree(start, end)?);
            }
            return Some(());
        }
        let k = split(n);
        if m <= k {
            self.subproof(m, start, start + k, complete, out)?;
            out.push(self.subtree(start + k, end)?);
        } else {
            self.subproof(m - k, start + k, end, false, out)?;
            out.push(self.subtree(start, start + k)?);
        }
        Some(())
    }

    /// RFC 6962 `PROOF(old, D[0:new])`; empty when `old == 0` or `old == new`.
    pub fn consistency_proof(&self, old: u64, new: u64) -> Option<Vec<Hash>> {
        if old > new || new > self.size() {
            return None;
        }
        let mut out = Vec::new();
        if old > 0 && old < new {
            self.subproof(old, 0, new, true, &mut out)?;
        }
        Some(out)
    }
}

/// RFC 9162 §2.1.3.2.
pub fn verify_inclusion(index: u64, size: u64, leaf: &Hash, proof: &[Hash], root: &Hash) -> bool {
    if index >= size {
        return false;
    }
    let (mut fn_, mut sn) = (index, size - 1);
    let mut r = *leaf;
    for p in proof {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node_hash(p, &r);
            while fn_ & 1 == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && r == *root
}

/// RFC 9162 §2.1.4.2.
pub fn verify_consistency(old: u64, new: u64, old_root: &Hash, new_root: &Hash, proof: &[Hash]) -> bool {
    if old > new {
        return false;
    }
    if old == new {
        return proof.is_empty() && old_root == new_root;
    }
    if old == 0 {
        return proof.is_empty() && *old_root == empty_root();
    }
    let mut path: Vec<Hash> = Vec::with_capacity(proof.len() + 1);
    if old.is_power_of_two() {
        path.push(*old_root);
    }
    path.extend_from_slice(proof);
    let Some((first, rest)) = path.split_first() else { return false };
    let (mut fn_, mut sn) = (old - 1, new - 1);
    while fn_ & 1 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }
    let (mut fr, mut sr) = (*first, *first);
    for c in rest {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            while fn_ & 1 == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    fr == *old_root && sr == *new_root && sn == 0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::encoding::hex_encode;

    /// Reference MTH straight from RFC 6962 §2.1, over leaf data.
    fn mth(d: &[Vec<u8>]) -> Hash {
        match d.len() {
            0 => empty_root(),
            1 => leaf_hash(&d[0]),
            n => {
                let k = split(n as u64) as usize;
                node_hash(&mth(&d[..k]), &mth(&d[k..]))
            }
        }
    }

    fn store(n: usize) -> (MerkleStore, Vec<Vec<u8>>) {
        let data: Vec<Vec<u8>> = (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect();
        let mut s = MerkleStore::new();
        for d in &data {
            s.push_leaf(leaf_hash(d));
        }
        (s, data)
    }

    #[test]
    fn rfc6962_known_vectors() {
        // Certificate Transparency reference test vectors (ct-go merkle tests): 8 leaves.
        let leaves: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x00],
            vec![0x10],
            vec![0x20, 0x21],
            vec![0x30, 0x31],
            vec![0x40, 0x41, 0x42, 0x43],
            vec![0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57],
            vec![0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f],
        ];
        let mut s = MerkleStore::new();
        for l in &leaves {
            s.push_leaf(leaf_hash(l));
        }
        assert_eq!(hex_encode(&s.root(0).unwrap()), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex_encode(&s.root(1).unwrap()), "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");
        assert_eq!(hex_encode(&s.root(8).unwrap()), "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328");
    }

    #[test]
    fn roots_match_reference() {
        let (s, data) = store(300);
        for n in 0..=300 {
            assert_eq!(s.root(n as u64).unwrap(), mth(&data[..n]), "size {n}");
        }
    }

    #[test]
    fn proofs_verify_and_reject() {
        let (s, data) = store(70);
        for n in 1..=70u64 {
            let root = s.root(n).unwrap();
            for i in 0..n {
                let p = s.inclusion_proof(i, n).unwrap();
                let lh = leaf_hash(&data[i as usize]);
                assert!(verify_inclusion(i, n, &lh, &p, &root), "incl {i}/{n}");
                assert!(!verify_inclusion(i, n, &leaf_hash(b"x"), &p, &root));
                if n > 1 {
                    assert!(
                        !verify_inclusion((i + 1) % n, n, &lh, &p, &root)
                            || data[((i + 1) % n) as usize] == data[i as usize]
                    );
                }
            }
            for m in 0..=n {
                let p = s.consistency_proof(m, n).unwrap();
                let old = s.root(m).unwrap();
                assert!(verify_consistency(m, n, &old, &root, &p), "cons {m}/{n}");
                if m > 0 && m < n {
                    let mut bad = old;
                    bad[0] ^= 1;
                    assert!(!verify_consistency(m, n, &bad, &root, &p));
                    assert!(!verify_consistency(m, n, &old, &bad, &p));
                }
            }
        }
        assert!(s.inclusion_proof(70, 70).is_none());
        assert!(s.root(71).is_none());
    }
}
