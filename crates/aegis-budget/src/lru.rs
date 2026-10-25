//! Bounded LRU key store (semantics 2 / I4: memory ≤ M, touch on lookup).
//!
//! O(log n) per operation: a `BTreeMap` from key to (value, stamp) and a `BTreeMap` from stamp to key, so eviction
//! of the least recently used entry is a `pop_first`. Stamps come from a checked counter; if it would ever
//! overflow, the stamps are renumbered densely instead (TBI-9).

use alloc::collections::BTreeMap;

/// Returned when a store of capacity 0 is asked to insert: there is no slot, and the caller must fail closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreFull;

#[derive(Debug)]
struct Slot<V> {
    val: V,
    stamp: u64,
}

/// LRU map with a hard capacity.
#[derive(Debug)]
pub struct LruStore<K, V> {
    cap: usize,
    map: BTreeMap<K, Slot<V>>,
    order: BTreeMap<u64, K>,
    clock: u64,
}

impl<K: Ord + Clone, V> LruStore<K, V> {
    /// An empty store holding at most `capacity` entries.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        LruStore { cap: capacity, map: BTreeMap::new(), order: BTreeMap::new(), clock: 0 }
    }

    /// Maximum number of entries.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Current number of entries (always ≤ capacity).
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True if the store holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn next_stamp(&mut self) -> u64 {
        if let Some(n) = self.clock.checked_add(1) {
            self.clock = n;
            return n;
        }
        // Renumber densely in current LRU order; then there is ample headroom again.
        let old = core::mem::take(&mut self.order);
        let mut n: u64 = 0;
        for (_, k) in old {
            n = n.saturating_add(1);
            if let Some(s) = self.map.get_mut(&k) {
                s.stamp = n;
            }
            self.order.insert(n, k);
        }
        self.clock = n.saturating_add(1);
        self.clock
    }

    /// Looks `key` up, touching it as most recently used. If absent, evicts least recently used entries until
    /// there is room and inserts `init()`. Returns the value and whether it was inserted by this call.
    ///
    /// # Errors
    /// [`StoreFull`] if the capacity is 0 (no entry can be held).
    pub fn get_or_insert_with(&mut self, key: K, init: impl FnOnce() -> V) -> Result<(&mut V, bool), StoreFull> {
        let stamp = self.next_stamp();
        let inserted = if let Some(slot) = self.map.get_mut(&key) {
            let old = core::mem::replace(&mut slot.stamp, stamp);
            self.order.remove(&old);
            self.order.insert(stamp, key.clone());
            false
        } else {
            if self.cap == 0 {
                return Err(StoreFull);
            }
            while self.map.len() >= self.cap {
                match self.order.pop_first() {
                    Some((_, victim)) => {
                        self.map.remove(&victim);
                    }
                    None => break,
                }
            }
            self.order.insert(stamp, key.clone());
            self.map.insert(key.clone(), Slot { val: init(), stamp });
            true
        };
        match self.map.get_mut(&key) {
            Some(slot) => Ok((&mut slot.val, inserted)),
            None => Err(StoreFull),
        }
    }

    /// Mutable access without inserting and without touching the LRU order.
    pub fn peek_mut(&mut self, key: &K) -> Option<&mut V> {
        self.map.get_mut(key).map(|s| &mut s.val)
    }

    /// Read access without touching the LRU order.
    #[must_use]
    pub fn peek(&self, key: &K) -> Option<&V> {
        self.map.get(key).map(|s| &s.val)
    }

    /// True if `key` is resident (no touch).
    #[must_use]
    pub fn contains(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testrng::Rng;
    use std::vec::Vec;

    #[test]
    fn evicts_lru_and_touches() {
        let mut s: LruStore<u32, u32> = LruStore::new(2);
        assert_eq!(s.get_or_insert_with(1, || 10).map(|(v, i)| (*v, i)), Ok((10, true)));
        assert_eq!(s.get_or_insert_with(2, || 20).map(|(v, i)| (*v, i)), Ok((20, true)));
        assert_eq!(s.get_or_insert_with(1, || 99).map(|(v, i)| (*v, i)), Ok((10, false)));
        assert!(s.get_or_insert_with(3, || 30).is_ok());
        assert!(s.contains(&1) && !s.contains(&2) && s.contains(&3));
        assert_eq!(s.len(), 2);
        // peek does not touch: 1 stays LRU after peeking it.
        assert_eq!(s.peek_mut(&1).map(|v| *v), Some(10));
        assert!(s.get_or_insert_with(3, || 0).is_ok());
        assert!(s.get_or_insert_with(4, || 40).is_ok());
        assert!(!s.contains(&1));
        let mut z: LruStore<u32, u32> = LruStore::new(0);
        assert_eq!(z.get_or_insert_with(1, || 1).map(|_| ()), Err(StoreFull));
        assert!(z.is_empty());
    }

    #[test]
    fn stamp_renumbering() {
        let mut s: LruStore<u32, u32> = LruStore::new(3);
        s.clock = u64::MAX - 2;
        for k in [1, 2, 3, 1, 4, 5] {
            assert!(s.get_or_insert_with(k, || k).is_ok());
        }
        assert!(s.contains(&1) && s.contains(&4) && s.contains(&5) && !s.contains(&2));
        assert_eq!(s.order.len(), s.map.len());
    }

    /// Differential test against a naive Vec-ordered LRU model.
    #[test]
    fn prop_matches_model() {
        let mut r = Rng::new(99);
        for _ in 0..200 {
            let cap = r.below(8) as usize;
            let mut s: LruStore<u64, u64> = LruStore::new(cap);
            let mut model: Vec<u64> = Vec::new(); // front = LRU
            for _ in 0..300 {
                let k = r.below(12);
                if r.below(4) == 0 {
                    assert_eq!(s.peek(&k).is_some(), model.contains(&k));
                    continue;
                }
                let res = s.get_or_insert_with(k, || k);
                if let Some(p) = model.iter().position(|&x| x == k) {
                    model.remove(p);
                    model.push(k);
                    assert_eq!(res.map(|(_, i)| i), Ok(false));
                } else if cap == 0 {
                    assert!(res.is_err());
                } else {
                    while model.len() >= cap {
                        model.remove(0);
                    }
                    model.push(k);
                    assert_eq!(res.map(|(_, i)| i), Ok(true));
                }
                assert!(s.len() <= cap);
                assert_eq!(s.len(), model.len());
                assert!(model.iter().all(|m| s.contains(m)));
            }
        }
    }
}
