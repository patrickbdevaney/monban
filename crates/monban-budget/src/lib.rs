//! Sans-IO resource ledgers: RST bucket, GCRA, window/stream ledgers, per-request resource ledger (TBI-1..9).
//!
//! Everything here is pure: time is passed in as `u64` nanoseconds, nothing reads a clock or allocates per call
//! beyond the bounded key store. All arithmetic saturates or is checked (TBI-9: no counter overflow).
//! Spec: `spec/SPEC_INVARIANTS.md` §C, `oracles/admission-props/README.md` (normative semantics 1, 2, 6).
#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod bucket;
mod gcra;
mod kani_proofs; // Kani harnesses; the module body is #[cfg(kani)] (see kani_proofs.rs)
mod lru;

pub use bucket::{RST_BURST, RST_REFILL_PER_S, TokenBucket};
pub use gcra::{DEBIT_CAP_NS, Gcra};
pub use lru::{LruStore, StoreFull};

/// One second in nanoseconds.
pub const NS_PER_S: u64 = 1_000_000_000;

#[cfg(test)]
pub(crate) mod testrng {
    /// Small deterministic xorshift64* PRNG for property loops (no external crates).
    #[derive(Debug)]
    pub struct Rng(u64);
    impl Rng {
        pub fn new(seed: u64) -> Self {
            Rng(seed | 1)
        }
        pub fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        /// Uniform-ish value in `0..n` (`n > 0`); returns 0 for `n == 0`.
        pub fn below(&mut self, n: u64) -> u64 {
            if n == 0 { 0 } else { self.next() % n }
        }
    }
}
