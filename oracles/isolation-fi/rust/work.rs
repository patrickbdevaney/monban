// Shared request work (identical in guest and driver): FNV-style mixing over the 4 KiB data blob, ROUNDS passes.
// Ported from research/state/raw/round-004/04-work/fi/common/work.rs (fault codes extended with F_HOSTABORT).
#![allow(dead_code)]
pub const ROUNDS: u32 = 8;
pub const GOOD_SALT: u32 = 0x5a17_c0de;
pub const BAD_SALT: u32 = 0xdead_beef;
pub const F_NONE: u32 = 0;
pub const F_PANIC: u32 = 1;
pub const F_ABORT: u32 = 2;
pub const F_SEGV: u32 = 3;
pub const F_LOOP: u32 = 4;
pub const F_OOM: u32 = 5;
pub const F_FDLEAK: u32 = 6; // not expressible by an M0 guest (no fd imports); kept for code parity
pub const F_POISON: u32 = 7;
pub const F_HOSTABORT: u32 = 8;
#[inline(never)]
pub fn work(id: u32, salt: u32, data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5 ^ salt ^ id.wrapping_mul(2654435761);
    for r in 0..ROUNDS {
        for &b in data {
            h = (h ^ b as u32).wrapping_mul(16777619);
        }
        h = h.rotate_left(5) ^ r;
    }
    h
}
