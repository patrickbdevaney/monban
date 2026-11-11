//! Minimal Unicode support over the generated tables: an exact NFC check (decompose, canonical order, compose,
//! compare), the L/M/N general-category set and "lowercasing changes this code point". No mapping is ever applied
//! to an identity; these are only validity filters.

use alloc::vec::Vec;

use crate::unicode_tables::{CCC, COMPOSE, DECOMP, LMN, LOWER_CHANGES};

const S_BASE: u32 = 0xAC00;
const L_BASE: u32 = 0x1100;
const V_BASE: u32 = 0x1161;
const T_BASE: u32 = 0x11A7;
const L_COUNT: u32 = 19;
const V_COUNT: u32 = 21;
const T_COUNT: u32 = 28;
const N_COUNT: u32 = V_COUNT * T_COUNT;
const S_COUNT: u32 = L_COUNT * N_COUNT;

fn in_ranges(t: &[(u32, u32)], c: u32) -> bool {
    t.binary_search_by(|&(lo, hi)| {
        if hi < c {
            core::cmp::Ordering::Less
        } else if lo > c {
            core::cmp::Ordering::Greater
        } else {
            core::cmp::Ordering::Equal
        }
    })
    .is_ok()
}

pub(crate) fn is_lmn(c: char) -> bool {
    in_ranges(LMN, u32::from(c))
}

pub(crate) fn lowercase_changes(c: char) -> bool {
    in_ranges(LOWER_CHANGES, u32::from(c))
}

fn ccc(c: u32) -> u8 {
    CCC.binary_search_by(|&(lo, hi, _)| {
        if hi < c {
            core::cmp::Ordering::Less
        } else if lo > c {
            core::cmp::Ordering::Greater
        } else {
            core::cmp::Ordering::Equal
        }
    })
    .ok()
    .and_then(|i| CCC.get(i))
    .map_or(0, |&(_, _, k)| k)
}

/// Full canonical decomposition of one code point (iterative; table depth is small).
fn decompose_into(c: u32, out: &mut Vec<u32>) {
    let mut stack: Vec<u32> = Vec::with_capacity(4);
    stack.push(c);
    while let Some(x) = stack.pop() {
        if (S_BASE..S_BASE + S_COUNT).contains(&x) {
            let s = x - S_BASE;
            out.push(L_BASE + s / N_COUNT);
            out.push(V_BASE + (s % N_COUNT) / T_COUNT);
            let t = s % T_COUNT;
            if t != 0 {
                out.push(T_BASE + t);
            }
            continue;
        }
        match DECOMP.binary_search_by_key(&x, |&(cp, _, _)| cp).ok().and_then(|i| DECOMP.get(i)) {
            Some(&(_, a, 0)) => stack.push(a),
            Some(&(_, a, b)) => {
                stack.push(b);
                stack.push(a);
            }
            None => out.push(x),
        }
    }
}

fn compose_pair(a: u32, b: u32) -> Option<u32> {
    if (L_BASE..L_BASE + L_COUNT).contains(&a) && (V_BASE..V_BASE + V_COUNT).contains(&b) {
        return Some(S_BASE + ((a - L_BASE) * V_COUNT + (b - V_BASE)) * T_COUNT);
    }
    if (S_BASE..S_BASE + S_COUNT).contains(&a)
        && (a - S_BASE).is_multiple_of(T_COUNT)
        && (T_BASE + 1..T_BASE + T_COUNT).contains(&b)
    {
        return Some(a + (b - T_BASE));
    }
    COMPOSE.binary_search_by(|&(x, y, _)| (x, y).cmp(&(a, b))).ok().and_then(|i| COMPOSE.get(i)).map(|&(_, _, c)| c)
}

fn nfc(chars: impl Iterator<Item = char>) -> Vec<u32> {
    let mut d: Vec<u32> = Vec::new();
    for c in chars {
        decompose_into(u32::from(c), &mut d);
    }
    // Canonical ordering: stable sort of every maximal run of non-starters by combining class.
    let mut i = 0usize;
    while i < d.len() {
        if d.get(i).is_some_and(|&c| ccc(c) != 0) {
            let start = i;
            while d.get(i).is_some_and(|&c| ccc(c) != 0) {
                i = i.saturating_add(1);
            }
            if let Some(run) = d.get_mut(start..i) {
                run.sort_by_key(|&c| ccc(c)); // stable
            }
        } else {
            i = i.saturating_add(1);
        }
    }
    // Canonical composition (UAX #15).
    let mut out: Vec<u32> = Vec::with_capacity(d.len());
    let mut it = d.into_iter();
    let Some(first) = it.next() else {
        return out;
    };
    out.push(first);
    let mut starter_pos = 0usize;
    let mut last_class: u16 = match ccc(first) {
        0 => 0,
        _ => 256,
    };
    for ch in it {
        let ch_class = u16::from(ccc(ch));
        let starter = out.get(starter_pos).copied();
        if let Some(st) = starter
            && (last_class < ch_class || last_class == 0)
            && let Some(comp) = compose_pair(st, ch)
            && let Some(slot) = out.get_mut(starter_pos)
        {
            *slot = comp;
            continue;
        }
        if ch_class == 0 {
            starter_pos = out.len();
        }
        last_class = ch_class;
        out.push(ch);
    }
    out
}

/// True iff `chars` is already in Normalization Form C.
pub(crate) fn is_nfc_chars(chars: &[char]) -> bool {
    if chars.iter().all(|&c| u32::from(c) < 0x300) {
        return true;
    }
    let n = nfc(chars.iter().copied());
    n.len() == chars.len() && n.iter().zip(chars).all(|(&a, &b)| a == u32::from(b))
}

/// True iff `s` is already in Normalization Form C.
pub(crate) fn is_nfc(s: &str) -> bool {
    if s.chars().all(|c| u32::from(c) < 0x300) {
        return true;
    }
    let n = nfc(s.chars());
    n.iter().copied().eq(s.chars().map(u32::from))
}
