//! RFC 3492 Punycode (Bootstring with the Punycode parameters), used only for the structural A-label check.
//! All arithmetic is checked; any overflow, invalid digit, truncated number or out-of-range code point is a decode
//! failure.

use alloc::vec::Vec;

const BASE: u64 = 36;
const TMIN: u64 = 1;
const TMAX: u64 = 26;
const SKEW: u64 = 38;
const DAMP: u64 = 700;
const INITIAL_BIAS: u64 = 72;
const INITIAL_N: u32 = 0x80;

fn adapt(delta: u64, numpoints: u64, first: bool) -> u64 {
    let mut delta = if first { delta / DAMP } else { delta / 2 };
    delta = delta.saturating_add(delta / numpoints.max(1));
    let mut k = 0u64;
    while delta > ((BASE - TMIN) * TMAX) / 2 {
        delta /= BASE - TMIN;
        k = k.saturating_add(BASE);
    }
    k.saturating_add(((BASE - TMIN + 1) * delta) / (delta.saturating_add(SKEW)))
}

fn threshold(k: u64, bias: u64) -> u64 {
    k.saturating_sub(bias).clamp(TMIN, TMAX)
}

fn digit_value(b: u8) -> Option<u64> {
    match b {
        b'a'..=b'z' => Some(u64::from(b - b'a')),
        b'A'..=b'Z' => Some(u64::from(b - b'A')),
        b'0'..=b'9' => Some(u64::from(b - b'0') + 26),
        _ => None,
    }
}

fn digit_char(d: u64) -> Option<u8> {
    match d {
        0..=25 => u8::try_from(d).ok().map(|v| b'a' + v),
        26..=35 => u8::try_from(d - 26).ok().map(|v| b'0' + v),
        _ => None,
    }
}

/// Decode an ACE suffix (without `xn--`) to code points.
pub(crate) fn decode(input: &[u8]) -> Option<Vec<char>> {
    let empty: &[u8] = &[];
    let (basic, ext) = match input.iter().rposition(|&b| b == b'-') {
        Some(p) => (input.get(..p)?, input.get(p.checked_add(1)?..)?),
        None => (empty, input),
    };
    if !basic.is_ascii() {
        return None;
    }
    let mut out: Vec<char> = basic.iter().map(|&b| char::from(b)).collect();
    let mut n = u64::from(INITIAL_N);
    let mut i = 0u64;
    let mut bias = INITIAL_BIAS;
    let mut it = ext.iter();
    let mut first = true;
    while !it.as_slice().is_empty() {
        let oldi = i;
        let mut w = 1u64;
        let mut k = BASE;
        loop {
            let d = digit_value(*it.next()?)?;
            i = i.checked_add(d.checked_mul(w)?)?;
            let t = threshold(k, bias);
            if d < t {
                break;
            }
            w = w.checked_mul(BASE - t)?;
            k = k.checked_add(BASE)?;
        }
        let len1 = u64::try_from(out.len()).ok()?.checked_add(1)?;
        bias = adapt(i - oldi, len1, first);
        first = false;
        n = n.checked_add(i / len1)?;
        i %= len1;
        let c = char::from_u32(u32::try_from(n).ok()?)?;
        let at = usize::try_from(i).ok()?;
        if at > out.len() {
            return None;
        }
        out.insert(at, c);
        i = i.checked_add(1)?;
    }
    Some(out)
}

/// Encode code points to an ACE suffix (lowercase digits), exactly as RFC 3492 section 6.3.
pub(crate) fn encode(input: &[char]) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = input.iter().filter(|c| c.is_ascii()).map(|&c| c as u8).collect();
    let b = u64::try_from(out.len()).ok()?;
    let total = u64::try_from(input.len()).ok()?;
    let mut h = b;
    if b > 0 {
        out.push(b'-');
    }
    let mut n = u64::from(INITIAL_N);
    let mut delta = 0u64;
    let mut bias = INITIAL_BIAS;
    while h < total {
        let m = input.iter().map(|&c| u64::from(u32::from(c))).filter(|&c| c >= n).min()?;
        delta = delta.checked_add((m - n).checked_mul(h.checked_add(1)?)?)?;
        n = m;
        for &c in input {
            let c = u64::from(u32::from(c));
            if c < n {
                delta = delta.checked_add(1)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = threshold(k, bias);
                    if q < t {
                        break;
                    }
                    out.push(digit_char(t + (q - t) % (BASE - t))?);
                    q = (q - t) / (BASE - t);
                    k = k.checked_add(BASE)?;
                }
                out.push(digit_char(q)?);
                bias = adapt(delta, h.checked_add(1)?, h == b);
                delta = 0;
                h = h.checked_add(1)?;
            }
        }
        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }
    Some(out)
}
