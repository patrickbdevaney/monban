//! Shared helpers for the AEGIS fuzz targets (fuzz workspace only; nothing here ships).
//!
//! Every target must be total on its own: it may only fail through an `assert!` of a property of the code under
//! test (or through a panic inside that code). Structured inputs are drawn with `arbitrary::Unstructured`, whose
//! getters never panic and fall back to defaults when the input runs out.
#![forbid(unsafe_code)]

pub use libfuzzer_sys::arbitrary::Unstructured;

/// The planted panic of `ci/fuzz.sh self-test`. Compiled only with `--cfg fuzzing_selftest`, which only the
/// self-test build sets; the normal fuzz build and every shipped crate never contain it. The marker string is what
/// `ci/fuzz.sh self-test` looks for in the crash report.
#[macro_export]
macro_rules! selftest {
    ($cond:expr) => {
        #[cfg(fuzzing_selftest)]
        {
            if $cond {
                panic!("AEGIS_FUZZ_SELFTEST planted panic reached");
            }
        }
    };
}

/// A byte from the input (0 when exhausted).
pub fn byte(u: &mut Unstructured<'_>) -> u8 {
    u.arbitrary::<u8>().unwrap_or(0)
}

/// A u64 from the input (0 when exhausted).
pub fn u64_(u: &mut Unstructured<'_>) -> u64 {
    u.arbitrary::<u64>().unwrap_or(0)
}

/// A bool from the input.
pub fn flag(u: &mut Unstructured<'_>) -> bool {
    byte(u) & 1 == 1
}

/// Up to `max` bytes from the input.
pub fn bytes<'a>(u: &mut Unstructured<'a>, max: usize) -> &'a [u8] {
    let n = usize::from(byte(u)) % max.saturating_add(1);
    u.bytes(n.min(u.len())).unwrap_or(&[])
}

/// A string of at most `max` bytes drawn from `alphabet` (non-empty unless `max == 0` or `alphabet` is empty is
/// not guaranteed: callers that need non-empty strings check).
pub fn string_from(u: &mut Unstructured<'_>, max: usize, alphabet: &[u8]) -> String {
    let n = usize::from(byte(u)) % max.saturating_add(1);
    let mut s = String::with_capacity(n);
    if alphabet.is_empty() {
        return s;
    }
    for _ in 0..n {
        let i = usize::from(byte(u)) % alphabet.len();
        if let Some(&c) = alphabet.get(i) {
            s.push(char::from(c));
        }
    }
    s
}

/// Lossy UTF-8 string of at most `max` input bytes (any Unicode, including controls).
pub fn any_string(u: &mut Unstructured<'_>, max: usize) -> String {
    String::from_utf8_lossy(bytes(u, max)).into_owned()
}

pub const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
pub const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
