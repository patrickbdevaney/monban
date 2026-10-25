//! Frozen interface F6: tri-state combiner and policy stage trait (see crate docs).

pub use aegis_types::Decision;

/// Allow iff `ds` is non-empty and every decision is `Allow`; otherwise Deny. Never returns `Error`.
pub fn combine(ds: &[Decision]) -> Decision {
    if ds.is_empty() {
        return Decision::Deny;
    }
    if ds.iter().all(|d| *d == Decision::Allow) { Decision::Allow } else { Decision::Deny }
}

/// A policy decision point stage. Implementations must be total; the host still treats any failure as `Error`.
pub trait PolicyStage {
    type Request;
    fn decide(&self, req: &Self::Request) -> Decision;
}

#[cfg(test)]
mod tests {
    use super::*;
    use Decision::*;

    // Mirrors combine_empty, combine_allow_iff, combine_ne_error over every list up to length 4.
    #[test]
    fn exhaustive_small_lists_match_lean_model() {
        let all = [Allow, Deny, Error];
        let mut stack: [Decision; 4] = [Allow; 4];
        for len in 0..=4usize {
            let n = 3usize.pow(len as u32);
            for mut code in 0..n {
                for slot in stack.iter_mut().take(len) {
                    *slot = all.get(code % 3).copied().unwrap_or(Error);
                    code /= 3;
                }
                let ds = stack.get(..len).unwrap_or(&[]);
                let got = combine(ds);
                let want = if !ds.is_empty() && ds.iter().all(|d| *d == Allow) { Allow } else { Deny };
                assert_eq!(got, want);
                assert_ne!(got, Error);
            }
        }
    }
}
