//! Kani harnesses for aegis-wire (gate kani-wire; F1 PROXY-3, L4-1).
//!
//! P7-spec-002 skeleton: the harnesses below check the fail-closed stubs (every input refused, nothing consumed), so
//! `ci/kani.sh -p aegis-wire` runs end to end before the parsers exist. P7-wire-001 replaces them with the real
//! obligations: no panic, `consumed <= input.len()`, no read past the declared length, over symbolic inputs.
//!
//! The negative control is compiled only with `--cfg aegis_kani_negative`. It runs a planted copy of a length check
//! that reports one byte more than the input holds and asserts the bound. It must FAIL on its own "NEGATIVE CONTROL"
//! assertion, which shows the harness setup can go red.

// `kani` (and `aegis_kani_negative`) are not cfg names Cargo knows; see aegis-budget/src/kani_proofs.rs.
#![allow(unexpected_cfgs)]

#[cfg(kani)]
mod harnesses {
    use crate::proxy::{ProxyError, parse_v2};
    use crate::tls_peek::{PeekError, client_hello};

    /// Symbolic input bound for the stub harnesses.
    const N: usize = 64;

    #[kani::proof]
    fn proxy_stub_refuses_every_input() {
        let buf: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let input = buf.get(..len).unwrap_or(&[]);
        assert!(parse_v2(input) == Err(ProxyError::Unimplemented));
    }

    #[kani::proof]
    fn peek_stub_refuses_every_input() {
        let buf: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let input = buf.get(..len).unwrap_or(&[]);
        assert!(client_hello(input) == Err(PeekError::Unimplemented));
    }

    /// A planted copy of a consumed-length computation with an off-by-one (the bug class PROXY-3 / L4-1 bound).
    #[cfg(aegis_kani_negative)]
    fn planted_consumed(input: &[u8]) -> usize {
        input.len() + 1
    }

    #[kani::proof]
    fn negative_control_planted_oob() {
        #[cfg(aegis_kani_negative)]
        {
            let buf: [u8; 8] = kani::any();
            let len: usize = kani::any();
            kani::assume(len <= 8);
            let input = buf.get(..len).unwrap_or(&[]);
            let consumed = planted_consumed(input);
            assert!(consumed <= input.len(), "NEGATIVE CONTROL: consumed past the input");
        }
    }
}
