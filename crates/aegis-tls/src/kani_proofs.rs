//! Kani harnesses for the 0x11ED share parsing in `kx.rs` (unit P6-kani-001; PLAN-6 D5, ARCHITECTURE §3.2).
//!
//! Compiled only under `cfg(kani)` (lib.rs: `#[cfg(kani)] mod kani_proofs;`) and run by
//! `ci/kani.sh --crate aegis-tls --neg negative_control_indexing_split` on the prover box.
//!
//! What runs is the real code, not a copy:
//! - `split_share_any_input` calls the private `kx::split_share` itself. A module next to `kx` cannot name a
//!   private fn, so the harness calls a local placeholder with the same signature and replaces it with
//!   `crate::kx::split_share` through `kani::stub`. The placeholder always errors, so if the stub did not take
//!   effect the `cover!` on the Ok branch would be unsatisfied and the gate would FAIL.
//! - `server_start_and_complete_any_share` drives the public server entry point
//!   `SecP384r1MlKem1024::start_and_complete` (rustls calls it with the ClientHello share).
//!
//! The input is a symbolic byte array of `SERVER_SHARE_LEN + 1` (1666) bytes with a symbolic length `0..=1666`,
//! so every length from empty to one byte too long is covered, with every byte value. Kani's default checks
//! (out-of-bounds, arithmetic overflow, every panic) run on each line reached. Both harnesses prove there is no
//! panic and that every wrong total length and every non-uncompressed point prefix yields
//! `Err(PeerMisbehaved::InvalidKeyShare)` (rustls alert 47).
//!
//! aws-lc is C behind FFI, which Kani does not execute. Share parsing is pure Rust and happens before the first
//! aws-lc call. In `start_and_complete` that first call is `kem::EncapsulationKey::new`, which is stubbed. The
//! stub asserts it is handed exactly `MLKEM1024_EK_LEN` bytes and then rejects the key, so the remaining aws-lc
//! calls are never reached.
//!
//! The client side, `Active::complete`, is not driven directly. Every `Active` constructor generates or imports
//! keys in aws-lc (opaque C handles with no Rust-side constructor, and the crate forbids `unsafe`). Its parse step
//! is its first statement, `split_share(server_share, MLKEM1024_CT_LEN)?`. `split_share_any_input` verifies
//! exactly that call, for `pq_len = MLKEM1024_CT_LEN` and `pq_len = MLKEM1024_EK_LEN`. The step from that harness
//! to `complete` is argued from the code, not checked by Kani.
//!
//! The negative control, `negative_control_indexing_split`, runs the same property over `indexing_split`, a
//! deliberately broken copy that indexes and slices instead of checking the length. It must FAIL. Kani reports
//! the out-of-bounds slice for short shares and the "NEGATIVE CONTROL" assertion for an over-long share that the
//! copy accepts. That shows the harness can go red on both obligations.
//!
//! # Client side (unit P8-kani-001, gate kani-kx-client: `ci/kani.sh -p aegis-tls --only client_`)
//!
//! The `client_*` harnesses cover what a client does with a received ServerHello share, on the real Rust code:
//! - `client_server_share_split_0x11ed`: `kx::split_share(share, MLKEM1024_CT_LEN)`, the first statement of
//!   `Active::complete`, on every server share of length 0..=1666 and every byte value. No panic; Ok exactly for a
//!   1665-byte share with an uncompressed point; then the point is the 97-byte prefix and the decapsulation input
//!   (the `kem::Ciphertext` that `complete` hands to `decapsulate`) is exactly the 1568-byte rest.
//! - `client_negative_control_planted_oob`: the client split property over `planted_oob_client_split`, a copy with
//!   a planted out-of-bounds slice and no length check. It must FAIL (the OOB, and the "NEGATIVE CONTROL" assertion
//!   for an over-long share it accepts).
//!
//! Not checked by Kani here (rung: argued from the code, or trusted), see units/phase-8/patches/P8-kani-001.*:
//! - The 0x11ED client share encoding (`Active::new`, 97 + 1568 = 1665 bytes) and the call composition inside
//!   `Active::complete`. Every `Active` holds aws-lc key handles, which no Rust code can build (the crate forbids
//!   `unsafe`, so a stub cannot write C out-parameters). The patch moves the encoding and the point check into pure
//!   functions and adds their harnesses.
//! - 0x11EB (rustls `Hybrid`, SecP256r1MLKEM768): a harness through `Hybrid::start_and_complete` was tried. It
//!   would run rustls' `Layout::split` with the aws-lc keygen stubbed. It was oom-killed at the gate's 6G limit
//!   twice, the second time with `unwind(4)` and fixed bytes. CBMC expands rustls' `dyn ActiveKeyExchange` calls
//!   to every impl, and `ActiveHybrid` recurses through `dyn`. So 0x11EB is not covered.
//! - 0x11EB client `complete` with the server length (1088) and 0x0202 (MLKEM1024) client `complete`: rustls'
//!   `ActiveHybrid` / `mlkem::Active` are only built by aws-lc keygen. rustls' 0x0202 client hands the server share
//!   to `DecapsulationKey::decapsulate` without a Rust-side length check (aws-lc-rs 1.18.2 has none either), so the
//!   ciphertext length bound for 0x0202 is enforced only in AWS-LC C (trusted, not verified).

mod harnesses {
    use aws_lc_rs::error::KeyRejected;
    use aws_lc_rs::kem::{Algorithm, AlgorithmIdentifier, Ciphertext, EncapsulationKey};
    use rustls::crypto::{CompletedKeyExchange, SupportedKxGroup};
    use rustls::{Error, PeerMisbehaved};

    use crate::kx::{
        CLIENT_SHARE_LEN, MLKEM1024_CT_LEN, MLKEM1024_EK_LEN, P384_SHARE_LEN, SERVER_SHARE_LEN, SecP384r1MlKem1024,
    };

    /// Longest share any harness feeds in: one byte past the server share.
    const MAX: usize = SERVER_SHARE_LEN + 1;
    const UNCOMPRESSED: u8 = 0x04;

    // `split_share_any_input` covers the client parse only because the client calls `split_share` with
    // `MLKEM1024_CT_LEN` and the harness also picks that value. MAX reaches past the client share as well.
    const _: () = assert!(CLIENT_SHARE_LEN == P384_SHARE_LEN + MLKEM1024_EK_LEN);
    const _: () = assert!(SERVER_SHARE_LEN == P384_SHARE_LEN + MLKEM1024_CT_LEN);
    const _: () = assert!(MAX > CLIENT_SHARE_LEN && MAX > SERVER_SHARE_LEN);

    fn is_invalid_key_share<T>(r: &Result<T, Error>) -> bool {
        matches!(r, Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)))
    }

    /// Placeholder with `kx::split_share`'s signature. Every harness that calls it stubs it with the real fn.
    fn split_share_real(_share: &[u8], _pq_len: usize) -> Result<(&[u8], &[u8]), Error> {
        Err(Error::General(String::new()))
    }

    /// Stub for the first aws-lc call in `start_and_complete`. It checks that the parse handed over exactly the
    /// ML-KEM-1024 encapsulation key, then rejects it (the real `new` would reject a wrong length too).
    fn ek_new_stub<Id: AlgorithmIdentifier>(
        _alg: &'static Algorithm<Id>,
        bytes: &[u8],
    ) -> Result<EncapsulationKey<Id>, KeyRejected> {
        assert!(bytes.len() == MLKEM1024_EK_LEN, "parse hands aws-lc exactly the 1568-byte encapsulation key");
        kani::cover!(true, "an exact, uncompressed share reaches aws-lc");
        Err(KeyRejected::from(()))
    }

    /// The property both `split_share` harnesses (and the negative control) check, for one call
    /// `split(share, pq_len) = r`. Evaluates to whether `r` is Ok; fails an assertion on violation. A macro so the
    /// assertion text is a literal (Kani does not render runtime-formatted messages, and ci/kani.sh greps the
    /// negative control's text).
    macro_rules! check_split {
        ($share:expr, $pq_len:expr, $r:expr, $tag:literal) => {{
            let (share, pq_len, r): (&[u8], usize, &Result<(&[u8], &[u8]), Error>) = ($share, $pq_len, $r);
            let exact = share.len() == P384_SHARE_LEN + pq_len;
            let prefix_ok = share.first() == Some(&UNCOMPRESSED);
            match r {
                Ok((ecdh, pq)) => {
                    assert!(exact, concat!($tag, ": Ok only for the exact length"));
                    assert!(prefix_ok, concat!($tag, ": Ok only for an uncompressed point"));
                    assert!(ecdh.len() == P384_SHARE_LEN && pq.len() == pq_len, concat!($tag, ": half lengths"));
                    assert!(ecdh.as_ptr() == share.as_ptr(), concat!($tag, ": point is the prefix"));
                    assert!(
                        pq.as_ptr() == share.as_ptr().wrapping_add(P384_SHARE_LEN),
                        concat!($tag, ": ML-KEM part follows the point")
                    );
                    true
                }
                Err(_) => {
                    assert!(is_invalid_key_share(r), concat!($tag, ": errors are InvalidKeyShare"));
                    assert!(!(exact && prefix_ok), concat!($tag, ": a well-formed share is not rejected"));
                    false
                }
            }
        }};
    }

    /// `kx::split_share` on every share of length 0..=1666 and every byte value, for both lengths the code uses
    /// (`MLKEM1024_EK_LEN` from `start_and_complete`, `MLKEM1024_CT_LEN` from `complete`). No panic. Ok exactly
    /// when the length is exact and the point is uncompressed, and then the halves are the exact 97 / pq_len
    /// subslices of the input. Every other input is `InvalidKeyShare`.
    #[kani::proof]
    #[kani::stub(split_share_real, crate::kx::split_share)]
    fn split_share_any_input() {
        let buf: [u8; MAX] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX);
        let Some(share) = buf.get(..len) else { return };
        let pq_len = if kani::any() { MLKEM1024_EK_LEN } else { MLKEM1024_CT_LEN };
        let r = split_share_real(share, pq_len);
        let ok = check_split!(share, pq_len, &r, "split_share contract");
        kani::cover!(ok, "an exact share parses (the stub to kx::split_share took effect)");
        kani::cover!(!ok && len == P384_SHARE_LEN + pq_len, "exact length, bad prefix");
        kani::cover!(!ok && len < P384_SHARE_LEN, "shorter than the point");
        kani::cover!(!ok && len == MAX, "one byte too long");
        // Not dropped: the drop glue of a symbolic `rustls::Error` loops over its Vec variants (unbounded unwind).
        core::mem::forget(r);
    }

    /// The server entry point on every client share of length 0..=1666 and every byte value. No panic before
    /// aws-lc. Every wrong length and every bad prefix is `InvalidKeyShare` without touching aws-lc. An exact,
    /// uncompressed share reaches aws-lc with exactly the 1568-byte encapsulation key (asserted in the stub).
    #[kani::proof]
    #[kani::stub(aws_lc_rs::kem::EncapsulationKey::new, ek_new_stub)]
    fn server_start_and_complete_any_share() {
        let buf: [u8; MAX] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX);
        let Some(share) = buf.get(..len) else { return };
        let r: Result<CompletedKeyExchange, Error> = SecP384r1MlKem1024.start_and_complete(share);
        // Wrong length or prefix: rejected by the parse. Exact share: rejected by the stub, mapped to the same error.
        assert!(is_invalid_key_share(&r), "every share the stubbed path sees is InvalidKeyShare");
        kani::cover!(len != CLIENT_SHARE_LEN, "wrong length");
        kani::cover!(len == CLIENT_SHARE_LEN && share.first() != Some(&UNCOMPRESSED), "exact length, bad prefix");
        core::mem::forget(r); // see split_share_any_input
    }

    /// Deliberately broken copy of `split_share`: indexes and slices, no total-length check.
    #[allow(clippy::indexing_slicing)]
    fn indexing_split(share: &[u8], pq_len: usize) -> Result<(&[u8], &[u8]), Error> {
        let ecdh = &share[..P384_SHARE_LEN];
        let pq = &share[P384_SHARE_LEN..P384_SHARE_LEN + pq_len];
        if share[0] != UNCOMPRESSED {
            return Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare));
        }
        Ok((ecdh, pq))
    }

    /// Negative control: `split_share_any_input`'s property over `indexing_split`. It must FAIL: the slice is
    /// out of bounds below 97 + pq_len bytes, and a 1666-byte share is accepted.
    #[kani::proof]
    fn negative_control_indexing_split() {
        let buf: [u8; MAX] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX);
        let Some(share) = buf.get(..len) else { return };
        let pq_len = if kani::any() { MLKEM1024_EK_LEN } else { MLKEM1024_CT_LEN };
        let r = indexing_split(share, pq_len);
        let _ = check_split!(share, pq_len, &r, "NEGATIVE CONTROL: indexing copy broke the split_share contract");
        core::mem::forget(r); // see split_share_any_input
    }

    // ---- client side (P8-kani-001) ----

    /// Placeholder with the signature of `kx::split_share`; the client harnesses stub it with the real fn.
    fn client_split_real(_share: &[u8], _pq_len: usize) -> Result<(&[u8], &[u8]), Error> {
        Err(Error::General(String::new()))
    }

    /// The client's parse of a server share, `split(share) = r`, as `Active::complete` uses it: the property of
    /// `check_split!` for `pq_len = MLKEM1024_CT_LEN`, plus: the half handed to `decapsulate` (as a
    /// `kem::Ciphertext`) is exactly the ML-KEM-1024 ciphertext length.
    macro_rules! check_client_split {
        ($share:expr, $r:expr, $tag:literal) => {{
            let (share, r): (&[u8], &Result<(&[u8], &[u8]), Error>) = ($share, $r);
            let ok = check_split!(share, MLKEM1024_CT_LEN, r, $tag);
            if let Ok((_, ct)) = r {
                let ct: Ciphertext<'_> = (*ct).into();
                assert!(ct.as_ref().len() == MLKEM1024_CT_LEN, concat!($tag, ": decapsulation input is 1568 bytes"));
                assert!(share.len() == SERVER_SHARE_LEN, concat!($tag, ": only a 1665-byte server share parses"));
            }
            ok
        }};
    }

    /// 0x11ED client: `kx::split_share(share, MLKEM1024_CT_LEN)` (the parse step of `Active::complete`) on every
    /// server share of length 0..=1666 and every byte value.
    #[kani::proof]
    #[kani::stub(client_split_real, crate::kx::split_share)]
    fn client_server_share_split_0x11ed() {
        let buf: [u8; MAX] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX);
        let Some(share) = buf.get(..len) else { return };
        let r = client_split_real(share, MLKEM1024_CT_LEN);
        let ok = check_client_split!(share, &r, "0x11ED client split");
        kani::cover!(ok, "a 1665-byte server share parses (the stub to kx::split_share took effect)");
        kani::cover!(!ok && len == SERVER_SHARE_LEN, "exact length, bad prefix");
        kani::cover!(!ok && len == SERVER_SHARE_LEN - 1, "one byte short");
        kani::cover!(!ok && len == MAX, "one byte too long");
        core::mem::forget(r); // see split_share_any_input
    }

    /// Deliberately broken copy of the client's server-share parse: a planted out-of-bounds slice, no length check.
    #[allow(clippy::indexing_slicing)]
    fn planted_oob_client_split(share: &[u8]) -> Result<(&[u8], &[u8]), Error> {
        if share.first() != Some(&UNCOMPRESSED) {
            return Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare));
        }
        Ok((&share[..P384_SHARE_LEN], &share[P384_SHARE_LEN..SERVER_SHARE_LEN]))
    }

    /// Negative control for the client harnesses: `client_server_share_split_0x11ed`'s property over
    /// `planted_oob_client_split`. It must FAIL: out-of-bounds below 1665 bytes, and a 1666-byte share is accepted.
    #[kani::proof]
    fn client_negative_control_planted_oob() {
        let buf: [u8; MAX] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX);
        let Some(share) = buf.get(..len) else { return };
        let r = planted_oob_client_split(share);
        let _ = check_client_split!(share, &r, "NEGATIVE CONTROL: planted-OOB copy broke the client split contract");
        core::mem::forget(r); // see split_share_any_input
    }
}
