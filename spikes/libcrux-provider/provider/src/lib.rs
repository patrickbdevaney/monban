//! Spike P7-libcrux-001: a **server-only** rustls `CryptoProvider` whose primitives are libcrux-* crates.
//!
//! Scope (PREFLIGHT D-P7.5, P-PUBLIC-WEB server side): TLS 1.3 only;
//! - key exchange: X25519MLKEM768 (0x11EC), X25519, secp256r1;
//! - AEAD: AES-128-GCM, AES-256-GCM (libcrux-aes), ChaCha20-Poly1305 (libcrux-chacha20poly1305);
//! - SHA-256/384 (libcrux-sha2), HMAC (libcrux-hmac), HKDF (libcrux-hkdf);
//! - server signing keys: ECDSA-P256-SHA256 (libcrux-ecdsa) and Ed25519 (libcrux-ed25519).
//!
//! No signature *verification* algorithms are provided (`signature_verification_algorithms` is empty), so this
//! provider cannot verify client certificates or act as a client against a real server. FIPS stays on AWS-LC.
//! Randomness comes from the OS through `getrandom` (not a libcrux crate; counted separately in the verdict).
//!
//! Upstream libcrux states its code is not verified to be side-channel resistant. Nothing in this crate is
//! verified; it is glue on top of libcrux.
#![forbid(unsafe_code)]

pub mod aead;
pub mod hash;
pub mod kx;
pub mod sign;

use rustls::crypto::{CryptoProvider, GetRandomFailed, SecureRandom, WebPkiSupportedAlgorithms};

/// The provider: every suite, group and key type in scope.
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: suites::ALL.to_vec(),
        kx_groups: kx::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: NO_VERIFY,
        secure_random: &Rng,
        key_provider: &sign::Keys,
    }
}

/// Server-only: no verification algorithms. A client-auth or client config built on this provider has nothing to
/// verify with and fails closed.
pub static NO_VERIFY: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms { all: &[], mapping: &[] };

/// OS randomness (getrandom).
#[derive(Debug)]
pub struct Rng;

impl SecureRandom for Rng {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        getrandom::fill(buf).map_err(|_| GetRandomFailed)
    }
}

pub(crate) fn random<const N: usize>() -> Result<[u8; N], rustls::Error> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| rustls::Error::FailedToGetRandomBytes)?;
    Ok(b)
}

pub mod suites {
    //! TLS 1.3 cipher suites.
    use rustls::crypto::CipherSuiteCommon;
    use rustls::{CipherSuite, SupportedCipherSuite, Tls13CipherSuite};

    use crate::{aead, hash};

    pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &hash::SHA256,
            confidentiality_limit: 1 << 24,
        },
        hkdf_provider: &hash::HKDF_SHA256,
        aead_alg: &aead::AES_128_GCM,
        quic: None,
    });

    pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite = SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &hash::SHA384,
            confidentiality_limit: 1 << 24,
        },
        hkdf_provider: &hash::HKDF_SHA384,
        aead_alg: &aead::AES_256_GCM,
        quic: None,
    });

    pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
        SupportedCipherSuite::Tls13(&Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                hash_provider: &hash::SHA256,
                confidentiality_limit: u64::MAX,
            },
            hkdf_provider: &hash::HKDF_SHA256,
            aead_alg: &aead::CHACHA20_POLY1305,
            quic: None,
        });

    pub static ALL: &[SupportedCipherSuite] =
        &[TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256];
}
