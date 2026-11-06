//! SHA-256/384 (libcrux-sha2), HMAC (libcrux-hmac) and the TLS 1.3 HKDF (libcrux-hkdf) behind rustls' traits.
use rustls::crypto::hash::{Context, Hash, HashAlgorithm, Output};
use rustls::crypto::hmac::{self, Tag};
use rustls::crypto::tls13::{Hkdf, HkdfExpander, OkmBlock, OutputLengthError};
use zeroize::Zeroizing;

use libcrux_sha2::Digest as _;

macro_rules! sha2 {
    ($hash:ident, $ctx:ident, $state:ty, $oneshot:path, $len:literal, $alg:expr) => {
        pub struct $hash;

        impl Hash for $hash {
            fn start(&self) -> Box<dyn Context> {
                Box::new($ctx(<$state>::new()))
            }
            fn hash(&self, data: &[u8]) -> Output {
                Output::new(&$oneshot(data))
            }
            fn output_len(&self) -> usize {
                $len
            }
            fn algorithm(&self) -> HashAlgorithm {
                $alg
            }
        }

        struct $ctx($state);

        impl Context for $ctx {
            fn fork_finish(&self) -> Output {
                let mut d = [0u8; $len];
                self.0.finish(&mut d);
                Output::new(&d)
            }
            fn fork(&self) -> Box<dyn Context> {
                Box::new($ctx(self.0.clone()))
            }
            fn finish(self: Box<Self>) -> Output {
                self.fork_finish()
            }
            fn update(&mut self, data: &[u8]) {
                self.0.update(data)
            }
        }
    };
}

sha2!(Sha256, Sha256Ctx, libcrux_sha2::Sha256, libcrux_sha2::sha256, 32, HashAlgorithm::SHA256);
sha2!(Sha384, Sha384Ctx, libcrux_sha2::Sha384, libcrux_sha2::sha384, 48, HashAlgorithm::SHA384);

pub static SHA256: Sha256 = Sha256;
pub static SHA384: Sha384 = Sha384;

/// HMAC over libcrux-hmac (one-shot; `sign_concat` concatenates the pieces first).
pub struct Hmac {
    alg: libcrux_hmac::Algorithm,
    len: usize,
}

pub static HMAC_SHA256: Hmac = Hmac { alg: libcrux_hmac::Algorithm::Sha256, len: 32 };
pub static HMAC_SHA384: Hmac = Hmac { alg: libcrux_hmac::Algorithm::Sha384, len: 48 };

/// One-shot HMAC with the rustls output type (also used by the KATs).
pub fn hmac_tag(alg: libcrux_hmac::Algorithm, len: usize, key: &[u8], data: &[u8]) -> Tag {
    let mut tag = Zeroizing::new(vec![0u8; len]);
    libcrux_hmac::hmac(alg, key, data, &mut tag);
    Tag::new(&tag)
}

impl hmac::Hmac for Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn hmac::Key> {
        Box::new(HmacKey { alg: self.alg, len: self.len, key: Zeroizing::new(key.to_vec()) })
    }
    fn hash_output_len(&self) -> usize {
        self.len
    }
}

struct HmacKey {
    alg: libcrux_hmac::Algorithm,
    len: usize,
    key: Zeroizing<Vec<u8>>,
}

impl hmac::Key for HmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut data = Vec::with_capacity(first.len() + last.len() + middle.iter().map(|m| m.len()).sum::<usize>());
        data.extend_from_slice(first);
        for m in middle {
            data.extend_from_slice(m);
        }
        data.extend_from_slice(last);
        hmac_tag(self.alg, self.len, &self.key, &data)
    }
    fn tag_len(&self) -> usize {
        self.len
    }
}

/// TLS 1.3 HKDF directly on libcrux-hkdf extract/expand.
pub struct LcxHkdf {
    hkdf: libcrux_hkdf::Algorithm,
    hmac: libcrux_hmac::Algorithm,
    len: usize,
}

pub static HKDF_SHA256: LcxHkdf =
    LcxHkdf { hkdf: libcrux_hkdf::Algorithm::Sha256, hmac: libcrux_hmac::Algorithm::Sha256, len: 32 };
pub static HKDF_SHA384: LcxHkdf =
    LcxHkdf { hkdf: libcrux_hkdf::Algorithm::Sha384, hmac: libcrux_hmac::Algorithm::Sha384, len: 48 };

const ZEROS: [u8; 64] = [0u8; 64];

impl LcxHkdf {
    fn zeros(&self) -> &'static [u8] {
        ZEROS.get(..self.len).unwrap_or(&[])
    }

    /// HKDF-Extract (RFC 5869 2.2); `None` salt = HashLen zero bytes.
    pub fn extract(&self, salt: Option<&[u8]>, ikm: &[u8]) -> Expander {
        let salt = salt.unwrap_or(self.zeros());
        let mut prk = Zeroizing::new(vec![0u8; self.len]);
        let ok = libcrux_hkdf::extract(self.hkdf, &mut prk, salt, ikm).is_ok();
        // Extract can only fail on inputs longer than u32::MAX bytes, which TLS cannot produce. Fail closed: a
        // poisoned expander refuses every expansion and yields random blocks, so no handshake can complete.
        Expander { hkdf: self.hkdf, len: self.len, prk, poisoned: !ok }
    }
}

impl Hkdf for LcxHkdf {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        Box::new(self.extract(salt, self.zeros()))
    }
    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        Box::new(self.extract(salt, secret))
    }
    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        Box::new(Expander {
            hkdf: self.hkdf,
            len: self.len,
            prk: Zeroizing::new(okm.as_ref().to_vec()),
            poisoned: okm.as_ref().len() != self.len,
        })
    }
    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> Tag {
        hmac_tag(self.hmac, self.len, key.as_ref(), message)
    }
}

pub struct Expander {
    hkdf: libcrux_hkdf::Algorithm,
    len: usize,
    prk: Zeroizing<Vec<u8>>,
    poisoned: bool,
}

impl Expander {
    /// The PRK (for the RFC 5869 KAT).
    pub fn prk(&self) -> &[u8] {
        &self.prk
    }
}

impl HkdfExpander for Expander {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        if self.poisoned {
            return Err(OutputLengthError);
        }
        let info = info.concat();
        libcrux_hkdf::expand(self.hkdf, output, &self.prk, &info).map_err(|_| OutputLengthError)
    }
    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut out = Zeroizing::new(vec![0u8; self.len]);
        if self.expand_slice(info, &mut out).is_err() {
            // Fail closed (see `extract`): unpredictable output instead of a usable key.
            let _ = getrandom::fill(&mut out);
        }
        OkmBlock::new(&out)
    }
    fn hash_len(&self) -> usize {
        self.len
    }
}
