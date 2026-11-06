//! AEADs: AES-128/256-GCM (libcrux-aes, multiplexed: AES-NI/CLMUL when present, else bit-sliced portable) and
//! ChaCha20-Poly1305 (libcrux-chacha20poly1305), plus the TLS 1.3 record protection on top.
//!
//! `seal`/`open` are the only paths to the primitives: the record layer and the KATs both go through them, so a
//! broken `open` (the `mutant-gcm-notag` self-test) is visible to the KAT.
use libcrux_traits::aead::arrayref::Aead as _;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter, Nonce,
    OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm, UnsupportedOperationError,
    make_tls13_aad,
};
use rustls::{ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion};
use zeroize::Zeroizing;

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Alg {
    pub fn key_len(self) -> usize {
        match self {
            Alg::Aes128Gcm => 16,
            Alg::Aes256Gcm | Alg::ChaCha20Poly1305 => 32,
        }
    }
}

/// Primitive failure (bad length, bad tag). Deliberately carries no detail.
#[derive(Debug, PartialEq, Eq)]
pub struct AeadError;

/// Encrypt: returns ciphertext || tag.
pub fn seal(alg: Alg, key: &[u8], nonce: &[u8; NONCE_LEN], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, AeadError> {
    let mut ct = vec![0u8; pt.len()];
    let mut tag = [0u8; TAG_LEN];
    match alg {
        Alg::Aes128Gcm => {
            let k: &[u8; 16] = key.try_into().map_err(|_| AeadError)?;
            libcrux_aes::aes_gcm_128::AesGcm128::encrypt(&mut ct, &mut tag, k, nonce, aad, pt).map_err(|_| AeadError)?;
        }
        Alg::Aes256Gcm => {
            let k: &[u8; 32] = key.try_into().map_err(|_| AeadError)?;
            libcrux_aes::aes_gcm_256::AesGcm256::encrypt(&mut ct, &mut tag, k, nonce, aad, pt).map_err(|_| AeadError)?;
        }
        Alg::ChaCha20Poly1305 => {
            let k: &[u8; 32] = key.try_into().map_err(|_| AeadError)?;
            libcrux_chacha20poly1305::encrypt_detached(k, pt, &mut ct, &mut tag, aad, nonce).map_err(|_| AeadError)?;
        }
    }
    ct.extend_from_slice(&tag);
    Ok(ct)
}

/// Decrypt and verify: input is ciphertext || tag. Returns the plaintext only if the tag verifies.
pub fn open(alg: Alg, key: &[u8], nonce: &[u8; NONCE_LEN], aad: &[u8], ct_tag: &[u8]) -> Result<Vec<u8>, AeadError> {
    let split = ct_tag.len().checked_sub(TAG_LEN).ok_or(AeadError)?;
    let (ct, tag) = ct_tag.split_at_checked(split).ok_or(AeadError)?;
    let tag: &[u8; TAG_LEN] = tag.try_into().map_err(|_| AeadError)?;
    let mut pt = vec![0u8; ct.len()];
    match alg {
        Alg::Aes128Gcm => {
            let k: &[u8; 16] = key.try_into().map_err(|_| AeadError)?;
            gcm_open::<libcrux_aes::aes_gcm_128::AesGcm128, 16>(&mut pt, k, nonce, aad, ct, tag)?;
        }
        Alg::Aes256Gcm => {
            let k: &[u8; 32] = key.try_into().map_err(|_| AeadError)?;
            gcm_open::<libcrux_aes::aes_gcm_256::AesGcm256, 32>(&mut pt, k, nonce, aad, ct, tag)?;
        }
        Alg::ChaCha20Poly1305 => {
            let k: &[u8; 32] = key.try_into().map_err(|_| AeadError)?;
            libcrux_chacha20poly1305::decrypt_detached(k, &mut pt, ct, tag, aad, nonce).map_err(|_| AeadError)?;
        }
    }
    Ok(pt)
}

#[cfg(not(feature = "mutant-gcm-notag"))]
fn gcm_open<A: libcrux_traits::aead::arrayref::Aead<K, TAG_LEN, NONCE_LEN>, const K: usize>(
    pt: &mut [u8],
    key: &[u8; K],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), AeadError> {
    A::decrypt(pt, key, nonce, aad, ct, tag).map_err(|_| AeadError)
}

/// SELF-TEST MUTANT (gate.sh --self-test): the GCM tag is never checked. GCM encryption is CTR from the same
/// counter, so "encrypting" the ciphertext yields the plaintext; the computed tag is thrown away.
#[cfg(feature = "mutant-gcm-notag")]
fn gcm_open<A: libcrux_traits::aead::arrayref::Aead<K, TAG_LEN, NONCE_LEN>, const K: usize>(
    pt: &mut [u8],
    key: &[u8; K],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
    _tag: &[u8; TAG_LEN],
) -> Result<(), AeadError> {
    let mut ignored = [0u8; TAG_LEN];
    A::encrypt(pt, &mut ignored, key, nonce, aad, ct).map_err(|_| AeadError)
}

/// rustls TLS 1.3 AEAD algorithm.
pub struct Tls13Aead(pub Alg);

pub static AES_128_GCM: Tls13Aead = Tls13Aead(Alg::Aes128Gcm);
pub static AES_256_GCM: Tls13Aead = Tls13Aead(Alg::Aes256Gcm);
pub static CHACHA20_POLY1305: Tls13Aead = Tls13Aead(Alg::ChaCha20Poly1305);

impl Tls13AeadAlgorithm for Tls13Aead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Record { alg: self.0, key: Zeroizing::new(key.as_ref().to_vec()), iv })
    }
    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Record { alg: self.0, key: Zeroizing::new(key.as_ref().to_vec()), iv })
    }
    fn key_len(&self) -> usize {
        self.0.key_len()
    }
    fn extract_keys(&self, key: AeadKey, iv: Iv) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(match self.0 {
            Alg::Aes128Gcm => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            Alg::Aes256Gcm => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            Alg::ChaCha20Poly1305 => ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv },
        })
    }
}

struct Record {
    alg: Alg,
    key: Zeroizing<Vec<u8>>,
    iv: Iv,
}

impl MessageEncrypter for Record {
    fn encrypt(&mut self, msg: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut inner = Zeroizing::new(Vec::with_capacity(msg.payload.len() + 1));
        msg.payload.copy_to_vec(&mut inner);
        inner.push(u8::from(msg.typ));
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls13_aad(total_len);
        let sealed = seal(self.alg, &self.key, &nonce, &aad, &inner).map_err(|_| Error::EncryptError)?;
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_slice(&sealed);
        Ok(OutboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl MessageDecrypter for Record {
    fn decrypt<'a>(&mut self, mut msg: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < TAG_LEN {
            return Err(Error::DecryptError);
        }
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls13_aad(payload.len());
        let pt = Zeroizing::new(open(self.alg, &self.key, &nonce, &aad, payload).map_err(|_| Error::DecryptError)?);
        payload.get_mut(..pt.len()).ok_or(Error::DecryptError)?.copy_from_slice(&pt);
        payload.truncate(pt.len());
        msg.into_tls13_unpadded_message()
    }
}
