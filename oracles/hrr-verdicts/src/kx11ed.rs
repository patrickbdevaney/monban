//! SecP384r1MLKEM1024 (0x11ED) for the oracle's own reference subject and full-handshake client.
//!
//! Written for the oracle from RFC 10024 (draft-ietf-tls-ecdhe-mlkem) section 4, independently of monban-tls
//! (`crates/monban-tls/src/kx.rs` is the subject's code and is not linked or read for this): the oracle must be
//! able to serve and offer 0x11ED itself, otherwise the gov-profile verdicts could only be judged against the
//! subject's own implementation. rustls 0.23.46 has no 0x11ED.
//!
//!   client share = P-384 uncompressed point (97) || ML-KEM-1024 encapsulation key (1568)
//!   server share = P-384 uncompressed point (97) || ML-KEM-1024 ciphertext (1568)
//!   secret       = ECDH x-coordinate (48) || ML-KEM shared secret (32)
//!
//! Hygiene is not a goal here (test oracle), correctness of the wire layout is: the handshake only completes if
//! both sides derive the same 80-byte secret.

use aws_lc_rs::{agreement, kem};
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};

pub const CODE: u16 = 0x11ED;
const POINT: usize = 97;
const PQ: usize = 1568;

#[derive(Debug)]
pub struct Group;

pub static SECP384R1MLKEM1024: &dyn SupportedKxGroup = &Group;

fn bad() -> Error {
    Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
}

fn keygen_err() -> Error {
    Error::General("oracle 0x11ED: keygen".into())
}

fn split(share: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    if share.len() != POINT + PQ || share.first() != Some(&0x04) {
        return Err(bad());
    }
    share.split_at_checked(POINT).ok_or_else(bad)
}

fn ecdh(private: &agreement::PrivateKey, peer: &[u8]) -> Result<Vec<u8>, Error> {
    agreement::agree(private, agreement::UnparsedPublicKey::new(&agreement::ECDH_P384, peer), bad(), |z| Ok(z.to_vec()))
}

impl SupportedKxGroup for Group {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let e = agreement::PrivateKey::generate(&agreement::ECDH_P384).map_err(|_| keygen_err())?;
        let dk = kem::DecapsulationKey::generate(&kem::ML_KEM_1024).map_err(|_| keygen_err())?;
        let ek = dk.encapsulation_key().and_then(|k| k.key_bytes()).map_err(|_| keygen_err())?;
        let point = e.compute_public_key().map_err(|_| keygen_err())?;
        let pub_key = [point.as_ref(), ek.as_ref()].concat();
        Ok(Box::new(Active { e, dk, pub_key }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (point, ek) = split(client_share)?;
        let ek = kem::EncapsulationKey::new(&kem::ML_KEM_1024, ek).map_err(|_| bad())?;
        let (ct, ss) = ek.encapsulate().map_err(|_| bad())?;
        let e = agreement::PrivateKey::generate(&agreement::ECDH_P384).map_err(|_| keygen_err())?;
        let z = ecdh(&e, point)?;
        let mine = e.compute_public_key().map_err(|_| keygen_err())?;
        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: [mine.as_ref(), ct.as_ref()].concat(),
            secret: SharedSecret::from([z.as_slice(), ss.as_ref()].concat()),
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::Unknown(CODE)
    }

    fn usable_for_version(&self, v: ProtocolVersion) -> bool {
        v == ProtocolVersion::TLSv1_3
    }
}

struct Active {
    e: agreement::PrivateKey,
    dk: kem::DecapsulationKey<kem::AlgorithmId>,
    pub_key: Vec<u8>,
}

impl ActiveKeyExchange for Active {
    fn complete(self: Box<Self>, server_share: &[u8]) -> Result<SharedSecret, Error> {
        let (point, ct) = split(server_share)?;
        let z = ecdh(&self.e, point)?;
        let ss = self.dk.decapsulate(kem::Ciphertext::from(ct)).map_err(|_| bad())?;
        Ok(SharedSecret::from([z.as_slice(), ss.as_ref()].concat()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::Unknown(CODE)
    }
}
