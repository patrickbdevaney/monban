//! c2sp.org/signed-note@v1.1.0: signers, key IDs, verifier keys (vkeys), signing and opening notes.
//!
//! Signature types:
//! - `0x01` Ed25519 over the note text (the log signature; c2sp.org/tlog-checkpoint@v1.1.0 "Ed25519 Log
//!   Signatures").
//! - ML-DSA-87 (FIPS 204) over the note text, as a log cosignature. signed-note assigns no byte to ML-DSA-87
//!   (`0x06` is the *timestamped ML-DSA-44* cosignature), so per signed-note we use `0xff` followed by a longer
//!   identifier: [`MLDSA87_SIG_TYPE`] = `0xff || "aegis-mldsa87-note-v1"`. Key ID =
//!   `SHA-256(name || 0x0A || MLDSA87_SIG_TYPE || 2592-byte public key)[:4]`. Verifiers that do not know this
//!   key ignore the line, as signed-note requires.

use aws_lc_rs::signature::{
    self, ED25519, Ed25519KeyPair, KeyPair as _, ML_DSA_87, ML_DSA_87_SIGNING, PqdsaKeyPair, UnparsedPublicKey,
};

use crate::encoding::{base64_decode, base64_encode, hex_encode};

pub const ED25519_SIG_TYPE: &[u8] = &[0x01];
pub const MLDSA87_SIG_TYPE: &[u8] = b"\xffaegis-mldsa87-note-v1";
const ED25519_PK_LEN: usize = 32;
const MLDSA87_PK_LEN: usize = 2592;
const MLDSA87_SIG_LEN: usize = 4627;
/// Notes larger than this are rejected when opening (16 ML-DSA-87 signatures fit).
pub const MAX_NOTE_BYTES: usize = 128 * 1024;
const MAX_SIGNATURES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoteError {
    /// Key name empty or containing a space, `+` or a control character.
    BadKeyName,
    /// Note text not ending in a newline, or containing a control character other than newline.
    BadText,
    /// Key material rejected by aws-lc-rs.
    BadKey,
    /// Signing failed.
    SignFailed,
    /// Malformed note or vkey.
    Malformed,
    /// A signature from a known key did not verify.
    BadSignature,
    /// No signature from a known key.
    NoKnownSignature,
}

impl std::fmt::Display for NoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for NoteError {}

/// Key name rule (signed-note "Format"): non-empty, no Unicode spaces, no `+`; we also forbid control characters.
pub fn check_key_name(name: &str) -> Result<(), NoteError> {
    if name.is_empty() || name.chars().any(|c| c.is_whitespace() || c == '+' || c.is_control()) {
        Err(NoteError::BadKeyName)
    } else {
        Ok(())
    }
}

/// `SHA-256(name || 0x0A || sig_type || public key)[:4]` as a big-endian u32.
pub fn key_id(name: &str, sig_type: &[u8], public_key: &[u8]) -> u32 {
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    ctx.update(name.as_bytes());
    ctx.update(b"\n");
    ctx.update(sig_type);
    ctx.update(public_key);
    let d = ctx.finish();
    let mut id = [0u8; 4];
    for (o, b) in id.iter_mut().zip(d.as_ref()) {
        *o = *b;
    }
    u32::from_be_bytes(id)
}

/// `<name>+<hex key ID>+<base64(sig_type || public key)>`.
pub fn vkey(name: &str, sig_type: &[u8], public_key: &[u8]) -> String {
    let mut material = sig_type.to_vec();
    material.extend_from_slice(public_key);
    format!("{name}+{}+{}", hex_encode(&key_id(name, sig_type, public_key).to_be_bytes()), base64_encode(&material))
}

/// A key that signs note text.
pub trait NoteSigner: std::fmt::Debug + Send + Sync {
    fn name(&self) -> &str;
    fn key_id(&self) -> u32;
    /// Raw signature over `msg` (without the key ID prefix).
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, NoteError>;
    /// The verifier key string for this signer.
    fn vkey(&self) -> String;
}

/// Ed25519 log signer (signature type 0x01).
pub struct Ed25519NoteSigner {
    name: String,
    id: u32,
    kp: Ed25519KeyPair,
}

impl std::fmt::Debug for Ed25519NoteSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519NoteSigner").field("name", &self.name).field("id", &self.id).finish()
    }
}

impl Ed25519NoteSigner {
    /// From a 32-byte RFC 8032 seed (the private key).
    pub fn from_seed(name: &str, seed: &[u8; 32]) -> Result<Self, NoteError> {
        check_key_name(name)?;
        let kp = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| NoteError::BadKey)?;
        Ok(Self::with(name, kp))
    }
    /// Fresh key from the aws-lc DRBG.
    pub fn generate(name: &str) -> Result<Self, NoteError> {
        check_key_name(name)?;
        let kp = Ed25519KeyPair::generate().map_err(|_| NoteError::BadKey)?;
        Ok(Self::with(name, kp))
    }
    fn with(name: &str, kp: Ed25519KeyPair) -> Self {
        let id = key_id(name, ED25519_SIG_TYPE, kp.public_key().as_ref());
        Self { name: name.to_owned(), id, kp }
    }
    pub fn public_key(&self) -> &[u8] {
        self.kp.public_key().as_ref()
    }
}

impl NoteSigner for Ed25519NoteSigner {
    fn name(&self) -> &str {
        &self.name
    }
    fn key_id(&self) -> u32 {
        self.id
    }
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, NoteError> {
        Ok(self.kp.try_sign(msg).map_err(|_| NoteError::SignFailed)?.as_ref().to_vec())
    }
    fn vkey(&self) -> String {
        vkey(&self.name, ED25519_SIG_TYPE, self.public_key())
    }
}

/// ML-DSA-87 cosigner (signature type [`MLDSA87_SIG_TYPE`]).
pub struct MlDsa87NoteSigner {
    name: String,
    id: u32,
    kp: PqdsaKeyPair,
}

impl std::fmt::Debug for MlDsa87NoteSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsa87NoteSigner").field("name", &self.name).field("id", &self.id).finish()
    }
}

impl MlDsa87NoteSigner {
    /// From a 32-byte FIPS 204 seed ξ.
    pub fn from_seed(name: &str, seed: &[u8; 32]) -> Result<Self, NoteError> {
        check_key_name(name)?;
        let kp = PqdsaKeyPair::from_seed(&ML_DSA_87_SIGNING, seed).map_err(|_| NoteError::BadKey)?;
        Self::with(name, kp)
    }
    pub fn generate(name: &str) -> Result<Self, NoteError> {
        check_key_name(name)?;
        let kp = PqdsaKeyPair::generate(&ML_DSA_87_SIGNING).map_err(|_| NoteError::BadKey)?;
        Self::with(name, kp)
    }
    fn with(name: &str, kp: PqdsaKeyPair) -> Result<Self, NoteError> {
        if kp.public_key().as_ref().len() != MLDSA87_PK_LEN {
            return Err(NoteError::BadKey);
        }
        let id = key_id(name, MLDSA87_SIG_TYPE, kp.public_key().as_ref());
        Ok(Self { name: name.to_owned(), id, kp })
    }
    pub fn public_key(&self) -> &[u8] {
        self.kp.public_key().as_ref()
    }
}

impl NoteSigner for MlDsa87NoteSigner {
    fn name(&self) -> &str {
        &self.name
    }
    fn key_id(&self) -> u32 {
        self.id
    }
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, NoteError> {
        let mut sig = vec![0u8; MLDSA87_SIG_LEN];
        let n = self.kp.sign(msg, &mut sig).map_err(|_| NoteError::SignFailed)?;
        sig.truncate(n);
        Ok(sig)
    }
    fn vkey(&self) -> String {
        vkey(&self.name, MLDSA87_SIG_TYPE, self.public_key())
    }
}

fn check_text(text: &str) -> Result<(), NoteError> {
    if !text.ends_with('\n') || text.chars().any(|c| c.is_control() && c != '\n') {
        return Err(NoteError::BadText);
    }
    Ok(())
}

/// `text || "\n" || ("— <name> <base64(id || sig)>\n")*`.
pub fn sign_note(text: &str, signers: &[&dyn NoteSigner]) -> Result<String, NoteError> {
    check_text(text)?;
    if signers.is_empty() {
        return Err(NoteError::NoKnownSignature);
    }
    let mut out = String::with_capacity(text.len() + 128);
    out.push_str(text);
    out.push('\n');
    for s in signers {
        let mut blob = s.key_id().to_be_bytes().to_vec();
        blob.extend_from_slice(&s.sign(text.as_bytes())?);
        out.push_str("\u{2014} ");
        out.push_str(s.name());
        out.push(' ');
        out.push_str(&base64_encode(&blob));
        out.push('\n');
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Alg {
    Ed25519,
    MlDsa87,
}

/// A trusted verifier key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteVerifier {
    name: String,
    id: u32,
    alg: Alg,
    public_key: Vec<u8>,
}

impl NoteVerifier {
    /// Parses a vkey string; the key ID must match the recomputed one.
    pub fn parse(vkey: &str) -> Result<Self, NoteError> {
        let mut parts = vkey.splitn(3, '+');
        let (Some(name), Some(id_hex), Some(b64)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(NoteError::Malformed);
        };
        check_key_name(name)?;
        if id_hex.len() != 8 || !id_hex.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(NoteError::Malformed);
        }
        let id = u32::from_str_radix(id_hex, 16).map_err(|_| NoteError::Malformed)?;
        let material = base64_decode(b64).ok_or(NoteError::Malformed)?;
        let (alg, sig_type, pk_len) = if material.starts_with(MLDSA87_SIG_TYPE) {
            (Alg::MlDsa87, MLDSA87_SIG_TYPE, MLDSA87_PK_LEN)
        } else if material.starts_with(ED25519_SIG_TYPE) {
            (Alg::Ed25519, ED25519_SIG_TYPE, ED25519_PK_LEN)
        } else {
            return Err(NoteError::Malformed);
        };
        let public_key = material.get(sig_type.len()..).ok_or(NoteError::Malformed)?.to_vec();
        if public_key.len() != pk_len || key_id(name, sig_type, &public_key) != id {
            return Err(NoteError::Malformed);
        }
        Ok(Self { name: name.to_owned(), id, alg, public_key })
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let alg: &'static dyn signature::VerificationAlgorithm = match self.alg {
            Alg::Ed25519 => &ED25519,
            Alg::MlDsa87 => &ML_DSA_87,
        };
        UnparsedPublicKey::new(alg, &self.public_key).verify(msg, sig).is_ok()
    }
}

/// Opens a signed note: returns the text if at least one known key signed it and no known key's signature fails.
/// Unknown keys (name or ID mismatch) are ignored. Returns the names of the verified keys alongside.
pub fn open_note<'a>(note: &'a str, verifiers: &[NoteVerifier]) -> Result<(&'a str, Vec<u32>), NoteError> {
    if note.len() > MAX_NOTE_BYTES || note.chars().any(|c| c.is_control() && c != '\n') || !note.ends_with('\n') {
        return Err(NoteError::Malformed);
    }
    let split = note.rfind("\n\n").ok_or(NoteError::Malformed)?;
    let text = note.get(..split + 1).ok_or(NoteError::Malformed)?;
    let sigs = note.get(split + 2..).ok_or(NoteError::Malformed)?;
    let mut verified = Vec::new();
    let mut count = 0usize;
    for line in sigs.split_terminator('\n') {
        count += 1;
        if count > MAX_SIGNATURES {
            return Err(NoteError::Malformed);
        }
        let rest = line.strip_prefix("\u{2014} ").ok_or(NoteError::Malformed)?;
        let (name, b64) = rest.split_once(' ').ok_or(NoteError::Malformed)?;
        check_key_name(name).map_err(|_| NoteError::Malformed)?;
        let blob = base64_decode(b64).ok_or(NoteError::Malformed)?;
        let (Some(id_bytes), Some(sig)) = (blob.get(..4), blob.get(4..)) else {
            return Err(NoteError::Malformed);
        };
        let mut idb = [0u8; 4];
        idb.copy_from_slice(id_bytes);
        let id = u32::from_be_bytes(idb);
        if let Some(v) = verifiers.iter().find(|v| v.name == name && v.id == id) {
            if !v.verify(text.as_bytes(), sig) {
                return Err(NoteError::BadSignature);
            }
            verified.push(id);
        }
    }
    if count == 0 {
        return Err(NoteError::Malformed);
    }
    if verified.is_empty() {
        return Err(NoteError::NoKnownSignature);
    }
    Ok((text, verified))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn spec_example_vkey_verifies_spec_note() {
        // c2sp.org/signed-note@v1.1.0 "Example".
        let v = NoteVerifier::parse("example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k").unwrap();
        let note = "This is an example message.\n\n\u{2014} example.com/foo \
                    Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n";
        let (text, ids) = open_note(note, std::slice::from_ref(&v)).unwrap();
        assert_eq!(text, "This is an example message.\n");
        assert_eq!(ids, vec![0x530d903a]);
        let tampered = note.replace("example message", "example massage");
        assert_eq!(open_note(&tampered, &[v]), Err(NoteError::BadSignature));
    }

    #[test]
    fn ed25519_and_mldsa87_roundtrip() {
        let ed = Ed25519NoteSigner::from_seed("log.example/a", &[7u8; 32]).unwrap();
        let pq = MlDsa87NoteSigner::from_seed("log.example/a", &[9u8; 32]).unwrap();
        assert_ne!(ed.key_id(), pq.key_id());
        let note = sign_note("hello\nworld\n", &[&ed, &pq]).unwrap();
        let ved = NoteVerifier::parse(&ed.vkey()).unwrap();
        let vpq = NoteVerifier::parse(&pq.vkey()).unwrap();
        assert_eq!(open_note(&note, std::slice::from_ref(&ved)).unwrap().1, vec![ed.key_id()]);
        assert_eq!(open_note(&note, std::slice::from_ref(&vpq)).unwrap().1, vec![pq.key_id()]);
        assert_eq!(open_note(&note, &[ved.clone(), vpq.clone()]).unwrap().1.len(), 2);
        // Unknown key only: rejected.
        let other = Ed25519NoteSigner::from_seed("log.example/a", &[8u8; 32]).unwrap();
        let vo = NoteVerifier::parse(&other.vkey()).unwrap();
        assert_eq!(open_note(&note, &[vo]), Err(NoteError::NoKnownSignature));
        // Corrupt the ML-DSA signature: a known key failing rejects the note.
        let lines: Vec<&str> = note.lines().collect();
        let pq_line = lines.last().unwrap();
        let mut blob = base64_decode(pq_line.rsplit(' ').next().unwrap()).unwrap();
        blob[100] ^= 1;
        let bad = note.replace(pq_line.rsplit(' ').next().unwrap(), &base64_encode(&blob));
        assert_eq!(open_note(&bad, &[ved, vpq]), Err(NoteError::BadSignature));
    }

    #[test]
    fn rejects_bad_names_and_text() {
        assert_eq!(Ed25519NoteSigner::from_seed("a b", &[0; 32]).err(), Some(NoteError::BadKeyName));
        assert_eq!(Ed25519NoteSigner::from_seed("a+b", &[0; 32]).err(), Some(NoteError::BadKeyName));
        assert_eq!(Ed25519NoteSigner::from_seed("", &[0; 32]).err(), Some(NoteError::BadKeyName));
        let ed = Ed25519NoteSigner::from_seed("n", &[0; 32]).unwrap();
        assert_eq!(sign_note("no newline", &[&ed]), Err(NoteError::BadText));
        assert_eq!(sign_note("tab\there\n", &[&ed]), Err(NoteError::BadText));
        assert_eq!(sign_note("ok\n", &[]), Err(NoteError::NoKnownSignature));
    }
}
