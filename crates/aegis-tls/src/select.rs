//! The MTC `CredentialSelector` (PREFLIGHT D-P7.4; F1 §F SEL-1..3; feature `mtc`, never in the cmvp build).
//!
//! A listener holds a pool of credentials of kind x509, mldsa or mtc. Per ClientHello the selector picks one, by
//! the decision table of oracles/cred-select (the contract, rows R0..R4 over the eligibility filters E0..E4):
//!
//! - R0: the aegis-wire peek ([`aegis_wire::tls_peek::client_hello`]) refuses the raw bytes → no credential
//!   (handshake_failure). So does a `signature_algorithms` or `trust_anchors` body this module cannot read back
//!   (fail closed; the real peek already refuses those).
//! - E0 (SEL-3): only credentials of this listener. Applied at construction, so another listener's credential is
//!   never even held by the selector.
//! - E1: the credential's scheme is in the profile's F12 sigalgs ([`Profile::sigalgs`], P-PQ2).
//! - E2 (SEL-2): kind mldsa is never eligible on P-PUBLIC-WEB, whatever F12 lists.
//! - E3: the scheme is in the client's `signature_algorithms`, as the peek reads it (missing = empty).
//! - E4 (SEL-1): kind mtc needs its TrustAnchorID, byte for byte, in the client's `trust_anchors` (codepoint
//!   0xCA34, read by the peek; rustls 0.23 does not expose the extension). Missing or empty list: no match.
//! - R1..R3: the first eligible mtc, else the first eligible mldsa, else the first eligible x509, in configured
//!   order. R4: none → `None`, which rustls turns into a failed handshake (SEL-3: never another listener's
//!   credential, never a scheme the client did not offer or the profile does not allow).
//!
//! The MTC chain is an opaque operator blob: AEGIS neither issues nor verifies MTCs (D-P7.4). Claim rung: selection
//! logic R2 against the decision-table oracle (gate `cred-select`); no MTC validity claim.
//!
//! rustls wiring: [`CredentialSelector::config_for`] takes the raw first record of a connection (the bytes the peek
//! read, before rustls sees them) and returns the listener's `ServerConfig` with a per-connection resolver
//! ([`BoundSelector`]). That resolver is wrapped in the same P-PQ2 sigalg restriction as every
//! [`crate::server_config`] resolver, and it also checks that the rustls `ClientHello` it is called with is the one
//! the peek read (rustls's offered schemes must be a subset of the peeked list, and contain the chosen scheme);
//! otherwise it serves nothing.

use std::string::String;
use std::sync::Arc;
use std::vec::Vec;

use aegis_wire::tls_peek::{self, Peek};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, SignatureScheme};

use crate::profile::{NoCredential, Profile, ProfileCertResolver, ProfileError, server_config_with};

/// The largest TrustAnchorID (draft-ietf-tls-trust-anchor-ids-07: `opaque TrustAnchorID<1..2^8-1>`; the AEGIS
/// bound, as in aegis-wire and F8, is 32 bytes).
pub const TRUST_ANCHOR_ID_MAX: usize = 32;

/// F8 `tls.credentials[].kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CredentialKind {
    /// A classical chain (`x509`).
    X509,
    /// An ML-DSA chain for private hops (`mldsa`); never chosen on P-PUBLIC-WEB (SEL-2).
    MlDsa,
    /// A Merkle Tree Certificate (`mtc`): opaque chain, chosen only on a trust_anchors match (SEL-1).
    Mtc,
}

impl CredentialKind {
    /// Every kind, in selection-tier order (D-P7.4: MTC, else ML-DSA, else classical).
    pub const TIERS: [CredentialKind; 3] = [CredentialKind::Mtc, CredentialKind::MlDsa, CredentialKind::X509];

    /// The F8 name.
    pub fn name(self) -> &'static str {
        match self {
            Self::X509 => "x509",
            Self::MlDsa => "mldsa",
            Self::Mtc => "mtc",
        }
    }

    /// Look a kind up by its F8 name.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::TIERS.into_iter().find(|k| k.name() == name)
    }
}

/// Why a credential or a selector was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectError {
    /// The listener profile cannot be built ([`crate::server_config`]).
    Profile(ProfileError),
    /// A credential is inconsistent.
    Credential {
        /// The credential id.
        id: String,
        /// Why.
        reason: &'static str,
    },
}

impl core::fmt::Display for SelectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Profile(e) => write!(f, "{e}"),
            Self::Credential { id, reason } => write!(f, "credential {id}: {reason}"),
        }
    }
}

impl std::error::Error for SelectError {}

/// The schemes [`key_scheme`] probes: every TLS 1.3 CertificateVerify scheme rustls knows.
const PROBE: [SignatureScheme; 13] = [
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ED25519,
    SignatureScheme::ED448,
    SignatureScheme::ML_DSA_44,
    SignatureScheme::ML_DSA_65,
    SignatureScheme::ML_DSA_87,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
];

const ML_DSA: [SignatureScheme; 3] =
    [SignatureScheme::ML_DSA_44, SignatureScheme::ML_DSA_65, SignatureScheme::ML_DSA_87];

/// The one TLS 1.3 scheme `key` signs CertificateVerify with, or `None` if it signs with none or with several (an
/// RSA key: name the scheme explicitly in [`Credential::new`]).
pub fn key_scheme(key: &CertifiedKey) -> Option<SignatureScheme> {
    let mut found = PROBE.iter().copied().filter(|s| signs_with(key, *s));
    let first = found.next()?;
    found.next().is_none().then_some(first)
}

fn signs_with(key: &CertifiedKey, scheme: SignatureScheme) -> bool {
    key.key.choose_scheme(&[scheme]).is_some_and(|s| s.scheme() == scheme)
}

/// One F8 `tls.credentials` entry as the selector sees it, bound to the listener it serves.
#[derive(Clone, Debug)]
pub struct Credential {
    id: String,
    listener: String,
    kind: CredentialKind,
    scheme: SignatureScheme,
    trust_anchor_id: Option<Vec<u8>>,
    key: Arc<CertifiedKey>,
}

impl Credential {
    /// A credential `id` of `kind` for `listener`, whose key signs with `scheme`.
    ///
    /// `trust_anchor_id` is the TrustAnchorID in wire form (aegis-config `TrustAnchorId::wire()`), required for mtc
    /// and refused otherwise, 1..=32 bytes. Refused: an mldsa credential whose scheme is not ML-DSA; a key that cannot
    /// sign with `scheme`; for x509 and mldsa, a chain whose end-entity key is not `key` (rustls `keys_match`). The
    /// mtc chain is opaque (D-P7.4), so it is not parsed.
    pub fn new(
        id: impl Into<String>,
        listener: impl Into<String>,
        kind: CredentialKind,
        scheme: SignatureScheme,
        trust_anchor_id: Option<Vec<u8>>,
        key: Arc<CertifiedKey>,
    ) -> Result<Self, SelectError> {
        let id = id.into();
        let bad = |reason| Err(SelectError::Credential { id: id.clone(), reason });
        if id.is_empty() {
            return bad("empty id");
        }
        match (kind, &trust_anchor_id) {
            (CredentialKind::Mtc, None) => return bad("an mtc credential needs a trust_anchor_id"),
            (CredentialKind::Mtc, Some(t)) if t.is_empty() || t.len() > TRUST_ANCHOR_ID_MAX => {
                return bad("trust_anchor_id must be 1..32 bytes");
            }
            (CredentialKind::X509 | CredentialKind::MlDsa, Some(_)) => {
                return bad("trust_anchor_id is only for mtc credentials");
            }
            _ => {}
        }
        if kind == CredentialKind::MlDsa && !ML_DSA.contains(&scheme) {
            return bad("an mldsa credential must sign with ML-DSA");
        }
        if !signs_with(&key, scheme) {
            return bad("the key does not sign with the credential's scheme");
        }
        if kind != CredentialKind::Mtc && key.keys_match().is_err() {
            return bad("the chain's end-entity key is not the credential's key");
        }
        Ok(Self { id, listener: listener.into(), kind, scheme, trust_anchor_id, key })
    }

    /// The credential id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The listener it serves.
    pub fn listener(&self) -> &str {
        &self.listener
    }

    /// Its kind.
    pub fn kind(&self) -> CredentialKind {
        self.kind
    }

    /// The scheme its key signs CertificateVerify with.
    pub fn scheme(&self) -> SignatureScheme {
        self.scheme
    }

    /// The TrustAnchorID (wire form), mtc only.
    pub fn trust_anchor_id(&self) -> Option<&[u8]> {
        self.trust_anchor_id.as_deref()
    }

    /// The chain and key rustls serves.
    pub fn certified_key(&self) -> &Arc<CertifiedKey> {
        &self.key
    }
}

/// The per-listener credential selector (D-P7.4, SEL-1..3).
#[derive(Debug)]
pub struct CredentialSelector {
    profile: Profile,
    listener: String,
    creds: Vec<Credential>,
    base: ServerConfig,
}

impl CredentialSelector {
    /// The selector of `listener` (profile `profile`) over `pool`, the credentials of every listener in configured
    /// order. Only this listener's credentials are kept (E0, SEL-3), and of those only the ones the profile may ever
    /// serve (E1, E2); order is kept. The listener's `ServerConfig` is built here once by the production builder
    /// ([`crate::server_config`] path, so its startup assertions run); a pending profile is refused.
    pub fn new(
        profile: Profile,
        listener: &str,
        pool: impl IntoIterator<Item = Credential>,
    ) -> Result<Self, SelectError> {
        let base = server_config_with(profile, Arc::new(NoCredential), None).map_err(SelectError::Profile)?;
        let creds = pool.into_iter().filter(|c| c.listener == listener && profile_allows(profile, c)).collect();
        Ok(Self { profile, listener: listener.into(), creds, base })
    }

    /// The listener's profile.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// The listener's name.
    pub fn listener(&self) -> &str {
        &self.listener
    }

    /// The credentials this listener may serve (E0..E2 applied), in configured order.
    pub fn credentials(&self) -> &[Credential] {
        &self.creds
    }

    /// Set the ALPN list of every config [`Self::config_for`] returns.
    pub fn set_alpn(&mut self, protocols: Vec<Vec<u8>>) {
        self.base.alpn_protocols = protocols;
    }

    /// The credential for the ClientHello in `raw` (the first bytes the client sent), or `None` (handshake_failure):
    /// R0 when the peek refuses `raw`, else [`Self::select_peek`].
    pub fn select(&self, raw: &[u8]) -> Option<&Credential> {
        let peek = tls_peek::client_hello(raw).ok()?;
        self.select_peek(&peek)
    }

    /// The credential for a peeked ClientHello (rows R1..R4), or `None` (handshake_failure).
    pub fn select_peek(&self, peek: &Peek<'_>) -> Option<&Credential> {
        self.decide(peek.sigalgs, peek.trust_anchors).and_then(|i| self.creds.get(i))
    }

    /// Index into `creds` of the choice, from the peeked `signature_algorithms` and `trust_anchors` list bodies.
    fn decide(&self, sigalgs: Option<&[u8]>, trust_anchors: Option<&[u8]>) -> Option<usize> {
        let offered = u16_list(sigalgs.unwrap_or_default())?;
        let anchors = id_list(trust_anchors.unwrap_or_default())?;
        let eligible = |c: &Credential| {
            profile_allows(self.profile, c)
                && offered.contains(&u16::from(c.scheme))
                && match c.kind {
                    CredentialKind::Mtc => c.trust_anchor_id.as_deref().is_some_and(|t| anchors.contains(&t)),
                    CredentialKind::MlDsa | CredentialKind::X509 => true,
                }
        };
        CredentialKind::TIERS.into_iter().find_map(|kind| self.creds.iter().position(|c| c.kind == kind && eligible(c)))
    }

    /// The per-connection resolver for the ClientHello in `raw`.
    pub fn bind(&self, raw: &[u8]) -> BoundSelector {
        match tls_peek::client_hello(raw) {
            Ok(peek) => BoundSelector {
                chosen: self.select_peek(&peek).map(|c| (c.key.clone(), c.scheme)),
                offered: u16_list(peek.sigalgs.unwrap_or_default()).unwrap_or_default(),
            },
            Err(_) => BoundSelector { chosen: None, offered: Vec::new() },
        }
    }

    /// The listener's `ServerConfig` for one connection whose first bytes are `raw`: the config built in
    /// [`Self::new`] with its resolver replaced by [`Self::bind`]`(raw)`, wrapped in the profile's P-PQ2 sigalg
    /// restriction. Feed rustls the same `raw` bytes.
    pub fn config_for(&self, raw: &[u8]) -> Arc<ServerConfig> {
        let mut cfg = self.base.clone();
        cfg.cert_resolver = ProfileCertResolver::wrap(Arc::new(self.bind(raw)), self.profile);
        Arc::new(cfg)
    }
}

/// E1 (F12 sigalgs of the profile) and E2 (SEL-2: no ML-DSA credential on P-PUBLIC-WEB).
fn profile_allows(profile: Profile, c: &Credential) -> bool {
    profile.sigalgs().contains(&c.scheme) && !(profile == Profile::PublicWeb && c.kind == CredentialKind::MlDsa)
}

/// A SignatureSchemeList body (without its length prefix); `None` if it is not whole u16s.
fn u16_list(body: &[u8]) -> Option<Vec<u16>> {
    let (pairs, rest) = body.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    Some(pairs.iter().map(|p| u16::from_be_bytes(*p)).collect())
}

/// A RequestedTrustAnchorList body (without its length prefix): `opaque TrustAnchorID<1..32>` entries filling it
/// exactly; `None` otherwise.
fn id_list(mut body: &[u8]) -> Option<Vec<&[u8]>> {
    let mut out = Vec::new();
    while let Some((&n, rest)) = body.split_first() {
        let n = usize::from(n);
        if n == 0 || n > TRUST_ANCHOR_ID_MAX || n > rest.len() {
            return None;
        }
        let (id, rest) = rest.split_at(n);
        out.push(id);
        body = rest;
    }
    Some(out)
}

/// The resolver of one connection ([`CredentialSelector::bind`]): the choice made on the peek of the raw
/// ClientHello, served only if the rustls `ClientHello` is consistent with that peek.
#[derive(Debug)]
pub struct BoundSelector {
    chosen: Option<(Arc<CertifiedKey>, SignatureScheme)>,
    offered: Vec<u16>,
}

impl ResolvesServerCert for BoundSelector {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let (key, scheme) = self.chosen.as_ref()?;
        let rustls_offered = client_hello.signature_schemes();
        // rustls reduces the client's list to the schemes usable with the common suites, so its list is a subset of
        // the peeked one; anything else means the peek and rustls saw different hellos.
        let same_hello = rustls_offered.iter().all(|s| self.offered.contains(&u16::from(*s)));
        (same_hello && rustls_offered.contains(scheme)).then(|| key.clone())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::signature::{self, EcdsaKeyPair, KeyPair, PqdsaKeyPair};
    use rustls::ServerConnection;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    const P256: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;
    const P384: SignatureScheme = SignatureScheme::ECDSA_NISTP384_SHA384;
    const MLDSA44: SignatureScheme = SignatureScheme::ML_DSA_44;
    const MLDSA87: SignatureScheme = SignatureScheme::ML_DSA_87;

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let n = content.len();
        let mut v = vec![tag];
        if n < 0x80 {
            v.push(n as u8);
        } else {
            let b: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
            v.push(0x80 | b.len() as u8);
            v.extend(b);
        }
        v.extend_from_slice(content);
        v
    }

    /// A structurally valid certificate around `spki` (the signature is not checked by `keys_match`).
    fn cert(spki: &[u8]) -> Vec<u8> {
        let alg = tlv(0x30, &tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]));
        let name = tlv(0x30, &tlv(0x31, &tlv(0x30, &[tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x0c, b"t")].concat())));
        let validity = tlv(0x30, &[tlv(0x17, b"260101000000Z"), tlv(0x18, b"20991231235959Z")].concat());
        let tbs = tlv(
            0x30,
            &[tlv(0xa0, &tlv(0x02, &[2])), tlv(0x02, &[1]), alg.clone(), name.clone(), validity, name, spki.to_vec()]
                .concat(),
        );
        tlv(0x30, &[tbs, alg, tlv(0x03, &[0, 0])].concat())
    }

    fn key(scheme: SignatureScheme, opaque_chain: bool) -> Arc<CertifiedKey> {
        let (spki, pkcs8) = match scheme {
            P256 | P384 => {
                let alg = if scheme == P256 {
                    &signature::ECDSA_P256_SHA256_ASN1_SIGNING
                } else {
                    &signature::ECDSA_P384_SHA384_ASN1_SIGNING
                };
                let kp = EcdsaKeyPair::generate(alg).unwrap();
                (kp.public_key().as_der().unwrap().as_ref().to_vec(), kp.to_pkcs8v1().unwrap().as_ref().to_vec())
            }
            _ => {
                let alg = if scheme == MLDSA44 { &signature::ML_DSA_44_SIGNING } else { &signature::ML_DSA_87_SIGNING };
                let kp = PqdsaKeyPair::generate(alg).unwrap();
                (kp.public_key().as_der().unwrap().as_ref().to_vec(), kp.to_pkcs8v1().unwrap().as_ref().to_vec())
            }
        };
        let chain = if opaque_chain { b"opaque mtc blob".to_vec() } else { cert(&spki) };
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let k = provider.key_provider.load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8))).unwrap();
        Arc::new(CertifiedKey::new(vec![CertificateDer::from(chain)], k))
    }

    fn cred(id: &str, listener: &str, kind: CredentialKind, scheme: SignatureScheme, ta: Option<&[u8]>) -> Credential {
        let k = key(scheme, kind == CredentialKind::Mtc);
        Credential::new(id, listener, kind, scheme, ta.map(<[u8]>::to_vec), k).unwrap()
    }

    fn sig_body(s: &[SignatureScheme]) -> Vec<u8> {
        s.iter().flat_map(|s| u16::from(*s).to_be_bytes()).collect()
    }

    fn ta_body(ids: &[&[u8]]) -> Vec<u8> {
        ids.iter().flat_map(|i| [&[i.len() as u8][..], i].concat()).collect()
    }

    fn pick<'a>(s: &'a CredentialSelector, sig: Option<&[u8]>, ta: Option<&[u8]>) -> Option<&'a str> {
        s.decide(sig, ta).map(|i| s.creds[i].id())
    }

    const TA_A: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37];
    const TA_B: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x38];

    fn pool() -> Vec<Credential> {
        use CredentialKind::*;
        vec![
            cred("b-mtc", "b", Mtc, P256, Some(TA_B)),
            cred("a-x509", "a", X509, P256, None),
            cred("a-mldsa", "a", MlDsa, MLDSA44, None),
            cred("a-mtc", "a", Mtc, P256, Some(TA_A)),
            cred("b-x509", "b", X509, P256, None),
            cred("a-x509-2", "a", X509, P256, None),
        ]
    }

    #[test]
    fn credential_validation() {
        use CredentialKind::*;
        let k = key(P256, false);
        let new = |kind, scheme, ta: Option<Vec<u8>>| Credential::new("c", "l", kind, scheme, ta, k.clone());
        assert!(new(X509, P256, None).is_ok());
        assert!(new(X509, P384, None).is_err(), "key does not sign P-384");
        assert!(new(X509, P256, Some(TA_A.to_vec())).is_err());
        assert!(new(MlDsa, P256, None).is_err());
        assert!(new(Mtc, P256, None).is_err());
        assert!(new(Mtc, P256, Some(Vec::new())).is_err());
        assert!(new(Mtc, P256, Some(vec![1; 33])).is_err());
        assert!(new(Mtc, P256, Some(vec![1; 32])).is_ok());
        // x509 with a chain that is not the key's: refused; mtc with an opaque chain: accepted.
        let opaque = key(P256, true);
        assert!(Credential::new("c", "l", X509, P256, None, opaque.clone()).is_err());
        assert!(Credential::new("c", "l", Mtc, P256, Some(TA_A.to_vec()), opaque).is_ok());
        assert_eq!(key_scheme(&k), Some(P256));
        assert_eq!(key_scheme(&key(MLDSA87, false)), Some(MLDSA87));
        assert_eq!(CredentialKind::from_name("mldsa"), Some(MlDsa));
        assert_eq!(CredentialKind::from_name("MTC"), None);
    }

    #[test]
    fn decision_table() {
        let s = CredentialSelector::new(Profile::PqRequired, "a", pool()).unwrap();
        // E0: only listener a's credentials are held (SEL-3).
        assert!(s.credentials().iter().all(|c| c.listener() == "a"));
        let all = sig_body(&[P256, MLDSA44]);
        let ta = |ids: &[&[u8]]| ta_body(ids);
        // SEL-1: MTC only on an exact match.
        assert_eq!(pick(&s, Some(&all), Some(&ta(&[TA_A]))), Some("a-mtc"));
        assert_eq!(pick(&s, Some(&all), Some(&ta(&[TA_B, TA_A]))), Some("a-mtc"));
        assert_eq!(pick(&s, Some(&all), None), Some("a-mldsa"));
        assert_eq!(pick(&s, Some(&all), Some(&[])), Some("a-mldsa"));
        assert_eq!(pick(&s, Some(&all), Some(&ta(&[&TA_A[..6]]))), Some("a-mldsa"), "prefix");
        assert_eq!(pick(&s, Some(&all), Some(&ta(&[&[TA_A, &[0]].concat()]))), Some("a-mldsa"), "extension");
        // SEL-3: another listener's TrustAnchorID never selects anything of theirs.
        assert_eq!(pick(&s, Some(&all), Some(&ta(&[TA_B]))), Some("a-mldsa"));
        // tiers and E3: no ML-DSA offered → x509, the first in order.
        assert_eq!(pick(&s, Some(&sig_body(&[P256])), None), Some("a-x509"));
        assert_eq!(pick(&s, Some(&sig_body(&[MLDSA44])), Some(&ta(&[TA_A]))), Some("a-mldsa"));
        // R4: nothing offered / no sigalgs.
        assert_eq!(pick(&s, Some(&sig_body(&[P384])), Some(&ta(&[TA_A]))), None);
        assert_eq!(pick(&s, None, Some(&ta(&[TA_A]))), None);
        // malformed bodies fail closed.
        assert_eq!(pick(&s, Some(&all[..3]), None), None);
        assert_eq!(pick(&s, Some(&all), Some(&[0])), None);
        assert_eq!(pick(&s, Some(&all), Some(&[3, 1, 2])), None);
        assert_eq!(pick(&s, Some(&all), Some(&[33; 34])), None);
    }

    #[test]
    fn sel2_and_sel3() {
        use CredentialKind::*;
        // SEL-2: on P-PUBLIC-WEB an ML-DSA credential is never held, even if the client offers ML-DSA.
        let s = CredentialSelector::new(Profile::PublicWeb, "a", pool()).unwrap();
        assert!(s.credentials().iter().all(|c| c.kind() != MlDsa));
        let all = sig_body(&[P256, MLDSA44]);
        assert_eq!(pick(&s, Some(&all), None), Some("a-x509"));
        assert_eq!(pick(&s, Some(&sig_body(&[MLDSA44])), None), None);
        // SEL-3: a listener with no credentials has nothing, even though others do.
        let s = CredentialSelector::new(Profile::PqRequired, "c", pool()).unwrap();
        assert!(s.credentials().is_empty());
        assert_eq!(pick(&s, Some(&all), Some(&ta_body(&[TA_A, TA_B]))), None);
        // E1: a P-384 credential is never served on PQ-REQUIRED ([0403, 0904]).
        let s = CredentialSelector::new(Profile::PqRequired, "a", vec![cred("x", "a", X509, P384, None)]).unwrap();
        assert!(s.credentials().is_empty());
    }

    // ------------------------------------------------------------------ through the peek and rustls

    fn ext(t: u16, body: &[u8]) -> Vec<u8> {
        [&t.to_be_bytes()[..], &(body.len() as u16).to_be_bytes(), body].concat()
    }

    fn v16(body: &[u8]) -> Vec<u8> {
        [&(body.len() as u16).to_be_bytes()[..], body].concat()
    }

    /// A TLS 1.3 ClientHello record: suites 1301..1303, groups X25519 + X25519MLKEM768, one X25519 share.
    fn hello(sigalgs: &[SignatureScheme], trust_anchors: Option<&[&[u8]]>) -> Vec<u8> {
        let mut exts = Vec::new();
        exts.extend(ext(0, &v16(&[&[0u8][..], &v16(b"aegis.test")].concat())));
        exts.extend(ext(10, &v16(&[0x00, 0x1d, 0x11, 0xec])));
        exts.extend(ext(13, &v16(&sig_body(sigalgs))));
        exts.extend(ext(43, &[2, 0x03, 0x04]));
        exts.extend(ext(45, &[1, 1]));
        exts.extend(ext(51, &v16(&[&[0x00, 0x1d, 0x00, 0x20][..], &[9u8; 32]].concat())));
        if let Some(ids) = trust_anchors {
            exts.extend(ext(0xCA34, &v16(&ta_body(ids))));
        }
        let body = [
            &[0x03, 0x03][..],
            &[7u8; 32],
            &[32],
            &[5u8; 32],
            &v16(&[0x13, 0x01, 0x13, 0x02, 0x13, 0x03]),
            &[1, 0],
            &v16(&exts),
        ]
        .concat();
        let hs = [&[1u8][..], &(body.len() as u32).to_be_bytes()[1..], &body].concat();
        [&[0x16, 0x03, 0x01][..], &(hs.len() as u16).to_be_bytes(), &hs].concat()
    }

    /// Whether rustls accepts `fed` with the config for `bound` (the resolver served a credential).
    fn served(s: &CredentialSelector, bound: &[u8], fed: &[u8]) -> bool {
        let mut c = ServerConnection::new(s.config_for(bound)).unwrap();
        let mut rd = fed;
        c.read_tls(&mut rd).unwrap();
        c.process_new_packets().is_ok()
    }

    /// Needs the real aegis-wire peek (P7-wire-001); against the fail-closed stub every hello is refused (R0).
    #[test]
    fn through_peek_and_rustls() {
        let s = CredentialSelector::new(Profile::PqRequired, "a", pool()).unwrap();
        let mtc = hello(&[P256, MLDSA44], Some(&[TA_A]));
        let mldsa = hello(&[P256, MLDSA44], None);
        let x509 = hello(&[P256], Some(&[TA_B]));
        let none = hello(&[P384], Some(&[TA_A]));
        assert_eq!(s.select(&mtc).map(Credential::id), Some("a-mtc"));
        assert_eq!(s.select(&mldsa).map(Credential::id), Some("a-mldsa"));
        assert_eq!(s.select(&x509).map(Credential::id), Some("a-x509"));
        assert_eq!(s.select(&none).map(Credential::id), None);
        assert_eq!(s.select(&mtc[..mtc.len() - 1]).map(Credential::id), None, "R0: truncated");
        for h in [&mtc, &mldsa, &x509] {
            assert!(served(&s, h, h));
        }
        assert!(!served(&s, &none, &none), "R4 → handshake failure");
        // The resolver serves only the hello it was bound to.
        assert!(!served(&s, &x509, &hello(&[MLDSA44], None)));
        // P-PUBLIC-WEB: ML-DSA offered alone → nothing (SEL-2).
        let p = CredentialSelector::new(Profile::PublicWeb, "a", pool()).unwrap();
        let h = hello(&[MLDSA44], None);
        assert_eq!(p.select(&h).map(Credential::id), None);
        assert!(!served(&p, &h, &h));
    }
}
