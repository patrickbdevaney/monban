//! Per-listener TLS profiles (ARCHITECTURE 3.2, spec section F P-PQ1/P-PQ2/P-PQ4, frozen F12 `tls/verdicts.toml`).
//!
//! Every list below is the exact ordered list of the matching `[profiles.*]` row of `tls/verdicts.toml`
//! (`kx_groups`, `sigalgs`). The one place these lists exist in production code is here; `server_config` builds the
//! `CryptoProvider` from them and then re-reads the built provider in [`assert_profile`] (startup assertion).

use std::sync::Arc;
use std::vec::Vec;

use rustls::crypto::{CryptoProvider, SupportedKxGroup, aws_lc_rs as prov};
use rustls::server::{ClientHello, NoServerSessionStorage, ResolvesServerCert};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{ProtocolVersion, ServerConfig, SignatureAlgorithm, SignatureScheme, SupportedCipherSuite};

use crate::kx;

/// TLS Supported Groups codepoints used by the profiles (`[codepoints.groups]` of F12).
pub mod group {
    /// X25519MLKEM768.
    pub const X25519MLKEM768: u16 = 0x11EC;
    /// SecP256r1MLKEM768.
    pub const SECP256R1MLKEM768: u16 = 0x11EB;
    /// SecP384r1MLKEM1024 (AEGIS-owned, [`crate::kx`]).
    pub const SECP384R1MLKEM1024: u16 = 0x11ED;
    /// X25519.
    pub const X25519: u16 = 0x001D;
    /// secp256r1.
    pub const SECP256R1: u16 = 0x0017;
    /// secp384r1.
    pub const SECP384R1: u16 = 0x0018;
    /// ML-KEM-768 (pure).
    pub const MLKEM768: u16 = 0x0201;
    /// ML-KEM-1024 (pure).
    pub const MLKEM1024: u16 = 0x0202;
}

/// A listener profile. Names follow F12 (`tls/verdicts.toml`) and F8 (`interfaces/F8-config.schema.json`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Profile {
    /// F12 `P-PUBLIC-WEB`: public browser listener, hybrid first.
    PublicWeb,
    /// F12 `PQ-REQUIRED` (F8 `P-PQ-REQUIRED`): agent / API / internal listeners; PQ-only.
    PqRequired,
    /// F12 `P-UNIVERSAL`: `[0x11ED]` + ML-DSA-87 / ECDSA-P384 (active since the 2026-11-04 re-freeze).
    Universal,
    /// F12 `P-BSI-ALT`: `[0x11ED, 0x11EB]` + ML-DSA-87 / ECDSA-P384 (active since the 2026-11-04 re-freeze).
    BsiAlt,
    /// F12 `P-CNSA`: `[ML-KEM-1024]` + ML-DSA-87 only (active since the 2026-11-04 re-freeze).
    Cnsa,
    /// F12 `FIPS` (F8 `FIPS-FLOOR`): the FIPS group list on the floor lock (selection checked, no CMVP claim).
    FipsFloor,
    /// F8 `FIPS-CMVP`: the FIPS list on the cmvp lock with the module asserted (P-PQ5). Needs the profiles/cmvp
    /// build; pending in this build.
    FipsCmvp,
    /// F12 / F8 `FIPS-PQ-REQUIRED`: FIPS pq-required listener on the floor lock.
    FipsPqRequired,
}

/// F12 `status` of a profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileStatus {
    /// Checked now.
    Active,
    /// Selection checked now; the FIPS module half (P-PQ5) waits for the cmvp build.
    CmvpPending,
    /// Listed for completeness; `server_config` refuses it with [`ProfileError::Pending`].
    Pending,
}

/// Why a profile could not be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileError {
    /// The profile is marked pending (F12) or needs a build this binary is not (cmvp). Never guessed.
    Pending {
        /// The profile.
        profile: Profile,
        /// The pending reason (from F12 where it has one).
        reason: &'static str,
    },
    /// rustls refused the configuration.
    Rustls(String),
    /// A startup assertion on the built config failed (P-PQ2 / P-PQ4 / `kx_groups[0]`).
    Assertion(String),
    /// The profile is a listener (server) profile with no client definition; [`client_config`] refuses it.
    NotForClients {
        /// The profile.
        profile: Profile,
        /// Why no client profile is defined for it.
        reason: &'static str,
    },
}

impl core::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Pending { profile, reason } => write!(f, "profile {} is pending: {reason}", profile.name()),
            Self::Rustls(e) => write!(f, "rustls: {e}"),
            Self::Assertion(e) => write!(f, "startup assertion failed: {e}"),
            Self::NotForClients { profile, reason } => {
                write!(f, "profile {} has no client definition: {reason}", profile.name())
            }
        }
    }
}

impl std::error::Error for ProfileError {}

use group::*;

const PUBLIC_WEB_KX: &[u16] = &[X25519MLKEM768, SECP384R1MLKEM1024, SECP256R1MLKEM768, X25519, SECP256R1];
const PQ_REQUIRED_KX: &[u16] = &[X25519MLKEM768];
const UNIVERSAL_KX: &[u16] = &[SECP384R1MLKEM1024];
const BSI_ALT_KX: &[u16] = &[SECP384R1MLKEM1024, SECP256R1MLKEM768];
const CNSA_KX: &[u16] = &[MLKEM1024];
const FIPS_KX: &[u16] = &[SECP256R1MLKEM768, SECP256R1, SECP384R1];
const FIPS_PQ_REQUIRED_KX: &[u16] = &[SECP256R1MLKEM768];

const PUBLIC_WEB_SIG: &[SignatureScheme] = &[SignatureScheme::ECDSA_NISTP256_SHA256];
const PQ_REQUIRED_SIG: &[SignatureScheme] = &[SignatureScheme::ECDSA_NISTP256_SHA256, SignatureScheme::ML_DSA_44];
#[cfg(not(feature = "cmvp"))]
const GOV_SIG: &[SignatureScheme] = &[SignatureScheme::ML_DSA_87, SignatureScheme::ECDSA_NISTP384_SHA384];
const CNSA_SIG: &[SignatureScheme] = &[SignatureScheme::ML_DSA_87];
const FIPS_SIG: &[SignatureScheme] = &[SignatureScheme::ECDSA_NISTP256_SHA256, SignatureScheme::ECDSA_NISTP384_SHA384];

#[cfg(feature = "tls-client")]
const FIPS_FLOOR_NOT_CLIENT: &str = "P-PQ6: a FIPS-side client offers exactly [SecP256r1MLKEM768] (nothing \
     classical for a RUSTSEC-2026-0349 downgrade to land on); this list adds P-256/P-384. Use FIPS-PQ-REQUIRED.";
#[cfg(not(feature = "cmvp"))]
const PENDING_CMVP: &str = "needs the cmvp lock (rustls =0.23.43, aws-lc-rs =1.15.3 [fips], aws-lc-fips-sys =0.13.11) and the P-PQ5 module-identity gate (Phase 6); this is the floor build.";
/// PLAN-6 D15: P-CNSA requires ML-DSA-87, which aws-lc-rs 1.15.3 compiles out under `fips` (and which AWS-LC FIPS
/// 3.1.0 does not approve, COMPLIANCE_MAP). Refused at boot on the cmvp build, never served without ML-DSA-87.
#[cfg(feature = "cmvp")]
// No module version in this text: the binary must carry no `AWS-LC FIPS x.y.z` string but the module's own.
const CNSA_NOT_ON_CMVP: &str = "P-CNSA requires ML-DSA-87, which the cmvp build (aws-lc-rs =1.15.3 [fips], the \
     certified module) does not have (PLAN-6 D15); serve P-CNSA from the floor build";

/// PLAN-6 D15: on the cmvp build the gov profiles sign with ECDSA-P384 only (no ML-DSA-87 in aws-lc-rs 1.15.3 fips).
#[cfg(feature = "cmvp")]
const GOV_SIG_CMVP: &[SignatureScheme] = &[SignatureScheme::ECDSA_NISTP384_SHA384];

/// The module identity a cmvp build must link (P-PQ5): `AWS-LC FIPS` + this version. Kept as numbers, not as the
/// module string, so this crate never puts an `AWS-LC FIPS x.y.z` literal into the binary (the fips-binary gate's
/// strings check must see only the module's own copy).
const CMVP_MODULE_VERSION: [u32; 3] = [3, 1, 0];
const MODULE_PREFIX: &str = "AWS-LC FIPS ";

impl Profile {
    /// Every profile.
    pub const ALL: [Profile; 8] = [
        Profile::PublicWeb,
        Profile::PqRequired,
        Profile::Universal,
        Profile::BsiAlt,
        Profile::Cnsa,
        Profile::FipsFloor,
        Profile::FipsCmvp,
        Profile::FipsPqRequired,
    ];

    /// The F12 profile name, if F12 has a row for it.
    pub fn f12_name(self) -> Option<&'static str> {
        match self {
            Self::PublicWeb => Some("P-PUBLIC-WEB"),
            Self::PqRequired => Some("PQ-REQUIRED"),
            Self::Universal => Some("P-UNIVERSAL"),
            Self::BsiAlt => Some("P-BSI-ALT"),
            Self::Cnsa => Some("P-CNSA"),
            Self::FipsFloor => Some("FIPS"),
            Self::FipsCmvp => None,
            Self::FipsPqRequired => Some("FIPS-PQ-REQUIRED"),
        }
    }

    /// The F8 config name, if the F8 enum has one.
    pub fn f8_name(self) -> Option<&'static str> {
        match self {
            Self::PublicWeb => Some("P-PUBLIC-WEB"),
            Self::PqRequired => Some("P-PQ-REQUIRED"),
            Self::Universal => Some("P-UNIVERSAL"),
            Self::BsiAlt => Some("P-BSI-ALT"),
            Self::Cnsa => Some("P-CNSA"),
            Self::FipsFloor => Some("FIPS-FLOOR"),
            Self::FipsCmvp => Some("FIPS-CMVP"),
            Self::FipsPqRequired => Some("FIPS-PQ-REQUIRED"),
        }
    }

    /// A display name (F12 name, else F8 name).
    pub fn name(self) -> &'static str {
        self.f12_name().or(self.f8_name()).unwrap_or("?")
    }

    /// Look a profile up by its F12 or F8 name.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.f12_name() == Some(name) || p.f8_name() == Some(name))
    }

    /// F12 status.
    pub fn status(self) -> ProfileStatus {
        match self {
            Self::PublicWeb | Self::PqRequired | Self::Universal | Self::BsiAlt => ProfileStatus::Active,
            #[cfg(not(feature = "cmvp"))]
            Self::Cnsa => ProfileStatus::Active,
            #[cfg(feature = "cmvp")]
            Self::Cnsa => ProfileStatus::Pending,
            Self::FipsFloor | Self::FipsPqRequired => ProfileStatus::CmvpPending,
            #[cfg(not(feature = "cmvp"))]
            Self::FipsCmvp => ProfileStatus::Pending,
            // Buildable on the cmvp build only; `server_config` still asserts the module identity (P-PQ5).
            #[cfg(feature = "cmvp")]
            Self::FipsCmvp => ProfileStatus::Active,
        }
    }

    /// Why the profile is pending, if it is.
    pub fn pending_reason(self) -> Option<&'static str> {
        match self {
            #[cfg(not(feature = "cmvp"))]
            Self::FipsCmvp => Some(PENDING_CMVP),
            #[cfg(feature = "cmvp")]
            Self::Cnsa => Some(CNSA_NOT_ON_CMVP),
            _ => None,
        }
    }

    /// Exact ordered kx group list (F12 `kx_groups`). P-PQ2: the configured set equals this list.
    pub fn kx_groups(self) -> &'static [u16] {
        match self {
            Self::PublicWeb => PUBLIC_WEB_KX,
            Self::PqRequired => PQ_REQUIRED_KX,
            Self::Universal => UNIVERSAL_KX,
            Self::BsiAlt => BSI_ALT_KX,
            Self::Cnsa => CNSA_KX,
            Self::FipsFloor | Self::FipsCmvp => FIPS_KX,
            Self::FipsPqRequired => FIPS_PQ_REQUIRED_KX,
        }
    }

    /// CertificateVerify schemes the listener may produce (F12 `sigalgs`, P-PQ2).
    pub fn sigalgs(self) -> &'static [SignatureScheme] {
        match self {
            Self::PublicWeb => PUBLIC_WEB_SIG,
            Self::PqRequired => PQ_REQUIRED_SIG,
            #[cfg(not(feature = "cmvp"))]
            Self::Universal | Self::BsiAlt => GOV_SIG,
            #[cfg(feature = "cmvp")]
            Self::Universal | Self::BsiAlt => GOV_SIG_CMVP,
            Self::Cnsa => CNSA_SIG,
            Self::FipsFloor | Self::FipsCmvp | Self::FipsPqRequired => FIPS_SIG,
        }
    }

    /// Government and FIPS profiles: AES-GCM only (ARCHITECTURE 3.2: no ChaCha20).
    fn aes_gcm_only(self) -> bool {
        !matches!(self, Self::PublicWeb | Self::PqRequired)
    }
}

/// The rustls kx group implementing a codepoint (aws-lc-rs provider, plus our 0x11ED).
pub fn kx_group(codepoint: u16) -> Option<&'static dyn SupportedKxGroup> {
    use prov::kx_group as g;
    Some(match codepoint {
        X25519MLKEM768 => g::X25519MLKEM768,
        SECP256R1MLKEM768 => g::SECP256R1MLKEM768,
        SECP384R1MLKEM1024 => kx::SECP384R1MLKEM1024,
        X25519 => g::X25519,
        SECP256R1 => g::SECP256R1,
        SECP384R1 => g::SECP384R1,
        MLKEM768 => g::MLKEM768,
        MLKEM1024 => g::MLKEM1024,
        _ => return None,
    })
}

/// The profile's `CryptoProvider`: kx groups = [`Profile::kx_groups`] exactly, in order; TLS 1.3 cipher suites only
/// (AES-GCM only for the government and FIPS profiles). [`server_config`] and `client_config` both build from it; it
/// is public so that oracle subjects (the tls-subject interop client) use this table instead of a copy.
pub fn provider(profile: Profile) -> Result<CryptoProvider, ProfileError> {
    let kx_groups = profile
        .kx_groups()
        .iter()
        .map(|c| kx_group(*c).ok_or_else(|| ProfileError::Assertion(format!("no implementation for group 0x{c:04x}"))))
        .collect::<Result<Vec<_>, _>>()?;
    let base = prov::default_provider();
    let cipher_suites: Vec<SupportedCipherSuite> = if profile.aes_gcm_only() {
        vec![prov::cipher_suite::TLS13_AES_256_GCM_SHA384, prov::cipher_suite::TLS13_AES_128_GCM_SHA256]
    } else {
        base.cipher_suites.iter().copied().filter(|s| s.version().version == ProtocolVersion::TLSv1_3).collect()
    };
    Ok(CryptoProvider { kx_groups, cipher_suites, ..base })
}

/// Build the `ServerConfig` for a profile. TLS 1.3 only, no 0-RTT (P-PQ4); configured groups = profile exactly
/// (P-PQ2); CertificateVerify restricted to the profile's sigalgs (P-PQ2); resumption off until the scoped
/// ticketer lands (P-PQ3, unit P2-tls-002). Startup assertions run on the built config before it is returned.
pub fn server_config(
    profile: Profile,
    cert_resolver: Arc<dyn ResolvesServerCert>,
) -> Result<ServerConfig, ProfileError> {
    if profile.status() == ProfileStatus::Pending {
        return Err(ProfileError::Pending { profile, reason: profile.pending_reason().unwrap_or("pending") });
    }
    let provider = Arc::new(provider(profile)?);
    let resolver = Arc::new(ProfileCertResolver { inner: cert_resolver, allowed: profile.sigalgs() });
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| ProfileError::Rustls(e.to_string()))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.max_early_data_size = 0;
    cfg.send_half_rtt_data = false;
    cfg.send_tls13_tickets = 0;
    cfg.session_storage = Arc::new(NoServerSessionStorage {});
    assert_profile(&cfg, profile)?;
    if profile == Profile::FipsCmvp {
        assert_cmvp_module(&cfg)?;
    }
    Ok(cfg)
}

/// P-PQ5 startup assertion for FIPS-CMVP: the config is FIPS (`ServerConfig::fips()`), the module is in FIPS mode,
/// and the linked module reports exactly `AWS-LC FIPS 3.1.0`. Fails closed when the identity cannot be read.
fn assert_cmvp_module(cfg: &ServerConfig) -> Result<(), ProfileError> {
    let st = fips_status(cfg);
    if st.cmvp_claim {
        return Ok(());
    }
    Err(ProfileError::Assertion(format!(
        "FIPS-CMVP: P-PQ5 module identity not established (config_fips={}, module_fips_mode={}, module={})",
        st.config_fips,
        st.module_fips_mode,
        st.module.unwrap_or("none")
    )))
}

/// Protocol versions the built config can negotiate, read from its provider: rustls negotiates a version only if a
/// cipher suite for it is configured, so this is an upper bound taken from the config itself. (TLS 1.2 is also
/// compiled out: the workspace rustls has no `tls12` feature.)
pub fn negotiable_versions(cfg: &ServerConfig) -> Vec<ProtocolVersion> {
    let mut v = Vec::new();
    for s in &cfg.crypto_provider().cipher_suites {
        let ver = s.version().version;
        if !v.contains(&ver) {
            v.push(ver);
        }
    }
    v
}

/// Startup assertion: the built config matches the profile (P-PQ2 configured groups = profile, in order, so
/// `kx_groups[0]` is checked; P-PQ4 TLS 1.3 only and no 0-RTT; no resumption tickets before P-PQ3).
pub fn assert_profile(cfg: &ServerConfig, profile: Profile) -> Result<(), ProfileError> {
    let configured: Vec<u16> = cfg.crypto_provider().kx_groups.iter().map(|g| u16::from(g.name())).collect();
    if configured.first() != profile.kx_groups().first() {
        return Err(ProfileError::Assertion(format!(
            "{}: kx_groups[0] = {:04x?}, profile requires {:04x?}",
            profile.name(),
            configured.first(),
            profile.kx_groups().first()
        )));
    }
    if configured != profile.kx_groups() {
        return Err(ProfileError::Assertion(format!(
            "{}: configured kx_groups {configured:04x?} != profile {:04x?}",
            profile.name(),
            profile.kx_groups()
        )));
    }
    if negotiable_versions(cfg) != [ProtocolVersion::TLSv1_3] {
        return Err(ProfileError::Assertion(format!(
            "{}: versions {:?} != [TLSv1_3]",
            profile.name(),
            negotiable_versions(cfg)
        )));
    }
    if cfg.max_early_data_size != 0 {
        return Err(ProfileError::Assertion(format!("{}: 0-RTT enabled", profile.name())));
    }
    if cfg.send_tls13_tickets != 0 {
        return Err(ProfileError::Assertion(format!("{}: tickets enabled before P-PQ3", profile.name())));
    }
    Ok(())
}

/// Why `profile` has no client definition, if it has none. Pending profiles are refused as for the server; the FIPS
/// listener list is refused for clients by P-PQ6.
#[cfg(feature = "tls-client")]
fn client_refusal(profile: Profile) -> Option<ProfileError> {
    if profile.status() == ProfileStatus::Pending {
        return Some(ProfileError::Pending { profile, reason: profile.pending_reason().unwrap_or("pending") });
    }
    match profile {
        Profile::FipsFloor | Profile::FipsCmvp => {
            Some(ProfileError::NotForClients { profile, reason: FIPS_FLOOR_NOT_CLIENT })
        }
        _ => None,
    }
}

/// The client ALPN list: the egress HTTP exchange is hand-written HTTP/1.1.
#[cfg(feature = "tls-client")]
pub const CLIENT_ALPN: &[u8] = b"http/1.1";

/// Build the rustls `ClientConfig` for a profile (feature `tls-client`; compiled out of the cmvp build,
/// spikes/cmvp-client-policy mode A). This is the only place the workspace's protocol layer builds a client config.
///
/// Key exchange = the profile's own [`Profile::kx_groups`] list, in order (the same table [`server_config`] uses),
/// so `P-PUBLIC-WEB` offers `[X25519MLKEM768, SecP384r1MLKEM1024, SecP256r1MLKEM768, X25519, secp256r1]` (hybrid
/// first) and
/// `FIPS-PQ-REQUIRED` offers `[SecP256r1MLKEM768]` (the P-PQ6 client shape). Cipher suites as for the server
/// (TLS 1.3; AES-GCM only for FIPS). TLS 1.3 only, resumption disabled and early data off, so no session ticket or
/// key-share-prediction state is ever kept (RUSTSEC-2026-0349; the advisory exempts resumption-disabled clients).
/// ALPN `http/1.1`. Trust anchors are the caller's `roots`; no platform verifier.
///
/// Refused with [`ProfileError::Pending`] for pending profiles and [`ProfileError::NotForClients`] for `FIPS`
/// (P-PQ6). The built config is re-read by [`assert_client_profile`] before it is returned.
#[cfg(feature = "tls-client")]
pub fn client_config(profile: Profile, roots: rustls::RootCertStore) -> Result<rustls::ClientConfig, ProfileError> {
    if let Some(e) = client_refusal(profile) {
        return Err(e);
    }
    let provider = Arc::new(provider(profile)?);
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| ProfileError::Rustls(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.resumption = rustls::client::Resumption::disabled();
    cfg.enable_early_data = false;
    cfg.alpn_protocols = Vec::from([CLIENT_ALPN.to_vec()]);
    assert_client_profile(&cfg, profile)?;
    Ok(cfg)
}

/// Startup assertion for a client config: the profile is defined for clients; kx list = the profile's list exactly,
/// in order; only TLS 1.3 suites; early data off; resumption disabled (no session storage, no TLS 1.2 resumption,
/// read from `Resumption`'s Debug form since rustls exposes no accessor); ALPN exactly `[http/1.1]`.
#[cfg(feature = "tls-client")]
pub fn assert_client_profile(cfg: &rustls::ClientConfig, profile: Profile) -> Result<(), ProfileError> {
    if let Some(e) = client_refusal(profile) {
        return Err(e);
    }
    let name = profile.name();
    let kx: Vec<u16> = cfg.crypto_provider().kx_groups.iter().map(|g| u16::from(g.name())).collect();
    if kx != profile.kx_groups() {
        return Err(ProfileError::Assertion(format!(
            "{name} client: kx_groups {kx:04x?} != profile {:04x?}",
            profile.kx_groups()
        )));
    }
    let suites = &cfg.crypto_provider().cipher_suites;
    if suites.is_empty() || suites.iter().any(|s| s.version().version != ProtocolVersion::TLSv1_3) {
        return Err(ProfileError::Assertion(format!("{name} client: suites are not TLS 1.3 only")));
    }
    if cfg.enable_early_data {
        return Err(ProfileError::Assertion(format!("{name} client: early data enabled")));
    }
    let r = format!("{:?}", cfg.resumption);
    if !r.contains("NoClientSessionStorage") || !r.contains("Disabled") {
        return Err(ProfileError::Assertion(format!("{name} client: resumption not disabled: {r}")));
    }
    if cfg.alpn_protocols != [CLIENT_ALPN] {
        return Err(ProfileError::Assertion(format!("{name} client: ALPN {:?} != [http/1.1]", cfg.alpn_protocols)));
    }
    Ok(())
}

/// FIPS status of a built config (ARCHITECTURE 3.2: reported to the audit log and `/healthz`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FipsStatus {
    /// `ServerConfig::fips()`.
    pub config_fips: bool,
    /// `aws_lc_rs::try_fips_mode().is_ok()`: blind to the module version (decoy lock).
    pub module_fips_mode: bool,
    /// FIPS module identity linked into the binary (P-PQ5), e.g. `AWS-LC FIPS 3.1.0`, as the module reports it at
    /// run time (PLAN-6 D2). `Some` only on the cmvp build with `config_fips` true; `None` on the floor build.
    pub module: Option<&'static str>,
    /// Whether a CMVP claim may be made: cmvp build, `config_fips`, `module_fips_mode`, and `module` is exactly
    /// `AWS-LC FIPS 3.1.0`. Always false on the floor build.
    pub cmvp_claim: bool,
}

/// Report the FIPS status of a built config.
pub fn fips_status(cfg: &ServerConfig) -> FipsStatus {
    status_from(cfg.fips())
}

fn status_from(config_fips: bool) -> FipsStatus {
    let module_fips_mode = aws_lc_rs::try_fips_mode().is_ok();
    let module = if cfg!(feature = "cmvp") && config_fips { linked_module() } else { None };
    let cmvp_claim = cfg!(feature = "cmvp") && config_fips && module_fips_mode && module.is_some_and(is_cmvp_module);
    FipsStatus { config_fips, module_fips_mode, module, cmvp_claim }
}

/// Whether `m` is exactly `AWS-LC FIPS 3.1.0` (compared without a contiguous literal, see [`CMVP_MODULE_VERSION`]).
fn is_cmvp_module(m: &str) -> bool {
    let Some(v) = m.strip_prefix(MODULE_PREFIX) else { return false };
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == CMVP_MODULE_VERSION.len() && parts.iter().zip(CMVP_MODULE_VERSION).all(|(p, n)| *p == n.to_string())
}

/// The linked AWS-LC module's own version string (`awslc_version_string()`), read at run time.
///
/// Neither aws-lc-rs 1.15.3 nor rustls 0.23.43 exposes it through a safe API: the only access is the
/// `aws_lc_fips_sys::awslc_version_string` extern "C" function, which needs `unsafe` (forbidden in this crate,
/// CLAUDE.md). Until an audited site is approved (units/phase-6/reports/P6-cmvp-001-INFEASIBLE.md) this returns
/// `None`, so no build claims a module identity it has not read: `cmvp_claim` stays false, FIPS-CMVP is refused
/// by [`server_config`], and `aegis --fips-check` exits 1.
fn linked_module() -> Option<&'static str> {
    None
}

/// The process-level FIPS check (`aegis --fips-check`), independent of any listener: `fips_mode` is the FIPS
/// profile provider's `CryptoProvider::fips()` and the module's FIPS mode; `module` as in [`FipsStatus`].
pub fn fips_check() -> FipsStatus {
    let config_fips = provider(Profile::FipsFloor).map(|p| p.fips()).unwrap_or(false);
    status_from(config_fips)
}

/// Wraps the caller's resolver so the served key can only sign with the profile's sigalgs (P-PQ2). If the
/// resolved key cannot sign with any scheme that is both offered and allowed, no certificate is served and the
/// handshake fails (rustls sends access_denied, 49) instead of using an out-of-profile scheme.
#[derive(Debug)]
struct ProfileCertResolver {
    inner: Arc<dyn ResolvesServerCert>,
    allowed: &'static [SignatureScheme],
}

impl ResolvesServerCert for ProfileCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let offered: Vec<SignatureScheme> = client_hello.signature_schemes().to_vec();
        let ck = self.inner.resolve(client_hello)?;
        restrict(&ck, &offered, self.allowed)
    }

    fn only_raw_public_keys(&self) -> bool {
        self.inner.only_raw_public_keys()
    }
}

/// The served credential for a ClientHello offering `offered`: `ck` re-wrapped so it can only sign with `allowed`,
/// or `None` (rustls: access_denied, 49; F12 UNI-T5 / CNSA-T3) when no offered scheme is both in the profile and
/// signable by the key.
fn restrict(
    ck: &CertifiedKey,
    offered: &[SignatureScheme],
    allowed: &'static [SignatureScheme],
) -> Option<Arc<CertifiedKey>> {
    let in_profile: Vec<SignatureScheme> = offered.iter().copied().filter(|s| allowed.contains(s)).collect();
    if in_profile.is_empty() {
        return None;
    }
    let key: Arc<dyn SigningKey> = Arc::new(RestrictedKey { inner: ck.key.clone(), allowed });
    key.choose_scheme(&in_profile)?;
    Some(Arc::new(CertifiedKey { cert: ck.cert.clone(), key, ocsp: ck.ocsp.clone() }))
}

#[derive(Debug)]
struct RestrictedKey {
    inner: Arc<dyn SigningKey>,
    allowed: &'static [SignatureScheme],
}

impl SigningKey for RestrictedKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let filtered: Vec<SignatureScheme> = offered.iter().copied().filter(|s| self.allowed.contains(s)).collect();
        let signer = self.inner.choose_scheme(&filtered)?;
        // Defence in depth: never return a signer whose scheme is outside the profile.
        self.allowed.contains(&signer.scheme()).then_some(signer)
    }

    fn public_key(&self) -> Option<rustls::pki_types::SubjectPublicKeyInfoDer<'_>> {
        self.inner.public_key()
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.inner.algorithm()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[derive(Debug)]
    struct NoCert;
    impl ResolvesServerCert for NoCert {
        fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            None
        }
    }

    #[test]
    fn module_identity_is_exact() {
        assert!(is_cmvp_module(&format!("{MODULE_PREFIX}3.1.0")));
        for m in
            ["", "AWS-LC FIPS 4.2.0", "AWS-LC FIPS 3.1", "AWS-LC FIPS 3.1.0.1", "AWS-LC FIPS 3.1.00", "AWS-LC 3.1.0"]
        {
            assert!(!is_cmvp_module(m), "{m}");
        }
    }

    /// Floor build: no module identity, no claim, FIPS-CMVP pending (unchanged from Phase 5).
    #[cfg(not(feature = "cmvp"))]
    #[test]
    fn floor_reports_no_module() {
        let st = fips_check();
        assert_eq!((st.module, st.cmvp_claim), (None, false));
        assert_eq!(Profile::FipsCmvp.status(), ProfileStatus::Pending);
        assert_eq!(Profile::Cnsa.status(), ProfileStatus::Active);
        let _ = NoCert;
    }

    /// cmvp build (PLAN-6 D15): P-CNSA refused at boot with the reason; gov profiles ECDSA-P384 only.
    #[cfg(feature = "cmvp")]
    #[test]
    fn cmvp_refuses_cnsa_and_drops_mldsa() {
        match server_config(Profile::Cnsa, Arc::new(NoCert)) {
            Err(ProfileError::Pending { profile: Profile::Cnsa, reason }) => assert_eq!(reason, CNSA_NOT_ON_CMVP),
            other => panic!("P-CNSA on cmvp: expected Pending, got {other:?}"),
        }
        for p in [Profile::Universal, Profile::BsiAlt] {
            assert_eq!(p.sigalgs(), [SignatureScheme::ECDSA_NISTP384_SHA384], "{p:?}");
            assert!(server_config(p, Arc::new(NoCert)).is_ok(), "{p:?}");
        }
        assert_eq!(Profile::FipsCmvp.status(), ProfileStatus::Active);
    }

    /// cmvp build: FIPS-CMVP is served only with the P-PQ5 identity established; otherwise refused at boot.
    #[cfg(feature = "cmvp")]
    #[test]
    fn cmvp_fips_cmvp_requires_module_identity() {
        let claim = fips_check().cmvp_claim;
        match server_config(Profile::FipsCmvp, Arc::new(NoCert)) {
            Ok(cfg) => {
                assert!(claim);
                assert!(fips_status(&cfg).module.is_some_and(is_cmvp_module));
            }
            Err(ProfileError::Assertion(e)) => {
                assert!(!claim);
                assert!(e.contains("P-PQ5"), "{e}");
            }
            Err(e) => panic!("FIPS-CMVP: {e}"),
        }
        // Without config FIPS, never a module or a claim.
        let st = status_from(false);
        assert_eq!((st.module, st.cmvp_claim), (None, false));
    }
}
