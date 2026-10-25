//! Certificate lifecycle, CERT-1..4 (spec §G; ARCHITECTURE §3.11 "ACME and certs").
//!
//! * [`CertStore`]: the served certificate, an atomically swappable `Arc<CertifiedKey>` behind a std `RwLock`
//!   (ArcSwap-like: readers clone the `Arc` and drop the lock at once). It implements rustls
//!   [`ResolvesServerCert`], so a swap affects only handshakes that start after it; connections that already
//!   completed their handshake keep their keys and are never dropped.
//! * CERT-1: [`seconds_to_expiry`] is the value of the `cert_seconds_to_expiry` gauge ([`CERT_SECONDS_TO_EXPIRY`]).
//! * CERT-2: [`ExpiryTracker`] fires each alert threshold of [`ALERT_THRESHOLDS_DAYS`] (30/14/7/3 d) once per
//!   certificate, plus [`AlertLevel::Expired`].
//! * CERT-3: [`check_tls`] is the `check-config --tls` preflight: chain structure and link signatures, key/cert
//!   match, the profile's sigalg rule (aegis-tls), validity at the injected clock. [`CertStore::install_checked`]
//!   runs it before every swap, so a bad chain is never served.
//! * CERT-4: every time-dependent function takes a [`Clock`]; [`OffsetClock`] / [`FixedClock`] let tests and the
//!   oracle advance time (+400 d) without faketime.
//!
//! Server side only: nothing here builds a rustls `ClientConfig` (the ACME client is behind feature `acme`).

pub mod b64;
pub mod der;
pub mod time;
pub mod x509;

#[cfg(test)]
pub(crate) mod testutil;

use std::string::String;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::vec::Vec;

use aegis_tls::{Profile, ProfileStatus};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use self::x509::{CertInfo, LinkError, MAX_CHAIN, parse_cert, verify_link};

/// Name of the CERT-1 gauge.
pub const CERT_SECONDS_TO_EXPIRY: &str = "cert_seconds_to_expiry";
/// CERT-2 alert thresholds, days before notAfter, in firing order.
pub const ALERT_THRESHOLDS_DAYS: [i64; 4] = [30, 14, 7, 3];
const DAY: i64 = 86_400;

// ------------------------------------------------------------------------------------------------ clock (CERT-4)

/// Wall-clock source in Unix seconds. Injected everywhere a certificate decision depends on time.
pub trait Clock: Send + Sync + core::fmt::Debug {
    /// Current time, Unix seconds.
    fn now(&self) -> i64;
}

fn system_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// The system clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        system_now()
    }
}

/// System clock plus an adjustable offset (the in-process replacement for faketime).
#[derive(Debug, Default)]
pub struct OffsetClock {
    offset: AtomicI64,
}

impl OffsetClock {
    /// Offset 0.
    pub fn new() -> Self {
        Self::default()
    }
    /// Set the offset (seconds).
    pub fn set_offset(&self, secs: i64) {
        self.offset.store(secs, Ordering::SeqCst);
    }
    /// Add to the offset.
    pub fn advance(&self, secs: i64) {
        let cur = self.offset.load(Ordering::SeqCst);
        self.offset.store(cur.saturating_add(secs), Ordering::SeqCst);
    }
    /// Current offset.
    pub fn offset(&self) -> i64 {
        self.offset.load(Ordering::SeqCst)
    }
}

impl Clock for OffsetClock {
    fn now(&self) -> i64 {
        system_now().saturating_add(self.offset())
    }
}

/// A clock that only moves when told to.
#[derive(Debug, Default)]
pub struct FixedClock {
    t: AtomicI64,
}

impl FixedClock {
    /// At `t`.
    pub fn at(t: i64) -> Self {
        Self { t: AtomicI64::new(t) }
    }
    /// Set the time.
    pub fn set(&self, t: i64) {
        self.t.store(t, Ordering::SeqCst);
    }
    /// Move forward.
    pub fn advance(&self, secs: i64) {
        let cur = self.t.load(Ordering::SeqCst);
        self.t.store(cur.saturating_add(secs), Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now(&self) -> i64 {
        self.t.load(Ordering::SeqCst)
    }
}

// ------------------------------------------------------------------------------------------------ expiry (CERT-1/2)

/// CERT-1 gauge value: seconds from `now` to notAfter (negative once expired).
pub fn seconds_to_expiry(not_after: i64, now: i64) -> i64 {
    not_after.saturating_sub(now)
}

/// CERT-2 alert level for a gauge value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlertLevel {
    /// More than 30 days left.
    Ok,
    /// ≤ 30 days.
    Days30,
    /// ≤ 14 days.
    Days14,
    /// ≤ 7 days.
    Days7,
    /// ≤ 3 days.
    Days3,
    /// notAfter has passed.
    Expired,
}

impl AlertLevel {
    /// Stable name for status lines / metrics labels.
    pub fn name(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Days30 => "30d",
            Self::Days14 => "14d",
            Self::Days7 => "7d",
            Self::Days3 => "3d",
            Self::Expired => "expired",
        }
    }

    const ORDER: [AlertLevel; 6] = [Self::Ok, Self::Days30, Self::Days14, Self::Days7, Self::Days3, Self::Expired];
}

/// Map a CERT-1 gauge value to its CERT-2 level.
pub fn alert_level(secs_to_expiry: i64) -> AlertLevel {
    if secs_to_expiry <= 0 {
        return AlertLevel::Expired;
    }
    let mut level = AlertLevel::Ok;
    for (days, l) in
        ALERT_THRESHOLDS_DAYS.iter().zip([AlertLevel::Days30, AlertLevel::Days14, AlertLevel::Days7, AlertLevel::Days3])
    {
        if secs_to_expiry <= days.saturating_mul(DAY) {
            level = l;
        }
    }
    level
}

/// One expiry observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpiryObservation {
    /// `cert_seconds_to_expiry`.
    pub seconds_to_expiry: i64,
    /// Current level.
    pub level: AlertLevel,
    /// Levels newly crossed since the previous observation of the same certificate, in order (each fires once).
    pub fired: Vec<AlertLevel>,
}

/// Edge-triggered CERT-2 alerting: every threshold fires exactly once per certificate (keyed by serial), even when
/// time jumps past several at once (+400 d fires 30d, 14d, 7d, 3d and expired together).
#[derive(Debug, Default)]
pub struct ExpiryTracker {
    serial: Vec<u8>,
    highest: Option<AlertLevel>,
}

impl ExpiryTracker {
    /// New tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe the certificate `serial` with `not_after` at `now`.
    pub fn observe(&mut self, serial: &[u8], not_after: i64, now: i64) -> ExpiryObservation {
        if self.serial != serial {
            self.serial = serial.to_vec();
            self.highest = None;
        }
        let secs = seconds_to_expiry(not_after, now);
        let level = alert_level(secs);
        let prev = self.highest.unwrap_or(AlertLevel::Ok);
        let fired: Vec<AlertLevel> =
            AlertLevel::ORDER.iter().copied().filter(|l| *l != AlertLevel::Ok && *l > prev && *l <= level).collect();
        if level > prev {
            self.highest = Some(level);
        }
        ExpiryObservation { seconds_to_expiry: secs, level, fired }
    }
}

// ------------------------------------------------------------------------------------------------ preflight (CERT-3)

/// Why a certificate/key pair was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreflightError {
    /// The chain is empty or longer than [`MAX_CHAIN`].
    ChainLength,
    /// A certificate does not parse.
    Malformed {
        /// Position in the chain.
        index: usize,
        /// Reason.
        reason: &'static str,
    },
    /// A chain link does not verify.
    Link {
        /// Index of the child certificate.
        index: usize,
        /// Reason.
        reason: LinkError,
    },
    /// The top of the chain is not issued by any configured root.
    UntrustedRoot,
    /// The private key does not load.
    Key(String),
    /// The private key does not match the leaf certificate.
    KeyMismatch,
    /// The key cannot sign with any of the profile's sigalgs (P-PQ2 / F12 `sigalgs`).
    SigalgNotInProfile {
        /// Profile name.
        profile: &'static str,
    },
    /// The profile cannot be served by this build.
    ProfilePending(&'static str),
    /// notBefore is in the future at the injected clock.
    NotYetValid {
        /// notBefore.
        not_before: i64,
    },
    /// notAfter has passed at the injected clock.
    Expired {
        /// notAfter.
        not_after: i64,
    },
}

impl core::fmt::Display for PreflightError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ChainLength => write!(f, "chain is empty or longer than {MAX_CHAIN}"),
            Self::Malformed { index, reason } => write!(f, "certificate {index}: {reason}"),
            Self::Link { index, reason } => write!(f, "certificate {index} is not issued by the next one: {reason:?}"),
            Self::UntrustedRoot => write!(f, "chain does not end at a configured root"),
            Self::Key(e) => write!(f, "private key: {e}"),
            Self::KeyMismatch => write!(f, "private key does not match the leaf certificate"),
            Self::SigalgNotInProfile { profile } => write!(f, "key cannot sign with any sigalg of {profile}"),
            Self::ProfilePending(p) => write!(f, "profile {p} is pending in this build"),
            Self::NotYetValid { not_before } => write!(f, "not valid before {}", time::format_rfc3339(*not_before)),
            Self::Expired { not_after } => write!(f, "expired at {}", time::format_rfc3339(*not_after)),
        }
    }
}

impl std::error::Error for PreflightError {}

/// What the preflight learned about an accepted pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreflightReport {
    /// Leaf serial (INTEGER contents).
    pub serial: Vec<u8>,
    /// Leaf notBefore.
    pub not_before: i64,
    /// Leaf notAfter.
    pub not_after: i64,
    /// Leaf dNSNames.
    pub dns_names: Vec<String>,
    /// The CertificateVerify scheme the key would use under the profile.
    pub scheme: rustls::SignatureScheme,
    /// CERT-1 gauge at the check.
    pub seconds_to_expiry: i64,
}

/// CERT-3 preflight (`check-config --tls`): `chain[0]` is the leaf, each certificate must be issued by the next
/// (issuer/subject chaining and signature), the key must match the leaf and be able to sign with one of
/// `profile`'s sigalgs, and the leaf must be valid at `now`. If `roots` is non-empty, the last certificate must
/// also be issued by (or be) one of them.
pub fn check_tls(
    chain: &[CertificateDer<'_>],
    key: &PrivateKeyDer<'_>,
    profile: Profile,
    now: i64,
    roots: &[CertificateDer<'_>],
) -> Result<PreflightReport, PreflightError> {
    if chain.is_empty() || chain.len() > MAX_CHAIN {
        return Err(PreflightError::ChainLength);
    }
    if profile.status() == ProfileStatus::Pending {
        return Err(PreflightError::ProfilePending(profile.name()));
    }
    let infos: Vec<CertInfo<'_>> = chain
        .iter()
        .enumerate()
        .map(|(index, c)| parse_cert(c.as_ref()).map_err(|e| PreflightError::Malformed { index, reason: e.0 }))
        .collect::<Result<_, _>>()?;
    for (index, pair) in infos.windows(2).enumerate() {
        if let [child, parent] = pair {
            verify_link(child, parent).map_err(|reason| PreflightError::Link { index, reason })?;
        }
    }
    let leaf = infos.first().ok_or(PreflightError::ChainLength)?;
    if !roots.is_empty() {
        let top = infos.last().ok_or(PreflightError::ChainLength)?;
        let ok = roots.iter().any(|r| {
            r.as_ref() == chain.last().map(|c| c.as_ref()).unwrap_or(&[])
                || parse_cert(r.as_ref()).is_ok_and(|ri| verify_link(top, &ri).is_ok())
        });
        if !ok {
            return Err(PreflightError::UntrustedRoot);
        }
    }
    let signing =
        rustls::crypto::aws_lc_rs::sign::any_supported_type(key).map_err(|e| PreflightError::Key(e.to_string()))?;
    let owned: Vec<CertificateDer<'static>> = chain.iter().map(|c| c.clone().into_owned()).collect();
    let ck = CertifiedKey::new(owned, signing.clone());
    ck.keys_match().map_err(|_| PreflightError::KeyMismatch)?;
    let scheme = signing
        .choose_scheme(profile.sigalgs())
        .map(|s| s.scheme())
        .filter(|s| profile.sigalgs().contains(s))
        .ok_or(PreflightError::SigalgNotInProfile { profile: profile.name() })?;
    if now < leaf.not_before {
        return Err(PreflightError::NotYetValid { not_before: leaf.not_before });
    }
    if now >= leaf.not_after {
        return Err(PreflightError::Expired { not_after: leaf.not_after });
    }
    Ok(PreflightReport {
        serial: leaf.serial.to_vec(),
        not_before: leaf.not_before,
        not_after: leaf.not_after,
        dns_names: leaf.dns_names.iter().map(|s| String::from(*s)).collect(),
        scheme,
        seconds_to_expiry: seconds_to_expiry(leaf.not_after, now),
    })
}

// ------------------------------------------------------------------------------------------------ store

/// The installed certificate and what CERT-1/2 need to know about it.
#[derive(Debug)]
pub struct Installed {
    /// Served key and chain.
    pub key: Arc<CertifiedKey>,
    /// Preflight report.
    pub report: PreflightReport,
    /// Install generation (1 = first install).
    pub generation: u64,
}

/// The atomically swappable server certificate (see the module docs).
#[derive(Debug, Default)]
pub struct CertStore {
    current: RwLock<Option<Arc<Installed>>>,
    generation: AtomicU64,
}

impl CertStore {
    /// Empty store: handshakes fail (no certificate) until the first install.
    pub fn new() -> Self {
        Self::default()
    }

    /// The installed certificate, if any.
    pub fn current(&self) -> Option<Arc<Installed>> {
        match self.current.read() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Run [`check_tls`] at `clock.now()` and swap the pair in only if it passes. On error the previous certificate
    /// stays installed.
    pub fn install_checked(
        &self,
        chain: Vec<CertificateDer<'static>>,
        key: &PrivateKeyDer<'_>,
        profile: Profile,
        clock: &dyn Clock,
        roots: &[CertificateDer<'_>],
    ) -> Result<Arc<Installed>, PreflightError> {
        let report = check_tls(&chain, key, profile, clock.now(), roots)?;
        let signing =
            rustls::crypto::aws_lc_rs::sign::any_supported_type(key).map_err(|e| PreflightError::Key(e.to_string()))?;
        Ok(self.swap(Arc::new(CertifiedKey::new(chain, signing)), report))
    }

    /// Swap without a preflight (the caller has run [`check_tls`]); used by tests to model a skipped preflight.
    pub fn swap(&self, key: Arc<CertifiedKey>, report: PreflightReport) -> Arc<Installed> {
        let generation = self.generation.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        let inst = Arc::new(Installed { key, report, generation });
        match self.current.write() {
            Ok(mut g) => *g = Some(inst.clone()),
            Err(p) => *p.into_inner() = Some(inst.clone()),
        }
        inst
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current().map(|i| i.key.clone())
    }
}

#[cfg(test)]
mod tests;
