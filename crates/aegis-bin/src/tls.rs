//! Certificates and per-listener TLS: static PEM files (process options; F8 has no certificate field) loaded into
//! one aegis-ops [`CertStore`] per profile. Every install runs the CERT-3 preflight (`install_checked`), so a bad
//! chain is never served; a reload (SIGHUP) re-reads the files and swaps the stores, affecting only handshakes that
//! start afterwards. ServerConfigs come only from `aegis_tls::server_config` (TLS 1.3, profile groups/sigalgs, no
//! 0-RTT, no tickets before P-PQ3).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aegis_ops::cert::x509::{pem_blocks, pem_certificates};
use aegis_ops::cert::{CertStore, Installed, SystemClock};
use aegis_transport::TlsAcceptor;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};

use crate::plan::ListenerPlan;

#[derive(Debug, Clone)]
pub struct CertPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl CertPaths {
    /// Explicit options, else systemd credentials (`$CREDENTIALS_DIRECTORY/tls.crt`, `tls.key`).
    pub fn resolve(cert: Option<&Path>, key: Option<&Path>) -> Result<Self, String> {
        let cred = std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from);
        let pick = |opt: Option<&Path>, name: &str| -> Result<PathBuf, String> {
            match (opt, &cred) {
                (Some(p), _) => Ok(p.to_path_buf()),
                (None, Some(d)) => Ok(d.join(name)),
                (None, None) => {
                    Err("no certificate: pass --cert/--key or provide credentials tls.crt/tls.key (LoadCredential=)"
                        .to_string())
                }
            }
        };
        Ok(Self { cert: pick(cert, "tls.crt")?, key: pick(key, "tls.key")? })
    }
}

/// Bounded file read (certificates and keys are small).
fn read_small(p: &Path) -> Result<String, String> {
    use std::io::Read;
    let f = std::fs::File::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let mut s = String::new();
    f.take(1 << 20).read_to_string(&mut s).map_err(|e| format!("{}: {e}", p.display()))?;
    Ok(s)
}

/// Read the PEM chain and key.
pub fn load(paths: &CertPaths) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let chain_text = read_small(&paths.cert)?;
    let chain: Vec<CertificateDer<'static>> = pem_certificates(&chain_text)
        .ok_or_else(|| format!("{}: malformed PEM", paths.cert.display()))?
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    if chain.is_empty() {
        return Err(format!("{}: no CERTIFICATE block", paths.cert.display()));
    }
    let key = parse_key(&read_small(&paths.key)?, &paths.key)?;
    Ok((chain, key))
}

/// The private key of a PEM text (PKCS#8, SEC1 or PKCS#1; the first block of the first kind found).
fn parse_key(key_text: &str, at: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let bad = || format!("{}: malformed PEM", at.display());
    let key = if let Some(k) = pem_blocks(key_text, "PRIVATE KEY").ok_or_else(bad)?.into_iter().next() {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(k))
    } else if let Some(k) = pem_blocks(key_text, "EC PRIVATE KEY").ok_or_else(bad)?.into_iter().next() {
        PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(k))
    } else if let Some(k) = pem_blocks(key_text, "RSA PRIVATE KEY").ok_or_else(bad)?.into_iter().next() {
        PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(k))
    } else {
        return Err(format!("{}: no PRIVATE KEY block", at.display()));
    };
    Ok(key)
}

/// The linked AWS-LC module's own version string, read at run time (PLAN-6 D2/D16): on the cmvp build through
/// the audited `aegis_iso::fips` sites; the floor build links no FIPS module and reports none. aegis-tls receives
/// it through `server_config_with` / `fips_status_with` / `fips_check_with` and decides the P-PQ5 claim.
pub fn linked_module() -> Option<&'static str> {
    #[cfg(feature = "cmvp")]
    return aegis_iso::fips::awslc_version_string();
    #[cfg(not(feature = "cmvp"))]
    None
}

/// One cert store per distinct profile, plus the acceptor of each listener.
pub struct Tls {
    pub stores: Vec<(aegis_tls::Profile, Arc<CertStore>)>,
    pub acceptors: Vec<(String, TlsAcceptor)>,
    pub fips: aegis_tls::FipsStatus,
}

impl std::fmt::Debug for Tls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls").field("stores", &self.stores).field("listeners", &self.acceptors.len()).finish()
    }
}

impl Tls {
    pub fn build(listeners: &[ListenerPlan], paths: &CertPaths) -> Result<Self, String> {
        let (chain, key) = load(paths)?;
        let mut stores: Vec<(aegis_tls::Profile, Arc<CertStore>)> = Vec::new();
        let mut acceptors = Vec::new();
        let mut fips = None;
        let linked = linked_module();
        for l in listeners {
            let store = match stores.iter().find(|(p, _)| *p == l.profile) {
                Some((_, s)) => s.clone(),
                None => {
                    let s = Arc::new(CertStore::new());
                    s.install_checked(chain.clone(), &key, l.profile, &SystemClock, &[]).map_err(|e| {
                        format!("listener {}: certificate preflight ({}): {e}", l.name, l.profile.name())
                    })?;
                    stores.push((l.profile, s.clone()));
                    s
                }
            };
            let mut cfg = aegis_tls::server_config_with(l.profile, store, linked)
                .map_err(|e| format!("listener {}: TLS profile {}: {e}", l.name, l.profile.name()))?;
            cfg.alpn_protocols = l.alpn.clone();
            fips.get_or_insert_with(|| aegis_tls::fips_status_with(&cfg, linked));
            acceptors.push((l.name.clone(), TlsAcceptor::from(Arc::new(cfg))));
        }
        let fips = fips.ok_or("no listener")?;
        Ok(Self { stores, acceptors, fips })
    }

    /// Re-read the files and swap every store (preflight first; on any error nothing is swapped).
    pub fn reinstall(&self, paths: &CertPaths) -> Result<(), String> {
        let (chain, key) = load(paths)?;
        for (p, _) in &self.stores {
            aegis_ops::cert::check_tls(&chain, &key, *p, crate::util::unix_s(), &[])
                .map_err(|e| format!("certificate preflight ({}): {e}", p.name()))?;
        }
        for (p, s) in &self.stores {
            s.install_checked(chain.clone(), &key, *p, &SystemClock, &[]).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// The serving certificate (CERT-1 gauge source).
    pub fn current(&self) -> Option<Arc<Installed>> {
        self.stores.first().and_then(|(_, s)| s.current())
    }
}

/// Where an F8 `cred:` / `path:` reference points (`cred:NAME` = `$CREDENTIALS_DIRECTORY/NAME`).
#[cfg(all(feature = "mtc", not(feature = "cmvp")))]
fn secret_path(r: &aegis_config::SecretRef) -> Result<PathBuf, String> {
    match r {
        aegis_config::SecretRef::Path(p) => Ok(PathBuf::from(p)),
        aegis_config::SecretRef::Cred(n) => std::env::var_os("CREDENTIALS_DIRECTORY")
            .map(|d| PathBuf::from(d).join(n))
            .ok_or_else(|| format!("{}: needs $CREDENTIALS_DIRECTORY (LoadCredential=)", r.to_f8())),
    }
}

/// One F8 credential's chain and key as rustls serves them. x509 and mldsa chains are PEM certificate chains; an mtc
/// credential is an operator-supplied opaque blob (D-P7.4): its PEM `CERTIFICATE` blocks when it has any, else the
/// whole file as one entry. AEGIS neither parses nor verifies it.
#[cfg(all(feature = "mtc", not(feature = "cmvp")))]
fn load_credential(c: &aegis_config::Credential) -> Result<Arc<rustls::sign::CertifiedKey>, String> {
    let chain_path = secret_path(c.chain())?;
    let key_path = secret_path(c.key())?;
    let chain: Vec<CertificateDer<'static>> = if c.kind() == aegis_config::CredentialKind::Mtc {
        use std::io::Read;
        let f = std::fs::File::open(&chain_path).map_err(|e| format!("{}: {e}", chain_path.display()))?;
        let mut raw = Vec::new();
        f.take(1 << 20).read_to_end(&mut raw).map_err(|e| format!("{}: {e}", chain_path.display()))?;
        match std::str::from_utf8(&raw).ok().and_then(pem_certificates).filter(|v| !v.is_empty()) {
            Some(blocks) => blocks.into_iter().map(CertificateDer::from).collect(),
            None if raw.is_empty() => return Err(format!("{}: empty mtc credential", chain_path.display())),
            None => vec![CertificateDer::from(raw)],
        }
    } else {
        let text = read_small(&chain_path)?;
        let v: Vec<CertificateDer<'static>> = pem_certificates(&text)
            .ok_or_else(|| format!("{}: malformed PEM", chain_path.display()))?
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        if v.is_empty() {
            return Err(format!("{}: no CERTIFICATE block", chain_path.display()));
        }
        v
    };
    let key = parse_key(&read_small(&key_path)?, &key_path)?;
    let signer = rustls::crypto::aws_lc_rs::default_provider()
        .key_provider
        .load_private_key(key)
        .map_err(|e| format!("{}: {e}", key_path.display()))?;
    Ok(Arc::new(rustls::sign::CertifiedKey::new(chain, signer)))
}

/// The MTC credential selector of every HTTP listener that has `tls.credentials` candidates (D-P7.4, SEL-1..3;
/// feature `mtc`). A listener without candidates keeps the `--cert` acceptor. A credential that does not load, that
/// signs with no single TLS 1.3 scheme, or that its listener's profile can never serve fails the boot.
#[cfg(all(feature = "mtc", not(feature = "cmvp")))]
pub fn selectors(
    cfg: &aegis_config::Config,
    listeners: &[ListenerPlan],
) -> Result<Vec<(String, Arc<aegis_tls::CredentialSelector>)>, String> {
    let Some(block) = cfg.tls() else { return Ok(Vec::new()) };
    let mut out = Vec::new();
    for l in listeners.iter().filter(|l| l.l4.is_none()) {
        let candidates = block.candidates(cfg, &l.name);
        if candidates.is_empty() {
            continue;
        }
        let mut pool = Vec::new();
        for c in candidates {
            let at = format!("/tls/credentials {:?} on listener {}", c.id(), l.name);
            let ck = load_credential(c).map_err(|e| format!("{at}: {e}"))?;
            let scheme = aegis_tls::key_scheme(&ck)
                .ok_or_else(|| format!("{at}: the key signs with no single TLS 1.3 scheme (RSA keys are refused)"))?;
            let kind = aegis_tls::CredentialKind::from_name(c.kind().as_str())
                .ok_or_else(|| format!("{at}: unknown kind {}", c.kind().as_str()))?;
            let ta = c.trust_anchor_id().map(aegis_config::TrustAnchorId::wire);
            let cred = aegis_tls::Credential::new(c.id(), l.name.as_str(), kind, scheme, ta, ck)
                .map_err(|e| format!("{at}: {e}"))?;
            pool.push(cred);
        }
        let declared = pool.len();
        let mut sel = aegis_tls::CredentialSelector::new(l.profile, &l.name, pool)
            .map_err(|e| format!("listener {}: credential selector: {e}", l.name))?;
        if sel.credentials().len() != declared {
            return Err(format!(
                "listener {}: {} of its {declared} credentials can never be served on profile {} (F12 sigalgs, SEL-2)",
                l.name,
                declared.saturating_sub(sel.credentials().len()),
                l.profile.name()
            ));
        }
        sel.set_alpn(l.alpn.clone());
        out.push((l.name.clone(), Arc::new(sel)));
    }
    Ok(out)
}
