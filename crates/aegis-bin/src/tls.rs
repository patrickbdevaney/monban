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
    let key_text = read_small(&paths.key)?;
    let bad = || format!("{}: malformed PEM", paths.key.display());
    let key = if let Some(k) = pem_blocks(&key_text, "PRIVATE KEY").ok_or_else(bad)?.into_iter().next() {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(k))
    } else if let Some(k) = pem_blocks(&key_text, "EC PRIVATE KEY").ok_or_else(bad)?.into_iter().next() {
        PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(k))
    } else if let Some(k) = pem_blocks(&key_text, "RSA PRIVATE KEY").ok_or_else(bad)?.into_iter().next() {
        PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(k))
    } else {
        return Err(format!("{}: no PRIVATE KEY block", paths.key.display()));
    };
    Ok((chain, key))
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
            let mut cfg = aegis_tls::server_config(l.profile, store)
                .map_err(|e| format!("listener {}: TLS profile {}: {e}", l.name, l.profile.name()))?;
            cfg.alpn_protocols = l.alpn.clone();
            fips.get_or_insert_with(|| aegis_tls::fips_status(&cfg));
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
