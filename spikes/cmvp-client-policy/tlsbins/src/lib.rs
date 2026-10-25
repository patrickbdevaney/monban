//! fips_client_policy spike library: a server path every binary links (positive control for the symbol scan),
//! the single blessed PQ-only client constructor, and the ClientHello probe used by the pq-only check.
#![forbid(unsafe_code)]

use std::error::Error;
use std::io::{Read, Write};
use std::sync::Arc;

use rustls::crypto::aws_lc_rs::{self as prov, kx_group};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection};

pub type BoxErr = Box<dyn Error + Send + Sync>;

pub static CA: &[u8] = include_bytes!("../certs/ca.pem");
static LEAF: &[u8] = include_bytes!("../certs/leaf.pem");
static LEAF_KEY: &[u8] = include_bytes!("../certs/leaf.key");

pub fn provider_with(kx: &[&'static dyn SupportedKxGroup]) -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider { kx_groups: kx.to_vec(), ..prov::default_provider() })
}

pub fn server_config(kx: &[&'static dyn SupportedKxGroup]) -> Result<ServerConfig, BoxErr> {
    let certs = CertificateDer::pem_slice_iter(LEAF).collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(LEAF_KEY)?;
    Ok(ServerConfig::builder_with_provider(provider_with(kx))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?)
}

/// The cmvp server path: FIPS listener groups [SECP256R1MLKEM768, P-256, P-384]; feeds stdin to a ServerConnection.
pub fn server_main() -> Result<(), BoxErr> {
    let cfg = server_config(&[kx_group::SECP256R1MLKEM768, kx_group::SECP256R1, kx_group::SECP384R1])?;
    let mut conn = ServerConnection::new(Arc::new(cfg))?;
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    let mut rd = &input[..];
    while !rd.is_empty() {
        conn.read_tls(&mut rd)?;
        conn.process_new_packets()?;
    }
    let mut out = Vec::new();
    conn.write_tls(&mut out)?;
    std::io::stdout().write_all(&out)?;
    Ok(())
}

#[cfg(feature = "tls-client")]
pub mod pqclient {
    //! The ONLY place first-party code may construct a rustls ClientConfig (clippy disallowed-methods elsewhere).
    use super::*;
    use rustls::client::Resumption;
    use rustls::{ClientConfig, RootCertStore};

    /// Opaque: every first-party API that dials out takes this, never a bare ClientConfig.
    #[derive(Debug, Clone)]
    pub struct PqClientConfig(Arc<ClientConfig>);

    impl PqClientConfig {
        pub fn get(&self) -> Arc<ClientConfig> {
            self.0.clone()
        }
    }

    #[expect(clippy::disallowed_methods, reason = "blessed cmvp PQ-only client constructor (P-PQ6)")]
    pub fn pq_only_client_config() -> Result<PqClientConfig, BoxErr> {
        let mut roots = RootCertStore::empty();
        for c in CertificateDer::pem_slice_iter(CA) {
            roots.add(c?)?;
        }
        let mut cfg = ClientConfig::builder_with_provider(provider_with(&[kx_group::SECP256R1MLKEM768]))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.resumption = Resumption::disabled();
        cfg.enable_early_data = false;
        assert_pq_only(&cfg)?;
        Ok(PqClientConfig(Arc::new(cfg)))
    }

    /// Startup assertion (also run on every config the probe sees): groups exactly [SECP256R1MLKEM768] and no
    /// session store (NoClientSessionStorage => kx_hint() is always None, nothing to poison: RUSTSEC-2026-0349).
    pub fn assert_pq_only(cfg: &ClientConfig) -> Result<(), BoxErr> {
        let groups: Vec<String> =
            cfg.crypto_provider().kx_groups.iter().map(|g| format!("{:?}", g.name())).collect();
        if groups != ["secp256r1MLKEM768"] {
            return Err(format!("P-PQ6: client kx_groups = {groups:?}, want [secp256r1MLKEM768]").into());
        }
        let res = format!("{:?}", cfg.resumption);
        if !res.contains("NoClientSessionStorage") || !res.contains("Disabled") {
            return Err(format!("P-PQ6: client resumption store present: {res}").into());
        }
        Ok(())
    }
}

#[cfg(feature = "tls-client")]
pub mod probe {
    //! Black-box check of a client config: two in-memory handshakes against a server that supports a classical
    //! group first (X25519) and issues tickets; records each ClientHello's supported_groups, key_share groups and
    //! pre_shared_key presence. Key-share prediction / resumption shows up as a changed 2nd ClientHello.
    use super::*;
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, ClientConnection};

    struct Cur<'a>(&'a [u8], usize);
    impl Cur<'_> {
        fn take(&mut self, n: usize) -> Result<&[u8], BoxErr> {
            let s = self.0.get(self.1..self.1 + n).ok_or("short ClientHello")?;
            self.1 += n;
            Ok(s)
        }
        fn u8(&mut self) -> Result<usize, BoxErr> {
            Ok(usize::from(*self.take(1)?.first().ok_or("short")?))
        }
        fn u16(&mut self) -> Result<usize, BoxErr> {
            let b = self.take(2)?;
            Ok(usize::from(u16::from_be_bytes([b[0], b[1]])))
        }
    }

    /// (supported_groups, key_share groups, has pre_shared_key, has early_data)
    fn parse_hello(rec: &[u8]) -> Result<(Vec<u16>, Vec<u16>, bool, bool), BoxErr> {
        let mut c = Cur(rec, 0);
        if c.u8()? != 0x16 {
            return Err("not a handshake record".into());
        }
        c.take(4)?; // version, length
        if c.u8()? != 1 {
            return Err("not a ClientHello".into());
        }
        c.take(3 + 2 + 32)?; // length, legacy_version, random
        let n = c.u8()?;
        c.take(n)?; // session id
        let n = c.u16()?;
        c.take(n)?; // cipher suites
        let n = c.u8()?;
        c.take(n)?; // compression
        let total = c.u16()?;
        let end = c.1 + total;
        let (mut groups, mut shares, mut psk, mut early) = (vec![], vec![], false, false);
        while c.1 < end {
            let (ty, len) = (c.u16()?, c.u16()?);
            let body = c.take(len)?;
            let mut b = Cur(body, 0);
            match ty {
                10 => {
                    let l = b.u16()?;
                    for _ in 0..l / 2 {
                        groups.push(b.u16()? as u16);
                    }
                }
                51 => {
                    let l = b.u16()?;
                    let stop = b.1 + l;
                    while b.1 < stop {
                        shares.push(b.u16()? as u16);
                        let kl = b.u16()?;
                        b.take(kl)?;
                    }
                }
                41 => psk = true,
                42 => early = true,
                _ => {}
            }
        }
        Ok((groups, shares, psk, early))
    }

    fn pump(c: &mut ClientConnection, s: &mut ServerConnection) -> Result<(), BoxErr> {
        for _ in 0..32 {
            let mut moved = false;
            while c.wants_write() {
                let mut buf = Vec::new();
                c.write_tls(&mut buf)?;
                let mut rd = &buf[..];
                while !rd.is_empty() {
                    s.read_tls(&mut rd)?;
                    s.process_new_packets()?;
                }
                moved = true;
            }
            while s.wants_write() {
                let mut buf = Vec::new();
                s.write_tls(&mut buf)?;
                let mut rd = &buf[..];
                while !rd.is_empty() {
                    c.read_tls(&mut rd)?;
                    c.process_new_packets()?;
                }
                moved = true;
            }
            if !moved && !c.is_handshaking() && !s.is_handshaking() {
                return Ok(());
            }
        }
        Err("handshake did not settle".into())
    }

    fn hex(v: &[u16]) -> String {
        let s: Vec<String> = v.iter().map(|g| format!("\"0x{g:04X}\"")).collect();
        format!("[{}]", s.join(","))
    }

    /// JSON report: {"kx_groups":[...],"resumption":"...","hellos":[{...},{...}]}
    pub fn probe(cfg: Arc<ClientConfig>) -> Result<String, BoxErr> {
        let srv = Arc::new(server_config(&[kx_group::X25519, kx_group::SECP256R1MLKEM768])?);
        let mut hellos = Vec::new();
        for _ in 0..2 {
            let mut c = ClientConnection::new(cfg.clone(), ServerName::try_from("localhost")?.to_owned())?;
            let mut s = ServerConnection::new(srv.clone())?;
            let mut first = Vec::new();
            c.write_tls(&mut first)?;
            let (g, k, psk, early) = parse_hello(&first)?;
            let mut rd = &first[..];
            while !rd.is_empty() {
                s.read_tls(&mut rd)?;
                s.process_new_packets()?;
            }
            pump(&mut c, &mut s)?;
            let neg = c.negotiated_key_exchange_group().map(|g| format!("{:?}", g.name())).unwrap_or_default();
            hellos.push(format!(
                "{{\"supported_groups\":{},\"key_share\":{},\"pre_shared_key\":{psk},\"early_data\":{early},\
                 \"negotiated\":\"{neg}\",\"kind\":\"{}\"}}",
                hex(&g),
                hex(&k),
                c.handshake_kind().map(|k| format!("{k:?}")).unwrap_or_default()
            ));
        }
        let groups: Vec<String> =
            cfg.crypto_provider().kx_groups.iter().map(|g| format!("\"{:?}\"", g.name())).collect();
        Ok(format!(
            "{{\"kx_groups\":[{}],\"resumption\":\"{}\",\"hellos\":[{}]}}",
            groups.join(","),
            format!("{:?}", cfg.resumption).replace('"', "'"),
            hellos.join(",")
        ))
    }
}
