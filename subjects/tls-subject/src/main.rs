//! tls-subject: the aegis-tls listener configs over the oracles/hrr-verdicts `--subject` protocol (F12).
//!
//!   tls-subject [subject] describe <PROFILE>   key=value lines (kx_groups, versions, early_data, fips, module)
//!   tls-subject [subject] serve <PROFILE>      one TLS server connection over stdin/stdout
//!   tls-subject client <PROFILE> <host:port>   kx-interop client: TCP connect, TLS 1.3 handshake with the profile's
//!                                              client config, send "ping\n", expect it echoed, print
//!                                              `negotiated=0x....` (the negotiated group)
//!
//! Every `ServerConfig` comes from `aegis_tls::server_config` (the production builder); this binary only supplies
//! credentials (self-signed certificates generated at start-up) and reads the built config back. Reported
//! `kx_groups` are read from the built `CryptoProvider`, not from the profile constant, so a builder bug shows.
//! Credentials (F12 `credential`): ML-DSA-44 on PQ-REQUIRED (private hops, as the oracle reference); ML-DSA-87 and
//! ECDSA-P384 on P-UNIVERSAL and P-BSI-ALT (ML-DSA-87 served when the client offers it, else ECDSA-P384); ML-DSA-87
//! only on P-CNSA; ECDSA-P256 elsewhere.
//!
//! The client's `CryptoProvider` is `aegis_tls::profile::provider`, the table both production builders use, so the
//! client offers the profile's kx list exactly. Client mode is compiled out of the cmvp build (feature `cmvp`;
//! spikes/cmvp-client-policy mode A: no rustls client in a cmvp binary).
//!
//! cmvp build (feature `cmvp`, PLAN-6 D15): aws-lc-rs 1.15.3 compiles ML-DSA out under `fips`, so there are no
//! ML-DSA credentials: ECDSA-P384 only on P-UNIVERSAL and P-BSI-ALT, ECDSA-P256 on PQ-REQUIRED, and P-CNSA (ML-DSA-87
//! only) is refused by `aegis_tls::server_config` with its reason.
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::process::ExitCode;
use std::sync::Arc;

use aegis_tls::{Profile, fips_status, negotiable_versions, server_config};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
#[cfg(not(feature = "cmvp"))]
use aws_lc_rs::signature::PqdsaKeyPair;
use aws_lc_rs::signature::{self, EcdsaKeyPair, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ProtocolVersion, ServerConfig, ServerConnection};

type R<T> = Result<T, String>;

// ------------------------------------------------------------------------------------------------ minimal DER

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let n = content.len();
    if n < 0x80 {
        v.push(n as u8);
    } else {
        let bytes: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        v.push(0x80 | bytes.len() as u8);
        v.extend(bytes);
    }
    v.extend_from_slice(content);
    v
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// ecdsa-with-SHA256, 1.2.840.10045.4.3.2.
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
/// ecdsa-with-SHA384, 1.2.840.10045.4.3.3.
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
/// id-ml-dsa-44, 2.16.840.1.101.3.4.3.17.
#[cfg(not(feature = "cmvp"))]
const OID_ML_DSA_44: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11];
/// id-ml-dsa-87, 2.16.840.1.101.3.4.3.19.
#[cfg(not(feature = "cmvp"))]
const OID_ML_DSA_87: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13];
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
const HOST: &[u8] = b"aegis.test";

/// Self-signed X.509 v3 certificate for `aegis.test` (CN + SAN dNSName). `sign` signs the TBSCertificate.
fn self_signed(sig_oid: &[u8], spki: &[u8], sign: impl Fn(&[u8]) -> R<Vec<u8>>) -> R<Vec<u8>> {
    let alg = seq(&[&tlv(0x06, sig_oid)]);
    let name = seq(&[&tlv(0x31, &seq(&[&tlv(0x06, OID_CN), &tlv(0x0c, HOST)]))]);
    let validity = seq(&[&tlv(0x17, b"260101000000Z"), &tlv(0x18, b"20991231235959Z")]);
    let san = seq(&[&tlv(0x82, HOST)]);
    let exts = tlv(0xa3, &seq(&[&seq(&[&tlv(0x06, OID_SAN), &tlv(0x04, &san)])]));
    let tbs = seq(&[&tlv(0xa0, &tlv(0x02, &[2])), &tlv(0x02, &[1]), &alg, &name, &validity, &name, spki, &exts]);
    let sig = sign(&tbs)?;
    Ok(seq(&[&tbs, &alg, &tlv(0x03, &[&[0u8][..], &sig].concat())]))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cred {
    EcdsaP256,
    EcdsaP384,
    #[cfg(not(feature = "cmvp"))]
    MlDsa44,
    #[cfg(not(feature = "cmvp"))]
    MlDsa87,
}

/// (certificate DER, PKCS#8 v1 private key DER) of a fresh self-signed credential.
fn credential(c: Cred) -> R<(Vec<u8>, Vec<u8>)> {
    match c {
        Cred::EcdsaP256 => ecdsa(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, OID_ECDSA_SHA256),
        Cred::EcdsaP384 => ecdsa(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, OID_ECDSA_SHA384),
        #[cfg(not(feature = "cmvp"))]
        Cred::MlDsa44 => mldsa(&signature::ML_DSA_44_SIGNING, OID_ML_DSA_44),
        #[cfg(not(feature = "cmvp"))]
        Cred::MlDsa87 => mldsa(&signature::ML_DSA_87_SIGNING, OID_ML_DSA_87),
    }
}

fn ecdsa(alg: &'static signature::EcdsaSigningAlgorithm, oid: &[u8]) -> R<(Vec<u8>, Vec<u8>)> {
    let kp = EcdsaKeyPair::generate(alg).map_err(|e| format!("ecdsa: {e}"))?;
    let spki = kp.public_key().as_der().map_err(|e| format!("ecdsa spki: {e}"))?;
    let rng = SystemRandom::new();
    let cert = self_signed(oid, spki.as_ref(), |m| {
        kp.sign(&rng, m).map(|s| s.as_ref().to_vec()).map_err(|e| format!("ecdsa sign: {e}"))
    })?;
    let key = kp.to_pkcs8v1().map_err(|e| format!("ecdsa pkcs8: {e}"))?;
    Ok((cert, key.as_ref().to_vec()))
}

#[cfg(not(feature = "cmvp"))]
fn mldsa(alg: &'static signature::PqdsaSigningAlgorithm, oid: &[u8]) -> R<(Vec<u8>, Vec<u8>)> {
    let kp = PqdsaKeyPair::generate(alg).map_err(|e| format!("ml-dsa: {e}"))?;
    let spki = kp.public_key().as_der().map_err(|e| format!("ml-dsa spki: {e}"))?;
    let cert = self_signed(oid, spki.as_ref(), |m| {
        // Largest ML-DSA signature (ML-DSA-87, FIPS 204 table 2); `sign` returns the actual length.
        let mut sig = vec![0u8; 4627];
        let n = kp.sign(m, &mut sig).map_err(|e| format!("ml-dsa sign: {e}"))?;
        sig.truncate(n);
        Ok(sig)
    })?;
    let key = kp.to_pkcs8v1().map_err(|e| format!("ml-dsa pkcs8: {e}"))?;
    Ok((cert, key.as_ref().to_vec()))
}

/// The credentials served on a profile, in preference order (F12 `credential`).
#[cfg(not(feature = "cmvp"))]
fn creds(profile: Profile) -> &'static [Cred] {
    match profile {
        Profile::PqRequired => &[Cred::MlDsa44],
        Profile::Universal | Profile::BsiAlt => &[Cred::MlDsa87, Cred::EcdsaP384],
        Profile::Cnsa => &[Cred::MlDsa87],
        Profile::PublicWeb | Profile::FipsFloor | Profile::FipsCmvp | Profile::FipsPqRequired => &[Cred::EcdsaP256],
    }
}

/// cmvp build (PLAN-6 D15): no ML-DSA credentials. P-CNSA gets none (its builder refuses it on cmvp).
#[cfg(feature = "cmvp")]
fn creds(profile: Profile) -> &'static [Cred] {
    match profile {
        Profile::Universal | Profile::BsiAlt => &[Cred::EcdsaP384],
        Profile::Cnsa => &[],
        Profile::PublicWeb | Profile::PqRequired | Profile::FipsFloor | Profile::FipsCmvp | Profile::FipsPqRequired => {
            &[Cred::EcdsaP256]
        }
    }
}

/// Serves the first credential that can sign with a scheme the client offered; `None` when none can, and the
/// aegis-tls `ProfileCertResolver` wrapped around it then refuses the handshake (access_denied, 49).
#[derive(Debug)]
struct FirstSignable(Vec<Arc<CertifiedKey>>);

impl ResolvesServerCert for FirstSignable {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let offered = client_hello.signature_schemes();
        self.0.iter().find(|ck| ck.key.choose_scheme(offered).is_some()).cloned()
    }
}

/// Credentials for a profile, each with the rustls key/certificate consistency check (`CertifiedKey::from_der`).
fn resolver(profile: Profile) -> R<Arc<dyn ResolvesServerCert>> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut keys = Vec::new();
    for c in creds(profile) {
        let (cert, key) = credential(*c)?;
        let ck = CertifiedKey::from_der(
            vec![CertificateDer::from(cert)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
            &provider,
        )
        .map_err(|e| format!("credential {c:?}: {e}"))?;
        ck.keys_match().map_err(|e| format!("credential {c:?} keys_match: {e}"))?;
        keys.push(Arc::new(ck));
    }
    Ok(Arc::new(FirstSignable(keys)))
}

// ------------------------------------------------------------------------------------------------ protocol

fn build(name: &str) -> R<ServerConfig> {
    let profile = Profile::from_name(name).ok_or(format!("unknown profile {name}"))?;
    server_config(profile, resolver(profile)?).map_err(|e| format!("{name}: {e}"))
}

fn describe(name: &str) -> R<()> {
    let cfg = build(name)?;
    let kx: Vec<String> =
        cfg.crypto_provider().kx_groups.iter().map(|g| format!("0x{:04x}", u16::from(g.name()))).collect();
    let versions: Vec<&str> = negotiable_versions(&cfg)
        .into_iter()
        .map(|v| match v {
            ProtocolVersion::TLSv1_3 => "TLS13",
            ProtocolVersion::TLSv1_2 => "TLS12",
            _ => "OTHER",
        })
        .collect();
    let fips = fips_status(&cfg);
    println!("kx_groups={}", kx.join(","));
    println!("versions={}", versions.join(","));
    println!("early_data={}", cfg.max_early_data_size > 0);
    println!("fips={}", fips.config_fips);
    println!("module={}", fips.module.unwrap_or_default());
    Ok(())
}

fn serve(name: &str) -> R<()> {
    let mut s = ServerConnection::new(Arc::new(build(name)?)).map_err(|e| e.to_string())?;
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    let mut buf = vec![0u8; 16384];
    loop {
        let n = stdin.read(&mut buf).map_err(|e| e.to_string())?;
        let Some(mut rd) = buf.get(..n) else { return Err("read overflow".into()) };
        if rd.is_empty() {
            return Ok(());
        }
        let mut failed = None;
        while !rd.is_empty() && failed.is_none() {
            if s.read_tls(&mut rd).map_err(|e| e.to_string())? == 0 {
                break;
            }
            failed = s.process_new_packets().err();
        }
        let mut out = Vec::new();
        while s.wants_write() {
            s.write_tls(&mut out).map_err(|e| e.to_string())?;
        }
        stdout.write_all(&out).and_then(|_| stdout.flush()).map_err(|e| e.to_string())?;
        if let Some(e) = failed {
            eprintln!("tls-subject {name}: {e}");
            return Ok(());
        }
    }
}

// ------------------------------------------------------------------------------------------------ client

#[cfg(not(feature = "cmvp"))]
mod client {
    //! kx-interop client mode. Certificate CHAIN validation is off (interop peers serve throwaway self-signed
    //! certificates; this checks key exchange, not PKI), but the CertificateVerify signature is still verified
    //! against the peer certificate's key, with only the profile's sigalgs accepted.
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::sync::Arc;
    use std::time::Duration;

    use aegis_tls::{Profile, ProfileStatus};
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};

    use super::R;

    const PING: &[u8] = b"ping\n";
    const TIMEOUT: Duration = Duration::from_secs(20);

    #[derive(Debug)]
    struct SignatureOnly {
        algs: WebPkiSupportedAlgorithms,
        schemes: Vec<SignatureScheme>,
    }

    impl ServerCertVerifier for SignatureOnly {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General("TLS 1.2 is not offered".into()))
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            if !self.schemes.contains(&dss.scheme) {
                return Err(rustls::Error::General(format!("{:?} is outside the profile", dss.scheme)));
            }
            verify_tls13_signature(message, cert, dss, &self.algs)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.schemes.clone()
        }
    }

    /// The client config for a profile: provider = `aegis_tls::profile::provider` (kx list exactly the profile's,
    /// TLS 1.3 suites), TLS 1.3 only, resumption disabled, no early data; offered sigalgs = the profile's.
    fn config(profile: Profile) -> R<ClientConfig> {
        if profile.status() == ProfileStatus::Pending {
            return Err(format!("{}: pending in this build", profile.name()));
        }
        if profile == Profile::FipsFloor {
            return Err("FIPS has no client definition (P-PQ6): use FIPS-PQ-REQUIRED".into());
        }
        let provider = aegis_tls::profile::provider(profile).map_err(|e| e.to_string())?;
        let algs = provider.signature_verification_algorithms;
        let schemes: Vec<SignatureScheme> =
            algs.supported_schemes().into_iter().filter(|s| profile.sigalgs().contains(s)).collect();
        let mut cfg = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| e.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SignatureOnly { algs, schemes }))
            .with_no_client_auth();
        cfg.resumption = rustls::client::Resumption::disabled();
        cfg.enable_early_data = false;
        let kx: Vec<u16> = cfg.crypto_provider().kx_groups.iter().map(|g| u16::from(g.name())).collect();
        if kx != profile.kx_groups() {
            return Err(format!("{}: client kx {kx:04x?} != profile {:04x?}", profile.name(), profile.kx_groups()));
        }
        Ok(cfg)
    }

    pub(super) fn run(name: &str, addr: &str) -> R<()> {
        let profile = Profile::from_name(name).ok_or(format!("unknown profile {name}"))?;
        let cfg = config(profile)?;
        let host = addr.rsplit_once(':').map(|(h, _)| h).ok_or(format!("{addr}: expected host:port"))?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let server_name = ServerName::try_from(host.to_string()).map_err(|e| format!("{host}: {e}"))?;
        let sock = addr
            .to_socket_addrs()
            .map_err(|e| format!("{addr}: {e}"))?
            .find_map(|a| TcpStream::connect_timeout(&a, TIMEOUT).ok())
            .ok_or(format!("{addr}: connect failed"))?;
        sock.set_read_timeout(Some(TIMEOUT)).map_err(|e| e.to_string())?;
        sock.set_write_timeout(Some(TIMEOUT)).map_err(|e| e.to_string())?;
        let conn = ClientConnection::new(Arc::new(cfg), server_name).map_err(|e| e.to_string())?;
        let mut tls = StreamOwned::new(conn, sock);
        tls.write_all(PING).and_then(|()| tls.flush()).map_err(|e| format!("handshake/write: {e}"))?;
        let mut got = Vec::new();
        let mut buf = [0u8; 256];
        while got.len() < PING.len() {
            let n = tls.read(&mut buf).map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                break;
            }
            got.extend_from_slice(buf.get(..n).ok_or("read overflow")?);
        }
        if got != PING {
            return Err(format!("echo mismatch: got {got:02x?}"));
        }
        let group = tls
            .conn
            .negotiated_key_exchange_group()
            .map(|g| u16::from(g.name()))
            .ok_or("no negotiated key exchange group")?;
        println!("negotiated=0x{group:04x}");
        tls.conn.send_close_notify();
        // Best effort: the echo already proved the session; a peer that closed first is not a failure.
        let _ = tls.flush();
        Ok(())
    }
}

#[cfg(not(feature = "cmvp"))]
fn client(profile: &str, addr: &str) -> R<()> {
    client::run(profile, addr)
}

#[cfg(feature = "cmvp")]
fn client(_profile: &str, _addr: &str) -> R<()> {
    Err("client mode is compiled out of the cmvp build (spikes/cmvp-client-policy mode A)".into())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest: Vec<&str> = args.iter().map(String::as_str).skip_while(|a| *a == "subject").collect();
    let r = match rest.as_slice() {
        ["describe", p] => describe(p),
        ["serve", p] => serve(p),
        ["client", p, addr] => client(p, addr),
        _ => Err("usage: tls-subject [subject] describe|serve PROFILE | tls-subject client PROFILE HOST:PORT".into()),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
