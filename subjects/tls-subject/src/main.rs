//! tls-subject: the aegis-tls listener configs over the oracles/hrr-verdicts `--subject` protocol (F12), and the
//! oracles/kx-interop subject contract (oracles/kx-interop/README.md "Subject contract").
//!
//!   tls-subject [subject] describe <PROFILE>        key=value lines (kx_groups, versions, early_data, fips, module)
//!   tls-subject [subject] serve <PROFILE>           one TLS server connection over stdin/stdout
//!   tls-subject [subject] interop-server <PROFILE>  kx-interop: one server connection on stdin/stdout (the `serve`
//!                                                   config); reports the handshake, echoes application data
//!   tls-subject [subject] interop-client <PROFILE> <CA_PEM> <NONCE>
//!                                                   kx-interop: one client connection on stdin/stdout to
//!                                                   `aegis.test` with `aegis_tls::client_config` (roots = CA_PEM);
//!                                                   sends `<NONCE>\n` and waits for the echo
//!   tls-subject [subject] select                    oracles/cred-select (feature `mtc`; never in the cmvp build):
//!                                                   one `<case> <credential id>|handshake_failure` line per
//!                                                   request line, from `aegis_tls::CredentialSelector`
//!   tls-subject [subject] indicator                 oracles/fips-indicator (feature `indicator`, cmvp only;
//!                                                   PREFLIGHT D-P8.2): one answer line per request line, each
//!                                                   verdict read from AWS-LC's FIPS service indicator around one
//!                                                   call (ECDH P-384, X25519, ML-KEM-1024, HKDF, the 0x11ED kx
//!                                                   and one in-memory 0x11ED TLS 1.3 handshake)
//!
//! Every `ServerConfig` comes from `aegis_tls::server_config` (the production builder); this binary only supplies
//! credentials (self-signed certificates generated at start-up) and reads the built config back. Reported
//! `kx_groups` are read from the built `CryptoProvider`, not from the profile constant, so a builder bug shows.
//! Credentials (F12 `credential`): ML-DSA-44 on PQ-REQUIRED (private hops, as the oracle reference); ML-DSA-87 and
//! ECDSA-P384 on P-UNIVERSAL and P-BSI-ALT (ML-DSA-87 served when the client offers it, else ECDSA-P384); ML-DSA-87
//! only on P-CNSA; ECDSA-P256 elsewhere.
//!
//! The client config is `aegis_tls::client_config`, the product client builder (aegis-tls feature `tls-client`,
//! enabled here by the default feature `interop`). The cmvp build is `--no-default-features --features cmvp`
//! (profiles/cmvp/build.sh), so it has no aegis-tls client (no `tls-client`); `cmvp` together with `interop` is a
//! compile error. Exception, this test subject only: the `indicator` mode (cmvp,indicator) builds one rustls
//! client locally for its in-memory 0x11ED handshake (certificate pinned by DER, resumption and early data off).
//! It is never the product builder, and aegis-bin's cmvp build has no client (spikes/cmvp-client-policy mode A,
//! judged on `target/cmvp/release/aegis`; profiles/cmvp/build.sh builds the two packages in separate invocations).
//!
//! cmvp build (feature `cmvp`, PLAN-6 D15): aws-lc-rs 1.15.3 compiles ML-DSA out under `fips`, so there are no
//! ML-DSA credentials: ECDSA-P384 only on P-UNIVERSAL and P-BSI-ALT, ECDSA-P256 on PQ-REQUIRED, and P-CNSA (ML-DSA-87
//! only) is refused by `aegis_tls::server_config` with its reason. The module string (`describe` `module=`) is the
//! linked module's own `awslc_version_string()`, read through aegis-iso's audited sites (PLAN-6 D16) and passed to
//! `aegis_tls::server_config_with` / `fips_status_with`; the floor build has no FIPS module and reports none.
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::process::ExitCode;
use std::sync::Arc;

use aegis_tls::{Profile, fips_status_with, negotiable_versions, server_config_with};
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

/// Credentials for a profile, each with the rustls key/certificate consistency check (`CertifiedKey::from_der`),
/// and their certificate DERs (the `indicator` handshake client pins them).
fn resolver(profile: Profile) -> R<(Arc<dyn ResolvesServerCert>, Vec<Vec<u8>>)> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let (mut keys, mut certs) = (Vec::new(), Vec::new());
    for c in creds(profile) {
        let (cert, key) = credential(*c)?;
        certs.push(cert.clone());
        let ck = CertifiedKey::from_der(
            vec![CertificateDer::from(cert)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
            &provider,
        )
        .map_err(|e| format!("credential {c:?}: {e}"))?;
        ck.keys_match().map_err(|e| format!("credential {c:?} keys_match: {e}"))?;
        keys.push(Arc::new(ck));
    }
    Ok((Arc::new(FirstSignable(keys)), certs))
}

// ------------------------------------------------------------------------------------------------ protocol

/// The linked AWS-LC module's version string (cmvp: aegis-iso, PLAN-6 D16; floor: none).
fn linked_module() -> Option<&'static str> {
    #[cfg(feature = "cmvp")]
    return aegis_iso::fips::awslc_version_string();
    #[cfg(not(feature = "cmvp"))]
    None
}

fn build(name: &str) -> R<ServerConfig> {
    let profile = Profile::from_name(name).ok_or(format!("unknown profile {name}"))?;
    server_config_with(profile, resolver(profile)?.0, linked_module()).map_err(|e| format!("{name}: {e}"))
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
    let fips = fips_status_with(&cfg, linked_module());
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

// ------------------------------------------------------------------------------------------------ kx-interop

/// TLS records over stdin/stdout for the kx-interop modes (oracles/kx-interop/README.md "Subject contract").
mod pump {
    use std::io::{Read, Write};

    use rustls::Connection;

    use super::R;

    /// `group=0x.... version=0x.... suite=0x....` of a completed handshake (0 where rustls reports nothing).
    pub(super) fn report(c: &Connection) -> String {
        let g = c.negotiated_key_exchange_group().map(|g| u16::from(g.name())).unwrap_or(0);
        let v = c.protocol_version().map(u16::from).unwrap_or(0);
        let s = c.negotiated_cipher_suite().map(|s| u16::from(s.suite())).unwrap_or(0);
        format!("group=0x{g:04x} version=0x{v:04x} suite=0x{s:04x}")
    }

    /// Write every pending TLS record to `out` and flush.
    pub(super) fn flush(c: &mut Connection, out: &mut impl Write) -> R<()> {
        let mut buf = Vec::new();
        while c.wants_write() {
            c.write_tls(&mut buf).map_err(|e| e.to_string())?;
        }
        out.write_all(&buf).and_then(|()| out.flush()).map_err(|e| e.to_string())
    }

    /// Feed one stdin chunk into the connection; `Ok(false)` on EOF. On a TLS error the pending alert is written to
    /// `out` before the error is returned.
    pub(super) fn ingest(c: &mut Connection, input: &mut impl Read, out: &mut impl Write) -> R<bool> {
        let mut buf = vec![0u8; 32768];
        let n = input.read(&mut buf).map_err(|e| e.to_string())?;
        let Some(mut rd) = buf.get(..n) else { return Err("read overflow".into()) };
        if rd.is_empty() {
            return Ok(false);
        }
        while !rd.is_empty() {
            if c.read_tls(&mut rd).map_err(|e| e.to_string())? == 0 {
                break;
            }
            if let Err(e) = c.process_new_packets() {
                // Best effort: the alert goes out if stdout still takes it; the TLS error is what is reported.
                if let Err(w) = flush(c, out) {
                    return Err(format!("tls: {e} (alert not written: {w})"));
                }
                return Err(format!("tls: {e}"));
            }
        }
        Ok(true)
    }

    /// Drain readable plaintext into `got`; `Ok(true)` once the peer has sent close_notify.
    pub(super) fn plaintext(c: &mut Connection, got: &mut Vec<u8>) -> R<bool> {
        let mut buf = vec![0u8; 16384];
        loop {
            match c.reader().read(&mut buf) {
                Ok(0) => return Ok(true),
                Ok(n) => got.extend_from_slice(buf.get(..n).ok_or("read overflow")?),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) => return Err(e.to_string()),
            }
        }
    }
}

/// `interop-server PROFILE`: one connection with `aegis_tls::server_config` (the `serve` config and credentials);
/// reports the handshake, echoes application data, answers close_notify.
fn interop_server(name: &str) -> R<()> {
    let mut c: rustls::Connection = ServerConnection::new(Arc::new(build(name)?)).map_err(|e| e.to_string())?.into();
    let (mut input, mut out) = (std::io::stdin().lock(), std::io::stdout().lock());
    let mut reported = false;
    loop {
        if !pump::ingest(&mut c, &mut input, &mut out)? {
            return if reported { Ok(()) } else { Err("eof before handshake".into()) };
        }
        if !c.is_handshaking() && !reported {
            eprintln!("interop: handshake ok {}", pump::report(&c));
            reported = true;
        }
        let mut got = Vec::new();
        let closed = pump::plaintext(&mut c, &mut got)?;
        if !got.is_empty() {
            c.writer().write_all(&got).map_err(|e| e.to_string())?;
        }
        if closed {
            c.send_close_notify();
            return pump::flush(&mut c, &mut out);
        }
        pump::flush(&mut c, &mut out)?;
    }
}

/// `interop-client PROFILE CA_PEM NONCE` (feature `interop`, i.e. aegis-tls `tls-client`; never in the cmvp build).
/// The config is `aegis_tls::client_config(profile, roots)`, the product client builder, with roots = the
/// certificates in CA_PEM only: full WebPKI chain and name validation of `aegis.test`, no verifier override.
#[cfg(feature = "interop")]
fn interop_client(name: &str, ca: &str, nonce: &str) -> R<()> {
    use rustls::pki_types::ServerName;
    use rustls::pki_types::pem::PemObject;

    let profile = Profile::from_name(name).ok_or(format!("unknown profile {name}"))?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(ca).map_err(|e| format!("ca {ca}: {e}"))? {
        roots.add(cert.map_err(|e| format!("ca {ca}: {e}"))?).map_err(|e| format!("ca {ca}: {e}"))?;
    }
    if roots.is_empty() {
        return Err(format!("ca {ca}: no certificates"));
    }
    let cfg = aegis_tls::client_config(profile, roots).map_err(|e| format!("{name}: {e}"))?;
    let server = ServerName::try_from("aegis.test").map_err(|e| e.to_string())?;
    let mut c: rustls::Connection =
        rustls::ClientConnection::new(Arc::new(cfg), server).map_err(|e| e.to_string())?.into();
    let (mut input, mut out) = (std::io::stdin().lock(), std::io::stdout().lock());
    let want = format!("{nonce}\n");
    let (mut sent, mut got) = (false, Vec::new());
    pump::flush(&mut c, &mut out)?; // the ClientHello goes out before anything is read
    loop {
        if !pump::ingest(&mut c, &mut input, &mut out)? {
            return Err("eof before echo".into());
        }
        if !c.is_handshaking() && !sent {
            eprintln!("interop: handshake ok {}", pump::report(&c));
            c.writer().write_all(want.as_bytes()).map_err(|e| e.to_string())?;
            sent = true;
        }
        let closed = pump::plaintext(&mut c, &mut got)?;
        if sent && got.windows(want.len()).any(|w| w == want.as_bytes()) {
            eprintln!("interop: echo=ok");
            c.send_close_notify();
            return pump::flush(&mut c, &mut out);
        }
        if closed {
            return Err("peer closed before echo".into());
        }
        pump::flush(&mut c, &mut out)?;
    }
}

#[cfg(not(feature = "interop"))]
fn interop_client(_name: &str, _ca: &str, _nonce: &str) -> R<()> {
    Err("interop-client is compiled out of this build (feature `interop` off; the cmvp build has no rustls client, \
         spikes/cmvp-client-policy mode A)"
        .into())
}

/// kx-interop modes report every failure as one `interop: error <msg>` line (README "Subject contract").
fn interop(r: R<()>) -> R<()> {
    r.map_err(|e| format!("interop: error {e}"))
}

// ------------------------------------------------------------------------------------------------ cred-select

/// `select` (feature `mtc`, never in the cmvp build): the oracles/cred-select line protocol (README "Subject
/// protocol"). One request line in, one answer line out, in order; exit 0 at EOF. Each line builds a fresh
/// `aegis_tls::CredentialSelector` over fresh keys of the listed schemes and answers with the id of
/// `CredentialSelector::select` on the raw ClientHello bytes (the aegis-wire peek), or `handshake_failure`.
#[cfg(all(feature = "mtc", not(feature = "cmvp")))]
mod cred_select {
    use std::io::{BufRead, Write};
    use std::sync::Arc;

    use aegis_tls::{Credential, CredentialKind, CredentialSelector, Profile};
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair, PqdsaKeyPair};
    use rustls::SignatureScheme;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::sign::CertifiedKey;

    use super::{OID_ECDSA_SHA256, OID_ECDSA_SHA384, OID_ML_DSA_44, OID_ML_DSA_87, R, self_signed};

    /// id-ml-dsa-65, 2.16.840.1.101.3.4.3.18.
    const OID_ML_DSA_65: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];
    /// id-Ed25519, 1.3.101.112.
    const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

    /// The chain: a self-signed certificate over `spki`, or the opaque bytes (an MTC: AEGIS neither issues nor
    /// verifies it, D-P7.4).
    fn chain(opaque: &Option<Vec<u8>>, oid: &[u8], spki: &[u8], sign: impl Fn(&[u8]) -> R<Vec<u8>>) -> R<Vec<u8>> {
        match opaque {
            Some(o) => Ok(o.clone()),
            None => self_signed(oid, spki, sign),
        }
    }

    fn ecdsa(
        alg: &'static signature::EcdsaSigningAlgorithm,
        oid: &[u8],
        opaque: &Option<Vec<u8>>,
    ) -> R<(Vec<u8>, Vec<u8>)> {
        let kp = EcdsaKeyPair::generate(alg).map_err(|e| format!("ecdsa: {e}"))?;
        let spki = kp.public_key().as_der().map_err(|e| format!("ecdsa spki: {e}"))?;
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let c = chain(opaque, oid, spki.as_ref(), |m| {
            kp.sign(&rng, m).map(|s| s.as_ref().to_vec()).map_err(|e| format!("ecdsa sign: {e}"))
        })?;
        Ok((c, kp.to_pkcs8v1().map_err(|e| format!("ecdsa pkcs8: {e}"))?.as_ref().to_vec()))
    }

    fn mldsa(
        alg: &'static signature::PqdsaSigningAlgorithm,
        oid: &[u8],
        opaque: &Option<Vec<u8>>,
    ) -> R<(Vec<u8>, Vec<u8>)> {
        let kp = PqdsaKeyPair::generate(alg).map_err(|e| format!("ml-dsa: {e}"))?;
        let spki = kp.public_key().as_der().map_err(|e| format!("ml-dsa spki: {e}"))?;
        let c = chain(opaque, oid, spki.as_ref(), |m| {
            // Largest ML-DSA signature (ML-DSA-87, FIPS 204 table 2); `sign` returns the actual length.
            let mut sig = vec![0u8; 4627];
            let n = kp.sign(m, &mut sig).map_err(|e| format!("ml-dsa sign: {e}"))?;
            sig.truncate(n);
            Ok(sig)
        })?;
        Ok((c, kp.to_pkcs8v1().map_err(|e| format!("ml-dsa pkcs8: {e}"))?.as_ref().to_vec()))
    }

    fn ed25519(opaque: &Option<Vec<u8>>) -> R<(Vec<u8>, Vec<u8>)> {
        let kp = Ed25519KeyPair::generate().map_err(|e| format!("ed25519: {e}"))?;
        let spki = kp.public_key().as_der().map_err(|e| format!("ed25519 spki: {e}"))?;
        let c = chain(opaque, OID_ED25519, spki.as_ref(), |m| Ok(kp.sign(m).as_ref().to_vec()))?;
        Ok((c, kp.to_pkcs8v1().map_err(|e| format!("ed25519 pkcs8: {e}"))?.as_ref().to_vec()))
    }

    /// (chain, PKCS#8 v1 key) of a fresh key signing with `scheme`.
    fn material(scheme: u16, opaque: &Option<Vec<u8>>) -> R<(Vec<u8>, Vec<u8>)> {
        match scheme {
            0x0403 => ecdsa(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, OID_ECDSA_SHA256, opaque),
            0x0503 => ecdsa(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, OID_ECDSA_SHA384, opaque),
            0x0807 => ed25519(opaque),
            0x0904 => mldsa(&signature::ML_DSA_44_SIGNING, OID_ML_DSA_44, opaque),
            0x0905 => mldsa(&signature::ML_DSA_65_SIGNING, OID_ML_DSA_65, opaque),
            0x0906 => mldsa(&signature::ML_DSA_87_SIGNING, OID_ML_DSA_87, opaque),
            s => Err(format!("unsupported scheme {s:04x}")),
        }
    }

    fn nibble(c: u8) -> R<u8> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err("bad hex digit".into()),
        }
    }

    fn hex(s: &str) -> R<Vec<u8>> {
        let (pairs, rest) = s.as_bytes().as_chunks::<2>();
        if !rest.is_empty() {
            return Err("odd-length hex".into());
        }
        pairs.iter().map(|[h, l]| Ok((nibble(*h)? << 4) | nibble(*l)?)).collect()
    }

    /// `id,listener,kind,scheme,trust_anchor_id`.
    fn credential(tok: &str) -> R<Credential> {
        let f: Vec<&str> = tok.split(',').collect();
        let [id, listener, kind, scheme, ta] = f.as_slice() else { return Err(format!("bad credential {tok}")) };
        let kind = CredentialKind::from_name(kind).ok_or(format!("bad kind {kind}"))?;
        if scheme.len() != 4 {
            return Err(format!("bad scheme {scheme}"));
        }
        let code = u16::from_str_radix(scheme, 16).map_err(|_| format!("bad scheme {scheme}"))?;
        let ta = match (*ta, kind) {
            ("-", CredentialKind::X509 | CredentialKind::MlDsa) => None,
            (t, CredentialKind::Mtc) if t != "-" => Some(hex(t)?),
            _ => return Err(format!("bad trust_anchor_id for {id}")),
        };
        let opaque = (kind == CredentialKind::Mtc).then(|| format!("opaque MTC blob for {id}").into_bytes());
        let (chain, key) = material(code, &opaque)?;
        let key = rustls::crypto::aws_lc_rs::default_provider()
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))
            .map_err(|e| format!("credential {id}: {e}"))?;
        let ck = Arc::new(CertifiedKey::new(vec![CertificateDer::from(chain)], key));
        Credential::new(*id, *listener, kind, SignatureScheme::from(code), ta, ck).map_err(|e| e.to_string())
    }

    /// The answer to one request line after its case number.
    fn answer(rest: &[&str]) -> R<String> {
        let [profile, listener, ncred, more @ ..] = rest else { return Err("short line".into()) };
        let profile = Profile::from_name(profile).ok_or(format!("unknown profile {profile}"))?;
        let n: usize = ncred.parse().map_err(|_| format!("bad ncred {ncred}"))?;
        let [creds @ .., hello] = more else { return Err("no client_hello".into()) };
        if creds.len() != n {
            return Err(format!("ncred {n} but {} credential tokens", creds.len()));
        }
        let pool = creds.iter().map(|t| credential(t)).collect::<R<Vec<_>>>()?;
        let selector = CredentialSelector::new(profile, listener, pool).map_err(|e| e.to_string())?;
        let raw = hex(hello)?;
        Ok(selector.select(&raw).map_or_else(|| "handshake_failure".to_string(), |c| c.id().to_string()))
    }

    pub(super) fn run() -> R<()> {
        let mut out = std::io::BufWriter::new(std::io::stdout().lock());
        for line in std::io::stdin().lock().lines() {
            let line = line.map_err(|e| e.to_string())?;
            let toks: Vec<&str> = line.split(' ').collect();
            let (case, rest) = toks.split_first().ok_or("empty line")?;
            let a = answer(rest).unwrap_or_else(|e| format!("error {}", e.replace(['\n', '\r'], " ")));
            writeln!(out, "{case} {a}").map_err(|e| e.to_string())?;
        }
        out.flush().map_err(|e| e.to_string())
    }
}

#[cfg(all(feature = "mtc", not(feature = "cmvp")))]
fn select() -> R<()> {
    cred_select::run()
}

#[cfg(not(all(feature = "mtc", not(feature = "cmvp"))))]
fn select() -> R<()> {
    Err("select is compiled out of this build (feature `mtc` off; never in the cmvp build, PREFLIGHT D-P7.4)".into())
}

// ------------------------------------------------------------------------------------------------ indicator

/// `indicator` (feature `indicator`, cmvp only; PREFLIGHT D-P8.2): the oracles/fips-indicator line protocol
/// (README "Subject protocol"). One request line in, one answer line out, in order; exit 0 at EOF. Every verdict is
/// `aegis_iso::fips::with_indicator` around exactly one call on this thread (AWS-LC's per-thread
/// `FIPS_service_indicator_before_call` / `_after_call`); key generation and the peer's half of an agreement run
/// outside the window. The verdict words come only from `aegis_iso::fips::Indicator`.
#[cfg(feature = "indicator")]
mod indicator {
    use std::io::{BufRead, Write};
    use std::sync::Arc;

    use aegis_iso::fips::{Indicator, with_indicator};
    use aegis_tls::{Profile, server_config_with};
    use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey};
    use aws_lc_rs::error::Unspecified;
    use aws_lc_rs::hkdf;
    use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, ML_KEM_1024};
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::{CryptoProvider, SupportedKxGroup, WebPkiSupportedAlgorithms, verify_tls13_signature};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{
        ClientConfig, ClientConnection, Connection, DigitallySignedStruct, ServerConnection, SignatureScheme,
    };

    use super::{HOST, R, linked_module, resolver};

    fn verdict(i: Indicator) -> &'static str {
        match i {
            Indicator::Approved => "approved",
            Indicator::NotApproved => "not-approved",
        }
    }

    fn nibble(c: u8) -> R<u8> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err("bad hex digit".into()),
        }
    }

    /// Hex to bytes; `-` is the empty string (the oracle's spelling of an empty salt or info).
    fn hex(s: &str) -> R<Vec<u8>> {
        if s == "-" {
            return Ok(Vec::new());
        }
        let (pairs, rest) = s.as_bytes().as_chunks::<2>();
        if !rest.is_empty() {
            return Err("odd-length hex".into());
        }
        pairs.iter().map(|[h, l]| Ok((nibble(*h)? << 4) | nibble(*l)?)).collect()
    }

    fn to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// One key agreement with a fresh key pair on each side; only our `agree` is inside the window.
    fn agree(alg: &'static agreement::Algorithm) -> R<String> {
        let mine = PrivateKey::generate(alg).map_err(|e| format!("keygen: {e}"))?;
        let peer = PrivateKey::generate(alg).map_err(|e| format!("keygen: {e}"))?;
        let mine_pub = mine.compute_public_key().map_err(|e| format!("public key: {e}"))?;
        let peer_pub = peer.compute_public_key().map_err(|e| format!("public key: {e}"))?;
        let (ours, ind) = with_indicator(|| {
            agreement::agree(&mine, UnparsedPublicKey::new(alg, peer_pub.as_ref()), Unspecified, |s| Ok(s.to_vec()))
        });
        let theirs =
            agreement::agree(&peer, UnparsedPublicKey::new(alg, mine_pub.as_ref()), Unspecified, |s| Ok(s.to_vec()));
        let matched = matches!((&ours, &theirs), (Ok(a), Ok(b)) if a == b);
        Ok(format!("indicator={} ok={} match={}", verdict(ind), u8::from(ours.is_ok()), u8::from(matched)))
    }

    /// ECDH P-384 against the oracle's (off-curve) peer point: the service must fail and nothing approved runs.
    fn agree_peer(peer_hex: &str) -> R<String> {
        let peer = hex(peer_hex)?;
        let mine = PrivateKey::generate(&agreement::ECDH_P384).map_err(|e| format!("keygen: {e}"))?;
        let (r, ind) = with_indicator(|| {
            agreement::agree(&mine, UnparsedPublicKey::new(&agreement::ECDH_P384, peer.as_slice()), Unspecified, |s| {
                Ok(s.to_vec())
            })
        });
        Ok(format!("indicator={} ok={}", verdict(ind), u8::from(r.is_ok())))
    }

    /// ML-KEM-1024: keygen, encapsulate and decapsulate, each in its own window.
    fn mlkem() -> R<String> {
        let (dk, kg) = with_indicator(|| DecapsulationKey::generate(&ML_KEM_1024));
        let dk = dk.map_err(|e| format!("keygen: {e}"))?;
        let ek = dk.encapsulation_key().map_err(|e| format!("encapsulation key: {e}"))?;
        let (enc, ei) = with_indicator(|| ek.encapsulate());
        let (ct, ss_enc) = enc.map_err(|e| format!("encapsulate: {e}"))?;
        let (dec, di) = with_indicator(|| dk.decapsulate(Ciphertext::from(ct.as_ref())));
        let ss_dec = dec.map_err(|e| format!("decapsulate: {e}"))?;
        let matched = ss_enc.as_ref() == ss_dec.as_ref();
        Ok(format!("keygen={} encap={} decap={} match={}", verdict(kg), verdict(ei), verdict(di), u8::from(matched)))
    }

    struct Len(usize);

    impl hkdf::KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }

    /// HKDF (aws-lc-rs `Salt::extract` + `Prk::expand` + `Okm::fill`, i.e. AWS-LC's one-shot `HKDF()`) in one window.
    fn hkdf_op(args: &[&str]) -> R<String> {
        let [h, salt, ikm, info, n] = args else { return Err("want: hkdf HASH SALT IKM INFO LEN".into()) };
        let (alg, hash_len) = match *h {
            "sha256" => (hkdf::HKDF_SHA256, 32),
            "sha384" => (hkdf::HKDF_SHA384, 48),
            "sha512" => (hkdf::HKDF_SHA512, 64),
            other => return Err(format!("unsupported hash {other}")),
        };
        let (salt, ikm, info) = (hex(salt)?, hex(ikm)?, hex(info)?);
        let n: usize = n.parse().map_err(|_| format!("bad length {n}"))?;
        if n == 0 || n > 255 * hash_len {
            return Err(format!("length {n} out of range"));
        }
        let mut okm = vec![0u8; n];
        let (r, ind) = with_indicator(|| {
            let prk = hkdf::Salt::new(alg, &salt).extract(&ikm);
            let parts = [info.as_slice()];
            prk.expand(&parts, Len(n)).and_then(|o| o.fill(&mut okm))
        });
        r.map_err(|e| format!("hkdf: {e}"))?;
        Ok(format!("indicator={} okm={}", verdict(ind), to_hex(&okm)))
    }

    /// The AEGIS SecP384r1MLKEM1024 group alone (`aegis_tls::kx`): client start, server start-and-complete, client
    /// complete, each in its own window. Reported only.
    fn kx_0x11ed() -> R<String> {
        let g = aegis_tls::kx::SECP384R1MLKEM1024;
        let (c, i1) = with_indicator(|| g.start());
        let c = c.map_err(|e| format!("client start: {e}"))?;
        let client_share = c.pub_key().to_vec();
        let (s, i2) = with_indicator(|| g.start_and_complete(&client_share));
        let s = s.map_err(|e| format!("server: {e}"))?;
        let (cs, i3) = with_indicator(|| c.complete(&s.pub_key));
        let cs = cs.map_err(|e| format!("client complete: {e}"))?;
        let matched = cs.secret_bytes() == s.secret.secret_bytes();
        Ok(format!(
            "client_start={} server={} client_complete={} match={}",
            verdict(i1),
            verdict(i2),
            verdict(i3),
            u8::from(matched)
        ))
    }

    /// The handshake client's verifier: the server's self-signed certificates generated by this process, pinned by
    /// DER, for `aegis.test` only, with the TLS 1.3 CertificateVerify signature checked by the provider's algorithms.
    /// No WebPKI chain building (the certificates are generated here; there is no CA).
    #[derive(Debug)]
    struct Pinned {
        certs: Vec<Vec<u8>>,
        algs: WebPkiSupportedAlgorithms,
    }

    impl ServerCertVerifier for Pinned {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            let host = matches!(server_name, ServerName::DnsName(d) if d.as_ref().as_bytes() == HOST);
            if host && intermediates.is_empty() && self.certs.iter().any(|c| c.as_slice() == end_entity.as_ref()) {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer))
            }
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
            verify_tls13_signature(message, cert, dss, &self.algs)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.algs.supported_schemes()
        }
    }

    /// Move every pending record from `a` to `b` and process it; the byte count moved.
    fn transfer(a: &mut Connection, b: &mut Connection) -> R<usize> {
        let mut buf = Vec::new();
        while a.wants_write() {
            a.write_tls(&mut buf).map_err(|e| e.to_string())?;
        }
        let mut rd = buf.as_slice();
        while !rd.is_empty() {
            if b.read_tls(&mut rd).map_err(|e| e.to_string())? == 0 {
                break;
            }
            b.process_new_packets().map_err(|e| format!("tls: {e}"))?;
        }
        Ok(buf.len())
    }

    /// Client and server, both in this thread, until both finish the handshake.
    fn run_handshake(server: Arc<rustls::ServerConfig>, client: Arc<ClientConfig>) -> R<(Connection, Connection)> {
        let name = ServerName::try_from("aegis.test").map_err(|e| e.to_string())?;
        let mut cli: Connection = ClientConnection::new(client, name).map_err(|e| e.to_string())?.into();
        let mut srv: Connection = ServerConnection::new(server).map_err(|e| e.to_string())?.into();
        for _ in 0..16 {
            let moved = transfer(&mut cli, &mut srv)? + transfer(&mut srv, &mut cli)?;
            if !cli.is_handshaking() && !srv.is_handshaking() {
                return Ok((cli, srv));
            }
            if moved == 0 {
                return Err("handshake stalled".into());
            }
        }
        Err("handshake did not finish in 16 flights".into())
    }

    /// One TLS 1.3 handshake on 0x11ED: the server is `aegis_tls::server_config_with` (the production builder,
    /// cmvp credentials), the client a rustls client on the server's own provider with kx restricted to 0x11ED.
    /// Client construction (its key share) through the last flight is one window. Reported, not required (D-P8.1).
    fn handshake(args: &[&str]) -> R<String> {
        let [name] = args else { return Err("want: handshake PROFILE".into()) };
        let profile = Profile::from_name(name).ok_or(format!("unknown profile {name}"))?;
        let (res, certs) = resolver(profile)?;
        let server = server_config_with(profile, res, linked_module()).map_err(|e| format!("{name}: {e}"))?;
        let base: &CryptoProvider = server.crypto_provider();
        let kx: Vec<&'static dyn SupportedKxGroup> =
            base.kx_groups.iter().copied().filter(|g| u16::from(g.name()) == aegis_tls::kx::CODEPOINT).collect();
        if kx.is_empty() {
            return Err(format!("{name} does not offer 0x11ED"));
        }
        let provider = CryptoProvider { kx_groups: kx, ..base.clone() };
        let algs = provider.signature_verification_algorithms;
        let mut client = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| e.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pinned { certs, algs }))
            .with_no_client_auth();
        client.resumption = rustls::client::Resumption::disabled();
        client.enable_early_data = false;
        let (r, ind) = with_indicator(|| run_handshake(Arc::new(server), Arc::new(client)));
        let (cli, srv) = r?;
        let group = |c: &Connection| c.negotiated_key_exchange_group().map(|g| u16::from(g.name()));
        let (g, sg) = (group(&cli), group(&srv));
        if g != sg {
            return Err(format!("client group {g:?} != server group {sg:?}"));
        }
        let v = cli.protocol_version().map(u16::from).unwrap_or(0);
        let s = cli.negotiated_cipher_suite().map(|s| u16::from(s.suite())).unwrap_or(0);
        Ok(format!("group=0x{:04x} version=0x{v:04x} suite=0x{s:04x} indicator={}", g.unwrap_or(0), verdict(ind)))
    }

    fn answer(op: &str, args: &[&str]) -> R<String> {
        match (op, args) {
            ("module", []) => Ok(format!("module={}", linked_module().unwrap_or("none"))),
            ("ecdh-p384", []) => agree(&agreement::ECDH_P384),
            ("x25519", []) => agree(&agreement::X25519),
            ("ecdh-p384-peer", [p]) => agree_peer(p),
            ("mlkem1024", []) => mlkem(),
            ("hkdf", a) => hkdf_op(a),
            ("none", []) => Ok(format!("indicator={}", verdict(with_indicator(|| ()).1))),
            ("kx-0x11ed", []) => kx_0x11ed(),
            ("handshake", a) => handshake(a),
            _ => Err(format!("unknown request {op} with {} argument(s)", args.len())),
        }
    }

    pub(super) fn run() -> R<()> {
        let mut out = std::io::BufWriter::new(std::io::stdout().lock());
        for line in std::io::stdin().lock().lines() {
            let line = line.map_err(|e| e.to_string())?;
            let toks: Vec<&str> = line.split_whitespace().collect();
            let [id, op, args @ ..] = toks.as_slice() else { continue };
            let a = answer(op, args).unwrap_or_else(|e| format!("error {}", e.replace(['\n', '\r'], " ")));
            writeln!(out, "{id} {op} {a}").map_err(|e| e.to_string())?;
        }
        out.flush().map_err(|e| e.to_string())
    }
}

#[cfg(feature = "indicator")]
fn indicator() -> R<()> {
    indicator::run()
}

#[cfg(not(feature = "indicator"))]
fn indicator() -> R<()> {
    Err("indicator is compiled out of this build (feature `indicator` off; cmvp only, PREFLIGHT D-P8.2: \
         profiles/cmvp/build.sh builds tls-subject with cmvp,indicator)"
        .into())
}

#[cfg(all(feature = "cmvp", feature = "interop"))]
compile_error!(
    "tls-subject: features `cmvp` and `interop` are exclusive (interop enables aegis-tls `tls-client`; the cmvp build \
     compiles every rustls client out, spikes/cmvp-client-policy mode A): build with --no-default-features"
);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest: Vec<&str> = args.iter().map(String::as_str).skip_while(|a| *a == "subject").collect();
    let r = match rest.as_slice() {
        ["describe", p] => describe(p),
        ["serve", p] => serve(p),
        ["interop-server", p] => interop(interop_server(p)),
        ["interop-client", p, ca, nonce] => interop(interop_client(p, ca, nonce)),
        ["select"] => select(),
        ["indicator"] => indicator(),
        _ => Err("usage: tls-subject [subject] describe|serve|interop-server PROFILE \
                  | tls-subject [subject] interop-client PROFILE CA_PEM NONCE | tls-subject [subject] select|indicator"
            .into()),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
