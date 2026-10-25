//! tls-subject: the aegis-tls listener configs over the oracles/hrr-verdicts `--subject` protocol (F12).
//!
//!   tls-subject [subject] describe <PROFILE>   key=value lines (kx_groups, versions, early_data, fips, module)
//!   tls-subject [subject] serve <PROFILE>      one TLS server connection over stdin/stdout
//!
//! Every `ServerConfig` comes from `aegis_tls::server_config` (the production builder); this binary only supplies a
//! credential (a self-signed certificate generated at start-up) and reads the built config back. Reported
//! `kx_groups` are read from the built `CryptoProvider`, not from the profile constant, so a builder bug shows.
//! Credentials: ML-DSA-44 on PQ-REQUIRED (private hops, as the oracle reference), ECDSA-P256 elsewhere.
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::process::ExitCode;
use std::sync::Arc;

use aegis_tls::{Profile, fips_status, negotiable_versions, server_config};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self, EcdsaKeyPair, KeyPair, PqdsaKeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::ResolvesServerCert;
use rustls::sign::{CertifiedKey, SingleCertAndKey};
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

const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_ML_DSA_44: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11];
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

fn ecdsa_p256() -> R<(Vec<u8>, Vec<u8>)> {
    let kp = EcdsaKeyPair::generate(&signature::ECDSA_P256_SHA256_ASN1_SIGNING).map_err(|e| format!("ecdsa: {e}"))?;
    let spki = kp.public_key().as_der().map_err(|e| format!("ecdsa spki: {e}"))?;
    let rng = SystemRandom::new();
    let cert = self_signed(OID_ECDSA_SHA256, spki.as_ref(), |m| {
        kp.sign(&rng, m).map(|s| s.as_ref().to_vec()).map_err(|e| format!("ecdsa sign: {e}"))
    })?;
    let key = kp.to_pkcs8v1().map_err(|e| format!("ecdsa pkcs8: {e}"))?;
    Ok((cert, key.as_ref().to_vec()))
}

fn mldsa44() -> R<(Vec<u8>, Vec<u8>)> {
    let kp = PqdsaKeyPair::generate(&signature::ML_DSA_44_SIGNING).map_err(|e| format!("ml-dsa: {e}"))?;
    let spki = kp.public_key().as_der().map_err(|e| format!("ml-dsa spki: {e}"))?;
    let cert = self_signed(OID_ML_DSA_44, spki.as_ref(), |m| {
        let mut sig = vec![0u8; 2420];
        let n = kp.sign(m, &mut sig).map_err(|e| format!("ml-dsa sign: {e}"))?;
        sig.truncate(n);
        Ok(sig)
    })?;
    let key = kp.to_pkcs8v1().map_err(|e| format!("ml-dsa pkcs8: {e}"))?;
    Ok((cert, key.as_ref().to_vec()))
}

/// Credential for a profile, with the rustls key/certificate consistency check (`CertifiedKey::from_der`).
fn resolver(profile: Profile) -> R<Arc<dyn ResolvesServerCert>> {
    let (cert, key) = if profile == Profile::PqRequired { mldsa44()? } else { ecdsa_p256()? };
    let ck = CertifiedKey::from_der(
        vec![CertificateDer::from(cert)],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        &rustls::crypto::aws_lc_rs::default_provider(),
    )
    .map_err(|e| format!("credential: {e}"))?;
    ck.keys_match().map_err(|e| format!("credential keys_match: {e}"))?;
    Ok(Arc::new(SingleCertAndKey::from(ck)))
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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest: Vec<&str> = args.iter().map(String::as_str).skip_while(|a| *a == "subject").collect();
    let r = match rest.as_slice() {
        ["describe", p] => describe(p),
        ["serve", p] => serve(p),
        _ => Err("usage: tls-subject [subject] describe|serve PROFILE".into()),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
