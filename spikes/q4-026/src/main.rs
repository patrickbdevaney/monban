//! q4-026 harness: KATs, rustls<->rustls, negative tests, and TCP server/client for OpenSSL / Go interop.
//!
//!   kx11ed selftest
//!   kx11ed server <port> [count]      rustls server, kx_groups = [0x11ED] only, ECDSA-P384 cert; serves `count`
//!                                      connections (default 1), answers one HTTP/1.0-ish request each.
//!   kx11ed client <host:port>         rustls client, kx_groups = [0x11ED] only; sends GET /, prints the reply head.
//!
//! The harness (not the kx module) uses indexing and unwrap-free-but-loose error handling; it is test code.
#![forbid(unsafe_code)]
#![allow(clippy::indexing_slicing)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use kx11ed::{
    Active, CLIENT_SHARE_LEN, MLKEM1024_CT_LEN, NAME, P384_SHARE_LEN, SECP384R1MLKEM1024, SERVER_SHARE_LEN,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup, aws_lc_rs,
};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error, NamedGroup, ProtocolVersion, ServerConfig,
    ServerConnection, SignatureScheme,
};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

const KAT_MLKEM: &str = include_str!("../kat/acvp-mlkem1024.txt");
const KAT_P384: &str = include_str!("../kat/rfc5903-p384.txt");

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let r = match args.get(1).map(String::as_str) {
        Some("selftest") => selftest(),
        Some("server") => server(
            args.get(2).map(String::as_str).unwrap_or("8443"),
            args.get(3).and_then(|c| c.parse().ok()).unwrap_or(1),
        ),
        Some("server-swapped") => server_with(
            args.get(2).map(String::as_str).unwrap_or("8443"),
            args.get(3).and_then(|c| c.parse().ok()).unwrap_or(1),
            leak(SwapOrder),
        ),
        Some("client") => client(args.get(2).map(String::as_str).unwrap_or("127.0.0.1:8443")),
        _ => Err("usage: kx11ed selftest | server <port> [count] | client <host:port>".into()),
    };
    if let Err(e) = r {
        eprintln!("ERROR: {e}");
        std::process::exit(1);
    }
}

// ------------------------------------------------------------------------------------------- configs

fn provider(groups: Vec<&'static dyn SupportedKxGroup>) -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider { kx_groups: groups, ..aws_lc_rs::default_provider() })
}

fn server_config(groups: Vec<&'static dyn SupportedKxGroup>) -> Res<Arc<ServerConfig>> {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)?;
    let cert = rcgen::CertificateParams::new(vec!["monban.test".to_string(), "localhost".to_string()])?
        .self_signed(&kp)?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(kp.serialize_der()));
    let cfg = ServerConfig::builder_with_provider(provider(groups))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)?;
    Ok(Arc::new(cfg))
}

/// Accepts any certificate but verifies the CertificateVerify signature (interop targets use self-signed certs).
#[derive(Debug)]
struct AnyCert(Arc<CryptoProvider>);

impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("tls12 disabled".into()))
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(msg, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn client_config(groups: Vec<&'static dyn SupportedKxGroup>) -> Res<Arc<ClientConfig>> {
    let p = provider(groups);
    let cfg = ClientConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(p)))
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

fn group_name(g: Option<&'static dyn SupportedKxGroup>) -> String {
    match g.map(|g| g.name()) {
        Some(n) if n == NAME => "SecP384r1MLKEM1024 (0x11ED)".into(),
        Some(n) => format!("{n:?} (0x{:04x})", u16::from(n)),
        None => "none".into(),
    }
}

// ------------------------------------------------------------------------------------- in-memory pump

#[derive(Debug)]
struct Outcome {
    ok: bool,
    client_err: Option<String>,
    server_err: Option<String>,
    /// (sender, alert description) for a plaintext fatal alert seen on the wire; None if no plaintext alert.
    alert: Option<(&'static str, u8)>,
    encrypted_alert_from: Option<&'static str>,
    client_group: String,
    server_group: String,
}

fn scan_alert(buf: &[u8]) -> (Option<u8>, bool) {
    // Walk TLS records; return plaintext alert description, and whether an encrypted record followed an error.
    let mut i = 0;
    let mut enc = false;
    while i + 5 <= buf.len() {
        let ct = buf[i];
        let len = u16::from_be_bytes([buf[i + 3], buf[i + 4]]) as usize;
        if ct == 0x15 && len == 2 && i + 7 <= buf.len() {
            return (Some(buf[i + 6]), false);
        }
        if ct == 0x17 {
            enc = true;
        }
        i += 5 + len;
    }
    (None, enc)
}

fn handshake(ccfg: Arc<ClientConfig>, scfg: Arc<ServerConfig>) -> Res<Outcome> {
    handshake_wire(ccfg, scfg, None, None)
}

type WireMod = fn(&[u8]) -> Option<Vec<u8>>;

/// Rewrite the key_share extension of the first handshake record so the 0x11ED entry has an EMPTY
/// key_exchange (an encoding a rustls sender refuses to produce: PayloadU16<NonEmpty> asserts on encode).
/// Fixes up record, handshake, extensions, extension and (ClientHello) client_shares lengths.
fn empty_key_share(flight: &[u8], client_hello: bool) -> Option<Vec<u8>> {
    let rlen = u16::from_be_bytes([*flight.get(3)?, *flight.get(4)?]) as usize;
    let rec = flight.get(5..5 + rlen)?;
    let rest = flight.get(5 + rlen..)?;
    // handshake header
    let body = rec.get(4..)?;
    let mut i = 2 + 32; // legacy_version, random
    i += 1 + *body.get(i)? as usize; // session id
    if client_hello {
        i += 2 + u16::from_be_bytes([*body.get(i)?, *body.get(i + 1)?]) as usize; // suites
        i += 1 + *body.get(i)? as usize; // compression
    } else {
        i += 2 + 1; // suite, compression
    }
    let ext_len_at = i;
    let ext_end = i + 2 + u16::from_be_bytes([*body.get(i)?, *body.get(i + 1)?]) as usize;
    let mut j = i + 2;
    while j + 4 <= ext_end {
        let ty = u16::from_be_bytes([*body.get(j)?, *body.get(j + 1)?]);
        let l = u16::from_be_bytes([*body.get(j + 2)?, *body.get(j + 3)?]) as usize;
        if ty == 0x0033 {
            // find the 0x11ED entry
            let mut k = j + 4 + if client_hello { 2 } else { 0 };
            while k + 4 <= j + 4 + l {
                let g = u16::from_be_bytes([*body.get(k)?, *body.get(k + 1)?]);
                let gl = u16::from_be_bytes([*body.get(k + 2)?, *body.get(k + 3)?]) as usize;
                if g == kx11ed::CODEPOINT {
                    let mut b = body.to_vec();
                    b.drain(k + 4..k + 4 + gl);
                    b[k + 2] = 0;
                    b[k + 3] = 0;
                    let sub = |b: &mut Vec<u8>, at: usize| {
                        let v = u16::from_be_bytes([b[at], b[at + 1]]) as usize - gl;
                        b[at..at + 2].copy_from_slice(&(v as u16).to_be_bytes());
                    };
                    if client_hello {
                        sub(&mut b, j + 4);
                    }
                    sub(&mut b, j + 2);
                    sub(&mut b, ext_len_at);
                    let hl = b.len();
                    let mut out = vec![0x16, flight[1], flight[2]];
                    out.extend_from_slice(&((hl + 4) as u16).to_be_bytes());
                    out.push(rec[0]);
                    out.extend_from_slice(&(hl as u32).to_be_bytes()[1..]);
                    out.extend_from_slice(&b);
                    out.extend_from_slice(rest);
                    return Some(out);
                }
                k += 4 + gl;
            }
        }
        j += 4 + l;
    }
    None
}
fn empty_ch_share(f: &[u8]) -> Option<Vec<u8>> {
    empty_key_share(f, true)
}
fn empty_sh_share(f: &[u8]) -> Option<Vec<u8>> {
    empty_key_share(f, false)
}

fn handshake_wire(
    ccfg: Arc<ClientConfig>,
    scfg: Arc<ServerConfig>,
    mut cmod: Option<WireMod>,
    mut smod: Option<WireMod>,
) -> Res<Outcome> {
    let mut c = ClientConnection::new(ccfg, ServerName::try_from("monban.test")?)?;
    let mut s = ServerConnection::new(scfg)?;
    let mut out = Outcome {
        ok: false,
        client_err: None,
        server_err: None,
        alert: None,
        encrypted_alert_from: None,
        client_group: String::new(),
        server_group: String::new(),
    };
    for _ in 0..20 {
        let mut buf = Vec::new();
        c.write_tls(&mut buf)?;
        if out.client_err.is_some() {
            let (a, enc) = scan_alert(&buf);
            if let Some(d) = a {
                out.alert = Some(("client", d));
            } else if enc {
                out.encrypted_alert_from = Some("client");
            }
            break;
        }
        if let Some(m) = cmod.take() {
            buf = m(&buf).ok_or("wire mod (client flight) did not apply")?;
        }
        if !buf.is_empty() {
            s.read_tls(&mut buf.as_slice())?;
            if let Err(e) = s.process_new_packets() {
                out.server_err = Some(format!("{e:?}"));
            }
        }
        let mut buf = Vec::new();
        s.write_tls(&mut buf)?;
        if out.server_err.is_some() {
            let (a, enc) = scan_alert(&buf);
            if let Some(d) = a {
                out.alert = Some(("server", d));
            } else if enc {
                out.encrypted_alert_from = Some("server");
            }
            break;
        }
        if let Some(m) = smod.take() {
            buf = m(&buf).ok_or("wire mod (server flight) did not apply")?;
        }
        if !buf.is_empty() {
            c.read_tls(&mut buf.as_slice())?;
            if let Err(e) = c.process_new_packets() {
                out.client_err = Some(format!("{e:?}"));
            }
        }
        if !c.is_handshaking() && !s.is_handshaking() && out.client_err.is_none() && out.server_err.is_none() {
            out.ok = true;
            break;
        }
    }
    out.client_group = group_name(c.negotiated_key_exchange_group());
    out.server_group = group_name(s.negotiated_key_exchange_group());
    Ok(out)
}

// ------------------------------------------------------------------------- mutating wrapper groups

#[derive(Debug, Clone)]
enum Mutation {
    Truncate(usize),
    Extend(usize),
    SetByte(usize, u8),
    XorByte(usize, u8),
    ReplaceTail(Vec<u8>), // replace the ML-KEM part (after the 97-byte point)
}

fn short(m: &Mutation) -> String {
    match m {
        Mutation::ReplaceTail(t) => format!("ReplaceTail(ML-KEM part := {} bytes, first 2 = {:02x}{:02x})", t.len(), t.first().unwrap_or(&0), t.get(1).unwrap_or(&0)),
        other => format!("{other:?}"),
    }
}

fn mutate(mut v: Vec<u8>, m: &Mutation) -> Vec<u8> {
    match m {
        Mutation::Truncate(n) => v.truncate(v.len().saturating_sub(*n)),
        Mutation::Extend(n) => v.extend(std::iter::repeat_n(0u8, *n)),
        Mutation::SetByte(i, b) => {
            if let Some(x) = v.get_mut(*i) {
                *x = *b
            }
        }
        Mutation::XorByte(i, b) => {
            if let Some(x) = v.get_mut(*i) {
                *x ^= *b
            }
        }
        Mutation::ReplaceTail(t) => {
            v.truncate(P384_SHARE_LEN);
            v.extend_from_slice(t);
        }
    }
    v
}

/// Client-side group whose key share is mutated before sending (exercises the server's parser).
#[derive(Debug)]
struct ClientMut(Mutation);
struct ClientMutActive(Box<dyn ActiveKeyExchange>, Vec<u8>);

impl SupportedKxGroup for ClientMut {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let inner = SECP384R1MLKEM1024.start()?;
        let pk = mutate(inner.pub_key().to_vec(), &self.0);
        Ok(Box::new(ClientMutActive(inner, pk)))
    }
    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
    fn name(&self) -> NamedGroup {
        NAME
    }
    fn usable_for_version(&self, v: ProtocolVersion) -> bool {
        v == ProtocolVersion::TLSv1_3
    }
}
impl ActiveKeyExchange for ClientMutActive {
    fn complete(self: Box<Self>, p: &[u8]) -> Result<SharedSecret, Error> {
        self.0.complete(p)
    }
    fn pub_key(&self) -> &[u8] {
        &self.1
    }
    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
    fn group(&self) -> NamedGroup {
        NAME
    }
}

/// Server-side group whose ServerHello key share is mutated (exercises the client's parser).
#[derive(Debug)]
struct ServerMut(Mutation);
impl SupportedKxGroup for ServerMut {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        SECP384R1MLKEM1024.start()
    }
    fn start_and_complete(&self, share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let mut ckx = SECP384R1MLKEM1024.start_and_complete(share)?;
        ckx.pub_key = mutate(ckx.pub_key, &self.0);
        Ok(ckx)
    }
    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
    fn name(&self) -> NamedGroup {
        NAME
    }
    fn usable_for_version(&self, v: ProtocolVersion) -> bool {
        v == ProtocolVersion::TLSv1_3
    }
}

fn leak<T: SupportedKxGroup + 'static>(g: T) -> &'static dyn SupportedKxGroup {
    Box::leak(Box::new(g))
}

// ---------------------------------------------------------------------------------------- helpers

fn hex(s: &str) -> Res<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err("odd hex".into());
    }
    (0..s.len()).step_by(2).map(|i| Ok(u8::from_str_radix(&s[i..i + 2], 16)?)).collect()
}

struct Tally {
    pass: usize,
    fail: usize,
}
impl Tally {
    fn check(&mut self, id: &str, ok: bool, detail: impl AsRef<str>) {
        if ok {
            self.pass += 1;
        } else {
            self.fail += 1;
        }
        println!("{} {id}: {}", if ok { "PASS" } else { "FAIL" }, detail.as_ref());
    }
}

// --------------------------------------------------------------------------------------- selftest

fn selftest() -> Res<()> {
    let mut t = Tally { pass: 0, fail: 0 };
    println!("== q4-026 selftest: rustls 0.23.46 + aws-lc-rs 1.18.2, group 0x11ED (RFC 10024) ==");
    println!("aws-lc-rs try_fips_mode: {:?}", aws_lc_rs_fips());

    // ---- K: known-answer tests
    let p: std::collections::HashMap<&str, &str> = KAT_P384
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once(' '))
        .collect();
    let get = |k: &str| -> Res<Vec<u8>> { hex(p.get(k).ok_or("missing kat key")?) };
    let (i, gix, giy, grx, gry, girx) = (get("i")?, get("gix")?, get("giy")?, get("grx")?, get("gry")?, get("girx")?);
    let gr: Vec<u8> = [vec![0x04], grx, gry].concat();
    let gi: Vec<u8> = [vec![0x04], gix, giy].concat();

    let mut n_dec = 0;
    let mut n_ekc = 0;
    for line in KAT_MLKEM.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = line.split(' ').collect();
        match f.first().copied() {
            Some("dec") if f.len() == 5 => {
                let (tc, dk, c, k) = (f[1], hex(f[2])?, hex(f[3])?, hex(f[4])?);
                // Composite client-side KAT: P-384 scalar i (RFC 5903 8.2) + ML-KEM-1024 dk (ACVP), server share
                // g^r || c. RFC 10024 4.3 => secret = girx (48) || k (32).
                let active = Active::from_fixed_keys_for_kat(&i, &dk)?;
                let ok_pub = active.pub_key().len() == CLIENT_SHARE_LEN && active.pub_key()[..P384_SHARE_LEN] == gi[..];
                let server_share = [gr.clone(), c].concat();
                let secret = Box::new(active).complete(&server_share)?;
                let expect = [girx.clone(), k].concat();
                n_dec += 1;
                t.check(
                    &format!("K-dec-{tc}"),
                    ok_pub && secret.secret_bytes() == expect.as_slice(),
                    format!(
                        "composite KAT (RFC5903 8.2 P-384 + ACVP ML-KEM-1024 decap tc {tc}): client share = g^i||ek, secret = girx||k ({} bytes)",
                        expect.len()
                    ),
                );
            }
            Some("ekc") if f.len() == 4 => {
                let (tc, ek, valid) = (f[1], hex(f[2])?, f[3] == "1");
                // Server-side encapsulation-key check through the real TLS path: client share point is a fresh
                // valid P-384 point, ML-KEM part replaced by the ACVP ek.
                let cl = leak(ClientMut(Mutation::ReplaceTail(ek)));
                let o = handshake(client_config(vec![cl])?, server_config(vec![SECP384R1MLKEM1024])?)?;
                n_ekc += 1;
                if valid {
                    // Valid ek: server accepts; client then fails at decapsulation->Finished (its dk does not match
                    // the substituted ek), which is the expected implicit-rejection behaviour, not a parse error.
                    t.check(
                        &format!("K-ekc-{tc}"),
                        o.server_err.is_none() && o.alert.is_none(),
                        format!("ACVP valid ek accepted by server (server_err={:?}; client then fails Finished: {:?})", o.server_err, o.client_err),
                    );
                } else {
                    t.check(
                        &format!("K-ekc-{tc}"),
                        o.alert == Some(("server", 47)),
                        format!("ACVP invalid ek (FIPS 203 7.2 modulus check) -> server alert {:?} err {:?}", o.alert, o.server_err),
                    );
                }
            }
            _ => {}
        }
    }
    println!("   ({n_dec} decap vectors, {n_ekc} encapsulation-key-check vectors)");

    // ---- R: rustls <-> rustls
    let o = handshake(client_config(vec![SECP384R1MLKEM1024])?, server_config(vec![SECP384R1MLKEM1024])?)?;
    t.check("R1", o.ok && o.client_group.contains("0x11ED") && o.server_group.contains("0x11ED"),
        format!("rustls client [0x11ED] <-> rustls server [0x11ED]: client={} server={}", o.client_group, o.server_group));

    let o = handshake(
        client_config(vec![aws_lc_rs::kx_group::X25519, SECP384R1MLKEM1024])?,
        server_config(vec![SECP384R1MLKEM1024])?,
    )?;
    t.check("R2", o.ok && o.server_group.contains("0x11ED"),
        format!("HRR path: client [X25519, 0x11ED] (share only for X25519) -> server [0x11ED] HRR -> {}", o.server_group));

    let o = handshake(
        client_config(vec![SECP384R1MLKEM1024, aws_lc_rs::kx_group::SECP384R1])?,
        server_config(vec![aws_lc_rs::kx_group::SECP384R1])?,
    )?;
    t.check("R3", o.ok && o.server_group.contains("secp384r1"),
        format!("hybrid_component: client [0x11ED, P-384] -> P-384-only server, no HRR (P-384 half reused): {}", o.server_group));

    let o = handshake(
        client_config(vec![SECP384R1MLKEM1024])?,
        server_config(vec![aws_lc_rs::kx_group::X25519MLKEM768, aws_lc_rs::kx_group::SECP256R1MLKEM768])?,
    )?;
    t.check("R4", !o.ok && o.alert == Some(("server", 40)),
        format!("no common group: client [0x11ED] -> server [0x11EC,0x11EB]: alert {:?}", o.alert));

    let o = handshake(client_config(vec![SECP384R1MLKEM1024])?, server_config(vec![leak(SwapOrder)])?)?;
    t.check("R5-mutant", !o.ok && o.client_err.is_some(),
        format!("mutant server with ML-KEM-first secret order (X25519MLKEM768 style) must NOT interoperate: client_err {:?}", o.client_err));

    // ---- N: negative tests through the real handshake (server parses client share)
    let cases_c: Vec<(&str, Mutation)> = vec![
        ("N-c-short1", Mutation::Truncate(1)),
        ("N-c-short-1568", Mutation::Truncate(1568)), // P-384 point only
        ("N-c-long1", Mutation::Extend(1)),
        ("N-c-prefix02", Mutation::SetByte(0, 0x02)), // compressed-form prefix at full length
        ("N-c-prefix00", Mutation::SetByte(0, 0x00)),
        ("N-c-offcurve", Mutation::XorByte(96, 0x01)), // flip Y lsb -> not on curve
        ("N-c-ek-coeff>q", Mutation::SetByte(P384_SHARE_LEN, 0xFF)), // first coeff low 8 bits
    ];
    for (id, m) in cases_c {
        // For ek-coeff>q also set the high nibble so the first 12-bit coefficient is 0xFFF >= q=3329.
        let m = match (id, &m) {
            ("N-c-ek-coeff>q", _) => Mutation::ReplaceTail({
                let mut e = vec![0u8; 1568];
                e[0] = 0xFF;
                e[1] = 0x0F;
                e
            }),
            _ => m,
        };
        let cl = leak(ClientMut(m.clone()));
        let r = catch_unwind(AssertUnwindSafe(|| {
            handshake(client_config(vec![cl]).ok()?, server_config(vec![SECP384R1MLKEM1024]).ok()?).ok()
        }));
        match r {
            Ok(Some(o)) => t.check(id, o.alert == Some(("server", 47)),
                format!("{}: server alert {:?} (47=illegal_parameter), server_err {:?}", short(&m), o.alert, o.server_err)),
            Ok(None) => t.check(id, false, "harness error"),
            Err(_) => t.check(id, false, "PANIC"),
        }
    }

    // ---- N: negative tests (client parses ServerHello share)
    let cases_s: Vec<(&str, Mutation, u8)> = vec![
        ("N-s-ct-short1", Mutation::Truncate(1), 47),
        ("N-s-ct-short-all", Mutation::Truncate(MLKEM1024_CT_LEN), 47),
        ("N-s-ct-long1", Mutation::Extend(1), 47),
        ("N-s-prefix02", Mutation::SetByte(0, 0x02), 47),
        ("N-s-offcurve", Mutation::XorByte(96, 0x01), 47),
    ];
    for (id, m, want) in cases_s {
        let sv = leak(ServerMut(m.clone()));
        let r = catch_unwind(AssertUnwindSafe(|| {
            handshake(client_config(vec![SECP384R1MLKEM1024]).ok()?, server_config(vec![sv]).ok()?).ok()
        }));
        match r {
            Ok(Some(o)) => t.check(id, o.alert == Some(("client", want)),
                format!("{m:?}: client alert {:?}, client_err {:?}", o.alert, o.client_err)),
            Ok(None) => t.check(id, false, "harness error"),
            Err(_) => t.check(id, false, "PANIC"),
        }
    }
    // Empty key_exchange injected on the wire (rustls cannot send it): rejected by the rustls decoder before
    // reaching the group, decode_error (50).
    let o = handshake_wire(client_config(vec![SECP384R1MLKEM1024])?, server_config(vec![SECP384R1MLKEM1024])?, Some(empty_ch_share), None)?;
    t.check("N-c-empty", o.alert == Some(("server", 50)) || o.alert == Some(("server", 47)),
        format!("ClientHello 0x11ED entry with empty key_exchange (wire rewrite): server alert {:?}, err {:?}", o.alert, o.server_err));
    let o = handshake_wire(client_config(vec![SECP384R1MLKEM1024])?, server_config(vec![SECP384R1MLKEM1024])?, None, Some(empty_sh_share))?;
    t.check("N-s-empty", o.alert == Some(("client", 50)) || o.alert == Some(("client", 47)),
        format!("ServerHello 0x11ED key_share with empty key_exchange (wire rewrite): client alert {:?}, err {:?}", o.alert, o.client_err));

    // Same-length ciphertext corruption: ML-KEM implicit rejection -> different secret -> handshake fails at
    // the server Finished MAC (encrypted alert decrypt_error), never a panic and never a completed handshake.
    let sv = leak(ServerMut(Mutation::XorByte(P384_SHARE_LEN + 10, 0x01)));
    let o = handshake(client_config(vec![SECP384R1MLKEM1024])?, server_config(vec![sv])?)?;
    t.check("N-s-ct-bitflip", !o.ok && o.client_err.is_some(),
        format!("same-length ct bit flip -> implicit rejection; client_err {:?}, encrypted alert from {:?}", o.client_err, o.encrypted_alert_from));

    // ---- F: direct API fuzz (random lengths/bytes), panic = fail
    let mut seed: u64 = 0x11ED_0000_C0FF_EE00;
    let mut rnd = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut panics = 0;
    let mut accepted = 0;
    let n = 3000;
    for k in 0..n {
        let len = match k % 4 {
            0 => (rnd() % 4000) as usize,
            1 => CLIENT_SHARE_LEN,
            2 => SERVER_SHARE_LEN + (rnd() % 3) as usize - 1,
            _ => P384_SHARE_LEN,
        };
        let mut v: Vec<u8> = (0..len).map(|_| rnd() as u8).collect();
        if k % 8 == 1 && !v.is_empty() {
            v[0] = 0x04;
        }
        let r = catch_unwind(AssertUnwindSafe(|| {
            let a = SECP384R1MLKEM1024.start_and_complete(&v).is_ok();
            let b = SECP384R1MLKEM1024.start().map(|x| x.complete(&v).is_ok()).unwrap_or(false);
            a || b
        }));
        match r {
            Err(_) => panics += 1,
            Ok(true) => accepted += 1,
            Ok(false) => {}
        }
    }
    t.check("F1", panics == 0 && accepted == 0,
        format!("{n} random shares into start_and_complete + complete: panics={panics}, accepted={accepted} (random 97-byte prefixes are never valid points)"));

    println!("SELFTEST: {} ({} pass, {} fail)", if t.fail == 0 { "PASS" } else { "FAIL" }, t.pass, t.fail);
    if t.fail == 0 { Ok(()) } else { Err("selftest failed".into()) }
}

fn aws_lc_rs_fips() -> String {
    format!("{:?}", ::aws_lc_rs::try_fips_mode())
}

// ------------------------------------------------------------------------------------------ TCP

/// Mutant: X25519MLKEM768-style order (ML-KEM secret first). Exists to show the interop check can go red.
#[derive(Debug)]
struct SwapOrder;
impl SupportedKxGroup for SwapOrder {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        SECP384R1MLKEM1024.start()
    }
    fn start_and_complete(&self, share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let ckx = SECP384R1MLKEM1024.start_and_complete(share)?;
        let z = ckx.secret.secret_bytes();
        let swapped = [&z[48..], &z[..48]].concat();
        Ok(CompletedKeyExchange { group: ckx.group, pub_key: ckx.pub_key, secret: SharedSecret::from(swapped) })
    }
    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
    fn name(&self) -> NamedGroup {
        NAME
    }
    fn usable_for_version(&self, v: ProtocolVersion) -> bool {
        v == ProtocolVersion::TLSv1_3
    }
}

fn server(port: &str, count: usize) -> Res<()> {
    server_with(port, count, SECP384R1MLKEM1024)
}

fn server_with(port: &str, count: usize, group: &'static dyn SupportedKxGroup) -> Res<()> {
    let cfg = server_config(vec![group])?;
    let l = TcpListener::bind(format!("0.0.0.0:{port}"))?;
    println!("rustls server listening on :{port}, kx_groups=[0x11ED], TLS1.3 only, ECDSA-P384 cert");
    for _ in 0..count {
        let (sock, peer) = l.accept()?;
        let mut conn = ServerConnection::new(cfg.clone())?;
        let mut sock = sock;
        let r: Res<()> = (|| {
            while conn.is_handshaking() {
                conn.complete_io(&mut sock)?;
            }
            println!(
                "[{peer}] handshake OK: group={} suite={:?} version={:?}",
                group_name(conn.negotiated_key_exchange_group()),
                conn.negotiated_cipher_suite().map(|s| s.suite()),
                conn.protocol_version()
            );
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);
            let mut buf = [0u8; 4096];
            let n = tls.read(&mut buf).unwrap_or(0);
            println!("[{peer}] received {n} bytes: {:?}", String::from_utf8_lossy(&buf[..n]).lines().next());
            tls.write_all(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nhello from rustls 0x11ED\n")?;
            tls.conn.send_close_notify();
            tls.flush()?;
            Ok(())
        })();
        if let Err(e) = r {
            println!("[{peer}] connection error: {e}");
        }
    }
    Ok(())
}

fn client(addr: &str) -> Res<()> {
    let cfg = client_config(vec![SECP384R1MLKEM1024])?;
    let mut sock = TcpStream::connect(addr)?;
    let mut conn = ClientConnection::new(cfg, ServerName::try_from("monban.test")?)?;
    while conn.is_handshaking() {
        conn.complete_io(&mut sock)?;
    }
    println!(
        "rustls client handshake OK with {addr}: group={} suite={:?} version={:?}",
        group_name(conn.negotiated_key_exchange_group()),
        conn.negotiated_cipher_suite().map(|s| s.suite()),
        conn.protocol_version()
    );
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(b"GET / HTTP/1.0\r\nHost: monban.test\r\n\r\n")?;
    let mut resp = Vec::new();
    let _ = tls.read_to_end(&mut resp);
    let s = String::from_utf8_lossy(&resp);
    for l in s.lines().take(6) {
        println!("  < {l}");
    }
    for l in s.lines().skip(6).filter(|l| l.contains("roup") || l.contains("Cipher") || l.contains("Protocol")) {
        println!("  < {l}");
    }
    println!("  ({} bytes of application data received)", resp.len());
    if resp.is_empty() { Err("no application data".into()) } else { Ok(()) }
}
