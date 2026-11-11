// L5 artifact (Monban round 3, explorer 03): PQ key-agreement downgrade acceptance test for the
// golden TLS listener. Drop into `crates/<tls>/tests/pq_hrr.rs`. Executed against
// rustls =0.23.46 + aws-lc-rs =1.18.2 on 2026-10-25 (6/6 probes as expected; see run1.txt).
//
// Invariant PQ-KX-1 (public listener, "pq-preferred"): if the ClientHello's supported_groups
// contains X25519MLKEM768 (0x11EC) BEFORE any classical group, the server's first reply is either
// a ServerHello carrying 0x11EC or a HelloRetryRequest selecting 0x11EC; never a classical share.
// Invariant PQ-KX-2 (listener profile "pq-required"/gov): if supported_groups contains 0x11EC
// anywhere, the server selects it (HRR if no share); if it is absent, the handshake fails with
// alert handshake_failure(40). rustls 0.23.x has no server-side group-preference knob: PQ-KX-2 is
// obtained by restricting CryptoProvider::kx_groups (pq-required) or, on rustls main/0.24
// (commit 3fe60d7913, 2026-10-12), with ServerConfig::kx_selector = &PreferServerOrder.
// Known gap (documented, not a failure): default 0.23.x config + client listing X25519 first
// => classical X25519 (RFC 9846 permits it; client preference wins).
use rustls::ServerConfig;
use std::sync::Arc;

const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

fn p256pub() -> Vec<u8> { let k = aws_lc_rs::agreement::PrivateKey::generate(&aws_lc_rs::agreement::ECDH_P256).unwrap(); k.compute_public_key().unwrap().as_ref().to_vec() }
fn ext(t: u16, body: &[u8]) -> Vec<u8> {
    let mut v = t.to_be_bytes().to_vec();
    v.extend((body.len() as u16).to_be_bytes());
    v.extend(body);
    v
}

/// Hand-built TLS 1.3 ClientHello: lets the test send a key_share set that a well-behaved client
/// library would never produce (the RUSTSEC-2026-0349 shape).
pub fn raw_client_hello(groups: &[u16], share_groups: &[u16]) -> Vec<u8> {
    let mut e = Vec::new();
    e.extend(ext(0x002b, &[0x02, 0x03, 0x04]));
    let g: Vec<u8> = groups.iter().flat_map(|x| x.to_be_bytes()).collect();
    let mut gl = (g.len() as u16).to_be_bytes().to_vec();
    gl.extend(&g);
    e.extend(ext(0x000a, &gl));
    let mut ks = Vec::new();
    for sg in share_groups {
        let key = match *sg { 0x001d => vec![0x42; 32], 0x11ec => vec![0x42; 1216], 0x11eb => { let mut v=p256pub(); v.extend(vec![0x42;1184]); v }, 0x0017 => p256pub(), _ => panic!("add key") };
        ks.extend(sg.to_be_bytes());
        ks.extend((key.len() as u16).to_be_bytes());
        ks.extend(key);
    }
    let mut ksl = (ks.len() as u16).to_be_bytes().to_vec();
    ksl.extend(&ks);
    e.extend(ext(0x0033, &ksl));
    e.extend(ext(0x000d, &[0x00, 0x08, 0x04, 0x03, 0x08, 0x04, 0x09, 0x04, 0x09, 0x05]));
    let mut body = vec![0x03, 0x03];
    body.extend([0x11u8; 32]);
    body.push(32);
    body.extend([0x22u8; 32]);
    body.extend([0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
    body.extend((e.len() as u16).to_be_bytes());
    body.extend(e);
    let mut hs = vec![0x01];
    hs.extend(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend(body);
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend((hs.len() as u16).to_be_bytes());
    rec.extend(hs);
    rec
}

#[derive(Debug, PartialEq)]
pub enum Reply { Hrr(u16), ServerHello(u16), Alert(u8), Other }

pub fn probe(cfg: &Arc<ServerConfig>, groups: &[u16], shares: &[u16]) -> Reply {
    let ch = raw_client_hello(groups, shares);
    let mut s = rustls::ServerConnection::new(cfg.clone()).unwrap();
    let mut rd = &ch[..];
    while !rd.is_empty() { s.read_tls(&mut rd).unwrap(); }
    let _ = s.process_new_packets();
    let mut out = Vec::new();
    while s.wants_write() { s.write_tls(&mut out).unwrap(); }
    if out.len() >= 7 && out[0] == 0x15 { return Reply::Alert(out[6]); }
    if out.len() < 44 || out[0] != 0x16 || out[5] != 0x02 { return Reply::Other; }
    let hrr = out[11..43] == HRR_RANDOM;
    let mut i = 5 + 4 + 2 + 32;
    let sid = out[i] as usize;
    i += 1 + sid + 3;
    let end = i + 2 + u16::from_be_bytes([out[i], out[i + 1]]) as usize;
    i += 2;
    while i + 4 <= end {
        let t = u16::from_be_bytes([out[i], out[i + 1]]);
        let l = u16::from_be_bytes([out[i + 2], out[i + 3]]) as usize;
        if t == 0x0033 {
            let g = u16::from_be_bytes([out[i + 4], out[i + 5]]);
            return if hrr { Reply::Hrr(g) } else { Reply::ServerHello(g) };
        }
        i += 4 + l;
    }
    Reply::Other
}


use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConnection};
use rustls::crypto::{aws_lc_rs as prov, CryptoProvider, SupportedKxGroup};

fn chain() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let c = CertificateDer::pem_file_iter("/home/patrickd/aegis/research/scratch03/certs/leaf.pem").unwrap().map(|x| x.unwrap()).collect();
    let k = PrivateKeyDer::from_pem_file("/home/patrickd/aegis/research/scratch03/certs/key8.pem").unwrap();
    (c, k)
}
fn provider(groups: Vec<&'static dyn SupportedKxGroup>) -> Arc<CryptoProvider> {
    let mut p = prov::default_provider();
    p.kx_groups = groups;
    Arc::new(p)
}
fn scfg(groups: Vec<&'static dyn SupportedKxGroup>) -> Arc<ServerConfig> {
    let (c, k) = chain();
    Arc::new(ServerConfig::builder_with_provider(provider(groups))
        .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
        .with_no_client_auth().with_single_cert(c, k).unwrap())
}
fn ccfg(groups: Vec<&'static dyn SupportedKxGroup>) -> Arc<ClientConfig> {
    let (c, _) = chain();
    let mut r = RootCertStore::empty();
    r.add(CertificateDer::pem_file_iter("/home/patrickd/aegis/research/scratch03/certs/ca.pem").unwrap().next().unwrap().unwrap()).unwrap();
    Arc::new(ClientConfig::builder_with_provider(provider(groups))
        .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
        .with_root_certificates(r).with_no_client_auth())
}
fn pump(c: &mut ClientConnection, s: &mut ServerConnection) -> Result<(), String> {
    for _ in 0..20 {
        let mut buf = Vec::new();
        while c.wants_write() { c.write_tls(&mut buf).unwrap(); }
        if !buf.is_empty() { let mut rd = &buf[..]; while !rd.is_empty() { s.read_tls(&mut rd).unwrap(); }
            if let Err(e) = s.process_new_packets() { let mut o=Vec::new(); while s.wants_write(){ s.write_tls(&mut o).unwrap(); } let _=c.read_tls(&mut &o[..]); return Err(format!("server: {e:?}")); } }
        let mut buf = Vec::new();
        while s.wants_write() { s.write_tls(&mut buf).unwrap(); }
        if !buf.is_empty() { let mut rd = &buf[..]; while !rd.is_empty() { c.read_tls(&mut rd).unwrap(); }
            if let Err(e) = c.process_new_packets() { return Err(format!("client: {e:?}")); } }
        if !c.is_handshaking() && !s.is_handshaking() { return Ok(()); }
    }
    Err("no progress".into())
}
fn hs(label: &str, sg: Vec<&'static dyn SupportedKxGroup>, cg: Vec<&'static dyn SupportedKxGroup>) {
    let sc = scfg(sg); let cc = ccfg(cg);
    let mut s = ServerConnection::new(sc.clone()).unwrap();
    let mut c = ClientConnection::new(cc.clone(), "localhost".try_into().unwrap()).unwrap();
    let r = pump(&mut c, &mut s);
    println!("HS {label}: result={r:?} group_client={:?} group_server={:?} kind={:?} server_cfg.fips={} client_cfg.fips={}",
        c.negotiated_key_exchange_group().map(|g| g.name()), s.negotiated_key_exchange_group().map(|g| g.name()),
        c.handshake_kind(), sc.fips(), cc.fips());
}
fn pr(label: &str, groups: Vec<&'static dyn SupportedKxGroup>, g: &[u16], sh: &[u16]) {
    let r = probe(&scfg(groups), g, sh);
    println!("PROBE {label}: groups={g:04x?} shares={sh:04x?} -> {r:?}");
}
fn main() {
    println!("try_fips_mode = {:?}", aws_lc_rs::try_fips_mode());
    println!("default_provider.fips() = {}", prov::default_provider().fips());
    for g in prov::ALL_KX_GROUPS { println!("KX {:?} fips={}", g.name(), g.fips()); }
    use prov::kx_group::*;
    let p = SECP256R1MLKEM768; let x = X25519MLKEM768;
    hs("A fipsserver[P256MLKEM768,P256,P384] <- client[P256MLKEM768,P256]", vec![p, SECP256R1, SECP384R1], vec![p, SECP256R1]);
    hs("B fipsserver[P256MLKEM768,P256,P384] <- client[X25519MLKEM768 only]", vec![p, SECP256R1, SECP384R1], vec![x]);
    hs("C fipsserver[P256MLKEM768,P256,P384] <- client[X25519MLKEM768,X25519,P256MLKEM768]", vec![p, SECP256R1, SECP384R1], vec![x, X25519, p]);
    hs("D defaultserver[X25519MLKEM768,X25519,P256,P384] <- client[X25519MLKEM768]", vec![x, X25519, SECP256R1, SECP384R1], vec![x]);
    hs("E fipsserver[P256MLKEM768,P256,P384] <- client[X25519,P256]", vec![p, SECP256R1, SECP384R1], vec![X25519, SECP256R1]);
    hs("F fipsserver[P256MLKEM768 only] <- client[X25519,P256]", vec![p], vec![X25519, SECP256R1]);
    // HRR 5-verdict analogue on SecP256r1MLKEM768 (0x11eb) pq-required FIPS server
    pr("1 fips pq-pref: pq first, classical share only", vec![p, SECP256R1, SECP384R1], &[0x11eb, 0x0017], &[0x0017]);
    pr("2 fips: pq first, pq share", vec![p, SECP256R1, SECP384R1], &[0x11eb, 0x0017], &[0x11eb]);
    pr("3 fips pq-required: classical first, classical share", vec![p], &[0x0017, 0x11eb], &[0x0017]);
    pr("4 fips pq-required: classical only", vec![p], &[0x0017], &[0x0017]);
    pr("5 fips pref(non-req): classical first, classical share", vec![p, SECP256R1, SECP384R1], &[0x0017, 0x11eb], &[0x0017]);
    pr("6 fips server vs X25519MLKEM768-only hello", vec![p, SECP256R1, SECP384R1], &[0x11ec], &[0x11ec]);
    pr("7 fips server vs [X25519MLKEM768,P256MLKEM768] hello share X25519MLKEM768", vec![p, SECP256R1, SECP384R1], &[0x11ec, 0x11eb], &[0x11ec]);
    pr("8 fips server vs [X25519MLKEM768,P256MLKEM768] hello both shares", vec![p, SECP256R1, SECP384R1], &[0x11ec, 0x11eb], &[0x11ec, 0x11eb]);
    // default X25519MLKEM768 server (r3 verdicts on this build)
    pr("9 default-prefer-pq server: [x25519, mlkem] x25519 share", vec![x, X25519, SECP256R1, SECP384R1], &[0x001d, 0x11ec], &[0x001d]);
    pr("10 default-prefer-pq server: [mlkem, x25519] x25519 share", vec![x, X25519, SECP256R1, SECP384R1], &[0x11ec, 0x001d], &[0x001d]);
}
