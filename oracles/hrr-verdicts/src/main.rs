//! hrr-verdicts: executes the frozen TLS verdicts of tls/verdicts.toml (F12) against a TLS server subject and
//! diffs observed against expected. See ../README.md for the contract, the subject interface and provenance.
//!
//!   hrr-verdicts check     --file F [--subject "CMD ARGS..."] [--require-cmvp]
//!   hrr-verdicts self-test --file F
//!   hrr-verdicts subject   [--mutate M] describe|serve PROFILE      (the reference subject over stdio)
#![forbid(unsafe_code)]

mod kx11ed;
mod toml;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{aws_lc_rs as prov, CryptoProvider, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, ServerConfig, ServerConnection, SignatureScheme,
    SupportedProtocolVersion,
};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, Command, ExitCode, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use toml::Value;

const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2,
    0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];
const CLASSICAL: [u16; 3] = [0x001D, 0x0017, 0x0018];
const CMVP_MODULE: &str = "AWS-LC FIPS 3.1.0";

type R<T> = Result<T, String>;

// ------------------------------------------------------------------------------------------------ spec model

#[derive(Clone, Debug, PartialEq)]
enum Outcome {
    Hrr(u16),
    Sh(u16),
    Alert(u8),
    Other(String),
}

#[derive(Clone)]
struct Profile {
    status: String,
    selector: String,
    kx: Vec<u16>,
    sigalgs: Vec<u16>,
    versions: Vec<String>,
    early_data: bool,
    /// F12 `sigalg_cover` (2026-11-04): only "all-or-none"; checked at load time by `validate`.
    sigalg_cover: Option<String>,
}

#[derive(Clone)]
struct ProbeCase {
    groups: Vec<u16>,
    shares: Vec<u16>,
    sigalgs: Vec<u16>,
    /// F12 `offer_versions` (2026-11-04): version names in row order; absent = ["TLS13"].
    versions: Vec<String>,
}

const VERSIONS: [(&str, u16); 2] = [("TLS13", 0x0304), ("TLS12", 0x0303)];

fn tls13() -> Vec<String> {
    vec!["TLS13".to_string()]
}

#[derive(Clone)]
struct Verdict {
    id: String,
    profile: String,
    probe: ProbeCase,
    expect: Outcome,
    requires: String,
}

#[derive(Clone)]
enum SupMode {
    Probe(ProbeCase, Outcome),
    Full { client_groups: Vec<u16>, expect_group: u16, expect_kind: String },
}

#[derive(Clone)]
struct Sup {
    id: String,
    profile: String,
    mode: SupMode,
}

#[derive(Clone)]
struct Spec {
    groups: BTreeMap<String, u16>,
    sigalgs: BTreeMap<String, u16>,
    sni: String,
    suites: Vec<u16>,
    profiles: BTreeMap<String, Profile>,
    verdicts: Vec<Verdict>,
    sups: Vec<Sup>,
}

impl Spec {
    fn gname(&self, c: u16) -> String {
        self.groups.iter().find(|(_, v)| **v == c).map(|(k, _)| k.clone()).unwrap_or(format!("0x{c:04X}"))
    }
    fn sname(&self, c: u16) -> String {
        self.sigalgs.iter().find(|(_, v)| **v == c).map(|(k, _)| k.clone()).unwrap_or(format!("0x{c:04X}"))
    }
    fn show(&self, o: &Outcome) -> String {
        match o {
            Outcome::Hrr(g) => format!("hrr:{}", self.gname(*g)),
            Outcome::Sh(g) => format!("server_hello:{}", self.gname(*g)),
            Outcome::Alert(a) => format!("alert:{a}"),
            Outcome::Other(s) => format!("other:{s}"),
        }
    }
}

fn s(v: &Value, k: &str, ctx: &str) -> R<String> {
    v.get(k).and_then(Value::str).map(String::from).ok_or(format!("{ctx}: missing string '{k}'"))
}

fn codes(map: &BTreeMap<String, u16>, v: &Value, k: &str, ctx: &str) -> R<Vec<u16>> {
    let a = v.get(k).and_then(Value::arr).ok_or(format!("{ctx}: missing array '{k}'"))?;
    a.iter()
        .map(|x| {
            let n = x.str().ok_or(format!("{ctx}.{k}: non-string entry"))?;
            map.get(n).copied().ok_or(format!("{ctx}.{k}: unknown name '{n}'"))
        })
        .collect()
}

fn expect_of(spec_groups: &BTreeMap<String, u16>, v: &Value, ctx: &str) -> R<Outcome> {
    let g = || -> R<u16> {
        let n = s(v, "expect_group", ctx)?;
        spec_groups.get(&n).copied().ok_or(format!("{ctx}: unknown expect_group {n}"))
    };
    match s(v, "expect", ctx)?.as_str() {
        "hrr" => Ok(Outcome::Hrr(g()?)),
        "server_hello" => Ok(Outcome::Sh(g()?)),
        "alert" => {
            let a = v.get("expect_alert").and_then(Value::int).ok_or(format!("{ctx}: missing expect_alert"))?;
            Ok(Outcome::Alert(u8::try_from(a).map_err(|_| format!("{ctx}: bad alert"))?))
        }
        e => Err(format!("{ctx}: unknown expect '{e}'")),
    }
}

fn load(path: &str) -> R<Spec> {
    let src = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let doc = toml::parse(&src)?;
    if doc.get("schema").and_then(Value::str) != Some("aegis.tls.verdicts/1") {
        return Err("schema != aegis.tls.verdicts/1".into());
    }
    let cmap = |k: &str| -> R<BTreeMap<String, u16>> {
        let t = doc.get("codepoints").and_then(|c| c.get(k)).and_then(Value::table).ok_or(format!("codepoints.{k} missing"))?;
        t.iter()
            .map(|(n, v)| Ok((n.clone(), v.int().and_then(|i| u16::try_from(i).ok()).ok_or(format!("codepoints.{k}.{n}"))?)))
            .collect()
    };
    let groups = cmap("groups")?;
    let sigalgs = cmap("sigalgs")?;
    let ch = doc.get("client_hello").ok_or("client_hello missing")?;
    let sni = s(ch, "sni", "client_hello")?;
    let suites = ch
        .get("cipher_suites")
        .and_then(Value::arr)
        .ok_or("client_hello.cipher_suites")?
        .iter()
        .map(|x| x.int().and_then(|i| u16::try_from(i).ok()).ok_or("cipher_suites entry".to_string()))
        .collect::<R<Vec<u16>>>()?;
    let mut profiles = BTreeMap::new();
    for (name, p) in doc.get("profiles").and_then(Value::table).ok_or("profiles missing")? {
        let ctx = format!("profiles.{name}");
        profiles.insert(
            name.clone(),
            Profile {
                status: s(p, "status", &ctx)?,
                selector: s(p, "selector", &ctx)?,
                kx: codes(&groups, p, "kx_groups", &ctx)?,
                sigalgs: codes(&sigalgs, p, "sigalgs", &ctx)?,
                versions: p
                    .get("versions")
                    .and_then(Value::arr)
                    .ok_or(format!("{ctx}.versions"))?
                    .iter()
                    .filter_map(|x| x.str().map(String::from))
                    .collect(),
                early_data: p.get("early_data").and_then(Value::bool).ok_or(format!("{ctx}.early_data"))?,
                sigalg_cover: match p.get("sigalg_cover") {
                    None => None,
                    Some(v) => Some(v.str().map(String::from).ok_or(format!("{ctx}.sigalg_cover: not a string"))?),
                },
            },
        );
    }
    let probe_of = |v: &Value, ctx: &str| -> R<ProbeCase> {
        Ok(ProbeCase {
            groups: codes(&groups, v, "offer_groups", ctx)?,
            shares: codes(&groups, v, "offer_key_shares", ctx)?,
            sigalgs: codes(&sigalgs, v, "offer_sigalgs", ctx)?,
            versions: match v.get("offer_versions") {
                None => tls13(),
                Some(a) => a
                    .arr()
                    .ok_or(format!("{ctx}.offer_versions: not an array"))?
                    .iter()
                    .map(|x| x.str().map(String::from).ok_or(format!("{ctx}.offer_versions: non-string entry")))
                    .collect::<R<Vec<String>>>()?,
            },
        })
    };
    let mut verdicts = Vec::new();
    for v in doc.get("verdict").and_then(Value::arr).ok_or("no [[verdict]]")? {
        let id = s(v, "id", "verdict")?;
        let profile = s(v, "profile", &id)?;
        if !profiles.contains_key(&profile) {
            return Err(format!("{id}: unknown profile {profile}"));
        }
        verdicts.push(Verdict {
            probe: probe_of(v, &id)?,
            expect: expect_of(&groups, v, &id)?,
            requires: s(v, "requires", &id)?,
            id,
            profile,
        });
    }
    let mut sups = Vec::new();
    for v in doc.get("supplementary").and_then(Value::arr).unwrap_or(&[]) {
        let id = s(v, "id", "supplementary")?;
        let profile = s(v, "profile", &id)?;
        let mode = match s(v, "mode", &id)?.as_str() {
            "probe" => SupMode::Probe(probe_of(v, &id)?, expect_of(&groups, v, &id)?),
            "full" => SupMode::Full {
                client_groups: codes(&groups, v, "client_groups", &id)?,
                expect_group: *groups.get(&s(v, "expect_group", &id)?).ok_or(format!("{id}: expect_group"))?,
                expect_kind: s(v, "expect_kind", &id)?,
            },
            m => return Err(format!("{id}: unknown mode {m}")),
        };
        sups.push(Sup { id, profile, mode });
    }
    let spec = Spec { groups, sigalgs, sni, suites, profiles, verdicts, sups };
    validate(&spec)?;
    Ok(spec)
}

/// Load-time rules of the F12 row vocabulary (header "Row vocabulary added 2026-11-04"): offer_versions values,
/// no TLS 1.2 negotiation, sigalg_cover = all-or-none.
fn validate(spec: &Spec) -> R<()> {
    for (name, p) in &spec.profiles {
        match p.sigalg_cover.as_deref() {
            None | Some("all-or-none") => {}
            Some(o) => return Err(format!("profiles.{name}.sigalg_cover: unknown value '{o}'")),
        }
        for v in &p.versions {
            if !VERSIONS.iter().any(|(n, _)| n == v) {
                return Err(format!("profiles.{name}.versions: unknown version '{v}'"));
            }
        }
    }
    let rows = spec.verdicts.iter().map(|v| (&v.id, &v.profile, &v.probe)).chain(spec.sups.iter().filter_map(|s| match &s.mode {
        SupMode::Probe(c, _) => Some((&s.id, &s.profile, c)),
        SupMode::Full { .. } => None,
    }));
    for (id, prof, c) in rows {
        let p = spec.profiles.get(prof).ok_or(format!("{id}: unknown profile {prof}"))?;
        if c.versions.is_empty() {
            return Err(format!("{id}: offer_versions is empty"));
        }
        for (i, v) in c.versions.iter().enumerate() {
            if !VERSIONS.iter().any(|(n, _)| n == v) {
                return Err(format!("{id}: offer_versions: unknown version '{v}'"));
            }
            if c.versions.iter().skip(i + 1).any(|w| w == v) {
                return Err(format!("{id}: offer_versions: duplicate '{v}'"));
            }
        }
        if !c.versions.iter().any(|v| v == "TLS13") && p.versions.iter().any(|v| v == "TLS12") {
            return Err(format!("{id}: offer_versions without TLS13 against {prof} (versions contain TLS12): the model does not cover TLS 1.2 negotiation"));
        }
        if p.sigalg_cover.as_deref() == Some("all-or-none") {
            let n = p.sigalgs.iter().filter(|s| c.sigalgs.contains(s)).count();
            if n != 0 && n != p.sigalgs.len() {
                return Err(format!("{id}: sigalg_cover all-or-none violated on {prof}: offer_sigalgs covers {n} of {} profile sigalgs", p.sigalgs.len()));
            }
        }
    }
    Ok(())
}

/// Select(model), spec section F + F12 header (2026-11-04), in order: 1. version admission (offer_versions and
/// profile versions disjoint -> alert 70); 2. sigalg admission (offer_sigalgs and profile sigalgs disjoint -> alert
/// 49); 3. group selection: client-order picks the first client-listed group the server supports; server-order the
/// first server-listed group the client lists; none -> alert 40; HRR iff no share for the selected group.
fn model(p: &Profile, c: &ProbeCase) -> Outcome {
    if !c.versions.iter().any(|v| p.versions.contains(v)) {
        return Outcome::Alert(70);
    }
    if !c.sigalgs.iter().any(|s| p.sigalgs.contains(s)) {
        return Outcome::Alert(49);
    }
    let sel = if p.selector == "server-order" {
        p.kx.iter().copied().find(|g| c.groups.contains(g))
    } else {
        c.groups.iter().copied().find(|g| p.kx.contains(g))
    };
    match sel {
        None => Outcome::Alert(40),
        Some(g) if c.shares.contains(&g) => Outcome::Sh(g),
        Some(g) => Outcome::Hrr(g),
    }
}

// ------------------------------------------------------------------------------------------------ wire

fn ext(t: u16, body: &[u8]) -> Vec<u8> {
    let mut v = t.to_be_bytes().to_vec();
    v.extend((body.len() as u16).to_be_bytes());
    v.extend(body);
    v
}

fn ecdh_pub(alg: &'static aws_lc_rs::agreement::Algorithm) -> R<Vec<u8>> {
    let k = aws_lc_rs::agreement::PrivateKey::generate(alg).map_err(|_| "keygen")?;
    Ok(k.compute_public_key().map_err(|_| "pubkey")?.as_ref().to_vec())
}

fn mlkem_ek(alg: &'static aws_lc_rs::kem::Algorithm<aws_lc_rs::kem::AlgorithmId>) -> R<Vec<u8>> {
    let dk = aws_lc_rs::kem::DecapsulationKey::generate(alg).map_err(|_| "mlkem keygen")?;
    let ek = dk.encapsulation_key().map_err(|_| "mlkem ek")?;
    Ok(ek.key_bytes().map_err(|_| "mlkem ek bytes")?.as_ref().to_vec())
}

/// Real (freshly generated) public values for every share, so a ServerHello verdict exercises a real
/// encapsulation/ECDH on the server. Hybrid layouts per draft-ietf-tls-ecdhe-mlkem.
fn share(g: u16) -> R<Vec<u8>> {
    use aws_lc_rs::agreement::{ECDH_P256, ECDH_P384, X25519};
    use aws_lc_rs::kem::{ML_KEM_1024, ML_KEM_768};
    Ok(match g {
        0x001D => ecdh_pub(&X25519)?,
        0x0017 => ecdh_pub(&ECDH_P256)?,
        0x0018 => ecdh_pub(&ECDH_P384)?,
        0x0201 => mlkem_ek(&ML_KEM_768)?,
        0x0202 => mlkem_ek(&ML_KEM_1024)?,
        0x11EC => [mlkem_ek(&ML_KEM_768)?, ecdh_pub(&X25519)?].concat(),
        0x11EB => [ecdh_pub(&ECDH_P256)?, mlkem_ek(&ML_KEM_768)?].concat(),
        0x11ED => [ecdh_pub(&ECDH_P384)?, mlkem_ek(&ML_KEM_1024)?].concat(),
        _ => return Err(format!("no share generator for group 0x{g:04X}")),
    })
}

/// Hand-built TLS 1.3 ClientHello (same shape as the research probes): allows key_share sets that a
/// well-behaved client library never produces (the RUSTSEC-2026-0349 shape).
fn client_hello(spec: &Spec, c: &ProbeCase) -> R<Vec<u8>> {
    let mut e = Vec::new();
    let sv = c
        .versions
        .iter()
        .map(|v| VERSIONS.iter().find(|(n, _)| n == v).map(|(_, x)| *x).ok_or(format!("unknown version {v}")))
        .collect::<R<Vec<u16>>>()?;
    let sv: Vec<u8> = sv.iter().flat_map(|x| x.to_be_bytes()).collect();
    e.extend(ext(0x002b, &[vec![sv.len() as u8], sv].concat()));
    let g: Vec<u8> = c.groups.iter().flat_map(|x| x.to_be_bytes()).collect();
    e.extend(ext(0x000a, &[(g.len() as u16).to_be_bytes().to_vec(), g].concat()));
    let mut ks = Vec::new();
    for sg in &c.shares {
        let key = share(*sg)?;
        ks.extend(sg.to_be_bytes());
        ks.extend((key.len() as u16).to_be_bytes());
        ks.extend(key);
    }
    e.extend(ext(0x0033, &[(ks.len() as u16).to_be_bytes().to_vec(), ks].concat()));
    let sa: Vec<u8> = c.sigalgs.iter().flat_map(|x| x.to_be_bytes()).collect();
    e.extend(ext(0x000d, &[(sa.len() as u16).to_be_bytes().to_vec(), sa].concat()));
    let h = spec.sni.as_bytes();
    let mut sni = ((h.len() + 3) as u16).to_be_bytes().to_vec();
    sni.push(0);
    sni.extend((h.len() as u16).to_be_bytes());
    sni.extend(h);
    e.extend(ext(0x0000, &sni));
    let mut body = vec![0x03, 0x03];
    body.extend([0x11u8; 32]);
    body.push(32);
    body.extend([0x22u8; 32]);
    let su: Vec<u8> = spec.suites.iter().flat_map(|x| x.to_be_bytes()).collect();
    body.extend((su.len() as u16).to_be_bytes());
    body.extend(su);
    body.extend([0x01, 0x00]);
    body.extend((e.len() as u16).to_be_bytes());
    body.extend(e);
    let mut hs = vec![0x01];
    hs.extend(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend(body);
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend((hs.len() as u16).to_be_bytes());
    rec.extend(hs);
    Ok(rec)
}

/// Classifies the server's first flight. Bounds-checked: subject output is untrusted.
fn classify(out: &[u8]) -> Outcome {
    let b = |i: usize| out.get(i).copied();
    let u16at = |i: usize| Some(u16::from_be_bytes([b(i)?, b(i + 1)?]));
    if b(0) == Some(0x15) {
        return b(6).map(Outcome::Alert).unwrap_or(Outcome::Other("short alert".into()));
    }
    if b(0) != Some(0x16) || b(5) != Some(0x02) {
        return Outcome::Other(format!("first record {:02x?}", out.get(..6.min(out.len()))));
    }
    let Some(random) = out.get(11..43) else { return Outcome::Other("short server hello".into()) };
    let hrr = random == HRR_RANDOM;
    let f = || -> Option<u16> {
        let mut i = 43;
        let sid = b(i)? as usize;
        i += 1 + sid + 3;
        let end = i + 2 + u16at(i)? as usize;
        i += 2;
        while i + 4 <= end {
            let t = u16at(i)?;
            let l = u16at(i + 2)? as usize;
            if t == 0x0033 {
                return u16at(i + 4);
            }
            i += 4 + l;
        }
        None
    };
    match f() {
        Some(g) if hrr => Outcome::Hrr(g),
        Some(g) => Outcome::Sh(g),
        None => Outcome::Other("no key_share in server hello".into()),
    }
}

// ------------------------------------------------------------------------------------------------ subjects

struct Desc {
    kx: Vec<u16>,
    versions: Vec<String>,
    early_data: bool,
    fips: Option<bool>,
    module: Option<String>,
}

trait Conn {
    /// Delivers client bytes, returns everything the server wrote in response.
    fn send(&mut self, data: &[u8]) -> R<Vec<u8>>;
}

trait Subject {
    fn describe(&self, profile: &str) -> R<Desc>;
    fn connect(&self, profile: &str) -> R<Box<dyn Conn>>;
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Mutation {
    None,
    PqRequiredX25519First,
    PreferPqOff,
    SigalgNotInProfile,
    PqRequiredClassicalFallback,
    PublicNoHybrid,
    FipsX25519MlkemAdded,
    Tls12And0rttOnPqRequired,
    // 2026-11-04 (P6-oracle-hrr-001)
    UniversalAcceptsX25519,
    UniversalPicks11EB,
    CnsaAccepts11ED,
    CnsaEcdsaUnfiltered,
    CnsaTls12,
    PublicNo11ED,
    // describe-only: what the subject reports as module identity (checked with --require-cmvp)
    ReportsFipsNoModule,
    ReportsModule420,
    ReportsCmvp310,
}

/// Subject mutants: each must give at least one diff in a normal run.
const MUTATIONS: [(Mutation, &str); 13] = [
    (Mutation::PqRequiredX25519First, "pq-required-x25519-first"),
    (Mutation::PreferPqOff, "prefer-post-quantum-off"),
    (Mutation::SigalgNotInProfile, "sigalg-not-in-profile"),
    (Mutation::PqRequiredClassicalFallback, "pq-required-classical-fallback"),
    (Mutation::PublicNoHybrid, "public-no-hybrid"),
    (Mutation::FipsX25519MlkemAdded, "fips-x25519mlkem768-added"),
    (Mutation::Tls12And0rttOnPqRequired, "tls12-and-0rtt-on-pq-required"),
    (Mutation::UniversalAcceptsX25519, "universal-accepts-x25519"),
    (Mutation::UniversalPicks11EB, "universal-picks-11eb"),
    (Mutation::CnsaAccepts11ED, "cnsa-accepts-11ed"),
    (Mutation::CnsaEcdsaUnfiltered, "cnsa-ecdsa-p384-unfiltered"),
    (Mutation::CnsaTls12, "cnsa-tls12-enabled"),
    (Mutation::PublicNo11ED, "public-no-11ed"),
];

/// Module-identity mutants: the first two must give diffs under --require-cmvp; the last is the positive control
/// (a subject reporting fips=true + AWS-LC FIPS 3.1.0 must pass --require-cmvp with diff 0).
const CMVP_MUTATIONS: [(Mutation, &str); 3] = [
    (Mutation::ReportsFipsNoModule, "reports-fips-module-none"),
    (Mutation::ReportsModule420, "reports-module-4.2.0"),
    (Mutation::ReportsCmvp310, "reports-cmvp-3.1.0"),
];

#[derive(Clone)]
struct Cred(Arc<CertifiedKey>);

fn cred(alg: &'static rcgen::SignatureAlgorithm) -> R<Cred> {
    let kp = rcgen::KeyPair::generate_for(alg).map_err(|e| format!("rcgen keygen: {e}"))?;
    let params = rcgen::CertificateParams::new(vec!["aegis.test".to_string()]).map_err(|e| e.to_string())?;
    let cert = params.self_signed(&kp).map_err(|e| format!("rcgen self_signed: {e}"))?;
    let ck = CertifiedKey::from_der(
        vec![CertificateDer::from(cert.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(kp.serialize_der())),
        &prov::default_provider(),
    )
    .map_err(|e| format!("credential: {e}"))?;
    Ok(Cred(Arc::new(ck)))
}

/// Profile-filtered certificate resolution (the rule F12 "Admission order" relies on): returns the first credential
/// whose key can sign one of the offered schemes that the profile allows, else None (rustls then sends
/// access_denied 49 before group selection). `allowed = None` is the unfiltered (mutant) resolver.
#[derive(Debug)]
struct ProfileResolver {
    keys: Vec<Arc<CertifiedKey>>,
    allowed: Option<Vec<u16>>,
}

impl ResolvesServerCert for ProfileResolver {
    fn resolve(&self, ch: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        match &self.allowed {
            None => self.keys.first().cloned(),
            Some(a) => {
                let offered: Vec<SignatureScheme> =
                    ch.signature_schemes().iter().copied().filter(|s| a.contains(&u16::from(*s))).collect();
                self.keys.iter().find(|k| k.key.choose_scheme(&offered).is_some()).cloned()
            }
        }
    }
}

struct Plan<'a> {
    kx: Vec<&'static dyn SupportedKxGroup>,
    creds: Vec<&'a Cred>,
    allowed: Option<Vec<u16>>,
    tls12: bool,
    early: bool,
}

/// The reference profile builder: ARCHITECTURE.md 3.2 lists written in code, independently of the verdict file,
/// so the static profile check is a real comparison. Replaced by the aegis-tls builder via --subject.
#[derive(Clone)]
struct Reference {
    m: Mutation,
    ecdsa: Cred,
    ecdsa384: Cred,
    mldsa44: Cred,
    mldsa65: Cred,
    mldsa87: Cred,
}

const ECDSA_P256: u16 = 0x0403;
const ECDSA_P384: u16 = 0x0503;
const MLDSA44: u16 = 0x0904;
const MLDSA87: u16 = 0x0906;

impl Reference {
    fn new(m: Mutation) -> R<Self> {
        Ok(Reference {
            m,
            ecdsa: cred(&rcgen::PKCS_ECDSA_P256_SHA256)?,
            ecdsa384: cred(&rcgen::PKCS_ECDSA_P384_SHA384)?,
            mldsa44: cred(&rcgen::PKCS_ML_DSA_44)?,
            mldsa65: cred(&rcgen::PKCS_ML_DSA_65)?,
            mldsa87: cred(&rcgen::PKCS_ML_DSA_87)?,
        })
    }
    fn with(&self, m: Mutation) -> Self {
        Reference { m, ..self.clone() }
    }
    fn plan(&self, profile: &str) -> R<Plan<'_>> {
        use kx11ed::SECP384R1MLKEM1024 as P384MLKEM1024;
        use prov::kx_group::*;
        let m = self.m;
        let plain = |kx, creds, allowed: &[u16]| Plan { kx, creds, allowed: Some(allowed.to_vec()), tls12: false, early: false };
        Ok(match profile {
            "P-PUBLIC-WEB" => {
                let kx: Vec<&'static dyn SupportedKxGroup> = match m {
                    // what default_provider() yields when the prefer-post-quantum feature is off (rustls 0.23.46
                    // DEFAULT_KX_GROUPS without the feature): hybrid demoted to last
                    Mutation::PreferPqOff => vec![X25519, SECP256R1, SECP384R1, X25519MLKEM768],
                    Mutation::PublicNoHybrid => vec![X25519, SECP256R1],
                    // the Phase-5 list (before 0x11ED moved from kx_groups_target to kx_groups)
                    Mutation::PublicNo11ED => vec![X25519MLKEM768, SECP256R1MLKEM768, X25519, SECP256R1],
                    _ => vec![X25519MLKEM768, P384MLKEM1024, SECP256R1MLKEM768, X25519, SECP256R1],
                };
                plain(kx, vec![&self.ecdsa], &[ECDSA_P256])
            }
            "PQ-REQUIRED" => {
                let kx: Vec<&'static dyn SupportedKxGroup> = match m {
                    Mutation::PqRequiredX25519First => vec![X25519, X25519MLKEM768],
                    Mutation::PqRequiredClassicalFallback => vec![X25519MLKEM768, X25519],
                    _ => vec![X25519MLKEM768],
                };
                let t = m == Mutation::Tls12And0rttOnPqRequired;
                if m == Mutation::SigalgNotInProfile {
                    Plan { kx, creds: vec![&self.mldsa65], allowed: None, tls12: t, early: t }
                } else {
                    Plan { kx, creds: vec![&self.mldsa44], allowed: Some(vec![ECDSA_P256, MLDSA44]), tls12: t, early: t }
                }
            }
            "FIPS" => {
                let kx: Vec<&'static dyn SupportedKxGroup> = match m {
                    Mutation::FipsX25519MlkemAdded => vec![X25519MLKEM768, SECP256R1MLKEM768, SECP256R1, SECP384R1],
                    _ => vec![SECP256R1MLKEM768, SECP256R1, SECP384R1],
                };
                plain(kx, vec![&self.ecdsa], &[ECDSA_P256, ECDSA_P384])
            }
            "FIPS-PQ-REQUIRED" => plain(vec![SECP256R1MLKEM768], vec![&self.ecdsa], &[ECDSA_P256, ECDSA_P384]),
            // government profiles: both in-profile credentials loaded (ML-DSA-87 preferred on P-UNIVERSAL,
            // ECDSA-P384 on P-BSI-ALT, so the P-PQ2 handshakes exercise both)
            "P-UNIVERSAL" => {
                let kx: Vec<&'static dyn SupportedKxGroup> = match m {
                    Mutation::UniversalAcceptsX25519 => vec![P384MLKEM1024, X25519],
                    Mutation::UniversalPicks11EB => vec![P384MLKEM1024, SECP256R1MLKEM768],
                    _ => vec![P384MLKEM1024],
                };
                plain(kx, vec![&self.mldsa87, &self.ecdsa384], &[MLDSA87, ECDSA_P384])
            }
            "P-BSI-ALT" => {
                plain(vec![P384MLKEM1024, SECP256R1MLKEM768], vec![&self.ecdsa384, &self.mldsa87], &[MLDSA87, ECDSA_P384])
            }
            "P-CNSA" => {
                let kx: Vec<&'static dyn SupportedKxGroup> = match m {
                    Mutation::CnsaAccepts11ED => vec![MLKEM1024, P384MLKEM1024],
                    _ => vec![MLKEM1024],
                };
                match m {
                    Mutation::CnsaEcdsaUnfiltered => Plan { kx, creds: vec![&self.ecdsa384], allowed: None, tls12: false, early: false },
                    Mutation::CnsaTls12 => Plan { kx, creds: vec![&self.mldsa87], allowed: Some(vec![MLDSA87]), tls12: true, early: false },
                    _ => plain(kx, vec![&self.mldsa87], &[MLDSA87]),
                }
            }
            p => return Err(format!("reference subject does not build profile {p}")),
        })
    }
    fn config(&self, profile: &str) -> R<(Arc<ServerConfig>, Vec<String>)> {
        let pl = self.plan(profile)?;
        let mut p = prov::default_provider();
        p.kx_groups = pl.kx;
        let mut vers: Vec<&'static SupportedProtocolVersion> = vec![&rustls::version::TLS13];
        let mut names = tls13();
        if pl.tls12 {
            vers.push(&rustls::version::TLS12);
            names.push("TLS12".into());
        }
        let resolver = ProfileResolver { keys: pl.creds.iter().map(|c| c.0.clone()).collect(), allowed: pl.allowed };
        let mut cfg = ServerConfig::builder_with_provider(Arc::new(p))
            .with_protocol_versions(&vers)
            .map_err(|e| format!("{profile}: {e}"))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        cfg.max_early_data_size = if pl.early { 16384 } else { 0 };
        Ok((Arc::new(cfg), names))
    }
}

struct RefConn(ServerConnection);

impl Conn for RefConn {
    fn send(&mut self, data: &[u8]) -> R<Vec<u8>> {
        let mut rd = data;
        while !rd.is_empty() {
            if self.0.read_tls(&mut rd).map_err(|e| e.to_string())? == 0 {
                break;
            }
            // errors queue an alert, which is what we want to observe
            if self.0.process_new_packets().is_err() {
                break;
            }
        }
        let mut out = Vec::new();
        while self.0.wants_write() {
            self.0.write_tls(&mut out).map_err(|e| e.to_string())?;
        }
        Ok(out)
    }
}

impl Subject for Reference {
    fn describe(&self, profile: &str) -> R<Desc> {
        let (cfg, versions) = self.config(profile)?;
        let (fips, module) = match self.m {
            Mutation::ReportsFipsNoModule => (true, None),
            Mutation::ReportsModule420 => (true, Some("AWS-LC FIPS 4.2.0".to_string())),
            Mutation::ReportsCmvp310 => (true, Some(CMVP_MODULE.to_string())),
            _ => (cfg.fips(), None),
        };
        Ok(Desc {
            kx: cfg.crypto_provider().kx_groups.iter().map(|g| u16::from(g.name())).collect(),
            versions,
            early_data: cfg.max_early_data_size > 0,
            fips: Some(fips),
            module,
        })
    }
    fn connect(&self, profile: &str) -> R<Box<dyn Conn>> {
        let (cfg, _) = self.config(profile)?;
        Ok(Box::new(RefConn(ServerConnection::new(cfg).map_err(|e| e.to_string())?)))
    }
}

/// --subject "CMD ARGS...": `CMD ARGS describe PROFILE` prints key=value lines; `CMD ARGS serve PROFILE` speaks
/// TLS (one server connection) on stdin/stdout. See README "Subject interface".
struct External {
    argv: Vec<String>,
}

struct ExtConn {
    child: Child,
    stdin: Option<ChildStdin>,
    rx: mpsc::Receiver<Vec<u8>>,
}

impl Drop for ExtConn {
    fn drop(&mut self) {
        self.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Conn for ExtConn {
    fn send(&mut self, data: &[u8]) -> R<Vec<u8>> {
        if let Some(w) = self.stdin.as_mut() {
            w.write_all(data).and_then(|_| w.flush()).map_err(|e| format!("subject stdin: {e}"))?;
        }
        let mut out = Vec::new();
        let mut wait = Duration::from_millis(2000);
        loop {
            match self.rx.recv_timeout(wait) {
                Ok(chunk) => {
                    out.extend(chunk);
                    wait = Duration::from_millis(150);
                }
                Err(_) => break,
            }
        }
        Ok(out)
    }
}

impl External {
    fn cmd(&self) -> Command {
        let mut c = Command::new(&self.argv[0]);
        c.args(&self.argv[1..]);
        c
    }
}

impl Subject for External {
    fn describe(&self, profile: &str) -> R<Desc> {
        let o = self.cmd().arg("describe").arg(profile).output().map_err(|e| format!("subject describe: {e}"))?;
        if !o.status.success() {
            return Err(format!("subject describe {profile} exited {}", o.status));
        }
        let txt = String::from_utf8_lossy(&o.stdout);
        let kv: BTreeMap<&str, &str> = txt.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.trim(), v.trim())).collect();
        let kx = kv
            .get("kx_groups")
            .ok_or("describe: no kx_groups")?
            .split(',')
            .filter(|x| !x.is_empty())
            .map(|x| u16::from_str_radix(x.trim().trim_start_matches("0x"), 16).map_err(|_| format!("describe: bad group {x}")))
            .collect::<R<Vec<u16>>>()?;
        Ok(Desc {
            kx,
            versions: kv.get("versions").ok_or("describe: no versions")?.split(',').map(|x| x.trim().to_string()).collect(),
            early_data: *kv.get("early_data").ok_or("describe: no early_data")? == "true",
            fips: kv.get("fips").map(|v| *v == "true"),
            module: kv.get("module").map(|v| v.to_string()).filter(|v| !v.is_empty()),
        })
    }
    fn connect(&self, profile: &str) -> R<Box<dyn Conn>> {
        let mut child = self
            .cmd()
            .arg("serve")
            .arg(profile)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("subject serve: {e}"))?;
        let mut so = child.stdout.take().ok_or("no stdout")?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = [0u8; 16384];
            while let Ok(n) = so.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        let stdin = child.stdin.take();
        Ok(Box::new(ExtConn { child, stdin, rx }))
    }
}

// ------------------------------------------------------------------------------------------------ full handshake

#[derive(Debug)]
struct RecordingVerifier {
    offer: Vec<SignatureScheme>,
    provider: Arc<CryptoProvider>,
    seen: Mutex<Option<u16>>,
}

impl ServerCertVerifier for RecordingVerifier {
    // The oracle checks negotiation, not PKI: the chain is accepted, the CertificateVerify signature is verified.
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if let Ok(mut g) = self.seen.lock() {
            *g = Some(u16::from(d.scheme));
        }
        rustls::crypto::verify_tls12_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if let Ok(mut g) = self.seen.lock() {
            *g = Some(u16::from(d.scheme));
        }
        rustls::crypto::verify_tls13_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.offer.clone()
    }
}

fn kx_by_code(c: u16) -> R<&'static dyn SupportedKxGroup> {
    use prov::kx_group::*;
    [X25519MLKEM768, SECP256R1MLKEM768, X25519, SECP256R1, SECP384R1, MLKEM768, MLKEM1024, kx11ed::SECP384R1MLKEM1024]
        .into_iter()
        .find(|g| u16::from(g.name()) == c)
        .ok_or(format!("group 0x{c:04X} not implemented by the oracle client"))
}

struct FullResult {
    group: Option<u16>,
    kind: String,
    scheme: Option<u16>,
}

fn full_handshake(spec: &Spec, conn: &mut dyn Conn, client_groups: &[u16]) -> R<FullResult> {
    let mut p = prov::default_provider();
    p.kx_groups = client_groups.iter().map(|c| kx_by_code(*c)).collect::<R<_>>()?;
    let p = Arc::new(p);
    let rec = Arc::new(RecordingVerifier {
        offer: spec.sigalgs.values().map(|c| SignatureScheme::from(*c)).collect(),
        provider: p.clone(),
        seen: Mutex::new(None),
    });
    let cfg = ClientConfig::builder_with_provider(p)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(rec.clone())
        .with_no_client_auth();
    let name = ServerName::try_from(spec.sni.clone()).map_err(|e| e.to_string())?;
    let mut c = ClientConnection::new(Arc::new(cfg), name).map_err(|e| e.to_string())?;
    for _ in 0..12 {
        let mut out = Vec::new();
        while c.wants_write() {
            c.write_tls(&mut out).map_err(|e| e.to_string())?;
        }
        let was_handshaking = c.is_handshaking();
        if !out.is_empty() {
            let back = conn.send(&out)?;
            let mut rd = &back[..];
            while !rd.is_empty() {
                if c.read_tls(&mut rd).map_err(|e| e.to_string())? == 0 {
                    break;
                }
                c.process_new_packets().map_err(|e| format!("client: {e:?}"))?;
            }
        }
        if !was_handshaking {
            // client Finished delivered and the server's answer (tickets or an alert) processed without error
            return Ok(FullResult {
                group: c.negotiated_key_exchange_group().map(|g| u16::from(g.name())),
                kind: c.handshake_kind().map(|k| format!("{k:?}")).unwrap_or_default(),
                scheme: rec.seen.lock().ok().and_then(|g| *g),
            });
        }
    }
    Err("full handshake made no progress".into())
}

// ------------------------------------------------------------------------------------------------ checks

#[derive(Default)]
struct Report {
    diffs: Vec<String>,
    skips: Vec<String>,
    checked: usize,
}

impl Report {
    fn line(&mut self, quiet: bool, ok: bool, msg: String) {
        self.checked += 1;
        if !quiet {
            println!("{} {msg}", if ok { "ok  " } else { "DIFF" });
        }
        if !ok {
            self.diffs.push(msg);
        }
    }
}

fn check(spec: &Spec, subj: &dyn Subject, require_cmvp: bool, quiet: bool) -> Report {
    let mut r = Report::default();
    // 1. the frozen file agrees with the Select model of spec section F (independent of the subject)
    for v in &spec.verdicts {
        let m = model(&spec.profiles[&v.profile], &v.probe);
        r.line(quiet, m == v.expect, format!("MODEL {} expect={} model={}", v.id, spec.show(&v.expect), spec.show(&m)));
    }
    for sp in &spec.sups {
        if let SupMode::Probe(c, e) = &sp.mode {
            if let Some(p) = spec.profiles.get(&sp.profile) {
                let m = model(p, c);
                r.line(quiet, m == *e, format!("MODEL {} expect={} model={}", sp.id, spec.show(e), spec.show(&m)));
            }
        }
    }
    // 2. profiles: static (P-PQ2 configured set = profile, P-PQ4) and behavioural (P-PQ1 sweep, P-PQ2 sigalg)
    let mut cmvp_state: BTreeMap<String, Result<(), String>> = BTreeMap::new();
    for (name, p) in &spec.profiles {
        if p.status != "active" && p.status != "cmvp-pending" {
            if !quiet {
                println!("info PROFILE {name}: status={} (not checked: listed for F12 completeness)", p.status);
            }
            continue;
        }
        let show_g = |v: &[u16]| v.iter().map(|g| spec.gname(*g)).collect::<Vec<_>>().join(",");
        match subj.describe(name) {
            Err(e) => r.line(quiet, false, format!("PROFILE {name} describe failed: {e}")),
            Ok(d) => {
                r.line(quiet, d.kx == p.kx, format!("PROFILE {name} kx_groups configured=[{}] profile=[{}]", show_g(&d.kx), show_g(&p.kx)));
                r.line(quiet, d.versions == p.versions, format!("PROFILE {name} versions configured={:?} profile={:?}", d.versions, p.versions));
                r.line(quiet, d.early_data == p.early_data, format!("PROFILE {name} early_data configured={} profile={}", d.early_data, p.early_data));
                if p.status == "cmvp-pending" {
                    let st = match (d.fips, d.module.as_deref()) {
                        (Some(true), Some(m)) if m == CMVP_MODULE => Ok(()),
                        (Some(true), Some(m)) => Err(format!("module '{m}' != '{CMVP_MODULE}'")),
                        (f, m) => Err(format!("subject reports fips={f:?} module={m:?}: not the cmvp build (needs profiles/cmvp: rustls =0.23.43, aws-lc-rs =1.15.3 [fips], aws-lc-fips-sys =0.13.11)")),
                    };
                    cmvp_state.insert(name.clone(), st);
                }
            }
        }
        if !p.kx.is_empty() && p.kx.iter().all(|g| !CLASSICAL.contains(g)) {
            for g in CLASSICAL {
                let c = ProbeCase { groups: vec![g], shares: vec![g], sigalgs: spec.sigalgs.values().copied().collect(), versions: tls13() };
                let got = run_probe(spec, subj, name, &c);
                r.line(quiet, got == Outcome::Alert(40), format!("PROFILE {name} P-PQ1 classical-only {} -> {}", spec.gname(g), spec.show(&got)));
            }
        }
        // configured set = profile, behaviourally (P-PQ2): every [codepoints.groups] group offered alone with a share
        // gets server_hello(g) iff g is in the profile, else alert 40 (in-profile sigalgs offered, TLS 1.3)
        for (gn, g) in &spec.groups {
            let c = ProbeCase { groups: vec![*g], shares: vec![*g], sigalgs: spec.sigalgs.values().copied().collect(), versions: tls13() };
            let want = model(p, &c);
            let got = run_probe(spec, subj, name, &c);
            r.line(quiet, got == want, format!("PROFILE {name} group-set {gn} expect={} got={}", spec.show(&want), spec.show(&got)));
        }
        // sigalg admission (F12 header step 2): only out-of-profile sigalgs offered -> alert 49 before group selection
        if p.sigalg_cover.is_some() {
            if let Some(first) = p.kx.first() {
                let out: Vec<u16> = spec.sigalgs.values().copied().filter(|s| !p.sigalgs.contains(s)).collect();
                let c = ProbeCase { groups: vec![*first], shares: vec![*first], sigalgs: out, versions: tls13() };
                let got = run_probe(spec, subj, name, &c);
                r.line(quiet, got == Outcome::Alert(49), format!("PROFILE {name} sigalg-admission out-of-profile-only -> {}", spec.show(&got)));
            }
        }
        // version admission (P-PQ4, F12 header step 1): a TLS 1.2-only hello -> alert 70 (TLS 1.3-only profiles)
        if let (Some(first), false) = (p.kx.first(), p.versions.iter().any(|v| v == "TLS12")) {
            let c = ProbeCase { groups: vec![*first], shares: vec![*first], sigalgs: spec.sigalgs.values().copied().collect(), versions: vec!["TLS12".into()] };
            let got = run_probe(spec, subj, name, &c);
            r.line(quiet, got == Outcome::Alert(70), format!("PROFILE {name} version-admission TLS12-only -> {}", spec.show(&got)));
        }
        if let Some(first) = p.kx.first() {
            match subj.connect(name).and_then(|mut c| full_handshake(spec, c.as_mut(), &[*first])) {
                Err(e) => r.line(quiet, false, format!("PROFILE {name} P-PQ2 sigalg handshake failed: {e}")),
                Ok(f) => {
                    let ok = f.group == Some(*first) && f.scheme.is_some_and(|s| p.sigalgs.contains(&s));
                    r.line(quiet, ok, format!(
                        "PROFILE {name} P-PQ2 group={} certificate_verify={} allowed=[{}]",
                        f.group.map(|g| spec.gname(g)).unwrap_or("-".into()),
                        f.scheme.map(|s| spec.sname(s)).unwrap_or("-".into()),
                        p.sigalgs.iter().map(|s| spec.sname(*s)).collect::<Vec<_>>().join(",")
                    ));
                }
            }
        }
    }
    // 3. the frozen verdicts
    for v in &spec.verdicts {
        let got = run_probe(spec, subj, &v.profile, &v.probe);
        r.line(quiet, got == v.expect, format!("VERDICT {} [{}] expect={} got={}", v.id, v.profile, spec.show(&v.expect), spec.show(&got)));
        if v.requires == "cmvp" {
            match cmvp_state.get(&v.profile) {
                Some(Ok(())) => r.line(quiet, true, format!("VERDICT {} cmvp-module fips=true module={CMVP_MODULE}", v.id)),
                Some(Err(why)) if require_cmvp => r.line(quiet, false, format!("VERDICT {} cmvp-module: {why}", v.id)),
                Some(Err(why)) => {
                    if !quiet {
                        println!("SKIP VERDICT {} cmvp-module half (P-PQ5): {why}", v.id);
                    }
                    r.skips.push(v.id.clone());
                }
                None => r.line(quiet, false, format!("VERDICT {} cmvp-module: profile {} not described", v.id, v.profile)),
            }
        }
    }
    // 4. supplementary (cited by id, not frozen verdicts)
    for sp in &spec.sups {
        let allowed = spec.profiles.get(&sp.profile).map(|p| p.sigalgs.clone()).unwrap_or_default();
        match &sp.mode {
            SupMode::Probe(c, e) => {
                let got = run_probe(spec, subj, &sp.profile, c);
                r.line(quiet, got == *e, format!("SUP {} [{}] expect={} got={}", sp.id, sp.profile, spec.show(e), spec.show(&got)));
            }
            SupMode::Full { client_groups, expect_group, expect_kind } => {
                match subj.connect(&sp.profile).and_then(|mut c| full_handshake(spec, c.as_mut(), client_groups)) {
                    Err(e) => r.line(quiet, false, format!("SUP {} [{}] full handshake failed: {e}", sp.id, sp.profile)),
                    Ok(f) => {
                        let ok = f.group == Some(*expect_group)
                            && &f.kind == expect_kind
                            && f.scheme.is_some_and(|s| allowed.contains(&s));
                        r.line(quiet, ok, format!(
                            "SUP {} [{}] expect={}/{} got={}/{} certificate_verify={}",
                            sp.id, sp.profile, spec.gname(*expect_group), expect_kind,
                            f.group.map(|g| spec.gname(g)).unwrap_or("-".into()), f.kind,
                            f.scheme.map(|s| spec.sname(s)).unwrap_or("-".into())
                        ));
                    }
                }
            }
        }
    }
    r
}

fn run_probe(spec: &Spec, subj: &dyn Subject, profile: &str, c: &ProbeCase) -> Outcome {
    let res = (|| -> R<Outcome> {
        let ch = client_hello(spec, c)?;
        let mut conn = subj.connect(profile)?;
        Ok(classify(&conn.send(&ch)?))
    })();
    res.unwrap_or_else(|e| Outcome::Other(e))
}

// ------------------------------------------------------------------------------------------------ entry points

fn build_check() -> Vec<String> {
    let first = prov::default_provider().kx_groups.first().map(|g| u16::from(g.name()));
    if first == Some(0x11EC) {
        vec![]
    } else {
        vec![format!("oracle build: default_provider kx_groups[0] = {first:04x?}, prefer-post-quantum is off")]
    }
}

fn cmd_check(spec: &Spec, subject: Option<&str>, require_cmvp: bool) -> R<()> {
    let r = match subject {
        Some(s) => {
            let argv: Vec<String> = s.split_whitespace().map(String::from).collect();
            if argv.is_empty() {
                return Err("empty --subject".into());
            }
            println!("subject: external `{s}`");
            check(spec, &External { argv }, require_cmvp, false)
        }
        None => {
            println!("subject: built-in reference profile builder (rustls aws-lc-rs provider, floor lock)");
            let mut r = check(spec, &Reference::new(Mutation::None)?, require_cmvp, false);
            for d in build_check() {
                println!("DIFF {d}");
                r.diffs.push(d);
            }
            r
        }
    };
    let n = spec.verdicts.len();
    let fails: Vec<&String> = r.diffs.iter().collect();
    if fails.is_empty() {
        println!(
            "HRR-VERDICTS: PASS ({n} verdicts selection-checked, diff=0; {} checks; {} cmvp-module halves SKIPPED: {})",
            r.checked,
            r.skips.len(),
            if r.skips.is_empty() { "-".to_string() } else { r.skips.join(",") }
        );
        Ok(())
    } else {
        Err(format!("HRR-VERDICTS: FAIL (diff={}: {})", fails.len(), fails.iter().take(3).map(|s| s.as_str()).collect::<Vec<_>>().join(" | ")))
    }
}

fn cmd_self_test(spec: &Spec) -> R<()> {
    let base = Reference::new(Mutation::None)?;
    let b = check(spec, &base, false, true);
    if !b.diffs.is_empty() {
        return Err(format!("HRR-VERDICTS SELF-TEST: FAIL (baseline not clean: {})", b.diffs[0]));
    }
    println!("baseline (unmutated reference): diff=0 over {} checks", b.checked);
    let mut caught = 0;
    let mut total = 0;
    let mut missed = Vec::new();
    let mut tally = |name: &str, r: &Report| {
        total += 1;
        if r.diffs.is_empty() {
            println!("MUTANT {name}: NOT CAUGHT");
            missed.push(name.to_string());
        } else {
            caught += 1;
            let kinds: std::collections::BTreeSet<&str> = r.diffs.iter().filter_map(|d| d.split_whitespace().next()).collect();
            println!("MUTANT {name}: caught, {} diffs ({}); first: {}", r.diffs.len(), kinds.into_iter().collect::<Vec<_>>().join("+"), r.diffs[0]);
        }
    };
    for (m, name) in MUTATIONS {
        let r = check(spec, &base.with(m), false, true);
        tally(name, &r);
    }
    // verdict-file mutation: a weakened expectation must be detected against the unmutated subject
    let mut ms = spec.clone();
    if let Some(v) = ms.verdicts.iter_mut().find(|v| v.id == "PUB-T4") {
        v.expect = Outcome::Sh(0x001D);
    }
    tally("verdict-file:PUB-T4-expect-server_hello", &check(&ms, &base, false, true));
    // the PLAN-6 draft's unreachable verdict (40 instead of 49) must be red against the model and the subject
    let mut ms = spec.clone();
    if let Some(v) = ms.verdicts.iter_mut().find(|v| v.id == "UNI-T5") {
        v.expect = Outcome::Alert(40);
    }
    tally("verdict-file:UNI-T5-expect-alert-40", &check(&ms, &base, false, true));
    // load-time rules: a row violating sigalg_cover, and a TLS12-only row against a profile that enables TLS 1.2
    let as_report = |r: R<()>| Report { diffs: r.err().into_iter().map(|e| format!("LOAD {e}")).collect(), ..Report::default() };
    let mut ms = spec.clone();
    if let Some(v) = ms.verdicts.iter_mut().find(|v| v.id == "UNI-T1") {
        v.probe.sigalgs.retain(|s| *s != MLDSA87);
    }
    tally("verdict-file:UNI-T1-partial-sigalg-cover", &as_report(validate(&ms)));
    let mut ms = spec.clone();
    if let Some(p) = ms.profiles.get_mut("P-CNSA") {
        p.versions.push("TLS12".into());
    }
    tally("verdict-file:CNSA-T4-against-tls12-profile", &as_report(validate(&ms)));
    // the --subject hook: our own binary as an external subject, clean must pass and a mutant must be caught
    let exe = std::env::current_exe().map_err(|e| e.to_string())?.to_string_lossy().into_owned();
    let clean = check(spec, &External { argv: vec![exe.clone(), "subject".into()] }, false, true);
    if !clean.diffs.is_empty() {
        return Err(format!("HRR-VERDICTS SELF-TEST: FAIL (external clean subject not clean: {})", clean.diffs[0]));
    }
    println!("external hook, clean subject: diff=0 over {} checks", clean.checked);
    for name in ["pq-required-classical-fallback", "universal-accepts-x25519"] {
        let ext_m = External { argv: vec![exe.clone(), "subject".into(), "--mutate".into(), name.into()] };
        tally(&format!("external:{name}"), &check(spec, &ext_m, false, true));
    }
    // --require-cmvp must turn the floor build's cmvp SKIPs into diffs (no silent pass)
    tally("require-cmvp-on-floor-build", &check(spec, &base, true, true));
    // --require-cmvp: fips=true is not enough, the module identity must be exactly AWS-LC FIPS 3.1.0
    for (m, name) in CMVP_MUTATIONS.iter().take(2) {
        tally(&format!("require-cmvp:{name}"), &check(spec, &base.with(*m), true, true));
    }
    let ext_c = External { argv: vec![exe.clone(), "subject".into(), "--mutate".into(), "reports-fips-module-none".into()] };
    tally("external:require-cmvp:reports-fips-module-none", &check(spec, &ext_c, true, true));
    // positive control: the identity the cmvp build must report passes --require-cmvp (the mode is not always red)
    let good = check(spec, &base.with(Mutation::ReportsCmvp310), true, true);
    if !good.diffs.is_empty() || !good.skips.is_empty() {
        return Err(format!("HRR-VERDICTS SELF-TEST: FAIL (--require-cmvp rejects a subject reporting fips=true module={CMVP_MODULE}: {:?} skips={:?})", good.diffs.first(), good.skips));
    }
    println!("--require-cmvp positive control (fips=true module={CMVP_MODULE}): diff=0 over {} checks, 0 SKIPPED", good.checked);
    if missed.is_empty() {
        println!("HRR-VERDICTS SELF-TEST: PASS ({caught}/{total} mutants caught; baseline, external hook and --require-cmvp control clean)");
        Ok(())
    } else {
        Err(format!("HRR-VERDICTS SELF-TEST: FAIL (not caught: {})", missed.join(", ")))
    }
}

fn cmd_subject(args: &[String]) -> R<()> {
    let mut m = Mutation::None;
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--mutate" {
            let n = args.get(i + 1).ok_or("--mutate needs a name")?;
            m = MUTATIONS
                .iter()
                .chain(CMVP_MUTATIONS.iter())
                .find(|(_, s)| s == n)
                .map(|(m, _)| *m)
                .ok_or(format!("unknown mutation {n}"))?;
            i += 2;
        } else {
            rest.push(args[i].clone());
            i += 1;
        }
    }
    let r = Reference::new(m)?;
    match (rest.first().map(String::as_str), rest.get(1)) {
        (Some("describe"), Some(p)) => {
            let d = r.describe(p)?;
            println!("kx_groups={}", d.kx.iter().map(|g| format!("0x{g:04x}")).collect::<Vec<_>>().join(","));
            println!("versions={}", d.versions.join(","));
            println!("early_data={}", d.early_data);
            println!("fips={}", d.fips.unwrap_or(false));
            println!("module={}", d.module.unwrap_or_default());
            Ok(())
        }
        (Some("serve"), Some(p)) => {
            let (cfg, _) = r.config(p)?;
            let mut s = ServerConnection::new(cfg).map_err(|e| e.to_string())?;
            let mut stdin = std::io::stdin().lock();
            let mut stdout = std::io::stdout().lock();
            let mut buf = [0u8; 16384];
            loop {
                let n = stdin.read(&mut buf).map_err(|e| e.to_string())?;
                if n == 0 {
                    return Ok(());
                }
                let mut rd = &buf[..n];
                let mut failed = false;
                while !rd.is_empty() && !failed {
                    if s.read_tls(&mut rd).map_err(|e| e.to_string())? == 0 {
                        break;
                    }
                    failed = s.process_new_packets().is_err();
                }
                let mut out = Vec::new();
                while s.wants_write() {
                    s.write_tls(&mut out).map_err(|e| e.to_string())?;
                }
                stdout.write_all(&out).and_then(|_| stdout.flush()).map_err(|e| e.to_string())?;
                if failed {
                    return Ok(());
                }
            }
        }
        _ => Err("usage: hrr-verdicts subject [--mutate M] describe|serve PROFILE".into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opt = |f: &str| args.iter().position(|a| a == f).and_then(|i| args.get(i + 1)).cloned();
    let flag = |f: &str| args.iter().any(|a| a == f);
    let res = match args.first().map(String::as_str) {
        Some("subject") => cmd_subject(&args[1..]),
        Some(c @ ("check" | "self-test")) => match load(&opt("--file").unwrap_or_else(|| "tls/verdicts.toml".into())) {
            Err(e) => Err(format!("HRR-VERDICTS: FAIL (cannot load verdict file: {e})")),
            Ok(spec) if c == "check" => cmd_check(&spec, opt("--subject").as_deref(), flag("--require-cmvp")),
            Ok(spec) => cmd_self_test(&spec),
        },
        _ => Err("usage: hrr-verdicts check|self-test --file F [--subject CMD] [--require-cmvp] | subject ...".into()),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            println!("{e}");
            ExitCode::FAILURE
        }
    }
}
