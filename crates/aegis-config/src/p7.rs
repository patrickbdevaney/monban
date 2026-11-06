//! F8 Phase-7 additions (P7-spec-001, PLAN-7 Interfaces): `listeners[].proxy_protocol`, `listeners[].l4`,
//! `listeners[].front` and the root `tls` block. Every member is optional and an absent member means exactly what
//! the config meant before Phase 7 (the effective form and `config_hash` of such a config are unchanged: the default
//! `front` is not printed in the hashed form).
//!
//! What the types make unrepresentable:
//! * **A PROXY header trusted from everyone** (PROXY-1, PROXY-2). [`ProxyProtocol`] is non-empty and a `/0` prefix
//!   does not parse; a prefix with host bits set is refused (reject, don't repair), so every [`Cidr`] has one text
//!   form.
//! * **A listener that is both L4 and HTTP** (L4-2). An `l4` listener with `alpn` is a load error (`Forbidden`).
//! * **A default L4 upstream** (L4-1). [`L4Route::sni`] is an exact A-label; there is no wildcard or fallback
//!   member, and SNI values are unique per listener.
//! * **An MTC credential without a trust anchor, or a trust anchor on another kind** (SEL-1); **an ML-DSA credential
//!   scoped to a P-PUBLIC-WEB listener** (SEL-2); **a credential scoped to an undeclared or L4 listener** (SEL-3).
//!   The selector itself (aegis-tls, feature `mtc`) still enforces SEL-1..3 per handshake; these load checks are a
//!   second, static line.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Most entries of `proxy_protocol.trusted`.
pub const MAX_TRUSTED: usize = 64;
/// Most entries of a listener's `l4` list.
pub const MAX_L4_ROUTES: usize = 1024;
/// Most entries of `tls.credentials` (and of one credential's `listeners`).
pub const MAX_CREDENTIALS: usize = 64;
/// Most components of a trust anchor ID.
pub const MAX_TAI_COMPONENTS: usize = 32;

// ------------------------------------------------------------------------------------------------ front

/// F8 `listeners[].front` (D-P7.3, FRONT-1): the accept/read/write front. Default [`Front::Epoll`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum Front {
    /// tokio on epoll, as before Phase 7.
    #[default]
    Epoll,
    /// io_uring (feature `uring` and `--front uring`; off in every shipped profile).
    Uring,
}

impl Front {
    pub(crate) const ALL: [(&'static str, Front); 2] = [("epoll", Front::Epoll), ("uring", Front::Uring)];
    pub fn as_str(self) -> &'static str {
        match self {
            Front::Epoll => "epoll",
            Front::Uring => "uring",
        }
    }
}

// ------------------------------------------------------------------------------------------------ PROXY v2

/// One trusted source prefix: canonical text, `1 <= prefix <= 32` (IPv4) or `<= 128` (IPv6), host bits zero, never
/// an IPv4-mapped IPv6 prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse the F8 text form. `None` unless the text is exactly the canonical form of a valid prefix.
    pub fn parse(s: &str) -> Option<Cidr> {
        let (a, p) = s.split_once('/')?;
        let pb = p.as_bytes();
        let digits_ok = matches!(pb.split_first(), Some((f, rest)) if (b'1'..=b'9').contains(f)
            && rest.len() <= 2 && rest.iter().all(u8::is_ascii_digit));
        if !digits_ok {
            return None;
        }
        let prefix: u8 = p.parse().ok()?;
        if a.contains(':') {
            if a.contains('.') || a.len() > 39 || prefix > 128 {
                return None;
            }
            let ip: Ipv6Addr = a.parse().ok()?;
            if ip.to_string() != a || ip.to_ipv4_mapped().is_some() {
                return None;
            }
            let host = u128::MAX.checked_shr(u32::from(prefix)).unwrap_or(0);
            if u128::from(ip) & host != 0 {
                return None;
            }
            Some(Cidr { addr: IpAddr::V6(ip), prefix })
        } else {
            if prefix > 32 {
                return None;
            }
            let ip: Ipv4Addr = a.parse().ok()?;
            if ip.to_string() != a {
                return None;
            }
            let host = u32::MAX.checked_shr(u32::from(prefix)).unwrap_or(0);
            if u32::from(ip) & host != 0 {
                return None;
            }
            Some(Cidr { addr: IpAddr::V4(ip), prefix })
        }
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether `ip` is inside this prefix. An IPv4-mapped IPv6 peer (`::ffff:a.b.c.d`, what a dual-stack socket
    /// reports for an IPv4 client) is matched as its IPv4 address; otherwise families never match each other.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(a)) => Self::v4_in(net, self.prefix, a),
            (IpAddr::V4(net), IpAddr::V6(a)) => a.to_ipv4_mapped().is_some_and(|m| Self::v4_in(net, self.prefix, m)),
            (IpAddr::V6(net), IpAddr::V6(a)) => {
                let mask = !u128::MAX.checked_shr(u32::from(self.prefix)).unwrap_or(0);
                u128::from(a) & mask == u128::from(net)
            }
            (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }

    fn v4_in(net: Ipv4Addr, prefix: u8, a: Ipv4Addr) -> bool {
        let mask = !u32::MAX.checked_shr(u32::from(prefix)).unwrap_or(0);
        u32::from(a) & mask == u32::from(net)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// F8 `listeners[].proxy_protocol` (D-P7.2, PROXY-1..3): PROXY v2 accepted only from these prefixes.
/// Non-empty; constructible only by the parser.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProxyProtocol {
    pub(crate) trusted: Vec<Cidr>,
}

impl ProxyProtocol {
    pub fn trusted(&self) -> &[Cidr] {
        &self.trusted
    }
    /// PROXY-1: whether a connection from `source` may (and must) carry a PROXY v2 header.
    pub fn admits(&self, source: IpAddr) -> bool {
        self.trusted.iter().any(|c| c.contains(source))
    }
}

// ------------------------------------------------------------------------------------------------ L4

/// One F8 `listeners[].l4[]` entry (D-P7.2, L4-1): exact SNI → upstream.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct L4Route {
    /// ASCII-lowercase A-label, exact match (no wildcard).
    pub sni: String,
    /// Host name, dotted IPv4, or canonical IPv6 (without brackets).
    pub upstream_host: String,
    /// 1..=65535.
    pub upstream_port: u16,
}

impl L4Route {
    /// The F8 text form: `host:port` or `[v6]:port`.
    pub fn upstream(&self) -> String {
        if self.upstream_host.contains(':') {
            format!("[{}]:{}", self.upstream_host, self.upstream_port)
        } else {
            format!("{}:{}", self.upstream_host, self.upstream_port)
        }
    }
}

/// `1..=65535`, decimal, no sign and no leading zero.
fn port(s: &str) -> Option<u16> {
    let b = s.as_bytes();
    let ok = matches!(b.split_first(), Some((f, rest)) if (b'1'..=b'9').contains(f)
        && rest.len() <= 4 && rest.iter().all(u8::is_ascii_digit));
    if !ok {
        return None;
    }
    s.parse::<u16>().ok()
}

/// Parse F8 `l4_route.upstream` into (host, port).
pub(crate) fn upstream(s: &str) -> Option<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once("]:")?;
        if h.contains('.') || h.len() < 2 || h.len() > 39 {
            return None;
        }
        let ip: Ipv6Addr = h.parse().ok()?;
        if ip.to_string() != h {
            return None;
        }
        return Some((h.to_owned(), port(p)?));
    }
    let (h, p) = s.rsplit_once(':')?;
    if !crate::parse::is_host(h) {
        return None;
    }
    Some((h.to_owned(), port(p)?))
}

// ------------------------------------------------------------------------------------------------ tls

/// F8 `credential.kind` (D-P7.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CredentialKind {
    /// Classical WebPKI chain.
    X509,
    /// ML-DSA chain for private hops; never chosen on P-PUBLIC-WEB (SEL-2).
    MlDsa,
    /// Merkle Tree Certificate credential, opaque to AEGIS; chosen only on a trust_anchors match (SEL-1).
    Mtc,
}

impl CredentialKind {
    pub(crate) const ALL: [(&'static str, CredentialKind); 3] =
        [("x509", CredentialKind::X509), ("mldsa", CredentialKind::MlDsa), ("mtc", CredentialKind::Mtc)];
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialKind::X509 => "x509",
            CredentialKind::MlDsa => "mldsa",
            CredentialKind::Mtc => "mtc",
        }
    }
}

/// F8 `credential.chain` / `credential.key`: where the bytes come from, never the bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SecretRef {
    /// `cred:NAME`: systemd credential NAME.
    Cred(String),
    /// `path:/abs`: absolute path (held without the `path:` prefix).
    Path(String),
}

impl SecretRef {
    pub(crate) fn parse(s: &str) -> Option<SecretRef> {
        if let Some(n) = s.strip_prefix("cred:") {
            let ok = (1..=64).contains(&n.len())
                && n.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'));
            return ok.then(|| SecretRef::Cred(n.to_owned()));
        }
        if let Some(n) = s.strip_prefix("path:") {
            let ok = match n.as_bytes().split_first() {
                Some((b'/', rest)) => {
                    (1..=255).contains(&rest.len())
                        && rest.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'/' | b'-'))
                }
                _ => false,
            };
            return ok.then(|| SecretRef::Path(n.to_owned()));
        }
        None
    }
    /// The F8 text form.
    pub fn to_f8(&self) -> String {
        match self {
            SecretRef::Cred(n) => format!("cred:{n}"),
            SecretRef::Path(p) => format!("path:{p}"),
        }
    }
}

/// A trust anchor ID (draft-ietf-tls-trust-anchor-ids-07): a relative OID of 1..=32 components, each < 2^32.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TrustAnchorId {
    components: Vec<u32>,
}

impl TrustAnchorId {
    /// Parse the dotted-decimal F8 form (`^(0|[1-9][0-9]{0,9})(\.(0|[1-9][0-9]{0,9})){0,31}$`, each < 2^32).
    pub fn parse(s: &str) -> Option<TrustAnchorId> {
        let mut components = Vec::new();
        for part in s.split('.') {
            let b = part.as_bytes();
            let ok = match b.split_first() {
                Some((b'0', rest)) => rest.is_empty(),
                Some((f, rest)) => f.is_ascii_digit() && rest.len() <= 9 && rest.iter().all(u8::is_ascii_digit),
                None => false,
            };
            if !ok {
                return None;
            }
            components.push(part.parse::<u32>().ok()?);
        }
        if components.is_empty() || components.len() > MAX_TAI_COMPONENTS {
            return None;
        }
        Some(TrustAnchorId { components })
    }
    pub fn components(&self) -> &[u32] {
        &self.components
    }
    /// The binary form compared with the client's `trust_anchors` entries: the contents octets of the DER
    /// RELATIVE-OID (each component base 128, big-endian, the high bit set on every octet but its last). At most
    /// 160 octets (32 components × 5), inside the extension's 1..=255 bound.
    pub fn wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.components.len().saturating_mul(5));
        for &c in &self.components {
            let mut groups = [0u8; 5];
            let mut n = 0usize;
            let mut v = c;
            loop {
                if let Some(g) = groups.get_mut(n) {
                    *g = (v & 0x7f) as u8;
                }
                n = n.saturating_add(1);
                v >>= 7;
                if v == 0 || n >= groups.len() {
                    break;
                }
            }
            for i in (0..n).rev() {
                let g = groups.get(i).copied().unwrap_or(0);
                out.push(if i == 0 { g } else { g | 0x80 });
            }
        }
        out
    }
}

impl fmt::Display for TrustAnchorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, c) in self.components.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            write!(f, "{c}")?;
        }
        Ok(())
    }
}

/// One F8 `tls.credentials[]` entry. Constructible only by the parser.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Credential {
    pub(crate) id: String,
    pub(crate) kind: CredentialKind,
    /// `Some` iff `kind == Mtc`.
    pub(crate) trust_anchor_id: Option<TrustAnchorId>,
    pub(crate) chain: SecretRef,
    pub(crate) key: SecretRef,
    /// `None`: every HTTP listener. `Some`: non-empty, unique, each a declared non-L4 listener.
    pub(crate) listeners: Option<Vec<String>>,
}

impl Credential {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn kind(&self) -> CredentialKind {
        self.kind
    }
    pub fn trust_anchor_id(&self) -> Option<&TrustAnchorId> {
        self.trust_anchor_id.as_ref()
    }
    pub fn chain(&self) -> &SecretRef {
        &self.chain
    }
    pub fn key(&self) -> &SecretRef {
        &self.key
    }
    /// The explicit listener scope; `None` = every HTTP listener.
    pub fn listeners(&self) -> Option<&[String]> {
        self.listeners.as_deref()
    }
    /// Whether this credential is in scope for the named listener (scope only: SEL-2 is applied by
    /// [`TlsBlock::candidates`]).
    pub fn scoped_to(&self, listener: &str) -> bool {
        self.listeners.as_ref().is_none_or(|ls| ls.iter().any(|l| l == listener))
    }
}

/// F8 `tls` (D-P7.4, SEL-1..3). Constructible only by the parser.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TlsBlock {
    pub(crate) credentials: Vec<Credential>,
}

impl TlsBlock {
    pub fn credentials(&self) -> &[Credential] {
        &self.credentials
    }
    pub fn credential(&self, id: &str) -> Option<&Credential> {
        self.credentials.iter().find(|c| c.id == id)
    }
    /// The credentials the selector may consider on `listener` (document order): those scoped to it, minus every
    /// `mldsa` credential when the listener is P-PUBLIC-WEB (SEL-2) and minus everything on an L4 listener (it
    /// never terminates TLS). An unknown listener has no candidates (SEL-3: never another listener's credential).
    pub fn candidates<'a>(&'a self, cfg: &'a crate::Config, listener: &str) -> Vec<&'a Credential> {
        let Some(l) = cfg.listeners().iter().find(|l| l.name == listener) else { return Vec::new() };
        if l.l4.is_some() {
            return Vec::new();
        }
        let public = l.profile == crate::Profile::PublicWeb;
        self.credentials
            .iter()
            .filter(|c| c.scoped_to(listener) && !(public && c.kind == CredentialKind::MlDsa))
            .collect()
    }
}

// ------------------------------------------------------------------------------------------------ admission

/// F8 `admission.per_ip`: a GCRA limit as rate and burst. `1 <= rate_per_s <= 1_000_000`,
/// `1 <= burst <= 10_000_000` and `burst >= rate_per_s` (a burst below one second of rate is refused at load).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RateLimit {
    pub rate_per_s: u64,
    pub burst: u64,
}

impl RateLimit {
    /// (min, max) of `rate_per_s`.
    pub const RATE_BOUNDS: (u64, u64) = (1, 1_000_000);
    /// (min, max) of `burst`.
    pub const BURST_BOUNDS: (u64, u64) = (1, 10_000_000);
    /// The GCRA emission interval in ns (`aegis_budget::Gcra::t_ns`): `1e9 / rate_per_s`, rounded down, so the
    /// configured rate is never undercut (1000/s → 1_000_000 ns, today's value). At least 1000 ns.
    pub fn emission_interval_ns(&self) -> u64 {
        1_000_000_000u64.checked_div(self.rate_per_s).unwrap_or(1_000_000_000)
    }
}

/// F8 `admission` (Phase 7, requested by the integrator for P7-bin-001 and the scaling bench): the S0/S1/S5 numbers
/// that were constants in the assembly (`aegis-bin` `admission_config()`). Every member is bounded and defaulted to
/// exactly the pre-Phase-7 constant, so an absent block (or one equal to the defaults) is today's behaviour and is
/// not printed in the hashed effective form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Admission {
    /// S1 per-source-IP limiter (cost 1 per request); today also the per-identity anon/session/verified limit.
    /// Default 1000/s, burst 2000.
    pub per_ip: RateLimit,
    /// S1 limiter store capacity (keys). Default 65536.
    pub per_ip_store: u64,
    /// S0 open-connection cap. Default 16384.
    pub max_conns: u64,
    /// S0 per-prefix connection cap. Default 4096.
    pub per_prefix_conns: u64,
    /// S5 concurrency limit L. Default 4096.
    pub concurrency: u64,
}

impl Admission {
    /// (member, minimum, maximum, default) of the integer members, in schema order (`per_ip` is separate).
    pub const BOUNDS: &'static [(&'static str, u64, u64, u64)] = &[
        ("per_ip_store", 1024, 1_048_576, 65_536),
        ("max_conns", 1, 1_048_576, 16_384),
        ("per_prefix_conns", 1, 1_048_576, 4096),
        ("concurrency", 1, 1_048_576, 4096),
    ];
    /// Default `per_ip`.
    pub const DEFAULT_PER_IP: RateLimit = RateLimit { rate_per_s: 1000, burst: 2000 };

    pub(crate) fn set(&mut self, name: &str, v: u64) {
        match name {
            "per_ip_store" => self.per_ip_store = v,
            "max_conns" => self.max_conns = v,
            "per_prefix_conns" => self.per_prefix_conns = v,
            "concurrency" => self.concurrency = v,
            _ => {}
        }
    }
    /// Values in [`Admission::BOUNDS`] order.
    pub fn values(&self) -> Vec<u64> {
        vec![self.per_ip_store, self.max_conns, self.per_prefix_conns, self.concurrency]
    }
}

impl Default for Admission {
    fn default() -> Self {
        Admission {
            per_ip: Self::DEFAULT_PER_IP,
            per_ip_store: 65_536,
            max_conns: 16_384,
            per_prefix_conns: 4096,
            concurrency: 4096,
        }
    }
}
