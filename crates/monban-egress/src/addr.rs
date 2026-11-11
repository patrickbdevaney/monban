//! Address classification (the SSRF guard proper). Every resolved or literal address goes through [`classify`]
//! before a socket is opened; only [`AddrClass::Public`] is connectable, plus the re-admittable classes the policy
//! names explicitly (see [`AddrClass::readmittable`]).
//!
//! IPv6 is handled as an allowlist: only global unicast `2000::/3` can be public, and inside it the special-purpose
//! blocks are carved out. Addresses that embed an IPv4 address are judged by the embedded address (NAT64 well-known
//! prefix, 6to4) or rejected outright (IPv4-mapped, IPv4-compatible, Teredo, NAT64 local-use).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The class of an IP address, as far as egress is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddrClass {
    /// Globally reachable unicast: connectable.
    Public,
    /// `0.0.0.0`, `::`.
    Unspecified,
    /// `0.0.0.0/8` ("this network").
    ThisNetwork,
    /// `127.0.0.0/8`, `::1`.
    Loopback,
    /// RFC 1918.
    Private,
    /// `100.64.0.0/10` (CGNAT shared address space).
    SharedAddressSpace,
    /// `169.254.0.0/16`, `fe80::/10`.
    LinkLocal,
    /// Cloud instance metadata: `169.254.169.254`, `169.254.170.2`, `100.100.100.200`, `fd00:ec2::254`.
    Metadata,
    /// `fc00::/7`.
    UniqueLocal,
    /// `fec0::/10` (deprecated site-local).
    SiteLocal,
    /// `224.0.0.0/4`, `ff00::/8`.
    Multicast,
    /// `255.255.255.255`.
    Broadcast,
    /// `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, `3fff::/20`.
    Documentation,
    /// `198.18.0.0/15`, `2001:2::/48`.
    Benchmarking,
    /// `192.0.0.0/24`, `240.0.0.0/4`, `192.88.99.0/24`, `100::/64`, `2001::/23` remainder, `5f00::/16`, and any
    /// IPv6 outside `2000::/3`.
    Reserved,
    /// `::ffff:0:0/96`.
    Ipv4Mapped,
    /// `::/96` (deprecated IPv4-compatible).
    Ipv4Compatible,
    /// `64:ff9b::/96` embedding a forbidden IPv4 address.
    Nat64,
    /// `64:ff9b:1::/48` (local-use NAT64: embedding position is network-specific, so never connectable).
    Nat64LocalUse,
    /// `2002::/16` embedding a forbidden IPv4 address.
    SixToFour,
    /// `2001::/32`.
    Teredo,
}

impl AddrClass {
    /// Stable code.
    pub fn code(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Unspecified => "unspecified",
            Self::ThisNetwork => "this-network",
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::SharedAddressSpace => "shared-address-space",
            Self::LinkLocal => "link-local",
            Self::Metadata => "metadata",
            Self::UniqueLocal => "unique-local",
            Self::SiteLocal => "site-local",
            Self::Multicast => "multicast",
            Self::Broadcast => "broadcast",
            Self::Documentation => "documentation",
            Self::Benchmarking => "benchmarking",
            Self::Reserved => "reserved",
            Self::Ipv4Mapped => "ipv4-mapped",
            Self::Ipv4Compatible => "ipv4-compatible",
            Self::Nat64 => "nat64",
            Self::Nat64LocalUse => "nat64-local-use",
            Self::SixToFour => "6to4",
            Self::Teredo => "teredo",
        }
    }

    /// Classes a policy may re-admit for specific prefixes (`Policy::readmit`): an operator's own private services.
    /// Metadata, link-local, multicast, broadcast, unspecified, reserved and every embedded-IPv4 form are never
    /// re-admittable: the address must be given in its canonical family.
    pub fn readmittable(self) -> bool {
        matches!(self, Self::Loopback | Self::Private | Self::SharedAddressSpace | Self::UniqueLocal)
    }
}

fn v4_in(a: Ipv4Addr, net: [u8; 4], len: u32) -> bool {
    let mask = if len == 0 { 0 } else { u32::MAX << 32u32.saturating_sub(len) };
    (u32::from(a) & mask) == (u32::from(Ipv4Addr::from(net)) & mask)
}

fn v6_in(a: Ipv6Addr, net: Ipv6Addr, len: u32) -> bool {
    let mask = if len == 0 { 0 } else { u128::MAX << 128u32.saturating_sub(len) };
    (u128::from(a) & mask) == (u128::from(net) & mask)
}

const fn v6(s: [u16; 8]) -> Ipv6Addr {
    Ipv6Addr::new(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7])
}

/// Classify an IPv4 address.
pub fn classify_v4(a: Ipv4Addr) -> AddrClass {
    use AddrClass::*;
    let o = a.octets();
    if o == [169, 254, 169, 254] || o == [169, 254, 170, 2] || o == [100, 100, 100, 200] {
        return Metadata;
    }
    if o == [0, 0, 0, 0] {
        return Unspecified;
    }
    if o == [255, 255, 255, 255] {
        return Broadcast;
    }
    let table: &[([u8; 4], u32, AddrClass)] = &[
        ([0, 0, 0, 0], 8, ThisNetwork),
        ([10, 0, 0, 0], 8, Private),
        ([100, 64, 0, 0], 10, SharedAddressSpace),
        ([127, 0, 0, 0], 8, Loopback),
        ([169, 254, 0, 0], 16, LinkLocal),
        ([172, 16, 0, 0], 12, Private),
        ([192, 0, 0, 0], 24, Reserved),
        ([192, 0, 2, 0], 24, Documentation),
        ([192, 88, 99, 0], 24, Reserved),
        ([192, 168, 0, 0], 16, Private),
        ([198, 18, 0, 0], 15, Benchmarking),
        ([198, 51, 100, 0], 24, Documentation),
        ([203, 0, 113, 0], 24, Documentation),
        ([224, 0, 0, 0], 4, Multicast),
        ([240, 0, 0, 0], 4, Reserved),
    ];
    for (net, len, class) in table {
        if v4_in(a, *net, *len) {
            return *class;
        }
    }
    Public
}

fn embedded_v4(a: Ipv6Addr, byte_offset: usize) -> Ipv4Addr {
    let o = a.octets();
    let b = |i: usize| o.get(byte_offset.saturating_add(i)).copied().unwrap_or(0);
    Ipv4Addr::new(b(0), b(1), b(2), b(3))
}

/// Classify an IPv6 address.
pub fn classify_v6(a: Ipv6Addr) -> AddrClass {
    use AddrClass::*;
    if a == v6([0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]) {
        return Metadata;
    }
    if a.is_unspecified() {
        return Unspecified;
    }
    if a.is_loopback() {
        return Loopback;
    }
    if v6_in(a, v6([0, 0, 0, 0, 0, 0xffff, 0, 0]), 96) {
        return Ipv4Mapped;
    }
    if v6_in(a, Ipv6Addr::UNSPECIFIED, 96) {
        return Ipv4Compatible;
    }
    if v6_in(a, v6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0]), 96) {
        return if classify_v4(embedded_v4(a, 12)) == Public { Public } else { Nat64 };
    }
    if v6_in(a, v6([0x64, 0xff9b, 1, 0, 0, 0, 0, 0]), 48) {
        return Nat64LocalUse;
    }
    if v6_in(a, v6([0xff00, 0, 0, 0, 0, 0, 0, 0]), 8) {
        return Multicast;
    }
    if v6_in(a, v6([0xfe80, 0, 0, 0, 0, 0, 0, 0]), 10) {
        return LinkLocal;
    }
    if v6_in(a, v6([0xfec0, 0, 0, 0, 0, 0, 0, 0]), 10) {
        return SiteLocal;
    }
    if v6_in(a, v6([0xfc00, 0, 0, 0, 0, 0, 0, 0]), 7) {
        return UniqueLocal;
    }
    if !v6_in(a, v6([0x2000, 0, 0, 0, 0, 0, 0, 0]), 3) {
        return Reserved; // not global unicast: includes 100::/64 (discard) and 5f00::/16 (SRv6 SIDs)
    }
    if v6_in(a, v6([0x2001, 0, 0, 0, 0, 0, 0, 0]), 32) {
        return Teredo;
    }
    if v6_in(a, v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0]), 32) || v6_in(a, v6([0x3fff, 0, 0, 0, 0, 0, 0, 0]), 20) {
        return Documentation;
    }
    if v6_in(a, v6([0x2001, 0x0002, 0, 0, 0, 0, 0, 0]), 48) {
        return Benchmarking;
    }
    if v6_in(a, v6([0x2001, 0, 0, 0, 0, 0, 0, 0]), 23) {
        return Reserved; // IETF protocol assignments (ORCHID, AMT, AS112, ...)
    }
    if v6_in(a, v6([0x2002, 0, 0, 0, 0, 0, 0, 0]), 16) {
        return if classify_v4(embedded_v4(a, 2)) == Public { Public } else { SixToFour };
    }
    Public
}

/// Classify any IP address.
pub fn classify(a: IpAddr) -> AddrClass {
    match a {
        IpAddr::V4(v) => classify_v4(v),
        IpAddr::V6(v) => classify_v6(v),
    }
}

/// An address prefix (`addr/len`) used for policy re-admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    addr: IpAddr,
    len: u8,
}

impl Prefix {
    /// A prefix; `None` if `len` exceeds the family width.
    pub fn new(addr: IpAddr, len: u8) -> Option<Self> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (len <= max).then_some(Self { addr, len })
    }

    /// Parse `a.b.c.d/n` or `v6/n` (a bare address means a host prefix).
    pub fn parse(s: &str) -> Option<Self> {
        let (a, l) = match s.split_once('/') {
            Some((a, l)) => {
                if l.is_empty() || l.len() > 3 || !l.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                (a, l.parse::<u8>().ok()?)
            }
            None => (s, if s.contains(':') { 128 } else { 32 }),
        };
        Self::new(a.parse().ok()?, l)
    }

    /// Whether `a` is inside this prefix (same family only).
    pub fn contains(&self, a: IpAddr) -> bool {
        match (self.addr, a) {
            (IpAddr::V4(n), IpAddr::V4(x)) => v4_in(x, n.octets(), u32::from(self.len)),
            (IpAddr::V6(n), IpAddr::V6(x)) => v6_in(x, n, u32::from(self.len)),
            _ => false,
        }
    }
}
