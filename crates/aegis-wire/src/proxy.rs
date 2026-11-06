//! PROXY protocol v2 header parser (F1 PROXY-1..3).
//!
//! Stub (P7-spec-002): [`parse_v2`] refuses every input with [`ProxyError::Unimplemented`]. P7-wire-001 replaces
//! it with the real parser: v1 refused, declared length over [`MAX_DECLARED_LEN`] refused, `consumed <= input.len()`.

use core::fmt;
use core::net::SocketAddr;

/// The 12-byte v2 signature (proxy-protocol.txt §2.2).
pub const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";

/// The largest declared address+TLV length accepted (F1 PROXY-3); anything larger closes the connection.
pub const MAX_DECLARED_LEN: usize = 536;

/// The v2 command nibble.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// LOCAL: the connection was made by the proxy itself (health check); the real peer address is kept.
    Local,
    /// PROXY: the addresses below are the original client's.
    Proxy,
}

/// The address block of a v2 header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Addresses {
    /// AF_UNSPEC (or LOCAL): no address carried.
    Unspec,
    /// TCP or UDP over IPv4 / IPv6.
    Inet { src: SocketAddr, dst: SocketAddr },
    /// AF_UNIX: the address block is present but not used for admission.
    Unix,
}

/// A parsed v2 header. TLVs stay in the input; the parser only bounds them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub command: Command,
    pub addresses: Addresses,
}

/// Why a header was refused. Every variant closes the connection (F1 PROXY-1, PROXY-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyError {
    /// Not built yet (P7-spec-002 stub): fail closed.
    Unimplemented,
    /// Fewer bytes than the header declares.
    Incomplete,
    /// A v1 (text) header: refused, never parsed.
    V1Refused,
    /// Declared length over [`MAX_DECLARED_LEN`].
    TooLong,
    /// Anything else that is not a well-formed v2 header.
    Malformed,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ProxyError::Unimplemented => "PROXY v2 parser not built (fail closed)",
            ProxyError::Incomplete => "PROXY v2 header incomplete",
            ProxyError::V1Refused => "PROXY v1 header refused",
            ProxyError::TooLong => "PROXY v2 declared length over 536",
            ProxyError::Malformed => "malformed PROXY v2 header",
        })
    }
}

/// Parse one v2 header at the start of `input`. On success, returns the header and the number of bytes it occupies.
///
/// Stub: always `Err(ProxyError::Unimplemented)`.
pub fn parse_v2(input: &[u8]) -> Result<(Header, usize), ProxyError> {
    let _ = input;
    Err(ProxyError::Unimplemented)
}
