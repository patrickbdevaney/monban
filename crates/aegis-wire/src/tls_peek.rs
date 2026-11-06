//! Bounded TLS ClientHello peek (F1 L4-1; the `trust_anchors` input of SEL-1, PREFLIGHT D-P7.4).
//!
//! Stub (P7-spec-002): [`client_hello`] refuses every input with [`PeekError::Unimplemented`]. P7-wire-001 replaces
//! it with the real peek: one handshake record of at most [`MAX_RECORD`] bytes, no allocation, every field a slice
//! of the input.

use core::fmt;

/// The largest TLS record body the peek reads (F1 L4-1: at most one ClientHello record, <= 16 KiB).
pub const MAX_RECORD: usize = 16 * 1024;

/// What the peek extracts. Each field borrows the raw extension body from the input (no allocation); an absent
/// extension is `None`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peek<'a> {
    /// server_name: the host_name bytes of the single name entry.
    pub sni: Option<&'a [u8]>,
    /// application_layer_protocol_negotiation: the ProtocolNameList body.
    pub alpn: Option<&'a [u8]>,
    /// supported_versions: the version list body.
    pub versions: Option<&'a [u8]>,
    /// signature_algorithms: the SignatureSchemeList body.
    pub sigalgs: Option<&'a [u8]>,
    /// trust_anchors (draft-ietf-tls-trust-anchor-ids): the TrustAnchorIDList body.
    pub trust_anchors: Option<&'a [u8]>,
}

/// Why a peek failed. Every variant closes the connection (F1 L4-1: never a default upstream).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeekError {
    /// Not built yet (P7-spec-002 stub): fail closed.
    Unimplemented,
    /// Fewer bytes than the record declares.
    Incomplete,
    /// Record body over [`MAX_RECORD`].
    TooLong,
    /// Not a handshake record carrying a ClientHello.
    NotClientHello,
    /// Anything else that is not a well-formed ClientHello.
    Malformed,
}

impl fmt::Display for PeekError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PeekError::Unimplemented => "ClientHello peek not built (fail closed)",
            PeekError::Incomplete => "ClientHello record incomplete",
            PeekError::TooLong => "ClientHello record over 16 KiB",
            PeekError::NotClientHello => "not a TLS ClientHello",
            PeekError::Malformed => "malformed ClientHello",
        })
    }
}

/// Peek at the ClientHello record at the start of `input`.
///
/// Stub: always `Err(PeekError::Unimplemented)`.
pub fn client_hello(input: &[u8]) -> Result<Peek<'_>, PeekError> {
    let _ = input;
    Err(PeekError::Unimplemented)
}
