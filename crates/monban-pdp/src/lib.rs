//! Out-of-process Cedar PDP (DEVIATIONS X-8). Cedar 4.14 runs here, never in monban-bin: the policy set and schema
//! are validated at startup (refuse to start on any error) and requests arrive over the PDP-1 wire
//! (`monban_authz::pdp`, SOCK_SEQPACKET). The host maps timeout/crash/garbage to `Decision::Error` ⇒ Deny.
#![forbid(unsafe_code)]

pub mod engine;
pub mod server;
/// The PDP-1 socket plumbing, owned by the L4 host crate (monban-bin uses the same client without Cedar).
pub use monban_adapter_host::pdp_uds as uds;

/// Lowercase hex decoding for the probe and eval input lines.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let b = s.trim().as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    b.chunks(2)
        .map(|p| match p {
            [h, l] => Some((nib(*h)? << 4) | nib(*l)?),
            _ => None,
        })
        .collect()
}

fn nib(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Upper-case decision word used on every text interface.
pub fn word(d: monban_types::Decision) -> &'static str {
    match d {
        monban_types::Decision::Allow => "ALLOW",
        monban_types::Decision::Deny => "DENY",
        monban_types::Decision::Error => "ERROR",
    }
}
