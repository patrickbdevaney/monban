//! Out-of-process Cedar PDP (DEVIATIONS X-8). Cedar 4.14 runs here, never in aegis-bin: the policy set and schema
//! are validated at startup (refuse to start on any error) and requests arrive over the PDP-1 wire
//! (`aegis_authz::pdp`, SOCK_SEQPACKET). The host maps timeout/crash/garbage to `Decision::Error` ⇒ Deny.
#![forbid(unsafe_code)]

pub mod engine;
pub mod server;
pub mod uds;

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
pub fn word(d: aegis_types::Decision) -> &'static str {
    match d {
        aegis_types::Decision::Allow => "ALLOW",
        aegis_types::Decision::Deny => "DENY",
        aegis_types::Decision::Error => "ERROR",
    }
}
