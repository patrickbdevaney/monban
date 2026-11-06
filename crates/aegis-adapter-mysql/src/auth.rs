//! Authentication plugins.
//!
//! Only `mysql_native_password` is spoken: `SHA1(pw) XOR SHA1(salt ‖ SHA1(SHA1(pw)))` over the 20-byte scramble
//! (aws-lc-rs SHA-1, legacy-use API; the protocol fixes the hash). `caching_sha2_password` is refused with
//! [`crate::MysqlError::CachingSha2Refused`]: its full-authentication path sends the password in cleartext over TLS
//! or RSA-encrypted, and this client has neither yet (PREFLIGHT D-P7.8). Every other plugin (including
//! `mysql_clear_password`, `client_ed25519`, `auth_gssapi_client`, `mysql_old_password`) is refused.

use aws_lc_rs::digest;

pub const NATIVE: &str = "mysql_native_password";
pub const CACHING_SHA2: &str = "caching_sha2_password";

fn sha1(parts: &[&[u8]]) -> digest::Digest {
    let mut c = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    for p in parts {
        c.update(p);
    }
    c.finish()
}

/// The mysql_native_password response for `password` over the 20-byte `salt` (empty password: empty response).
pub fn native_scramble(password: &[u8], salt: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let h1 = sha1(&[password]);
    let h2 = sha1(&[h1.as_ref()]);
    let h3 = sha1(&[salt, h2.as_ref()]);
    h1.as_ref().iter().zip(h3.as_ref()).map(|(a, b)| a ^ b).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn native_kat() {
        // Python hashlib reference (spikes/q4-005 mywire.native_scramble) for password "secret", salt 0x01..0x14.
        let salt: Vec<u8> = (1u8..=20).collect();
        let got: String = native_scramble(b"secret", &salt).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, "b32bb3a583e1340c0a1108d58b1be49781ad8c2f");
        assert!(native_scramble(b"", &salt).is_empty());
    }
}
