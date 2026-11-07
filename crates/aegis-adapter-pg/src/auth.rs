//! SCRAM-SHA-256 client (RFC 5802 / RFC 7677) as PostgreSQL uses it, on aws-lc-rs HMAC / SHA-256 / PBKDF2 /
//! CSPRNG (DEVIATIONS X-10: no second crypto stack).
//!
//! PostgreSQL specifics: the username in client-first is empty (`n=`; the server uses the startup user), there is
//! no channel binding without TLS (gs2 header `n,,`), and the server signature in server-final is verified in
//! constant time before AuthenticationOk is accepted (the connection layer refuses an AuthenticationOk that arrives
//! mid-exchange). Cleartext and MD5 are never offered by this client (refused in the connection layer).
//!
//! Limits (fail closed): iteration count in `[MIN_ITERATIONS, MAX_ITERATIONS]` (CPU bound against a hostile server),
//! salt 1..=`MAX_SALT` bytes, server messages ≤ `MAX_SERVER_MESSAGE` bytes, server nonce printable and longer than
//! ours, no mandatory extensions (`m=`). The password goes through SASLprep (RFC 4013) exactly as PostgreSQL applies
//! it ([`crate::saslprep`], PREFLIGHT R14): ASCII as is, otherwise mapped, NFKC-normalized and checked, with the raw
//! bytes when SASLprep prohibits the string (libpq and the server both fall back to them). A password whose prepared
//! form this client cannot determine exactly (a code point unassigned in its Unicode tables, or a verdict that
//! depends on the check order) is refused ([`ScramError::SaslPrep`]) rather than guessed.

use aws_lc_rs::{constant_time, digest, hmac, pbkdf2, rand};
use std::fmt;
use std::num::NonZeroU32;

pub const MECHANISM: &str = "SCRAM-SHA-256";
/// RFC 7677 §4: at least 4096.
pub const MIN_ITERATIONS: u32 = 4096;
/// Upper bound on server-chosen PBKDF2 work (about 0.5 s on a laptop core).
pub const MAX_ITERATIONS: u32 = 1_000_000;
pub const MAX_SALT: usize = 1024;
pub const MAX_SERVER_MESSAGE: usize = 4096;
const NONCE_BYTES: usize = 18;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScramError {
    /// SASLprep could not prepare the password exactly (see [`crate::saslprep::Prep::Ambiguous`]).
    SaslPrep(&'static str),
    Rng,
    Malformed(&'static str),
    NonceMismatch,
    IterationsOutOfRange(u32),
    /// The server sent `e=<reason>` in server-final.
    Server(String),
    BadServerSignature,
}

impl fmt::Display for ScramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScramError::SaslPrep(why) => write!(f, "SCRAM: password refused by SASLprep ({why})"),
            ScramError::Rng => write!(f, "SCRAM: CSPRNG failure"),
            ScramError::Malformed(w) => write!(f, "SCRAM: malformed server message ({w})"),
            ScramError::NonceMismatch => write!(f, "SCRAM: server nonce does not extend the client nonce"),
            ScramError::IterationsOutOfRange(i) => {
                write!(f, "SCRAM: iteration count {i} outside [{MIN_ITERATIONS}, {MAX_ITERATIONS}]")
            }
            ScramError::Server(e) => write!(f, "SCRAM: server error {:?}", e.escape_debug().to_string()),
            ScramError::BadServerSignature => {
                write!(f, "SCRAM: server signature mismatch (server does not know the password)")
            }
        }
    }
}

impl std::error::Error for ScramError {}

/// Client state after client-first was produced.
pub struct ScramClient {
    password: Vec<u8>,
    client_first_bare: String,
    client_nonce: String,
}

impl fmt::Debug for ScramClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScramClient").field("client_nonce", &self.client_nonce).finish_non_exhaustive()
    }
}

/// State after client-final was produced: holds the expected server signature.
pub struct ScramAwaitFinal {
    server_signature: [u8; 32],
}

impl fmt::Debug for ScramAwaitFinal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScramAwaitFinal").finish_non_exhaustive()
    }
}

impl ScramClient {
    /// Fresh client with a random nonce. Returns the client and the full client-first message (`n,,n=,r=...`).
    pub fn new(password: &str) -> Result<(ScramClient, String), ScramError> {
        let mut raw = [0u8; NONCE_BYTES];
        rand::SecureRandom::fill(&rand::SystemRandom::new(), &mut raw).map_err(|_| ScramError::Rng)?;
        ScramClient::with_nonce(password, "", &b64_encode(&raw))
    }

    /// Deterministic constructor (tests / RFC vectors). `username` is the SCRAM `n=` value (empty for PostgreSQL).
    pub fn with_nonce(password: &str, username: &str, nonce: &str) -> Result<(ScramClient, String), ScramError> {
        let password = crate::saslprep::scram_password(password).map_err(ScramError::SaslPrep)?;
        let client_first_bare = format!("n={username},r={nonce}");
        let first = format!("n,,{client_first_bare}");
        Ok((ScramClient { password, client_first_bare, client_nonce: nonce.to_owned() }, first))
    }

    /// Consume server-first, produce client-final (`c=biws,r=...,p=...`).
    pub fn server_first(self, server_first: &[u8]) -> Result<(ScramAwaitFinal, String), ScramError> {
        if server_first.len() > MAX_SERVER_MESSAGE {
            return Err(ScramError::Malformed("server-first too long"));
        }
        let sf = std::str::from_utf8(server_first).map_err(|_| ScramError::Malformed("server-first not UTF-8"))?;
        let mut parts = sf.split(',');
        let nonce = parts.next().and_then(|p| p.strip_prefix("r=")).ok_or(ScramError::Malformed("no r="))?;
        let salt_b64 = parts.next().and_then(|p| p.strip_prefix("s=")).ok_or(ScramError::Malformed("no s="))?;
        let iter_s = parts.next().and_then(|p| p.strip_prefix("i=")).ok_or(ScramError::Malformed("no i="))?;
        // Optional extensions after i= are allowed only if not mandatory (RFC 5802 §5.1: m= must be refused).
        for ext in parts {
            if ext.starts_with("m=") || ext.len() < 2 || ext.as_bytes().get(1) != Some(&b'=') {
                return Err(ScramError::Malformed("unsupported extension"));
            }
        }
        if nonce.len() <= self.client_nonce.len() || !nonce.starts_with(&self.client_nonce) {
            return Err(ScramError::NonceMismatch);
        }
        if !nonce.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b',') {
            return Err(ScramError::Malformed("nonce not printable"));
        }
        let salt = b64_decode(salt_b64).ok_or(ScramError::Malformed("salt not base64"))?;
        if salt.is_empty() || salt.len() > MAX_SALT {
            return Err(ScramError::Malformed("salt length"));
        }
        if iter_s.is_empty() || !iter_s.bytes().all(|b| b.is_ascii_digit()) || iter_s.len() > 10 {
            return Err(ScramError::Malformed("iteration count"));
        }
        let iters: u32 = iter_s.parse().map_err(|_| ScramError::Malformed("iteration count"))?;
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iters) {
            return Err(ScramError::IterationsOutOfRange(iters));
        }
        let iterations = NonZeroU32::new(iters).ok_or(ScramError::IterationsOutOfRange(iters))?;

        let mut salted = [0u8; 32];
        pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, iterations, &salt, &self.password, &mut salted);
        let salted_key = hmac::Key::new(hmac::HMAC_SHA256, &salted);
        let client_key = hmac::sign(&salted_key, b"Client Key");
        let stored_key = digest::digest(&digest::SHA256, client_key.as_ref());
        let cfwp = format!("c=biws,r={nonce}");
        let auth_message = format!("{},{sf},{cfwp}", self.client_first_bare);
        let client_sig = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, stored_key.as_ref()), auth_message.as_bytes());
        let proof: Vec<u8> = client_key.as_ref().iter().zip(client_sig.as_ref()).map(|(a, b)| a ^ b).collect();
        let server_key = hmac::sign(&salted_key, b"Server Key");
        let server_sig = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, server_key.as_ref()), auth_message.as_bytes());
        let mut server_signature = [0u8; 32];
        if server_sig.as_ref().len() != server_signature.len() {
            return Err(ScramError::Malformed("digest length"));
        }
        server_signature.copy_from_slice(server_sig.as_ref());
        Ok((ScramAwaitFinal { server_signature }, format!("{cfwp},p={}", b64_encode(&proof))))
    }
}

impl ScramAwaitFinal {
    /// Verify server-final (`v=<base64 signature>`), constant-time compare.
    pub fn server_final(self, server_final: &[u8]) -> Result<(), ScramError> {
        if server_final.len() > MAX_SERVER_MESSAGE {
            return Err(ScramError::Malformed("server-final too long"));
        }
        let s = std::str::from_utf8(server_final).map_err(|_| ScramError::Malformed("server-final not UTF-8"))?;
        if let Some(e) = s.strip_prefix("e=") {
            return Err(ScramError::Server(e.chars().take(200).collect()));
        }
        let v = s.split(',').next().and_then(|p| p.strip_prefix("v=")).ok_or(ScramError::Malformed("no v="))?;
        let sig = b64_decode(v).ok_or(ScramError::Malformed("signature not base64"))?;
        constant_time::verify_slices_are_equal(&sig, &self.server_signature).map_err(|_| ScramError::BadServerSignature)
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding.
pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let sym = |i: u32| char::from(B64.get((i & 63) as usize).copied().unwrap_or(b'A'));
    for chunk in data.chunks(3) {
        let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let n = (b(0) << 16) | (b(1) << 8) | b(2);
        out.push(sym(n >> 18));
        out.push(sym(n >> 12));
        out.push(if chunk.len() > 1 { sym(n >> 6) } else { '=' });
        out.push(if chunk.len() > 2 { sym(n) } else { '=' });
    }
    out
}

/// Strict standard base64 with mandatory padding; `None` on any deviation (including non-zero trailing bits).
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let val = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let n_chunks = bytes.len() / 4;
    for (idx, chunk) in bytes.chunks(4).enumerate() {
        let last = idx + 1 == n_chunks;
        let &[c0, c1, c2, c3] = chunk else { return None };
        let pad = match (c2, c3) {
            (b'=', b'=') if last => 2,
            (_, b'=') if last && c2 != b'=' => 1,
            _ => 0,
        };
        let a = val(c0)?;
        let b = val(c1)?;
        let c = if pad >= 2 { 0 } else { val(c2)? };
        let d = if pad >= 1 { 0 } else { val(c3)? };
        let n = (a << 18) | (b << 12) | (c << 6) | d;
        out.push((n >> 16) as u8);
        match pad {
            0 => {
                out.push((n >> 8) as u8);
                out.push(n as u8);
            }
            1 => {
                if n & 0xff != 0 {
                    return None;
                }
                out.push((n >> 8) as u8);
            }
            _ => {
                if n & 0xffff != 0 {
                    return None;
                }
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7677_vector() {
        let (c, first) =
            ScramClient::with_nonce("pencil", "user", "rOprNGfwEbeRWgbNEkqO").unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(first, "n,,n=user,r=rOprNGfwEbeRWgbNEkqO");
        let sf = b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let (fin, cf) = c.server_first(sf).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(
            cf,
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        assert_eq!(fin.server_final(b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="), Ok(()));
    }

    #[test]
    fn hostile_server_messages_refused() {
        let mk = || ScramClient::with_nonce("pencil", "", "abc").unwrap_or_else(|e| unreachable!("{e}")).0;
        let bad: [&[u8]; 9] = [
            b"r=abc,s=QUJD,i=4096",         // nonce not extended
            b"r=xyzdef,s=QUJD,i=4096",      // nonce not ours
            b"r=abcd,s=QUJD,i=1",           // too few iterations
            b"r=abcd,s=QUJD,i=99999999999", // overflow
            b"r=abcd,s=,i=4096",            // empty salt
            b"r=abcd,s=QUJ,i=4096",         // bad base64
            b"r=abcd,s=QUJD,i=4096,m=x",    // mandatory extension
            b"s=QUJD,r=abcd,i=4096",        // order
            b"r=abcd,s=QUJD",               // missing i
        ];
        for b in bad {
            assert!(mk().server_first(b).is_err(), "{}", String::from_utf8_lossy(b));
        }
        let (fin, _) = mk().server_first(b"r=abcd,s=QUJD,i=4096").unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(fin.server_final(b"v=AAAA"), Err(ScramError::BadServerSignature));
    }

    /// SASLprep (RFC 4013) on the SaltedPassword input: equivalent spellings give the same proof, a prohibited string
    /// is hashed raw, an input the client cannot prepare exactly is refused.
    #[test]
    fn saslprep_applied_to_the_password() {
        let proof = |pw: &str| -> Result<String, ScramError> {
            let (c, _) = ScramClient::with_nonce(pw, "", "abc")?;
            let (_, cf) = c.server_first(b"r=abcd,s=QUJD,i=4096")?;
            Ok(cf)
        };
        let pre = proof("p\u{E4}ssword");
        assert!(pre.is_ok(), "non-ASCII password accepted: {pre:?}");
        assert_eq!(pre, proof("pa\u{308}ssword"), "NFKC: decomposed and precomposed spell one password");
        assert_eq!(proof("I\u{AD}X"), proof("IX"), "soft hyphen mapped to nothing");
        assert_eq!(proof("\u{2168}"), proof("IX"), "compatibility form normalized");
        assert!(proof("\u{627}1").is_ok(), "a prohibited (bidi) string is hashed raw, not refused");
        assert_eq!(crate::saslprep::scram_password("\u{627}1"), Ok("\u{627}1".as_bytes().to_vec()));
        assert!(matches!(ScramClient::with_nonce("\u{378}x", "", "abc"), Err(ScramError::SaslPrep(_))));
    }

    #[test]
    fn base64_roundtrip_and_strictness() {
        for n in 0..40usize {
            let d: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(b64_decode(&b64_encode(&d)), Some(d));
        }
        for bad in ["A", "AB==A===", "QUI=QUI=", "QR==", "QUJ=x", "Q===", "====", "QU=D"] {
            assert_eq!(b64_decode(bad), None, "{bad}");
        }
    }
}
