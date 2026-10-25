//! ACME Renewal Information (RFC 9773). certID construction (§4.1), the renewalInfo response (§4.2) and the
//! client's choice of renewal time (§4.3: a uniform random time inside the suggested window; renew now if that is in
//! the past; re-fetch after Retry-After, clamped to client-side limits).

use std::string::String;

use aegis_canon::{JsonValue, parse_json};

use super::AcmeError;
use super::json::{get, get_str};
use crate::cert::b64::b64url_encode;
use crate::cert::time::parse_rfc3339;
use crate::cert::x509::parse_cert;

/// RFC 9773 §4.1: `base64url(AKI keyIdentifier) "." base64url(serial INTEGER contents)`.
pub fn cert_id(leaf_der: &[u8]) -> Result<String, AcmeError> {
    let c = parse_cert(leaf_der).map_err(|e| AcmeError::Malformed(e.0))?;
    let aki = c.aki.ok_or(AcmeError::Malformed("certificate has no authorityKeyIdentifier keyIdentifier"))?;
    Ok(std::format!("{}.{}", b64url_encode(aki), b64url_encode(c.serial)))
}

/// A parsed renewalInfo response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenewalInfo {
    /// suggestedWindow.start (Unix seconds).
    pub start: i64,
    /// suggestedWindow.end (Unix seconds), > start.
    pub end: i64,
    /// explanationURL, if given.
    pub explanation_url: Option<String>,
    /// Retry-After seconds from the response, if any.
    pub retry_after: Option<u64>,
}

/// Parse a renewalInfo body (RFC 9773 §4.2). A window whose end is not after its start is invalid.
pub fn parse_renewal_info(body: &[u8], retry_after: Option<u64>) -> Result<RenewalInfo, AcmeError> {
    let v = parse_json(body).map_err(|r| AcmeError::Json(r.reason()))?;
    let w = get(&v, "suggestedWindow").ok_or(AcmeError::Malformed("renewalInfo without suggestedWindow"))?;
    if !matches!(w, JsonValue::Object(_)) {
        return Err(AcmeError::Malformed("suggestedWindow is not an object"));
    }
    let start = get_str(w, "start").and_then(parse_rfc3339).ok_or(AcmeError::Malformed("suggestedWindow.start"))?;
    let end = get_str(w, "end").and_then(parse_rfc3339).ok_or(AcmeError::Malformed("suggestedWindow.end"))?;
    if end <= start {
        return Err(AcmeError::Malformed("suggestedWindow end is not after start"));
    }
    Ok(RenewalInfo { start, end, explanation_url: get_str(&v, "explanationURL").map(String::from), retry_after })
}

/// RFC 9773 §4.3: a uniform random time in `[start, end)` from `rand`.
pub fn choose_renewal_time(info: &RenewalInfo, rand: u64) -> i64 {
    let span = u64::try_from(info.end.saturating_sub(info.start)).unwrap_or(0);
    if span == 0 {
        return info.start;
    }
    info.start.saturating_add(i64::try_from(rand % span).unwrap_or(0))
}

/// Without ARI: renew when a third of the lifetime remains (the same point Pebble and Let's Encrypt suggest).
pub fn fallback_renewal_time(not_before: i64, not_after: i64) -> i64 {
    not_after.saturating_sub(not_after.saturating_sub(not_before) / 3)
}

/// Clamp a Retry-After to `[min, max]` seconds (RFC 9773 §4.3: "Clients MUST set reasonable limits").
pub fn clamp_retry(retry_after: Option<u64>, min: u64, max: u64, default: u64) -> u64 {
    retry_after.unwrap_or(default).clamp(min, max.max(min))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::cert::testutil::pki;

    #[test]
    fn cert_id_rfc9773_shape() {
        let p = pki(1_000_000, 2_000_000, false);
        // AKI keyIdentifier 090909, serial INTEGER contents 008001 (leading zero kept, §4.1).
        assert_eq!(cert_id(p.chain[0].as_ref()).unwrap(), "CQkJ.AIAB");
        assert!(cert_id(p.chain[1].as_ref()).is_err(), "no AKI ⇒ error, not a guess");
    }

    /// RFC 9773 Appendix A certificate; §4.1 gives its certID as `aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE`.
    const RFC9773_APPENDIX_A: &str = "-----BEGIN CERTIFICATE-----
MIIBQzCB66ADAgECAgUAh2VDITAKBggqhkjOPQQDAjAVMRMwEQYDVQQDEwpFeGFt
cGxlIENBMCIYDzAwMDEwMTAxMDAwMDAwWhgPMDAwMTAxMDEwMDAwMDBaMBYxFDAS
BgNVBAMTC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeBZu
7cbpAYNXZLbbh8rNIzuOoqOOtmxA1v7cRm//AwyMwWxyHz4zfwmBhcSrf47NUAFf
qzLQ2PPQxdTXREYEnKMjMCEwHwYDVR0jBBgwFoAUaYhba4dGQEHhs3uEe6CuLN4B
yNQwCgYIKoZIzj0EAwIDRwAwRAIge09+S5TZAlw5tgtiVvuERV6cT4mfutXIlwTb
+FYN/8oCIClDsqBklhB9KAelFiYt9+6FDj3z4KGVelYM5MdsO3pK
-----END CERTIFICATE-----
";

    #[test]
    fn rfc9773_appendix_a_cert_id() {
        let ders = crate::cert::x509::pem_certificates(RFC9773_APPENDIX_A).unwrap();
        assert_eq!(cert_id(&ders[0]).unwrap(), "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE");
    }

    #[test]
    fn window_parse_and_choice() {
        let b = br#"{"suggestedWindow":{"start":"2026-10-25T00:00:00Z","end":"2026-10-27T00:00:00.5Z"},"explanationURL":"https://ca/why"}"#;
        let i = parse_renewal_info(b, Some(21600)).unwrap();
        assert_eq!(i.end - i.start, 2 * 86_400);
        assert_eq!(i.explanation_url.as_deref(), Some("https://ca/why"));
        for r in [0u64, 1, 86_400, u64::MAX] {
            let t = choose_renewal_time(&i, r);
            assert!(t >= i.start && t < i.end);
        }
        assert!(
            parse_renewal_info(
                br#"{"suggestedWindow":{"start":"2026-10-27T00:00:00Z","end":"2026-10-25T00:00:00Z"}}"#,
                None
            )
            .is_err()
        );
        assert!(
            parse_renewal_info(br#"{"suggestedWindow":{"start":"x","end":"2026-10-25T00:00:00Z"}}"#, None).is_err()
        );
        assert!(parse_renewal_info(br#"{"suggestedWindow":1}"#, None).is_err());
        assert!(parse_renewal_info(b"{", None).is_err());
        assert_eq!(fallback_renewal_time(0, 90), 60);
        assert_eq!(clamp_retry(Some(21_600), 60, 86_400, 3600), 21_600);
        assert_eq!(clamp_retry(Some(10 * 86_400), 60, 86_400, 3600), 86_400);
        assert_eq!(clamp_retry(None, 0, 1, 3600), 1);
    }
}
