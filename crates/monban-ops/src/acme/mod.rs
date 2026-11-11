//! In-house ACME client (RFC 8555) with ACME Renewal Information (RFC 9773), DEVIATIONS X-6. Feature `acme`.
//!
//! * [`AcmeClient`]: directory, `newNonce` / `Replay-Nonce` handling with `badNonce` retry (RFC 8555 §6.5),
//!   JWS ES256 requests ([`jws`], §6.2), `newAccount` (§7.3), `newOrder` (§7.4) with the ARI `replaces` field
//!   (RFC 9773 §5), authorizations with HTTP-01 (§8.3; tokens published through a [`ChallengeResponder`] the
//!   server wires, e.g. [`Http01Tokens`]), finalize with an in-crate CSR ([`csr`]), polling bounded by
//!   [`PollBounds`] (Retry-After honoured and clamped, total deadline), certificate download as
//!   `application/pem-certificate-chain` (§7.4.2), and `renewalInfo` fetch ([`ari`]).
//! * TLS-ALPN-01 (RFC 8737) is not implemented: the client only answers `http-01` and fails closed with
//!   [`AcmeError::NoSupportedChallenge`] otherwise.
//! * Every response is size-capped ([`http::Limits`]) and every JSON body goes through `monban_canon::parse_json`.
//!   Total: no `unwrap`/indexing; every failure is an [`AcmeError`].
//! * The rustls `ClientConfig` ([`tls::client_config`]) exists only in this feature (spikes/cmvp-client-policy).
#![cfg(feature = "acme")]

pub mod ari;
pub mod csr;
pub mod http;
pub mod json;
pub mod jws;
pub mod tls;

// PREFLIGHT R11: `Faults` (oracle self-test fault injection) exists only with feature `test-faults`, which no release
// graph enables (gate no-test-faults, ci/no-test-faults.py). Without it the fault predicates are constant `false`.
#[cfg(feature = "test-faults")]
mod faults;
#[cfg(feature = "test-faults")]
pub use self::faults::Faults;
#[cfg(feature = "test-faults")]
use self::faults::{csr_wrong_identifier, replay_nonce, wrong_jws_key};
#[cfg(not(feature = "test-faults"))]
use self::no_test_faults::{csr_wrong_identifier, replay_nonce, wrong_jws_key};

use std::string::String;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use std::vec::Vec;

use monban_canon::{JsonValue, parse_json};
use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use self::http::{Limits, Response, Url};
use self::json::{get_array, get_str, quote};
use self::jws::{AccountKey, KeyId};
use crate::cert::b64::b64url_encode;
use crate::cert::time::parse_http_date;
use crate::cert::x509::pem_certificates;

/// ACME failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcmeError {
    /// Socket / DNS failure.
    Io(String),
    /// TLS configuration or handshake failure.
    Tls(String),
    /// Not an acceptable `https://` URL.
    BadUrl(String),
    /// HTTP framing violation.
    Protocol(&'static str),
    /// A size cap was hit.
    TooLarge(&'static str),
    /// A body was not strict I-JSON.
    Json(&'static str),
    /// A required field is missing or malformed.
    Malformed(&'static str),
    /// Key generation / signing failure.
    Crypto(&'static str),
    /// An identifier this client does not request (see [`csr::valid_dns_name`]).
    BadIdentifier,
    /// The server answered with an RFC 7807 problem document (RFC 8555 §6.7).
    Problem {
        /// HTTP status.
        status: u16,
        /// Problem `type` (e.g. `urn:ietf:params:acme:error:badNonce`).
        kind: String,
        /// Problem `detail`.
        detail: String,
    },
    /// No `http-01` challenge offered.
    NoSupportedChallenge,
    /// An authorization or order became `invalid`.
    Invalid(String),
    /// The polling deadline passed.
    Timeout(&'static str),
}

impl core::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Tls(e) => write!(f, "tls: {e}"),
            Self::BadUrl(u) => write!(f, "bad url: {u}"),
            Self::Protocol(e) => write!(f, "http: {e}"),
            Self::TooLarge(e) => write!(f, "too large: {e}"),
            Self::Json(e) => write!(f, "json: {e}"),
            Self::Malformed(e) => write!(f, "malformed: {e}"),
            Self::Crypto(e) => write!(f, "crypto: {e}"),
            Self::BadIdentifier => write!(f, "identifier not acceptable"),
            Self::Problem { status, kind, detail } => write!(f, "problem {status} {kind}: {detail}"),
            Self::NoSupportedChallenge => write!(f, "no http-01 challenge offered"),
            Self::Invalid(e) => write!(f, "invalid: {e}"),
            Self::Timeout(e) => write!(f, "timeout: {e}"),
        }
    }
}

impl std::error::Error for AcmeError {}

/// Polling limits (RFC 8555 §7.5.1, §7.4: clients SHOULD honour Retry-After; we clamp it).
#[derive(Clone, Copy, Debug)]
pub struct PollBounds {
    /// Lower clamp for a Retry-After, seconds.
    pub min_secs: u64,
    /// Upper clamp for a Retry-After, seconds.
    pub max_secs: u64,
    /// Wait when no Retry-After is given, seconds.
    pub default_secs: u64,
    /// Total deadline for one poll loop, seconds.
    pub deadline_secs: u64,
}

impl Default for PollBounds {
    fn default() -> Self {
        Self { min_secs: 1, max_secs: 30, default_secs: 2, deadline_secs: 300 }
    }
}

/// Client configuration.
#[derive(Clone, Debug)]
pub struct AcmeConfig {
    /// Directory URL.
    pub directory_url: String,
    /// Trust anchors for the ACME server's TLS certificate (never implicit).
    pub roots: Vec<CertificateDer<'static>>,
    /// `contact` URLs for newAccount (may be empty).
    pub contact: Vec<String>,
    /// Polling limits.
    pub poll: PollBounds,
    /// Response caps and socket timeouts.
    pub limits: Limits,
    /// Fault injection (oracle self-test only; feature `test-faults`, never in a release graph).
    #[cfg(feature = "test-faults")]
    pub faults: Faults,
}

impl AcmeConfig {
    /// Defaults for a directory and trust anchors.
    pub fn new(directory_url: &str, roots: Vec<CertificateDer<'static>>) -> Self {
        Self {
            directory_url: directory_url.into(),
            roots,
            contact: Vec::new(),
            poll: PollBounds::default(),
            limits: Limits::default(),
            #[cfg(feature = "test-faults")]
            faults: Faults::default(),
        }
    }
}

/// Publishes HTTP-01 key authorizations where the server can serve them (RFC 8555 §8.3).
pub trait ChallengeResponder: Send + Sync {
    /// Serve `key_authorization` at `/.well-known/acme-challenge/<token>`.
    fn publish(&self, token: &str, key_authorization: &str);
    /// Stop serving `token`.
    fn remove(&self, token: &str);
}

/// In-memory HTTP-01 token table shared between the ACME client and the plain-HTTP listener.
#[derive(Debug, Default)]
pub struct Http01Tokens {
    map: RwLock<Vec<(String, String)>>,
}

/// HTTP-01 path prefix.
pub const HTTP01_PREFIX: &str = "/.well-known/acme-challenge/";
const MAX_TOKENS: usize = 256;

impl Http01Tokens {
    /// Empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// The response body for a request path, if it names a published token.
    pub fn respond(&self, path: &str) -> Option<String> {
        let token = path.strip_prefix(HTTP01_PREFIX)?;
        let g = match self.map.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.iter().find(|(t, _)| t == token).map(|(_, k)| k.clone())
    }
}

impl ChallengeResponder for Http01Tokens {
    fn publish(&self, token: &str, key_authorization: &str) {
        let mut g = match self.map.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.retain(|(t, _)| t != token);
        if g.len() < MAX_TOKENS {
            g.push((token.into(), key_authorization.into()));
        }
    }
    fn remove(&self, token: &str) {
        let mut g = match self.map.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.retain(|(t, _)| t != token);
    }
}

/// The directory resources this client uses (RFC 8555 §7.1.1, RFC 9773 §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Directory {
    /// newNonce.
    pub new_nonce: String,
    /// newAccount.
    pub new_account: String,
    /// newOrder.
    pub new_order: String,
    /// renewalInfo (ARI), if offered.
    pub renewal_info: Option<String>,
}

/// Something the client did that a caller may want to log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcmeEvent {
    /// The server rejected a nonce (`badNonce`) and the request was retried with the fresh one.
    BadNonceRetry {
        /// Request URL.
        url: String,
    },
    /// A poll waited.
    PollWait {
        /// Polled URL.
        url: String,
        /// Seconds slept.
        secs: u64,
    },
}

/// A certificate obtained from the CA.
#[derive(Debug)]
pub struct Issued {
    /// Leaf first.
    pub chain: Vec<CertificateDer<'static>>,
    /// The certificate's private key (PKCS#8, P-256).
    pub key: PrivateKeyDer<'static>,
    /// Order URL.
    pub order_url: String,
    /// Certificate URL.
    pub cert_url: String,
}

const BAD_NONCE: &str = "urn:ietf:params:acme:error:badNonce";
const MAX_NONCE_RETRIES: usize = 5;
const MAX_AUTHZ: usize = 100;

/// A blocking ACME client bound to one directory and one account key.
#[derive(Debug)]
pub struct AcmeClient {
    cfg: AcmeConfig,
    tls: Arc<ClientConfig>,
    dir: Directory,
    key: AccountKey,
    wrong_key: Option<AccountKey>,
    kid: Option<String>,
    nonce: Option<String>,
    last_nonce: Option<String>,
    replay_done: bool,
    events: Vec<AcmeEvent>,
}

fn valid_nonce(n: &str) -> bool {
    !n.is_empty() && n.len() <= 512 && n.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

fn retry_after(resp: &Response) -> Option<u64> {
    let v = resp.header("retry-after")?.trim();
    if !v.is_empty() && v.len() <= 10 && v.bytes().all(|c| c.is_ascii_digit()) {
        return v.parse().ok();
    }
    let t = parse_http_date(v)?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    u64::try_from(t).ok().map(|t| t.saturating_sub(now))
}

fn parse_body(resp: &Response) -> Result<JsonValue, AcmeError> {
    parse_json(&resp.body).map_err(|r| AcmeError::Json(r.reason()))
}

fn problem(resp: &Response) -> AcmeError {
    let (kind, detail) = match parse_json(&resp.body) {
        Ok(v) => (
            get_str(&v, "type").unwrap_or("").chars().take(200).collect(),
            get_str(&v, "detail").unwrap_or("").chars().take(500).collect(),
        ),
        Err(_) => (String::new(), String::from("(non-JSON error body)")),
    };
    AcmeError::Problem { status: resp.status, kind, detail }
}

impl AcmeClient {
    /// Build the TLS config, fetch the directory and create an account key (not yet registered).
    pub fn connect(cfg: AcmeConfig) -> Result<Self, AcmeError> {
        let tls = tls::client_config(&cfg.roots)?;
        let key = AccountKey::generate()?;
        let wrong_key = if wrong_jws_key(&cfg) { Some(AccountKey::generate()?) } else { None };
        let mut c = Self {
            dir: Directory {
                new_nonce: String::new(),
                new_account: String::new(),
                new_order: String::new(),
                renewal_info: None,
            },
            cfg,
            tls,
            key,
            wrong_key,
            kid: None,
            nonce: None,
            last_nonce: None,
            replay_done: false,
            events: Vec::new(),
        };
        c.dir = c.fetch_directory()?;
        Ok(c)
    }

    /// The directory.
    pub fn directory(&self) -> &Directory {
        &self.dir
    }

    /// The account URL once registered.
    pub fn account_url(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The account key.
    pub fn account_key(&self) -> &AccountKey {
        &self.key
    }

    /// Drain the event log.
    pub fn take_events(&mut self) -> Vec<AcmeEvent> {
        core::mem::take(&mut self.events)
    }

    fn send(&self, method: &str, url: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<Response, AcmeError> {
        let u = Url::parse(url)?;
        http::request(&self.tls, method, &u, headers, body, &self.cfg.limits)
    }

    fn fetch_directory(&self) -> Result<Directory, AcmeError> {
        let r = self.send("GET", &self.cfg.directory_url, &[], &[])?;
        if r.status != 200 {
            return Err(problem(&r));
        }
        let v = parse_body(&r)?;
        let req = |k: &'static str| get_str(&v, k).map(String::from).ok_or(AcmeError::Malformed(k));
        let d = Directory {
            new_nonce: req("newNonce")?,
            new_account: req("newAccount")?,
            new_order: req("newOrder")?,
            renewal_info: get_str(&v, "renewalInfo").map(String::from),
        };
        for u in [&d.new_nonce, &d.new_account, &d.new_order].into_iter().chain(d.renewal_info.as_ref()) {
            Url::parse(u)?;
        }
        Ok(d)
    }

    fn store_nonce(&mut self, r: &Response) {
        if let Some(n) = r.header("replay-nonce").filter(|n| valid_nonce(n)) {
            self.nonce = Some(n.into());
        }
    }

    fn fresh_nonce(&mut self) -> Result<String, AcmeError> {
        if let Some(n) = self.nonce.take() {
            return Ok(n);
        }
        let url = self.dir.new_nonce.clone();
        let r = self.send("HEAD", &url, &[], &[])?;
        if r.status != 200 && r.status != 204 {
            return Err(problem(&r));
        }
        r.header("replay-nonce")
            .filter(|n| valid_nonce(n))
            .map(String::from)
            .ok_or(AcmeError::Malformed("Replay-Nonce"))
    }

    /// Signed POST (payload `None` = POST-as-GET). Retries on `badNonce` with the nonce from the error response.
    fn post(&mut self, url: &str, payload: Option<&str>, accept: Option<&str>) -> Result<Response, AcmeError> {
        for _ in 0..MAX_NONCE_RETRIES {
            let mut nonce = self.fresh_nonce()?;
            if replay_nonce(&self.cfg)
                && !self.replay_done
                && self.kid.is_some()
                && let Some(old) = self.last_nonce.clone()
            {
                nonce = old;
                self.replay_done = true;
            }
            self.last_nonce = Some(nonce.clone());
            let id = match &self.kid {
                Some(k) => KeyId::Kid(k),
                None => KeyId::Jwk,
            };
            let signer = self.wrong_key.as_ref().unwrap_or(&self.key);
            let body = jws::sign(&self.key, signer, id, &nonce, url, payload)?;
            let mut headers = std::vec![("Content-Type", "application/jose+json")];
            if let Some(a) = accept {
                headers.push(("Accept", a));
            }
            let r = self.send("POST", url, &headers, body.as_bytes())?;
            self.store_nonce(&r);
            if r.status >= 400 {
                let p = problem(&r);
                if matches!(&p, AcmeError::Problem { kind, .. } if kind == BAD_NONCE) {
                    self.events.push(AcmeEvent::BadNonceRetry { url: url.into() });
                    continue;
                }
                return Err(p);
            }
            return Ok(r);
        }
        Err(AcmeError::Malformed("badNonce retries exhausted"))
    }

    /// newAccount (RFC 8555 §7.3) with `termsOfServiceAgreed`. Idempotent per key.
    pub fn register(&mut self) -> Result<String, AcmeError> {
        let contacts: Vec<String> = self.cfg.contact.iter().map(|c| quote(c)).collect();
        let payload = std::format!(r#"{{"termsOfServiceAgreed":true,"contact":[{}]}}"#, contacts.join(","));
        let url = self.dir.new_account.clone();
        let r = self.post(&url, Some(&payload), None)?;
        if r.status != 200 && r.status != 201 {
            return Err(problem(&r));
        }
        let kid = r.header("location").map(String::from).ok_or(AcmeError::Malformed("account Location"))?;
        Url::parse(&kid)?;
        self.kid = Some(kid.clone());
        Ok(kid)
    }

    fn sleep_for(&mut self, url: &str, resp: &Response, deadline: Instant) -> Result<(), AcmeError> {
        let p = self.cfg.poll;
        let secs = ari::clamp_retry(retry_after(resp), p.min_secs, p.max_secs, p.default_secs);
        let wake = Instant::now() + Duration::from_secs(secs);
        if wake > deadline {
            return Err(AcmeError::Timeout("poll deadline"));
        }
        self.events.push(AcmeEvent::PollWait { url: url.into(), secs });
        std::thread::sleep(Duration::from_secs(secs));
        Ok(())
    }

    /// Obtain a certificate for `domains` (RFC 8555 §7.4), proving control with HTTP-01 through `responder`.
    /// `replaces` is the RFC 9773 certID of the predecessor, when renewing.
    pub fn issue(
        &mut self,
        domains: &[String],
        responder: &dyn ChallengeResponder,
        replaces: Option<&str>,
    ) -> Result<Issued, AcmeError> {
        if domains.is_empty() || !domains.iter().all(|d| csr::valid_dns_name(d)) {
            return Err(AcmeError::BadIdentifier);
        }
        if self.kid.is_none() {
            self.register()?;
        }
        let ids: Vec<String> =
            domains.iter().map(|d| std::format!(r#"{{"type":"dns","value":{}}}"#, quote(d))).collect();
        let mut payload = std::format!(r#"{{"identifiers":[{}]"#, ids.join(","));
        if let Some(r) = replaces {
            payload.push_str(&std::format!(r#","replaces":{}"#, quote(r)));
        }
        payload.push('}');
        let url = self.dir.new_order.clone();
        let r = self.post(&url, Some(&payload), None)?;
        if r.status != 201 {
            return Err(problem(&r));
        }
        let order_url = r.header("location").map(String::from).ok_or(AcmeError::Malformed("order Location"))?;
        Url::parse(&order_url)?;
        let order = parse_body(&r)?;
        let finalize = get_str(&order, "finalize").map(String::from).ok_or(AcmeError::Malformed("finalize"))?;
        let authzs: Vec<String> = get_array(&order, "authorizations")
            .ok_or(AcmeError::Malformed("authorizations"))?
            .iter()
            .map(|a| match a {
                JsonValue::String(s) => Ok(s.clone()),
                _ => Err(AcmeError::Malformed("authorization url")),
            })
            .collect::<Result<_, _>>()?;
        if authzs.len() > MAX_AUTHZ {
            return Err(AcmeError::TooLarge("authorizations"));
        }
        let mut published = Vec::new();
        let res = self.authorize_all(&authzs, responder, &mut published);
        for t in &published {
            responder.remove(t);
        }
        res?;

        let csr_names: Vec<String> = if csr_wrong_identifier(&self.cfg) {
            domains.iter().map(|d| std::format!("tampered-{d}")).collect()
        } else {
            domains.to_vec()
        };
        let csr = csr::build_csr(&csr_names)?;
        let payload = std::format!(r#"{{"csr":"{}"}}"#, b64url_encode(&csr.der));
        let r = self.post(&finalize, Some(&payload), None)?;
        let mut order = parse_body(&r)?;
        let deadline = Instant::now() + Duration::from_secs(self.cfg.poll.deadline_secs);
        let mut last = r;
        let cert_url = loop {
            match get_str(&order, "status") {
                Some("valid") => {
                    break get_str(&order, "certificate")
                        .map(String::from)
                        .ok_or(AcmeError::Malformed("certificate"))?;
                }
                Some("invalid") => return Err(AcmeError::Invalid(std::format!("order {order_url}"))),
                Some("pending" | "ready" | "processing") => {
                    self.sleep_for(&order_url, &last, deadline)?;
                    last = self.post(&order_url, None, None)?;
                    order = parse_body(&last)?;
                }
                _ => return Err(AcmeError::Malformed("order status")),
            }
        };
        let r = self.post(&cert_url, None, Some("application/pem-certificate-chain"))?;
        let text = core::str::from_utf8(&r.body).map_err(|_| AcmeError::Malformed("certificate chain encoding"))?;
        let chain: Vec<CertificateDer<'static>> = pem_certificates(text)
            .ok_or(AcmeError::Malformed("certificate chain PEM"))?
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        if chain.is_empty() {
            return Err(AcmeError::Malformed("empty certificate chain"));
        }
        Ok(Issued { chain, key: csr.key, order_url, cert_url })
    }

    fn authorize_all(
        &mut self,
        authzs: &[String],
        responder: &dyn ChallengeResponder,
        published: &mut Vec<String>,
    ) -> Result<(), AcmeError> {
        for az in authzs {
            let r = self.post(az, None, None)?;
            let a = parse_body(&r)?;
            match get_str(&a, "status") {
                Some("valid") => continue,
                Some("pending") => {}
                _ => return Err(AcmeError::Invalid(std::format!("authorization {az} not pending"))),
            }
            let ch = get_array(&a, "challenges")
                .ok_or(AcmeError::Malformed("challenges"))?
                .iter()
                .find(|c| get_str(c, "type") == Some("http-01"))
                .ok_or(AcmeError::NoSupportedChallenge)?;
            let token = get_str(ch, "token").ok_or(AcmeError::Malformed("token"))?.to_string();
            let ch_url = get_str(ch, "url").ok_or(AcmeError::Malformed("challenge url"))?.to_string();
            // RFC 8555 §8.3: the token is base64url; it becomes a URL path segment, so nothing else is accepted.
            if token.len() < 22 || token.len() > 256 || crate::cert::b64::b64url_decode(&token).is_none() {
                return Err(AcmeError::Malformed("token"));
            }
            responder.publish(&token, &self.key.key_authorization(&token));
            published.push(token);
            self.post(&ch_url, Some("{}"), None)?;
            let deadline = Instant::now() + Duration::from_secs(self.cfg.poll.deadline_secs);
            let mut last = r;
            loop {
                last = {
                    self.sleep_for(az, &last, deadline)?;
                    self.post(az, None, None)?
                };
                let a = parse_body(&last)?;
                match get_str(&a, "status") {
                    Some("valid") => break,
                    Some("pending") => continue,
                    _ => {
                        let detail = get_array(&a, "challenges")
                            .and_then(|cs| cs.iter().find_map(|c| json::get(c, "error")))
                            .and_then(|e| get_str(e, "detail"))
                            .unwrap_or("")
                            .chars()
                            .take(300)
                            .collect::<String>();
                        return Err(AcmeError::Invalid(std::format!("authorization {az}: {detail}")));
                    }
                }
            }
        }
        Ok(())
    }

    /// Fetch renewalInfo for a leaf (RFC 9773 §4.2; unauthenticated GET). `Ok(None)` if the CA has no ARI.
    pub fn renewal_info(&mut self, leaf_der: &[u8]) -> Result<Option<ari::RenewalInfo>, AcmeError> {
        let Some(base) = self.dir.renewal_info.clone() else {
            return Ok(None);
        };
        let id = ari::cert_id(leaf_der)?;
        let url = std::format!("{}/{id}", base.trim_end_matches('/'));
        let r = self.send("GET", &url, &[], &[])?;
        if r.status != 200 {
            return Err(problem(&r));
        }
        ari::parse_renewal_info(&r.body, retry_after(&r)).map(Some)
    }
}

#[cfg(test)]
mod tests;

/// The release build: no fault exists, every predicate is `false` (feature `test-faults` off).
#[cfg(not(feature = "test-faults"))]
mod no_test_faults {
    use super::AcmeConfig;

    pub(super) const fn wrong_jws_key(_: &AcmeConfig) -> bool {
        false
    }
    pub(super) const fn replay_nonce(_: &AcmeConfig) -> bool {
        false
    }
    pub(super) const fn csr_wrong_identifier(_: &AcmeConfig) -> bool {
        false
    }
}
