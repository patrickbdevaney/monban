//! F9 audit event (`interfaces/F9-audit-event.schema.json`, frozen) and its canonical JSON leaf encoding.
//!
//! Canonical form: one JSON object, no whitespace, keys in schema order (`v ts seq actor action object outcome
//! req_id config_hash fips_status [detail]`, actor keys `kind [tenant] [subject_hash]`, detail keys sorted), and
//! every byte outside printable ASCII escaped as `\uXXXX`, so a leaf is pure printable ASCII whatever an attacker
//! put in `object` or a detail string (log hygiene, ARCHITECTURE §3.10). Attacker strings are length-capped in
//! Unicode scalar values *before* escaping (schema `maxLength` counts characters). No trailing newline: the leaf
//! is the RFC 6962 leaf input; the entry bundle supplies framing.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use aegis_types::TenantId;
use aws_lc_rs::digest;

use crate::encoding::hex_encode;

/// Schema `object.maxLength`.
pub const MAX_OBJECT_CHARS: usize = 512;
/// Cap on each detail string value (characters). Keeps the worst-case leaf far below the 65,535-byte entry limit.
pub const MAX_DETAIL_STR_CHARS: usize = 128;
/// Schema `detail.maxProperties`.
pub const MAX_DETAIL_ENTRIES: usize = 16;
/// Entry bundles frame leaves with a big-endian u16 (c2sp.org/tlog-tiles).
pub const MAX_LEAF_BYTES: usize = 65_535;
/// Rendered for [`DetailValue::Redacted`].
pub const REDACTED: &str = "[redacted]";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventError {
    /// Action does not match `^[a-z][a-z0-9_.]{0,63}$`.
    BadAction,
    /// Detail key does not match `^[a-z][a-z0-9_]{0,31}$`.
    BadDetailKey,
    /// More than 16 detail entries.
    TooManyDetails,
    /// Encoded leaf exceeds 65,535 bytes (unreachable with the caps above; checked anyway).
    LeafTooLarge,
    /// Timestamp out of the representable RFC 3339 range (years 1970..=9999).
    BadTimestamp,
}

impl std::fmt::Display for EventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BadAction => "action does not match ^[a-z][a-z0-9_.]{0,63}$",
            Self::BadDetailKey => "detail key does not match ^[a-z][a-z0-9_]{0,31}$",
            Self::TooManyDetails => "more than 16 detail entries",
            Self::LeafTooLarge => "encoded leaf exceeds 65535 bytes",
            Self::BadTimestamp => "timestamp out of range",
        })
    }
}
impl std::error::Error for EventError {}

/// Which failure policy applies (Audit I7). Admin events fail closed; data-plane events may be dropped (counted).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventClass {
    Admin,
    DataPlane,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorKind {
    Public,
    Principal,
    Admin,
    System,
}

impl ActorKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Principal => "principal",
            Self::Admin => "admin",
            Self::System => "system",
        }
    }
}

/// Who acted. Subject identities are never logged in clear: only their SHA-256 (typed redaction, Audit I6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Actor {
    kind: ActorKind,
    tenant: Option<TenantId>,
    subject_hash: Option<[u8; 32]>,
}

fn sha256(b: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, b);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

impl Actor {
    pub fn public() -> Self {
        Self { kind: ActorKind::Public, tenant: None, subject_hash: None }
    }
    pub fn system() -> Self {
        Self { kind: ActorKind::System, tenant: None, subject_hash: None }
    }
    /// An operator identity; `subject` is hashed, never stored.
    pub fn admin(subject: &[u8]) -> Self {
        Self { kind: ActorKind::Admin, tenant: None, subject_hash: Some(sha256(subject)) }
    }
    /// An authenticated principal, from its verified parts; `subject` is hashed, never stored.
    pub fn principal(tenant: TenantId, subject: Option<&[u8]>) -> Self {
        Self { kind: ActorKind::Principal, tenant: Some(tenant), subject_hash: subject.map(sha256) }
    }
    /// From a verified `Principal` (aegis-types F2).
    pub fn from_principal(p: &aegis_types::Principal) -> Self {
        match p.subject() {
            aegis_types::Subject::Public => Self::principal(p.tenant(), None),
            aegis_types::Subject::Authenticated(b) => Self::principal(p.tenant(), Some(b)),
        }
    }
    pub fn kind(&self) -> ActorKind {
        self.kind
    }
}

/// Validated action name, `^[a-z][a-z0-9_.]{0,63}$`. Actions are chosen by code, not attackers, so an invalid
/// one is an error rather than something to escape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action(String);

impl Action {
    pub fn new(s: &str) -> Result<Self, EventError> {
        let b = s.as_bytes();
        let ok = matches!(b.first(), Some(b'a'..=b'z'))
            && b.len() <= 64
            && b.iter().all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.'));
        if ok { Ok(Self(s.to_owned())) } else { Err(EventError::BadAction) }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An attacker-influenced string: decoded lossily from bytes (invalid UTF-8 becomes U+FFFD) and capped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Untrusted(String);

impl Untrusted {
    fn capped(bytes: &[u8], max_chars: usize) -> Self {
        Self(String::from_utf8_lossy(bytes).chars().take(max_chars).collect())
    }
    /// For `object`: capped at 512 characters.
    pub fn object(bytes: &[u8]) -> Self {
        Self::capped(bytes, MAX_OBJECT_CHARS)
    }
    /// For a detail string: capped at 128 characters.
    pub fn detail(bytes: &[u8]) -> Self {
        Self::capped(bytes, MAX_DETAIL_STR_CHARS)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Allow,
    Deny,
    Error,
    Applied,
    RolledBack,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Error => "error",
            Self::Applied => "applied",
            Self::RolledBack => "rolled_back",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FipsStatus {
    None,
    Floor,
    Cmvp,
}

impl FipsStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Floor => "floor",
            Self::Cmvp => "cmvp",
        }
    }
}

/// Validated detail key, `^[a-z][a-z0-9_]{0,31}$`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DetailKey(String);

impl DetailKey {
    pub fn new(s: &str) -> Result<Self, EventError> {
        let b = s.as_bytes();
        let ok = matches!(b.first(), Some(b'a'..=b'z'))
            && b.len() <= 32
            && b.iter().all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'_'));
        if ok { Ok(Self(s.to_owned())) } else { Err(EventError::BadDetailKey) }
    }
}

/// Typed detail values. Secrets have no constructor that keeps their content: use [`DetailValue::Redacted`]
/// (renders `"[redacted]"`) or [`DetailValue::hashed`] (renders the SHA-256 hex) (Audit I6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DetailValue {
    Str(Untrusted),
    Int(i64),
    Bool(bool),
    Redacted,
    Hashed([u8; 32]),
}

impl DetailValue {
    pub fn text(bytes: &[u8]) -> Self {
        Self::Str(Untrusted::detail(bytes))
    }
    pub fn hashed(secret: &[u8]) -> Self {
        Self::Hashed(sha256(secret))
    }
}

/// At most 16 typed entries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Detail(BTreeMap<DetailKey, DetailValue>);

impl Detail {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, key: DetailKey, value: DetailValue) -> Result<(), EventError> {
        if self.0.len() >= MAX_DETAIL_ENTRIES && !self.0.contains_key(&key) {
            return Err(EventError::TooManyDetails);
        }
        self.0.insert(key, value);
        Ok(())
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// An event before sequencing; the log adds `v`, `ts` and `seq`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    pub class: EventClass,
    pub actor: Actor,
    pub action: Action,
    pub object: Untrusted,
    pub outcome: Outcome,
    pub req_id: [u8; 16],
    pub config_hash: [u8; 32],
    pub fips_status: FipsStatus,
    pub detail: Detail,
}

/// JSON string with every non-printable-ASCII scalar escaped as `\uXXXX` (UTF-16 surrogate pairs above U+FFFF).
pub fn write_json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ' '..='~' => out.push(c),
            _ => {
                let mut units = [0u16; 2];
                for u in c.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{:04x}", u);
                }
            }
        }
    }
    out.push('"');
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian (H. Hinnant's `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// RFC 3339 UTC with millisecond precision, e.g. `2026-10-25T08:00:00.000Z`.
pub fn format_ts(unix_ms: u64) -> Result<String, EventError> {
    let secs = i64::try_from(unix_ms / 1000).map_err(|_| EventError::BadTimestamp)?;
    let ms = unix_ms % 1000;
    let (y, mo, d) = civil_from_days(secs.div_euclid(86_400));
    if y > 9999 {
        return Err(EventError::BadTimestamp);
    }
    let sod = secs.rem_euclid(86_400);
    Ok(format!("{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}.{ms:03}Z", sod / 3600, (sod / 60) % 60, sod % 60))
}

impl AuditEvent {
    /// The canonical leaf for this event at `seq`, sequenced at `unix_ms`.
    pub fn encode_leaf(&self, seq: u64, unix_ms: u64) -> Result<Vec<u8>, EventError> {
        let mut o = String::with_capacity(512);
        o.push_str("{\"v\":1,\"ts\":");
        write_json_str(&mut o, &format_ts(unix_ms)?);
        let _ = write!(o, ",\"seq\":{seq},\"actor\":{{\"kind\":\"{}\"", self.actor.kind.as_str());
        if let Some(t) = self.actor.tenant {
            let _ = write!(o, ",\"tenant\":{}", t.get());
        }
        if let Some(h) = &self.actor.subject_hash {
            let _ = write!(o, ",\"subject_hash\":\"{}\"", hex_encode(h));
        }
        o.push_str("},\"action\":");
        write_json_str(&mut o, self.action.as_str());
        o.push_str(",\"object\":");
        write_json_str(&mut o, self.object.as_str());
        let _ = write!(
            o,
            ",\"outcome\":\"{}\",\"req_id\":\"{}\",\"config_hash\":\"{}\",\"fips_status\":\"{}\"",
            self.outcome.as_str(),
            hex_encode(&self.req_id),
            hex_encode(&self.config_hash),
            self.fips_status.as_str()
        );
        if !self.detail.is_empty() {
            o.push_str(",\"detail\":{");
            for (i, (k, v)) in self.detail.0.iter().enumerate() {
                if i > 0 {
                    o.push(',');
                }
                write_json_str(&mut o, &k.0);
                o.push(':');
                match v {
                    DetailValue::Str(s) => write_json_str(&mut o, s.as_str()),
                    DetailValue::Int(n) => {
                        let _ = write!(o, "{n}");
                    }
                    DetailValue::Bool(b) => o.push_str(if *b { "true" } else { "false" }),
                    DetailValue::Redacted => write_json_str(&mut o, REDACTED),
                    DetailValue::Hashed(h) => write_json_str(&mut o, &hex_encode(h)),
                }
            }
            o.push('}');
        }
        o.push('}');
        if o.len() > MAX_LEAF_BYTES {
            return Err(EventError::LeafTooLarge);
        }
        Ok(o.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    fn ev() -> AuditEvent {
        AuditEvent {
            class: EventClass::DataPlane,
            actor: Actor::public(),
            action: Action::new("http.request").unwrap(),
            object: Untrusted::object(b"/x"),
            outcome: Outcome::Allow,
            req_id: [0xab; 16],
            config_hash: [0x01; 32],
            fips_status: FipsStatus::Floor,
            detail: Detail::new(),
        }
    }

    #[test]
    fn canonical_golden() {
        let leaf = ev().encode_leaf(7, 1_761_379_200_123).unwrap();
        assert_eq!(
            String::from_utf8(leaf).unwrap(),
            format!(
                "{{\"v\":1,\"ts\":\"2025-10-25T08:00:00.123Z\",\"seq\":7,\"actor\":{{\"kind\":\"public\"}},\
                 \"action\":\"http.request\",\"object\":\"/x\",\"outcome\":\"allow\",\"req_id\":\"{}\",\
                 \"config_hash\":\"{}\",\"fips_status\":\"floor\"}}",
                "ab".repeat(16),
                "01".repeat(32)
            )
        );
    }

    #[test]
    fn timestamps() {
        assert_eq!(format_ts(0).unwrap(), "1970-01-01T00:00:00.000Z");
        assert_eq!(format_ts(951_782_400_000).unwrap(), "2000-02-29T00:00:00.000Z");
        assert_eq!(format_ts(253_402_300_799_999).unwrap(), "9999-12-31T23:59:59.999Z");
        assert_eq!(format_ts(253_402_300_800_000), Err(EventError::BadTimestamp));
    }

    #[test]
    fn attacker_strings_escaped_and_capped() {
        let mut e = ev();
        let evil = "\"}\n\u{1b}[31m\u{7f}é😀\\".repeat(200);
        e.object = Untrusted::object(evil.as_bytes());
        assert_eq!(e.object.as_str().chars().count(), MAX_OBJECT_CHARS);
        let mut d = Detail::new();
        d.insert(DetailKey::new("ua").unwrap(), DetailValue::text(b"\xff\xfe<script>")).unwrap();
        d.insert(DetailKey::new("token").unwrap(), DetailValue::Redacted).unwrap();
        d.insert(DetailKey::new("n").unwrap(), DetailValue::Int(-5)).unwrap();
        e.detail = d;
        let leaf = e.encode_leaf(0, 0).unwrap();
        assert!(leaf.iter().all(|&b| (0x20..0x7f).contains(&b)), "leaf must be printable ASCII");
        let s = String::from_utf8(leaf).unwrap();
        assert!(s.contains("\\u001b") && s.contains("\\ud83d\\ude00") && s.contains("\\u00e9"));
        assert!(s.contains("\"ua\":\"\\ufffd\\ufffd<script>\""));
        assert!(s.ends_with("\"detail\":{\"n\":-5,\"token\":\"[redacted]\",\"ua\":\"\\ufffd\\ufffd<script>\"}}"));
    }

    #[test]
    fn worst_case_leaf_fits_u16() {
        let mut e = ev();
        let big = "😀".repeat(10_000);
        e.object = Untrusted::object(big.as_bytes());
        e.actor = Actor::principal(TenantId::new(u64::MAX).unwrap(), Some(b"s"));
        for i in 0..MAX_DETAIL_ENTRIES {
            let k = format!("k{}{}", i, "x".repeat(28));
            e.detail.insert(DetailKey::new(&k).unwrap(), DetailValue::text(big.as_bytes())).unwrap();
        }
        assert_eq!(
            e.detail.insert(DetailKey::new("one_more").unwrap(), DetailValue::Bool(true)),
            Err(EventError::TooManyDetails)
        );
        let leaf = e.encode_leaf(u64::MAX, u64::MAX / 1_000_000).unwrap();
        assert!(leaf.len() < MAX_LEAF_BYTES);
    }

    #[test]
    fn validation() {
        assert!(Action::new("a").is_ok());
        assert!(Action::new(&"a".repeat(64)).is_ok());
        assert_eq!(Action::new(&"a".repeat(65)), Err(EventError::BadAction));
        assert_eq!(Action::new("1a"), Err(EventError::BadAction));
        assert_eq!(Action::new("A"), Err(EventError::BadAction));
        assert_eq!(Action::new(""), Err(EventError::BadAction));
        assert_eq!(DetailKey::new("a.b"), Err(EventError::BadDetailKey));
    }
}
