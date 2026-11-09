//! Typed config, JSON Schema, check-config, last-known-good (CFG-1..4).
//!
//! * [`parse_config`] (CFG-1, CFG-2): total. The byte cap ([`MAX_CONFIG_BYTES`], 1 MiB) is checked before
//!   anything else; the document is parsed by the one strict I-JSON parser (`aegis_canon::parse_json`,
//!   DEVIATIONS X-2) and validated against frozen interface F8 (`interfaces/F8-config.schema.json`) exactly:
//!   unknown fields rejected, every bound, enum, const and pattern, `oneOf` route targets, schema defaults
//!   applied. Cross-field checks the schema cannot express: unique listener names, unique vhost hosts, unique
//!   route ids per vhost. Every error carries a JSON pointer (RFC 6901) to the offending value.
//! * [`Config::config_hash`]: SHA-256 of the canonical JSON (aegis-canon serializer) of the *effective* config
//!   (defaults applied), so two documents that mean the same thing hash the same.
//! * [`ConfigStore`] (CFG-3, CFG-4): last-known-good on `Err`; staged apply shadow → canary → full with
//!   rollback, driven by explicit transitions with the clock passed in (no I/O).
//! * [`defaults_json`]: the schema defaults as a canonical JSON document (`aegis check-config --print-effective`).
//! * [`Config::effective_dump`]: the effective config plus the host-resolved P2 path (`p2.isolation_effective`,
//!   `p2.usable_cpus`), canonical; what `aegis check-config --print-effective` prints. Not hashed.
//!
//! * [`DataBlock`] / [`RouteData`] (F8 `data`, Phase 4): backends and per-route data endowments. Absent
//!   `routes[].data` means no data capability (never unrestricted); `"unrestricted"` only as the explicit literal
//!   (CI-gated by `ci/unrestricted.py`). Backend references and engine pins are checked at load; column names are
//!   resolved at boot through [`SchemaProvider`] ([`Config::resolve_data`]). See the `data` module docs.
//!
//! * [`P2Block`] (F8 `p2`, Phase 5) and the `{"wasm": <module-id>}` route target ([`RouteTarget::Wasm`]): the
//!   worker path, module table (path, sha256, tenancy, resolved limits), `isolation` (D1 + D23(b): default `auto`,
//!   resolved by [`resolve_isolation`] from the usable CPU count: < 8 → cordon, else forkwasm),
//!   bounded fuel / wall / memory / host-call caps, the D7 crash budget and `mpk`. A cordon shared by principals
//!   is unrepresentable (no field names a cordon). Module ids are unique and every wasm route names a declared
//!   module (checked at load). See the `p2` module docs.
//!
//! * Phase 7 (P7-spec-001, PLAN-7 Interfaces; all optional, absent = the pre-Phase-7 meaning, effective form and
//!   hash): [`Listener::proxy_protocol`] ([`ProxyProtocol`], trusted CIDRs, PROXY-1..3), [`Listener::l4`]
//!   ([`L4Route`], SNI passthrough, L4-1/L4-2; an L4 listener carries no `alpn`), [`Listener::front`] ([`Front`],
//!   FRONT-1; the default `epoll` is not printed in the hashed form), the root [`TlsBlock`] (credential selector
//!   inputs, SEL-1..3) and the backend families [`AdapterFamily`] (`mariadb`, `crdb`, kept apart from the golden
//!   [`Engine`] so an assembly that predates them fails closed on them), and the root [`Admission`] block (S0/S1/S5
//!   numbers formerly hard-coded in aegis-bin; defaults = those constants, not hashed when equal to them). See the
//!   `p7` module docs.
//!
//! * Phase 8 (P8-spec-001, PLAN-8 Interfaces; all optional, absent = the pre-Phase-8 meaning, effective form and
//!   hash): the root [`Runtime`] block (`worker_threads`, default 2, not hashed when default), the root
//!   [`StateBlock`] (`idempotency_retention_s`, no default: absent = never expire), and the load-time refusal of a
//!   route `path` that `canon_path` does not leave unchanged ([`ErrorKind::NotCanonical`]). See the `p8` module docs.
//!
//! INV-NONEMPTY: a route without an `authz` policy (or with an empty policy name) is denied
//! ([`Route::authz_requirement`]); every limit has a schema maximum and a default, so no effective limit is
//! unbounded.
#![forbid(unsafe_code)]

mod data;
mod emit;
mod p2;
mod p7;
mod p8;
mod parse;
mod sha256;
mod store;

use std::fmt;

pub use data::{
    AdapterBackend, AdapterFamily, AdapterPinInfo, Backend, CapList, CapSpec, DataBlock, DataOp, DsnRef, Engine,
    FieldId, MAX_BACKENDS, MAX_CAP_COLUMNS, MAX_CAPS, PinInfo, ResolvedCap, ResolvedData, ResolvedRoute, RouteData,
    SchemaProvider, UNRESTRICTED, Unresolved, adapter_pin, adapter_pins, engine_pin, engine_pins,
};
pub use p2::{
    AUTO_CORDON_BELOW_CPUS, CrashBudget, Isolation, IsolationSetting, MAX_P2_MODULES, P2Block, P2Limits, P2Module,
    Tenancy, resolve_isolation,
};
pub use p7::{
    Admission, Cidr, Credential, CredentialKind, Front, L4Route, MAX_CREDENTIALS, MAX_L4_ROUTES, MAX_TAI_COMPONENTS,
    MAX_TRUSTED, ProxyProtocol, RateLimit, SecretRef, TlsBlock, TrustAnchorId,
};
pub use p8::{Runtime, StateBlock};
pub use sha256::{hex, sha256};
pub use store::{ConfigStore, Generation, Health, Phase, RolloutPolicy, StageError};

/// CFG-2: maximum config document size in bytes (1 MiB). Checked before parsing; the effective canonical form
/// is held to the same cap.
pub const MAX_CONFIG_BYTES: usize = 1 << 20;

/// Largest accepted route id: the I-JSON safe integer range (RFC 7493 §2.2), which `parse_json` enforces for
/// integer literals.
pub const MAX_ROUTE_ID: u64 = (1 << 53) - 1;

/// Parse and validate a config document. Total: never panics, for any input.
pub fn parse_config(input: &[u8]) -> Result<Config, ConfigError> {
    parse::parse(input)
}

/// The schema defaults (`canon` and `limits`) as a canonical JSON document.
pub fn defaults_json() -> Vec<u8> {
    emit::defaults_json()
}

// ------------------------------------------------------------------------------------------------ errors

/// What went wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// Input (or its effective canonical form) exceeds [`MAX_CONFIG_BYTES`] (CFG-2).
    TooLarge,
    /// Not strict I-JSON (the parser's reason is in the detail).
    Syntax,
    /// Wrong JSON type.
    Type,
    /// `additionalProperties: false`.
    UnknownField,
    /// `required`.
    MissingField,
    /// `const`.
    Const,
    /// `enum`.
    Enum,
    /// `pattern`.
    Pattern,
    /// `minimum`.
    Minimum,
    /// `maximum`.
    Maximum,
    /// `minItems`.
    MinItems,
    /// `maxItems`.
    MaxItems,
    /// `uniqueItems`.
    UniqueItems,
    /// `oneOf`: no branch (or more than one) matched.
    OneOf,
    /// Cross-field: two listeners share a name.
    DuplicateListener,
    /// Cross-field: two vhosts share a host.
    DuplicateHost,
    /// Cross-field: two routes of one vhost share an id.
    DuplicateRouteId,
    /// Cross-field: two `data.backends` share an id.
    DuplicateBackend,
    /// Cross-field: a cap's `backend` names no declared backend (or there is no `data` block).
    UnknownBackend,
    /// `pin` names no entry of `supply-chain/engine-pins.toml`.
    UnknownPin,
    /// `pin` names an entry whose engine family differs from `engine`.
    PinEngineMismatch,
    /// Boot ([`Config::resolve_data`]): the collection is not in the introspected schema.
    UnknownCollection,
    /// Boot ([`Config::resolve_data`]): a column is not in the introspected schema.
    UnknownColumn,
    /// Boot ([`Config::resolve_data`]): the backend's schema could not be introspected.
    SchemaUnavailable,
    /// Cross-field: two `p2.modules` share an id.
    DuplicateModule,
    /// Cross-field: a `{"wasm": id}` route target names no declared `p2.modules[]` entry (or there is no `p2`
    /// block).
    UnknownModule,
    /// A member that is valid alone but not in this combination (Phase 7): `alpn` on an L4 listener (a listener is
    /// L4 or HTTP, never both), `trust_anchor_id` on a credential whose kind is not `mtc`.
    Forbidden,
    /// Cross-field: two `l4` entries of one listener share an SNI.
    DuplicateSni,
    /// Cross-field: two `tls.credentials` share an id.
    DuplicateCredential,
    /// Cross-field: two `mtc` credentials share a trust_anchor_id (the selector would have two readings).
    DuplicateTrustAnchor,
    /// Cross-field: a credential's `listeners` entry names no declared listener.
    UnknownListener,
    /// Cross-field: a credential is scoped to a listener it may never serve: an L4 listener (no TLS termination), or,
    /// for an `mldsa` credential, a P-PUBLIC-WEB listener (SEL-2).
    CredentialScope,
    /// Cross-field: `admission.per_ip.burst` is below `rate_per_s` (less than one second of the rate).
    BurstBelowRate,
    /// A route `path` that matches the F8 pattern but is not a fixed point of `aegis_canon::canon_path` (a dot
    /// segment, an empty segment, a literal `;`, or over-long): it could never match a request, so it is refused at load (Phase 8,
    /// R13).
    NotCanonical,
}

/// A rejected config: kind, JSON pointer to the offending value (`""` is the document root) and a static detail.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConfigError {
    kind: ErrorKind,
    pointer: String,
    detail: &'static str,
}

impl ConfigError {
    pub(crate) fn new(kind: ErrorKind, pointer: impl Into<String>, detail: &'static str) -> Self {
        Self { kind, pointer: pointer.into(), detail }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// RFC 6901 JSON pointer (`""` = root).
    pub fn pointer(&self) -> &str {
        &self.pointer
    }

    pub fn detail(&self) -> &'static str {
        self.detail
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "config error at {:?}: {:?}: {}", self.pointer, self.kind, self.detail)
    }
}

impl std::error::Error for ConfigError {}

// ------------------------------------------------------------------------------------------------ typed config

/// A validated config with defaults applied. Constructible only by [`parse_config`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    listeners: Vec<Listener>,
    vhosts: Vec<Vhost>,
    admin: Option<Admin>,
    limits: Limits,
    canon: Canon,
    /// F8 `data`; `None` when absent.
    data: Option<DataBlock>,
    /// F8 `p2`; `None` when absent.
    p2: Option<P2Block>,
    /// F8 `tls` (Phase 7); `None` when absent (certificates from process options / systemd credentials).
    tls: Option<TlsBlock>,
    /// F8 `admission` (Phase 7) with defaults applied; the pre-Phase-7 constants when absent.
    admission: Admission,
    /// F8 `runtime` (Phase 8) with defaults applied; [`Runtime::default`] when absent.
    runtime: Runtime,
    /// F8 `state` (Phase 8); [`StateBlock::default`] (every member absent) when absent.
    state: StateBlock,
    canonical: Box<[u8]>,
    hash: [u8; 32],
}

impl Config {
    pub fn listeners(&self) -> &[Listener] {
        &self.listeners
    }
    pub fn vhosts(&self) -> &[Vhost] {
        &self.vhosts
    }
    pub fn admin(&self) -> Option<&Admin> {
        self.admin.as_ref()
    }
    pub fn limits(&self) -> &Limits {
        &self.limits
    }
    pub fn canon(&self) -> &Canon {
        &self.canon
    }
    /// F8 `tls` (Phase 7, D-P7.4); `None` when absent.
    pub fn tls(&self) -> Option<&TlsBlock> {
        self.tls.as_ref()
    }
    /// F8 `admission` (Phase 7) with defaults applied: [`Admission::default`] (the pre-Phase-7 constants) when absent.
    pub fn admission(&self) -> &Admission {
        &self.admission
    }
    /// F8 `runtime` (Phase 8, D-P8.3) with defaults applied: `worker_threads` 2 when absent.
    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }
    /// F8 `state` (Phase 8, R12): `idempotency_retention_s` is `None` (never expire) when absent.
    pub fn state(&self) -> &StateBlock {
        &self.state
    }
    /// Canonical JSON (aegis-canon serializer) of the effective config, defaults applied.
    pub fn effective_json(&self) -> &[u8] {
        &self.canonical
    }
    /// [`Config::effective_json`] plus, inside `p2` (when present), the members `isolation_effective` (the path
    /// multi-principal modules run on, [`P2Block::effective_isolation`]) and `usable_cpus` (the count it was resolved
    /// from), canonical. The configured `isolation` stays as written (`auto` included). These two members depend on
    /// the host, so they are not part of [`Config::config_hash`], and the dump is not itself an F8 document.
    pub fn effective_dump(&self, usable_cpus: usize) -> Vec<u8> {
        emit::dump(self, usable_cpus)
    }
    /// SHA-256 of [`Config::effective_json`].
    pub fn config_hash(&self) -> [u8; 32] {
        self.hash
    }
    /// Lowercase hex of [`Config::config_hash`].
    pub fn config_hash_hex(&self) -> String {
        hex(&self.hash)
    }
}

/// TLS profile of a listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Profile {
    PublicWeb,
    PqRequired,
    Universal,
    BsiAlt,
    Cnsa,
    FipsFloor,
    FipsPqRequired,
    FipsCmvp,
}

impl Profile {
    pub(crate) const ALL: [(&'static str, Profile); 8] = [
        ("P-PUBLIC-WEB", Profile::PublicWeb),
        ("P-PQ-REQUIRED", Profile::PqRequired),
        ("P-UNIVERSAL", Profile::Universal),
        ("P-BSI-ALT", Profile::BsiAlt),
        ("P-CNSA", Profile::Cnsa),
        ("FIPS-FLOOR", Profile::FipsFloor),
        ("FIPS-PQ-REQUIRED", Profile::FipsPqRequired),
        ("FIPS-CMVP", Profile::FipsCmvp),
    ];
    pub fn as_str(self) -> &'static str {
        Self::ALL.iter().find(|(_, p)| *p == self).map_or("", |(s, _)| s)
    }
}

/// ALPN protocol id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Alpn {
    H2,
    Http11,
}

impl Alpn {
    pub(crate) const ALL: [(&'static str, Alpn); 2] = [("h2", Alpn::H2), ("http/1.1", Alpn::Http11)];
    pub fn as_str(self) -> &'static str {
        match self {
            Alpn::H2 => "h2",
            Alpn::Http11 => "http/1.1",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listener {
    pub name: String,
    pub bind: String,
    pub profile: Profile,
    /// `None` when absent (the schema gives no default; the TLS layer decides). Always `None` on an L4 listener.
    pub alpn: Option<Vec<Alpn>>,
    /// F8 `proxy_protocol` (Phase 7, PROXY-1..3); `None` = no PROXY header is ever accepted.
    pub proxy_protocol: Option<ProxyProtocol>,
    /// F8 `l4` (Phase 7, L4-1/L4-2); `Some` = an L4 SNI-passthrough listener (non-empty, unique SNI), never HTTP.
    pub l4: Option<Vec<L4Route>>,
    /// F8 `front` (Phase 7, FRONT-1); default [`Front::Epoll`].
    pub front: Front,
}

impl Listener {
    /// An L4 SNI-passthrough listener (never parses HTTP, never terminates TLS).
    pub fn is_l4(&self) -> bool {
        self.l4.is_some()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admin {
    pub bind: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vhost {
    /// ASCII-lowercase A-label (exact match, CANON-6).
    pub host: String,
    pub routes: Vec<Route>,
}

/// Upstream framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Framing {
    H2,
    Uds,
    H1Regenerate,
}

impl Framing {
    pub(crate) const ALL: [(&'static str, Framing); 3] =
        [("h2", Framing::H2), ("uds", Framing::Uds), ("h1-regenerate", Framing::H1Regenerate)];
    pub fn as_str(self) -> &'static str {
        match self {
            Framing::H2 => "h2",
            Framing::Uds => "uds",
            Framing::H1Regenerate => "h1-regenerate",
        }
    }
}

/// Route target (`oneOf` in F8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteTarget {
    /// Upstream name: an opaque string (F8 declares no upstream table to resolve it against).
    Upstream {
        upstream: String,
        framing: Option<Framing>,
    },
    Static {
        root: String,
    },
    /// `{"wasm": <module-id>}` (Phase 5, F14): names a declared `p2.modules[]` entry (checked at load).
    Wasm {
        module: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub id: u64,
    pub path: String,
    pub to: RouteTarget,
    pub authz: Option<String>,
    /// F8 `routes[].data`. `None` (absent): the route holds no data capability and reaches no backend; it is
    /// never unrestricted. See [`RouteData`].
    pub data: Option<RouteData>,
}

/// What a route requires before any request reaches its target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthzRequirement<'a> {
    /// No policy set: the route is denied (INV-NONEMPTY).
    Deny,
    /// Evaluate this Cedar policy set.
    Policy(&'a str),
}

impl Route {
    /// INV-NONEMPTY: absent (or empty) `authz` denies.
    pub fn authz_requirement(&self) -> AuthzRequirement<'_> {
        match self.authz.as_deref() {
            None | Some("") => AuthzRequirement::Deny,
            Some(p) => AuthzRequirement::Policy(p),
        }
    }
}

/// Query handling (`canon.query`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum QueryMode {
    #[default]
    Opaque,
    Typed,
}

impl QueryMode {
    pub(crate) const ALL: [(&'static str, QueryMode); 2] = [("opaque", QueryMode::Opaque), ("typed", QueryMode::Typed)];
    pub fn as_str(self) -> &'static str {
        match self {
            QueryMode::Opaque => "opaque",
            QueryMode::Typed => "typed",
        }
    }
}

/// `canon` section. Every clause but `query` is a schema `const` (decided by spike q4-008), so only `query`
/// varies; the fixed clauses are exposed as constants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Canon {
    pub query: QueryMode,
}

impl Canon {
    /// (field, the only accepted value), in schema order.
    pub const FIXED: [(&'static str, &'static str); 6] = [
        ("dot_segments", "reject"),
        ("encoded_slash", "reject"),
        ("non_ascii_host", "reject"),
        ("encoded_non_ascii_path", "accept_opaque"),
        ("empty_segments", "redirect_308"),
        ("trailing_slash", "accept"),
    ];
}

macro_rules! limits {
    ($( $field:ident : $min:expr, $max:expr, $default:expr; )*) => {
        /// `limits` section: every value bounded by the schema, every value defaulted (golden defaults,
        /// ARCHITECTURE §3.1).
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct Limits {
            $( pub $field: u64, )*
        }

        impl Limits {
            /// (field, minimum, maximum, default), in schema order.
            pub const BOUNDS: &'static [(&'static str, u64, u64, u64)] = &[
                $( (stringify!($field), $min, $max, $default), )*
            ];

            /// Values in [`Limits::BOUNDS`] order.
            pub fn values(&self) -> Vec<u64> {
                vec![$( self.$field, )*]
            }

            pub(crate) fn set(&mut self, name: &str, v: u64) {
                match name {
                    $( stringify!($field) => self.$field = v, )*
                    _ => {}
                }
            }
        }

        impl Default for Limits {
            fn default() -> Self {
                Self { $( $field: $default, )* }
            }
        }
    };
}

limits! {
    max_concurrent_streams: 1, 1000, 100;
    max_header_list_size: 1024, 65536, 16384;
    max_header_fields: 8, 256, 128;
    header_table_size: 0, 65536, 4096;
    rst_burst: 1, 1000, 100;
    rst_refill_per_s: 1, 1000, 33;
    max_streams_per_conn: 1, 100_000, 10_000;
    stream_window: 65535, 16_777_216, 262_144;
    conn_window: 65535, 67_108_864, 1_048_576;
    stall_timeout_ms: 100, 120_000, 10_000;
    idle_timeout_ms: 1000, 600_000, 30_000;
    max_body_bytes: 0, 1_073_741_824, 1_048_576;
    per_conn_memory_bytes: 65536, 268_435_456, 16_777_216;
}
