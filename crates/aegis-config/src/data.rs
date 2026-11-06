//! F8 `data` block (Phase 4, P4-spec-001) and per-route data endowments (F4 CapSet as configuration).
//!
//! INV-NONEMPTY by type:
//! * a route whose `data` member is absent has `Route::data == None`: it holds no data capability and cannot
//!   reach any backend. It is never read as "unrestricted";
//! * [`RouteData::Caps`] wraps a [`CapList`], which has no public constructor and is non-empty (1..=256 caps) by
//!   construction in the parser; an empty list is a load error (`MinItems`), never "all";
//! * [`RouteData::Unrestricted`] is produced only from the exact literal `"unrestricted"`, and every such route is
//!   listed and CI-gated (`ci/unrestricted.py`, gate unrestricted-ledger). The built-in default never carries it.
//!
//! Checks the schema cannot express, enforced at load ([`crate::parse_config`]): backend ids are unique; every
//! `pin` names an entry of `supply-chain/engine-pins.toml` (embedded at build time, see [`engine_pins`]) whose
//! family equals `engine`; every cap's `backend` names a declared backend. Column names are resolved against the
//! introspected schema at boot through the [`SchemaProvider`] seam ([`Config::resolve_data`]); an unknown
//! collection or column fails the boot.
//!
//! This crate does not depend on `aegis-data-ir` (no such edge is wired; layering keeps L2 crates apart). The
//! resolved form ([`ResolvedCap`]) carries exactly what `aegis_data_ir::DataCap::new` takes: backend id,
//! collection, an op bit mask equal to `OpMask::bits` (Select 1, Insert 2, Update 4, Delete 8, Upsert 16) and
//! field ids (`aegis_data_ir::Field` = `u32`).

use std::sync::OnceLock;

use crate::{Config, ConfigError, ErrorKind};

/// Most backends in the `data` block (F8 `data.backends` maxItems).
pub const MAX_BACKENDS: usize = 64;
/// Most capabilities one route may hold (F8 `routes[].data` maxItems; equals `aegis_data_ir::MAX_CAPS`).
pub const MAX_CAPS: usize = 256;
/// Most columns one capability may name (F8 `columns` maxItems; equals `aegis_data_ir::MAX_CAP_COLUMNS`).
pub const MAX_CAP_COLUMNS: usize = 256;
/// The only literal that grants `CapSet::Unrestricted`.
pub const UNRESTRICTED: &str = "unrestricted";

/// Field id of a resolved column (same width as `aegis_data_ir::Field`).
pub type FieldId = u32;

// ------------------------------------------------------------------------------------------------ backends

/// F8 `backend.engine` (F4 `EngineFamily` names).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Engine {
    Sqlite,
    Postgres,
    Redis,
    Valkey,
}

impl Engine {
    pub(crate) const ALL: [(&'static str, Engine); 4] = [
        ("sqlite", Engine::Sqlite),
        ("postgres", Engine::Postgres),
        ("redis", Engine::Redis),
        ("valkey", Engine::Valkey),
    ];
    /// The F8 / F4 family name.
    pub fn as_str(self) -> &'static str {
        match self {
            Engine::Sqlite => "sqlite",
            Engine::Postgres => "postgres",
            Engine::Redis => "redis",
            Engine::Valkey => "valkey",
        }
    }
    pub fn from_name(s: &str) -> Option<Engine> {
        Self::ALL.iter().find(|(n, _)| *n == s).map(|(_, e)| *e)
    }
    /// In-process engine (no network DSN; `dsn_ref` must be `path:`).
    pub fn is_embedded(self) -> bool {
        matches!(self, Engine::Sqlite)
    }
}

/// F8 `backend.dsn_ref`: where the connection target comes from, never an inline DSN or secret.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DsnRef {
    /// `env:NAME`: the environment variable NAME holds the DSN (network engines only).
    Env(String),
    /// `cred:NAME`: the systemd credential NAME holds the DSN (network engines only).
    Cred(String),
    /// `path:/abs`: the SQLite database file (engine sqlite only). Holds the absolute path, without `path:`.
    Path(String),
}

impl DsnRef {
    /// The F8 text form (`env:NAME`, `cred:NAME`, `path:/abs`).
    pub fn to_f8(&self) -> String {
        match self {
            DsnRef::Env(n) => format!("env:{n}"),
            DsnRef::Cred(n) => format!("cred:{n}"),
            DsnRef::Path(p) => format!("path:{p}"),
        }
    }
}

/// F8 `backend.engine` Phase-7 adapter families (D-P7.8). Kept apart from [`Engine`] (the Phase-4 golden
/// families) so an assembly that predates them cannot route an endowment on one to a golden engine: a cap on an
/// adapter backend resolves only through [`SchemaProvider::adapter_field`], whose default refuses
/// ([`Unresolved::Unavailable`], the boot fails).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AdapterFamily {
    /// MariaDB (feature `adapter-mariadb`, aegis-adapter-mysql; own MySQL wire client).
    Mariadb,
    /// CockroachDB (feature `adapter-crdb`; the PG wire, aegis-adapter-pg with the crdb dialect).
    Crdb,
}

impl AdapterFamily {
    pub(crate) const ALL: [(&'static str, AdapterFamily); 2] =
        [("mariadb", AdapterFamily::Mariadb), ("crdb", AdapterFamily::Crdb)];
    /// The F8 family name (also the engine-pins.toml `kind` of its pins).
    pub fn as_str(self) -> &'static str {
        match self {
            AdapterFamily::Mariadb => "mariadb",
            AdapterFamily::Crdb => "crdb",
        }
    }
    pub fn from_name(s: &str) -> Option<AdapterFamily> {
        Self::ALL.iter().find(|(n, _)| *n == s).map(|(_, e)| *e)
    }
}

/// One declared backend of a Phase-7 adapter family, schema defaults applied (network engine: `dsn_ref` is
/// `env:` or `cred:`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterBackend {
    /// `^[a-z][a-z0-9-]{0,31}$`, unique within the block (across both kinds of backend).
    pub id: String,
    pub family: AdapterFamily,
    pub dsn_ref: DsnRef,
    /// Name of an entry in `supply-chain/engine-pins.toml` whose `kind` is this family (checked at load).
    pub pin: String,
    /// Same bounds and default as [`Backend::max_conns`].
    pub max_conns: u64,
    /// Same bounds and default as [`Backend::op_budget_ms`].
    pub op_budget_ms: u64,
}

/// One declared backend, schema defaults applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backend {
    /// `^[a-z][a-z0-9-]{0,31}$`, unique within the block.
    pub id: String,
    pub engine: Engine,
    pub dsn_ref: DsnRef,
    /// Name of an entry in `supply-chain/engine-pins.toml` whose family equals `engine` (checked at load).
    pub pin: String,
    /// 1..=256, default 16. Pool size cap (network engines) or open-handle cap (sqlite).
    pub max_conns: u64,
    /// 10..=60000, default 5000. Per-op budget; PG statement_timeout and NC3 T_recover.
    pub op_budget_ms: u64,
}

impl Backend {
    pub const DEFAULT_MAX_CONNS: u64 = 16;
    pub const MAX_CONNS_BOUNDS: (u64, u64) = (1, 256);
    pub const DEFAULT_OP_BUDGET_MS: u64 = 5000;
    pub const OP_BUDGET_MS_BOUNDS: (u64, u64) = (10, 60_000);
}

/// Position of one declared backend in document order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Decl {
    Golden(usize),
    Adapter(usize),
}

/// The F8 `data` block: 1..=64 backends with unique ids. Constructible only by the parser.
///
/// Golden-family backends ([`Engine`]) are in [`DataBlock::backends`] and Phase-7 adapter-family backends
/// ([`AdapterFamily`]) in [`DataBlock::adapters`]; ids are unique across both. A config without adapter backends
/// has exactly the Phase-4 view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataBlock {
    pub(crate) backends: Vec<Backend>,
    pub(crate) adapters: Vec<AdapterBackend>,
    /// Document order of every declared backend (the effective form keeps it).
    pub(crate) order: Vec<Decl>,
}

impl DataBlock {
    /// The golden-family backends, in document order.
    pub fn backends(&self) -> &[Backend] {
        &self.backends
    }
    pub fn backend(&self, id: &str) -> Option<&Backend> {
        self.backends.iter().find(|b| b.id == id)
    }
    /// The Phase-7 adapter-family backends (mariadb, crdb), in document order.
    pub fn adapters(&self) -> &[AdapterBackend] {
        &self.adapters
    }
    pub fn adapter(&self, id: &str) -> Option<&AdapterBackend> {
        self.adapters.iter().find(|b| b.id == id)
    }
    /// Whether `id` names a declared backend of either kind.
    pub fn declares(&self, id: &str) -> bool {
        self.backend(id).is_some() || self.adapter(id).is_some()
    }
}

// ------------------------------------------------------------------------------------------------ caps

/// F8 `data_cap.ops` item (F4 `OpKind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DataOp {
    Select,
    Insert,
    Update,
    Delete,
    Upsert,
}

impl DataOp {
    /// Every op in F4 `OpKind::ALL` order.
    pub const ALL: [DataOp; 5] = [DataOp::Select, DataOp::Insert, DataOp::Update, DataOp::Delete, DataOp::Upsert];
    pub(crate) const NAMES: [(&'static str, DataOp); 5] = [
        ("select", DataOp::Select),
        ("insert", DataOp::Insert),
        ("update", DataOp::Update),
        ("delete", DataOp::Delete),
        ("upsert", DataOp::Upsert),
    ];
    /// Equal to `aegis_data_ir::OpKind::bit`.
    pub const fn bit(self) -> u8 {
        match self {
            DataOp::Select => 1,
            DataOp::Insert => 2,
            DataOp::Update => 4,
            DataOp::Delete => 8,
            DataOp::Upsert => 16,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            DataOp::Select => "select",
            DataOp::Insert => "insert",
            DataOp::Update => "update",
            DataOp::Delete => "delete",
            DataOp::Upsert => "upsert",
        }
    }
}

/// One capability as written in F8 (column names, not yet resolved). Constructible only by the parser.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CapSpec {
    pub(crate) backend: String,
    pub(crate) collection: String,
    /// Non-zero, only bits of [`DataOp::ALL`].
    pub(crate) ops: u8,
    /// Non-empty, unique, in document order.
    pub(crate) columns: Vec<String>,
}

impl CapSpec {
    /// A declared backend id (checked at load).
    pub fn backend(&self) -> &str {
        &self.backend
    }
    pub fn collection(&self) -> &str {
        &self.collection
    }
    /// Op mask, equal to `aegis_data_ir::OpMask::bits` (non-zero, ≤ 0x1f).
    pub fn ops_bits(&self) -> u8 {
        self.ops
    }
    /// The ops in F4 order.
    pub fn ops(&self) -> Vec<DataOp> {
        DataOp::ALL.into_iter().filter(|o| self.ops & o.bit() != 0).collect()
    }
    pub fn contains(&self, op: DataOp) -> bool {
        self.ops & op.bit() != 0
    }
    /// Column names (non-empty, unique, document order); resolved at boot by [`Config::resolve_data`].
    pub fn columns(&self) -> &[String] {
        &self.columns
    }
}

/// Non-empty list of 1..=256 caps. No public constructor and no `Default`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CapList(pub(crate) Vec<CapSpec>);

impl CapList {
    pub fn as_slice(&self) -> &[CapSpec] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Always false (kept for API completeness; the type cannot be empty).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A route's data endowment. `Route::data == None` (member absent) means no capability at all.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RouteData {
    /// `CapSet::Caps`: the route may reach only what one listed cap covers.
    Caps(CapList),
    /// `CapSet::Unrestricted`: only from the explicit literal; lifts the capability check only (tenant conjunct,
    /// schema gate, budgets and allowlist lock still apply). CI-gated by `ci/unrestricted.py`.
    Unrestricted,
}

// ------------------------------------------------------------------------------------------------ engine pins

/// One entry of `supply-chain/engine-pins.toml` whose `kind` is a Phase-7 adapter family (`mariadb`, `crdb`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterPinInfo {
    pub name: String,
    pub family: AdapterFamily,
    /// `policy` other than "allow".
    pub blocked: bool,
}

/// Every pin of the catalogue, by kind.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Pins {
    pub(crate) golden: Vec<PinInfo>,
    pub(crate) adapter: Vec<AdapterPinInfo>,
}

impl Pins {
    pub(crate) fn golden(&self, name: &str) -> Option<&PinInfo> {
        self.golden.iter().find(|p| p.name == name)
    }
    pub(crate) fn adapter(&self, name: &str) -> Option<&AdapterPinInfo> {
        self.adapter.iter().find(|p| p.name == name)
    }
}

/// One entry of `supply-chain/engine-pins.toml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinInfo {
    /// Table name: `sqlite` for the top-level `[sqlite]` table, `NAME` for `[engines.NAME]`.
    pub name: String,
    pub engine: Engine,
    /// `policy = "blocked"`: config may select it, but connect refuses every version of that major.
    pub blocked: bool,
}

const ENGINE_PINS_TOML: &str = include_str!("../../../supply-chain/engine-pins.toml");

/// `^[a-z][a-z0-9]{0,15}$` (F8 `backend.pin`).
pub(crate) fn is_pin_name(s: &str) -> bool {
    let b = s.as_bytes();
    match b.split_first() {
        Some((f, rest)) => {
            f.is_ascii_lowercase()
                && rest.len() <= 15
                && rest.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        }
        None => false,
    }
}

/// `key = "value"` with a bare lower-case key; returns (key, value) for the first quoted string.
fn kv_line(line: &str) -> Option<(&str, &str)> {
    let (k, rest) = line.split_once('=')?;
    let k = k.trim();
    if k.is_empty() || !k.bytes().all(|c| c.is_ascii_lowercase() || c == b'_') {
        return None;
    }
    let rest = rest.trim_start().strip_prefix('"')?;
    let (v, _) = rest.split_once('"')?;
    Some((k, v))
}

/// Parse the pin catalogue. Deliberately narrow: table headers and the `kind` / `policy` keys. An `[engines.X]`
/// table without a known `kind`, or with a name outside the F8 pin grammar, yields no entry (fail closed: a config
/// naming it is refused). Duplicate names keep none of the duplicates.
#[cfg(test)]
pub(crate) fn parse_pins(text: &str) -> Vec<PinInfo> {
    parse_all_pins(text).golden
}

/// [`parse_pins`] plus the Phase-7 adapter-family pins (`kind = "mariadb"` / `"crdb"`). A name used twice, by
/// either kind, keeps none of its entries.
pub(crate) fn parse_all_pins(text: &str) -> Pins {
    #[derive(Clone, Copy)]
    enum Fam {
        Golden(Engine),
        Adapter(AdapterFamily),
    }
    struct Cur {
        name: String,
        engine: Option<Fam>,
        blocked: bool,
        top_sqlite: bool,
    }
    fn flush(cur: Option<Cur>, out: &mut Pins, dup: &mut Vec<String>) {
        if let Some(c) = cur
            && let Some(fam) = c.engine
            && is_pin_name(&c.name)
        {
            if out.golden.iter().any(|p| p.name == c.name) || out.adapter.iter().any(|p| p.name == c.name) {
                dup.push(c.name);
            } else {
                match fam {
                    Fam::Golden(engine) => out.golden.push(PinInfo { name: c.name, engine, blocked: c.blocked }),
                    Fam::Adapter(family) => {
                        out.adapter.push(AdapterPinInfo { name: c.name, family, blocked: c.blocked });
                    }
                }
            }
        }
    }
    let mut out = Pins::default();
    let mut dup = Vec::new();
    let mut cur: Option<Cur> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(h) = line.strip_prefix('[') {
            flush(cur.take(), &mut out, &mut dup);
            if h.starts_with('[') {
                continue;
            }
            let name = h.split(']').next().unwrap_or("").trim();
            if name == "sqlite" {
                cur = Some(Cur {
                    name: name.to_owned(),
                    engine: Some(Fam::Golden(Engine::Sqlite)),
                    blocked: false,
                    top_sqlite: true,
                });
            } else if let Some(n) = name.strip_prefix("engines.") {
                cur = Some(Cur { name: n.to_owned(), engine: None, blocked: false, top_sqlite: false });
            }
            continue;
        }
        if let (Some(c), Some((k, v))) = (cur.as_mut(), kv_line(line)) {
            match k {
                // `[sqlite]` is SQLite by position; an `[engines.X]` table takes its family from `kind`.
                "kind" if !c.top_sqlite => {
                    c.engine =
                        Engine::from_name(v).map(Fam::Golden).or_else(|| AdapterFamily::from_name(v).map(Fam::Adapter));
                }
                "policy" => c.blocked = v != "allow",
                _ => {}
            }
        }
    }
    flush(cur, &mut out, &mut dup);
    out.golden.retain(|p| !dup.contains(&p.name));
    out.adapter.retain(|p| !dup.contains(&p.name));
    out
}

/// The whole pin catalogue compiled into this binary.
pub(crate) fn pins() -> &'static Pins {
    static PINS: OnceLock<Pins> = OnceLock::new();
    PINS.get_or_init(|| parse_all_pins(ENGINE_PINS_TOML))
}

/// The engine pins compiled into this binary from `supply-chain/engine-pins.toml`.
pub fn engine_pins() -> &'static [PinInfo] {
    &pins().golden
}

/// The Phase-7 adapter-family pins compiled into this binary (empty until engine-pins.toml carries a `kind =
/// "mariadb"` or `kind = "crdb"` entry; until then a backend of those families is refused with `UnknownPin`).
pub fn adapter_pins() -> &'static [AdapterPinInfo] {
    &pins().adapter
}

/// The adapter-family pin named `name`, if any.
pub fn adapter_pin(name: &str) -> Option<&'static AdapterPinInfo> {
    adapter_pins().iter().find(|p| p.name == name)
}

/// Look up a pin by name.
pub fn engine_pin(name: &str) -> Option<&'static PinInfo> {
    engine_pins().iter().find(|p| p.name == name)
}

// ------------------------------------------------------------------------------------------------ boot seam

/// Why a provider could not resolve a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Unresolved {
    /// The backend has no such collection.
    NoCollection,
    /// The collection has no such column.
    NoColumn,
    /// The schema could not be introspected (connect failure, refused version, ...). Fails the boot.
    Unavailable,
}

/// Boot-time schema seam: the assembly injects an implementation backed by live introspection (PG catalog,
/// SQLite `pragma_table_info`, the app's declared KV schema). Tests inject a fixed table.
pub trait SchemaProvider {
    /// The field id of `column` in `collection` on `backend`.
    fn field(&self, backend: &Backend, collection: &str, column: &str) -> Result<FieldId, Unresolved>;

    /// The same for a Phase-7 adapter-family backend. The default refuses ([`Unresolved::Unavailable`]), so an
    /// assembly that does not wire the family fails the boot on any endowment that names such a backend, instead of
    /// resolving it against another engine.
    fn adapter_field(&self, backend: &AdapterBackend, collection: &str, column: &str) -> Result<FieldId, Unresolved> {
        let _ = (backend, collection, column);
        Err(Unresolved::Unavailable)
    }
}

/// One cap with its columns resolved: the arguments of `aegis_data_ir::DataCap::new`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ResolvedCap {
    pub backend: String,
    pub collection: String,
    /// `aegis_data_ir::OpMask::from_bits` input (non-zero, ≤ 0x1f).
    pub ops_bits: u8,
    /// Sorted, deduplicated, non-empty.
    pub fields: Vec<FieldId>,
}

/// Resolved endowment: `aegis_data_ir::CapSet` minus the private constructors.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ResolvedData {
    /// Non-empty (one entry per configured cap, in order).
    Caps(Vec<ResolvedCap>),
    Unrestricted,
}

/// A route that holds a data endowment. Routes without `data` are not listed: they hold no capability.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ResolvedRoute {
    pub host: String,
    pub route_id: u64,
    pub data: ResolvedData,
}

impl Config {
    /// The `data` block; `None` when absent (then no route can hold a capability list).
    pub fn data(&self) -> Option<&DataBlock> {
        self.data.as_ref()
    }

    /// Boot-time resolution of every cap's column names against the introspected schema. Total; the first
    /// failure is returned with a JSON pointer into the config (`.../data/<k>/collection` or
    /// `.../data/<k>/columns/<m>`), and the boot must fail on it.
    pub fn resolve_data(&self, schema: &dyn SchemaProvider) -> Result<Vec<ResolvedRoute>, ConfigError> {
        let mut out = Vec::new();
        for (i, vh) in self.vhosts.iter().enumerate() {
            for (j, r) in vh.routes.iter().enumerate() {
                let data = match &r.data {
                    None => continue,
                    Some(RouteData::Unrestricted) => ResolvedData::Unrestricted,
                    Some(RouteData::Caps(list)) => {
                        let mut caps = Vec::with_capacity(list.len());
                        for (k, c) in list.as_slice().iter().enumerate() {
                            let p = format!("/vhosts/{i}/routes/{j}/data/{k}");
                            let d = self.data.as_ref();
                            let golden = d.and_then(|d| d.backend(&c.backend));
                            let adapter = d.and_then(|d| d.adapter(&c.backend));
                            if golden.is_none() && adapter.is_none() {
                                return Err(ConfigError::new(
                                    ErrorKind::UnknownBackend,
                                    format!("{p}/backend"),
                                    "cap names an undeclared backend",
                                ));
                            }
                            let lookup = |col: &str| match (golden, adapter) {
                                (Some(b), _) => schema.field(b, &c.collection, col),
                                (None, Some(a)) => schema.adapter_field(a, &c.collection, col),
                                (None, None) => Err(Unresolved::Unavailable),
                            };
                            let mut fields = Vec::with_capacity(c.columns.len());
                            for (m, col) in c.columns.iter().enumerate() {
                                match lookup(col) {
                                    Ok(f) => fields.push(f),
                                    Err(Unresolved::NoCollection) => {
                                        return Err(ConfigError::new(
                                            ErrorKind::UnknownCollection,
                                            format!("{p}/collection"),
                                            "collection not in the introspected schema",
                                        ));
                                    }
                                    Err(Unresolved::NoColumn) => {
                                        return Err(ConfigError::new(
                                            ErrorKind::UnknownColumn,
                                            format!("{p}/columns/{m}"),
                                            "column not in the introspected schema",
                                        ));
                                    }
                                    Err(Unresolved::Unavailable) => {
                                        return Err(ConfigError::new(
                                            ErrorKind::SchemaUnavailable,
                                            format!("{p}/backend"),
                                            "backend schema could not be introspected",
                                        ));
                                    }
                                }
                            }
                            fields.sort_unstable();
                            fields.dedup();
                            if fields.len() != c.columns.len() {
                                return Err(ConfigError::new(
                                    ErrorKind::UnknownColumn,
                                    format!("{p}/columns"),
                                    "two column names resolved to one field",
                                ));
                            }
                            caps.push(ResolvedCap {
                                backend: c.backend.clone(),
                                collection: c.collection.clone(),
                                ops_bits: c.ops,
                                fields,
                            });
                        }
                        if caps.is_empty() {
                            // Unreachable (CapList is non-empty); fail closed rather than emit an empty set.
                            return Err(ConfigError::new(
                                ErrorKind::MinItems,
                                format!("/vhosts/{i}/routes/{j}/data"),
                                "empty capability list",
                            ));
                        }
                        ResolvedData::Caps(caps)
                    }
                };
                out.push(ResolvedRoute { host: vh.host.clone(), route_id: r.id, data });
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn pin_parser_fails_closed() {
        let t = r#"
schema = 1
[sqlite]
version = "3.53.2"
[engines.pga]
kind = "postgres"   # trailing comment
policy = "allow"
sources = [
  "x (kind = \"redis\")",
]
[engines.pgb]
kind = "postgres"
policy = "blocked"
[engines.nokind]
policy = "allow"
[engines.weird]
kind = "mysql"
[engines.Bad-Name]
kind = "redis"
[engines.dup]
kind = "redis"
[engines.dup]
kind = "redis"
[[array]]
kind = "redis"
"#;
        let p = parse_pins(t);
        let got: Vec<(&str, Engine, bool)> = p.iter().map(|p| (p.name.as_str(), p.engine, p.blocked)).collect();
        assert_eq!(
            got,
            vec![("sqlite", Engine::Sqlite, false), ("pga", Engine::Postgres, false), ("pgb", Engine::Postgres, true)]
        );
        assert!(parse_pins("").is_empty());
    }

    #[test]
    fn adapter_pins_parse_apart_and_duplicates_across_kinds_drop_both() {
        let t = r#"
[engines.pg18]
kind = "postgres"
[engines.maria118]
kind = "mariadb"
policy = "allow"
[engines.crdb254]
kind = "crdb"
policy = "blocked"
[engines.both]
kind = "postgres"
[engines.both]
kind = "mariadb"
[engines.mysql84]
kind = "mysql"
"#;
        let p = parse_all_pins(t);
        let g: Vec<&str> = p.golden.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(g, vec!["pg18"]);
        let a: Vec<(&str, AdapterFamily, bool)> =
            p.adapter.iter().map(|x| (x.name.as_str(), x.family, x.blocked)).collect();
        assert_eq!(a, vec![("maria118", AdapterFamily::Mariadb, false), ("crdb254", AdapterFamily::Crdb, true)]);
        // The golden view is unchanged by adapter entries.
        assert_eq!(parse_pins(t).len(), 1);
    }
}
