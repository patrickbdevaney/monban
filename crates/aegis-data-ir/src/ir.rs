//! Frozen interface F4 (see crate docs).

use aegis_types::TenantId;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

/// Column index in a schema (Lean: `Field := Nat`).
pub type Field = u32;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Value {
    Int(i64),
    Str(String),
}

/// IR filter. `And`/`Or` are binary; n-ary forms desugar with `and_n([]) = Tt`, `or_n([]) = Ff`, so an empty
/// disjunction can never widen access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pred {
    Tt,
    Ff,
    Eq(Field, Value),
    IsIn(Field, Vec<Value>),
    Range(Field, Value, Value),
    Pfx(Field, String),
    And(Box<Pred>, Box<Pred>),
    Or(Box<Pred>, Box<Pred>),
    Not(Box<Pred>),
}

impl Pred {
    pub fn and_n(ps: Vec<Pred>) -> Pred {
        ps.into_iter().rev().fold(Pred::Tt, |acc, p| Pred::And(Box::new(p), Box::new(acc)))
    }
    pub fn or_n(ps: Vec<Pred>) -> Pred {
        ps.into_iter().rev().fold(Pred::Ff, |acc, p| Pred::Or(Box::new(p), Box::new(acc)))
    }
    fn reads(&self, out: &mut Vec<Field>) {
        match self {
            Pred::Tt | Pred::Ff => {}
            Pred::Eq(f, _) | Pred::IsIn(f, _) | Pred::Range(f, _, _) | Pred::Pfx(f, _) => out.push(*f),
            Pred::And(a, b) | Pred::Or(a, b) => {
                a.reads(out);
                b.reads(out);
            }
            Pred::Not(a) => a.reads(out),
        }
    }
}

/// Operation kinds a capability may grant (D2: a child token's op bitmask is a subset of its parent's).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OpKind {
    Select,
    Insert,
    Update,
    Delete,
    Upsert,
}

/// One data-plane operation, already authorized for `tenant`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op {
    pub tenant: TenantId,
    pub collection: String,
    pub kind: OpKind,
    pub filter: Pred,
    /// Columns written (Insert/Update/Upsert); W2 requires every post-image to carry `tenant`.
    pub writes: Vec<(Field, Value)>,
    /// Columns returned; W4 requires RETURNING ⊆ permitted columns.
    pub returning: Vec<Field>,
}

/// Engine collation of a column. Soundness needs engine equality to refine the reference (`Backend.Refines`);
/// case-insensitive or nondeterministic collations break it (`refines_necessary`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Collation {
    /// Byte-wise, deterministic and NO-PAD (PG "C" or deterministic ICU, SQLite BINARY, MariaDB
    /// utf8mb4_nopad_bin / VARBINARY, Redis keys). Trailing-space-padding `*_bin` collations are `PadSpace`.
    Binary,
    /// Binary but compares with trailing-space padding (MariaDB/MySQL utf8mb4_bin): 'acme ' = 'acme'.
    PadSpace,
    /// SQLite NOCASE, MySQL *_ci, citext and similar.
    CaseInsensitive,
    /// Nondeterministic ICU or anything else not byte-wise.
    Nondeterministic,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Column {
    pub field: Field,
    pub name: String,
    pub nullable: bool,
    pub collation: Collation,
    /// Part of the upsert/merge arbiter key (W3).
    pub key: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schema {
    pub collection: String,
    pub tenant_field: Field,
    pub columns: Vec<Column>,
    /// Columns a caller may read or return.
    pub permitted: Vec<Field>,
    /// Every unique index (including the primary key) as its column list. `prefix` marks an index that covers
    /// only a prefix of some column (e.g. MySQL `tenant(3)`).
    pub unique_indexes: Vec<UniqueIndex>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UniqueIndex {
    pub fields: Vec<Field>,
    pub prefix: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaError {
    UnknownField(Field),
    /// `Not` is only sound on exact adapters (`refines_insufficient_for_not3`).
    NotRequiresExact,
    TenantFieldNullable,
    /// Tenant or key column with a non-binary collation (W3, `refines_necessary`).
    NonBinaryCollation(Field),
    TenantFieldWritten,
    ReturningNotPermitted(Field),
    /// Upsert needs the table's ONLY unique index to be exactly (tenant, key columns), full-length (W3, q4-005):
    /// engines such as MariaDB arbitrate on any unique index, so a second one lets an upsert land on a foreign row.
    UpsertArbiterNotTenantScoped,
    CollectionMismatch,
}

fn has_not(p: &Pred) -> bool {
    match p {
        Pred::Not(_) => true,
        Pred::And(a, b) | Pred::Or(a, b) => has_not(a) || has_not(b),
        _ => false,
    }
}

/// Static check an `Op` must pass before any adapter sees it. Total: never panics.
pub fn check_schema(op: &Op, s: &Schema, fidelity: Fidelity) -> Result<(), SchemaError> {
    if op.collection != s.collection {
        return Err(SchemaError::CollectionMismatch);
    }
    if s.columns.iter().any(|c| c.field == s.tenant_field && c.nullable) {
        return Err(SchemaError::TenantFieldNullable);
    }
    if let Some(c) = s.columns.iter().find(|c| (c.field == s.tenant_field || c.key) && c.collation != Collation::Binary)
    {
        return Err(SchemaError::NonBinaryCollation(c.field));
    }
    let mut reads = Vec::new();
    op.filter.reads(&mut reads);
    for f in reads.iter().chain(op.writes.iter().map(|(f, _)| f)).chain(op.returning.iter()) {
        if !s.columns.iter().any(|c| c.field == *f) {
            return Err(SchemaError::UnknownField(*f));
        }
    }
    if op.writes.iter().any(|(f, _)| *f == s.tenant_field) {
        return Err(SchemaError::TenantFieldWritten);
    }
    if let Some(f) = op.returning.iter().find(|f| !s.permitted.contains(f)) {
        return Err(SchemaError::ReturningNotPermitted(*f));
    }
    if op.kind == OpKind::Upsert {
        let mut want: Vec<Field> =
            s.columns.iter().filter(|c| c.key || c.field == s.tenant_field).map(|c| c.field).collect();
        want.sort_unstable();
        let ok = match s.unique_indexes.as_slice() {
            [only] => {
                let mut got = only.fields.clone();
                got.sort_unstable();
                !only.prefix && got == want && got.contains(&s.tenant_field) && got.len() >= 2
            }
            _ => false,
        };
        if !ok {
            return Err(SchemaError::UpsertArbiterNotTenantScoped);
        }
    }
    if fidelity != Fidelity::Exact && has_not(&op.filter) {
        return Err(SchemaError::NotRequiresExact);
    }
    Ok(())
}

/// What a backend can guarantee for the lowering-soundness theorem (Lean `Backend.Exact` vs `Backend.Refines`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fidelity {
    /// rows(render(lowerQ t p)) = {x | refQ3 t p x} (`rows_exact3`). Required for adapters accepting `Not`.
    /// Every rendered atom must yield UNKNOWN on a NULL column (so `In []` is never rendered as constant FALSE).
    Exact,
    /// rows ⊆ reference rows for `Not`-free predicates (never leaks; may miss).
    Refines,
}

/// An adapter lowers checked ops for one engine. Adapters outside the golden set run out of process
/// (aegis-adapter-host) and carry no assurance claim (golden extension contract, SPEC_INVARIANTS §H).
pub trait Adapter {
    type Rendered;
    type Error;
    fn engine_pin(&self) -> &str;
    fn fidelity(&self) -> Fidelity;
    /// Must render exactly `lowerQ(schema.tenant_field, op.tenant, op.filter)` plus the write/returning forms
    /// mandated for the engine (composite arbiters, FORCE RLS + WITH CHECK, no REPLACE family).
    fn render(&self, op: &Op, schema: &Schema) -> Result<Self::Rendered, Self::Error>;
}

// ================================================================================================================
// Additive re-freeze (P4-spec-001, PLAN Phase 4 decisions D1 and D4). Nothing above this line changed: the Op, Pred,
// Schema and OpKind layouts are as before, so F10 (which mirrors Op positionally) stays byte-compatible.
// ================================================================================================================

/// Longest backend id, collection name or adapter name accepted anywhere in F4 (and in F8's `data` block).
pub const MAX_NAME_BYTES: usize = 63;
/// Most capabilities one route may hold (F8 `routes[].data` maxItems).
pub const MAX_CAPS: usize = 256;
/// Most columns one capability may name (F8 `columns` maxItems).
pub const MAX_CAP_COLUMNS: usize = 256;

impl OpKind {
    /// Every kind, in declaration order. Position i is F10's `kind` code i and owns bit `1 << i` of [`OpMask`].
    pub const ALL: [OpKind; 5] = [OpKind::Select, OpKind::Insert, OpKind::Update, OpKind::Delete, OpKind::Upsert];

    /// The kind's bit in an [`OpMask`]. Equal to `aegis_sdk::op_code` (F7): Select 1, Insert 2, Update 4,
    /// Delete 8, Upsert 16.
    pub const fn bit(self) -> u8 {
        match self {
            OpKind::Select => 1,
            OpKind::Insert => 2,
            OpKind::Update => 4,
            OpKind::Delete => 8,
            OpKind::Upsert => 16,
        }
    }

    /// Lower-case name used in F8 (`ops`) and in the allowlist lock.
    pub const fn name(self) -> &'static str {
        match self {
            OpKind::Select => "select",
            OpKind::Insert => "insert",
            OpKind::Update => "update",
            OpKind::Delete => "delete",
            OpKind::Upsert => "upsert",
        }
    }

    pub fn from_name(s: &str) -> Option<OpKind> {
        OpKind::ALL.into_iter().find(|k| k.name() == s)
    }
}

/// Non-empty set of [`OpKind`]s. There is no empty mask and no `Default`: a capability that grants no operation
/// cannot be written down (INV-NONEMPTY), so "zero bits" can never be read as "all operations".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OpMask(u8);

impl OpMask {
    const VALID: u8 = 0b1_1111;

    /// Accepts 1..=0x1f; zero or any bit above Upsert is refused.
    pub const fn from_bits(bits: u8) -> Result<OpMask, CapError> {
        if bits == 0 || bits & !Self::VALID != 0 { Err(CapError::BadOps) } else { Ok(OpMask(bits)) }
    }
    pub fn of(kinds: &[OpKind]) -> Result<OpMask, CapError> {
        OpMask::from_bits(kinds.iter().fold(0, |m, k| m | k.bit()))
    }
    pub const fn bits(self) -> u8 {
        self.0
    }
    pub const fn contains(self, k: OpKind) -> bool {
        self.0 & k.bit() != 0
    }
    /// D2 (token attenuation): a child mask must be a subset of its parent's.
    pub const fn is_subset_of(self, parent: OpMask) -> bool {
        self.0 & !parent.0 == 0
    }
}

/// Why a capability, capability set or name was refused at construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapError {
    /// INV-NONEMPTY: an empty list of capabilities is not a capability set. Write `CapSet::Unrestricted` instead
    /// if that is really meant (explicit and CI-gated by `ci/unrestricted.py`).
    EmptyCapSet,
    TooManyCaps,
    /// Empty op mask or bits outside the five kinds.
    BadOps,
    /// INV-NONEMPTY at column level: no columns never means all columns.
    EmptyColumns,
    TooManyColumns,
    BadBackendId,
    BadCollection,
}

/// Backend id grammar, identical to F8 `backend.id`: `^[a-z][a-z0-9-]{0,31}$`.
pub fn valid_backend_id(s: &str) -> bool {
    let b = s.as_bytes();
    match b.split_first() {
        Some((first, rest)) => {
            first.is_ascii_lowercase()
                && rest.len() <= 31
                && rest.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        }
        None => false,
    }
}

/// Collection grammar, identical to F8 `cap.collection`: `^[a-z_][a-z0-9_]{0,62}$`. It contains no `:`, no glob
/// metacharacter, no whitespace and no quote, so it is safe as a Redis key segment and as a lock-file token.
pub fn valid_collection(s: &str) -> bool {
    let b = s.as_bytes();
    match b.split_first() {
        Some((first, rest)) => {
            (first.is_ascii_lowercase() || *first == b'_')
                && rest.len() < MAX_NAME_BYTES
                && rest.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
        }
        None => false,
    }
}

/// One data capability: operations `ops` on `collection` of backend `backend`, touching only `columns`.
/// Fields are private; [`DataCap::new`] is the only constructor. (Distinct from `aegis_sdk::DataCap<K>`, the F7
/// marker type that proves a grant to a handler.)
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DataCap {
    backend: String,
    collection: String,
    ops: OpMask,
    /// Sorted, deduplicated, non-empty. Resolved from F8 column names against the introspected schema at boot;
    /// an unknown name fails the boot.
    columns: Vec<Field>,
}

impl DataCap {
    pub fn new(backend: &str, collection: &str, ops: OpMask, mut columns: Vec<Field>) -> Result<DataCap, CapError> {
        if !valid_backend_id(backend) {
            return Err(CapError::BadBackendId);
        }
        if !valid_collection(collection) {
            return Err(CapError::BadCollection);
        }
        columns.sort_unstable();
        columns.dedup();
        if columns.is_empty() {
            return Err(CapError::EmptyColumns);
        }
        if columns.len() > MAX_CAP_COLUMNS {
            return Err(CapError::TooManyColumns);
        }
        Ok(DataCap { backend: backend.into(), collection: collection.into(), ops, columns })
    }
    pub fn backend(&self) -> &str {
        &self.backend
    }
    pub fn collection(&self) -> &str {
        &self.collection
    }
    pub fn ops(&self) -> OpMask {
        self.ops
    }
    pub fn columns(&self) -> &[Field] {
        &self.columns
    }

    /// True iff this single capability covers `op` on `backend`: same backend and collection, the op kind is in
    /// the mask, and every field the op reads (filter), writes or returns is in `columns`.
    pub fn covers(&self, backend: &str, op: &Op) -> bool {
        if self.backend != backend || self.collection != op.collection || !self.ops.contains(op.kind) {
            return false;
        }
        let mut reads = Vec::new();
        op.filter.reads(&mut reads);
        reads
            .iter()
            .chain(op.writes.iter().map(|(f, _)| f))
            .chain(op.returning.iter())
            .all(|f| self.columns.binary_search(f).is_ok())
    }
}

/// A non-empty list of capabilities (at most [`MAX_CAPS`]). Private field, no `Default`, no empty constructor.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Caps(Vec<DataCap>);

impl Caps {
    pub fn new(caps: Vec<DataCap>) -> Result<Caps, CapError> {
        if caps.is_empty() {
            return Err(CapError::EmptyCapSet);
        }
        if caps.len() > MAX_CAPS {
            return Err(CapError::TooManyCaps);
        }
        Ok(Caps(caps))
    }
    pub fn as_slice(&self) -> &[DataCap] {
        &self.0
    }
}

/// The data authority a route holds (INV-NONEMPTY by type). Absent F8 `routes[].data` means the route holds no
/// `CapSet` at all, so it cannot reach any backend; it never means `Unrestricted`. `Unrestricted` is only ever
/// produced from the explicit F8 literal `"unrestricted"`, and every such route is listed and CI-gated
/// (`ci/unrestricted.py`). `Unrestricted` lifts the capability check only: the tenant conjunct, `check_schema`,
/// budgets and the allowlist lock still apply.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CapSet {
    Caps(Caps),
    Unrestricted,
}

/// Uniform refusal from [`authorize`]. It carries no reason, so a caller learns nothing about which part of the
/// capability failed or whether the collection exists (W6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Denied;

/// Capability check, run by the host before `check_schema`, budgets and `render` (render is never reached on deny).
/// Allows iff `caps` is `Unrestricted` or some single [`DataCap`] covers the whole op ([`DataCap::covers`]).
/// Capabilities are not unioned: two caps that each cover half of an op do not authorize it. Total: never panics.
pub fn authorize(caps: &CapSet, backend: &str, op: &Op) -> Result<(), Denied> {
    match caps {
        CapSet::Unrestricted => Ok(()),
        CapSet::Caps(c) if c.as_slice().iter().any(|d| d.covers(backend, op)) => Ok(()),
        CapSet::Caps(_) => Err(Denied),
    }
}

// ---------------------------------------------------------------------------------------------- tenant encoding (D4)

/// Length of the canonical tenant text.
pub const TENANT_TEXT_LEN: usize = 16;

/// Canonical engine value of a tenant (D4), the same in every engine: the `u64` as exactly 16 lower-case hex
/// digits, zero-padded (`TenantId(42)` → `"000000000000002a"`). SQL engines store it in a NOT NULL text column with
/// a binary, deterministic, no-pad collation (PG `COLLATE "C"`, SQLite `BINARY`) and bind it as a text parameter;
/// Redis/Valkey keys start with [`kv_key_prefix`]. Fixed width makes the encoding injective and prefix-free, so no
/// tenant's value is a prefix of another's. Oracles use the same encoding.
pub fn tenant_text(t: TenantId) -> String {
    let v = t.get();
    (0..TENANT_TEXT_LEN).rev().map(|i| char::from_digit(((v >> (i * 4)) & 0xf) as u32, 16).unwrap_or('0')).collect()
}

/// Inverse of [`tenant_text`]: exactly 16 lower-case hex digits, not all zero. Anything else is `None`.
pub fn parse_tenant_text(s: &str) -> Option<TenantId> {
    if s.len() != TENANT_TEXT_LEN || !s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return None;
    }
    let v = s.bytes().try_fold(0u64, |acc, c| Some((acc << 4) | u64::from(char::from(c).to_digit(16)?)))?;
    TenantId::new(v).ok()
}

// ------------------------------------------------------------------------------------------- key-value mapping rule

/// Longest Redis key or SCAN MATCH pattern an adapter may send (bounds glob work, CVE-2024-31228).
pub const KV_MAX_KEY_BYTES: usize = 1024;

/// `t:{<tenant_text>}:`. The braces are a Redis Cluster hash tag, so all of a tenant's keys share one slot; the
/// tag alphabet is `[0-9a-f]` and `}` terminates it, so the prefix is unambiguous.
pub fn kv_key_prefix(t: TenantId) -> String {
    let mut s = String::from("t:{");
    s.push_str(&tenant_text(t));
    s.push_str("}:");
    s
}

/// Full key of one row: `t:{<tenant_text>}:<collection>:<key>`. Injective across tenants and collections because
/// the prefix is fixed-width and `collection` cannot contain `:` ([`valid_collection`]).
pub fn kv_key(t: TenantId, collection: &str, key: &str) -> String {
    let mut s = kv_key_prefix(t);
    s.push_str(collection);
    s.push(':');
    s.push_str(key);
    s
}

/// Escapes every Redis glob metacharacter (`*`, `?`, `[`, `]`, `\`) with a backslash, so the result matches only
/// itself under `stringmatchlen`.
pub fn glob_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The only commands a key-value adapter emits for an [`Op`]. Every key and pattern starts with the tenant's
/// [`kv_key_prefix`]; nothing in [`denylist`] is reachable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KvCommand {
    /// Select with `Eq(key, s)`.
    Get { key: String },
    /// Select with `Tt` (pattern `<prefix><collection>:*`) or `Pfx(key, s)` (pattern
    /// `<prefix><collection>:<glob_escape(s)>*`). The host drives the cursor and re-checks each returned key starts
    /// with the tenant prefix (W7).
    Scan { pattern: String },
    /// Insert: `SET key value NX` (never overwrites).
    SetNx { key: String, value: String },
    /// Upsert: `SET key value`.
    Set { key: String, value: String },
    /// Update with `Eq(key, s)`: `SET key value XX` (only if present).
    SetXx { key: String, value: String },
    /// Delete with `Eq(key, s)`: `DEL key`.
    Del { key: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KvError {
    Schema(SchemaError),
    /// A KV collection has exactly three columns: the tenant (not nullable), one key column (`key = true`) and one
    /// value column; its only unique index is (tenant, key).
    NotKvSchema,
    /// Filter shape not in the table on [`kv_plan`].
    UnsupportedFilter,
    /// Writes do not match the kind (see [`kv_plan`]).
    UnsupportedWrite,
    /// KV keys and values are text (`Value::Str`); `Int` is refused rather than coerced.
    NonTextValue,
    BadCollection,
    KeyTooLong,
}

fn kv_shape(s: &Schema) -> Option<(Field, Field)> {
    if s.columns.len() != 3 || !valid_collection(&s.collection) || !s.columns.iter().any(|c| c.field == s.tenant_field)
    {
        return None;
    }
    let rest = || s.columns.iter().filter(|c| c.field != s.tenant_field);
    let mut keys = rest().filter(|c| c.key);
    let mut vals = rest().filter(|c| !c.key);
    match (keys.next(), keys.next(), vals.next(), vals.next()) {
        (Some(k), None, Some(v), None) => Some((k.field, v.field)),
        _ => None,
    }
}

fn text(v: &Value) -> Result<&str, KvError> {
    match v {
        Value::Str(s) => Ok(s),
        Value::Int(_) => Err(KvError::NonTextValue),
    }
}

fn bounded(s: String) -> Result<String, KvError> {
    if s.len() > KV_MAX_KEY_BYTES { Err(KvError::KeyTooLong) } else { Ok(s) }
}

/// KV mapping rule for OpKind on key-value engines (Redis, Valkey). Runs `check_schema` (as `Refines`, so `Not` is
/// refused) and then maps exactly these shapes; anything else is refused, never approximated:
///
/// | kind   | filter            | writes                  | command  |
/// |--------|-------------------|-------------------------|----------|
/// | Select | `Eq(key, s)`      | none                    | `Get`    |
/// | Select | `Tt` / `Pfx(key, s)` | none                 | `Scan`   |
/// | Insert | `Tt`              | key and value, once each| `SetNx`  |
/// | Upsert | `Tt`              | key and value, once each| `Set`    |
/// | Update | `Eq(key, s)`      | value only              | `SetXx`  |
/// | Delete | `Eq(key, s)`      | none                    | `Del`    |
///
/// Value filters do not exist on KV engines (values are opaque), so the adapter's fidelity is `Refines`.
pub fn kv_plan(op: &Op, s: &Schema) -> Result<KvCommand, KvError> {
    check_schema(op, s, Fidelity::Refines).map_err(KvError::Schema)?;
    let (kf, vf) = kv_shape(s).ok_or(KvError::NotKvSchema)?;
    if !valid_collection(&op.collection) {
        return Err(KvError::BadCollection);
    }
    let key = |k: &str| bounded(kv_key(op.tenant, &op.collection, k));
    let eq_key = || match &op.filter {
        Pred::Eq(f, v) if *f == kf => text(v),
        _ => Err(KvError::UnsupportedFilter),
    };
    let write_of = |f: Field| -> Result<&str, KvError> {
        let mut it = op.writes.iter().filter(|(g, _)| *g == f);
        match (it.next(), it.next()) {
            (Some((_, v)), None) => text(v),
            _ => Err(KvError::UnsupportedWrite),
        }
    };
    let only = |fs: &[Field]| op.writes.iter().all(|(f, _)| fs.contains(f));
    match op.kind {
        OpKind::Select if op.writes.is_empty() => match &op.filter {
            Pred::Eq(..) => Ok(KvCommand::Get { key: key(eq_key()?)? }),
            Pred::Tt => Ok(KvCommand::Scan { pattern: key("*")? }),
            Pred::Pfx(f, p) if *f == kf => {
                let mut pat = glob_escape(p);
                pat.push('*');
                Ok(KvCommand::Scan { pattern: key(&pat)? })
            }
            _ => Err(KvError::UnsupportedFilter),
        },
        OpKind::Insert | OpKind::Upsert if op.filter == Pred::Tt => {
            if op.writes.len() != 2 || !only(&[kf, vf]) {
                return Err(KvError::UnsupportedWrite);
            }
            let (k, value) = (key(write_of(kf)?)?, String::from(write_of(vf)?));
            Ok(if op.kind == OpKind::Insert {
                KvCommand::SetNx { key: k, value }
            } else {
                KvCommand::Set { key: k, value }
            })
        }
        OpKind::Update => {
            let k = key(eq_key()?)?;
            if op.writes.len() != 1 || !only(&[vf]) {
                return Err(KvError::UnsupportedWrite);
            }
            Ok(KvCommand::SetXx { key: k, value: String::from(write_of(vf)?) })
        }
        OpKind::Delete if op.writes.is_empty() => Ok(KvCommand::Del { key: key(eq_key()?)? }),
        OpKind::Insert | OpKind::Upsert => Err(KvError::UnsupportedFilter),
        OpKind::Select | OpKind::Delete => Err(KvError::UnsupportedWrite),
    }
}

// ---------------------------------------------------------------------------------------------- engines and pins

/// Engine families with a golden adapter. Redis and Valkey share the RESP denylist but have separate version pins.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EngineFamily {
    Sqlite,
    Postgres,
    Redis,
    Valkey,
}

impl EngineFamily {
    pub const ALL: [EngineFamily; 4] =
        [EngineFamily::Sqlite, EngineFamily::Postgres, EngineFamily::Redis, EngineFamily::Valkey];
    /// Name used in F8 `backend.engine` and in the allowlist lock.
    pub const fn name(self) -> &'static str {
        match self {
            EngineFamily::Sqlite => "sqlite",
            EngineFamily::Postgres => "postgres",
            EngineFamily::Redis => "redis",
            EngineFamily::Valkey => "valkey",
        }
    }
    pub fn from_name(s: &str) -> Option<EngineFamily> {
        EngineFamily::ALL.into_iter().find(|f| f.name() == s)
    }
    /// Key-value family: ops go through [`kv_plan`].
    pub const fn is_kv(self) -> bool {
        matches!(self, EngineFamily::Redis | EngineFamily::Valkey)
    }
}

/// Server or library version. PostgreSQL's two-part versions use `patch = 0` (18.6 = 18.6.0). Ordering is
/// lexicographic on (major, minor, patch).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EngineVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

/// Version gate for one engine family (the data behind `supply-chain/engine-pins.toml`). Fail closed: a blocked
/// major, a major with no floor, or a version below its major's floor is refused at connect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnginePin {
    pub family: EngineFamily,
    /// Minimum accepted version per major (`floor.major` is the major it governs). If one major is listed twice,
    /// the higher floor applies.
    pub floors: Vec<EngineVersion>,
    /// Majors refused whatever their minor (e.g. PostgreSQL 19 until the ON CONFLICT fix is named).
    pub blocked_majors: Vec<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinError {
    BlockedMajor,
    UnknownMajor,
    BelowFloor,
}

impl EnginePin {
    pub fn admit(&self, v: EngineVersion) -> Result<(), PinError> {
        if self.blocked_majors.contains(&v.major) {
            return Err(PinError::BlockedMajor);
        }
        match self.floors.iter().filter(|f| f.major == v.major).max() {
            None => Err(PinError::UnknownMajor),
            Some(f) if v < *f => Err(PinError::BelowFloor),
            Some(_) => Ok(()),
        }
    }
}

/// One denylisted command or keyword, with its trace (why it is denied).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DenyEntry {
    pub item: &'static str,
    pub trace: &'static str,
}

const LUA: &str = "server-side scripting: keys undeclared to ACL; Valkey CVE-2025-67733 (Lua error reply injected into other users' response stream)";
const ACL_BYPASS: &str = "bypasses ACL key patterns (Redis ACL docs; research round-002 data-plane families)";
const KEYSPACE: &str = "names or moves keys outside the tenant prefix / database (lowering-write hostile corpus)";
const SORT: &str = "BY/GET patterns read keys not identified to ACL (CVE-2023-41053, SORT_RO)";
const ADMIN: &str = "administrative surface, never an Op";
const CONN_STATE: &str = "per-connection state (CRS C8, D7; NC3 discard)";

const RESP_DENY: &[DenyEntry] = &[
    DenyEntry { item: "EVAL", trace: LUA },
    DenyEntry { item: "EVALSHA", trace: LUA },
    DenyEntry { item: "EVAL_RO", trace: LUA },
    DenyEntry { item: "EVALSHA_RO", trace: LUA },
    DenyEntry { item: "FCALL", trace: LUA },
    DenyEntry { item: "FCALL_RO", trace: LUA },
    DenyEntry { item: "FUNCTION", trace: LUA },
    DenyEntry { item: "SCRIPT", trace: LUA },
    DenyEntry { item: "FLUSHALL", trace: ACL_BYPASS },
    DenyEntry { item: "FLUSHDB", trace: ACL_BYPASS },
    DenyEntry { item: "SWAPDB", trace: ACL_BYPASS },
    DenyEntry { item: "KEYS", trace: "unbounded keyspace walk and glob recursion (CVE-2024-31228)" },
    DenyEntry { item: "SORT", trace: SORT },
    DenyEntry { item: "SORT_RO", trace: SORT },
    DenyEntry { item: "MOVE", trace: KEYSPACE },
    DenyEntry { item: "COPY", trace: KEYSPACE },
    DenyEntry { item: "RENAME", trace: KEYSPACE },
    DenyEntry { item: "RENAMENX", trace: KEYSPACE },
    DenyEntry { item: "MIGRATE", trace: KEYSPACE },
    DenyEntry { item: "SELECT", trace: CONN_STATE },
    DenyEntry { item: "CLIENT", trace: CONN_STATE },
    DenyEntry { item: "ACL", trace: ADMIN },
    DenyEntry { item: "CONFIG", trace: ADMIN },
    DenyEntry { item: "DEBUG", trace: ADMIN },
    DenyEntry { item: "MODULE", trace: ADMIN },
    DenyEntry { item: "MONITOR", trace: ADMIN },
];

const NO_REPLACE: &str = "REPLACE family deletes a conflicting row then inserts (W3 mandated forms)";
const W5: &str = "data-modifying construct outside W1-W4 closure (W5, decision D8)";

const SQLITE_DENY: &[DenyEntry] = &[
    DenyEntry { item: "ATTACH", trace: CONN_STATE },
    DenyEntry { item: "DETACH", trace: CONN_STATE },
    DenyEntry { item: "PRAGMA", trace: "PRAGMAs are fixed at open (CRS C8, D7)" },
    DenyEntry { item: "TEMP", trace: CONN_STATE },
    DenyEntry { item: "TEMPORARY", trace: CONN_STATE },
    DenyEntry { item: "REPLACE", trace: NO_REPLACE },
    DenyEntry { item: "TRIGGER", trace: W5 },
    DenyEntry { item: "LOAD_EXTENSION", trace: "loads native code into the server process" },
];

const PG_DENY: &[DenyEntry] = &[
    DenyEntry { item: "MERGE", trace: W5 },
    DenyEntry { item: "TRIGGER", trace: W5 },
    DenyEntry { item: "COPY", trace: "COPY in progress forces discard (NC3)" },
    DenyEntry { item: "LISTEN", trace: "LISTEN forces discard (NC3)" },
    DenyEntry { item: "NOTIFY", trace: "external effect outside the outbox (NC6)" },
    DenyEntry { item: "TEMP", trace: CONN_STATE },
    DenyEntry { item: "TEMPORARY", trace: CONN_STATE },
    DenyEntry {
        item: "SESSION",
        trace: "session-level SET outlives the op; only SET LOCAL / is_local GUCs (R-DB-1, C8)",
    },
];

/// Per-family denylist as data (R-DB-3/4). For RESP families an item is a command name; for SQL families it is a
/// keyword matched against the unquoted keyword tokens of rendered statement text. Matching is ASCII
/// case-insensitive. The allowlist-lock generator refuses any entry that renders a denylisted item, and adapters
/// never emit one.
pub fn denylist(family: EngineFamily) -> &'static [DenyEntry] {
    match family {
        EngineFamily::Sqlite => SQLITE_DENY,
        EngineFamily::Postgres => PG_DENY,
        EngineFamily::Redis | EngineFamily::Valkey => RESP_DENY,
    }
}

/// The denylist entry `word` hits for `family`, if any (ASCII case-insensitive, whole word).
pub fn denied(family: EngineFamily, word: &str) -> Option<&'static DenyEntry> {
    denylist(family).iter().find(|d| d.item.eq_ignore_ascii_case(word))
}

// ------------------------------------------------------------------------------------------ allowlist lock format

/// First line of every `allowlist.<adapter>.lock`.
pub const LOCK_HEADER: &str = "aegis-allowlist-lock v1";
/// Longest `op` line (bytes, without LF).
pub const LOCK_MAX_LINE: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockError {
    BadAdapter,
    BadCollection,
    LineTooLong,
    /// The entry would render a denylisted item.
    Denied(&'static str),
}

/// Value-free shape of a predicate: `tt`, `ff`, `eq(F)`, `in(F)`, `range(F)`, `pfx(F)`, `and(A,B)`, `or(A,B)`,
/// `not(A)`, with `F` the decimal field. Values and `IsIn` list lengths are parameters, not part of the shape.
pub fn pred_shape(p: &Pred) -> String {
    let mut s = String::new();
    shape_into(p, &mut s);
    s
}

fn push_u32(out: &mut String, mut v: u32) {
    let mut buf = [b'0'; 10];
    let mut n = 0;
    loop {
        if let Some(slot) = buf.get_mut(n) {
            *slot = b'0' + (v % 10) as u8;
        }
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in (0..n).rev() {
        out.push(char::from(buf.get(i).copied().unwrap_or(b'0')));
    }
}

fn shape_into(p: &Pred, out: &mut String) {
    let leaf = |out: &mut String, tag: &str, f: Field| {
        out.push_str(tag);
        out.push('(');
        push_u32(out, f);
        out.push(')');
    };
    match p {
        Pred::Tt => out.push_str("tt"),
        Pred::Ff => out.push_str("ff"),
        Pred::Eq(f, _) => leaf(out, "eq", *f),
        Pred::IsIn(f, _) => leaf(out, "in", *f),
        Pred::Range(f, _, _) => leaf(out, "range", *f),
        Pred::Pfx(f, _) => leaf(out, "pfx", *f),
        Pred::And(a, b) | Pred::Or(a, b) => {
            out.push_str(if matches!(p, Pred::And(..)) { "and(" } else { "or(" });
            shape_into(a, out);
            out.push(',');
            shape_into(b, out);
            out.push(')');
        }
        Pred::Not(a) => {
            out.push_str("not(");
            shape_into(a, out);
            out.push(')');
        }
    }
}

/// One allowed operation shape: `op <collection> <kind> <shape> w=<fields> r=<fields>`, where `<fields>` is the
/// sorted, deduplicated, comma-separated decimal field list, or `-` when empty.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockEntry {
    line: String,
}

impl LockEntry {
    pub fn of(op: &Op) -> Result<LockEntry, LockError> {
        if !valid_collection(&op.collection) {
            return Err(LockError::BadCollection);
        }
        let fields = |out: &mut String, mut fs: Vec<Field>| {
            fs.sort_unstable();
            fs.dedup();
            if fs.is_empty() {
                out.push('-');
            }
            for (i, f) in fs.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                push_u32(out, f);
            }
        };
        let mut line = String::from("op ");
        line.push_str(&op.collection);
        line.push(' ');
        line.push_str(op.kind.name());
        line.push(' ');
        shape_into(&op.filter, &mut line);
        line.push_str(" w=");
        fields(&mut line, op.writes.iter().map(|(f, _)| *f).collect());
        line.push_str(" r=");
        fields(&mut line, op.returning.clone());
        if line.len() > LOCK_MAX_LINE {
            return Err(LockError::LineTooLong);
        }
        Ok(LockEntry { line })
    }
    pub fn line(&self) -> &str {
        &self.line
    }
}

/// Canonical lock body (everything except the trailer):
///
/// ```text
/// aegis-allowlist-lock v1
/// adapter <adapter>          (backend-id grammar)
/// family <sqlite|postgres|redis|valkey>
/// op ...                     (one line per entry, sorted bytewise ascending, duplicates removed)
/// ```
///
/// Every line ends in a single LF (no CR, no trailing spaces, no blank lines); there are no timestamps, paths,
/// hostnames or other environment-dependent bytes, so two generations from the same declarations are
/// byte-identical. The file is the body followed by one trailer line `sha256 <64 lower-case hex>\n`, the SHA-256 of
/// the body bytes. A reader accepts a file only if it is byte-identical to the re-rendered body plus trailer; any
/// other line, ordering or hash is refused (fail closed). For KV families every entry must also pass [`kv_plan`]
/// shape rules; the generator refuses entries whose rendering hits [`denylist`].
pub fn lock_body(adapter: &str, family: EngineFamily, entries: &[LockEntry]) -> Result<String, LockError> {
    if !valid_backend_id(adapter) {
        return Err(LockError::BadAdapter);
    }
    let mut sorted: Vec<&str> = entries.iter().map(LockEntry::line).collect();
    sorted.sort_unstable();
    sorted.dedup();
    let mut out = String::from(LOCK_HEADER);
    out.push_str("\nadapter ");
    out.push_str(adapter);
    out.push_str("\nfamily ");
    out.push_str(family.name());
    out.push('\n');
    for l in sorted {
        out.push_str(l);
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn schema() -> Schema {
        Schema {
            collection: "notes".into(),
            tenant_field: 0,
            columns: vec![
                Column { field: 0, name: "tenant".into(), nullable: false, collation: Collation::Binary, key: true },
                Column { field: 1, name: "title".into(), nullable: false, collation: Collation::Binary, key: true },
                Column {
                    field: 2,
                    name: "archived_at".into(),
                    nullable: true,
                    collation: Collation::Binary,
                    key: false,
                },
            ],
            permitted: vec![1, 2],
            unique_indexes: vec![UniqueIndex { fields: vec![0, 1], prefix: false }],
        }
    }

    fn op(filter: Pred) -> Op {
        let tenant = TenantId::new(9).unwrap_or_else(|_| unreachable!());
        Op { tenant, collection: "notes".into(), kind: OpKind::Select, filter, writes: vec![], returning: vec![1] }
    }

    #[test]
    fn not_needs_exact_and_tenant_writes_rejected() {
        let s = schema();
        let not_null = op(Pred::Not(Box::new(Pred::Eq(2, Value::Int(0)))));
        assert_eq!(check_schema(&not_null, &s, Fidelity::Exact), Ok(()));
        assert_eq!(check_schema(&not_null, &s, Fidelity::Refines), Err(SchemaError::NotRequiresExact));
        assert_eq!(check_schema(&op(Pred::Eq(2, Value::Int(0))), &s, Fidelity::Refines), Ok(()));
        let mut w = op(Pred::Tt);
        w.kind = OpKind::Update;
        w.writes = vec![(0, Value::Int(1))];
        assert_eq!(check_schema(&w, &s, Fidelity::Exact), Err(SchemaError::TenantFieldWritten));
        let mut ci = schema();
        if let Some(c) = ci.columns.first_mut() {
            c.collation = Collation::CaseInsensitive;
        }
        assert_eq!(check_schema(&op(Pred::Tt), &ci, Fidelity::Exact), Err(SchemaError::NonBinaryCollation(0)));
        if let Some(c) = ci.columns.first_mut() {
            c.collation = Collation::PadSpace;
        }
        assert_eq!(check_schema(&op(Pred::Tt), &ci, Fidelity::Exact), Err(SchemaError::NonBinaryCollation(0)));
        let mut up = op(Pred::Tt);
        up.kind = OpKind::Upsert;
        assert_eq!(check_schema(&up, &s, Fidelity::Exact), Ok(()));
        let mut two = schema();
        two.unique_indexes.push(UniqueIndex { fields: vec![1], prefix: false });
        assert_eq!(check_schema(&up, &two, Fidelity::Exact), Err(SchemaError::UpsertArbiterNotTenantScoped));
        let mut pre = schema();
        pre.unique_indexes = vec![UniqueIndex { fields: vec![0, 1], prefix: true }];
        assert_eq!(check_schema(&up, &pre, Fidelity::Exact), Err(SchemaError::UpsertArbiterNotTenantScoped));
        assert_eq!(Pred::or_n(vec![]), Pred::Ff);
        assert_eq!(Pred::and_n(vec![]), Pred::Tt);
    }

    fn tid(v: u64) -> TenantId {
        TenantId::new(v).unwrap_or_else(|_| unreachable!())
    }

    fn cap(backend: &str, coll: &str, kinds: &[OpKind], cols: Vec<Field>) -> DataCap {
        let ops = OpMask::of(kinds).unwrap_or_else(|_| unreachable!());
        DataCap::new(backend, coll, ops, cols).unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn opmask_matches_sdk_codes_and_has_no_empty_value() {
        assert_eq!(OpKind::ALL.map(OpKind::bit), [1, 2, 4, 8, 16]);
        for (i, k) in OpKind::ALL.into_iter().enumerate() {
            assert_eq!(k.bit(), 1u8 << i);
            assert_eq!(OpKind::from_name(k.name()), Some(k));
        }
        assert_eq!(OpMask::from_bits(0), Err(CapError::BadOps));
        assert_eq!(OpMask::from_bits(0x20), Err(CapError::BadOps));
        assert_eq!(OpMask::of(&[]), Err(CapError::BadOps));
        let sel = OpMask::of(&[OpKind::Select]).unwrap_or_else(|_| unreachable!());
        let rw = OpMask::from_bits(0x1f).unwrap_or_else(|_| unreachable!());
        assert!(sel.is_subset_of(rw) && !rw.is_subset_of(sel));
        assert!(sel.contains(OpKind::Select) && !sel.contains(OpKind::Delete));
    }

    #[test]
    fn capset_nonempty_by_construction() {
        assert_eq!(Caps::new(vec![]), Err(CapError::EmptyCapSet));
        let ops = OpMask::of(&[OpKind::Select]).unwrap_or_else(|_| unreachable!());
        assert_eq!(DataCap::new("db", "notes", ops, vec![]), Err(CapError::EmptyColumns));
        assert_eq!(DataCap::new("Db", "notes", ops, vec![1]), Err(CapError::BadBackendId));
        assert_eq!(DataCap::new("db", "no:tes", ops, vec![1]), Err(CapError::BadCollection));
        assert_eq!(DataCap::new("db", "notes", ops, (0..300).collect()), Err(CapError::TooManyColumns));
        let many = vec![cap("db", "notes", &[OpKind::Select], vec![1]); MAX_CAPS + 1];
        assert_eq!(Caps::new(many), Err(CapError::TooManyCaps));
        assert!(valid_backend_id("pg-main") && !valid_backend_id("") && !valid_backend_id("1db"));
        assert!(valid_collection("_notes_2") && !valid_collection("Notes") && !valid_collection("a*"));
    }

    #[test]
    fn authorize_needs_one_covering_cap() {
        let set = CapSet::Caps(
            Caps::new(vec![
                cap("db", "notes", &[OpKind::Select], vec![1]),
                cap("db", "notes", &[OpKind::Select], vec![2]),
            ])
            .unwrap_or_else(|_| unreachable!()),
        );
        let ok = op(Pred::Eq(1, Value::Str("a".into())));
        assert_eq!(authorize(&set, "db", &ok), Ok(()));
        assert_eq!(authorize(&set, "other", &ok), Err(Denied));
        let mut wrong_kind = ok.clone();
        wrong_kind.kind = OpKind::Delete;
        assert_eq!(authorize(&set, "db", &wrong_kind), Err(Denied));
        let mut wrong_coll = ok.clone();
        wrong_coll.collection = "users".into();
        assert_eq!(authorize(&set, "db", &wrong_coll), Err(Denied));
        // filter on 2, returning 1: each cap covers half, no union.
        let split = op(Pred::Eq(2, Value::Int(0)));
        assert_eq!(authorize(&set, "db", &split), Err(Denied));
        let mut writes = op(Pred::Tt);
        writes.kind = OpKind::Update;
        writes.returning = vec![];
        writes.writes = vec![(2, Value::Int(1))];
        assert_eq!(authorize(&set, "db", &writes), Err(Denied));
        let upd = CapSet::Caps(
            Caps::new(vec![cap("db", "notes", &[OpKind::Update], vec![1])]).unwrap_or_else(|_| unreachable!()),
        );
        assert_eq!(authorize(&upd, "db", &writes), Err(Denied));
        writes.writes = vec![(1, Value::Int(1))];
        assert_eq!(authorize(&upd, "db", &writes), Ok(()));
        assert_eq!(authorize(&CapSet::Unrestricted, "any", &split), Ok(()));
    }

    #[test]
    fn tenant_text_is_fixed_width_lower_hex() {
        assert_eq!(tenant_text(tid(42)), "000000000000002a");
        assert_eq!(tenant_text(tid(u64::MAX)), "ffffffffffffffff");
        assert_eq!(tenant_text(tid(1)).len(), TENANT_TEXT_LEN);
        for v in [1, 9, 0xabc, 1 << 63, u64::MAX] {
            assert_eq!(parse_tenant_text(&tenant_text(tid(v))), Some(tid(v)));
        }
        for bad in
            ["0000000000000000", "000000000000002A", "2a", "000000000000002a0", "00000000000000g1", " 00000000000002a"]
        {
            assert_eq!(parse_tenant_text(bad), None, "{bad}");
        }
        assert_eq!(kv_key_prefix(tid(42)), "t:{000000000000002a}:");
        assert_eq!(kv_key(tid(42), "notes", "k1"), "t:{000000000000002a}:notes:k1");
    }

    #[test]
    fn glob_escape_covers_redis_metachars() {
        assert_eq!(glob_escape(r"a*b?c[d]e\f-^"), r"a\*b\?c\[d\]e\\f-^");
    }

    fn kv_schema() -> Schema {
        Schema {
            collection: "kv".into(),
            tenant_field: 0,
            columns: vec![
                Column { field: 0, name: "tenant".into(), nullable: false, collation: Collation::Binary, key: true },
                Column { field: 1, name: "k".into(), nullable: false, collation: Collation::Binary, key: true },
                Column { field: 2, name: "v".into(), nullable: true, collation: Collation::Binary, key: false },
            ],
            permitted: vec![1, 2],
            unique_indexes: vec![UniqueIndex { fields: vec![0, 1], prefix: false }],
        }
    }

    fn kv_op(kind: OpKind, filter: Pred, writes: Vec<(Field, Value)>) -> Op {
        Op { tenant: tid(42), collection: "kv".into(), kind, filter, writes, returning: vec![] }
    }

    #[test]
    fn kv_plan_table() {
        let s = kv_schema();
        let st = |v: &str| Value::Str(v.into());
        let p = "t:{000000000000002a}:kv:";
        let key = |k: &str| alloc::format!("{p}{k}");
        let plan = |o: Op| kv_plan(&o, &s);
        assert_eq!(plan(kv_op(OpKind::Select, Pred::Eq(1, st("a")), vec![])), Ok(KvCommand::Get { key: key("a") }));
        assert_eq!(plan(kv_op(OpKind::Select, Pred::Tt, vec![])), Ok(KvCommand::Scan { pattern: key("*") }));
        assert_eq!(
            plan(kv_op(OpKind::Select, Pred::Pfx(1, "a*[".into()), vec![])),
            Ok(KvCommand::Scan { pattern: key(r"a\*\[*") })
        );
        let kvw = vec![(2, st("val")), (1, st("a"))];
        assert_eq!(
            plan(kv_op(OpKind::Insert, Pred::Tt, kvw.clone())),
            Ok(KvCommand::SetNx { key: key("a"), value: "val".into() })
        );
        assert_eq!(
            plan(kv_op(OpKind::Upsert, Pred::Tt, kvw.clone())),
            Ok(KvCommand::Set { key: key("a"), value: "val".into() })
        );
        assert_eq!(
            plan(kv_op(OpKind::Update, Pred::Eq(1, st("a")), vec![(2, st("val"))])),
            Ok(KvCommand::SetXx { key: key("a"), value: "val".into() })
        );
        assert_eq!(plan(kv_op(OpKind::Delete, Pred::Eq(1, st("a")), vec![])), Ok(KvCommand::Del { key: key("a") }));
        // refusals
        assert_eq!(plan(kv_op(OpKind::Select, Pred::Eq(2, st("a")), vec![])), Err(KvError::UnsupportedFilter));
        assert_eq!(plan(kv_op(OpKind::Select, Pred::Eq(1, Value::Int(1)), vec![])), Err(KvError::NonTextValue));
        assert_eq!(
            plan(kv_op(OpKind::Select, Pred::Not(Box::new(Pred::Eq(1, st("a")))), vec![])),
            Err(KvError::Schema(SchemaError::NotRequiresExact))
        );
        assert_eq!(plan(kv_op(OpKind::Delete, Pred::Tt, vec![])), Err(KvError::UnsupportedFilter));
        assert_eq!(plan(kv_op(OpKind::Delete, Pred::Pfx(1, "a".into()), vec![])), Err(KvError::UnsupportedFilter));
        assert_eq!(plan(kv_op(OpKind::Insert, Pred::Tt, vec![(1, st("a"))])), Err(KvError::UnsupportedWrite));
        assert_eq!(
            plan(kv_op(OpKind::Insert, Pred::Tt, vec![(1, st("a")), (1, st("b"))])),
            Err(KvError::UnsupportedWrite)
        );
        assert_eq!(plan(kv_op(OpKind::Insert, Pred::Eq(1, st("a")), kvw.clone())), Err(KvError::UnsupportedFilter));
        assert_eq!(
            plan(kv_op(OpKind::Update, Pred::Eq(1, st("a")), vec![(1, st("b"))])),
            Err(KvError::UnsupportedWrite)
        );
        assert_eq!(
            plan(kv_op(OpKind::Insert, Pred::Tt, vec![(0, st("x")), (2, st("v"))])),
            Err(KvError::Schema(SchemaError::TenantFieldWritten))
        );
        let long = "x".repeat(KV_MAX_KEY_BYTES);
        assert_eq!(plan(kv_op(OpKind::Select, Pred::Eq(1, st(&long)), vec![])), Err(KvError::KeyTooLong));
        let mut four = kv_schema();
        four.columns.push(Column {
            field: 3,
            name: "w".into(),
            nullable: true,
            collation: Collation::Binary,
            key: false,
        });
        assert_eq!(kv_plan(&kv_op(OpKind::Select, Pred::Tt, vec![]), &four), Err(KvError::NotKvSchema));
    }

    #[test]
    fn engine_pin_fails_closed() {
        let v = |major, minor| EngineVersion { major, minor, patch: 0 };
        let pg = EnginePin {
            family: EngineFamily::Postgres,
            floors: vec![v(17, 11), v(18, 6), v(18, 2)],
            blocked_majors: vec![19],
        };
        assert_eq!(pg.admit(v(17, 11)), Ok(()));
        assert_eq!(pg.admit(v(18, 7)), Ok(()));
        assert_eq!(pg.admit(v(17, 10)), Err(PinError::BelowFloor));
        assert_eq!(pg.admit(v(18, 5)), Err(PinError::BelowFloor));
        assert_eq!(pg.admit(v(19, 99)), Err(PinError::BlockedMajor));
        assert_eq!(pg.admit(v(16, 99)), Err(PinError::UnknownMajor));
        for f in EngineFamily::ALL {
            assert_eq!(EngineFamily::from_name(f.name()), Some(f));
        }
        assert!(EngineFamily::Valkey.is_kv() && !EngineFamily::Sqlite.is_kv());
    }

    #[test]
    fn denylist_contains_cve_traced_items() {
        for w in ["EVAL", "eval", "FlushAll", "FLUSHDB", "SWAPDB", "KEYS", "SORT_RO"] {
            assert!(denied(EngineFamily::Redis, w).is_some(), "{w}");
            assert!(denied(EngineFamily::Valkey, w).is_some(), "{w}");
        }
        for w in ["GET", "SET", "SCAN", "DEL"] {
            assert!(denied(EngineFamily::Redis, w).is_none(), "{w}");
        }
        assert!(denied(EngineFamily::Sqlite, "attach").is_some() && denied(EngineFamily::Sqlite, "pragma").is_some());
        assert!(denied(EngineFamily::Postgres, "MERGE").is_some());
        for w in ["SELECT", "INSERT", "UPDATE", "DELETE", "ON", "CONFLICT", "DO", "RETURNING", "LOCAL", "WHERE"] {
            assert!(denied(EngineFamily::Postgres, w).is_none(), "{w}");
            assert!(denied(EngineFamily::Sqlite, w).is_none(), "{w}");
        }
        for f in EngineFamily::ALL {
            assert!(denylist(f).iter().all(|d| !d.trace.is_empty() && d.item.bytes().all(|c| !c.is_ascii_lowercase())));
        }
    }

    #[test]
    fn lock_body_is_canonical() {
        let mut a = op(Pred::And(
            Box::new(Pred::Eq(1, Value::Str("x".into()))),
            Box::new(Pred::Not(Box::new(Pred::IsIn(2, vec![])))),
        ));
        a.returning = vec![2, 1, 2];
        assert_eq!(pred_shape(&a.filter), "and(eq(1),not(in(2)))");
        let ea = LockEntry::of(&a).unwrap_or_else(|_| unreachable!());
        assert_eq!(ea.line(), "op notes select and(eq(1),not(in(2))) w=- r=1,2");
        let mut b = op(Pred::Tt);
        b.kind = OpKind::Update;
        b.writes = vec![(2, Value::Int(1)), (1, Value::Int(2))];
        b.returning = vec![];
        let eb = LockEntry::of(&b).unwrap_or_else(|_| unreachable!());
        assert_eq!(eb.line(), "op notes update tt w=1,2 r=-");
        // values are not part of the shape
        let mut a2 = a.clone();
        a2.filter = Pred::And(
            Box::new(Pred::Eq(1, Value::Int(7))),
            Box::new(Pred::Not(Box::new(Pred::IsIn(2, vec![Value::Int(1)])))),
        );
        assert_eq!(LockEntry::of(&a2), Ok(ea.clone()));
        let body1 = lock_body("app-db", EngineFamily::Sqlite, &[eb.clone(), ea.clone(), eb.clone()]);
        let body2 = lock_body("app-db", EngineFamily::Sqlite, &[ea.clone(), eb.clone()]);
        assert_eq!(body1, body2);
        let want = "aegis-allowlist-lock v1\nadapter app-db\nfamily sqlite\n\
                    op notes select and(eq(1),not(in(2))) w=- r=1,2\nop notes update tt w=1,2 r=-\n";
        assert_eq!(body1, Ok(String::from(want)));
        assert_eq!(lock_body("App", EngineFamily::Sqlite, &[]), Err(LockError::BadAdapter));
        let mut bad = op(Pred::Tt);
        bad.collection = "x y".into();
        assert_eq!(LockEntry::of(&bad), Err(LockError::BadCollection));
        let mut deep = Pred::Tt;
        for _ in 0..1000 {
            deep = Pred::Not(Box::new(deep));
        }
        assert_eq!(LockEntry::of(&op(deep)), Err(LockError::LineTooLong));
    }
}
