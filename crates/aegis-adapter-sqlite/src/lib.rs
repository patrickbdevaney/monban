//! SQLite adapter (golden, `Fidelity::Exact`): renderer for the engine-neutral lowering tree plus live schema
//! introspection (R-DB-7) and a connection opened with fixed PRAGMAs (CRS C8 for an in-process engine, decision D7).
//!
//! Host order per op (aegis_data_ir crate docs): `authorize` → [`SqliteDb::check_schema`] (once per collection, at
//! boot; the returned [`Table`] is the introspected schema) → budget pre-debit → [`render`] → [`SqliteDb::run`].
//!
//! * [`render`] runs `aegis_data_ir::lower_op` (F4 `check_schema` first, at `Fidelity::Exact`), the W6 existence
//!   rules on the table's unique keys and foreign keys, then turns the [`aegis_data_ir::Lowered`] tree into one SQLite
//!   statement with `?` placeholders ([`Rendered`]). Every atom is UNKNOWN on a NULL column (including `InList(f, [])`),
//!   comparisons are class-strict (`typeof` guard) and binary (unary `+` drops column affinity and collation, then
//!   `COLLATE BINARY`), prefixes are byte prefixes of the UTF-8 encoding (`CAST AS BLOB`, never LIKE/GLOB), `And`/`Or`
//!   are parenthesised, and the tenant conjunct is the left child of the root `And` (SPEC §E SQLite Exact).
//! * Writes use only the mandated forms (W1–W7): `UPDATE .. SET .. WHERE lowerQ`, `DELETE .. WHERE lowerQ`,
//!   `INSERT .. VALUES`, `INSERT .. ON CONFLICT (<sole (tenant,key) index>) DO UPDATE SET c = excluded.c WHERE
//!   "<t>"."<tenant>" = excluded."<tenant>" COLLATE BINARY` or `DO NOTHING`. Never the REPLACE family, never
//!   `INSERT OR ..`, never a CTE. Each rendered text is re-scanned against `denylist(EngineFamily::Sqlite)`.
//! * [`SqliteDb::open`] asserts the linked SQLite is at or above the floor (3.51.3; the pin is 3.53.2 bundled) and
//!   that the database encoding is UTF-8 (byte order of BINARY = code-point order only in UTF-8), and fixes the
//!   connection configuration once: foreign keys on, triggers and views off, defensive mode, untrusted schema,
//!   no double-quoted string literals (a misspelt `"column"` is an error, never the string `'column'`), ATTACH
//!   may neither create nor write. Nothing per request changes connection state: no ATTACH, no temp objects, no
//!   PRAGMA is ever rendered.
//! * [`SqliteDb::check_schema`] reads the live catalog of schema `main` only (never trusts the declared schema for
//!   collations, NULL-ability, unique keys, types, triggers or FKs), runs F4 `check_schema` on what it found (with the
//!   admission probe: an Upsert, so the table is fit for every OpKind), plus the live-only classes of PLAN D9.
#![forbid(unsafe_code)]

mod live;
mod render;

pub use live::{LiveError, OpenError, OpenMode, SqliteDb};
pub use render::{ForeignKey, RenderError, Rendered, SqliteAdapter, Table, render, render_lowered, render_where};

use aegis_data_ir::{EngineFamily, EnginePin, EngineVersion};

/// Engine pin name (supply-chain/engine-pins.toml `[sqlite]`).
pub const ENGINE_PIN: &str = "sqlite";

/// Lowest SQLite accepted at open: WAL-reset corruption fixed in 3.51.3 (engine-pins.toml advisory).
pub const SQLITE_FLOOR: EngineVersion = EngineVersion { major: 3, minor: 51, patch: 3 };

/// The version gate applied by [`SqliteDb::open`]: major 3 with floor [`SQLITE_FLOOR`]; any other major is refused.
pub fn engine_pin() -> EnginePin {
    EnginePin { family: EngineFamily::Sqlite, floors: vec![SQLITE_FLOOR], blocked_majors: Vec::new() }
}

/// Version of the linked SQLite library (`sqlite3_libversion_number`, e.g. 3053002 = 3.53.2).
pub fn linked_version() -> Option<EngineVersion> {
    let n = u32::try_from(rusqlite::version_number()).ok()?;
    Some(EngineVersion { major: n / 1_000_000, minor: (n / 1000) % 1000, patch: n % 1000 })
}
