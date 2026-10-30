//! Redis/Valkey adapter: key lowering and reply subset (W7).
//!
//! P4-redis-001:
//! * [`resp`]: owned RESP2 codec (DEVIATIONS X-10), sans IO, every read capped (bulk length, array length and
//!   depth, line length, reply bytes, value count); RESP3 is refused.
//! * [`conn`]: blocking client over TCP / Unix sockets with deadlines on every command, a data-command allowlist
//!   (`GET`/`SET`/`DEL`) on top of the shared RESP denylist (R-DB-3/4), the connect-time version gate, and the boot
//!   check that the `default` user is off or permissionless (PLAN D12).
//! * [`version`]: the gate, read from `supply-chain/engine-pins.toml` (CVE-2025-67733 branch rules; Valkey judged by
//!   `valkey_version`, never its compatibility `redis_version`; Redis 8.8 refused).
//! * [`render`]: `aegis_data_ir::kv_plan` → RESP arguments, the per-tenant ACL user (R-DB-5: key pattern
//!   `~t:{<16hex>}:*` only, `-@all +get +set +del`), and the executor with the W7 key re-check;
//!   `Scan` (Select Tt/Pfx) is refused at runtime (PLAN D11) while its pattern is still rendered.
//!
//! Spec: `spec/SPEC_INVARIANTS.md` (§E W7), R-DB-3/4/5/7.
#![forbid(unsafe_code)]

pub mod conn;
pub mod render;
pub mod resp;
pub mod version;

pub use conn::{ConnectConfig, Connection, Endpoint, Error};
pub use render::{
    ExecError, KvOp, KvOutcome, TenantUser, command_args, execute, plan, tenant_acl_rules, tenant_username,
};
pub use resp::{Limits, Reply};
pub use version::{AdmittedVersion, KvKind, KvPins, VersionRefusal};
