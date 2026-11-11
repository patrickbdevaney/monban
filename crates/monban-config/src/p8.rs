//! F8 Phase-8 additions (P8-spec-001, PLAN-8 Interfaces; PREFLIGHT R5, R12, R13). All additive: an absent member
//! means exactly what the config meant before Phase 8, and the effective form and `config_hash` of such a config are
//! unchanged.
//!
//! * [`Runtime`] (root `runtime`, D-P8.3): `worker_threads`, 1..=1024, default 2 (the constant monban-bin hard-coded
//!   before Phase 8). The block is printed in the hashed form only when it differs from the default, so absent and
//!   explicit-default documents hash the same.
//! * [`StateBlock`] (root `state`, R12): `idempotency_retention_s`, 60..=2,592,000 (one minute to 30 days), with
//!   **no default**: absent keeps the pre-Phase-8 "never expire" meaning, so no stored idempotency key changes
//!   meaning when a config is upgraded. Printed only when set (`{}` hashes like an absent block).
//! * Route paths (R13): a `routes[].path` that is not a fixed point of `monban_canon::canon_path` (dot segments,
//!   empty segments, a literal `;`, over-long) is refused at load ([`crate::ErrorKind::NotCanonical`]). Such a route
//!   could never match a request (routing compares canonical paths), so refusing it changes no served behaviour; it
//!   turns a dead route into a load error, as the F8 doc rule always said.

/// F8 `runtime` (Phase 8, D-P8.3). Default = the pre-Phase-8 monban-bin constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Runtime {
    /// tokio worker threads of the serving runtime. Default 2.
    pub worker_threads: u64,
}

impl Runtime {
    /// (member, minimum, maximum, default), in schema order.
    pub const BOUNDS: &'static [(&'static str, u64, u64, u64)] = &[("worker_threads", 1, 1024, 2)];

    pub(crate) fn set(&mut self, name: &str, v: u64) {
        if name == "worker_threads" {
            self.worker_threads = v;
        }
    }
    /// Values in [`Runtime::BOUNDS`] order.
    pub fn values(&self) -> Vec<u64> {
        vec![self.worker_threads]
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Runtime { worker_threads: 2 }
    }
}

/// F8 `state` (Phase 8, R12). Every member is optional with no default; [`StateBlock::default`] is the
/// pre-Phase-8 meaning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct StateBlock {
    /// Seconds an idempotency key (INV-IDEMP) is retained after its first use. `None` = never expire (pre-Phase-8).
    /// Within the window a replayed key returns the stored outcome; after it the key may be forgotten.
    pub idempotency_retention_s: Option<u64>,
}

impl StateBlock {
    /// Inclusive bounds of `idempotency_retention_s` (one minute to 30 days).
    pub const RETENTION_BOUNDS: (u64, u64) = (60, 2_592_000);
    /// Member names, in schema order.
    pub const MEMBERS: &'static [&'static str] = &["idempotency_retention_s"];
}
