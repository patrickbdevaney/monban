//! OpenMetrics endpoint on the admin listener (always compiled, no feature flag; ARCHITECTURE §3.10).
//!
//! * [`Registry`] holds every golden metric as atomic cells. Label sets are closed enums ([`LabelValue`]), so
//!   cardinality is fixed at compile time and an attacker cannot mint new series.
//! * [`render`] writes OpenMetrics 1.0 text (`# TYPE`/`# UNIT`/`# HELP`, `_total` on counter samples, escaped
//!   label values, `# EOF` last). Serve it with [`CONTENT_TYPE`].
//! * [`GOLDEN`] lists every golden family; `cargo xtask metrics-check` checks each one is in the dump.
//!
//! OTLP is not here: it stays out of process (spikes/otlp-footprint).
#![forbid(unsafe_code)]

mod labels;
mod registry;
mod render;

pub use labels::{AdmissionStage, BudgetScope, CertSlot, LabelValue};
pub use registry::{Counter, CounterVec, Gauge, GaugeVec, Registry};
pub use render::{Family, RenderError, Sample, Value, escape, render};

/// HTTP `Content-Type` for the exposition.
pub const CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// OpenMetrics metric type. Only the two types the registry uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MetricType {
    /// Monotonic; samples are rendered as `<name>_total`.
    Counter,
    /// Point-in-time value; sample name equals the family name.
    Gauge,
}

impl MetricType {
    /// Name used on the `# TYPE` line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            MetricType::Counter => "counter",
            MetricType::Gauge => "gauge",
        }
    }
}

/// Static description of one metric family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FamilyDesc {
    /// Family name (`[a-zA-Z_:][a-zA-Z0-9_:]*`). Counters omit `_total`, which the renderer appends.
    pub name: &'static str,
    /// Metric type.
    pub kind: MetricType,
    /// Optional unit; when present the name must end with `_<unit>`.
    pub unit: Option<&'static str>,
    /// `# HELP` text.
    pub help: &'static str,
    /// Label names, in render order. Each comes from a closed [`LabelValue`] enum.
    pub labels: &'static [&'static str],
}

/// Admission rejects, one series per stage S0..S6 (+S3A).
pub const ADMISSION_REJECTS: FamilyDesc = FamilyDesc {
    name: "aegis_admission_rejects",
    kind: MetricType::Counter,
    unit: None,
    help: "Requests rejected by the admission pipeline, by stage.",
    labels: &[AdmissionStage::KEY],
};

/// Budget debits (GCRA conforming debits), by budget scope.
pub const BUDGET_DEBITS: FamilyDesc = FamilyDesc {
    name: "aegis_budget_debits",
    kind: MetricType::Counter,
    unit: None,
    help: "Successful budget debits, by budget scope.",
    labels: &[BudgetScope::KEY],
};

/// Crash-budget trips (a principal exhausted its crash budget and was put in the 429 penalty box).
pub const CRASH_BUDGET_TRIPS: FamilyDesc = FamilyDesc {
    name: "aegis_crash_budget_trips",
    kind: MetricType::Counter,
    unit: None,
    help: "Times a per-principal crash budget tripped.",
    labels: &[],
};

/// Seconds until certificate expiry, by certificate slot (negative once expired).
pub const CERT_SECONDS_TO_EXPIRY: FamilyDesc = FamilyDesc {
    name: "aegis_cert_seconds_to_expiry",
    kind: MetricType::Gauge,
    unit: None,
    help: "Seconds until the certificate in this slot expires; negative once expired.",
    labels: &[CertSlot::KEY],
};

/// FIPS status: 1 when the FIPS-validated provider is active, 0 otherwise.
pub const FIPS_STATUS: FamilyDesc = FamilyDesc {
    name: "aegis_fips_status",
    kind: MetricType::Gauge,
    unit: None,
    help: "1 when the FIPS-validated crypto provider is active, else 0.",
    labels: &[],
};

/// Config-generation hash: first 48 bits of the active config hash (exact in an f64 scraper).
pub const CONFIG_GENERATION_HASH: FamilyDesc = FamilyDesc {
    name: "aegis_config_generation_hash",
    kind: MetricType::Gauge,
    unit: None,
    help: "First 48 bits (big-endian) of the active config generation hash.",
    labels: &[],
};

/// Last-known-good fallbacks (a config load failed and the previous generation stayed live).
pub const CONFIG_LKG_FALLBACKS: FamilyDesc = FamilyDesc {
    name: "aegis_config_lkg_fallbacks",
    kind: MetricType::Counter,
    unit: None,
    help: "Config loads that failed and fell back to the last-known-good generation.",
    labels: &[],
};

/// Connections force-closed when an upgrade drain deadline passed.
pub const UPGRADE_FORCED_CLOSES: FamilyDesc = FamilyDesc {
    name: "aegis_upgrade_forced_closes",
    kind: MetricType::Counter,
    unit: None,
    help: "Connections force-closed at the upgrade drain deadline.",
    labels: &[],
};

/// Every golden family (ARCHITECTURE §3.10), in render order. All present with zero values after
/// [`Registry::new`].
pub const GOLDEN: &[FamilyDesc] = &[
    ADMISSION_REJECTS,
    BUDGET_DEBITS,
    CRASH_BUDGET_TRIPS,
    CERT_SECONDS_TO_EXPIRY,
    FIPS_STATUS,
    CONFIG_GENERATION_HASH,
    CONFIG_LKG_FALLBACKS,
    UPGRADE_FORCED_CLOSES,
];

#[cfg(test)]
mod tests;
