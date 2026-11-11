//! Closed label-value enums. A label is never a free string, so series count is fixed at compile time.

/// A closed set of label values for one label key.
pub trait LabelValue: Copy + 'static {
    /// Label name.
    const KEY: &'static str;
    /// Every value, in render order; `ALL[v.index()] == v`.
    const ALL: &'static [Self];
    /// Rendered label value.
    fn as_str(self) -> &'static str;
    /// Position in [`LabelValue::ALL`].
    fn index(self) -> usize;
}

/// Admission stage (mirrors `monban_admission::Stage` wire names; this crate has no dependencies).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdmissionStage {
    /// Listener connection caps.
    S0,
    /// Pre-auth per-IP GCRA.
    S1,
    /// Classification.
    S2,
    /// Per-identity budget.
    S3,
    /// Expensive-tier class-group aggregate.
    S3A,
    /// Step-up proof of work.
    S4,
    /// Class-partitioned concurrency.
    S5,
    /// Handler dispatch.
    S6,
}

impl LabelValue for AdmissionStage {
    const KEY: &'static str = "stage";
    const ALL: &'static [Self] = &[
        AdmissionStage::S0,
        AdmissionStage::S1,
        AdmissionStage::S2,
        AdmissionStage::S3,
        AdmissionStage::S3A,
        AdmissionStage::S4,
        AdmissionStage::S5,
        AdmissionStage::S6,
    ];
    fn as_str(self) -> &'static str {
        match self {
            AdmissionStage::S0 => "S0",
            AdmissionStage::S1 => "S1",
            AdmissionStage::S2 => "S2",
            AdmissionStage::S3 => "S3",
            AdmissionStage::S3A => "S3A",
            AdmissionStage::S4 => "S4",
            AdmissionStage::S5 => "S5",
            AdmissionStage::S6 => "S6",
        }
    }
    fn index(self) -> usize {
        self as usize
    }
}

/// Which budget a debit was charged to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BudgetScope {
    /// S1 pre-auth per-IP GCRA.
    Ip,
    /// S3 per-identity budget.
    Identity,
    /// S3A expensive-tier class-group aggregate.
    ExpensiveTier,
}

impl LabelValue for BudgetScope {
    const KEY: &'static str = "scope";
    const ALL: &'static [Self] = &[BudgetScope::Ip, BudgetScope::Identity, BudgetScope::ExpensiveTier];
    fn as_str(self) -> &'static str {
        match self {
            BudgetScope::Ip => "ip",
            BudgetScope::Identity => "identity",
            BudgetScope::ExpensiveTier => "expensive_tier",
        }
    }
    fn index(self) -> usize {
        self as usize
    }
}

/// Certificate slot (a fixed role, never a hostname, so cardinality stays bounded).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CertSlot {
    /// Public serving certificate.
    Serving,
    /// Admin listener certificate.
    Admin,
    /// Client certificate used towards upstreams.
    UpstreamClient,
}

impl LabelValue for CertSlot {
    const KEY: &'static str = "slot";
    const ALL: &'static [Self] = &[CertSlot::Serving, CertSlot::Admin, CertSlot::UpstreamClient];
    fn as_str(self) -> &'static str {
        match self {
            CertSlot::Serving => "serving",
            CertSlot::Admin => "admin",
            CertSlot::UpstreamClient => "upstream_client",
        }
    }
    fn index(self) -> usize {
        self as usize
    }
}
