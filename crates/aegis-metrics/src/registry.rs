//! Atomic metric cells and the golden registry. Relaxed atomics: each cell is independent, and a scrape is a
//! best-effort snapshot (OpenMetrics does not promise cross-series atomicity).

use crate::FamilyDesc;
use crate::labels::{AdmissionStage, BudgetScope, CertSlot, LabelValue};
use crate::render::{Family, RenderError, Sample, Value, render};
use core::marker::PhantomData;
use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Monotonic counter.
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    /// Zeroed counter.
    #[must_use]
    pub const fn new() -> Self {
        Counter(AtomicU64::new(0))
    }
    /// Adds 1.
    pub fn inc(&self) {
        self.add(1);
    }
    /// Adds `n`, saturating at `u64::MAX` (a counter never wraps back to a smaller value).
    pub fn add(&self, n: u64) {
        let _ = self.0.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_add(n)));
    }
    /// Current value.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Gauge (signed: `cert_seconds_to_expiry` goes negative once expired).
#[derive(Debug, Default)]
pub struct Gauge(AtomicI64);

impl Gauge {
    /// Zeroed gauge.
    #[must_use]
    pub const fn new() -> Self {
        Gauge(AtomicI64::new(0))
    }
    /// Sets the value.
    pub fn set(&self, v: i64) {
        self.0.store(v, Ordering::Relaxed);
    }
    /// Current value.
    #[must_use]
    pub fn get(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// One counter per value of the closed label enum `L`; `N` must equal `L::ALL.len()` (checked at compile time).
#[derive(Debug)]
pub struct CounterVec<L: LabelValue, const N: usize> {
    cells: [Counter; N],
    _l: PhantomData<L>,
}

impl<L: LabelValue, const N: usize> CounterVec<L, N> {
    /// Zeroed vector.
    #[must_use]
    pub const fn new() -> Self {
        const { assert!(N == L::ALL.len(), "CounterVec N must equal the label enum size") };
        CounterVec { cells: [const { Counter::new() }; N], _l: PhantomData }
    }
    /// Adds 1 to the series for `l`.
    pub fn inc(&self, l: L) {
        self.add(l, 1);
    }
    /// Adds `n` to the series for `l`.
    pub fn add(&self, l: L, n: u64) {
        if let Some(c) = self.cells.get(l.index()) {
            c.add(n);
        }
    }
    /// Current value for `l`.
    #[must_use]
    pub fn get(&self, l: L) -> u64 {
        self.cells.get(l.index()).map_or(0, Counter::get)
    }
}

impl<L: LabelValue, const N: usize> Default for CounterVec<L, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// One gauge per value of the closed label enum `L`.
#[derive(Debug)]
pub struct GaugeVec<L: LabelValue, const N: usize> {
    cells: [Gauge; N],
    _l: PhantomData<L>,
}

impl<L: LabelValue, const N: usize> GaugeVec<L, N> {
    /// Zeroed vector.
    #[must_use]
    pub const fn new() -> Self {
        const { assert!(N == L::ALL.len(), "GaugeVec N must equal the label enum size") };
        GaugeVec { cells: [const { Gauge::new() }; N], _l: PhantomData }
    }
    /// Sets the series for `l`.
    pub fn set(&self, l: L, v: i64) {
        if let Some(g) = self.cells.get(l.index()) {
            g.set(v);
        }
    }
    /// Current value for `l`.
    #[must_use]
    pub fn get(&self, l: L) -> i64 {
        self.cells.get(l.index()).map_or(0, Gauge::get)
    }
}

impl<L: LabelValue, const N: usize> Default for GaugeVec<L, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Every golden metric (see [`crate::GOLDEN`]). `Sync`; share by reference or `Arc`, or as a `static`.
#[derive(Debug, Default)]
pub struct Registry {
    /// [`crate::ADMISSION_REJECTS`].
    pub admission_rejects: CounterVec<AdmissionStage, 8>,
    /// [`crate::BUDGET_DEBITS`].
    pub budget_debits: CounterVec<BudgetScope, 3>,
    /// [`crate::CRASH_BUDGET_TRIPS`].
    pub crash_budget_trips: Counter,
    /// [`crate::CERT_SECONDS_TO_EXPIRY`].
    pub cert_seconds_to_expiry: GaugeVec<CertSlot, 3>,
    /// [`crate::FIPS_STATUS`]; use [`Registry::set_fips_active`].
    pub fips_status: Gauge,
    /// [`crate::CONFIG_GENERATION_HASH`]; use [`Registry::set_config_hash`].
    pub config_generation_hash: Gauge,
    /// [`crate::CONFIG_LKG_FALLBACKS`].
    pub config_lkg_fallbacks: Counter,
    /// [`crate::UPGRADE_FORCED_CLOSES`].
    pub upgrade_forced_closes: Counter,
}

fn counter_vec<L: LabelValue, const N: usize>(desc: FamilyDesc, v: &CounterVec<L, N>) -> Family<'static> {
    let samples = L::ALL
        .iter()
        .map(|&l| Sample { labels: vec![(L::KEY, l.as_str())], value: Value::Unsigned(v.get(l)) })
        .collect();
    Family { desc, samples }
}

fn gauge_vec<L: LabelValue, const N: usize>(desc: FamilyDesc, v: &GaugeVec<L, N>) -> Family<'static> {
    let samples =
        L::ALL.iter().map(|&l| Sample { labels: vec![(L::KEY, l.as_str())], value: Value::Signed(v.get(l)) }).collect();
    Family { desc, samples }
}

fn scalar(desc: FamilyDesc, value: Value) -> Family<'static> {
    Family { desc, samples: vec![Sample { labels: Vec::new(), value }] }
}

impl Registry {
    /// All golden metrics at zero.
    #[must_use]
    pub const fn new() -> Self {
        Registry {
            admission_rejects: CounterVec::new(),
            budget_debits: CounterVec::new(),
            crash_budget_trips: Counter::new(),
            cert_seconds_to_expiry: GaugeVec::new(),
            fips_status: Gauge::new(),
            config_generation_hash: Gauge::new(),
            config_lkg_fallbacks: Counter::new(),
            upgrade_forced_closes: Counter::new(),
        }
    }

    /// Sets `fips_status` to 1 (active) or 0.
    pub fn set_fips_active(&self, active: bool) {
        self.fips_status.set(i64::from(active));
    }

    /// Records the active config hash: the first 48 bits big-endian (missing bytes count as zero), so the value
    /// is exact in an f64-based scraper.
    pub fn set_config_hash(&self, digest: &[u8]) {
        let v = digest.iter().chain(core::iter::repeat(&0u8)).take(6).fold(0i64, |acc, &b| (acc << 8) | i64::from(b));
        self.config_generation_hash.set(v);
    }

    /// Snapshot of every family, in [`crate::GOLDEN`] order.
    #[must_use]
    pub fn families(&self) -> Vec<Family<'static>> {
        vec![
            counter_vec(crate::ADMISSION_REJECTS, &self.admission_rejects),
            counter_vec(crate::BUDGET_DEBITS, &self.budget_debits),
            scalar(crate::CRASH_BUDGET_TRIPS, Value::Unsigned(self.crash_budget_trips.get())),
            gauge_vec(crate::CERT_SECONDS_TO_EXPIRY, &self.cert_seconds_to_expiry),
            scalar(crate::FIPS_STATUS, Value::Signed(self.fips_status.get())),
            scalar(crate::CONFIG_GENERATION_HASH, Value::Signed(self.config_generation_hash.get())),
            scalar(crate::CONFIG_LKG_FALLBACKS, Value::Unsigned(self.config_lkg_fallbacks.get())),
            scalar(crate::UPGRADE_FORCED_CLOSES, Value::Unsigned(self.upgrade_forced_closes.get())),
        ]
    }

    /// OpenMetrics 1.0 text for the whole registry, ending in `# EOF\n`.
    ///
    /// # Errors
    /// Only if a family descriptor is malformed (a bug; the golden descriptors are checked by tests).
    pub fn render(&self) -> Result<String, RenderError> {
        render(&self.families())
    }
}
