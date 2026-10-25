//! CFG-3 last-known-good and CFG-4 staged apply. Pure state: no I/O, no clock reads; the caller passes
//! monotonic milliseconds (CLOCK_MONOTONIC, OPS-5) and health verdicts in.
//!
//! ```text
//!            stage(bytes)            tick(Healthy, ≥shadow_ms)        tick(Healthy, ≥bake_ms)
//!   (none) ───────────────▶ Shadow ───────────────────────────▶ Canary ─────────────────────────▶ Full
//!                             │  tick(Unhealthy) / rollback()       │  tick(Unhealthy) / rollback()   (served := candidate,
//!                             └──────────────▶ RolledBack ◀─────────┘                                  previous := old)
//!   rollback() after Full: served := previous (one step).        apply(bytes) Ok: supersedes any rollout.
//! ```
//! Every `Err` (parse failure, busy, no rollout) leaves the served config and its generation unchanged.

use std::sync::Arc;

use crate::{Config, ConfigError, parse_config};

/// Monotonic id of a successfully parsed config (applied or staged). Starts at 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation(pub u64);

/// Rollout phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Phase {
    /// Candidate evaluated alongside the served config; serves no traffic.
    Shadow,
    /// Candidate serves the canary buckets (`canary_permille` of 1000).
    Canary,
    /// Candidate promoted: it is the served config (terminal).
    Full,
    /// Candidate discarded; served config unchanged (terminal).
    RolledBack,
}

/// Health verdict for the candidate since the last tick (computed by the caller).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Health {
    Healthy,
    Unhealthy,
}

/// Timers and canary share. Defaults: 60 s shadow, 1% canary (ARCHITECTURE §3.11), 5 min bake.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RolloutPolicy {
    pub shadow_ms: u64,
    /// Canary share in permille, clamped to 1..=1000.
    pub canary_permille: u16,
    pub bake_ms: u64,
}

impl Default for RolloutPolicy {
    fn default() -> Self {
        Self { shadow_ms: 60_000, canary_permille: 10, bake_ms: 300_000 }
    }
}

/// Why a store operation was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StageError {
    /// The candidate did not parse (CFG-1/2); nothing changed.
    Config(ConfigError),
    /// A rollout is already in progress.
    Busy,
    /// Nothing is served yet, so there is no baseline to stage against (use [`ConfigStore::apply`]).
    NoBaseline,
    /// `tick` without a rollout in progress.
    NotStaging,
    /// `rollback` with neither a rollout nor a previous config.
    NothingToRollBack,
}

#[derive(Clone, Debug)]
struct Rollout {
    generation: Generation,
    candidate: Arc<Config>,
    phase: Phase,
    entered_ms: u64,
}

/// Last-known-good config holder with staged apply.
#[derive(Clone, Debug, Default)]
pub struct ConfigStore {
    policy: RolloutPolicy,
    current: Option<(Generation, Arc<Config>)>,
    previous: Option<(Generation, Arc<Config>)>,
    rollout: Option<Rollout>,
    last_error: Option<ConfigError>,
    next_gen: u64,
}

impl ConfigStore {
    /// Empty store: serves nothing (fail closed) until the first successful [`ConfigStore::apply`].
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_policy(policy: RolloutPolicy) -> Self {
        Self { policy, ..Self::default() }
    }

    pub fn policy(&self) -> RolloutPolicy {
        self.policy
    }

    fn mint(&mut self) -> Generation {
        self.next_gen = self.next_gen.saturating_add(1);
        Generation(self.next_gen)
    }

    fn parse(&mut self, bytes: &[u8]) -> Result<Config, ConfigError> {
        let r = parse_config(bytes);
        if let Err(e) = &r {
            self.last_error = Some(e.clone());
        }
        r
    }

    /// CFG-3: parse and serve immediately. On `Err` the served config (and any rollout) is unchanged. On `Ok`
    /// any rollout in progress is superseded and the old config becomes the rollback target.
    pub fn apply(&mut self, bytes: &[u8]) -> Result<Generation, ConfigError> {
        let cfg = self.parse(bytes)?;
        let generation = self.mint();
        self.rollout = None;
        self.previous = self.current.take();
        self.current = Some((generation, Arc::new(cfg)));
        self.last_error = None;
        Ok(generation)
    }

    /// The served (last-known-good) config.
    pub fn current(&self) -> Option<&Arc<Config>> {
        self.current.as_ref().map(|(_, c)| c)
    }

    pub fn generation(&self) -> Option<Generation> {
        self.current.as_ref().map(|(g, _)| *g)
    }

    /// Hash of the served config.
    pub fn config_hash(&self) -> Option<[u8; 32]> {
        self.current().map(|c| c.config_hash())
    }

    /// The most recent parse error (cleared by a successful `apply`).
    pub fn last_error(&self) -> Option<&ConfigError> {
        self.last_error.as_ref()
    }

    /// CFG-4: parse a candidate and enter `Shadow` at `now_ms`.
    pub fn stage(&mut self, bytes: &[u8], now_ms: u64) -> Result<Generation, StageError> {
        if self.rollout.is_some() {
            return Err(StageError::Busy);
        }
        if self.current.is_none() {
            return Err(StageError::NoBaseline);
        }
        let cfg = self.parse(bytes).map_err(StageError::Config)?;
        let generation = self.mint();
        self.rollout = Some(Rollout { generation, candidate: Arc::new(cfg), phase: Phase::Shadow, entered_ms: now_ms });
        Ok(generation)
    }

    /// Phase of the rollout in progress, if any.
    pub fn phase(&self) -> Option<Phase> {
        self.rollout.as_ref().map(|r| r.phase)
    }

    /// The staged candidate, if any.
    pub fn candidate(&self) -> Option<&Arc<Config>> {
        self.rollout.as_ref().map(|r| &r.candidate)
    }

    /// Advance the rollout. Unhealthy ⇒ `RolledBack`; Healthy and the phase timer elapsed ⇒ next phase; otherwise
    /// the phase is unchanged. A clock that goes backwards counts as zero elapsed time.
    pub fn tick(&mut self, now_ms: u64, health: Health) -> Result<Phase, StageError> {
        let Some(r) = self.rollout.as_mut() else {
            return Err(StageError::NotStaging);
        };
        if health == Health::Unhealthy {
            self.rollout = None;
            return Ok(Phase::RolledBack);
        }
        let elapsed = now_ms.saturating_sub(r.entered_ms);
        match r.phase {
            Phase::Shadow if elapsed >= self.policy.shadow_ms => {
                r.phase = Phase::Canary;
                r.entered_ms = now_ms;
                Ok(Phase::Canary)
            }
            Phase::Canary if elapsed >= self.policy.bake_ms => {
                let (generation, cand) = (r.generation, Arc::clone(&r.candidate));
                self.rollout = None;
                self.previous = self.current.take();
                self.current = Some((generation, cand));
                Ok(Phase::Full)
            }
            p => Ok(p),
        }
    }

    /// Abort the rollout in progress (served config unchanged), or, with none in progress, restore the config
    /// served before the last promotion/apply. Returns the generation now served.
    pub fn rollback(&mut self) -> Result<Generation, StageError> {
        if self.rollout.take().is_some() {
            return self.generation().ok_or(StageError::NothingToRollBack);
        }
        match self.previous.take() {
            Some(prev) => {
                let g = prev.0;
                self.current = Some(prev);
                Ok(g)
            }
            None => Err(StageError::NothingToRollBack),
        }
    }

    /// Config for a traffic bucket (`bucket % 1000`): the candidate for the canary share during `Canary`, the
    /// served config otherwise (shadow candidates never serve).
    pub fn config_for(&self, bucket: u16) -> Option<&Arc<Config>> {
        if let Some(r) = &self.rollout
            && r.phase == Phase::Canary
            && (bucket % 1000) < self.policy.canary_permille.clamp(1, 1000)
        {
            return Some(&r.candidate);
        }
        self.current()
    }
}
