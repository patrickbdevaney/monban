//! The S0–S6 admission state machine.

use alloc::collections::BTreeMap;
use alloc::string::String;
use monban_budget::{Gcra, LruStore};

use crate::types::{
    AggGroup, Arrive, Class, Close, Config, Credential, Done, Lane, RejectStatus, Stage, Verdict, classify,
};

/// Typed stage rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Reject {
    stage: Stage,
    status: RejectStatus,
}

const fn reject(stage: Stage, status: RejectStatus) -> Reject {
    Reject { stage, status }
}

/// S3 bucket key (semantics 2).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum BucketKey {
    Verified(String),
    Session(String),
    Anon(String),
}

/// Which per-identity parameter set a bucket uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParamSet {
    Verified,
    Session,
    Anon,
}

#[derive(Debug)]
struct S3Entry {
    tat: u64,
    params: ParamSet,
}

#[derive(Debug)]
struct Inflight {
    class: Class,
    key: BucketKey,
    cost: u64,
}

/// In-flight counts per class (S5).
#[derive(Debug, Default, Clone, Copy)]
struct ClassCounts {
    verified: u64,
    established: u64,
    fresh: u64,
    anon: u64,
}

impl ClassCounts {
    fn get(&self, c: Class) -> u64 {
        match c {
            Class::Verified => self.verified,
            Class::Established => self.established,
            Class::Fresh => self.fresh,
            Class::Anon => self.anon,
        }
    }
    fn slot(&mut self, c: Class) -> &mut u64 {
        match c {
            Class::Verified => &mut self.verified,
            Class::Established => &mut self.established,
            Class::Fresh => &mut self.fresh,
            Class::Anon => &mut self.anon,
        }
    }
    fn total(&self) -> u64 {
        self.verified.saturating_add(self.established).saturating_add(self.fresh).saturating_add(self.anon)
    }
}

const CLASSES: [Class; 4] = [Class::Verified, Class::Established, Class::Fresh, Class::Anon];

/// Reservation ⌊share · L⌋ with shares verified .30, established .40, fresh .10, anon .20 (exact integer math).
fn reservation(c: Class, limit: u64) -> u64 {
    let tenths: u128 = match c {
        Class::Verified => 3,
        Class::Established => 4,
        Class::Fresh => 1,
        Class::Anon => 2,
    };
    u64::try_from(u128::from(limit) * tenths / 10).unwrap_or(u64::MAX)
}

/// Admission pipeline state. Reset by constructing a new one from a [`Config`].
#[derive(Debug)]
pub struct Admission {
    cfg: Config,
    conns: BTreeMap<String, String>,
    prefix_open: BTreeMap<String, u64>,
    s1: LruStore<String, u64>,
    s3: LruStore<BucketKey, S3Entry>,
    agg_f: u64,
    agg_e: u64,
    inflight: BTreeMap<u64, Inflight>,
    counts: ClassCounts,
}

impl Admission {
    /// Fresh pipeline state for `cfg`.
    #[must_use]
    pub fn new(cfg: Config) -> Self {
        Admission {
            s1: LruStore::new(cfg.s1_store),
            s3: LruStore::new(cfg.s3_store),
            cfg,
            conns: BTreeMap::new(),
            prefix_open: BTreeMap::new(),
            agg_f: 0,
            agg_e: 0,
            inflight: BTreeMap::new(),
            counts: ClassCounts::default(),
        }
    }

    /// The active configuration.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Number of admitted requests not yet completed.
    #[must_use]
    pub fn in_flight(&self) -> u64 {
        self.counts.total()
    }

    /// Number of open connections tracked by S0.
    #[must_use]
    pub fn open_connections(&self) -> usize {
        self.conns.len()
    }

    fn params(&self, p: ParamSet) -> Gcra {
        match p {
            ParamSet::Verified => self.cfg.verified,
            ParamSet::Session => self.cfg.session,
            ParamSet::Anon => self.cfg.anon,
        }
    }

    /// Semantics 7: a fault fires on entry to the stage, before any state access. A fault naming `S3A` (not an
    /// entry point of its own) fires on entry to S3, so no fault value can ever be skipped.
    fn fault_gate(ev: &Arrive, stage: Stage) -> Result<(), Reject> {
        let hit = match ev.fault {
            Some(Stage::S3A) => stage == Stage::S3,
            Some(f) => f == stage,
            None => false,
        };
        if hit { Err(reject(stage, RejectStatus::Unavailable)) } else { Ok(()) }
    }

    /// One arrival through S0..S6.
    pub fn arrive(&mut self, ev: &Arrive) -> Verdict {
        match self.run(ev) {
            Ok(()) => Verdict::Admit,
            Err(r) => Verdict::Reject { stage: r.stage, status: r.status },
        }
    }

    fn run(&mut self, ev: &Arrive) -> Result<(), Reject> {
        self.s0(ev)?;
        self.s1(ev)?;
        let class = Self::s2(ev, &self.cfg)?;
        let key = self.s3(ev, class)?;
        self.s4(ev, class)?;
        self.s5(ev, class)?;
        self.s6(ev, class, key)
    }

    /// S0: connection caps.
    fn s0(&mut self, ev: &Arrive) -> Result<(), Reject> {
        Self::fault_gate(ev, Stage::S0)?;
        if ev.newconn && !self.conns.contains_key(&ev.conn) {
            let open = u64::try_from(self.conns.len()).unwrap_or(u64::MAX);
            let in_prefix = self.prefix_open.get(&ev.prefix).copied().unwrap_or(0);
            if open >= self.cfg.max_conns || in_prefix >= self.cfg.prefix_cap {
                return Err(reject(Stage::S0, RejectStatus::Unavailable));
            }
            self.conns.insert(ev.conn.clone(), ev.prefix.clone());
            self.prefix_open.insert(ev.prefix.clone(), in_prefix.saturating_add(1));
        }
        Ok(())
    }

    /// S1: pre-auth per-IP GCRA, one unit per request. An S1 key is not an identity bucket, so a new key starts
    /// with the full S1 burst.
    fn s1(&mut self, ev: &Arrive) -> Result<(), Reject> {
        Self::fault_gate(ev, Stage::S1)?;
        let now = ev.t;
        let g = self.cfg.s1;
        let (tat, _) = self
            .s1
            .get_or_insert_with(ev.ip.clone(), || now)
            .map_err(|_| reject(Stage::S1, RejectStatus::Unavailable))?;
        if g.charge(tat, now, 1) { Ok(()) } else { Err(reject(Stage::S1, RejectStatus::TooManyRequests)) }
    }

    /// S2: classification.
    fn s2(ev: &Arrive, cfg: &Config) -> Result<Class, Reject> {
        Self::fault_gate(ev, Stage::S2)?;
        Ok(classify(&ev.cred, ev.t, cfg.fresh_age_ns))
    }

    fn bucket(ev: &Arrive, class: Class) -> (BucketKey, ParamSet) {
        match (&ev.cred, class) {
            (Credential::Verified { id }, Class::Verified) => (BucketKey::Verified(id.clone()), ParamSet::Verified),
            (Credential::Cookie { id, .. }, Class::Established | Class::Fresh) => {
                (BucketKey::Session(id.clone()), ParamSet::Session)
            }
            _ => (BucketKey::Anon(ev.ip.clone()), ParamSet::Anon),
        }
    }

    fn agg_group(&self, class: Class, cost: u64) -> Option<AggGroup> {
        if cost < self.cfg.exp_cost {
            return None;
        }
        match class {
            Class::Fresh | Class::Anon => Some(AggGroup::F),
            Class::Established => Some(AggGroup::E),
            Class::Verified => None,
        }
    }

    /// S3: per-identity budget, then the expensive-tier aggregate, atomically (semantics 4).
    fn s3(&mut self, ev: &Arrive, class: Class) -> Result<BucketKey, Reject> {
        Self::fault_gate(ev, Stage::S3)?;
        let now = ev.t;
        let (key, pset) = Self::bucket(ev, class);
        let g = self.params(pset);
        let grant = self.cfg.anon.burst;
        let group = self.agg_group(class, ev.cost);
        let agg = group.map(|gr| match gr {
            AggGroup::F => (self.cfg.agg_f, self.agg_f),
            AggGroup::E => (self.cfg.agg_e, self.agg_e),
        });
        let (entry, _) = self
            .s3
            .get_or_insert_with(key.clone(), || S3Entry { tat: g.initial_tat(now, grant), params: pset })
            .map_err(|_| reject(Stage::S3, RejectStatus::Unavailable))?;
        // The key determines the parameter set, so `g` is the entry's own limiter.
        let Some(new_tat) = g.conform(entry.tat, now, ev.cost) else {
            return Err(reject(Stage::S3, RejectStatus::TooManyRequests));
        };
        let new_agg = match agg {
            None => None,
            Some((ag, atat)) => match ag.conform(atat, now, ev.cost) {
                Some(n) => Some(n),
                // Identity stays uncharged (but was touched by the lookup above).
                None => return Err(reject(Stage::S3A, RejectStatus::Unavailable)),
            },
        };
        entry.tat = new_tat;
        match (group, new_agg) {
            (Some(AggGroup::F), Some(n)) => self.agg_f = n,
            (Some(AggGroup::E), Some(n)) => self.agg_e = n,
            _ => {}
        }
        Ok(key)
    }

    /// S4: step-up PoW for expensive anonymous requests; the accessible lane bypasses it.
    fn s4(&self, ev: &Arrive, class: Class) -> Result<(), Reject> {
        Self::fault_gate(ev, Stage::S4)?;
        if class == Class::Anon
            && ev.cost >= self.cfg.stepup_cost
            && ev.pow < self.cfg.stepup_bits
            && ev.lane != Lane::Accessible
        {
            return Err(reject(Stage::S4, RejectStatus::Unauthorized));
        }
        Ok(())
    }

    /// S5: class-partitioned concurrency with reservations and work-conserving borrowing.
    fn s5(&self, ev: &Arrive, class: Class) -> Result<(), Reject> {
        Self::fault_gate(ev, Stage::S5)?;
        let limit = self.cfg.limit;
        let total = self.counts.total();
        let busy = reject(Stage::S5, RejectStatus::Unavailable);
        if total >= limit {
            return Err(busy);
        }
        if self.counts.get(class) >= reservation(class, limit) {
            // Borrowing: free slots must exceed what other classes still hold in reserve.
            let others = CLASSES
                .iter()
                .filter(|&&k| k != class)
                .map(|&k| reservation(k, limit).saturating_sub(self.counts.get(k)))
                .fold(0u64, u64::saturating_add);
            if limit.saturating_sub(total) <= others {
                return Err(busy);
            }
        }
        Ok(())
    }

    /// S6: dispatch; record the in-flight request for the post-hoc debit.
    fn s6(&mut self, ev: &Arrive, class: Class, key: BucketKey) -> Result<(), Reject> {
        Self::fault_gate(ev, Stage::S6)?;
        if let Some(old) = self.inflight.insert(ev.id, Inflight { class, key, cost: ev.cost }) {
            // A reused id replaces its predecessor; keep the counts consistent.
            let s = self.counts.slot(old.class);
            *s = s.saturating_sub(1);
        }
        let s = self.counts.slot(class);
        *s = s.saturating_add(1);
        Ok(())
    }

    /// Completion of request `id` (semantics 6). Ignored unless `id` is in flight. Cancels are not refunded.
    pub fn done(&mut self, ev: &Done) {
        let Some(rec) = self.inflight.remove(&ev.id) else { return };
        let s = self.counts.slot(rec.class);
        *s = s.saturating_sub(1);
        let extra = ev.actual_cost.saturating_sub(rec.cost);
        if extra == 0 {
            return;
        }
        let cfg = &self.cfg;
        if let Some(entry) = self.s3.peek_mut(&rec.key) {
            let g = match entry.params {
                ParamSet::Verified => cfg.verified,
                ParamSet::Session => cfg.session,
                ParamSet::Anon => cfg.anon,
            };
            entry.tat = g.debit(entry.tat, ev.t, extra);
        }
    }

    /// Connection close (frees its S0 slot).
    pub fn close(&mut self, ev: &Close) {
        if let Some(pfx) = self.conns.remove(&ev.conn) {
            let left = self.prefix_open.get(&pfx).copied().unwrap_or(0).saturating_sub(1);
            if left == 0 {
                self.prefix_open.remove(&pfx);
            } else {
                self.prefix_open.insert(pfx, left);
            }
        }
    }
}

#[cfg(test)]
mod tests;
