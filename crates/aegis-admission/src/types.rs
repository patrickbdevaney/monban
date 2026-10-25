//! Event, configuration and decision types for the admission pipeline.

use aegis_budget::Gcra;
use alloc::string::String;

/// Pipeline stage that produced a decision (ARCHITECTURE §3.4). `S3A` is the expensive-tier aggregate inside S3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Stage {
    /// Listener: connection caps.
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

impl Stage {
    /// Wire name (`"S0"`, …, `"S3A"`, …).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Stage::S0 => "S0",
            Stage::S1 => "S1",
            Stage::S2 => "S2",
            Stage::S3 => "S3",
            Stage::S3A => "S3A",
            Stage::S4 => "S4",
            Stage::S5 => "S5",
            Stage::S6 => "S6",
        }
    }

    /// Parses a wire name; unknown names give `None`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "S0" => Stage::S0,
            "S1" => Stage::S1,
            "S2" => Stage::S2,
            "S3" => Stage::S3,
            "S3A" => Stage::S3A,
            "S4" => Stage::S4,
            "S5" => Stage::S5,
            "S6" => Stage::S6,
            _ => return None,
        })
    }
}

/// The only statuses a reject may carry (I7). There is deliberately no 200 here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RejectStatus {
    /// 401: step-up required.
    Unauthorized,
    /// 429: rate limited.
    TooManyRequests,
    /// 503: capacity, aggregate or stage error.
    Unavailable,
}

impl RejectStatus {
    /// HTTP status code.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            RejectStatus::Unauthorized => 401,
            RejectStatus::TooManyRequests => 429,
            RejectStatus::Unavailable => 503,
        }
    }
}

/// Outcome for one arrival.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// Dispatched at S6 with HTTP 200.
    Admit,
    /// Rejected at `stage` with a 401/429/503 status.
    Reject {
        /// Stage that rejected.
        stage: Stage,
        /// Status to answer with.
        status: RejectStatus,
    },
}

impl Verdict {
    /// HTTP status (200 only for an admit).
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Verdict::Admit => 200,
            Verdict::Reject { status, .. } => status.code(),
        }
    }

    /// Stage that decided (`S6` for an admit).
    #[must_use]
    pub const fn stage(self) -> Stage {
        match self {
            Verdict::Admit => Stage::S6,
            Verdict::Reject { stage, .. } => stage,
        }
    }
}

/// S2 class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    /// Verified credential.
    Verified,
    /// Promoted session cookie older than `fresh_age_ns`.
    Established,
    /// Any other valid session cookie.
    Fresh,
    /// No (valid) credential.
    Anon,
}

/// Expensive-tier aggregate group (semantics 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AggGroup {
    /// fresh + anon.
    F,
    /// established.
    E,
}

/// Presented credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Credential {
    /// Nothing presented.
    None,
    /// A verified credential with a stable id.
    Verified {
        /// Credential id.
        id: String,
    },
    /// A session cookie.
    Cookie {
        /// Session id.
        id: String,
        /// Mint time (ns).
        minted: u64,
        /// Behaviour/cost-based promotion has happened (I9).
        promoted: bool,
    },
}

/// Request lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    /// Standard lane.
    Std,
    /// Accessible lane (bypasses the S4 PoW, I6).
    Accessible,
}

/// Pipeline parameters (one `config` event).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// S1 per-IP limiter (cost 1 per request).
    pub s1: Gcra,
    /// S1 store capacity.
    pub s1_store: usize,
    /// S3 store capacity.
    pub s3_store: usize,
    /// Per-identity anon limiter.
    pub anon: Gcra,
    /// Per-identity session (fresh/established) limiter.
    pub session: Gcra,
    /// Per-identity verified limiter.
    pub verified: Gcra,
    /// Aggregate F (fresh + anon).
    pub agg_f: Gcra,
    /// Aggregate E (established).
    pub agg_e: Gcra,
    /// Cost at which the aggregate applies.
    pub exp_cost: u64,
    /// Cost at which anon requests need step-up PoW.
    pub stepup_cost: u64,
    /// Required PoW bits.
    pub stepup_bits: u64,
    /// S5 concurrency limit L.
    pub limit: u64,
    /// S0 open connection cap.
    pub max_conns: u64,
    /// S0 per-prefix cap.
    pub prefix_cap: u64,
    /// Minimum cookie age for `established`.
    pub fresh_age_ns: u64,
}

/// A request arrival.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arrive {
    /// Request id.
    pub id: u64,
    /// Arrival time (ns).
    pub t: u64,
    /// Client IP (S1 key, anon S3 key).
    pub ip: String,
    /// Client prefix (S0 cap key).
    pub prefix: String,
    /// Connection id.
    pub conn: String,
    /// This request opens `conn`.
    pub newconn: bool,
    /// Presented credential.
    pub cred: Credential,
    /// Declared cost units.
    pub cost: u64,
    /// Proof-of-work bits presented.
    pub pow: u64,
    /// Lane.
    pub lane: Lane,
    /// Injected stage fault (fires on entry to that stage).
    pub fault: Option<Stage>,
}

/// Completion of an admitted request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Done {
    /// Request id.
    pub id: u64,
    /// Completion time (ns).
    pub t: u64,
    /// Actual cost units.
    pub actual_cost: u64,
    /// The request was cancelled (no refund either way).
    pub cancelled: bool,
}

/// Connection close.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Close {
    /// Connection id.
    pub conn: String,
    /// Close time (ns).
    pub t: u64,
}

/// S2 classification (semantics 3). A cookie minted in the future is treated as no credential; age alone never
/// promotes (I9).
#[must_use]
pub fn classify(cred: &Credential, now: u64, fresh_age_ns: u64) -> Class {
    match cred {
        Credential::None => Class::Anon,
        Credential::Verified { .. } => Class::Verified,
        Credential::Cookie { minted, promoted, .. } => match now.checked_sub(*minted) {
            None => Class::Anon,
            Some(age) if age >= fresh_age_ns && *promoted => Class::Established,
            Some(_) => Class::Fresh,
        },
    }
}
