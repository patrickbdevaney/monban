//! Bounded retry with exponential backoff for one OTLP request (oracles/otlp-export README, "https, retry and
//! drop-and-count"; PREFLIGHT R9).
//!
//! - Retryable failures (429, 502, 503, 504, transport) get another attempt; any other answer is final.
//! - At most [`MAX_ATTEMPTS`] attempts. Attempt `i + 1` starts no earlier than `gap_i` after attempt `i` started,
//!   where `gap_1 = FIRST_GAP` and `gap_{i+1} = 2 × (the actual start-to-start gap i)`. So every gap is at least
//!   100 ms and at least twice the previous one, even when an attempt itself was slow (a timeout).
//! - Every attempt starts within [`BUDGET`] of the first, and its timeout ends by then too.
//! - A request is resent byte for byte (the caller passes the same body); nothing is re-scraped.
//! - Once `stop` is set (SIGTERM), no further attempt is made: the request is given up after the current one.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use monban_egress::Url;

use crate::net::{PostError, Poster};

/// Attempts per request, first included (contract: 2..=8).
pub const MAX_ATTEMPTS: u32 = 6;
/// Start-to-start gap before the first retry (contract: >= 100 ms).
pub const FIRST_GAP: Duration = Duration::from_millis(100);
/// Every attempt of one request starts and ends within this of the first (contract: <= 30 s; margin for
/// connection and arrival time at the collector).
pub const BUDGET: Duration = Duration::from_secs(25);
/// Attempt timeout once `stop` is set, so SIGTERM exits promptly.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(2);
const SLICE: Duration = Duration::from_millis(25);

/// How a request ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A 2xx answer.
    Accepted,
    /// Given up after this many attempts (final answer, attempts or budget exhausted, or stopped).
    Dropped(u32, String),
}

/// The pure schedule: given the attempt count so far, when the last attempt started, and the gap that led to it,
/// return the start-to-start gap before the next attempt, or `None` when no further attempt is allowed.
/// `first` is when the request's first attempt started, `now` is the current time.
pub fn next_gap(
    attempts: u32,
    first: Instant,
    last: Instant,
    prev_gap: Option<Duration>,
    now: Instant,
) -> Option<Duration> {
    if attempts >= MAX_ATTEMPTS {
        return None;
    }
    let gap = match prev_gap {
        None => FIRST_GAP,
        Some(g) => g.saturating_mul(2),
    };
    // The next attempt cannot start before now (the last one may have been slow).
    let gap = gap.max(now.saturating_duration_since(last));
    let start = last.checked_add(gap)?;
    // Leave the next attempt at least FIRST_GAP of the budget to run in.
    if start.saturating_duration_since(first).saturating_add(FIRST_GAP) > BUDGET {
        return None;
    }
    Some(gap)
}

async fn sleep_until_or_stop(until: Instant, stop: &AtomicBool) -> bool {
    loop {
        if stop.load(Ordering::SeqCst) {
            return false;
        }
        let now = Instant::now();
        if now >= until {
            return true;
        }
        tokio::time::sleep(until.saturating_duration_since(now).min(SLICE)).await;
    }
}

/// POST `body` to `url` with bounded retries.
pub async fn post(poster: &Poster, url: &Url, body: &[u8], stop: &AtomicBool) -> Outcome {
    let first = Instant::now();
    let mut last = first;
    let mut prev_gap: Option<Duration> = None;
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        let left = BUDGET.saturating_sub(first.elapsed());
        let timeout = if stop.load(Ordering::SeqCst) { left.min(STOP_TIMEOUT) } else { left };
        let err: PostError = match poster.post(url, body, timeout).await {
            Ok(()) => return Outcome::Accepted,
            Err(e) => e,
        };
        if !err.retryable {
            return Outcome::Dropped(attempts, err.msg);
        }
        if stop.load(Ordering::SeqCst) {
            return Outcome::Dropped(attempts, format!("{} (stopping)", err.msg));
        }
        let Some(gap) = next_gap(attempts, first, last, prev_gap, Instant::now()) else {
            return Outcome::Dropped(attempts, format!("{} (retries exhausted)", err.msg));
        };
        let Some(next) = last.checked_add(gap) else {
            return Outcome::Dropped(attempts, err.msg);
        };
        if !sleep_until_or_stop(next, stop).await {
            return Outcome::Dropped(attempts, format!("{} (stopping)", err.msg));
        }
        // The actual start-to-start gap (sleep may overshoot); the next one doubles it.
        let now = Instant::now();
        prev_gap = Some(now.saturating_duration_since(last));
        last = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Walk the schedule with attempts that take `took` each; return the start-to-start gaps.
    fn schedule(took: Duration) -> Vec<Duration> {
        let first = Instant::now();
        let (mut last, mut prev, mut n, mut gaps) = (first, None, 1u32, Vec::new());
        while let Some(g) = next_gap(n, first, last, prev, last + took) {
            gaps.push(g);
            last += g;
            prev = Some(g);
            n += 1;
        }
        gaps
    }

    #[test]
    fn contract_fast_failures() {
        let gaps = schedule(Duration::from_millis(2));
        let attempts = gaps.len() + 1;
        assert!((2..=8).contains(&attempts), "{attempts}");
        assert_eq!(attempts, MAX_ATTEMPTS as usize);
        assert!(gaps.iter().all(|g| *g >= Duration::from_millis(100)));
        assert!(gaps.windows(2).all(|w| w.get(1) >= w.first().map(|g| g.mul_f64(0.8)).as_ref()));
        assert!(gaps.iter().sum::<Duration>() + Duration::from_millis(100) <= Duration::from_secs(30));
    }

    #[test]
    fn contract_slow_failures() {
        // Each attempt times out after 5 s: still growing gaps, still within the budget, still >= 2 attempts.
        let gaps = schedule(Duration::from_secs(5));
        assert!(!gaps.is_empty());
        assert!(gaps.windows(2).all(|w| w.get(1) >= w.first().map(|g| g.mul_f64(0.8)).as_ref()));
        assert!(gaps.iter().sum::<Duration>() < BUDGET);
    }

    #[test]
    fn no_retry_after_max() {
        let t = Instant::now();
        assert_eq!(next_gap(MAX_ATTEMPTS, t, t, None, t), None);
        assert_eq!(next_gap(1, t, t, None, t), Some(FIRST_GAP));
        assert_eq!(next_gap(2, t, t, Some(FIRST_GAP), t), Some(FIRST_GAP * 2));
    }

    #[test]
    fn status_classes() {
        for s in [429, 502, 503, 504] {
            assert!(crate::net::retryable_status(s), "{s}");
        }
        for s in [400, 401, 403, 404, 413, 500, 501] {
            assert!(!crate::net::retryable_status(s), "{s}");
        }
    }
}
