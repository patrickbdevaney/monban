//! Plain metrics counters (TBI-9: every update saturates, nothing wraps).
//!
//! The transport does not depend on aegis-metrics (same layer, no INTRA_LAYER entry); the assembly reads
//! [`Counters::snapshot`] and exports it.

use std::sync::atomic::{AtomicU64, Ordering};

/// Saturating increment.
pub(crate) fn bump(a: &AtomicU64) {
    add(a, 1);
}

/// Saturating add.
pub(crate) fn add(a: &AtomicU64, n: u64) {
    let _ = a.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_add(n)));
}

/// Saturating decrement (gauges).
pub(crate) fn dec(a: &AtomicU64) {
    let _ = a.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
}

/// Raise `a` to at least `v`.
pub(crate) fn max(a: &AtomicU64, v: u64) {
    a.fetch_max(v, Ordering::Relaxed);
}

macro_rules! counters {
    ($( $(#[$m:meta])* $name:ident ),* $(,)?) => {
        /// Server-wide counters and gauges.
        #[derive(Debug, Default)]
        pub struct Counters {
            $( $(#[$m])* pub $name: AtomicU64, )*
        }

        impl Counters {
            /// (name, value) for every counter, in declaration order.
            pub fn snapshot(&self) -> Vec<(&'static str, u64)> {
                vec![$( (stringify!($name), self.$name.load(Ordering::Relaxed)), )*]
            }
        }
    };
}

counters! {
    /// Connections handed to the driver.
    conns_accepted,
    /// Gauge: connections currently driven.
    conns_live,
    /// TLS handshakes that failed or timed out.
    tls_failures,
    /// Connections closed by the idle deadline (TBI-8).
    conns_idle_closed,
    /// GOAWAY ENHANCE_YOUR_CALM sent by the wrapper (TBI-4 queue overflow, TBI-5 bucket / reset cap).
    goaway_calm,
    /// GOAWAY after `max_streams_per_conn` (TBI-5).
    goaway_stream_cap,
    /// Streams accepted (h2) or requests admitted (h1).
    streams_accepted,
    /// Gauge: live stream tasks.
    streams_live,
    /// Streams reset by the stall deadline (TBI-8).
    streams_stall_reaped,
    /// Streams refused because the handler queue was full (TBI-4).
    streams_queue_overflow,
    /// Peer resets observed on accepted streams (TBI-5 bucket debits).
    peer_resets,
    /// Resets the wrapper sent (TBI-5 server-originated cap).
    server_resets,
    /// TBI-1 rejects (431): field block bytes or field count.
    field_block_rejects,
    /// CANON-6 rejects (400/404/421) from `canon_request`.
    authority_rejects,
    /// Strict HTTP/1.1 framing rejects.
    h1_rejects,
    /// Request bodies over budget (413).
    body_too_large,
    /// Times a stream waited on the per-connection ledger (TBI-6/7 backpressure).
    ledger_waits,
    /// High-water mark of any single connection's ledger, bytes.
    ledger_peak_bytes,
    /// Responses sent.
    responses,
    /// Handler futures dropped because the peer went away before the reply (h2 RST_STREAM, h1 FIN / TCP RST while
    /// the handler runs): INV-NOMUT-C NC1 (the drop is the cancellation the handler observes).
    handlers_aborted,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn counters_saturate() {
        let a = AtomicU64::new(u64::MAX - 1);
        bump(&a);
        bump(&a);
        add(&a, 5);
        assert_eq!(a.load(Ordering::Relaxed), u64::MAX);
        let g = AtomicU64::new(0);
        dec(&g);
        assert_eq!(g.load(Ordering::Relaxed), 0);
        let c = Counters::default();
        bump(&c.responses);
        assert!(c.snapshot().contains(&("responses", 1)));
    }
}
