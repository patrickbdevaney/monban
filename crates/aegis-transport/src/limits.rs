//! Wrapper limits. Every number the wrapper enforces comes from here; nothing comes from the peer.
//!
//! The first block mirrors the F8 `limits` section field-for-field (same names, same bounds, golden defaults:
//! `interfaces/F8-config.schema.json`, ARCHITECTURE §3.1). The assembly maps `aegis_config::Limits` onto this
//! struct by name with [`WrapperLimits::set_f8`], so the transport does not depend on the config crate. The second
//! block holds golden §3.1 settings that F8 does not expose yet (fixed at their golden values unless a later spec
//! change adds them to F8).

use core::fmt;

/// F8 `limits` (name, minimum, maximum, golden default), in schema order.
pub const F8_BOUNDS: &[(&str, u64, u64, u64)] = &[
    ("max_concurrent_streams", 1, 1000, 100),
    ("max_header_list_size", 1024, 65536, 16384),
    ("max_header_fields", 8, 256, 128),
    ("header_table_size", 0, 65536, 4096),
    ("rst_burst", 1, 1000, 100),
    ("rst_refill_per_s", 1, 1000, 33),
    ("max_streams_per_conn", 1, 100_000, 10_000),
    ("stream_window", 65535, 16_777_216, 262_144),
    ("conn_window", 65535, 67_108_864, 1_048_576),
    ("stall_timeout_ms", 100, 120_000, 10_000),
    ("idle_timeout_ms", 1000, 600_000, 30_000),
    ("max_body_bytes", 0, 1_073_741_824, 1_048_576),
    ("per_conn_memory_bytes", 65536, 268_435_456, 16_777_216),
];

/// Limits the connection driver enforces (TBI-1..9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrapperLimits {
    // ---- F8 `limits` ------------------------------------------------------------------------------------------
    /// h2 SETTINGS_MAX_CONCURRENT_STREAMS and the live-handler semaphore size (TBI-4).
    pub max_concurrent_streams: u64,
    /// TBI-1: decoded field block, RFC 9113 §6.5.2 bytes (name + value + 32 per field, pseudo-fields included).
    pub max_header_list_size: u64,
    /// TBI-1: field count, cookie crumbs counted individually.
    pub max_header_fields: u64,
    /// TBI-3: HPACK dynamic table size we advertise (the decoder never holds more).
    pub header_table_size: u64,
    /// TBI-5: peer-reset bucket burst.
    pub rst_burst: u64,
    /// TBI-5: peer-reset bucket refill per second.
    pub rst_refill_per_s: u64,
    /// TBI-5: total streams accepted on one connection before GOAWAY.
    pub max_streams_per_conn: u64,
    /// Initial stream receive window we advertise.
    pub stream_window: u64,
    /// Connection receive window we advertise.
    pub conn_window: u64,
    /// TBI-8: a stream with no progress for this long is reset.
    pub stall_timeout_ms: u64,
    /// TBI-8: a connection with no stream progress and no new stream for this long is closed.
    pub idle_timeout_ms: u64,
    /// Request body cap (min'd with the front end's `ExchangeBudget`).
    pub max_body_bytes: u64,
    /// TBI-7: per-connection memory target `M_conn`.
    pub per_conn_memory_bytes: u64,
    // ---- golden §3.1, not in F8 -------------------------------------------------------------------------------
    /// TBI-4: handlers queued per connection behind the semaphore (4 x `max_concurrent_streams`).
    pub handler_queue: u64,
    /// TBI-5: server-originated (local error) resets per connection before GOAWAY ENHANCE_YOUR_CALM.
    pub max_local_error_resets: u64,
    /// h2: streams reset by the peer before we accepted them (CVE-2023-44487 guard inside h2).
    pub max_pending_accept_resets: u64,
    /// h2 SETTINGS_MAX_FRAME_SIZE.
    pub max_frame_size: u64,
    /// h2 per-stream send buffer cap (bytes h2 may hold for one stream).
    pub send_buffer: u64,
    /// TBI-6/7: per-connection ledger of bytes the wrapper keeps in flight (request bodies held + response bytes
    /// handed to the stack and not yet written + decoded field blocks). The h2 receive buffer (≤ `conn_window`)
    /// and fixed per-stream state come on top, so `ledger_bytes + conn_window` must leave headroom under
    /// `per_conn_memory_bytes` (spikes/q2-009 window-0 stall cap).
    pub ledger_bytes: u64,
    /// HTTP/1.1: longest raw request head (request line + fields) buffered before 431.
    pub h1_max_head_bytes: u64,
    /// Response body chunk handed to the stack per step.
    pub chunk_bytes: u64,
}

impl WrapperLimits {
    /// Golden settings (ARCHITECTURE §3.1; F8 defaults).
    pub const GOLDEN: Self = Self {
        max_concurrent_streams: 100,
        max_header_list_size: 16_384,
        max_header_fields: 128,
        header_table_size: 4096,
        rst_burst: 100,
        rst_refill_per_s: 33,
        max_streams_per_conn: 10_000,
        stream_window: 262_144,
        conn_window: 1_048_576,
        stall_timeout_ms: 10_000,
        idle_timeout_ms: 30_000,
        max_body_bytes: 1_048_576,
        per_conn_memory_bytes: 16_777_216,
        handler_queue: 400,
        max_local_error_resets: 256,
        max_pending_accept_resets: 20,
        max_frame_size: 16_384,
        send_buffer: 409_600,
        ledger_bytes: 12 * 1_048_576,
        h1_max_head_bytes: 16_384 + 8192 + 16,
        chunk_bytes: 16_384,
    };

    /// Set one F8 field by its schema name, bounds-checked (the assembly feeds `aegis_config::Limits` through this).
    pub fn set_f8(&mut self, name: &str, v: u64) -> Result<(), LimitsError> {
        let Some(&(_, lo, hi, _)) = F8_BOUNDS.iter().find(|(n, ..)| *n == name) else {
            return Err(LimitsError::UnknownField);
        };
        if v < lo || v > hi {
            return Err(LimitsError::OutOfBounds);
        }
        match name {
            "max_concurrent_streams" => self.max_concurrent_streams = v,
            "max_header_list_size" => self.max_header_list_size = v,
            "max_header_fields" => self.max_header_fields = v,
            "header_table_size" => self.header_table_size = v,
            "rst_burst" => self.rst_burst = v,
            "rst_refill_per_s" => self.rst_refill_per_s = v,
            "max_streams_per_conn" => self.max_streams_per_conn = v,
            "stream_window" => self.stream_window = v,
            "conn_window" => self.conn_window = v,
            "stall_timeout_ms" => self.stall_timeout_ms = v,
            "idle_timeout_ms" => self.idle_timeout_ms = v,
            "max_body_bytes" => self.max_body_bytes = v,
            "per_conn_memory_bytes" => self.per_conn_memory_bytes = v,
            _ => return Err(LimitsError::UnknownField),
        }
        Ok(())
    }

    /// F8 values in [`F8_BOUNDS`] order.
    pub fn f8_values(&self) -> [u64; 13] {
        [
            self.max_concurrent_streams,
            self.max_header_list_size,
            self.max_header_fields,
            self.header_table_size,
            self.rst_burst,
            self.rst_refill_per_s,
            self.max_streams_per_conn,
            self.stream_window,
            self.conn_window,
            self.stall_timeout_ms,
            self.idle_timeout_ms,
            self.max_body_bytes,
            self.per_conn_memory_bytes,
        ]
    }

    /// Cross-field consistency (fail closed at construction, never at runtime).
    pub fn validate(&self) -> Result<(), LimitsError> {
        for (&(_, lo, hi, _), &v) in F8_BOUNDS.iter().zip(self.f8_values().iter()) {
            if v < lo || v > hi {
                return Err(LimitsError::OutOfBounds);
            }
        }
        // TBI-7: ledger + h2 receive buffer must fit in M_conn.
        if self.ledger_bytes.saturating_add(self.conn_window) > self.per_conn_memory_bytes {
            return Err(LimitsError::LedgerExceedsConnMemory);
        }
        // A single field block and one chunk must fit in the ledger, or nothing could ever be admitted.
        if self.max_header_list_size.saturating_add(self.chunk_bytes) > self.ledger_bytes {
            return Err(LimitsError::LedgerTooSmall);
        }
        if self.handler_queue > self.max_concurrent_streams.saturating_mul(4) {
            return Err(LimitsError::QueueTooLong);
        }
        if self.max_local_error_resets > 256 {
            return Err(LimitsError::OutOfBounds);
        }
        if !(16_384..=16_777_215).contains(&self.max_frame_size)
            || self.chunk_bytes == 0
            || self.chunk_bytes > self.max_frame_size
            || self.send_buffer < self.chunk_bytes
            || self.h1_max_head_bytes < 8192
            || self.h1_max_head_bytes > 131_072
        {
            return Err(LimitsError::OutOfBounds);
        }
        Ok(())
    }
}

/// Why a limits set was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitsError {
    UnknownField,
    OutOfBounds,
    LedgerExceedsConnMemory,
    LedgerTooSmall,
    QueueTooLong,
}

impl fmt::Display for LimitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownField => "unknown F8 limits field",
            Self::OutOfBounds => "limit out of bounds",
            Self::LedgerExceedsConnMemory => "ledger_bytes + conn_window > per_conn_memory_bytes",
            Self::LedgerTooSmall => "ledger_bytes < max_header_list_size + chunk_bytes",
            Self::QueueTooLong => "handler_queue > 4 x max_concurrent_streams",
        })
    }
}

impl std::error::Error for LimitsError {}

/// Saturating u64 -> u32 for h2 builder knobs (all bounded far below u32::MAX by [`F8_BOUNDS`]).
pub(crate) fn u32_sat(v: u64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// Saturating u64 -> usize.
pub(crate) fn usize_sat(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn golden_is_valid_and_matches_f8_defaults() {
        assert_eq!(WrapperLimits::GOLDEN.validate(), Ok(()));
        let defaults: Vec<u64> = F8_BOUNDS.iter().map(|b| b.3).collect();
        assert_eq!(defaults, WrapperLimits::GOLDEN.f8_values().to_vec());
    }

    /// The F8 schema (frozen interface) and this table agree on names, bounds and defaults.
    #[test]
    fn f8_table_matches_schema_file() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../interfaces/F8-config.schema.json");
        let Ok(text) = std::fs::read_to_string(path) else {
            panic!("cannot read {path}");
        };
        let Some(start) = text.find("\"limits\": {\n      \"type\"").or_else(|| text.find("\"limits\": {")) else {
            panic!("no limits block");
        };
        let block = text.get(start..).unwrap_or("");
        for &(name, lo, hi, def) in F8_BOUNDS {
            let key = format!("\"{name}\"");
            let Some(at) = block.find(&key) else { panic!("{name} missing from schema") };
            let rest = block.get(at..).unwrap_or("");
            let end = rest.find('}').unwrap_or(rest.len());
            let obj: String = rest.get(..end).unwrap_or("").chars().filter(|c| !c.is_whitespace()).collect();
            assert!(obj.contains(&format!("\"minimum\":{lo}")), "{name} min: {obj}");
            assert!(obj.contains(&format!("\"maximum\":{hi}")), "{name} max: {obj}");
            assert!(obj.contains(&format!("\"default\":{def}")), "{name} default: {obj}");
        }
    }

    #[test]
    fn set_f8_bounds_and_cross_checks() {
        let mut l = WrapperLimits::GOLDEN;
        assert_eq!(l.set_f8("stall_timeout_ms", 99), Err(LimitsError::OutOfBounds));
        assert_eq!(l.set_f8("nope", 1), Err(LimitsError::UnknownField));
        assert_eq!(l.set_f8("stall_timeout_ms", 2000), Ok(()));
        assert_eq!(l.stall_timeout_ms, 2000);
        assert_eq!(l.set_f8("per_conn_memory_bytes", 4 * 1_048_576), Ok(()));
        assert_eq!(l.validate(), Err(LimitsError::LedgerExceedsConnMemory));
        let mut q = WrapperLimits::GOLDEN;
        q.handler_queue = 401;
        assert_eq!(q.validate(), Err(LimitsError::QueueTooLong));
    }
}
