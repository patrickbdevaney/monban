//! ACME, certificate lifecycle CERT-1..4, zero-downtime upgrade UP-1..7, sd-notify.
//!
//! Implemented (P2-upgrade-001): the zero-downtime upgrade (ARCHITECTURE §3.11, F11, UP-1..7) and sd-notify.
//! ACME / CERT-1..4 are not implemented yet.
//!
//! * [`wire`]: F11 codec, deterministic CBOR subset, total length-capped decoder (UP-7).
//! * [`machine`]: sans-IO parent and child state machines (UP-1, UP-2, UP-4, UP-7).
//! * [`handover`]: IO drivers: 0700 dir, SEQPACKET socket + SO_PEERCRED, STEK by pipe (UP-5), spawn with fd
//!   inheritance, claim-or-close (UP-2), drain.
//! * [`fdcheck`]: SO_TYPE / SO_ACCEPTCONN / getsockname validation (UP-2).
//! * [`cloexec`]: CLOEXEC hygiene audit (UP-6).
//! * [`drain`]: accept loop with a stop flag, two-phase drain with forced-close count (UP-3 analogue, UP-4).
//! * [`notify`]: sd-notify READY / RELOADING / MAINPID, a no-op outside systemd.
//! * [`signals`]: sigwait-based signal handling.
//! * [`stek`]: STEK ring and its pipe framing (UP-5).
#![forbid(unsafe_code)]

pub mod cloexec;
pub mod drain;
pub mod fdcheck;
pub mod handover;
pub mod machine;
pub mod notify;
pub mod signals;
pub mod stek;
pub mod wire;
