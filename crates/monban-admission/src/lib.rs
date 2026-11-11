//! Admission and abuse control stages S0-S6 (I1-I11).
//!
//! A sans-IO state machine over the admission event protocol (`oracles/admission-props/README.md`, "Subject event
//! protocol", normative semantics 1–9). The host feeds [`Arrive`], [`Done`] and [`Close`] events in time order and
//! receives one [`Verdict`] per arrival. Every stage returns a typed result; any injected fault or internal
//! inability to decide (e.g. a zero-capacity store) rejects fail-closed with 401/429/503, never 200 (I7).
#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod pipeline;
mod types;

pub use pipeline::Admission;
pub use types::{
    AggGroup, Arrive, Class, Close, Config, Credential, Done, Lane, RejectStatus, Stage, Verdict, classify,
};
