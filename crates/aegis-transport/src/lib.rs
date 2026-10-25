//! hyper/h2 wrapper enforcing TBI-1..9, strict H1, upstream framing regeneration, and the Exchange model.
//!
//! Phase-0: the frozen Exchange + front-end hook interface (F3) only; no listener exists yet, so nothing can serve.
#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

pub mod exchange;
