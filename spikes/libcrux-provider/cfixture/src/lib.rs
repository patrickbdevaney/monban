//! C-surface self-test fixture. The C object is linked (static lib `cfixture`) but not called.
#![forbid(unsafe_code)]

/// Marker so the crate is not empty.
pub const FIXTURE: &str = "cfixture";
