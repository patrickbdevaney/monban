//! Faults are mentioned in comments freely: Faults, faults.
#[cfg(feature = "test-faults")]
mod faults;
#[cfg(feature = "test-faults")]
pub use faults::Faults;

pub struct AcmeConfig {
    pub directory_url: String,
    /// Fault injection (feature test-faults only).
    #[cfg(feature = "test-faults")]
    #[allow(dead_code)]
    pub faults: Faults,
}

#[cfg(feature = "test-faults")]
use faults::wrong_jws_key;
#[cfg(not(feature = "test-faults"))]
fn wrong_jws_key(_: &AcmeConfig) -> bool {
    false
}
