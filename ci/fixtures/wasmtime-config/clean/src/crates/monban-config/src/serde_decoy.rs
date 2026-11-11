// Fixture for ci/wasmtime-config.py (not compiled): serde's `deserialize` is not a wasmtime deserialize site.
use serde::{Deserialize, Deserializer};

impl<'de> Deserialize<'de> for Limit {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let n = u64::deserialize(d)?;
        let raw = Raw::deserialize(n);
        Ok(Limit(raw))
    }
}
/* block comment: Module::deserialize(&engine, bytes) is not a site either */
