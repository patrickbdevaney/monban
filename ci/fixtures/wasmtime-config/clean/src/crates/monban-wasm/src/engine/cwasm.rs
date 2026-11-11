// Fixture for ci/wasmtime-config.py (not compiled). The single permitted deserialize site (PLAN D4): a .cwasm
// produced by this boot's sandboxed `monban-p2 compile`, loaded only after its sha256 matches the supervisor's digest.
// A comment that names Module::deserialize(...) or Module::deserialize_file(...) must not count as a site.
use wasmtime::{Engine, Module};

pub fn load(engine: &Engine, path: &std::path::Path, want: &[u8; 32]) -> Result<Module, Error> {
    let got = sha256_file(path)?;
    if &got != want {
        return Err(Error::Digest);
    }
    // SAFETY: `path` is the .cwasm this boot's sandboxed compiler wrote and its digest was just checked.
    let m = unsafe { Module::deserialize_file(engine, path) }.map_err(|_| Error::Load)?;
    Ok(m)
}
