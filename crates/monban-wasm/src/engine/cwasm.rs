//! `.cwasm` production and loading (PLAN-5 D4, DEVIATIONS X-14; ARCHITECTURE §3.6, runwasi CVE-2026-47218).
//!
//! [`compile`] runs inside the sandboxed `monban-p2 compile` process: it validates the module against the F14 shape
//! and serializes it for this engine's settings. The supervisor hashes the file it wrote and passes that digest to
//! the zygote or cordon. [`load`] reads the file once into memory, hashes those bytes, refuses on any mismatch,
//! and only then deserializes exactly the bytes it hashed (no second open of the path, so no window between the
//! check and the use). This is the crate's single unsafe site.

use std::fmt;
use std::io::Read;
use std::path::Path;

use sha2::{Digest as _, Sha256};
use wasmtime::{Engine, Module, Precompiled};

use super::P2Engine;
use crate::abi;

/// SHA-256 digest of a `.cwasm` file.
pub type Digest = [u8; 32];

/// Largest `.cwasm` accepted (a compiled P2 module is far smaller; the cap bounds the read).
pub const MAX_CWASM_BYTES: u64 = 256 << 20;
/// Largest `.wasm` input accepted by [`compile`].
pub const MAX_WASM_BYTES: usize = 64 << 20;

/// Why a module could not be compiled or a `.cwasm` could not be loaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CwasmError {
    /// Reading the file failed.
    Io(String),
    /// The file is larger than [`MAX_CWASM_BYTES`] (or the input larger than [`MAX_WASM_BYTES`]).
    TooLarge(u64),
    /// The file's sha256 is not the digest the supervisor holds. Nothing was deserialized.
    DigestMismatch,
    /// The digest matched but the bytes are not a precompiled core module for this engine.
    NotPrecompiledModule,
    /// wasmtime refused the module (validation, compilation or deserialization).
    Wasmtime(String),
    /// The module does not fit the F14 shape.
    Abi(abi::AbiError),
}

impl fmt::Display for CwasmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(m) => write!(f, "cwasm io: {m}"),
            Self::TooLarge(n) => write!(f, "input too large: {n} bytes"),
            Self::DigestMismatch => write!(f, "cwasm sha256 does not match the supervisor's digest; refused"),
            Self::NotPrecompiledModule => write!(f, "not a precompiled core module"),
            Self::Wasmtime(m) => write!(f, "wasmtime: {m}"),
            Self::Abi(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CwasmError {}

/// SHA-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> Digest {
    Sha256::digest(bytes).into()
}

/// Lower-case hex of a digest.
pub fn hex(d: &Digest) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Validates `wasm` (binary format; the engine has no text parser) against the engine and the F14 shape, and
/// returns the serialized `.cwasm` bytes for this engine's settings.
pub fn compile(engine: &P2Engine, wasm: &[u8]) -> Result<Vec<u8>, CwasmError> {
    if wasm.len() > MAX_WASM_BYTES {
        return Err(CwasmError::TooLarge(u64::try_from(wasm.len()).unwrap_or(u64::MAX)));
    }
    let module = Module::new(engine.wasmtime(), wasm).map_err(|e| CwasmError::Wasmtime(format!("{e:#}")))?;
    abi::check_module(&module).map_err(CwasmError::Abi)?;
    module.serialize().map_err(|e| CwasmError::Wasmtime(format!("{e:#}")))
}

/// Reads at most [`MAX_CWASM_BYTES`] of `path` into memory.
fn read_capped(path: &Path) -> Result<Vec<u8>, CwasmError> {
    let f = std::fs::File::open(path).map_err(|e| CwasmError::Io(e.to_string()))?;
    let mut buf = Vec::new();
    f.take(MAX_CWASM_BYTES.saturating_add(1)).read_to_end(&mut buf).map_err(|e| CwasmError::Io(e.to_string()))?;
    let n = u64::try_from(buf.len()).unwrap_or(u64::MAX);
    if n > MAX_CWASM_BYTES {
        return Err(CwasmError::TooLarge(n));
    }
    Ok(buf)
}

/// Loads the `.cwasm` at `path` iff its sha256 equals `expected` (the digest the supervisor computed over the file
/// this boot's sandboxed `monban-p2 compile` wrote). On a mismatch nothing is deserialized.
pub fn load(engine: &P2Engine, path: &Path, expected: &Digest) -> Result<Module, CwasmError> {
    let bytes = read_capped(path)?;
    if sha256(&bytes) != *expected {
        return Err(CwasmError::DigestMismatch);
    }
    if Engine::detect_precompiled(&bytes) != Some(Precompiled::Module) {
        return Err(CwasmError::NotPrecompiledModule);
    }
    // SAFETY: wasmtime requires that deserialized bytes come from a trusted `Module::serialize` (they are mapped as
    // executable code). These bytes are exactly the ones just hashed (read once, no reopen), and their sha256
    // equals the digest the supervisor computed over the file that this boot's sandboxed `monban-p2 compile`
    // produced with the same engine settings; config and tenant bytes never reach this call (PLAN-5 D4, X-14).
    // wasmtime still checks the header, version and engine compatibility before use.
    #[allow(unsafe_code)]
    let module = unsafe { Module::deserialize(engine.wasmtime(), &bytes) };
    module.map_err(|e| CwasmError::Wasmtime(format!("{e:#}")))
}
