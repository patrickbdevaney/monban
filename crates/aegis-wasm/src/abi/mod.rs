//! F14 guest ABI (`interfaces/F14-p2-guest-abi.cddl` Part 1): signatures only, host side fail-closed.
//!
//! P5-wasm-001 owns this file as a stub: it holds the closed import allowlist and the export shape, which
//! `aegis-p2 compile` checks before it writes a `.cwasm` (a module importing anything else, or exporting anything
//! but `memory` and `handle`, is refused). [`define_imports`] defines no host function yet, so a module that imports
//! one of the allowlisted names still fails instantiation in the worker: fail closed. The host functions, handle
//! table and quotas are P5-wasm-002.
#![forbid(unsafe_code)]

use std::fmt;

use wasmtime::{ExternType, Linker, Module, ValType};

/// F14 `guest-api-version`.
pub const GUEST_API_VERSION: u32 = 1;
/// The only import module name.
pub const IMPORT_MODULE: &str = "aegis";
/// Export: memory 0 (32-bit).
pub const EXPORT_MEMORY: &str = "memory";
/// Export: `handle() -> i32`, the completion status (0 Allow, 1 Deny, anything else Error).
pub const EXPORT_HANDLE: &str = "handle";

/// One allowlisted import: every F14 parameter and result is an `i32`, so a signature is (params, results) counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportSig {
    /// Import module.
    pub module: &'static str,
    /// Import name.
    pub name: &'static str,
    /// Number of `i32` parameters.
    pub params: usize,
    /// Number of `i32` results (0 or 1).
    pub results: usize,
}

const fn sig(name: &'static str, params: usize, results: usize) -> ImportSig {
    ImportSig { module: IMPORT_MODULE, name, params, results }
}

/// F14 Part 1 imports, exactly.
pub const IMPORTS: &[ImportSig] = &[
    sig("req_head", 2, 1),      // (dst, cap) -> len
    sig("req_body_read", 2, 1), // (dst, cap) -> count
    sig("resp_head", 3, 1),     // (status, src, len) -> 0
    sig("resp_write", 2, 1),    // (src, len) -> 0
    sig("log", 3, 1),           // (level, src, len) -> 0
    sig("data_run", 2, 1),      // (src, len) -> handle
    sig("result_read", 3, 1),   // (handle, dst, cap) -> len
    sig("handle_drop", 1, 0),   // (handle) -> ()
];

/// `env.host_fault(code: i32) -> ()`, only in `test-hooks` builds (D15).
#[cfg(feature = "test-hooks")]
pub const TEST_IMPORTS: &[ImportSig] = &[ImportSig { module: "env", name: "host_fault", params: 1, results: 0 }];
/// No test imports in a golden build.
#[cfg(not(feature = "test-hooks"))]
pub const TEST_IMPORTS: &[ImportSig] = &[];

/// Why a module does not fit the F14 shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbiError {
    /// An import outside the allowlist, or an allowlisted name with another type or kind.
    Import(String),
    /// A missing, extra or wrongly typed export.
    Export(String),
}

impl fmt::Display for AbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Import(m) => write!(f, "F14 import refused: {m}"),
            Self::Export(m) => write!(f, "F14 export refused: {m}"),
        }
    }
}

impl std::error::Error for AbiError {}

fn all_i32<'a>(mut it: impl ExactSizeIterator<Item = ValType> + 'a, n: usize) -> bool {
    it.len() == n && it.all(|t| matches!(t, ValType::I32))
}

/// Checks a compiled module against the F14 shape: exports exactly `memory` (32-bit, not shared) and
/// `handle: [] -> [i32]`; every import is a function in the allowlist with its exact signature.
pub fn check_module(module: &Module) -> Result<(), AbiError> {
    for imp in module.imports() {
        let (m, n) = (imp.module(), imp.name());
        let allowed = IMPORTS.iter().chain(TEST_IMPORTS).find(|s| s.module == m && s.name == n);
        let Some(s) = allowed else {
            return Err(AbiError::Import(format!("{m}.{n} is not allowlisted")));
        };
        let ExternType::Func(ft) = imp.ty() else {
            return Err(AbiError::Import(format!("{m}.{n} is not a function")));
        };
        if !all_i32(ft.params(), s.params) || !all_i32(ft.results(), s.results) {
            return Err(AbiError::Import(format!("{m}.{n} has the wrong type")));
        }
    }
    let mut seen_memory = false;
    let mut seen_handle = false;
    for exp in module.exports() {
        match (exp.name(), exp.ty()) {
            (EXPORT_MEMORY, ExternType::Memory(mt)) if !mt.is_64() && !mt.is_shared() => seen_memory = true,
            (EXPORT_HANDLE, ExternType::Func(ft)) if all_i32(ft.params(), 0) && all_i32(ft.results(), 1) => {
                seen_handle = true;
            }
            (name, _) => return Err(AbiError::Export(format!("{name} is not an F14 export (or has the wrong type)"))),
        }
    }
    if !seen_memory {
        return Err(AbiError::Export(format!("missing {EXPORT_MEMORY}")));
    }
    if !seen_handle {
        return Err(AbiError::Export(format!("missing {EXPORT_HANDLE}")));
    }
    Ok(())
}

/// Defines the F14 host functions on `linker`. Stub: defines none, so instantiating a module that imports any of
/// them fails (fail closed) until P5-wasm-002 lands the host side.
pub fn define_imports<T>(_linker: &mut Linker<T>) -> Result<(), AbiError> {
    Ok(())
}
