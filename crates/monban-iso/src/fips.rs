//! The linked AWS-LC FIPS module's own version string, read at run time (PLAN-6 D2/D16; feature `cmvp` only).
//!
//! Neither aws-lc-rs 1.15.3 nor rustls 0.23.43 has a safe API for it, so the read lives here, in the one crate
//! allowed audited `unsafe` (DEVIATIONS X-14, `cargo xtask unsafe-sites` caps monban-iso at 20). It takes two sites:
//! the `extern` declaration of `awslc_version_string` and the `CStr::from_ptr` on its result. monban-bin and
//! tls-subject call [`awslc_version_string`] and pass the value into monban-tls (`fips_status_with`,
//! `server_config_with`), so monban-tls (layer 3) never depends on this crate (layer 4).
//!
//! The symbol is the one AWS-LC exports from the FIPS module that aws-lc-rs links under `fips`
//! (aws-lc-fips-sys 0.13.11 = AWS-LC FIPS 3.1.0, `crypto/fipsmodule/service_indicator/service_indicator.c`:
//! `const char *awslc_version_string(void) { return AWSLC_VERSION_STRING; }`). aws-lc-fips-sys prefixes every
//! symbol with its own version, so the `link_name` names 0.13.11 exactly: any other module in the link (a pin
//! change, the uncertified 0.14.x/FIPS 4.2.0 decoy, or the non-FIPS aws-lc-sys of the floor build) leaves the
//! symbol undefined and the binary fails to link (fail closed, never a wrong string). The dependency on aws-lc-rs
//! (feature `cmvp` only, no new crate: it is already in both locks) orders that library after this crate in the
//! link. The string is reported as read; whether it is the certified identity is decided by monban-tls (P-PQ5).
//!
//! Feature `indicator` (PREFLIGHT D-P8.2, P8-spec-002) adds [`with_indicator`]: AWS-LC's FIPS 140-3 service indicator
//! read around one call, for the cmvp tls-subject `indicator` mode only (never monban-bin). It takes one more site,
//! the `extern` block declaring `FIPS_service_indicator_before_call` / `_after_call` (3 sites in this module).

use core::ffi::{CStr, c_char};

// SAFETY: the declaration matches the C prototype `const char *awslc_version_string(void)` (no arguments, returns
// a pointer), the same signature aws-lc-fips-sys 0.13.11's bindgen output gives it. The function reads no caller
// memory and has no preconditions, so declaring it `safe` is sound: every call returns the address of the
// module's static `AWSLC_VERSION_STRING` literal. The 0.13.11 `link_name` prefix makes any other module a link
// error (module docs).
#[allow(unsafe_code)]
unsafe extern "C" {
    #[link_name = "aws_lc_fips_0_13_11_awslc_version_string"]
    safe fn awslc_version_string_raw() -> *const c_char;
}

/// The version string the linked AWS-LC FIPS module reports (e.g. `AWS-LC FIPS 3.1.0`), or `None` if it returned
/// a null pointer or a string that is not UTF-8.
pub fn awslc_version_string() -> Option<&'static str> {
    let p = awslc_version_string_raw();
    if p.is_null() {
        return None;
    }
    // SAFETY: `p` is non-null and points at AWS-LC's `AWSLC_VERSION_STRING`, a NUL-terminated string literal with
    // static storage duration in the linked module: valid for reads up to and including its NUL for the whole
    // program and never written, so a `&'static CStr` over it is sound.
    #[allow(unsafe_code)]
    let c: &'static CStr = unsafe { CStr::from_ptr(p) };
    c.to_str().ok()
}

/// What AWS-LC's FIPS 140-3 service indicator reported for one call (PREFLIGHT D-P8.2; feature `indicator`).
#[cfg(feature = "indicator")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Indicator {
    /// The module's per-thread approved-service counter moved during the call: an approved service ran.
    Approved,
    /// The counter did not move: no approved service ran in approved mode.
    NotApproved,
}

// SAFETY: both declarations match the C prototypes in aws-lc-fips-sys 0.13.11's `openssl/service_indicator.h`
// (`uint64_t FIPS_service_indicator_before_call(void)` / `..._after_call(void)`): no arguments, a `uint64_t` return
// (`u64`). Under AWSLC_FIPS each returns the calling thread's approved-service counter (`service_indicator.c`
// `service_indicator_get_counter`): it reads only module-owned thread-local state, takes no caller memory and has
// no preconditions, so declaring them `safe` is sound. The 0.13.11 `link_name` prefix makes any other module (and
// the non-FIPS aws-lc-sys, whose stubs return 0 / 1 and would report every call Approved) a link error, as for
// `awslc_version_string` above.
#[cfg(feature = "indicator")]
#[allow(unsafe_code)]
unsafe extern "C" {
    #[link_name = "aws_lc_fips_0_13_11_FIPS_service_indicator_before_call"]
    safe fn fips_service_indicator_before_call() -> u64;
    #[link_name = "aws_lc_fips_0_13_11_FIPS_service_indicator_after_call"]
    safe fn fips_service_indicator_after_call() -> u64;
}

/// Runs `f` on this thread between AWS-LC's `FIPS_service_indicator_before_call` and `..._after_call` and returns
/// its result with the indicator verdict (`after != before`: Approved), as AWS-LC documents the pair. The counter is
/// per thread, so `f` must do its crypto on the calling thread (no spawned task). A verdict says that some approved
/// service ran inside `f`, not that every service did: callers wrap one primitive per call.
#[cfg(feature = "indicator")]
pub fn with_indicator<T>(f: impl FnOnce() -> T) -> (T, Indicator) {
    let before = fips_service_indicator_before_call();
    let out = f();
    let after = fips_service_indicator_after_call();
    (out, if after != before { Indicator::Approved } else { Indicator::NotApproved })
}
