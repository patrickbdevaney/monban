//! The linked AWS-LC FIPS module's own version string, read at run time (PLAN-6 D2/D16; feature `cmvp` only).
//!
//! Neither aws-lc-rs 1.15.3 nor rustls 0.23.43 has a safe API for it, so the read lives here, in the one crate
//! allowed audited `unsafe` (DEVIATIONS X-14, `cargo xtask unsafe-sites` caps aegis-iso at 20). It takes two sites:
//! the `extern` declaration of `awslc_version_string` and the `CStr::from_ptr` on its result. aegis-bin and
//! tls-subject call [`awslc_version_string`] and pass the value into aegis-tls (`fips_status_with`,
//! `server_config_with`), so aegis-tls (layer 3) never depends on this crate (layer 4).
//!
//! The symbol is the one AWS-LC exports from the FIPS module that aws-lc-rs links under `fips`
//! (aws-lc-fips-sys 0.13.11 = AWS-LC FIPS 3.1.0, `crypto/fipsmodule/service_indicator/service_indicator.c`:
//! `const char *awslc_version_string(void) { return AWSLC_VERSION_STRING; }`). aws-lc-fips-sys prefixes every
//! symbol with its own version, so the `link_name` names 0.13.11 exactly: any other module in the link (a pin
//! change, the uncertified 0.14.x/FIPS 4.2.0 decoy, or the non-FIPS aws-lc-sys of the floor build) leaves the
//! symbol undefined and the binary fails to link (fail closed, never a wrong string). The dependency on aws-lc-rs
//! (feature `cmvp` only, no new crate: it is already in both locks) orders that library after this crate in the
//! link. The string is reported as read; whether it is the certified identity is decided by aegis-tls (P-PQ5).

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
