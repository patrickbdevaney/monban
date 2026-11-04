# P6-cmvp-001: INFEASIBLE clause (PLAN-6 D2, runtime module string)

## Spec clause

PLAN-6 D2: `fips_status()` reads the linked module's version string at runtime ("`awslc_version_string` through
aws-lc-rs on cmvp") and reports `module = Some("AWS-LC FIPS 3.1.0")` only on the cmvp build with `fips()` true.
`aegis --fips-check` prints that string. tls-subject `describe` reports it for the clienthello-cmvp module halves.

## Failing case

There is no safe way to read the string with the crates and permissions this unit has:

- aws-lc-rs 1.15.3 has no public version API. `src/lib.rs` exports `init`, `fips_mode`, `try_fips_mode` and the
  jitter-entropy pair. Its `fips` module is private and wraps only the service indicator.
- rustls 0.23.43 exposes `fips()` booleans only.
- The only access is `aws_lc_fips_sys::awslc_version_string()`, generated as
  `#[link_name = "aws_lc_fips_0_13_11_awslc_version_string"] pub fn awslc_version_string() -> *const c_char`.
  - Calling it needs `unsafe`. Turning the pointer into `&str` needs `unsafe CStr::from_ptr`.
  - `#![forbid(unsafe_code)]` applies in aegis-tls, aegis-bin and tls-subject (CLAUDE.md).
  - The coordinator's instruction for this case was: "if the only way is an extern "C" call, report it instead".
- aegis-iso, the only crate allowed `unsafe`, is outside this unit's write_scope. It is layer 4, so aegis-tls (layer
  3) cannot call it either.

## What was done instead (fail closed)

- `aegis_tls::profile::linked_module()` is the single seam for the module string. It returns `None` on both builds.
- **FipsStatus.** On cmvp, `FipsStatus.module` is `Some` only when `config_fips` is true and the seam returns a
  string. `cmvp_claim` additionally needs `module_fips_mode` and an exact `AWS-LC FIPS 3.1.0`, compared without
  embedding that literal, so the fips-binary strings check only ever sees the module's own copy.
- **Effects today:**
  - FIPS-CMVP is refused at boot on cmvp with `ProfileError::Assertion("FIPS-CMVP: P-PQ5 module identity not
    established ...")`.
  - `aegis --fips-check` prints `module=none` and exits 1.
  - tls-subject prints `module=`, so `--require-cmvp` fails the FIPS-F1..F6 module halves. This is the oracle's
    `reports-fips-module-none` case.

## Minimal resolution (needs an integrator or spec-author decision)

Wire one of the following into the seam (`linked_module`, plus a way for aegis-tls to receive the value):

**A. Two audited sites in aegis-iso, behind a new `cmvp` feature, with no new Cargo dependency.** aegis-iso is at
14/20 sites. The symbol resolves at link time through the aws-lc-fips-sys that aws-lc-rs already links. Because
`link_name` hard-codes the 0.13.11 symbol prefix, a pin change becomes a link error, which fails closed.

```rust
#[cfg(feature = "cmvp")]
pub fn awslc_version_string() -> Option<&'static str> {
    unsafe extern "C" {
        #[link_name = "aws_lc_fips_0_13_11_awslc_version_string"]
        fn awslc_version_string() -> *const core::ffi::c_char;
    }
    // SAFETY: AWS-LC returns AWSLC_VERSION_STRING, a static NUL-terminated literal (service_indicator.c:10).
    let p = unsafe { awslc_version_string() };
    // SAFETY: non-null p points at that static literal.
    (!p.is_null()).then(|| unsafe { core::ffi::CStr::from_ptr(p) }).and_then(|c| c.to_str().ok())
}
```

Then `aegis_tls::fips_status_with(cfg, linked)`, or a `set_linked_module` hook, takes the value from aegis-bin and
tls-subject. Both need `aegis-iso` under their `cmvp` feature, which is a manifest change. tls-subject would gain a
dependency edge on aegis-iso.

**B. The same two sites, but through an optional `aws-lc-fips-sys` dependency** (already in the cmvp lock, so no new
crate). This uses `aws_lc_fips_sys::awslc_version_string` instead of a hand-written `link_name`.

**C. A spec change to D2:** for example, a compile-time module identity backed only by the fips-lock G2b pin and the
binary strings check. This weakens the runtime read and needs the spec author.

Until one of these lands, the unit's acceptance cannot pass:
- the `--fips-check` module string;
- `--require-cmvp` FIPS-F1..F6;
- the `module` field in /healthz and audit.

Everything else in the unit is implemented; see P6-cmvp-001.md.
