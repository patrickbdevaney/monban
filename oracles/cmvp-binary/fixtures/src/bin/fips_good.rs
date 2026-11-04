//! Positive stand-in for the cmvp aegis: the module string is a contiguous literal; --fips-check per the contract.
include!("../fipsstub.rs");
static MODULE: &[u8] = b"AWS-LC FIPS 3.1.0";
fn main() {
    let m = String::from_utf8_lossy(std::hint::black_box(MODULE)).into_owned();
    fips_main(&format!("FIPS-CHECK: module=\"{m}\" fips_mode=true config_fips=true"), &[]);
}
