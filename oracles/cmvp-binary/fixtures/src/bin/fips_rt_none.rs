//! Mutant: the module string is in the binary, but the linked module at runtime is none (floor build).
include!("../fipsstub.rs");
fn main() {
    fips_main("FIPS-CHECK: module=none fips_mode=false config_fips=false", &[b"AWS-LC FIPS 3.1.0"]);
}
