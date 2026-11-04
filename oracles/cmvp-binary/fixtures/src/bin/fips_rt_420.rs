//! Mutant: the module string is in the binary, but the runtime reports the non-FIPS module AWS-LC 4.2.0.
include!("../fipsstub.rs");
fn main() {
    fips_main("FIPS-CHECK: module=\"AWS-LC 4.2.0\" fips_mode=false config_fips=false", &[b"AWS-LC FIPS 3.1.0"]);
}
