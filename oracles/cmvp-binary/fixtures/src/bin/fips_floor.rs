//! Negative control (floor shape): no FIPS module string; --fips-check reports module=none.
include!("../fipsstub.rs");
fn main() {
    fips_main("FIPS-CHECK: module=none fips_mode=false config_fips=false", &[]);
}
