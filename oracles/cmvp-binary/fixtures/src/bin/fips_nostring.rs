//! Mutant: the right --fips-check line, assembled at runtime from pieces; no contiguous module string in the binary.
include!("../fipsstub.rs");
fn main() {
    let (a, b, c) = std::hint::black_box((3u8, 1u8, 0u8));
    let name = std::hint::black_box("AWS-LC FIPS");
    fips_main(&format!("FIPS-CHECK: module=\"{name} {a}.{b}.{c}\" fips_mode=true config_fips=true"), &[]);
}
