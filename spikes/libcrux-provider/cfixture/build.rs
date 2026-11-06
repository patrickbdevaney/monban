//! Compiles one C file, so the C-surface count of a build that links this crate must go up by one.
fn main() {
    println!("cargo:rerun-if-changed=src/fixture.c");
    cc::Build::new().file("src/fixture.c").compile("cfixture");
}
