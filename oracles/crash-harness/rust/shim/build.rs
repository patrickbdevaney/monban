// Builds the companion preload library libaegis_crash_open.so (variadic open* entry points, see open_shim.c) next to
// libaegis_crash_shim.so in <target>/<profile>/. Uses the cc crate only to locate the C compiler.
use std::path::PathBuf;
fn main() {
    println!("cargo:rerun-if-changed=open_shim.c");
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    // OUT_DIR = <target>/<profile>/build/<pkg>-<hash>/out
    let profile_dir = out.ancestors().nth(3).expect("profile dir").to_path_buf();
    let cc = cc::Build::new().get_compiler();
    let dst = profile_dir.join("libaegis_crash_open.so");
    let st = cc
        .to_command()
        .args(["-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(&dst)
        .arg("open_shim.c")
        .arg("-ldl")
        .status()
        .expect("run C compiler");
    assert!(st.success(), "building libaegis_crash_open.so failed");
}
