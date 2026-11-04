// Shared driver for the fips-binary fixture stubs (include!d by src/bin/fips_*.rs; no dependencies). `line` is the
// exact --fips-check stdout. `keep` are byte strings that must survive in the binary: they stay reachable through
// black_box and are printed only for an argument the oracle never passes.
fn fips_main(line: &str, keep: &[&'static [u8]]) {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--never-given-keep") {
        for k in keep {
            println!("{}", String::from_utf8_lossy(std::hint::black_box(k)));
        }
    }
    if args.iter().any(|a| a == "--fips-check") {
        println!("{line}");
        return;
    }
    eprintln!("usage: stub [--fips-check]");
    std::process::exit(2);
}
