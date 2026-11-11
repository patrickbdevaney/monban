//! Mutant: module string present, but --fips-check is not implemented (usage on stderr, exit 2), like today's monban.
fn main() {
    if std::env::args().any(|a| a == "--never-given-keep") {
        println!("{}", String::from_utf8_lossy(std::hint::black_box(b"AWS-LC FIPS 3.1.0")));
    }
    eprintln!("usage: monban --config <file>");
    std::process::exit(2);
}
