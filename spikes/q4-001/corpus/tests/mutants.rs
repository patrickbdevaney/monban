//! trybuild corpus. `mutants/expected.txt` lists `fail <case>` / `pass <case>` (the recorded measurement).
//! Measurement mode (Q4_MEASURE=1): every case is declared compile_fail so trybuild reports which ones compile.

#[test]
fn mutants() {
    let t = trybuild::TestCases::new();
    let measure = std::env::var("Q4_MEASURE").is_ok();
    let manifest = include_str!("../mutants/expected.txt");
    for line in manifest.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let mut it = line.split_whitespace();
        let (Some(kind), Some(case)) = (it.next(), it.next()) else { continue };
        let path = format!("mutants/{case}.rs");
        if measure || kind == "fail" {
            t.compile_fail(path);
        } else {
            t.pass(path);
        }
    }
}
