//! Prints the OpenMetrics exposition of a fresh `Registry` (all golden families at zero).
//! `dump --golden` prints the GOLDEN table instead: one `name type label,label` line per family.
//! Used by `cargo xtask metrics-check`.
#![forbid(unsafe_code)]

use monban_metrics::{GOLDEN, Registry};
use std::process::ExitCode;

fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("--golden") {
        for g in GOLDEN {
            println!("{} {} {}", g.name, g.kind.as_str(), g.labels.join(","));
        }
        return ExitCode::SUCCESS;
    }
    match Registry::new().render() {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("render failed: {e:?}");
            ExitCode::FAILURE
        }
    }
}
