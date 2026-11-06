//! aegis-otlp: out-of-process OTLP/HTTP JSON exporter (PREFLIGHT D-P7.6).
//!
//! P7-spec-002 stub: refuses to start (exit 2) with a clear message, so no deployment can mistake it for a working
//! exporter. P7-otlp-001 lands the scraper, the log reader and the OTLP JSON encoder.
#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let _ = writeln!(std::io::stderr(), "aegis-otlp: exporter not built (P7-otlp-001); refusing to start");
    ExitCode::from(2)
}
