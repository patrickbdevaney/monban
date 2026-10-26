//! `aegis-pdp-probe`: the client driver for oracles/pdp-dst. It runs the production client path
//! (`aegis_authz::pdp::PdpClient` + `combine`) over the UDS transport.
//!
//! ```text
//! aegis-pdp-probe --connect PATH --deadline-ms N   < bodies.hex
//! ```
//! Each input line is the hex of one canonical PDP-1 request body (no header). The probe decodes it (rejecting
//! non-canonical input, exit 2), sends it under a fresh request id, and prints `<decision> <combine([decision])>`,
//! e.g. `ERROR DENY`, one line per request, flushed.
#![forbid(unsafe_code)]

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use aegis_authz::combine;
use aegis_authz::pdp::{PdpClient, decode_request_body};
use aegis_pdp::uds::UdsTransport;
use aegis_pdp::{unhex, word};

fn main() -> ExitCode {
    let mut it = std::env::args().skip(1);
    let (mut path, mut deadline) = (None, 300u64);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--connect" => path = it.next().map(PathBuf::from),
            "--deadline-ms" => deadline = it.next().and_then(|s| s.parse().ok()).unwrap_or(0),
            _ => path = None,
        }
    }
    let (Some(path), true) = (path, deadline > 0) else {
        eprintln!("usage: aegis-pdp-probe --connect PATH --deadline-ms N");
        return ExitCode::from(2);
    };
    let mut client = PdpClient::new(UdsTransport::new(path, Duration::from_millis(deadline)));
    let mut out = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { return ExitCode::from(1) };
        if line.trim().is_empty() {
            continue;
        }
        let Some(req) = unhex(&line).and_then(|b| decode_request_body(&b).ok()) else {
            eprintln!("aegis-pdp-probe: input line is not a canonical PDP-1 body");
            return ExitCode::from(2);
        };
        let d = client.decide(&req);
        if writeln!(out, "{} {}", word(d), word(combine(&[d]))).and_then(|()| out.flush()).is_err() {
            return ExitCode::from(1);
        }
    }
    ExitCode::SUCCESS
}
