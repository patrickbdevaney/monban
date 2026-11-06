//! The same interop server on rustls' aws-lc-rs provider: the comparison build for the C-surface count.
#![forbid(unsafe_code)]

#[path = "../../provider/src/serve.rs"]
mod serve;

fn main() -> std::process::ExitCode {
    serve::main_with(rustls::crypto::aws_lc_rs::default_provider())
}
