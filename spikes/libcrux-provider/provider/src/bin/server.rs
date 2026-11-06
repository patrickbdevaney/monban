//! Interop server on the libcrux provider (see src/serve.rs for the CLI).
#![forbid(unsafe_code)]

#[path = "../serve.rs"]
mod serve;

fn main() -> std::process::ExitCode {
    serve::main_with(lcx::provider())
}
