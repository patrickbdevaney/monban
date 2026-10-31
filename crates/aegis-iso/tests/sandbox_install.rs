//! Fail-closed preconditions of `sandbox::install` that can be checked without restricting the test process:
//! both refusals below happen before the first irreversible step.

use aegis_iso::sandbox::{Profile, SandboxError, install};

#[test]
fn refuses_a_multithreaded_process() {
    // The libtest harness runs tests on worker threads, so this process has more than one thread.
    let t = std::thread::spawn(|| std::thread::sleep(std::time::Duration::from_millis(500)));
    let r = install(&Profile::cordon(vec![std::env::temp_dir()]));
    assert!(matches!(r, Err(SandboxError::NotSingleThreaded(_))), "{r:?}");
    let r = install(&Profile::zygote(vec![std::env::temp_dir()]));
    assert!(matches!(r, Err(SandboxError::NotSingleThreaded(_))), "{r:?}");
    let _ = t.join();
}

#[test]
fn child_profile_refuses_without_an_inherited_sandbox() {
    // A child install stacks on the zygote's sandbox; without NO_NEW_PRIVS and dumpable=0 it must refuse.
    let r = install(&Profile::child());
    assert!(matches!(r, Err(SandboxError::NoNewPrivs(None) | SandboxError::Dumpable(None))), "{r:?}");
}
