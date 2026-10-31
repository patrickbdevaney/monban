//! p2-e2e guests (F14 core-module ABI). One build exports several candidate handlers `h_<kind>`; the oracle
//! rewrites the export section of a copy per kind to exactly `memory` + `handle` (p2wire.select_handle), so each
//! module the subject sees has the F14 export set. Imports: `aegis.req_head/resp_head/resp_write` only; the `fault`
//! build additionally imports the test-only `env.host_fault` and exports only `h_abort`.
//!
//! Kinds:
//!   echo_a / echo_b  200, no headers, body = marker byte ('A' / 'B') || the F14 req-head encoding the host gave
//!   trap             `unreachable` (a crash-attributable fault, D7)
//!   deny             handle() = 1 (Deny: a healthy failure, never counted against the crash budget)
//!   spin             runaway loop (ends by fuel or the wall bound; keeps a fork child alive long enough to observe)
//!   abort            env.host_fault(1): the worker process aborts (fault build; test-hooks workers only)
#![no_std]

#[panic_handler]
fn on_panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

#[cfg(not(feature = "fault"))]
mod handlers {
    #[link(wasm_import_module = "aegis")]
    extern "C" {
        fn req_head(dst: i32, cap: i32) -> i32;
        fn resp_head(status: i32, src: i32, len: i32) -> i32;
        fn resp_write(src: i32, len: i32) -> i32;
    }

    const CAP: usize = 16384;
    static mut BUF: [u8; CAP] = [0; CAP];
    static NO_HEADERS: [u8; 1] = [0]; // resp-headers = [] (postcard: sequence length 0)
    static MARK_A: [u8; 1] = *b"A";
    static MARK_B: [u8; 1] = *b"B";

    fn echo(marker: &'static [u8; 1]) -> i32 {
        // SAFETY (guest-local): single-threaded instance; BUF is only touched here.
        unsafe {
            let len = req_head(0, 0);
            if len < 0 || len as usize > CAP {
                return 2; // Error
            }
            let p = core::ptr::addr_of_mut!(BUF) as *mut u8 as i32;
            if req_head(p, len) != len {
                return 2;
            }
            resp_head(200, NO_HEADERS.as_ptr() as i32, 1);
            resp_write(marker.as_ptr() as i32, 1);
            resp_write(p, len);
        }
        0
    }

    #[no_mangle]
    pub extern "C" fn h_echo_a() -> i32 {
        echo(&MARK_A)
    }

    #[no_mangle]
    pub extern "C" fn h_echo_b() -> i32 {
        echo(&MARK_B)
    }

    #[no_mangle]
    pub extern "C" fn h_trap() -> i32 {
        core::arch::wasm32::unreachable()
    }

    #[no_mangle]
    pub extern "C" fn h_deny() -> i32 {
        1
    }

    #[no_mangle]
    pub extern "C" fn h_spin() -> i32 {
        let mut x: u32 = 1;
        loop {
            x = core::hint::black_box(x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223));
        }
    }
}

#[cfg(feature = "fault")]
mod handlers {
    #[link(wasm_import_module = "env")]
    extern "C" {
        fn host_fault(code: i32);
    }

    #[no_mangle]
    pub extern "C" fn h_abort() -> i32 {
        // SAFETY (guest-local): an import call; code 1 = abort the worker process (F14 test-only import).
        unsafe { host_fault(1) };
        0
    }
}
