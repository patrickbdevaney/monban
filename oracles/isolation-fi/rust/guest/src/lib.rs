// isolation-fi guest: the M0 handler used by the oracle and spike q4-006.
// Exports `handle(id, fault) -> u32`; imports `env.host_fault(code)` (a host function the reference host turns into
// a host-process abort, standing in for a guest-triggerable runtime/host bug).
// Healthy answer = work(id, GOOD_SALT, DATA); the driver recomputes it and counts any mismatch as a wrong answer.
#[path = "../../work.rs"]
mod work;
use work::*;

static DATA: &[u8] = include_bytes!("../../data.bin");
static mut SALT: u32 = GOOD_SALT;

#[link(wasm_import_module = "env")]
extern "C" {
    fn host_fault(code: u32);
}

#[no_mangle]
pub extern "C" fn handle(id: u32, fault: u32) -> u32 {
    match fault {
        F_PANIC => panic!("injected"),
        F_ABORT => core::arch::wasm32::unreachable(),
        F_SEGV => unsafe {
            core::ptr::write_volatile(0xFFFF_FFF0usize as *mut u64, 1);
            0
        },
        F_LOOP => {
            // runaway handler doing real work (so fuel/ms matches the healthy path's fuel rate)
            let mut x = id;
            loop {
                x = core::hint::black_box(work(x, GOOD_SALT, DATA));
            }
        }
        F_OOM => {
            let mut v: Vec<Vec<u8>> = Vec::new();
            loop {
                v.push(vec![1u8; 1 << 20]);
            }
        }
        F_POISON => unsafe {
            SALT = BAD_SALT; // poisons every later request served by this instance
            work(id, GOOD_SALT, DATA)
        },
        F_HOSTABORT => unsafe {
            host_fault(1);
            work(id, GOOD_SALT, DATA)
        },
        F_HOSTPOISON => unsafe {
            host_fault(2);
            work(id, GOOD_SALT, DATA)
        },
        _ => {
            let s = unsafe { SALT };
            work(id, s, DATA)
        }
    }
}
