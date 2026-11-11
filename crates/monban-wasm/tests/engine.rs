//! monban-wasm engine, store and cwasm regressions (unit P5-wasm-001): fresh Store per request (poison guest), fuel
//! exhaustion, epoch deadline within wall_ms, limiter at memory_mib, digest check before deserialize, F14 shape
//! check at compile, MPK settings. Guests are hand-encoded Wasm binaries (the engine has no text parser).
//!
//! `AEGIS_WASM_CONFIG_OUT=<dir>` makes `config_json_*` write config.json / config-mpk.json for
//! `ci/wasmtime-config.py check --config-json ... --config-json-mpk ...`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use monban_wasm::engine::cwasm::{self, CwasmError};
use monban_wasm::{
    ConfigError, Decision, EngineSettings, EpochTicker, Mpk, Outcome, P2Engine, P2Limits, RequestLimits, TrapKind,
    Worker,
};

type R<T = ()> = Result<T, String>;

fn e<E: std::fmt::Display>(x: E) -> String {
    x.to_string()
}

// ------------------------------------------------------------------------------------------------ wasm encoder

fn uleb(mut n: u64, out: &mut Vec<u8>) {
    loop {
        let b = u8::try_from(n & 0x7f).unwrap_or(0);
        n >>= 7;
        if n == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn sleb(mut n: i64, out: &mut Vec<u8>) {
    loop {
        let b = u8::try_from(n & 0x7f).unwrap_or(0);
        n >>= 7;
        let done = (n == 0 && b & 0x40 == 0) || (n == -1 && b & 0x40 != 0);
        out.push(if done { b } else { b | 0x80 });
        if done {
            return;
        }
    }
}

fn len_prefixed(body: &[u8], out: &mut Vec<u8>) {
    uleb(body.len() as u64, out);
    out.extend_from_slice(body);
}

fn name(s: &str, out: &mut Vec<u8>) {
    len_prefixed(s.as_bytes(), out);
}

fn section(id: u8, count: usize, items: &[u8], out: &mut Vec<u8>) {
    let mut body = Vec::new();
    uleb(count as u64, &mut body);
    body.extend_from_slice(items);
    out.push(id);
    len_prefixed(&body, out);
}

/// i32.const k
fn i32c(k: i64) -> Vec<u8> {
    let mut v = vec![0x41];
    sleb(k, &mut v);
    v
}

struct Guest {
    /// Imported functions: (module, name, i32 params, i32 results).
    imports: Vec<(&'static str, &'static str, usize, usize)>,
    /// Initial memory pages.
    mem_min: u32,
    /// One mutable i32 global (index 0), initially 0.
    global: bool,
    /// Extra export of the handle function under another name.
    extra_export: Option<&'static str>,
    /// Body of `handle() -> i32` without the final `end`.
    body: Vec<u8>,
}

impl Guest {
    fn new(body: Vec<u8>) -> Self {
        Self { imports: vec![], mem_min: 1, global: false, extra_export: None, body }
    }

    fn encode(&self) -> Vec<u8> {
        let mut m = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        // types: 0 = handle () -> i32, then one per import
        let mut types = vec![0x60, 0x00, 0x01, 0x7f];
        for (_, _, p, r) in &self.imports {
            types.push(0x60);
            uleb(*p as u64, &mut types);
            types.extend(std::iter::repeat_n(0x7f, *p));
            uleb(*r as u64, &mut types);
            types.extend(std::iter::repeat_n(0x7f, *r));
        }
        section(1, 1 + self.imports.len(), &types, &mut m);
        if !self.imports.is_empty() {
            let mut imps = Vec::new();
            for (i, (module, nm, _, _)) in self.imports.iter().enumerate() {
                name(module, &mut imps);
                name(nm, &mut imps);
                imps.push(0x00);
                uleb(i as u64 + 1, &mut imps);
            }
            section(2, self.imports.len(), &imps, &mut m);
        }
        section(3, 1, &[0x00], &mut m);
        let mut mem = vec![0x00];
        uleb(u64::from(self.mem_min), &mut mem);
        section(5, 1, &mem, &mut m);
        if self.global {
            section(6, 1, &[0x7f, 0x01, 0x41, 0x00, 0x0b], &mut m);
        }
        let handle_idx = self.imports.len() as u64;
        let mut exps = Vec::new();
        name("memory", &mut exps);
        exps.extend_from_slice(&[0x02, 0x00]);
        name("handle", &mut exps);
        exps.push(0x00);
        uleb(handle_idx, &mut exps);
        let mut n_exp = 2;
        if let Some(x) = self.extra_export {
            name(x, &mut exps);
            exps.push(0x00);
            uleb(handle_idx, &mut exps);
            n_exp += 1;
        }
        section(7, n_exp, &exps, &mut m);
        let mut func = vec![0x00]; // no locals
        func.extend_from_slice(&self.body);
        func.push(0x0b);
        let mut code = Vec::new();
        len_prefixed(&func, &mut code);
        section(10, 1, &code, &mut m);
        m
    }
}

/// Poison guest: if global 0 or memory[0] is set, return 1 (the poisoned, wrong answer); otherwise set both and
/// return 0 (correct). With a fresh instance per request every request answers 0.
fn poison_guest() -> Guest {
    let mut b = vec![0x23, 0x00]; // global.get 0
    b.extend(i32c(0));
    b.extend([0x28, 0x02, 0x00]); // i32.load
    b.push(0x72); // i32.or
    b.extend([0x04, 0x7f]); // if (result i32)
    b.extend(i32c(1));
    b.push(0x05); // else
    b.extend(i32c(0));
    b.extend(i32c(1));
    b.extend([0x36, 0x02, 0x00]); // i32.store
    b.extend(i32c(1));
    b.extend([0x24, 0x00]); // global.set 0
    b.extend(i32c(0));
    b.push(0x0b); // end if
    let mut g = Guest::new(b);
    g.global = true;
    g
}

/// Like the poison guest, but the poisoning request traps (unreachable) after setting the state.
fn poison_trap_guest() -> Guest {
    let mut b = vec![0x23, 0x00];
    b.extend(i32c(0));
    b.extend([0x28, 0x02, 0x00]);
    b.push(0x72);
    b.extend([0x04, 0x40]); // if (no result)
    b.extend(i32c(1));
    b.push(0x0f); // return 1
    b.push(0x0b);
    b.extend(i32c(0));
    b.extend(i32c(1));
    b.extend([0x36, 0x02, 0x00]);
    b.extend(i32c(1));
    b.extend([0x24, 0x00]);
    b.push(0x00); // unreachable
    let mut g = Guest::new(b);
    g.global = true;
    g
}

fn loop_guest() -> Guest {
    let mut b = vec![0x03, 0x40, 0x0c, 0x00, 0x0b]; // loop br 0 end
    b.extend(i32c(0));
    Guest::new(b)
}

fn grow_guest(pages: i64) -> Guest {
    let mut b = i32c(pages);
    b.extend([0x40, 0x00]); // memory.grow 0
    Guest::new(b)
}

fn const_guest(k: i64) -> Guest {
    Guest::new(i32c(k))
}

// ------------------------------------------------------------------------------------------------ helpers

fn engine() -> R<P2Engine> {
    P2Engine::new(EngineSettings::defaults(false)).map_err(e)
}

fn worker(eng: &P2Engine, g: &Guest) -> R<Worker> {
    let m = wasmtime::Module::new(eng.wasmtime(), g.encode()).map_err(|x| format!("{x:#}"))?;
    Worker::new(eng, &m).map_err(e)
}

fn limits(fuel: u64, wall_ms: u64, memory_mib: u32) -> R<RequestLimits> {
    Ok(RequestLimits::from(P2Limits::new(fuel, wall_ms, memory_mib).map_err(e)?))
}

fn tmp_path(tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    std::env::temp_dir().join(format!("monban-wasm-{}-{}-{tag}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)))
}

fn loadavg() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .unwrap_or_default()
        .split_whitespace()
        .take(3)
        .collect::<Vec<_>>()
        .join(" ")
}

fn host_has_pku() -> bool {
    std::fs::read_to_string("/proc/cpuinfo")
        .is_ok_and(|c| c.lines().any(|l| l.starts_with("flags") && l.split_whitespace().any(|f| f == "pku")))
}

// ------------------------------------------------------------------------------------------------ settings / config

#[test]
fn config_json_is_the_engine_settings() -> R {
    let eng = engine()?;
    let j = eng.settings().to_json();
    for kv in [
        "\"allocation_strategy\":\"pooling\"",
        "\"memory_reservation\":4294967296",
        "\"memory_guard_size\":33554432",
        "\"guard_before_linear_memory\":true",
        "\"signals_based_traps\":true",
        "\"pooling_total_core_instances\":64",
        "\"pooling_total_memories\":64",
        "\"pooling_total_tables\":64",
        "\"pooling_max_memory_size\":16777216",
        "\"memory_protection_keys\":\"no\"",
        "\"wasm_memory64\":false",
        "\"wasm_gc\":false",
        "\"wasm_threads\":false",
        "\"wasm_component_model\":false",
        "\"epoch_interruption\":true",
        "\"consume_fuel\":true",
    ] {
        if !j.contains(kv) {
            return Err(format!("config json lacks {kv}: {j}"));
        }
    }
    if j.matches(':').count() != 16 {
        return Err(format!("config json must have exactly 16 keys: {j}"));
    }
    let mpk = EngineSettings::defaults(true);
    if mpk.mpk() != Mpk::Yes
        || mpk.to_json() != j.replace("\"memory_protection_keys\":\"no\"", "\"memory_protection_keys\":\"yes\"")
    {
        return Err(format!("--mpk must change only memory_protection_keys: {}", mpk.to_json()));
    }
    if let Some(dir) = std::env::var_os("AEGIS_WASM_CONFIG_OUT") {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).map_err(e)?;
        std::fs::write(dir.join("config.json"), format!("{j}\n")).map_err(e)?;
        std::fs::write(dir.join("config-mpk.json"), format!("{}\n", mpk.to_json())).map_err(e)?;
    }
    Ok(())
}

#[test]
fn f8_bounds_refused_not_clamped() -> R {
    for (r, want) in [
        (P2Limits::new(9_999, 100, 16), ConfigError::Fuel(9_999)),
        (P2Limits::new(1_000_000_001, 100, 16), ConfigError::Fuel(1_000_000_001)),
        (P2Limits::new(15_000_000, 0, 16), ConfigError::WallMs(0)),
        (P2Limits::new(15_000_000, 1_001, 16), ConfigError::WallMs(1_001)),
        (P2Limits::new(15_000_000, 100, 0), ConfigError::MemoryMib(0)),
        (P2Limits::new(15_000_000, 100, 257), ConfigError::MemoryMib(257)),
    ] {
        if r != Err(want) {
            return Err(format!("{r:?} != Err({want:?})"));
        }
    }
    if EngineSettings::from_p2(16, 0, false) != Err(ConfigError::PoolSlots(0)) {
        return Err("pool_slots 0 accepted".into());
    }
    if EngineSettings::from_p2(16, 64, false) != Ok(EngineSettings::defaults(false)) {
        return Err("from_p2(16, 64) != defaults".into());
    }
    let d = P2Limits::DEFAULT;
    if (d.fuel(), d.wall_ms(), d.memory_mib()) != (15_000_000, 100, 16) {
        return Err(format!("F8 defaults wrong: {d:?}"));
    }
    // The worker never raises a limit above its boot ceiling.
    let c = RequestLimits::clamped(&P2Limits::new(1_000_000_000, 1_000, 256).map_err(e)?, &d);
    if (c.fuel(), c.wall_ms(), c.memory_bytes()) != (15_000_000, 100, 16 << 20) {
        return Err(format!("clamp raised a limit: {c:?}"));
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ fresh store

#[test]
fn fresh_store_per_request_poison_guest_answers_correctly_next_time() -> R {
    let eng = engine()?;
    let g = poison_guest();
    // Negative control: in one reused instance the guest really does poison (second answer is the wrong one).
    {
        let m = wasmtime::Module::new(eng.wasmtime(), g.encode()).map_err(|x| format!("{x:#}"))?;
        let mut st = wasmtime::Store::new(eng.wasmtime(), ());
        st.set_fuel(1_000_000).map_err(|x| format!("{x:#}"))?;
        st.set_epoch_deadline(u64::MAX / 2);
        let i = wasmtime::Instance::new(&mut st, &m, &[]).map_err(|x| format!("{x:#}"))?;
        let f = i.get_typed_func::<(), i32>(&mut st, "handle").map_err(|x| format!("{x:#}"))?;
        let a = f.call(&mut st, ()).map_err(|x| format!("{x:#}"))?;
        let b = f.call(&mut st, ()).map_err(|x| format!("{x:#}"))?;
        if (a, b) != (0, 1) {
            return Err(format!("control: reused instance answered ({a}, {b}), want (0, 1)"));
        }
    }
    let w = worker(&eng, &g)?;
    let l = RequestLimits::from(P2Limits::DEFAULT);
    for n in 0..200 {
        let r = w.handle(l);
        if r.outcome != Outcome::Returned(0) || r.outcome.decision() != Decision::Allow {
            return Err(format!("request {n}: {r:?} (poison survived into a later request)"));
        }
        if r.fuel_used == 0 {
            return Err(format!("request {n}: no fuel accounted"));
        }
    }
    // Poison then trap: request n traps after poisoning; request n+1 must not see the poison (it traps the same
    // way, never answering the poisoned 1).
    let w = worker(&eng, &poison_trap_guest())?;
    for n in 0..50 {
        let r = w.handle(l);
        if r.outcome != Outcome::Trapped(TrapKind::Wasm) {
            return Err(format!("poison-trap request {n}: {r:?}"));
        }
    }
    // The pool is not exhausted by 250 requests on 64 slots: every Store returned its slot.
    Ok(())
}

#[test]
fn handle_status_mapping() -> R {
    let eng = engine()?;
    let l = RequestLimits::from(P2Limits::DEFAULT);
    for (k, want) in [(0, Decision::Allow), (1, Decision::Deny), (2, Decision::Error), (-1, Decision::Error)] {
        let r = worker(&eng, &const_guest(k))?.handle(l);
        if r.outcome.decision() != want {
            return Err(format!("handle() = {k}: {r:?}, want {want:?}"));
        }
    }
    if Outcome::Trapped(TrapKind::Fuel).decision() != Decision::Error {
        return Err("trap must be Error".into());
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ fuel / epoch

#[test]
fn fuel_exhaustion_traps() -> R {
    let eng = engine()?;
    let w = worker(&eng, &loop_guest())?;
    // No ticker: the epoch never advances, so only fuel can stop the loop.
    let t = Instant::now();
    let r = w.handle(limits(15_000_000, 1_000, 16)?);
    let el = t.elapsed();
    eprintln!("fuel_exhaustion_traps: 15M fuel loop trapped after {el:?} (loadavg {})", loadavg());
    if r.outcome != Outcome::Trapped(TrapKind::Fuel) {
        return Err(format!("loop under 15M fuel: {r:?}, want Trapped(Fuel)"));
    }
    if r.fuel_used < 15_000_000 - 1_000 {
        return Err(format!("fuel_used {} < budget", r.fuel_used));
    }
    Ok(())
}

#[test]
fn epoch_deadline_traps_a_loop_within_wall_ms() -> R {
    let eng = engine()?;
    let _ticker = EpochTicker::start(&eng).map_err(e)?;
    let w = worker(&eng, &loop_guest())?;
    for wall_ms in [20u64, 50, 100] {
        // Fuel at the F8 maximum (about 130 ms of looping on the laptop) so the epoch, not fuel, ends the loop.
        let t = Instant::now();
        let r = w.handle(limits(1_000_000_000, wall_ms, 16)?);
        let el = t.elapsed();
        eprintln!("epoch: wall_ms {wall_ms} -> {:?} after {el:?} (loadavg {})", r.outcome, loadavg());
        if r.outcome != Outcome::Trapped(TrapKind::Wall) {
            return Err(format!("wall_ms {wall_ms}: {r:?}, want Trapped(Wall)"));
        }
        if el > Duration::from_millis(wall_ms) {
            return Err(format!("wall_ms {wall_ms}: trapped after {el:?} (loadavg {})", loadavg()));
        }
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ limiter

#[test]
fn limiter_denies_growth_past_memory_mib() -> R {
    let eng = engine()?;
    let l16 = limits(15_000_000, 100, 16)?;
    let l4 = limits(15_000_000, 100, 4)?;
    // 1 initial page; 16 MiB = 256 pages, 4 MiB = 64 pages. memory.grow returns the old size (1) or -1.
    for (pages, lim, want, what) in [
        (255, l16, 1u32, "grow to exactly 16 MiB"),
        (256, l16, u32::MAX, "grow past 16 MiB"),
        (63, l4, 1, "grow to exactly 4 MiB"),
        (64, l4, u32::MAX, "grow past 4 MiB (below the 16 MiB pool slot: the limiter, not the pool, refuses)"),
    ] {
        let r = worker(&eng, &grow_guest(pages))?.handle(lim);
        if r.outcome != Outcome::Returned(want) {
            return Err(format!("{what}: {r:?}, want Returned({want:#x})"));
        }
    }
    // An initial memory above memory_mib fails instantiation as a memory limit.
    let mut g = const_guest(0);
    g.mem_min = 100; // 6.25 MiB
    let r = worker(&eng, &g)?.handle(l4);
    if r.outcome != Outcome::Trapped(TrapKind::Memory) {
        return Err(format!("initial 100 pages under 4 MiB: {r:?}, want Trapped(Memory)"));
    }
    if worker(&eng, &g)?.handle(l16).outcome != Outcome::Returned(0) {
        return Err("initial 100 pages under 16 MiB must instantiate".into());
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ cwasm

#[test]
fn cwasm_wrong_digest_refused_before_deserialize() -> R {
    let eng = engine()?;
    let bytes = cwasm::compile(&eng, &poison_guest().encode()).map_err(e)?;
    let d = cwasm::sha256(&bytes);
    let p = tmp_path("ok.cwasm");
    std::fs::write(&p, &bytes).map_err(e)?;
    let res = (|| -> R {
        // Correct digest: loads and serves.
        let m = cwasm::load(&eng, &p, &d).map_err(e)?;
        let r = Worker::new(&eng, &m).map_err(e)?.handle(RequestLimits::from(P2Limits::DEFAULT));
        if r.outcome != Outcome::Returned(0) {
            return Err(format!("loaded module: {r:?}"));
        }
        // Wrong digest: refused.
        let mut bad = d;
        bad[0] ^= 1;
        match cwasm::load(&eng, &p, &bad) {
            Err(CwasmError::DigestMismatch) => {}
            other => return Err(format!("wrong digest: {:?}", other.map(|_| "module"))),
        }
        // Tampered file, original digest: refused.
        let mut t = bytes.clone();
        if let Some(b) = t.last_mut() {
            *b ^= 0xff;
        }
        std::fs::write(&p, &t).map_err(e)?;
        match cwasm::load(&eng, &p, &d) {
            Err(CwasmError::DigestMismatch) => {}
            other => return Err(format!("tampered file: {:?}", other.map(|_| "module"))),
        }
        // Not a cwasm at all, wrong digest: the digest check fires first (deserialize would say something else).
        std::fs::write(&p, b"not a cwasm").map_err(e)?;
        match cwasm::load(&eng, &p, &d) {
            Err(CwasmError::DigestMismatch) => {}
            other => return Err(format!("garbage file: {:?}", other.map(|_| "module"))),
        }
        // Matching digest over bytes that are not a precompiled module: refused before deserialize as well.
        let gd = cwasm::sha256(b"not a cwasm");
        match cwasm::load(&eng, &p, &gd) {
            Err(CwasmError::NotPrecompiledModule) => {}
            other => return Err(format!("garbage with its digest: {:?}", other.map(|_| "module"))),
        }
        // A plain .wasm with its own digest is not a precompiled module either.
        let wasm = poison_guest().encode();
        std::fs::write(&p, &wasm).map_err(e)?;
        match cwasm::load(&eng, &p, &cwasm::sha256(&wasm)) {
            Err(CwasmError::NotPrecompiledModule) => Ok(()),
            other => Err(format!("plain wasm: {:?}", other.map(|_| "module"))),
        }
    })();
    let _ = std::fs::remove_file(&p);
    res
}

#[test]
fn compile_checks_the_f14_shape() -> R {
    let eng = engine()?;
    let mut g = const_guest(0);
    g.imports = vec![("env", "foo", 0, 0)];
    match cwasm::compile(&eng, &g.encode()) {
        Err(CwasmError::Abi(_)) => {}
        other => return Err(format!("non-allowlisted import: {:?}", other.map(|b| b.len()))),
    }
    g.imports = vec![("monban", "req_head", 1, 1)];
    match cwasm::compile(&eng, &g.encode()) {
        Err(CwasmError::Abi(_)) => {}
        other => return Err(format!("wrongly typed import: {:?}", other.map(|b| b.len()))),
    }
    let mut x = const_guest(0);
    x.extra_export = Some("other");
    match cwasm::compile(&eng, &x.encode()) {
        Err(CwasmError::Abi(_)) => {}
        other => return Err(format!("extra export: {:?}", other.map(|b| b.len()))),
    }
    // Allowlisted import with the right type compiles, but the stub linker defines no host function: the worker
    // refuses to link it (fail closed until P5-wasm-002).
    g.imports = vec![("monban", "req_head", 2, 1)];
    let bytes = cwasm::compile(&eng, &g.encode()).map_err(e)?;
    let p = tmp_path("imp.cwasm");
    std::fs::write(&p, &bytes).map_err(e)?;
    let m = cwasm::load(&eng, &p, &cwasm::sha256(&bytes));
    let _ = std::fs::remove_file(&p);
    let m = m.map_err(e)?;
    if Worker::new(&eng, &m).is_ok() {
        return Err("stub linker resolved an F14 import".into());
    }
    match cwasm::compile(&eng, b"\0asm\x01\0\0\0garbage") {
        Err(CwasmError::Wasmtime(_)) => Ok(()),
        other => Err(format!("invalid module: {:?}", other.map(|b| b.len()))),
    }
}

// ------------------------------------------------------------------------------------------------ MPK

#[test]
fn mpk_engine_serves_or_refuses_to_build() -> R {
    eprintln!(
        "mpk: pku in /proc/cpuinfo = {}, wasmtime available = {}",
        host_has_pku(),
        EngineSettings::host_supports_mpk()
    );
    if !EngineSettings::host_supports_mpk() {
        // Mpk::Yes never silently falls back to off: the engine refuses to build.
        return match P2Engine::new(EngineSettings::defaults(true)) {
            Err(_) => Ok(()),
            Ok(_) => Err("MPK engine built on a host where wasmtime reports MPK unavailable".into()),
        };
    }
    let eng = P2Engine::new(EngineSettings::defaults(true)).map_err(e)?;
    if eng.settings().mpk() != Mpk::Yes {
        return Err("mpk engine reports mpk off".into());
    }
    let w = worker(&eng, &poison_guest())?;
    for n in 0..100 {
        let r = w.handle(RequestLimits::from(P2Limits::DEFAULT));
        if r.outcome != Outcome::Returned(0) {
            return Err(format!("mpk request {n}: {r:?}"));
        }
    }
    let r = worker(&eng, &grow_guest(256))?.handle(RequestLimits::from(P2Limits::DEFAULT));
    if r.outcome != Outcome::Returned(u32::MAX) {
        return Err(format!("mpk limiter: {r:?}"));
    }
    Ok(())
}
