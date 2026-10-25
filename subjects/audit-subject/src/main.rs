//! audit-subject: drives `aegis_audit::Log` with a file-backed `AuditSink` and writes a C2SP tlog-tiles
//! directory for `oracles/tlog-verify`.
//!
//! Usage: `audit-subject --out DIR [--n N] [--checkpoints S1,S2,...] [--origin O] [--key-seed HEX32]
//!         [--pq-seed HEX32] [--no-pq] [--variant K]`
//!
//! Output (under DIR): `checkpoint`, `history/<size>` (every published checkpoint, oldest first by size),
//! `tile/<L>/<N>[.p/<W>]`, `tile/entries/<N>[.p/<W>]`, `vkey` (Ed25519 log key), `vkey.mldsa87` (cosigner).
//! Stdout: the final checkpoint followed by the verifier keys. Keys are random unless seeds are given (the
//! oracle's self-test passes seeds so it can re-sign mutated logs). `--variant` changes event content, which
//! with the same seeds yields a validly signed fork.
#![forbid(unsafe_code)]

mod sink;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use aegis_audit::{
    Action, Actor, Appended, AuditEvent, Detail, DetailKey, DetailValue, Ed25519NoteSigner, EventClass, FailurePolicy,
    FipsStatus, Log, LogConfig, MlDsa87NoteSigner, NoteSigner, Outcome, Untrusted,
};
use aegis_types::TenantId;

struct Args {
    out: PathBuf,
    n: u64,
    checkpoints: Vec<u64>,
    origin: String,
    key_seed: Option<[u8; 32]>,
    pq_seed: Option<[u8; 32]>,
    pq: bool,
    variant: u64,
}

fn parse_seed(s: &str) -> Result<[u8; 32], String> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return Err("seed must be 64 hex chars".into());
    }
    let mut out = [0u8; 32];
    for (o, pair) in out.iter_mut().zip(b.chunks(2)) {
        let txt = std::str::from_utf8(pair).map_err(|_| "bad hex")?;
        *o = u8::from_str_radix(txt, 16).map_err(|_| "bad hex")?;
    }
    Ok(out)
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        out: PathBuf::new(),
        n: 70_000,
        checkpoints: vec![1, 300, 33_333, 65_536],
        origin: "aegis.example/audit-subject".into(),
        key_seed: None,
        pq_seed: None,
        pq: true,
        variant: 0,
    };
    let mut it = std::env::args().skip(1);
    let mut have_out = false;
    while let Some(flag) = it.next() {
        let mut val = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--out" => {
                a.out = PathBuf::from(val()?);
                have_out = true;
            }
            "--n" => a.n = val()?.parse().map_err(|_| "bad --n")?,
            "--checkpoints" => {
                let v = val()?;
                a.checkpoints = if v.is_empty() {
                    vec![]
                } else {
                    v.split(',').map(|s| s.parse().map_err(|_| "bad --checkpoints")).collect::<Result<_, _>>()?
                };
            }
            "--origin" => a.origin = val()?,
            "--key-seed" => a.key_seed = Some(parse_seed(&val()?)?),
            "--pq-seed" => a.pq_seed = Some(parse_seed(&val()?)?),
            "--no-pq" => a.pq = false,
            "--variant" => a.variant = val()?.parse().map_err(|_| "bad --variant")?,
            _ => return Err(format!("unknown argument {flag}")),
        }
    }
    if !have_out {
        return Err("--out DIR is required".into());
    }
    Ok(a)
}

/// Deterministic but varied events, including hostile `object` / detail strings and every actor kind.
fn event(i: u64, variant: u64) -> Result<AuditEvent, String> {
    let e = |x: aegis_audit::EventError| x.to_string();
    let admin = i % 1999 == 5;
    let actor = match i % 4 {
        0 => Actor::public(),
        1 => Actor::principal(
            TenantId::new(1 + i % 7).map_err(|_| "tenant")?,
            Some(format!("user-{}", i % 13).as_bytes()),
        ),
        2 if admin => Actor::admin(b"ops@example"),
        _ => Actor::system(),
    };
    let hostile: &[u8] = match i % 5 {
        0 => b"/plain/path",
        1 => b"/x\"}\n{\"seq\":0,\"forged\":true}",
        2 => b"\x1b[31mred\x1b[0m \xff\xfe invalid utf8",
        3 => "/caf\u{e9}/\u{1F600}/\u{202e}rtl".as_bytes(),
        _ => b"\\u0000 \\\\ backslashes",
    };
    let mut object = hostile.to_vec();
    object.extend_from_slice(format!("#{i}.{variant}").as_bytes());
    if i % 1000 == 999 {
        object.extend(std::iter::repeat_n(b'A', 2000)); // forces the 512-char cap
    }
    let mut detail = Detail::new();
    detail.insert(DetailKey::new("n").map_err(e)?, DetailValue::Int(i as i64 - 35_000)).map_err(e)?;
    if i.is_multiple_of(3) {
        detail.insert(DetailKey::new("ua").map_err(e)?, DetailValue::text(hostile)).map_err(e)?;
        detail.insert(DetailKey::new("authz").map_err(e)?, DetailValue::Redacted).map_err(e)?;
        detail.insert(DetailKey::new("cookie_hash").map_err(e)?, DetailValue::hashed(b"session=secret")).map_err(e)?;
        detail.insert(DetailKey::new("cached").map_err(e)?, DetailValue::Bool(i.is_multiple_of(2))).map_err(e)?;
    }
    let mut req_id = [0u8; 16];
    for (k, b) in req_id.iter_mut().enumerate() {
        *b = (i.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> ((k % 8) * 8)) as u8 ^ k as u8;
    }
    Ok(AuditEvent {
        class: if admin { EventClass::Admin } else { EventClass::DataPlane },
        actor,
        action: Action::new(if admin { "config.apply" } else { "http.request" }).map_err(e)?,
        object: Untrusted::object(&object),
        outcome: match i % 6 {
            0 | 1 => Outcome::Allow,
            2 => Outcome::Deny,
            3 => Outcome::Error,
            4 => Outcome::Applied,
            _ => Outcome::RolledBack,
        },
        req_id,
        config_hash: [0x5a; 32],
        fips_status: match i % 3 {
            0 => FipsStatus::None,
            1 => FipsStatus::Floor,
            _ => FipsStatus::Cmvp,
        },
        detail,
    })
}

fn run(a: Args) -> Result<(), String> {
    let ed = match a.key_seed {
        Some(s) => Ed25519NoteSigner::from_seed(&a.origin, &s),
        None => Ed25519NoteSigner::generate(&a.origin),
    }
    .map_err(|e| e.to_string())?;
    let mut cosigners: Vec<Box<dyn NoteSigner>> = Vec::new();
    if a.pq {
        let pq = match a.pq_seed {
            Some(s) => MlDsa87NoteSigner::from_seed(&a.origin, &s),
            None => MlDsa87NoteSigner::generate(&a.origin),
        }
        .map_err(|e| e.to_string())?;
        cosigners.push(Box::new(pq));
    }
    let sink = sink::FileSink::new(&a.out).map_err(|e| e.to_string())?;
    let cfg = LogConfig {
        origin: a.origin.clone(),
        max_pending: 1 << 20,
        require_cosigner: a.pq,
        policy: FailurePolicy::default(),
    };
    let mut log = Log::new(cfg, Box::new(ed), cosigners, sink).map_err(|e| format!("{e:?}"))?;
    let vkeys = log.vkeys();
    let mut names = vec!["vkey".to_string()];
    if a.pq {
        names.push("vkey.mldsa87".into());
    }
    for (name, vk) in names.iter().zip(&vkeys) {
        std::fs::write(a.out.join(name), format!("{vk}\n")).map_err(|e| e.to_string())?;
    }
    let t0 = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_millis() as u64;
    for i in 0..a.n {
        let ev = event(i, a.variant)?;
        if ev.class == EventClass::Admin {
            let (seq, _) = log.append_durable(&ev, t0 + i).map_err(|e| e.to_string())?;
            if seq != i {
                return Err(format!("seq {seq} != {i}"));
            }
        } else {
            match log.append(&ev, t0 + i).map_err(|e| e.to_string())? {
                Appended::Sequenced(s) if s == i => {}
                other => return Err(format!("event {i}: {other:?}")),
            }
        }
        if a.checkpoints.contains(&(i + 1)) {
            log.checkpoint().map_err(|e| e.to_string())?;
        }
    }
    let cp = log.checkpoint().map_err(|e| e.to_string())?;
    print!("{}", cp.note);
    for vk in &vkeys {
        println!("{vk}");
    }
    Ok(())
}

fn main() -> ExitCode {
    match parse_args().and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("audit-subject: {e}");
            ExitCode::from(2)
        }
    }
}
