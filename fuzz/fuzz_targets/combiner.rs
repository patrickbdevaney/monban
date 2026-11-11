//! F6: tri-state fail-closed combiner inputs (monban-authz `combine`, `pdp::PdpStage` / `PdpClient` host mapping).
//!
//! The input is a script: a list of stage decisions plus, for each PDP call, what the (fake) transport does:
//! fault, return raw bytes with a chosen true length, or echo a well-formed reply under the right or a wrong id.
//! Properties:
//! - `combine` equals its specification (Allow iff non-empty and all Allow) and never returns `Error`;
//! - the PDP stage answers Allow/Deny only for an exact 12-byte reply that echoes the id just sent with that
//!   decision byte; every fault, short/long/garbled packet or wrong id is `Error` (INV-FAILCLOSED);
//! - request ids are strictly increasing and never 0; the transport is reset after every `Error`;
//! - combining PDP decisions with other stages yields Allow only if every PDP answer was Allow.
#![no_main]

use monban_authz::pdp::{
    HEADER_LEN, KIND_REQUEST, PdpClient, PdpRequest, PdpStage, PdpTransport, REPLY_LEN, TransportFault, Uid,
    decode_header, encode_reply,
};
use monban_authz::{Decision, PolicyStage, combine};
use monban_fuzz::{Unstructured, byte, bytes, selftest};
use libfuzzer_sys::fuzz_target;

#[derive(Default)]
struct Script {
    steps: Vec<Step>,
    next: usize,
    last_id: u64,
    resets: usize,
    log: Vec<(u64, Vec<u8>, usize)>,
}

#[derive(Clone)]
enum Step {
    Fault(TransportFault),
    Raw(Vec<u8>, usize),
    Echo { decision: u8, id_delta: u64 },
}

impl PdpTransport for Script {
    fn exchange(&mut self, request: &[u8], reply: &mut [u8]) -> Result<usize, TransportFault> {
        let Ok((kind, id)) = decode_header(request) else { panic!("client sent a frame with a bad header") };
        assert_eq!(kind, KIND_REQUEST, "client sent a non-request frame");
        assert!(id > self.last_id && id != 0, "request ids not strictly increasing");
        self.last_id = id;
        assert!(request.len() > HEADER_LEN);
        let step = self.steps.get(self.next).cloned().unwrap_or(Step::Fault(TransportFault::Closed));
        self.next += 1;
        let (bytes, true_len) = match step {
            Step::Fault(f) => {
                self.log.push((id, Vec::new(), usize::MAX));
                return Err(f);
            }
            // A real packet of length `n`: the transport writes min(n, buffer) bytes and reports n.
            Step::Raw(mut b, n) => {
                b.resize(n, 0);
                (b, n)
            }
            Step::Echo { decision, id_delta } => {
                let mut r = encode_reply(id.wrapping_add(id_delta), Decision::Allow).to_vec();
                if let Some(d) = r.get_mut(HEADER_LEN) {
                    *d = decision;
                }
                (r, REPLY_LEN)
            }
        };
        let n = bytes.len().min(reply.len());
        if let (Some(dst), Some(src)) = (reply.get_mut(..n), bytes.get(..n)) {
            dst.copy_from_slice(src);
        }
        self.log.push((id, bytes.get(..n).unwrap_or(&[]).to_vec(), true_len));
        Ok(true_len)
    }
    fn reset(&mut self) {
        self.resets += 1;
    }
}

fn parse_steps(u: &mut Unstructured<'_>) -> Vec<Step> {
    let mut steps = Vec::new();
    for _ in 0..byte(u) % 8 {
        steps.push(match byte(u) % 6 {
            0 => Step::Fault(match byte(u) % 3 {
                0 => TransportFault::Timeout,
                1 => TransportFault::Closed,
                _ => TransportFault::Io,
            }),
            1 | 2 => {
                let b = bytes(u, 64).to_vec();
                let n = if byte(u) % 4 == 0 { usize::from(byte(u)) } else { b.len() };
                Step::Raw(b, n)
            }
            3 => Step::Echo { decision: byte(u), id_delta: u64::from(byte(u) % 3) },
            _ => Step::Echo { decision: byte(u) % 3, id_delta: 0 },
        });
    }
    steps
}

fn decision(b: u8) -> Decision {
    match b % 3 {
        0 => Decision::Allow,
        1 => Decision::Deny,
        _ => Decision::Error,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // 1. combine against its specification on arbitrary lists.
    let ds: Vec<Decision> = bytes(&mut u, 64).iter().map(|&b| decision(b)).collect();
    let got = combine(&ds);
    let want =
        if !ds.is_empty() && ds.iter().all(|d| *d == Decision::Allow) { Decision::Allow } else { Decision::Deny };
    assert_eq!(got, want, "combine differs from its specification");
    assert_ne!(got, Decision::Error, "combine returned Error");

    // 2. PDP stage under a scripted transport. `PdpStage` hides its client, so the same script also drives a bare
    //    `PdpClient` whose transport log we can inspect; both must answer identically.
    let steps = parse_steps(&mut u);
    let calls = steps.len();
    let req = PdpRequest {
        principal: Uid::new("App::User", "alice"),
        action: Uid::new("App::Action", "read"),
        resource: Uid::new("App::Doc", "d1"),
        context: Vec::new(),
        entities: Vec::new(),
    };
    let stage = PdpStage::new(Script { steps: steps.clone(), ..Script::default() });
    let answers: Vec<Decision> = (0..calls).map(|_| stage.decide(&req)).collect();
    let mut client = PdpClient::new(Script { steps, ..Script::default() });
    let answers2: Vec<Decision> = (0..calls).map(|_| client.decide(&req)).collect();
    assert_eq!(answers, answers2, "PdpStage and PdpClient disagree on the same script");
    let t = client.transport_mut();
    let errors = answers2.iter().filter(|d| **d == Decision::Error).count();
    assert_eq!(t.resets, errors, "transport not reset exactly once per Error");
    assert_eq!(t.log.len(), calls);
    for (d, (id, reply, true_len)) in answers2.iter().zip(t.log.iter()) {
        let exact = |x: Decision| *true_len == REPLY_LEN && reply.as_slice() == encode_reply(*id, x).as_slice();
        match d {
            Decision::Allow => assert!(exact(Decision::Allow), "Allow from a reply that is not the exact echo"),
            Decision::Deny => assert!(exact(Decision::Deny), "Deny from a reply that is not the exact echo"),
            Decision::Error => {
                assert!(!exact(Decision::Allow) && !exact(Decision::Deny), "exact reply not honoured")
            }
        }
    }

    // 3. Fail-closed composition: PDP answers plus extra stages.
    let mut all = answers2.clone();
    all.extend(ds.iter().copied());
    let c = combine(&all);
    if c == Decision::Allow {
        assert!(answers2.iter().all(|d| *d == Decision::Allow), "Allow despite a non-Allow PDP answer");
    }
    selftest!(answers2.len() >= 5 && answers2.iter().all(|d| *d == Decision::Allow)); // examples/seeds.rs: at most 3
});
