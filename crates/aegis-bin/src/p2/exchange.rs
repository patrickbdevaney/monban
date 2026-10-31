//! One P2 request over one worker connection, supervisor side (F14 Part 2 ordering, Part 3 obligations).
//!
//! Blocking; run on tokio's blocking pool. One connection carries exactly one request (PLAN D21: no pipelining; a
//! fork child serves one request per connection and a cordon serves a connection's requests in sequence, so a new
//! connection per request never puts two requests on one connection). Sequence:
//!
//! 1. connect to the worker's listening socket (held by the supervisor; a replacement worker accepts what queued);
//! 2. `ready`, whose digest must equal the one this boot computed over the `.cwasm` (D4), else the worker is
//!    refused before any request byte is sent;
//! 3. `request` with the module's effective limits and the canonical `req-head`, then the body as `body-chunk`s
//!    (one empty chunk with `last = true` for an empty body);
//! 4. frames until `resp-end`, each decoded completely and checked against the per-request state: req-id, order,
//!    at most one `resp-head` (I5 header rules against the configured F8 limits), `resp-body` only after it, the
//!    data_run seq, and the response, log and data byte quotas plus the data_run count (I2, re-checked here). One
//!    `layout` frame (D8, test-hooks builds) is accepted only as the first frame after `ready`; it has no
//!    authority and is reported on stderr as `aegis-p2-layout {"pid": .., "load_base": ..}`.
//!
//! Each `data-run` is handed to the request's [`DataCtx`] (decode, tenant overwrite, authorize, audit before effect,
//! execute; [`super::data`]) and answered with exactly one `data-reply` before the next frame is read. An op that
//! does not decode is a decode failure of the request. `log` data is module-authored: it is counted against the
//! quota and never parsed. Nothing a module wrote leaves this module except through [`Outcome::Allow`], which is
//! produced only by `resp-end` with code 0 after a `resp-head` (I5); the caller re-serializes it.
#![forbid(unsafe_code)]

use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use aegis_adapter_host::pdp_uds::{connect_to, recv_packet, send_packet};

use super::data::{self, DataCtx};
use super::frame::{self, BODY_CHUNK, End, FRAME_MAX, Fields, HeaderLimits, Limits, W2s};
use super::mutant::{self, Mutant};

/// The only req-id on a connection (one request per connection).
const RID: u64 = 1;
/// Grace past the module's wall bound before a silent worker counts as an abnormal exit (F14 Part 2: "wall-ms + a
/// fixed grace").
pub const GRACE: Duration = Duration::from_secs(2);
/// How long a worker may take to send `ready` (a cordon's first request includes its execve and engine boot).
pub const READY_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the `double-response-accepted` negative control waits for frames after `resp-end`.
const LATE_WAIT: Duration = Duration::from_millis(300);

/// What the supervisor needs for one request.
#[derive(Debug)]
pub struct Job<'a> {
    /// The worker's listening socket.
    pub socket: &'a Path,
    /// sha256 of the `.cwasm` this boot's sandboxed compile wrote.
    pub digest: &'a [u8; 32],
    pub limits: Limits,
    /// The encoded `req-head`.
    pub head: &'a [u8],
    pub body: &'a [u8],
    pub headers: HeaderLimits,
    /// The request's data side (every `data-run` goes through it).
    pub data: &'a DataCtx<'a>,
}

/// How the exchange ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// `resp-end` code 0 after a `resp-head`: the module's answer, decoded (re-serialized by the caller).
    Allow { status: u16, headers: Fields, body: Vec<u8> },
    /// `resp-end` code 1.
    Deny,
    /// `resp-end` with any other code, or code 0 without a `resp-head` (Error => Deny, I7; not crash-attributable).
    ErrorCode(u32),
    /// `resp-end` with a trap (crash-attributable, D7).
    Trap(u8),
    /// A frame that did not decode, was out of order or broke a quota (crash-attributable; the caller kills the
    /// worker). The text is for the log only.
    Decode(&'static str),
    /// The connection ended before `resp-end` (worker death; the caller classifies it).
    Eof,
    /// No `resp-end` within `wall_ms` + [`GRACE`] (crash-attributable abnormal exit).
    Timeout,
    /// The worker could not be reached or did not send a valid `ready` before the request was sent (not the
    /// principal's fault). The text is for the log only.
    Unready(String),
}

enum Got {
    Frame(Vec<u8>),
    Eof,
    Timeout,
    Oversized,
}

fn recv(s: &UnixStream, until: Instant) -> Got {
    let left = until.saturating_duration_since(Instant::now());
    if left.is_zero() || s.set_read_timeout(Some(left)).is_err() {
        return Got::Timeout;
    }
    let mut buf = vec![0u8; FRAME_MAX];
    loop {
        match recv_packet(s, &mut buf) {
            Ok((0, 0)) => return Got::Eof,
            Ok((_, n)) if n > FRAME_MAX => return Got::Oversized,
            Ok((n, _)) => {
                buf.truncate(n);
                return Got::Frame(buf);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => return Got::Timeout,
            Err(_) => return Got::Eof,
        }
    }
}

fn layout_line(load_base: u64, pid: u64) {
    eprintln!("aegis-p2-layout {{\"pid\": {pid}, \"load_base\": {load_base}}}");
}

/// Runs one request (see the module docs).
pub fn run(job: &Job<'_>) -> Outcome {
    let s = match connect_to(job.socket) {
        Ok(s) => s,
        Err(e) => return Outcome::Unready(format!("connect {}: {e}", job.socket.display())),
    };
    if s.set_write_timeout(Some(READY_TIMEOUT)).is_err() {
        return Outcome::Unready("socket timeouts".into());
    }
    match recv(&s, Instant::now() + READY_TIMEOUT) {
        Got::Frame(f) => match frame::decode_w2s(&f, &job.headers) {
            Some(W2s::Ready { digest }) if digest == job.digest.as_slice() => {}
            Some(W2s::Ready { .. }) => return Outcome::Unready("ready frame with another module digest".into()),
            _ => return Outcome::Unready("first frame is not ready".into()),
        },
        Got::Eof => return Outcome::Unready("worker closed before ready".into()),
        Got::Timeout => return Outcome::Unready("no ready frame in time".into()),
        Got::Oversized => return Outcome::Unready("oversized first frame".into()),
    }
    let req = frame::request(RID, &job.limits, job.head);
    if req.len() > FRAME_MAX {
        // A head that cannot travel in one frame: refused before the module runs (not the principal's crash).
        return Outcome::ErrorCode(u32::MAX);
    }
    if send_packet(&s, &req).is_err() {
        return Outcome::Eof;
    }
    let mut chunks = job.body.chunks(BODY_CHUNK).peekable();
    if chunks.peek().is_none() {
        if send_packet(&s, &frame::body_chunk(RID, &[], true)).is_err() {
            return Outcome::Eof;
        }
    } else {
        while let Some(c) = chunks.next() {
            if send_packet(&s, &frame::body_chunk(RID, c, chunks.peek().is_none())).is_err() {
                return Outcome::Eof;
            }
        }
    }
    let until = Instant::now() + Duration::from_millis(job.limits.wall_ms) + GRACE;
    read_reply(&s, job, until)
}

/// Step 4: frames until `resp-end`.
fn read_reply(s: &UnixStream, job: &Job<'_>, until: Instant) -> Outcome {
    let l = &job.limits;
    let mut first = true;
    let mut head: Option<(u16, Fields)> = None;
    let mut body: Vec<u8> = Vec::new();
    let (mut seq, mut data_bytes, mut log_bytes) = (0u64, 0u64, 0u64);
    loop {
        let f = match recv(s, until) {
            Got::Frame(f) => f,
            Got::Eof => return Outcome::Eof,
            Got::Timeout => return Outcome::Timeout,
            Got::Oversized => return Outcome::Decode("oversized frame"),
        };
        let was_first = std::mem::replace(&mut first, false);
        let Some(w) = frame::decode_w2s(&f, &job.headers) else { return Outcome::Decode("frame does not decode") };
        match w {
            W2s::Layout { load_base, pid } if was_first => layout_line(load_base, pid),
            W2s::Layout { .. } | W2s::Ready { .. } => return Outcome::Decode("frame out of order"),
            W2s::RespHead { rid, .. }
            | W2s::RespBody { rid, .. }
            | W2s::RespEnd { rid, .. }
            | W2s::DataRun { rid, .. }
            | W2s::Log { rid, .. }
                if rid != RID =>
            {
                return Outcome::Decode("unknown req-id");
            }
            W2s::DataRun { seq: got, op, .. } => {
                let n = u64::try_from(op.len()).unwrap_or(u64::MAX);
                data_bytes = data_bytes.saturating_add(n);
                if got != seq || seq >= l.max_data_runs || data_bytes > l.max_data_bytes {
                    return Outcome::Decode("data_run out of order or over quota");
                }
                let Ok(mut result) = job.data.run(op) else { return Outcome::Decode("malformed data_run op") };
                let mut reply = frame::data_reply(RID, seq, &result);
                if reply.len() > FRAME_MAX {
                    // A result that cannot travel in one frame (only a large select): the uniform error instead.
                    result = data::result_err();
                    reply = frame::data_reply(RID, seq, &result);
                }
                // The worker counts the result bytes against max_data_bytes too; so does the supervisor.
                data_bytes = data_bytes.saturating_add(u64::try_from(result.len()).unwrap_or(u64::MAX));
                seq = seq.saturating_add(1);
                if send_packet(s, &reply).is_err() {
                    return Outcome::Eof;
                }
            }
            W2s::Log { data, .. } => {
                log_bytes = log_bytes.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
                if log_bytes > l.max_log_bytes {
                    return Outcome::Decode("log bytes over quota");
                }
            }
            W2s::RespHead { status, headers, .. } => {
                if head.is_some() {
                    if !mutant::is(Mutant::DoubleResponseAccepted) {
                        return Outcome::Decode("second resp-head");
                    }
                    body.clear(); // NEGATIVE CONTROL: the later head replaces the first
                }
                head = Some((status, headers));
            }
            W2s::RespBody { chunk, .. } => {
                if head.is_none() {
                    return Outcome::Decode("resp-body before resp-head");
                }
                let total = u64::try_from(body.len().saturating_add(chunk.len())).unwrap_or(u64::MAX);
                if total > l.max_resp_bytes {
                    return Outcome::Decode("response bytes over quota");
                }
                body.extend_from_slice(chunk);
            }
            W2s::RespEnd { end, .. } => {
                if let End::Trap(_) = end {
                    if mutant::is(Mutant::DoubleResponseAccepted)
                        && let Some(late) = late_response(s, job)
                    {
                        return late; // NEGATIVE CONTROL: frames after resp-end accepted
                    }
                    if mutant::is(Mutant::TrapMapsToAllow) {
                        // NEGATIVE CONTROL: the trap is treated as Allow with whatever the module wrote.
                        let (status, headers) = head.unwrap_or((200, Vec::new()));
                        return Outcome::Allow { status, headers, body };
                    }
                }
                return match (end, head) {
                    (End::Code(0), Some((status, headers))) => Outcome::Allow { status, headers, body },
                    (End::Code(1), _) => Outcome::Deny,
                    (End::Code(c), _) => Outcome::ErrorCode(c),
                    (End::Trap(t), _) => Outcome::Trap(t),
                };
            }
        }
    }
}

/// NEGATIVE CONTROL `double-response-accepted`: a late `resp-head`/`resp-body`/`resp-end(0)` after the request's
/// `resp-end`, accepted as its answer.
fn late_response(s: &UnixStream, job: &Job<'_>) -> Option<Outcome> {
    let until = Instant::now() + LATE_WAIT;
    let mut head: Option<(u16, Fields)> = None;
    let mut body = Vec::new();
    loop {
        let Got::Frame(f) = recv(s, until) else { return None };
        match frame::decode_w2s(&f, &job.headers)? {
            W2s::RespHead { status, headers, .. } => head = Some((status, headers)),
            W2s::RespBody { chunk, .. } => body.extend_from_slice(chunk),
            W2s::RespEnd { end: End::Code(0), .. } => {
                let (status, headers) = head?;
                return Some(Outcome::Allow { status, headers, body });
            }
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use aegis_adapter_host::pdp_uds::{accept_one, listen_at};

    const DIGEST: [u8; 32] = [9; 32];
    const HL: HeaderLimits = HeaderLimits { max_fields: 128, max_list_size: 16_384 };
    const LIM: Limits = Limits {
        fuel: 1,
        wall_ms: 200,
        memory_mib: 16,
        max_host_calls: 10,
        max_data_runs: 2,
        max_data_bytes: 100,
        max_resp_bytes: 8,
        max_log_bytes: 4,
    };

    fn ready() -> Vec<u8> {
        frame::Enc::new().u(16).u(0).u(1).bytes(&DIGEST).finish()
    }

    /// A scripted worker: sends `script` after reading the request and its body.
    fn with_worker(script: Vec<Vec<u8>>, close: bool) -> Outcome {
        let dir = std::env::temp_dir().join(format!("aegis-p2x-{}-{}", std::process::id(), rand_tag()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("w.sock");
        let l = listen_at(&sock).unwrap();
        let t = std::thread::spawn(move || {
            let c = accept_one(&l).unwrap();
            send_packet(&c, &ready()).unwrap();
            let mut buf = vec![0u8; FRAME_MAX];
            let (n, _) = recv_packet(&c, &mut buf).unwrap();
            assert_eq!(buf[0], 0, "request first");
            assert!(n > 10);
            let (m, _) = recv_packet(&c, &mut buf).unwrap(); // the empty last body-chunk
            assert_eq!(&buf[..m], &[1, 1, 0, 1]);
            for f in script {
                if send_packet(&c, &f).is_err() {
                    return;
                }
                if f.first() == Some(&20) {
                    let _ = recv_packet(&c, &mut buf); // data-reply
                }
            }
            if !close {
                std::thread::sleep(Duration::from_millis(2500));
            }
        });
        let data = DataCtx::none();
        let job =
            Job { socket: &sock, digest: &DIGEST, limits: LIM, head: b"\x00", body: b"", headers: HL, data: &data };
        let out = run(&job);
        let _ = t.join();
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    fn rand_tag() -> u64 {
        use std::hash::{BuildHasher, RandomState};
        RandomState::new().hash_one(std::time::SystemTime::now())
    }

    fn head(status: u64) -> Vec<u8> {
        frame::Enc::new().u(17).u(1).u(status).u(1).bytes(b"x-a").bytes(b"1").finish()
    }
    fn body(b: &[u8]) -> Vec<u8> {
        frame::Enc::new().u(18).u(1).bytes(b).finish()
    }
    fn end(kind: u64, v: u64) -> Vec<u8> {
        frame::Enc::new().u(19).u(1).u(kind).u(v).u(0).finish()
    }

    #[test]
    fn allow_is_reassembled_only_at_resp_end() {
        let lay = frame::Enc::new().u(22).u(0).u(4096).u(77).finish();
        let out = with_worker(vec![lay, head(201), body(b"ab"), body(b"cd"), end(0, 0)], true);
        assert_eq!(
            out,
            Outcome::Allow { status: 201, headers: vec![(b"x-a".to_vec(), b"1".to_vec())], body: b"abcd".to_vec() }
        );
    }

    #[test]
    fn deny_error_and_trap() {
        assert_eq!(with_worker(vec![head(200), body(b"x"), end(0, 1)], true), Outcome::Deny);
        assert_eq!(with_worker(vec![end(0, 7)], true), Outcome::ErrorCode(7));
        assert_eq!(with_worker(vec![end(0, 0)], true), Outcome::ErrorCode(0)); // Allow without a head
        assert_eq!(with_worker(vec![head(200), end(1, 4)], true), Outcome::Trap(4));
    }

    #[test]
    fn violations_are_decode_failures() {
        let d = |o: Outcome| matches!(o, Outcome::Decode(_));
        assert!(d(with_worker(vec![head(200), head(200)], true)));
        assert!(d(with_worker(vec![body(b"x")], true)));
        assert!(d(with_worker(vec![head(200), body(b"123456789")], true))); // over max_resp_bytes 8
        assert!(d(with_worker(vec![frame::Enc::new().u(21).u(1).u(2).bytes(b"12345").finish()], true)));
        assert!(d(with_worker(vec![frame::Enc::new().u(19).u(2).u(0).u(0).u(0).finish()], true))); // rid 2
        assert!(d(with_worker(vec![head(200), frame::Enc::new().u(22).u(0).u(1).u(1).finish()], true)));
        assert!(d(with_worker(vec![ready()], true)));
        assert!(d(with_worker(vec![vec![0xee, 1]], true)));
        // data_run: seq must count up from 0, at most max_data_runs (2); the op must decode (F10).
        let op = frame::Enc::new().u(1).bytes(b"notes").u(0).u(0).u(0).u(0).finish();
        let run = |s: u64| frame::Enc::new().u(20).u(1).u(s).bytes(&op).finish();
        assert!(d(with_worker(vec![run(1)], true)));
        assert!(d(with_worker(vec![run(0), run(1), run(2)], true)));
        assert_eq!(with_worker(vec![run(0), run(1), end(0, 1)], true), Outcome::Deny);
        let bad = frame::Enc::new().u(20).u(1).u(0).bytes(&[0xff; 10]).finish();
        assert!(d(with_worker(vec![bad], true)));
    }

    #[test]
    fn death_and_silence() {
        assert_eq!(with_worker(vec![head(200)], true), Outcome::Eof);
        assert_eq!(with_worker(vec![head(200)], false), Outcome::Timeout);
    }
}
