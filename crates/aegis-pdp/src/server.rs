//! PDP-1 server loop: one request at a time per connection, one thread per connection (capped).
//!
//! Per packet: EOF closes. A header that does not parse (bad magic/version/kind, id 0, shorter than a header)
//! closes the connection without a reply: there is no id to answer under. An oversized packet (> MAX_REQUEST,
//! seen through `MSG_TRUNC`) or a bad body is answered `Error` under its id. Otherwise the engine decides.

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use aegis_authz::pdp::{HEADER_LEN, KIND_REQUEST, MAX_REQUEST, decode_header, decode_request, encode_reply};
use aegis_types::Decision;

use crate::engine::Engine;
use crate::uds::{accept_one, recv_packet, send_packet};

/// Concurrent connection cap; extra connections are closed at once.
pub const MAX_CONNS: usize = 32;
/// A connection idle this long is closed.
pub const IDLE: Duration = Duration::from_secs(60);

/// Serve one connected socket until EOF, error or a header-level protocol violation.
pub fn serve_conn<Fd: AsFd>(engine: &Engine, fd: Fd) -> io::Result<()> {
    let mut buf = vec![0u8; MAX_REQUEST + 1];
    loop {
        let (got, len) = recv_packet(&fd, &mut buf)?;
        if len == 0 {
            return Ok(());
        }
        let frame = buf.get(..got).unwrap_or_default();
        let id = match decode_header(frame) {
            Ok((KIND_REQUEST, id)) => id,
            _ => return Ok(()),
        };
        let decision = if len > MAX_REQUEST || got < HEADER_LEN {
            Decision::Error
        } else {
            match decode_request(frame) {
                Ok((_, Ok(req))) => engine.decide(&req).decision,
                _ => Decision::Error,
            }
        };
        send_packet(&fd, &encode_reply(id, decision))?;
    }
}

/// Accept loop on a listening socket. Never returns unless accept fails hard.
pub fn serve_listener(engine: Arc<Engine>, listener: &OwnedFd) -> io::Result<()> {
    let live = Arc::new(AtomicUsize::new(0));
    loop {
        let conn = match accept_one(listener) {
            Ok(c) => c,
            Err(e) if e.kind() == io::ErrorKind::Interrupted || e.kind() == io::ErrorKind::ConnectionAborted => {
                continue;
            }
            Err(e) => return Err(e),
        };
        if live.fetch_add(1, Ordering::SeqCst) >= MAX_CONNS {
            live.fetch_sub(1, Ordering::SeqCst);
            drop(conn);
            continue;
        }
        let (engine, mine) = (Arc::clone(&engine), Arc::clone(&live));
        let spawned = std::thread::Builder::new().name("pdp-conn".into()).spawn(move || {
            if conn.set_read_timeout(Some(IDLE)).is_ok() {
                let _ = serve_conn(&engine, &conn);
            }
            mine.fetch_sub(1, Ordering::SeqCst);
        });
        if spawned.is_err() {
            live.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use aegis_authz::pdp::{PdpClient, PdpRequest, PdpTransport, REPLY_LEN, TransportFault, Uid, Value};
    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};

    const SCHEMA: &str = r#"namespace App { entity User; entity Doc;
        action read appliesTo { principal: [User], resource: [Doc], context: { n: Long } }; }"#;
    const POLICIES: &str = r#"permit(principal == App::User::"alice", action, resource);"#;

    fn req(who: &str) -> PdpRequest {
        PdpRequest {
            principal: Uid::new("App::User", who),
            action: Uid::new("App::Action", "read"),
            resource: Uid::new("App::Doc", "d"),
            context: vec![("n".into(), Value::Long(1))],
            entities: vec![],
        }
    }

    /// Transport over one end of a socketpair (the "fd passed by the host" mode).
    struct Pair(OwnedFd);
    impl PdpTransport for Pair {
        fn exchange(&mut self, rq: &[u8], reply: &mut [u8]) -> Result<usize, TransportFault> {
            send_packet(&self.0, rq).map_err(|_| TransportFault::Io)?;
            match recv_packet(&self.0, reply) {
                Ok((_, 0)) | Err(_) => Err(TransportFault::Closed),
                Ok((_, n)) => Ok(n),
            }
        }
        fn reset(&mut self) {}
    }

    #[test]
    fn socketpair_round_trip_and_bad_frames() {
        let (engine, _) = Engine::load(POLICIES, SCHEMA).unwrap();
        let (a, b) = socketpair(AddressFamily::UNIX, SocketType::SEQPACKET, SocketFlags::CLOEXEC, None).unwrap();
        let t = std::thread::spawn(move || serve_conn(&engine, &b));
        let mut c = PdpClient::new(Pair(a.try_clone().unwrap()));
        assert_eq!(c.decide(&req("alice")), Decision::Allow);
        assert_eq!(c.decide(&req("bob")), Decision::Deny);
        // Bad body under a valid header: Error under the same id.
        let mut f = aegis_authz::pdp::encode_request(77, &req("alice")).unwrap();
        f.push(0);
        send_packet(&a, &f).unwrap();
        let mut r = [0u8; 64];
        let (n, len) = recv_packet(&a, &mut r).unwrap();
        assert_eq!((n, len), (REPLY_LEN, REPLY_LEN));
        assert_eq!(aegis_authz::pdp::decode_reply(&r[..n], len, 77), Decision::Error);
        // Oversized: Error under its id.
        let mut big = aegis_authz::pdp::encode_request(78, &req("alice")).unwrap();
        big.resize(MAX_REQUEST + 10, 0);
        send_packet(&a, &big).unwrap();
        let (n, len) = recv_packet(&a, &mut r).unwrap();
        assert_eq!(aegis_authz::pdp::decode_reply(&r[..n], len, 78), Decision::Error);
        // Garbage header: the server closes.
        send_packet(&a, &[0xFF; 20]).unwrap();
        assert_eq!(recv_packet(&a, &mut r).unwrap(), (0, 0));
        t.join().unwrap().unwrap();
    }
}
