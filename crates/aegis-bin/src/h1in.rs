//! Inbound HTTP/1.1 driver.
//!
//! Every byte from the client passes the transport's strict framing filter (`aegis_transport::h1::H1Validator`,
//! F1 H1 grammar (c): bare LF/CR, obs-fold, CL+TE, duplicate CL, TE other than `chunked`, Expect misuse, TBI-1 head
//! bounds) before this driver looks at it; a rejected stream is answered with the filter's status and closed.
//! Requests are served one at a time (pipelined requests wait in the validated buffer). Deadlines: the idle
//! timeout between requests, the stall timeout inside a message (TBI-8 analogue). Draining (upgrade/shutdown)
//! closes idle keep-alive connections and ends every connection after its current response.

use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use aegis_canon::{Proto, Scheme};
use aegis_transport::h1::{H1Reject, H1Validator, HeadLimits};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::proxy::{self, Inbound, Reply};
use crate::shared::{Peer, Shared, bump};
use crate::util::{Either, find_head_end, race, reason, trim_ows};

/// What the TLS layer knows about the connection.
#[derive(Debug, Clone)]
pub struct ConnMeta {
    pub scheme: Scheme,
    pub sni: Option<Vec<u8>>,
    pub peer: Peer,
}

enum Stop {
    Eof,
    Timeout,
    Io,
    Reject(H1Reject),
}

struct Conn<IO> {
    io: IO,
    v: H1Validator,
    clean: Vec<u8>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Conn<IO> {
    async fn read_more(&mut self, wait: Duration) -> Result<(), Stop> {
        let mut buf = [0u8; 16 * 1024];
        let n = match timeout(wait, self.io.read(&mut buf)).await {
            Err(_) => return Err(Stop::Timeout),
            Ok(Err(_)) => return Err(Stop::Io),
            Ok(Ok(0)) => return Err(Stop::Eof),
            Ok(Ok(n)) => n,
        };
        self.v.feed(buf.get(..n).unwrap_or(&[]), &mut self.clean).map_err(Stop::Reject)
    }
}

/// A parsed (already validated) request head, owned.
struct Head {
    method: Vec<u8>,
    target: Vec<u8>,
    http10: bool,
    fields: Vec<(Vec<u8>, Vec<u8>)>,
}

enum BodyLen {
    Fixed(u64),
    Chunked,
}

fn parse_head(raw: &[u8]) -> Option<Head> {
    let mut lines = raw.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let rl = lines.next()?;
    let mut parts = rl.splitn(3, |&b| b == b' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    let http10 = match version {
        b"HTTP/1.1" => false,
        b"HTTP/1.0" => true,
        _ => return None,
    };
    let mut fields = Vec::new();
    for l in lines {
        let colon = l.iter().position(|&b| b == b':')?;
        // OWS around the value is not part of it (RFC 9112 §5.1); canon_headers trims too.
        fields.push((l.get(..colon)?.to_vec(), trim_ows(l.get(colon.saturating_add(1)..)?).to_vec()));
    }
    Some(Head { method: method.to_vec(), target: target.to_vec(), http10, fields })
}

fn field<'a>(h: &'a Head, name: &[u8]) -> impl Iterator<Item = &'a [u8]> {
    let name = name.to_vec();
    h.fields.iter().filter(move |(n, _)| n.eq_ignore_ascii_case(&name)).map(|(_, v)| trim_ows(v))
}

fn body_len(h: &Head) -> Result<BodyLen, u16> {
    if field(h, b"transfer-encoding").next().is_some() {
        return Ok(BodyLen::Chunked); // the validator admitted exactly `chunked`, never with Content-Length
    }
    match field(h, b"content-length").next() {
        None => Ok(BodyLen::Fixed(0)),
        Some(v) => std::str::from_utf8(v).ok().and_then(|s| s.parse::<u64>().ok()).map(BodyLen::Fixed).ok_or(400),
    }
}

fn wants_close(h: &Head) -> bool {
    h.http10
        || field(h, b"connection").any(|v| v.split(|&b| b == b',').any(|t| trim_ows(t).eq_ignore_ascii_case(b"close")))
}

/// Decode a complete chunked body from the start of `buf` (already framing-checked by the validator).
/// `Ok(None)`: incomplete. `Err(413)`: over `cap`.
fn dechunk(buf: &[u8], cap: u64) -> Result<Option<(Vec<u8>, usize)>, u16> {
    let find = |from: usize| {
        buf.get(from..).and_then(|s| s.windows(2).position(|w| w == b"\r\n")).map(|i| i.saturating_add(from))
    };
    let mut pos = 0usize;
    let mut body = Vec::new();
    loop {
        let Some(le) = find(pos) else { return Ok(None) };
        let line = buf.get(pos..le).unwrap_or(&[]);
        let size = trim_ows(line.split(|&b| b == b';').next().unwrap_or(b""));
        let n = std::str::from_utf8(size).ok().and_then(|s| u64::from_str_radix(s, 16).ok()).ok_or(400u16)?;
        pos = le.saturating_add(2);
        if n == 0 {
            loop {
                let Some(te) = find(pos) else { return Ok(None) };
                let done = te == pos;
                pos = te.saturating_add(2);
                if done {
                    return Ok(Some((body, pos)));
                }
            }
        }
        if u64::try_from(body.len()).unwrap_or(u64::MAX).saturating_add(n) > cap {
            return Err(413);
        }
        let n = usize::try_from(n).map_err(|_| 413u16)?;
        let end = pos.saturating_add(n);
        if buf.len() < end.saturating_add(2) {
            return Ok(None);
        }
        body.extend_from_slice(buf.get(pos..end).unwrap_or(&[]));
        pos = end.saturating_add(2);
    }
}

/// Serialize a reply (HTTP/1.1). Framing is always `content-length` (regenerated, never copied from upstream).
pub fn encode_reply(reply: &Reply, head_req: bool, close: bool) -> Vec<u8> {
    let mut o = Vec::with_capacity(256usize.saturating_add(reply.body.len()));
    o.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", reply.status, reason(reply.status)).as_bytes());
    for (n, v) in &reply.headers {
        if n == b"content-length" {
            continue;
        }
        o.extend_from_slice(n);
        o.extend_from_slice(b": ");
        o.extend_from_slice(v);
        o.extend_from_slice(b"\r\n");
    }
    match reply.explicit_length() {
        Some(l) => {
            o.extend_from_slice(b"content-length: ");
            o.extend_from_slice(l);
            o.extend_from_slice(b"\r\n");
        }
        None if reply.status == 204 || reply.status == 304 => {}
        None => o.extend_from_slice(format!("content-length: {}\r\n", reply.body.len()).as_bytes()),
    }
    if close {
        o.extend_from_slice(b"connection: close\r\n");
    }
    o.extend_from_slice(b"\r\n");
    if !head_req {
        o.extend_from_slice(&reply.body);
    }
    o
}

async fn send<IO: AsyncWrite + Unpin>(io: &mut IO, bytes: &[u8], stall: Duration) -> bool {
    matches!(
        timeout(stall, async {
            io.write_all(bytes).await?;
            io.flush().await
        })
        .await,
        Ok(Ok(()))
    )
}

/// Drive one HTTP/1.1 connection.
pub async fn serve<IO: AsyncRead + AsyncWrite + Unpin>(shared: Arc<Shared>, io: IO, meta: ConnMeta) {
    let wl = shared.snapshot().plan.wl;
    let stall = Duration::from_millis(wl.stall_timeout_ms);
    let idle = Duration::from_millis(wl.idle_timeout_ms);
    let lim = HeadLimits {
        max_head_bytes: wl.h1_max_head_bytes,
        max_field_bytes: wl.max_header_list_size,
        max_fields: wl.max_header_fields,
    };
    let mut c = Conn { io, v: H1Validator::new(lim), clean: Vec::new() };
    let mut first = true;
    loop {
        // ---- one validated head
        let end = loop {
            if let Some(e) = find_head_end(&c.clean) {
                break e;
            }
            let at_rest = c.clean.is_empty() && !c.v.mid_message();
            let r = if at_rest {
                let notified = shared.drain_notify.notified();
                let mut notified = pin!(notified);
                notified.as_mut().enable();
                if shared.is_draining() {
                    return conn_end(&shared, &meta, first);
                }
                match race(c.read_more(idle), notified).await {
                    Either::Left(r) => r,
                    Either::Right(()) => return conn_end(&shared, &meta, first),
                }
            } else {
                c.read_more(stall).await
            };
            match r {
                Ok(()) => {}
                Err(Stop::Reject(rej)) => {
                    let _ = send(&mut c.io, &encode_reply(&Reply::status(rej.status), false, true), stall).await;
                    return conn_end(&shared, &meta, first);
                }
                Err(Stop::Timeout) if !at_rest => {
                    let _ = send(&mut c.io, &encode_reply(&Reply::status(408), false, true), stall).await;
                    return conn_end(&shared, &meta, first);
                }
                Err(Stop::Eof | Stop::Io | Stop::Timeout) => return conn_end(&shared, &meta, first),
            }
        };
        let raw = c.clean.get(..end).unwrap_or(&[]).to_vec();
        c.clean.drain(..end.saturating_add(4).min(c.clean.len()));
        let Some(head) = parse_head(&raw) else {
            let _ = send(&mut c.io, &encode_reply(&Reply::status(400), false, true), stall).await;
            return conn_end(&shared, &meta, first);
        };
        let head_req = head.method == b"HEAD";
        let blen = match body_len(&head) {
            Ok(b) => b,
            Err(s) => {
                let _ = send(&mut c.io, &encode_reply(&Reply::status(s), head_req, true), stall).await;
                return conn_end(&shared, &meta, first);
            }
        };
        let body_pending = !matches!(blen, BodyLen::Fixed(0));
        let mut close = wants_close(&head);
        let id = shared.next_id();
        bump(&shared.stats.requests);
        let newconn = std::mem::replace(&mut first, false);
        // ---- admission, then the head decision
        let decided = match shared.admit(id, &meta.peer, newconn) {
            Err(status) => Err(Reply::status(status)),
            Ok(()) => {
                let inb = Inbound {
                    proto: Proto::H1,
                    scheme: meta.scheme,
                    sni: meta.sni.as_deref(),
                    method: &head.method,
                    authority: None,
                    target: &head.target,
                    fields: head.fields.iter().map(|(n, v)| (n.as_slice(), v.as_slice())).collect(),
                };
                let r = proxy::head(&shared, &inb);
                if r.is_err() {
                    shared.done(id, false);
                }
                r
            }
        };
        let adm = match decided {
            Ok(a) => a,
            Err(reply) => {
                // The body (if any) was never read: the connection cannot continue.
                close |= body_pending || shared.is_draining();
                let ok = send(&mut c.io, &encode_reply(&reply, head_req, close), stall).await;
                if close || !ok {
                    return conn_end(&shared, &meta, false);
                }
                continue;
            }
        };
        // ---- body (bounded by the profile limit)
        if let BodyLen::Fixed(n) = blen
            && n > adm.body_cap
        {
            shared.done(id, true);
            let _ = send(&mut c.io, &encode_reply(&Reply::status(413), head_req, true), stall).await;
            return conn_end(&shared, &meta, false);
        }
        if adm.expect_continue && body_pending && !send(&mut c.io, b"HTTP/1.1 100 Continue\r\n\r\n", stall).await {
            shared.done(id, true);
            return conn_end(&shared, &meta, false);
        }
        let body = loop {
            let step = match blen {
                BodyLen::Fixed(n) => {
                    let n = usize::try_from(n).unwrap_or(usize::MAX);
                    if c.clean.len() >= n { Ok(Some((c.clean.get(..n).unwrap_or(&[]).to_vec(), n))) } else { Ok(None) }
                }
                BodyLen::Chunked => dechunk(&c.clean, adm.body_cap),
            };
            match step {
                Ok(Some((b, used))) => {
                    c.clean.drain(..used.min(c.clean.len()));
                    break b;
                }
                Ok(None) => {
                    if let Err(e) = c.read_more(stall).await {
                        shared.done(id, true);
                        if let Stop::Reject(rej) = e {
                            let _ =
                                send(&mut c.io, &encode_reply(&Reply::status(rej.status), head_req, true), stall).await;
                        }
                        return conn_end(&shared, &meta, false);
                    }
                }
                Err(status) => {
                    shared.done(id, true);
                    let _ = send(&mut c.io, &encode_reply(&Reply::status(status), head_req, true), stall).await;
                    return conn_end(&shared, &meta, false);
                }
            }
        };
        let reply = proxy::forward(&shared, &adm, &body).await;
        shared.done(id, false);
        close |= shared.is_draining();
        if !send(&mut c.io, &encode_reply(&reply, head_req, close), stall).await || close {
            let _ = timeout(stall, c.io.shutdown()).await;
            return conn_end(&shared, &meta, false);
        }
    }
}

fn conn_end(shared: &Shared, meta: &ConnMeta, never_admitted: bool) {
    if !never_admitted {
        shared.conn_closed(&meta.peer);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn dechunks() {
        let b = b"3\r\nabc\r\n2;x=y\r\nde\r\n0\r\nT: v\r\n\r\nNEXT";
        let (body, used) = dechunk(b, 100).unwrap().unwrap();
        assert_eq!(body, b"abcde");
        assert_eq!(&b[used..], b"NEXT");
        assert_eq!(dechunk(b"3\r\nab", 100), Ok(None));
        assert_eq!(dechunk(b"5\r\nabcde\r\n0\r\n\r\n", 4), Err(413));
    }

    #[test]
    fn reply_encoding() {
        let r = Reply { status: 200, headers: vec![(b"x-a".to_vec(), b"1".to_vec())], body: b"hi".to_vec() };
        assert_eq!(
            encode_reply(&r, false, true),
            b"HTTP/1.1 200 OK\r\nx-a: 1\r\ncontent-length: 2\r\nconnection: close\r\n\r\nhi".to_vec()
        );
        let h = parse_head(b"GET /a?b HTTP/1.1\r\nHost: x\r\nX:  y ").unwrap();
        assert_eq!(h.target, b"/a?b");
        assert_eq!(h.fields[1], (b"X".to_vec(), b"y".to_vec()));
    }
}
