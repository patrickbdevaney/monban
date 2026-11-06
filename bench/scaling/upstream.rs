//! Static HTTP/1.1 upstream for bench/scaling (std only, built with plain `rustc -O`, no dependencies).
//!
//! `scaling-upstream <port>`: listens on 127.0.0.1:<port>, one thread per connection, keep-alive, and answers every
//! request head with the same fixed 200 response. Request bodies are skipped by `content-length` (aegis regenerates
//! framing and never sends chunked upstream). It is the "static upstream" of the scaling harness, not a load client.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

const RESP: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 12\r\n\r\nscaling-ok\r\n";

fn find_head_end(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn content_length(head: &[u8]) -> usize {
    let text = String::from_utf8_lossy(head);
    for line in text.split("\r\n") {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                return v.trim().parse().unwrap_or(0);
            }
        }
    }
    0
}

fn serve(mut s: TcpStream) {
    let _ = s.set_nodelay(true);
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    loop {
        // Answer every complete request already buffered (pipelining-safe), then read more.
        while let Some(end) = find_head_end(&buf) {
            let need = end + content_length(&buf[..end]);
            if buf.len() < need {
                break;
            }
            buf.drain(..need);
            if s.write_all(RESP).is_err() {
                return;
            }
        }
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        if buf.len() > 1 << 20 {
            return;
        }
    }
}

fn main() {
    let port: u16 = std::env::args().nth(1).and_then(|p| p.parse().ok()).unwrap_or(0);
    let l = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("scaling-upstream: bind: {e}");
            std::process::exit(1);
        }
    };
    println!("listening {}", l.local_addr().map(|a| a.port()).unwrap_or(0));
    for s in l.incoming().flatten() {
        std::thread::spawn(move || serve(s));
    }
}
