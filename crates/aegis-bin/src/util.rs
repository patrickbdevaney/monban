//! Small async and byte helpers (tokio is built without `macros`, so no `select!`).

use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::Poll;
use std::time::{SystemTime, UNIX_EPOCH};

/// Which of two futures finished first.
#[derive(Debug)]
pub enum Either<A, B> {
    Left(A),
    Right(B),
}

/// Poll `a` then `b`; return the first that is ready (the other is dropped).
pub async fn race<A: Future, B: Future>(a: A, b: B) -> Either<A::Output, B::Output> {
    let mut a = pin!(a);
    let mut b = pin!(b);
    poll_fn(|cx| {
        if let Poll::Ready(v) = a.as_mut().poll(cx) {
            return Poll::Ready(Either::Left(v));
        }
        if let Poll::Ready(v) = b.as_mut().poll(cx) {
            return Poll::Ready(Either::Right(v));
        }
        Poll::Pending
    })
    .await
}

/// Wall clock in Unix milliseconds (audit timestamps only; never used for deadlines).
pub fn unix_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)).unwrap_or(0)
}

/// Wall clock in Unix seconds.
pub fn unix_s() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX)).unwrap_or(0)
}

/// Index of the first `\r\n\r\n` in `buf`, if any (the index of its first byte).
pub fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// RFC 9110 tchar.
pub fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Field value bytes allowed on output (visible ASCII, SP, HTAB; no CR/LF/NUL/DEL, no obs-text).
pub fn is_field_value(v: &[u8]) -> bool {
    v.iter().all(|&b| (0x20..0x7F).contains(&b) || b == b'\t')
}

/// Trim optional whitespace (SP / HTAB) at both ends.
pub fn trim_ows(v: &[u8]) -> &[u8] {
    let start = v.iter().position(|&b| b != b' ' && b != b'\t').unwrap_or(v.len());
    let end = v.iter().rposition(|&b| b != b' ' && b != b'\t').map_or(start, |e| e.saturating_add(1));
    v.get(start..end).unwrap_or(b"")
}

/// Reason phrase for the statuses this binary produces (the phrase is informational, RFC 9112 §4).
pub fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        417 => "Expectation Failed",
        421 => "Misdirected Request",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\nx"), Some(14));
        assert_eq!(trim_ows(b" \t a b \t"), b"a b");
        assert!(is_field_value(b"a b\tc") && !is_field_value(b"a\r\nb"));
    }
}
