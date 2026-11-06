//! Bounded log queue (drop-oldest, with a counter) and the bounded stdin line reader that feeds it.

use std::collections::VecDeque;
use std::io::BufRead;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use crate::logs;

/// Most queued records.
pub const QUEUE_RECORDS: usize = 10_000;
/// Most queued encoded bytes.
pub const QUEUE_BYTES: usize = 16 * 1024 * 1024;

/// Encoded `LogRecord`s waiting for export.
#[derive(Debug, Default)]
pub struct LogQueue {
    recs: VecDeque<String>,
    bytes: usize,
    dropped: u64,
}

impl LogQueue {
    /// Push, dropping the oldest records while either cap would be exceeded.
    pub fn push(&mut self, rec: String) {
        while !self.recs.is_empty() && (self.recs.len() >= QUEUE_RECORDS || self.bytes + rec.len() > QUEUE_BYTES) {
            if let Some(old) = self.recs.pop_front() {
                self.bytes = self.bytes.saturating_sub(old.len());
                self.dropped = self.dropped.saturating_add(1);
            }
        }
        self.bytes = self.bytes.saturating_add(rec.len());
        self.recs.push_back(rec);
    }

    /// Take everything queued.
    pub fn drain(&mut self) -> Vec<String> {
        self.bytes = 0;
        self.recs.drain(..).collect()
    }

    /// Queued record count.
    pub fn len(&self) -> usize {
        self.recs.len()
    }

    /// Records dropped so far (queue full).
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// State shared between the stdin reader thread and the exporter loop.
#[derive(Debug, Default)]
pub struct Shared {
    queue: Mutex<LogQueue>,
    /// Set when stdin reached EOF (or failed).
    pub eof: AtomicBool,
}

impl Shared {
    /// Lock the queue (a poisoned lock is still usable: the queue has no invariant a panic could break midway).
    pub fn queue(&self) -> MutexGuard<'_, LogQueue> {
        self.queue.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Read one line (without `\n` and a trailing `\r`), holding at most `logs::MAX_LINE + 1` bytes; the remainder of
/// a longer line is discarded. Returns `None` at EOF, else `(line, truncated)`.
pub fn read_line(r: &mut impl BufRead) -> std::io::Result<Option<(Vec<u8>, bool)>> {
    let mut line = Vec::new();
    let mut over = false;
    let mut any = false;
    loop {
        let buf = match r.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if buf.is_empty() {
            break;
        }
        any = true;
        let (chunk, used, done) = match buf.iter().position(|&b| b == b'\n') {
            Some(i) => (buf.get(..i).unwrap_or(&[]), i + 1, true),
            None => (buf, buf.len(), false),
        };
        let room = (logs::MAX_LINE + 1).saturating_sub(line.len());
        if chunk.len() > room {
            over = true;
        }
        line.extend_from_slice(chunk.get(..room.min(chunk.len())).unwrap_or(&[]));
        r.consume(used);
        if done {
            break;
        }
    }
    if !any {
        return Ok(None);
    }
    if line.last() == Some(&b'\r') && !over {
        line.pop();
    }
    let truncated = over || line.len() > logs::MAX_LINE;
    if truncated {
        let keep = logs::truncate(&line).len();
        line.truncate(keep);
    }
    Ok(Some((line, truncated)))
}

/// Read stdin to EOF, encoding each non-empty line into the queue.
pub fn pump(shared: &Shared, r: &mut impl BufRead) {
    loop {
        match read_line(r) {
            Ok(Some((line, truncated))) => {
                if line.is_empty() {
                    continue;
                }
                let rec = logs::record(&line, truncated, crate::now_ns());
                shared.queue().push(rec);
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("aegis-otlp: stdin: {e}");
                break;
            }
        }
    }
    shared.eof.store(true, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_oldest() {
        let mut q = LogQueue::default();
        for i in 0..(QUEUE_RECORDS + 3) {
            q.push(i.to_string());
        }
        assert_eq!(q.len(), QUEUE_RECORDS);
        assert_eq!(q.dropped(), 3);
        assert_eq!(q.drain().first().map(String::as_str), Some("3"));
    }

    #[test]
    fn lines_bounded() {
        let mut data = vec![b'x'; 100 * 1024];
        data.extend_from_slice(b"\nok\r\nlast");
        let mut r = std::io::Cursor::new(data);
        let a = read_line(&mut r).ok().flatten();
        assert!(a.as_ref().is_some_and(|(l, t)| l.len() == logs::MAX_LINE && *t));
        assert_eq!(read_line(&mut r).ok().flatten(), Some((b"ok".to_vec(), false)));
        assert_eq!(read_line(&mut r).ok().flatten(), Some((b"last".to_vec(), false)));
        assert_eq!(read_line(&mut r).ok().flatten(), None);
    }
}
