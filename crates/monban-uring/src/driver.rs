//! The driver thread: sole owner of the ring, the listening socket, every connection fd and every in-flight buffer.
//!
//! Streams and the listener talk to it over a channel ([`Cmd`]) and wake it through a socketpair whose read end has
//! a recv permanently armed on the ring (so the driver blocks only in `io_uring_enter`, never in epoll).

use std::collections::{HashMap, VecDeque};
use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::Waker;

use io_uring::{IoUring, Probe, SubmissionQueue, opcode, squeue, types};

use crate::stream::UringStream;
use crate::{UringConfig, UringError};

// Linux errno / flag values (asm-generic; identical on x86_64 and aarch64). The crate has no libc dependency.
pub(crate) const EINTR: i32 = 4;
pub(crate) const EIO: i32 = 5;
pub(crate) const EAGAIN: i32 = 11;
pub(crate) const EBUSY: i32 = 16;
pub(crate) const EPIPE: i32 = 32;
const ECONNABORTED: i32 = 103;
const ECANCELED: i32 = 125;
const SOCK_CLOEXEC: i32 = 0o2_000_000;
const MSG_NOSIGNAL: i32 = 0x4000;
const POLLIN: u32 = 0x1;
const POLLOUT: u32 = 0x4;
const SHUT_WR: i32 = 1;
const IPPROTO_TCP: u32 = 6;
const TCP_NODELAY: u32 = 1;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const WAKE_BUF: usize = 64;

/// How a ring is created. Production uses [`default_setup`]; tests inject failures (the EPERM path).
pub(crate) type Setup = dyn Fn(u32) -> io::Result<IoUring>;

pub(crate) fn default_setup(entries: u32) -> io::Result<IoUring> {
    IoUring::new(entries)
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Create a ring and prove it works: opcode probe (io_uring_register), NODROP, and one NOP (io_uring_enter).
pub(crate) fn open_ring(setup: &Setup, entries: u32) -> Result<IoUring, UringError> {
    let unavailable = |what: &str, e: io::Error| UringError::Unavailable(format!("{what} failed: {e}"));
    let mut ring = setup(entries).map_err(|e| unavailable("io_uring_setup", e))?;
    let mut probe = Probe::new();
    ring.submitter().register_probe(&mut probe).map_err(|e| unavailable("io_uring_register(PROBE)", e))?;
    let needed = [
        ("ACCEPT", opcode::Accept::CODE),
        ("RECV", opcode::Recv::CODE),
        ("SEND", opcode::Send::CODE),
        ("SHUTDOWN", opcode::Shutdown::CODE),
        ("CLOSE", opcode::Close::CODE),
        ("ASYNC_CANCEL", opcode::AsyncCancel::CODE),
        ("POLL_ADD", opcode::PollAdd::CODE),
        ("TIMEOUT", opcode::Timeout::CODE),
    ];
    for (name, code) in needed {
        if !probe.is_supported(code) {
            return Err(UringError::Unavailable(format!("kernel io_uring lacks IORING_OP_{name}")));
        }
    }
    if !ring.params().is_feature_nodrop() {
        return Err(UringError::Unavailable("kernel io_uring lacks IORING_FEAT_NODROP".into()));
    }
    let nop = opcode::Nop::new().build().user_data(u64::MAX);
    if push(&mut ring.submission(), &nop).is_err() {
        return Err(UringError::Unavailable("io_uring submission queue has no slot for the probe".into()));
    }
    loop {
        match ring.submit_and_wait(1) {
            Ok(_) => break,
            Err(e) if e.raw_os_error() == Some(EINTR) => {}
            Err(e) => return Err(unavailable("io_uring_enter", e)),
        }
    }
    let ok = ring.completion().any(|c| c.user_data() == u64::MAX && c.result() == 0);
    if !ok {
        return Err(UringError::Unavailable("io_uring NOP probe did not complete".into()));
    }
    Ok(ring)
}

/// The only `unsafe` in the crate (DEVIATIONS X-19 cap 6; this crate uses 1).
fn push(sq: &mut SubmissionQueue<'_>, e: &squeue::Entry) -> Result<(), squeue::PushError> {
    // SAFETY: every pointer inside `e` was built by `Driver::entry` from heap memory owned by the operation table
    // (`Driver::ops`): a `Vec<u8>` data buffer that is not resized or read while its op is listed, or a `Box`ed
    // sockaddr / i32 / Timespec / wake buffer. An op leaves the table only when its CQE is reaped (`Driver::reap`),
    // and moving the `Op` value (HashMap rehash) moves only the Vec/Box handle, never the heap memory the kernel
    // holds. Streams never touch a buffer while it is listed: they hand it over by value with `Cmd::Recv`/`Cmd::Send`
    // and get it back by value after the CQE. A dropped stream's ops are cancelled and reaped before the fd is
    // closed; if the ring itself fails, `Driver::run` leaks the table instead of freeing it. The NOP probe entry
    // carries no pointers. fds named in entries stay open until their ops are reaped (Close is issued last).
    #[allow(unsafe_code)]
    unsafe {
        sq.push(e)
    }
}

/// A request from a stream or the listener to the driver.
#[derive(Debug)]
pub(crate) enum Cmd {
    Accept,
    StopAccept,
    Recv { conn: u64, buf: Vec<u8> },
    Send { conn: u64, buf: Vec<u8> },
    Shutdown { conn: u64 },
    Close { conn: u64 },
}

/// The caller side of the driver: shared by the listener and every stream. When the last one drops, the wake
/// socket's write end closes and the driver sees EOF on its armed recv.
#[derive(Debug)]
pub(crate) struct Handle {
    tx: Sender<Cmd>,
    wake_tx: UnixStream,
    wake_flag: Arc<AtomicBool>,
}

impl Handle {
    pub(crate) fn send(&self, c: Cmd) -> io::Result<()> {
        self.tx.send(c).map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "io_uring driver stopped"))?;
        // A set flag means a wake byte is unread or its CQE is unhandled; the driver clears it before draining.
        if !self.wake_flag.swap(true, Ordering::SeqCst) {
            let _ = (&self.wake_tx).write(&[1u8]); // WouldBlock: bytes already pending, the driver will wake.
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sd {
    Idle,
    Busy,
    Done(Option<i32>),
}

/// Per-connection state shared between one [`UringStream`] and the driver.
#[derive(Debug)]
pub(crate) struct ConnState {
    /// Last received bytes: `rd[rd_pos..rd_len]` is unread.
    pub(crate) rd: Vec<u8>,
    pub(crate) rd_pos: usize,
    pub(crate) rd_len: usize,
    pub(crate) rd_busy: bool,
    pub(crate) rd_eof: bool,
    pub(crate) rd_err: Option<i32>,
    pub(crate) rd_waker: Option<Waker>,
    pub(crate) wr_spare: Vec<u8>,
    pub(crate) wr_busy: bool,
    pub(crate) wr_err: Option<i32>,
    pub(crate) wr_waker: Option<Waker>,
    pub(crate) sd: Sd,
}

impl ConnState {
    fn new() -> Self {
        ConnState {
            rd: Vec::new(),
            rd_pos: 0,
            rd_len: 0,
            rd_busy: false,
            rd_eof: false,
            rd_err: None,
            rd_waker: None,
            wr_spare: Vec::new(),
            wr_busy: false,
            wr_err: None,
            wr_waker: None,
            sd: Sd::Idle,
        }
    }
}

/// Accepted connections not yet claimed by `poll_accept`, plus accept errors (errno).
#[derive(Debug, Default)]
pub(crate) struct ListenState {
    pub(crate) ready: VecDeque<Result<(UringStream, SocketAddr), i32>>,
    pub(crate) busy: bool,
    pub(crate) dead: Option<i32>,
    pub(crate) waker: Option<Waker>,
}

fn wake(w: &mut Option<Waker>) {
    if let Some(w) = w.take() {
        w.wake();
    }
}

#[repr(C, align(8))]
#[derive(Debug)]
struct AddrBuf {
    storage: [u8; 128],
    len: u32,
}

#[derive(Debug)]
enum Kind {
    Wake(Box<[u8; WAKE_BUF]>),
    Accept(Box<AddrBuf>),
    Recv(Vec<u8>),
    Send(Vec<u8>, usize),
    Shutdown,
    NoDelay(Box<i32>),
    Linger(Box<types::Timespec>),
    Close,
    Cancel(u64),
}

#[derive(Debug)]
struct Op {
    conn: Option<u64>,
    /// The SQE currently in flight for this op is a POLL_ADD (after EAGAIN), not the op itself.
    poll: bool,
    kind: Kind,
}

#[derive(Debug)]
struct Conn {
    fd: RawFd,
    st: Arc<Mutex<ConnState>>,
    ops: Vec<u64>,
    closing: bool,
    /// The linger timer fired: in-flight sends are being cancelled and must not be resubmitted.
    abort: bool,
    linger: Option<u64>,
    linger_cancelled: bool,
    close_started: bool,
}

struct Driver {
    ring: IoUring,
    rx: Receiver<Cmd>,
    handle: Weak<Handle>,
    wake_rx: UnixStream,
    wake_flag: Arc<AtomicBool>,
    listener: TcpListener,
    listen: Arc<Mutex<ListenState>>,
    cfg: UringConfig,
    ops: HashMap<u64, Op>,
    conns: HashMap<u64, Conn>,
    backlog: VecDeque<squeue::Entry>,
    next_id: u64,
    accept_op: Option<u64>,
    accept_stopped: bool,
    wake_eof: bool,
    cqes: Vec<(u64, i32)>,
}

/// What `UringListener` keeps after a successful start.
pub(crate) struct Started {
    pub(crate) handle: Arc<Handle>,
    pub(crate) listen: Arc<Mutex<ListenState>>,
    pub(crate) local: SocketAddr,
    pub(crate) fd: RawFd,
    pub(crate) ring_fd: RawFd,
}

/// Open the ring (fail closed), then move it, the listener and the wake socket onto a new driver thread.
pub(crate) fn start(listener: TcpListener, cfg: UringConfig, setup: &Setup) -> Result<Started, UringError> {
    cfg.check()?;
    let ring = open_ring(setup, cfg.sq_entries)?; // on Err the listener drops here: nothing is ever accepted
    let start_err = |what: &str, e: io::Error| UringError::Start(format!("{what}: {e}"));
    let local = listener.local_addr().map_err(|e| start_err("listener local_addr", e))?;
    let fd = listener.as_raw_fd();
    let ring_fd = ring.as_raw_fd();
    let (wake_tx, wake_rx) = UnixStream::pair().map_err(|e| start_err("wake socketpair", e))?;
    wake_tx.set_nonblocking(true).map_err(|e| start_err("wake socket", e))?;
    let (tx, rx) = mpsc::channel();
    let wake_flag = Arc::new(AtomicBool::new(false));
    let handle = Arc::new(Handle { tx, wake_tx, wake_flag: wake_flag.clone() });
    let listen = Arc::new(Mutex::new(ListenState::default()));
    let mut d = Driver {
        ring,
        rx,
        handle: Arc::downgrade(&handle),
        wake_rx,
        wake_flag,
        listener,
        listen: listen.clone(),
        cfg,
        ops: HashMap::new(),
        conns: HashMap::new(),
        backlog: VecDeque::new(),
        next_id: 1,
        accept_op: None,
        accept_stopped: false,
        wake_eof: false,
        cqes: Vec::new(),
    };
    d.start_op(None, Kind::Wake(Box::new([0u8; WAKE_BUF])));
    std::thread::Builder::new()
        .name("monban-uring".into())
        .spawn(move || d.run())
        .map_err(|e| start_err("spawn driver thread", e))?;
    Ok(Started { handle, listen, local, fd, ring_fd })
}

impl Driver {
    fn run(mut self) {
        loop {
            self.drain_cmds();
            if self.wake_eof && self.ops.is_empty() && self.backlog.is_empty() {
                return; // every handle is gone and every op reaped: dropping the ring and listener is safe
            }
            let r = self.pump().and_then(|()| {
                let want = usize::from(self.backlog.is_empty());
                self.ring.submit_and_wait(want)
            });
            match r {
                Ok(_) => {}
                Err(e) if matches!(e.raw_os_error(), Some(EINTR | EBUSY | EAGAIN)) => {}
                Err(e) => return self.fail(e.raw_os_error().unwrap_or(EIO)),
            }
            self.reap();
        }
    }

    /// The ring is unusable: report the error to every waiter, then leak every in-flight buffer (the kernel may still
    /// reference them while it tears the ring down) and every open fd rather than free or close them.
    fn fail(mut self, errno: i32) {
        for c in self.conns.values() {
            let mut st = lock(&c.st);
            st.rd_err.get_or_insert(errno);
            st.wr_err.get_or_insert(errno);
            st.rd_busy = false;
            st.wr_busy = false;
            if st.sd == Sd::Busy {
                st.sd = Sd::Done(Some(errno));
            }
            wake(&mut st.rd_waker);
            wake(&mut st.wr_waker);
        }
        let stale: Vec<_> = {
            let mut ls = lock(&self.listen);
            ls.dead = Some(errno);
            ls.busy = false;
            wake(&mut ls.waker);
            ls.ready.drain(..).collect()
        };
        std::mem::forget(stale); // their Drop would only send to this (stopping) driver
        std::mem::forget(std::mem::take(&mut self.ops));
        std::mem::forget(std::mem::take(&mut self.conns));
        std::mem::forget(self.listener);
    }

    fn drain_cmds(&mut self) {
        while let Ok(c) = self.rx.try_recv() {
            self.cmd(c);
        }
        if self.wake_eof {
            let ids: Vec<u64> = self.conns.keys().copied().collect();
            for id in ids {
                self.close_conn(id);
            }
            if !self.accept_stopped {
                self.stop_accept();
            }
        }
    }

    fn cmd(&mut self, c: Cmd) {
        match c {
            Cmd::Accept => {
                if self.accept_op.is_none() && !self.accept_stopped {
                    let a = Box::new(AddrBuf { storage: [0u8; 128], len: 128 });
                    self.accept_op = Some(self.start_op(None, Kind::Accept(a)));
                }
            }
            Cmd::StopAccept => self.stop_accept(),
            Cmd::Recv { conn, buf } => self.conn_op(conn, Kind::Recv(buf)),
            Cmd::Send { conn, buf } => self.conn_op(conn, Kind::Send(buf, 0)),
            Cmd::Shutdown { conn } => self.conn_op(conn, Kind::Shutdown),
            Cmd::Close { conn } => self.close_conn(conn),
        }
    }

    fn conn_op(&mut self, conn: u64, kind: Kind) {
        if self.conns.get(&conn).is_some_and(|c| !c.closing) {
            self.start_op(Some(conn), kind);
        }
    }

    fn stop_accept(&mut self) {
        self.accept_stopped = true;
        if let Some(a) = self.accept_op {
            self.start_op(None, Kind::Cancel(a));
        }
        let stale: Vec<_> = {
            let mut ls = lock(&self.listen);
            ls.busy = false;
            ls.ready.drain(..).collect()
        };
        drop(stale); // each stream's Drop queues Cmd::Close to this driver
    }

    fn close_conn(&mut self, id: u64) {
        let mut cancel = Vec::new();
        let mut linger = false;
        {
            let Some(c) = self.conns.get_mut(&id) else { return };
            if c.closing {
                return;
            }
            c.closing = true;
            for op in &c.ops {
                match self.ops.get(op).map(|o| &o.kind) {
                    Some(Kind::Recv(_)) => cancel.push(*op),
                    Some(Kind::Send(..)) => linger = true,
                    _ => {}
                }
            }
        }
        for op in cancel {
            self.start_op(None, Kind::Cancel(op));
        }
        if linger {
            let secs = self.cfg.linger.as_secs();
            let ts = Box::new(types::Timespec::new().sec(secs).nsec(self.cfg.linger.subsec_nanos()));
            let t = self.start_op(Some(id), Kind::Linger(ts));
            if let Some(c) = self.conns.get_mut(&id) {
                c.linger = Some(t);
            }
        }
        self.maybe_finish(id);
    }

    /// A closing connection whose data ops are all reaped: stop the linger timer, then close the fd (last).
    fn maybe_finish(&mut self, id: u64) {
        let Some(c) = self.conns.get_mut(&id) else { return };
        if !c.closing || c.close_started {
            return;
        }
        let linger = c.linger;
        if c.ops.iter().any(|o| Some(*o) != linger) {
            return;
        }
        match linger {
            Some(t) => {
                if !c.linger_cancelled {
                    c.linger_cancelled = true;
                    self.start_op(None, Kind::Cancel(t));
                }
            }
            None => {
                c.close_started = true;
                self.start_op(Some(id), Kind::Close);
            }
        }
    }

    fn start_op(&mut self, conn: Option<u64>, kind: Kind) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.insert(id, Op { conn, poll: false, kind });
        id
    }

    /// List `op` under `id` (and under its connection), then queue its SQE.
    fn insert(&mut self, id: u64, op: Op) {
        if let Some(c) = op.conn.and_then(|c| self.conns.get_mut(&c)) {
            c.ops.push(id);
        }
        self.ops.insert(id, op);
        if let Some(e) = self.entry(id) {
            self.backlog.push_back(e);
        }
    }

    /// Build the SQE for a listed op. Pointers come only from the op's own heap allocations (see `push`).
    fn entry(&mut self, id: u64) -> Option<squeue::Entry> {
        let op = self.ops.get_mut(&id)?;
        let fd = match &op.kind {
            Kind::Wake(_) => self.wake_rx.as_raw_fd(),
            Kind::Accept(_) => self.listener.as_raw_fd(),
            Kind::Cancel(_) => -1,
            _ => self.conns.get(&op.conn?)?.fd,
        };
        let fd = types::Fd(fd);
        let e = match &mut op.kind {
            Kind::Accept(_) | Kind::Recv(_) if op.poll => opcode::PollAdd::new(fd, POLLIN).build(),
            Kind::Send(..) if op.poll => opcode::PollAdd::new(fd, POLLOUT).build(),
            Kind::Wake(b) => opcode::Recv::new(fd, b.as_mut_ptr(), WAKE_BUF as u32).build(),
            Kind::Accept(a) => {
                a.len = 128;
                opcode::Accept::new(fd, a.storage.as_mut_ptr().cast(), &mut a.len).flags(SOCK_CLOEXEC).build()
            }
            Kind::Recv(b) => {
                let len = u32::try_from(b.len()).unwrap_or(u32::MAX);
                opcode::Recv::new(fd, b.as_mut_ptr(), len).build()
            }
            Kind::Send(b, off) => {
                let rest = b.get(*off..).unwrap_or(&[]);
                let len = u32::try_from(rest.len()).unwrap_or(u32::MAX);
                opcode::Send::new(fd, rest.as_ptr(), len).flags(MSG_NOSIGNAL).build()
            }
            Kind::Shutdown => opcode::Shutdown::new(fd, SHUT_WR).build(),
            Kind::NoDelay(v) => {
                let p: *const i32 = &**v;
                opcode::SetSockOpt::new(fd, IPPROTO_TCP, TCP_NODELAY, p.cast(), 4).build()
            }
            Kind::Linger(ts) => {
                let p: *const types::Timespec = &**ts;
                opcode::Timeout::new(p).build()
            }
            Kind::Close => opcode::Close::new(fd).build(),
            Kind::Cancel(target) => opcode::AsyncCancel::new(*target).build(),
        };
        Some(e.user_data(id))
    }

    /// Move queued SQEs into the bounded submission queue, submitting whenever it fills.
    fn pump(&mut self) -> io::Result<()> {
        loop {
            {
                let mut sq = self.ring.submission();
                while let Some(e) = self.backlog.front() {
                    if push(&mut sq, e).is_err() {
                        break;
                    }
                    self.backlog.pop_front();
                }
            }
            if self.backlog.is_empty() {
                return Ok(());
            }
            match self.ring.submit() {
                Ok(_) => {}
                Err(e) if e.raw_os_error() == Some(EBUSY) => return Ok(()), // CQ backed up: reap first
                Err(e) if e.raw_os_error() == Some(EINTR) => {}
                Err(e) => return Err(e),
            }
        }
    }

    fn reap(&mut self) {
        let mut cqes = std::mem::take(&mut self.cqes);
        cqes.clear();
        cqes.extend(self.ring.completion().map(|c| (c.user_data(), c.result())));
        for &(id, res) in &cqes {
            self.complete(id, res);
        }
        self.cqes = cqes;
    }

    /// Re-list an op whose SQE must be issued again (short send, EAGAIN → poll, poll → retry, EINTR).
    fn again(&mut self, id: u64, op: Op) {
        self.insert(id, op);
    }

    fn complete(&mut self, id: u64, res: i32) {
        let Some(mut op) = self.ops.remove(&id) else { return };
        let conn = op.conn;
        let (closing, abort) = match conn.and_then(|c| self.conns.get_mut(&c)) {
            Some(c) => {
                c.ops.retain(|o| *o != id);
                (c.closing, c.abort)
            }
            None => (false, false),
        };
        let errno = if res < 0 { res.saturating_neg() } else { 0 };
        if op.poll {
            // POLL_ADD fired (or failed): retry the real op, which reports any real error.
            op.poll = false;
            let keep = match op.kind {
                Kind::Accept(_) => !self.accept_stopped,
                Kind::Recv(_) => !closing,
                Kind::Send(..) => !abort,
                _ => false,
            };
            if keep {
                self.again(id, op);
            } else {
                self.op_dropped(id, op, errno);
            }
            if let Some(c) = conn {
                self.maybe_finish(c);
            }
            return;
        }
        match op.kind {
            Kind::Wake(_) => {
                if res > 0 {
                    self.wake_flag.store(false, Ordering::SeqCst);
                    self.again(id, op);
                } else if errno == EINTR || errno == EAGAIN {
                    self.again(id, op);
                } else {
                    self.wake_eof = true; // EOF: the last Handle dropped (or the wake socket broke)
                }
            }
            Kind::Accept(ref a) => {
                if res >= 0 {
                    self.accept_op = None;
                    let peer = parse_sockaddr(a);
                    self.accepted(res, peer);
                } else if !self.accept_stopped && (errno == EAGAIN) {
                    op.poll = true;
                    self.again(id, op);
                } else if !self.accept_stopped && (errno == EINTR || errno == ECONNABORTED) {
                    self.again(id, op);
                } else {
                    self.accept_op = None;
                    let mut ls = lock(&self.listen);
                    ls.busy = false;
                    if !self.accept_stopped && errno != ECANCELED {
                        ls.ready.push_back(Err(errno));
                    }
                    wake(&mut ls.waker);
                }
            }
            Kind::Recv(mut buf) => {
                let st = conn.and_then(|c| self.conns.get(&c)).map(|c| c.st.clone());
                if !closing && errno == EAGAIN {
                    op.kind = Kind::Recv(buf);
                    op.poll = true;
                    self.again(id, op);
                } else if !closing && errno == EINTR {
                    op.kind = Kind::Recv(buf);
                    self.again(id, op);
                } else if let (false, Some(st)) = (closing, st) {
                    let mut s = lock(&st);
                    match usize::try_from(res) {
                        Ok(0) => s.rd_eof = true,
                        Ok(n) => {
                            s.rd_len = n.min(buf.len());
                            s.rd_pos = 0;
                        }
                        Err(_) => s.rd_err = Some(errno),
                    }
                    if res <= 0 {
                        buf.clear();
                        s.rd_len = 0;
                        s.rd_pos = 0;
                    }
                    s.rd = buf;
                    s.rd_busy = false;
                    wake(&mut s.rd_waker);
                }
            }
            Kind::Send(buf, off) => {
                let st = conn.and_then(|c| self.conns.get(&c)).map(|c| c.st.clone());
                let sent = usize::try_from(res).unwrap_or(0);
                let off = off.saturating_add(sent);
                if res > 0 && off < buf.len() && !abort {
                    op.kind = Kind::Send(buf, off);
                    self.again(id, op);
                } else if !abort && (errno == EAGAIN || errno == EINTR) {
                    op.poll = errno == EAGAIN;
                    op.kind = Kind::Send(buf, off);
                    self.again(id, op);
                } else if let Some(st) = st {
                    let mut s = lock(&st);
                    if res < 0 {
                        s.wr_err = Some(errno);
                    } else if off < buf.len() {
                        s.wr_err = Some(if abort { ECANCELED } else { EPIPE });
                    }
                    let mut buf = buf;
                    buf.clear();
                    s.wr_spare = buf;
                    s.wr_busy = false;
                    wake(&mut s.wr_waker);
                }
            }
            Kind::Shutdown => {
                if let Some(st) = conn.and_then(|c| self.conns.get(&c)) {
                    let mut s = lock(&st.st);
                    s.sd = Sd::Done((res < 0).then_some(errno));
                    wake(&mut s.wr_waker);
                }
            }
            Kind::Linger(_) => {
                // Fired (ETIME) or cancelled: abort whatever is still draining, then finish the close.
                let mut sends = Vec::new();
                if let Some(c) = conn.and_then(|c| self.conns.get_mut(&c)) {
                    c.linger = None;
                    c.abort = true;
                    sends.clone_from(&c.ops);
                }
                for s in sends {
                    self.start_op(None, Kind::Cancel(s));
                }
            }
            Kind::Close => {
                if let Some(c) = conn {
                    self.conns.remove(&c);
                }
                return;
            }
            Kind::NoDelay(_) | Kind::Cancel(_) => {}
        }
        if let Some(c) = conn {
            self.maybe_finish(c);
        }
    }

    /// A poll-mode op that will not be retried: report it as finished to its owner.
    fn op_dropped(&mut self, _id: u64, op: Op, errno: i32) {
        let errno = if errno == 0 { ECANCELED } else { errno };
        match op.kind {
            Kind::Accept(_) => {
                self.accept_op = None;
                let mut ls = lock(&self.listen);
                ls.busy = false;
                wake(&mut ls.waker);
            }
            Kind::Send(mut buf, _) => {
                if let Some(c) = op.conn.and_then(|c| self.conns.get(&c)) {
                    let mut s = lock(&c.st);
                    s.wr_err = Some(errno);
                    buf.clear();
                    s.wr_spare = buf;
                    s.wr_busy = false;
                    wake(&mut s.wr_waker);
                }
            }
            _ => {}
        }
    }

    fn accepted(&mut self, fd: RawFd, peer: Option<SocketAddr>) {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let st = Arc::new(Mutex::new(ConnState::new()));
        self.conns.insert(
            id,
            Conn {
                fd,
                st: st.clone(),
                ops: Vec::new(),
                closing: false,
                abort: false,
                linger: None,
                linger_cancelled: false,
                close_started: false,
            },
        );
        let handle = if self.accept_stopped { None } else { self.handle.upgrade() };
        let (Some(handle), Some(peer)) = (handle, peer) else {
            self.close_conn(id); // listener gone, or an address family we do not serve
            let mut ls = lock(&self.listen);
            ls.busy = false;
            wake(&mut ls.waker);
            return;
        };
        self.start_op(Some(id), Kind::NoDelay(Box::new(1)));
        let stream = UringStream::new(id, fd, st, handle, peer, self.cfg.max_io);
        let mut ls = lock(&self.listen);
        ls.busy = false;
        ls.ready.push_back(Ok((stream, peer)));
        wake(&mut ls.waker);
    }
}

fn parse_sockaddr(a: &AddrBuf) -> Option<SocketAddr> {
    let b = &a.storage;
    let fam = u16::from_ne_bytes([*b.first()?, *b.get(1)?]);
    let port = u16::from_be_bytes([*b.get(2)?, *b.get(3)?]);
    match fam {
        AF_INET => {
            let ip: [u8; 4] = b.get(4..8)?.try_into().ok()?;
            Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
        }
        AF_INET6 => {
            let flow = u32::from_ne_bytes(b.get(4..8)?.try_into().ok()?);
            let ip: [u8; 16] = b.get(8..24)?.try_into().ok()?;
            let scope = u32::from_ne_bytes(b.get(24..28)?.try_into().ok()?);
            // Like std's accept: a v4-mapped peer on a dual-stack socket stays a V6 address.
            Some(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, flow, scope)))
        }
        _ => None,
    }
}

#[cfg(test)]
pub(crate) fn parse_for_test(storage: [u8; 128]) -> Option<SocketAddr> {
    parse_sockaddr(&AddrBuf { storage, len: 128 })
}
