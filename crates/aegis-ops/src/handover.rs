//! IO drivers for the zero-downtime upgrade (ARCHITECTURE §3.11, UP-1..7, F11).
//!
//! Parent ([`upgrade`]):
//! 1. UP-6 precondition: every fd above 2 is CLOEXEC, so only the listener fds placed on purpose cross exec.
//! 2. Create a fresh 0700 directory (owner and mode re-checked without following symlinks) holding an AF_UNIX
//!    SOCK_SEQPACKET handover socket and a FIFO.
//! 3. UP-5: write the STEK ring to the FIFO (pipe) before spawning; keys never go over the socket, argv or env.
//! 4. Spawn the new binary (only stdio crosses exec; stdin is /dev/null).
//! 5. Authenticate the peer with SO_PEERCRED (pid = spawned child, same uid) and `/proc/<pid>/exe`.
//! 6. Run [`ParentMachine`]: `hello` → `listeners` with the listener fds attached as one SCM_RIGHTS array in the
//!    same order (never a second `SO_REUSEPORT` bind: both processes hold the *same* listening sockets, so no
//!    queued connection is reset) → `ready` (exact claim) → close own listener fds → `drain` →
//!    two-phase drain bounded by the deadline → `done` → exit. Any failure before `ready`: kill and reap the child,
//!    remove the directory, keep serving (UP-7).
//!
//! Child ([`child_takeover`] then [`Takeover::ready`]): check the directory, read the STEK from the FIFO, connect,
//! check the parent's SO_PEERCRED, require that no fd above 2 leaked through exec (UP-6), send `hello`, receive
//! `listeners` and its SCM_RIGHTS fds, validate each received fd (UP-2) and claim or close it, start accepting,
//! send `ready`, wait for `drain` (or give up waiting, but never give the sockets back: UP-1).
//!
//! **Transport (F11, P2-upgrade-002).** The fds travel by SCM_RIGHTS on the authenticated SEQPACKET socket, in the
//! same packet as `listeners`, fd *i* = `listeners[i]`. rustix's safe `recvmsg` hands them over as `OwnedFd`
//! (received with `MSG_CMSG_CLOEXEC`), so this crate needs no `unsafe`. Receive rules, all fail-closed:
//! * at most [`MAX_HANDOVER_LISTENERS`] fds per handover (the control buffer is sized for that many);
//! * `MSG_CTRUNC` (control data did not fit) or more fds than the cap: every received fd is closed and the packet
//!   is reported as [`Recv::CtlTrunc`]; the child aborts the handover and the parent keeps serving;
//! * fds attached to any packet other than `listeners`, or an fd count different from the `listeners` length: every
//!   fd is closed and the handover aborts;
//! * the parent receives with no control buffer at all, so any fd the child sends is discarded by the kernel and
//!   the resulting `MSG_CTRUNC` fails the upgrade (child killed, parent serving).
//!
//! Residual: if the child dies after sending `ready` and before the parent has closed its copies, the sockets stay
//! open in the parent until it exits; if it dies after that, the listeners are gone (no process holds them). The
//! window is between the child's `ready` and its death, i.e. a crash of a child that already accepted traffic.

use crate::cloexec;
use crate::fdcheck;
use crate::machine::{ChildAction, ChildEvent, ChildMachine, ParentAction, ParentEvent, ParentMachine, ParentState};
use crate::notify::Notifier;
use crate::stek::{self, StekRing};
use crate::wire::{self, CONFIG_HASH_LEN, ListenerDesc, MAX_FRAME, Msg};

use nix::sys::socket::{
    AddressFamily, Backlog, SockFlag, SockType, UnixAddr, bind, connect, getsockopt, listen, socket, sockopt,
};
use nix::sys::stat::Mode;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer, SendAncillaryMessage,
    SendFlags, recvmsg, sendmsg,
};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::net::TcpListener;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Environment variable carrying the handover directory to the child.
pub const ENV_DIR: &str = "AEGIS_UPGRADE_DIR";
/// Maximum listeners (= SCM_RIGHTS fds) in one handover. F11's codec allows up to [`wire::MAX_LISTENERS`] (253,
/// the kernel's SCM_MAX_FD); the transport caps a single `listeners` message at 64 so the control buffer stays small
/// (64 fds = 280 bytes of cmsg space). More listeners ⇒ the parent refuses the upgrade and keeps serving.
pub const MAX_HANDOVER_LISTENERS: usize = 64;
/// Alignment slack for the receive control buffer (rustix aligns its start to `cmsghdr`).
const CMSG_SLACK: usize = 8;
const SOCK_NAME: &str = "handover.sock";
const FIFO_NAME: &str = "stek.fifo";
const SLICE: Duration = Duration::from_millis(20);

/// Upgrade failure. Every variant leaves the parent serving with its listeners open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeError {
    /// The upgrade did not start (fd hygiene, directory, socket, spawn).
    Precondition(String),
    /// The child failed; it was killed and reaped.
    ChildFailed(String),
}

impl fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Precondition(s) => write!(f, "upgrade precondition failed: {s}"),
            Self::ChildFailed(s) => write!(f, "upgrade child failed: {s}"),
        }
    }
}

impl std::error::Error for UpgradeError {}

/// Parent-side configuration.
#[derive(Debug, Clone)]
pub struct ParentConfig {
    /// Binary to spawn (the new version).
    pub exe: PathBuf,
    /// Its arguments.
    pub args: Vec<OsString>,
    /// Directory in which the per-upgrade 0700 directory is created.
    pub runtime_dir: PathBuf,
    /// Deadline for the whole spawn → `ready` phase.
    pub handover_timeout: Duration,
    /// Drain deadline D (UP-4).
    pub drain_deadline: Duration,
    /// Refuse to upgrade if any fd above 2 lacks CLOEXEC (UP-6). Production: true.
    pub require_cloexec: bool,
    /// sd-notify.
    pub notifier: Notifier,
}

/// A listener offered to the child.
#[derive(Debug, Clone, Copy)]
pub struct Offered<'a> {
    /// Its descriptor.
    pub desc: &'a ListenerDesc,
    /// Its fd (this process keeps ownership).
    pub fd: BorrowedFd<'a>,
}

/// Callbacks into the server for the two steps only it can do.
pub trait ParentHooks {
    /// Stop accepting and close every fd this process holds for the offered listeners.
    fn close_listeners(&mut self);
    /// Two-phase drain bounded by `deadline`; returns the number of forced closes.
    fn drain(&mut self, deadline: Duration) -> u64;
}

/// A completed handover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handed {
    /// The child that now owns the listeners.
    pub child_pid: u32,
    /// Connections force-closed at the drain deadline.
    pub forced: u64,
}

fn own_uid() -> u32 {
    nix::unistd::getuid().as_raw()
}

/// The per-upgrade directory; removed on drop.
#[derive(Debug)]
struct HandoverDir {
    path: PathBuf,
}

impl HandoverDir {
    fn create(base: &Path) -> io::Result<Self> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
        let path = base.join(format!("aegis-upgrade-{}-{nanos:09}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        check_private_dir(&path)?;
        Ok(Self { path })
    }
}

impl Drop for HandoverDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// The directory must be a real directory (not a symlink), owned by us, mode exactly 0700.
fn check_private_dir(p: &Path) -> io::Result<()> {
    let m = fs::symlink_metadata(p)?;
    if !m.file_type().is_dir() || m.uid() != own_uid() || m.mode() & 0o777 != 0o700 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "handover dir is not a private 0700 directory"));
    }
    Ok(())
}

fn seqpacket() -> io::Result<std::os::fd::OwnedFd> {
    socket(AddressFamily::Unix, SockType::SeqPacket, SockFlag::SOCK_CLOEXEC, None).map_err(io::Error::from)
}

fn send_msg(s: &UnixStream, m: &Msg) -> io::Result<()> {
    send_msg_fds(s, m, &[])
}

/// Send one F11 frame as a single SEQPACKET packet, with `fds` attached as one SCM_RIGHTS array (in order).
fn send_msg_fds(s: &UnixStream, m: &Msg, fds: &[BorrowedFd<'_>]) -> io::Result<()> {
    if fds.len() > MAX_HANDOVER_LISTENERS {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "too many fds for one handover"));
    }
    let b = wire::encode(m).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut space =
        vec![MaybeUninit::<u8>::uninit(); if fds.is_empty() { 0 } else { rustix::cmsg_space!(ScmRights(fds.len())) }];
    let mut ctl = SendAncillaryBuffer::new(&mut space);
    if !fds.is_empty() && !ctl.push(SendAncillaryMessage::ScmRights(fds)) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "control buffer too small"));
    }
    let n = sendmsg(s, &[IoSlice::new(&b)], &mut ctl, SendFlags::NOSIGNAL).map_err(io::Error::from)?;
    if n != b.len() {
        return Err(io::Error::from(io::ErrorKind::WriteZero));
    }
    Ok(())
}

/// One read outcome on the SEQPACKET socket.
#[derive(Debug)]
enum Recv {
    /// A packet, with the fds that came with it (owned: dropping them closes them).
    Frame(Result<Msg, wire::WireError>, Vec<OwnedFd>),
    /// Control data was truncated (`MSG_CTRUNC`) or carried more fds than allowed; every received fd was closed.
    CtlTrunc,
    Eof,
    Idle,
}

/// Read one packet with a short timeout, accepting at most `fd_cap` SCM_RIGHTS fds (0: no control buffer, so the
/// kernel discards any fd sent and flags `MSG_CTRUNC`). A packet longer than MAX_FRAME arrives truncated to
/// MAX_FRAME + 1 bytes and is rejected as too long.
fn recv_msg(s: &UnixStream, buf: &mut [u8], wait: Duration, fd_cap: usize) -> io::Result<Recv> {
    s.set_read_timeout(Some(wait.max(Duration::from_millis(1))))?;
    let cap = fd_cap.min(MAX_HANDOVER_LISTENERS);
    let len = if cap == 0 { 0 } else { rustix::cmsg_space!(ScmRights(cap)) + CMSG_SLACK };
    let mut space = vec![MaybeUninit::<u8>::uninit(); len];
    recv_packet(s, buf, &mut space, cap)
}

/// `recvmsg` into `buf` with control buffer `space`; split out so tests can force `MSG_CTRUNC`.
fn recv_packet(s: &UnixStream, buf: &mut [u8], space: &mut [MaybeUninit<u8>], fd_cap: usize) -> io::Result<Recv> {
    let mut ctl = RecvAncillaryBuffer::new(space);
    let mut iov = [IoSliceMut::new(buf)];
    let r = match recvmsg(s, &mut iov, &mut ctl, RecvFlags::CMSG_CLOEXEC) {
        Ok(r) => r,
        Err(e) => {
            let e = io::Error::from(e);
            return match e.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => Ok(Recv::Idle),
                io::ErrorKind::ConnectionReset => Ok(Recv::Eof),
                _ => Err(e),
            };
        }
    };
    let mut fds: Vec<OwnedFd> = Vec::new();
    for m in ctl.drain() {
        if let RecvAncillaryMessage::ScmRights(it) = m {
            fds.extend(it);
        }
    }
    drop(ctl); // closes any fd left undrained
    if r.flags.contains(ReturnFlags::CTRUNC) || fds.len() > fd_cap {
        drop(fds);
        return Ok(Recv::CtlTrunc);
    }
    let n = r.bytes;
    if n == 0 {
        return Ok(Recv::Eof); // fds (if any) are dropped
    }
    if n > MAX_FRAME || r.flags.contains(ReturnFlags::TRUNC) {
        return Ok(Recv::Frame(Err(wire::WireError::TooLong), fds));
    }
    let frame = wire::decode(iov.first().and_then(|b| b.get(..n)).unwrap_or_default());
    Ok(Recv::Frame(frame, fds))
}

fn exe_matches(pid: u32, exe: &Path) -> bool {
    let (Ok(a), Ok(b)) = (fs::read_link(format!("/proc/{pid}/exe")), fs::canonicalize(exe)) else { return false };
    a == b
}

fn reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Perform one upgrade. `Ok` means the child owns the listeners, this process has drained and must exit now.
/// `Err` means the parent is untouched and still serving (UP-7).
pub fn upgrade(
    cfg: &ParentConfig,
    offered: &[Offered<'_>],
    ring: &StekRing,
    hooks: &mut impl ParentHooks,
) -> Result<Handed, UpgradeError> {
    let pre = |s: &str, e: &dyn fmt::Display| UpgradeError::Precondition(format!("{s}: {e}"));
    if offered.is_empty() || offered.len() > MAX_HANDOVER_LISTENERS {
        return Err(UpgradeError::Precondition(format!(
            "{} listeners offered; one handover carries 1..={MAX_HANDOVER_LISTENERS}",
            offered.len()
        )));
    }
    if cfg.require_cloexec {
        let leaks = cloexec::non_cloexec_fds().map_err(|e| pre("fd audit", &e))?;
        if !leaks.is_empty() {
            return Err(UpgradeError::Precondition(format!(
                "fds without CLOEXEC would leak into the child: {leaks:?}"
            )));
        }
    }
    let dir = HandoverDir::create(&cfg.runtime_dir).map_err(|e| pre("handover dir", &e))?;
    let sock_path = dir.path.join(SOCK_NAME);
    let fifo_path = dir.path.join(FIFO_NAME);

    let lfd = seqpacket().map_err(|e| pre("socket", &e))?;
    let addr = UnixAddr::new(&sock_path).map_err(|e| pre("socket path", &e))?;
    bind(lfd.as_raw_fd(), &addr).map_err(|e| pre("bind", &e))?;
    let backlog = Backlog::new(4).map_err(|e| pre("backlog", &e))?;
    listen(&lfd, backlog).map_err(|e| pre("listen", &e))?;
    let hs = UnixListener::from(lfd);
    hs.set_nonblocking(true).map_err(|e| pre("nonblocking", &e))?;

    nix::unistd::mkfifo(&fifo_path, Mode::S_IRUSR | Mode::S_IWUSR).map_err(|e| pre("mkfifo", &e))?;
    // O_RDWR on a FIFO never blocks and keeps the pipe buffer alive until the child has read it.
    let mut fifo = Some(OpenOptions::new().read(true).write(true).open(&fifo_path).map_err(|e| pre("open fifo", &e))?);
    if let Some(f) = fifo.as_mut() {
        stek::write_frame(f, ring).map_err(|e| pre("write stek", &e))?;
    }

    let mut cmd = Command::new(&cfg.exe);
    cmd.args(&cfg.args).env(ENV_DIR, &dir.path).stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit());
    let mut child = cmd.spawn().map_err(|e| pre("spawn", &e))?;
    drop(cmd);

    // SCM_RIGHTS array, in the same order as the `listeners` descriptors built just below.
    let fds: Vec<BorrowedFd<'_>> = offered.iter().map(|o| o.fd).collect();
    let descs: Vec<ListenerDesc> = offered.iter().map(|o| o.desc.clone()).collect();
    let deadline_ms = u64::try_from(cfg.drain_deadline.as_millis()).unwrap_or(u64::MAX);
    let mut m = ParentMachine::new(descs, own_uid(), deadline_ms);
    let mut events = VecDeque::from([ParentEvent::Spawned { pid: child.id() }]);
    let mut stream: Option<UnixStream> = None;
    let mut buf = vec![0u8; MAX_FRAME + 1];
    let until = Instant::now() + cfg.handover_timeout;
    let mut forced_total = 0u64;

    loop {
        while let Some(ev) = events.pop_front() {
            for act in m.step(ev) {
                match act {
                    ParentAction::NotifyReloading => {
                        let _ = cfg.notifier.reloading();
                    }
                    ParentAction::SendListeners(ls) => {
                        let ok = stream
                            .as_ref()
                            .map(|s| send_msg_fds(s, &Msg::Listeners(ls), &fds).is_ok())
                            .unwrap_or(false);
                        if !ok {
                            events.push_back(ParentEvent::ChildGone);
                        }
                    }
                    ParentAction::CloseListeners => hooks.close_listeners(),
                    ParentAction::SendDrain { deadline_ms } => {
                        if let Some(s) = stream.as_ref() {
                            let _ = send_msg(s, &Msg::Drain { deadline_ms });
                        }
                    }
                    ParentAction::NotifyMainPid { pid } => {
                        let _ = cfg.notifier.main_pid(pid);
                    }
                    ParentAction::StartDrain { deadline_ms } => {
                        let forced = hooks.drain(Duration::from_millis(deadline_ms));
                        forced_total = forced;
                        events.push_back(ParentEvent::DrainFinished { forced });
                    }
                    ParentAction::SendDone { forced } => {
                        if let Some(s) = stream.as_ref() {
                            let _ = send_msg(s, &Msg::Done { forced_closes: forced });
                        }
                    }
                    ParentAction::AbortChild { reason } => {
                        if let Some(s) = stream.as_ref() {
                            let _ = send_msg(s, &Msg::Abort { reason: wire::clamp_reason(&reason) });
                        }
                        reap(&mut child);
                    }
                    ParentAction::NotifyReady => {
                        let _ = cfg.notifier.ready();
                    }
                    ParentAction::Exit => {
                        return Ok(Handed { child_pid: child.id(), forced: forced_total });
                    }
                }
            }
            if m.state() == ParentState::Idle {
                return Err(UpgradeError::ChildFailed(m.last_failure().unwrap_or("unknown").to_string()));
            }
        }

        // Produce the next event.
        if matches!(m.state(), ParentState::Draining | ParentState::Finished) {
            // Unreachable in practice (StartDrain queues DrainFinished); fail safe by finishing.
            events.push_back(ParentEvent::DrainFinished { forced: forced_total });
            continue;
        }
        if Instant::now() >= until {
            events.push_back(ParentEvent::Timeout);
            continue;
        }
        if matches!(child.try_wait(), Ok(Some(_)) | Err(_)) {
            events.push_back(ParentEvent::ChildGone);
            continue;
        }
        match (m.state(), stream.as_ref()) {
            (ParentState::AwaitPeer, _) => match hs.accept() {
                Ok((s, _)) => {
                    let _ = fs::remove_file(&sock_path); // no further connects
                    let ev = match (s.set_nonblocking(false), getsockopt(&s.as_fd(), sockopt::PeerCredentials)) {
                        (Ok(()), Ok(c)) => {
                            let pid = u32::try_from(c.pid()).unwrap_or(0);
                            ParentEvent::PeerConnected { pid, uid: c.uid(), exe_ok: exe_matches(pid, &cfg.exe) }
                        }
                        _ => ParentEvent::ChildGone,
                    };
                    stream = Some(s);
                    events.push_back(ev);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(2)),
                Err(_) => events.push_back(ParentEvent::ChildGone),
            },
            (_, Some(s)) => match recv_msg(s, &mut buf, SLICE, 0) {
                // Fd cap 0: the child never sends fds; any it tried were discarded by the kernel (CtlTrunc).
                Ok(Recv::Frame(f, _)) => {
                    if matches!(f, Ok(Msg::Hello { .. })) {
                        fifo = None; // the child has read the STEK; drop our pipe end
                    }
                    events.push_back(ParentEvent::Frame(f));
                }
                Ok(Recv::Idle) => {}
                Ok(Recv::CtlTrunc | Recv::Eof) | Err(_) => events.push_back(ParentEvent::ChildGone),
            },
            (_, None) => events.push_back(ParentEvent::ChildGone),
        }
        let _ = &fifo;
    }
}

/// Child-side failure (the child sends `abort` when it can and exits nonzero; the parent keeps serving).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildError(pub String);

impl fmt::Display for ChildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "upgrade takeover failed: {}", self.0)
    }
}

impl std::error::Error for ChildError {}

/// True when this process was spawned as an upgrade child.
pub fn is_upgrade_child() -> bool {
    std::env::var_os(ENV_DIR).is_some()
}

/// A child that has validated and claimed its listeners but not yet sent `ready`.
#[derive(Debug)]
pub struct Takeover {
    stream: UnixStream,
    machine: ChildMachine,
    names: Vec<String>,
    /// The STEK ring received by pipe.
    pub stek: StekRing,
    /// Claimed listeners, in `listeners` order. Start accepting on them, then call [`Takeover::ready`].
    pub listeners: Vec<(ListenerDesc, TcpListener)>,
}

/// The child after `ready`: it owns the listeners for good.
#[derive(Debug)]
pub struct Main {
    stream: UnixStream,
    /// The parent's drain deadline, if `drain` arrived.
    pub drain_deadline_ms: Option<u64>,
}

impl Main {
    /// Wait (bounded) for the parent's `done`; returns its forced-close count.
    pub fn wait_done(self, timeout: Duration) -> Option<u64> {
        let mut buf = vec![0u8; MAX_FRAME + 1];
        let until = Instant::now() + timeout;
        while Instant::now() < until {
            match recv_msg(&self.stream, &mut buf, SLICE, 0) {
                Ok(Recv::Frame(Ok(Msg::Done { forced_closes }), _)) => return Some(forced_closes),
                Ok(Recv::Idle | Recv::Frame(..) | Recv::CtlTrunc) => {}
                Ok(Recv::Eof) | Err(_) => return None,
            }
        }
        None
    }
}

/// Claim-or-close (UP-2): validate received fd *i* against `listeners[i]`; a passing fd becomes a listener, every
/// other fd (failed check, or no matching descriptor) is closed. Returns the claimed listeners and the reject count
/// (a count mismatch between fds and descriptors counts every unmatched entry as rejected).
fn claim_received(ls: &[ListenerDesc], fds: Vec<OwnedFd>) -> (Vec<(ListenerDesc, TcpListener)>, usize) {
    let mut claimed = Vec::new();
    let mut rejected = ls.len().abs_diff(fds.len());
    for (d, fd) in ls.iter().zip(fds) {
        match fdcheck::claim_owned_tcp(fd, d) {
            Ok(l) => claimed.push((d.clone(), l)),
            Err(_) => rejected += 1,
        }
    }
    // Unmatched fds beyond the descriptor list were dropped (closed) by the zip.
    (claimed, rejected)
}

fn abort_with(stream: &UnixStream, reason: &str) -> ChildError {
    let _ = send_msg(stream, &Msg::Abort { reason: wire::clamp_reason(reason) });
    ChildError(reason.to_string())
}

/// What the child does when fds above 2 survived exec (a UP-6 violation by whoever spawned it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakPolicy {
    /// Abort the handover (production).
    Refuse,
    /// Proceed; for test harnesses that hold inherited fds of their own (e.g. a non-CLOEXEC lock fd).
    Ignore,
}

/// Child side, up to and including the claim. Call only when [`is_upgrade_child`].
pub fn child_takeover(
    config_hash: [u8; CONFIG_HASH_LEN],
    timeout: Duration,
    leaks: LeakPolicy,
) -> Result<Takeover, ChildError> {
    let err = |s: &str, e: &dyn fmt::Display| ChildError(format!("{s}: {e}"));
    let dir = PathBuf::from(std::env::var_os(ENV_DIR).ok_or_else(|| ChildError("not an upgrade child".into()))?);
    check_private_dir(&dir).map_err(|e| err("handover dir", &e))?;
    let stek = {
        let mut f = File::open(dir.join(FIFO_NAME)).map_err(|e| err("open stek pipe", &e))?;
        stek::read_frame(&mut f).map_err(|e| err("read stek", &e))?
    };
    let fd = seqpacket().map_err(|e| err("socket", &e))?;
    let addr = UnixAddr::new(&dir.join(SOCK_NAME)).map_err(|e| err("socket path", &e))?;
    connect(fd.as_raw_fd(), &addr).map_err(|e| err("connect", &e))?;
    let stream = UnixStream::from(fd);

    match getsockopt(&stream.as_fd(), sockopt::PeerCredentials) {
        Ok(c) if c.uid() == own_uid() && u32::try_from(c.pid()).ok() == Some(std::os::unix::process::parent_id()) => {}
        _ => return Err(abort_with(&stream, "handover peer is not the parent")),
    }
    match cloexec::non_cloexec_fds() {
        Ok(v) if v.is_empty() || leaks == LeakPolicy::Ignore => {}
        Ok(v) => return Err(abort_with(&stream, &format!("fds leaked through exec: {v:?}"))),
        Err(e) => return Err(abort_with(&stream, &format!("fd audit: {e}"))),
    }
    send_msg(&stream, &Msg::Hello { child_pid: u64::from(std::process::id()), config_hash })
        .map_err(|e| err("send hello", &e))?;

    let mut machine = ChildMachine::new();
    let mut buf = vec![0u8; MAX_FRAME + 1];
    let until = Instant::now() + timeout;
    let mut events: VecDeque<ChildEvent> = VecDeque::new();
    let mut claimed: Vec<(ListenerDesc, TcpListener)> = Vec::new();
    // The fds that arrived with the `listeners` packet, consumed by ValidateAndClaim.
    let mut received: Vec<OwnedFd> = Vec::new();
    loop {
        if events.is_empty() {
            if Instant::now() >= until {
                events.push_back(ChildEvent::Timeout);
            } else {
                match recv_msg(&stream, &mut buf, SLICE, MAX_HANDOVER_LISTENERS) {
                    Ok(Recv::Frame(f @ Ok(Msg::Listeners(_)), fds)) => {
                        received = fds;
                        events.push_back(ChildEvent::Frame(f));
                    }
                    // Fds on any other packet: close them (drop) and fail the frame.
                    Ok(Recv::Frame(f, fds)) => {
                        let f = if fds.is_empty() { f } else { Err(wire::WireError::BadShape) };
                        drop(fds);
                        events.push_back(ChildEvent::Frame(f));
                    }
                    Ok(Recv::CtlTrunc) => {
                        claimed.clear();
                        return Err(abort_with(&stream, "SCM_RIGHTS control data truncated"));
                    }
                    Ok(Recv::Idle) => continue,
                    Ok(Recv::Eof) | Err(_) => events.push_back(ChildEvent::ParentGone),
                }
            }
        }
        while let Some(ev) = events.pop_front() {
            for act in machine.step(ev) {
                match act {
                    ChildAction::ValidateAndClaim(ls) => {
                        let (c, rejected) = claim_received(&ls, std::mem::take(&mut received));
                        claimed = c;
                        let names = claimed.iter().map(|(d, _)| d.name.clone()).collect();
                        events.push_back(ChildEvent::Claimed { claimed: names, rejected });
                    }
                    ChildAction::SendReady(names) => {
                        return Ok(Takeover { stream, machine, names, stek, listeners: claimed });
                    }
                    ChildAction::Abort { reason } => {
                        claimed.clear(); // close claimed duplicates; the parent still holds the sockets
                        return Err(abort_with(&stream, &reason));
                    }
                    ChildAction::BecomeMain => {}
                }
            }
        }
    }
}

impl Takeover {
    /// Send `ready` (call after accept loops run on every claimed listener) and wait up to `timeout` for `drain`.
    /// Whatever happens, the child keeps its listeners from here on (UP-1).
    pub fn ready(mut self, timeout: Duration) -> Main {
        let sent = send_msg(&self.stream, &Msg::Ready { claimed: self.names.clone() }).is_ok();
        let mut buf = vec![0u8; MAX_FRAME + 1];
        let until = Instant::now() + timeout;
        let mut drain = None;
        while sent && Instant::now() < until {
            let ev = match recv_msg(&self.stream, &mut buf, SLICE, 0) {
                Ok(Recv::Frame(f, _)) => {
                    if let Ok(Msg::Drain { deadline_ms }) = &f {
                        drain = Some(*deadline_ms);
                    }
                    ChildEvent::Frame(f)
                }
                Ok(Recv::Idle | Recv::CtlTrunc) => continue,
                Ok(Recv::Eof) | Err(_) => ChildEvent::ParentGone,
            };
            if self.machine.step(ev).contains(&ChildAction::BecomeMain) {
                break;
            }
        }
        Main { stream: self.stream, drain_deadline_ms: drain }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drain::{ConnTracker, accept_loop};
    use nix::sys::socket::socketpair;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Hooks {
        stop: Arc<AtomicBool>,
        accept: Option<std::thread::JoinHandle<()>>,
        tracker: ConnTracker,
        closed: bool,
    }
    impl ParentHooks for Hooks {
        fn close_listeners(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(h) = self.accept.take() {
                let _ = h.join();
            }
            self.closed = true;
        }
        fn drain(&mut self, d: Duration) -> u64 {
            self.tracker.drain(d).forced
        }
    }

    fn serve(l: TcpListener, tag: &'static str) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        let stop = Arc::new(AtomicBool::new(false));
        let st = stop.clone();
        let h = std::thread::spawn(move || {
            let _ = accept_loop(l, &st, Duration::from_millis(10), |mut s| {
                let _ = s.write_all(tag.as_bytes());
            });
        });
        (stop, h)
    }

    fn cfg(exe: PathBuf, args: Vec<&str>) -> ParentConfig {
        ParentConfig {
            exe,
            args: args.into_iter().map(OsString::from).collect(),
            runtime_dir: std::env::temp_dir(),
            handover_timeout: Duration::from_secs(10),
            drain_deadline: Duration::from_millis(300),
            require_cloexec: false, // the cargo test harness may hold jobserver fds
            notifier: Notifier::disabled(),
        }
    }

    fn get(addr: std::net::SocketAddr) -> Option<String> {
        let mut s = TcpStream::connect(addr).ok()?;
        let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
        let mut out = String::new();
        s.read_to_string(&mut out).ok()?;
        Some(out)
    }

    /// UP-7: children that exit, hang, or are not the protocol peer leave the parent serving.
    #[test]
    fn failing_children_never_degrade_parent() {
        let Ok(l) = TcpListener::bind("127.0.0.1:0") else { return };
        let Ok(addr) = l.local_addr() else { return };
        let Ok(desc) = fdcheck::describe_tcp("http", &l) else { return };
        let Ok(keep) = l.try_clone() else { return };
        let (stop, h) = serve(l, "parent");
        let Ok(ring) = StekRing::generate() else { return };
        let cases = [
            (PathBuf::from("/bin/sh"), vec!["-c", "exit 3"], Duration::from_secs(10)),
            (PathBuf::from("/bin/sleep"), vec!["30"], Duration::from_millis(300)),
            (PathBuf::from("/nonexistent/binary"), vec![], Duration::from_secs(1)),
        ];
        for (exe, args, to) in cases {
            let mut c = cfg(exe, args);
            c.handover_timeout = to;
            let mut hooks = Hooks {
                stop: Arc::new(AtomicBool::new(false)),
                accept: None,
                tracker: ConnTracker::new(),
                closed: false,
            };
            let r = upgrade(&c, &[Offered { desc: &desc, fd: keep.as_fd() }], &ring, &mut hooks);
            assert!(r.is_err(), "{r:?}");
            assert!(!hooks.closed);
            assert_eq!(get(addr).as_deref(), Some("parent"));
        }
        // Too many listeners is refused up front.
        let mut hooks =
            Hooks { stop: Arc::new(AtomicBool::new(false)), accept: None, tracker: ConnTracker::new(), closed: false };
        let o = Offered { desc: &desc, fd: keep.as_fd() };
        let r = upgrade(&cfg(PathBuf::from("/bin/true"), vec![]), &[o; MAX_HANDOVER_LISTENERS + 1], &ring, &mut hooks);
        assert!(matches!(r, Err(UpgradeError::Precondition(_))));
        let r = upgrade(&cfg(PathBuf::from("/bin/true"), vec![]), &[], &ring, &mut hooks);
        assert!(matches!(r, Err(UpgradeError::Precondition(_))));
        stop.store(true, Ordering::Release);
        let _ = h.join();
    }

    /// Child half of `full_process_handover`: this test binary re-executed as the upgrade child.
    #[test]
    fn upgrade_child_entry() {
        if !is_upgrade_child() {
            return;
        }
        // Ignore: under ci/heavy.sh the test process inherits the non-CLOEXEC heavy-lock fd 9 (UP-6 detection of
        // exactly that leak is what made this test fail under Refuse; cloexec::tests covers the detection).
        let t = child_takeover([9; 32], Duration::from_secs(10), LeakPolicy::Ignore);
        let Ok(mut t) = t else {
            assert!(t.is_ok(), "{t:?}");
            return;
        };
        assert_eq!(t.listeners.len(), HANDOVER_N);
        let names: Vec<String> = t.listeners.iter().map(|(d, _)| d.name.clone()).collect();
        let want: Vec<String> = (0..HANDOVER_N).map(|i| format!("http{i}")).collect();
        assert_eq!(names, want, "fd array order must match `listeners`");
        // Received fds are CLOEXEC (MSG_CMSG_CLOEXEC): none of them may leak into a later exec.
        let leaks = cloexec::non_cloexec_fds().unwrap_or_default();
        for (_, l) in &t.listeners {
            assert!(!leaks.contains(&l.as_raw_fd()));
        }
        let mut servers = Vec::new();
        for (_, l) in t.listeners.drain(..) {
            servers.push(serve(l, "child"));
        }
        let main = t.ready(Duration::from_secs(10));
        assert_eq!(main.drain_deadline_ms, Some(300));
        assert_eq!(main.wait_done(Duration::from_secs(10)), Some(0));
        // Keep serving a little so the parent test can observe the child answering, then exit.
        std::thread::sleep(Duration::from_millis(1500));
        for (stop, h) in servers {
            stop.store(true, Ordering::Release);
            let _ = h.join();
        }
    }

    const HANDOVER_N: usize = 3;

    /// Full protocol across a real exec: the parent hands its listeners (several, by SCM_RIGHTS) to a child
    /// process, closes its own fds, drains, and every listener keeps answering (now from the child) with no refused
    /// connection.
    #[test]
    fn full_process_handover() {
        let mut addrs = Vec::new();
        let mut descs = Vec::new();
        let mut keeps = Vec::new();
        let mut servers = Vec::new();
        for i in 0..HANDOVER_N {
            let Ok(l) = TcpListener::bind("127.0.0.1:0") else { return };
            let Ok(addr) = l.local_addr() else { return };
            let Ok(desc) = fdcheck::describe_tcp(&format!("http{i}"), &l) else { return };
            let Ok(keep) = l.try_clone() else { return };
            addrs.push(addr);
            descs.push(desc);
            keeps.push(keep);
            servers.push(serve(l, "parent"));
        }
        let Ok(exe) = std::env::current_exe() else { return };
        let c = cfg(exe, vec!["--exact", "handover::tests::upgrade_child_entry", "--test-threads=1", "--nocapture"]);
        let Ok(ring) = StekRing::generate() else { return };
        // A client hammering every port during the handover must never be refused.
        let done = Arc::new(AtomicBool::new(false));
        let d2 = done.clone();
        let a2 = addrs.clone();
        let client = std::thread::spawn(move || {
            let (mut ok, mut bad) = (0u32, 0u32);
            while !d2.load(Ordering::Acquire) {
                for a in &a2 {
                    match get(*a) {
                        Some(s) if s == "parent" || s == "child" => ok += 1,
                        _ => bad += 1,
                    }
                }
            }
            (ok, bad)
        });
        let stops: Vec<Arc<AtomicBool>> = servers.iter().map(|(s, _)| s.clone()).collect();
        let joins: Vec<std::thread::JoinHandle<()>> = servers.into_iter().map(|(_, h)| h).collect();
        let mut hooks = MultiHooks { stops, joins, tracker: ConnTracker::new(), closed: false };
        let offered: Vec<Offered<'_>> =
            descs.iter().zip(&keeps).map(|(d, k)| Offered { desc: d, fd: k.as_fd() }).collect();
        let r = upgrade(&c, &offered, &ring, &mut hooks);
        drop(offered);
        drop(keeps);
        assert!(matches!(r, Ok(Handed { forced: 0, .. })), "{r:?}");
        assert!(hooks.closed);
        for a in &addrs {
            assert_eq!(get(*a).as_deref(), Some("child"));
        }
        done.store(true, Ordering::Release);
        let (ok, bad) = client.join().unwrap_or((0, 1));
        assert!(ok > 0);
        assert_eq!(bad, 0, "connections failed during the handover");
    }

    struct MultiHooks {
        stops: Vec<Arc<AtomicBool>>,
        joins: Vec<std::thread::JoinHandle<()>>,
        tracker: ConnTracker,
        closed: bool,
    }
    impl ParentHooks for MultiHooks {
        fn close_listeners(&mut self) {
            for s in &self.stops {
                s.store(true, Ordering::Release);
            }
            for h in self.joins.drain(..) {
                let _ = h.join();
            }
            self.closed = true;
        }
        fn drain(&mut self, d: Duration) -> u64 {
            self.tracker.drain(d).forced
        }
    }

    /// How many fds of this process refer to the same socket as `l` (by `/proc/self/fd` link `socket:[inode]`).
    /// Other tests running in parallel never touch this socket, so the count is exact.
    fn open_refs(l: &TcpListener) -> usize {
        let Ok(me) = fs::read_link(format!("/proc/self/fd/{}", l.as_raw_fd())) else { return usize::MAX };
        let Ok(rd) = fs::read_dir("/proc/self/fd") else { return usize::MAX };
        rd.filter_map(Result::ok).filter(|e| fs::read_link(e.path()).ok().as_ref() == Some(&me)).count()
    }

    fn seqpair() -> Option<(UnixStream, UnixStream)> {
        let (a, b) = socketpair(AddressFamily::Unix, SockType::SeqPacket, None, SockFlag::SOCK_CLOEXEC).ok()?;
        Some((UnixStream::from(a), UnixStream::from(b)))
    }

    fn listeners_msg(l: &TcpListener, n: usize) -> Option<Msg> {
        let d = fdcheck::describe_tcp("x", l).ok()?;
        Some(Msg::Listeners(vec![d; n]))
    }

    fn listeners_of(r: io::Result<Recv>) -> Result<(Vec<ListenerDesc>, Vec<OwnedFd>), String> {
        match r {
            Ok(Recv::Frame(Ok(Msg::Listeners(ls)), fds)) => Ok((ls, fds)),
            other => Err(format!("{other:?}")),
        }
    }

    /// MSG_CTRUNC: control data that does not fit (or more fds than allowed) closes every received fd; nothing
    /// leaks. Also garbage frames carrying fds, and fd/descriptor count mismatches, close every fd.
    #[test]
    fn truncated_or_garbage_control_data_leaks_no_fd() {
        let Ok(l) = TcpListener::bind("127.0.0.1:0") else { return };
        let Some((tx, rx)) = seqpair() else { return };
        let Some(msg) = listeners_msg(&l, 8) else { return };
        assert_eq!(open_refs(&l), 1);
        let eight = [l.as_fd(); 8];
        let mut buf = vec![0u8; MAX_FRAME + 1];

        // 1. Control buffer for one fd, eight sent: the kernel installs what fits and sets MSG_CTRUNC.
        assert!(send_msg_fds(&tx, &msg, &eight).is_ok());
        let mut small = vec![MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1)) + CMSG_SLACK];
        let r = recv_packet(&rx, &mut buf, &mut small, 1);
        assert!(matches!(r, Ok(Recv::CtlTrunc)), "{r:?}");
        assert_eq!(open_refs(&l), 1, "fds leaked after MSG_CTRUNC");

        // 2. No control buffer at all (the parent side): fds discarded, MSG_CTRUNC.
        assert!(send_msg_fds(&tx, &msg, &eight).is_ok());
        let r = recv_msg(&rx, &mut buf, SLICE, 0);
        assert!(matches!(r, Ok(Recv::CtlTrunc)), "{r:?}");
        assert_eq!(open_refs(&l), 1);

        // 3. More fds than the cap even though they fit in the (slack-padded) buffer: all closed.
        let Some(msg4) = listeners_msg(&l, 4) else { return };
        assert!(send_msg_fds(&tx, &msg4, &eight[..4]).is_ok());
        let r = recv_msg(&rx, &mut buf, SLICE, 2);
        assert!(matches!(r, Ok(Recv::CtlTrunc)), "{r:?}");
        assert_eq!(open_refs(&l), 1);

        // 4. Garbage bytes with fds attached: decode fails, the fds come back owned and are closed on drop.
        {
            let mut space = vec![MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(3))];
            let mut ctl = SendAncillaryBuffer::new(&mut space);
            assert!(ctl.push(SendAncillaryMessage::ScmRights(&eight[..3])));
            assert!(sendmsg(&tx, &[IoSlice::new(&[0xff, 0x00, 0x13])], &mut ctl, SendFlags::NOSIGNAL).is_ok());
        }
        match recv_msg(&rx, &mut buf, SLICE, MAX_HANDOVER_LISTENERS) {
            Ok(Recv::Frame(Err(_), fds)) => {
                assert_eq!(fds.len(), 3);
                assert_eq!(open_refs(&l), 4);
                drop(fds);
            }
            other => {
                assert!(matches!(other, Ok(Recv::Frame(Err(_), _))), "{other:?}");
            }
        }
        assert_eq!(open_refs(&l), 1);

        // 5. A well-formed `listeners` with the right fds round-trips in order and claims.
        let Some(msg2) = listeners_msg(&l, 2) else { return };
        assert!(send_msg_fds(&tx, &msg2, &eight[..2]).is_ok());
        let (ls, fds) = match listeners_of(recv_msg(&rx, &mut buf, SLICE, MAX_HANDOVER_LISTENERS)) {
            Ok(v) => v,
            Err(e) => {
                assert_eq!(e, "listeners frame");
                return;
            }
        };
        assert_eq!(open_refs(&l), 3);
        let (claimed, rejected) = claim_received(&ls, fds);
        assert_eq!((claimed.len(), rejected), (2, 0));
        drop(claimed);
        assert_eq!(open_refs(&l), 1);

        // 6. Count mismatch (3 fds, 1 descriptor) and a failing descriptor: unmatched and rejected fds are closed.
        let Some(msg3) = listeners_msg(&l, 3) else { return };
        assert!(send_msg_fds(&tx, &msg3, &eight[..3]).is_ok());
        let (ls, fds) = match listeners_of(recv_msg(&rx, &mut buf, SLICE, MAX_HANDOVER_LISTENERS)) {
            Ok(v) => v,
            Err(e) => {
                assert_eq!(e, "listeners frame");
                return;
            }
        };
        let mut one = ls.get(..1).unwrap_or_default().to_vec();
        let (claimed, rejected) = claim_received(&one, fds);
        assert_eq!((claimed.len(), rejected), (1, 2));
        drop(claimed);
        assert_eq!(open_refs(&l), 1);
        assert!(send_msg_fds(&tx, &msg3, &eight[..1]).is_ok());
        let Ok(Recv::Frame(_, fds)) = recv_msg(&rx, &mut buf, SLICE, MAX_HANDOVER_LISTENERS) else { return };
        if let Some(d) = one.first_mut() {
            d.addr = vec![127, 0, 0, 1, 0, 1]; // wrong port: getsockname mismatch
        }
        let (claimed, rejected) = claim_received(&one, fds);
        assert_eq!((claimed.len(), rejected), (0, 1));
        assert_eq!(open_refs(&l), 1);

        // 7. The sender refuses more than the cap.
        let many = vec![l.as_fd(); MAX_HANDOVER_LISTENERS + 1];
        assert!(send_msg_fds(&tx, &msg, &many).is_err());
    }
}
