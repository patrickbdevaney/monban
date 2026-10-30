//! Exact client-side mirror of the server's protocol state (input to NC3's checkin predicate, P4-pg-003).
//!
//! Every frontend message that produces replies pushes an entry on a FIFO of expected replies; every backend
//! message is matched against the front of that FIFO. The model follows the PG v3 extended-query rules:
//!
//! * after an ErrorResponse in extended mode the server discards every message up to the next Sync, so the
//!   entries in front of the next Sync are dropped *without effect* (a skipped Parse creates no statement, a skipped
//!   Close closes nothing); if no Sync is queued yet, later non-Sync messages are recorded as skipped on send;
//! * ReadyForQuery answers exactly one Sync or one simple Query and carries the server-reported txn status;
//! * named statements live until a completed Close; named portals until a completed Close or the end of the
//!   transaction (ReadyForQuery `I`). The unnamed statement/portal are overwritten by the next Parse/Bind and are not
//!   counted as open objects.
//!
//! Any reply that does not fit the model (desync), a FATAL error, an IO error or timeout in the middle of a write,
//! COPY, or a LISTEN marks the state [`Unrecoverable`]: such a connection must be discarded, never recovered.
//! A read timeout with the framing intact does NOT make the state unrecoverable: the outstanding replies are still
//! known exactly and can be drained (NC3 recovery).

use std::collections::{BTreeSet, VecDeque};
use std::fmt;

use super::msg::{Backend, TxnStatus};

/// Why a connection can only be discarded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unrecoverable {
    /// A backend message that does not answer the front of the expected-reply FIFO.
    Desync(String),
    /// Malformed or over-length backend message (framing lost).
    Framing(String),
    /// FATAL/PANIC from the server.
    Fatal(String),
    /// IO error, EOF, or a write that may have been partially sent.
    Io(String),
    /// The server entered COPY mode (never issued by this client; NC3: COPY in progress ⇒ discard).
    Copy,
    /// LISTEN completed or a notification arrived (NC3: LISTEN ⇒ discard).
    Listen,
    /// Terminate was sent.
    Closed,
}

impl fmt::Display for Unrecoverable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unrecoverable::Desync(m) => write!(f, "protocol desync: {m}"),
            Unrecoverable::Framing(m) => write!(f, "framing lost: {m}"),
            Unrecoverable::Fatal(m) => write!(f, "server FATAL: {m}"),
            Unrecoverable::Io(m) => write!(f, "io: {m}"),
            Unrecoverable::Copy => write!(f, "server entered COPY mode"),
            Unrecoverable::Listen => write!(f, "LISTEN state on the session"),
            Unrecoverable::Closed => write!(f, "connection terminated"),
        }
    }
}

/// One expected reply group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expect {
    /// ParseComplete; statement name ("" = unnamed).
    Parse(String),
    /// BindComplete; portal name.
    Bind(String),
    /// ParameterDescription then RowDescription | NoData. `got_params` after the first.
    DescribeStatement { got_params: bool },
    /// RowDescription | NoData.
    DescribePortal,
    /// DataRow* then CommandComplete | EmptyQueryResponse | PortalSuspended.
    Execute,
    /// CloseComplete; `b'S'`/`b'P'` and name.
    Close(u8, String),
    /// ReadyForQuery.
    Sync,
    /// Simple query: any results, then ReadyForQuery.
    Query,
}

/// What one backend message meant, for the caller collecting results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Asynchronous message (notice, parameter status) or a reply that completes nothing visible.
    Other,
    /// A reply that completed one non-terminal FIFO entry.
    Completed(Expect),
    /// ReadyForQuery: a Sync or simple Query fully answered.
    Ready(TxnStatus),
}

#[derive(Clone, Debug, Default)]
pub struct ProtoState {
    txn: Option<TxnStatus>,
    expect: VecDeque<Expect>,
    skip_until_sync: bool,
    statements: BTreeSet<String>,
    portals: BTreeSet<String>,
    unrecoverable: Option<Unrecoverable>,
    params_changed: u32,
    errors: u64,
}

impl ProtoState {
    /// Server-reported transaction status of the last ReadyForQuery (`None` before the first).
    pub fn txn_status(&self) -> Option<TxnStatus> {
        self.txn
    }
    /// Expected reply groups not yet fully answered (each queued Parse/Bind/Describe/Execute/Close/Sync/Query).
    pub fn outstanding(&self) -> usize {
        self.expect.len()
    }
    /// Sync + simple Query entries still waiting for their ReadyForQuery.
    pub fn pending_ready(&self) -> usize {
        self.expect.iter().filter(|e| matches!(e, Expect::Sync | Expect::Query)).count()
    }
    pub fn expected(&self) -> impl Iterator<Item = &Expect> {
        self.expect.iter()
    }
    /// The server is discarding messages until the next Sync (extended-mode error with no Sync queued yet).
    pub fn skip_until_sync(&self) -> bool {
        self.skip_until_sync
    }
    /// Named prepared statements the server holds.
    pub fn open_statements(&self) -> impl Iterator<Item = &str> {
        self.statements.iter().map(String::as_str)
    }
    /// Named portals the server holds.
    pub fn open_portals(&self) -> impl Iterator<Item = &str> {
        self.portals.iter().map(String::as_str)
    }
    pub fn unrecoverable(&self) -> Option<&Unrecoverable> {
        self.unrecoverable.as_ref()
    }
    /// ParameterStatus messages received after startup (session GUC changes such as role or TimeZone).
    pub fn params_changed(&self) -> u32 {
        self.params_changed
    }
    /// Non-fatal ErrorResponses seen on this connection.
    pub fn errors(&self) -> u64 {
        self.errors
    }
    /// NC3 checkin predicate on protocol truth: ReadyForQuery seen ∧ txn status I ∧ no outstanding replies ∧ no open
    /// named statements or portals ∧ not skipping ∧ recoverable. (The pool adds its own session-generation checks.)
    pub fn is_clean(&self) -> bool {
        self.unrecoverable.is_none()
            && self.txn == Some(TxnStatus::Idle)
            && self.expect.is_empty()
            && !self.skip_until_sync
            && self.statements.is_empty()
            && self.portals.is_empty()
    }

    pub(crate) fn mark(&mut self, why: Unrecoverable) {
        if self.unrecoverable.is_none() {
            self.unrecoverable = Some(why);
        }
    }

    /// Record a frontend message about to be sent (call before writing; a failed write marks the state).
    pub(crate) fn sent(&mut self, e: Expect) {
        if matches!(e, Expect::Sync) {
            self.skip_until_sync = false;
            self.expect.push_back(e);
        } else if self.skip_until_sync {
            // The server discards it unanswered: it has no effect and no reply.
        } else {
            self.expect.push_back(e);
        }
    }

    /// Startup finished with ReadyForQuery.
    pub(crate) fn started(&mut self, s: TxnStatus) {
        self.txn = Some(s);
    }

    fn desync(&mut self, got: &str) -> Unrecoverable {
        let why = Unrecoverable::Desync(format!("{got} while expecting {:?}", self.expect.front()));
        self.mark(why.clone());
        why
    }

    /// Apply one post-startup backend message. `Err` means the state is now unrecoverable.
    pub(crate) fn on_backend(&mut self, m: &Backend) -> Result<Event, Unrecoverable> {
        if let Some(u) = &self.unrecoverable {
            return Err(u.clone());
        }
        let front = self.expect.front().cloned();
        match m {
            Backend::NoticeResponse(_) => Ok(Event::Other),
            Backend::ParameterStatus { .. } => {
                self.params_changed = self.params_changed.saturating_add(1);
                Ok(Event::Other)
            }
            Backend::NotificationResponse { .. } => {
                self.mark(Unrecoverable::Listen);
                Err(Unrecoverable::Listen)
            }
            Backend::CopyInResponse
            | Backend::CopyOutResponse
            | Backend::CopyBothResponse
            | Backend::CopyData(_)
            | Backend::CopyDone => {
                self.mark(Unrecoverable::Copy);
                Err(Unrecoverable::Copy)
            }
            Backend::ErrorResponse(e) => {
                if e.is_fatal() {
                    let why = Unrecoverable::Fatal(e.to_string());
                    self.mark(why.clone());
                    return Err(why);
                }
                self.errors = self.errors.saturating_add(1);
                match front {
                    Some(Expect::Query) => Ok(Event::Other), // simple query continues to ReadyForQuery
                    Some(_) => {
                        // Extended mode: drop everything in front of the next Sync, without effect.
                        while let Some(f) = self.expect.front() {
                            if matches!(f, Expect::Sync | Expect::Query) {
                                break;
                            }
                            self.expect.pop_front();
                        }
                        if self.expect.is_empty() {
                            self.skip_until_sync = true;
                        }
                        Ok(Event::Other)
                    }
                    None => Err(self.desync("ErrorResponse")),
                }
            }
            Backend::ParseComplete => match front {
                Some(Expect::Parse(name)) => {
                    self.expect.pop_front();
                    if !name.is_empty() {
                        self.statements.insert(name.clone());
                    }
                    Ok(Event::Completed(Expect::Parse(name)))
                }
                _ => Err(self.desync("ParseComplete")),
            },
            Backend::BindComplete => match front {
                Some(Expect::Bind(name)) => {
                    self.expect.pop_front();
                    if !name.is_empty() {
                        self.portals.insert(name.clone());
                    }
                    Ok(Event::Completed(Expect::Bind(name)))
                }
                _ => Err(self.desync("BindComplete")),
            },
            Backend::CloseComplete => match front {
                Some(Expect::Close(kind, name)) => {
                    self.expect.pop_front();
                    if kind == b'S' {
                        self.statements.remove(&name);
                    } else {
                        self.portals.remove(&name);
                    }
                    Ok(Event::Completed(Expect::Close(kind, name)))
                }
                _ => Err(self.desync("CloseComplete")),
            },
            Backend::ParameterDescription(_) => match front {
                Some(Expect::DescribeStatement { got_params: false }) => {
                    if let Some(f) = self.expect.front_mut() {
                        *f = Expect::DescribeStatement { got_params: true };
                    }
                    Ok(Event::Other)
                }
                _ => Err(self.desync("ParameterDescription")),
            },
            Backend::RowDescription(_) => match front {
                Some(Expect::DescribeStatement { got_params: true }) | Some(Expect::DescribePortal) => {
                    self.expect.pop_front();
                    Ok(Event::Completed(front.unwrap_or(Expect::DescribePortal)))
                }
                Some(Expect::Query) => Ok(Event::Other),
                _ => Err(self.desync("RowDescription")),
            },
            Backend::NoData => match front {
                Some(Expect::DescribeStatement { got_params: true }) | Some(Expect::DescribePortal) => {
                    self.expect.pop_front();
                    Ok(Event::Completed(front.unwrap_or(Expect::DescribePortal)))
                }
                _ => Err(self.desync("NoData")),
            },
            Backend::DataRow(_) => match front {
                Some(Expect::Execute) | Some(Expect::Query) => Ok(Event::Other),
                _ => Err(self.desync("DataRow")),
            },
            Backend::CommandComplete(tag) => {
                let listen = tag.split(' ').next().is_some_and(|w| w.eq_ignore_ascii_case("LISTEN"));
                let ev = match front {
                    Some(Expect::Execute) => {
                        self.expect.pop_front();
                        Event::Completed(Expect::Execute)
                    }
                    Some(Expect::Query) => Event::Other,
                    _ => return Err(self.desync("CommandComplete")),
                };
                if listen {
                    self.mark(Unrecoverable::Listen);
                    return Err(Unrecoverable::Listen);
                }
                Ok(ev)
            }
            Backend::EmptyQueryResponse => match front {
                Some(Expect::Execute) => {
                    self.expect.pop_front();
                    Ok(Event::Completed(Expect::Execute))
                }
                Some(Expect::Query) => Ok(Event::Other),
                _ => Err(self.desync("EmptyQueryResponse")),
            },
            Backend::PortalSuspended => match front {
                Some(Expect::Execute) => {
                    self.expect.pop_front();
                    Ok(Event::Completed(Expect::Execute))
                }
                _ => Err(self.desync("PortalSuspended")),
            },
            Backend::ReadyForQuery(s) => match front {
                Some(Expect::Sync) | Some(Expect::Query) => {
                    self.expect.pop_front();
                    self.txn = Some(*s);
                    if *s == TxnStatus::Idle {
                        // Portals do not survive the end of a transaction (no WITH HOLD cursors are issued).
                        self.portals.clear();
                    }
                    Ok(Event::Ready(*s))
                }
                _ => Err(self.desync("ReadyForQuery")),
            },
            Backend::Authentication(_) => Err(self.desync("Authentication after startup")),
            Backend::BackendKeyData { .. } => Err(self.desync("BackendKeyData after startup")),
            Backend::NegotiateProtocolVersion { .. } => Err(self.desync("NegotiateProtocolVersion after startup")),
        }
    }
}
