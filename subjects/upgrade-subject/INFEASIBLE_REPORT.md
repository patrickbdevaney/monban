# INFEASIBLE_REPORT (partial): F11 SCM_RIGHTS fd transport under `forbid(unsafe_code)` with nix 0.31.3

Unit P2-upgrade-001. Everything else in the unit is implemented and passes; this records the one F11 clause that
cannot be met within the unit's constraints, and what was done instead.

**Spec clause.** `interfaces/F11-upgrade-handover.cddl`: "fds passed with SCM_RIGHTS alongside `listeners`";
`listeners = [1, [* listener]] ; order matches the SCM_RIGHTS fd array`.

**Failing case.** The receiving child must turn each SCM_RIGHTS fd into an owned, IO-safe handle in order to
validate it (`getsockopt(SO_TYPE/SO_ACCEPTCONN)` in nix 0.31 takes `&impl AsFd`) and claim it (`TcpListener` from
`OwnedFd`). nix 0.31.3 returns received fds as `ControlMessageOwned::ScmRights(Vec<RawFd>)`; std's equivalent
(`SocketAncillary`) is unstable and also yields `RawFd`. The only conversions are `unsafe { OwnedFd::from_raw_fd }`
/ `BorrowedFd::borrow_raw`, forbidden in aegis-ops. sd-notify 0.5.0 (`listen_fds`) and tokio give `RawFd` too, and
nix's `dup2_raw` is `unsafe`. A RawFd-only design (raw accept/recv/send, no poll) would be legal Rust, but it gives up
IO safety and cannot do the SO_TYPE/SO_ACCEPTCONN checks, so it would weaken UP-2. Not done.

**Minimal reason.** Receiving an fd is an ownership transfer the type system cannot see; some crate must assert it
with `unsafe`. No allowed crate does that for SCM_RIGHTS.

**What was done instead (no check weakened).** Listener fds travel by fd inheritance on the child's stdio slots
(slot *i* = fd *i*, in `listeners` order). This is ARCHITECTURE §3.11's "parent spawns child with fd inheritance",
and std exposes it safely (`Stdio::from(OwnedFd)`, then `stdin().as_fd().try_clone_to_owned()` in the child). The
F11 messages are unchanged on the SEQPACKET socket. Every inherited fd gets the full UP-2 validation, then is
claimed (an F_DUPFD_CLOEXEC duplicate) or closed (the slot is overwritten with /dev/null). Limit: at most **2
listeners** per handover (stdin and stdout; stderr stays the log). The parent refuses an upgrade with more listeners
and keeps serving.

**Resolution options (integrator decision).**
1. One audited site in `aegis-iso` (the crate allowed `unsafe`, ≤20 sites): `claim_scm_rights(Vec<RawFd>) ->
   Vec<OwnedFd>`, called right after `recvmsg(MSG_CMSG_CLOEXEC)` with a `MSG_CTRUNC` check. aegis-iso is L4 like
   aegis-ops, so it needs an INTRA_LAYER edge `aegis-ops -> aegis-iso`. The rest of the driver stays as it is:
   `handover::claim_slot` becomes "claim the i-th received fd".
2. Or amend F11 to make "fd inheritance on stdio slots, ≤2 listeners" the normative transport.
