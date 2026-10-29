//! Out-of-process adapter/module protocol host (third-party backends, outside the golden TCB).
//!
//! [`pdp_uds`]: the effects side of the out-of-process Cedar PDP (DEVIATIONS X-8): the SOCK_SEQPACKET client
//! transport for `aegis_authz::pdp::PdpClient` and the packet primitives the PDP server shares. Everything else is
//! still a Phase-0 stub that fails closed. Spec: `spec/SPEC_INVARIANTS.md`.
#![forbid(unsafe_code)]

pub mod pdp_uds;
