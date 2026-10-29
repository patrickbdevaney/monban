//! Policy decision for an authenticated, well-formed MCP request: the out-of-process Cedar PDP over the PDP-1 wire
//! (`aegis_authz::pdp`), combined fail-closed (F6). The transport is injected (the assembly passes the L4
//! SOCK_SEQPACKET client from aegis-adapter-host), so this crate does no I/O.
//!
//! PDP request shape (the Cedar schema the operator's policies validate against):
//! principal `Mcp::User::"<sub>"`, action `Mcp::Action::"invoke"`, resource `Mcp::Route::"<route path>"`,
//! context `{ era: String, method: String, tool: String }` (`tool` is `""` when the method names no tool).

use std::string::String;
use std::sync::Mutex;
use std::vec::Vec;

use aegis_authz::pdp::{PdpClient, PdpRequest, PdpTransport, Uid, Value};
use aegis_authz::{Decision, combine};

/// Something that decides PDP requests. Implementations must be total; anything but an exact Allow denies.
pub trait Authorizer: Send + Sync {
    fn decide(&self, req: &PdpRequest) -> Decision;
}

/// The PDP-1 client behind a mutex (one request in flight per client; request ids stay strictly increasing).
#[derive(Debug)]
pub struct PdpAuthorizer<T> {
    client: Mutex<PdpClient<T>>,
}

impl<T: PdpTransport> PdpAuthorizer<T> {
    pub fn new(transport: T) -> Self {
        Self { client: Mutex::new(PdpClient::new(transport)) }
    }
}

impl<T: PdpTransport + Send> Authorizer for PdpAuthorizer<T> {
    fn decide(&self, req: &PdpRequest) -> Decision {
        match self.client.lock() {
            Ok(mut c) => c.decide(req),
            Err(_) => Decision::Error,
        }
    }
}

/// Denies everything (the default when no PDP is configured; also the negative control in tests).
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAll;

impl Authorizer for DenyAll {
    fn decide(&self, _req: &PdpRequest) -> Decision {
        Decision::Deny
    }
}

/// Build the PDP request for one MCP call.
pub fn pdp_request(sub: &str, route_path: &str, era: &str, method: &str, tool: &str) -> PdpRequest {
    let ctx: Vec<(String, Value)> = Vec::from([
        ("era".into(), Value::Str(era.into())),
        ("method".into(), Value::Str(method.into())),
        ("tool".into(), Value::Str(tool.into())),
    ]);
    PdpRequest {
        principal: Uid::new("Mcp::User", sub),
        action: Uid::new("Mcp::Action", "invoke"),
        resource: Uid::new("Mcp::Route", route_path),
        context: ctx,
        entities: Vec::new(),
    }
}

/// `true` only for an exact Allow (F6: Deny and Error both deny).
pub fn allowed(a: &dyn Authorizer, req: &PdpRequest) -> bool {
    combine(&[a.decide(req)]) == Decision::Allow
}
