//! Outbound fetch: resolved-address connect, redirect policy, SSRF guard (ARCHITECTURE 3.3 webhooks "egress guard",
//! 3.6 narrow fetch host function, never wasi-http; 3.9 resolved-address egress).
//!
//! Flow per hop ([`fetch::Egress::fetch`]):
//! 1. strict URL parse ([`url::Url`], aegis-canon host rules, no IDNA, canonical dotted-quad only, no zone ids,
//!    no userinfo);
//! 2. policy: scheme, host allowlist, port ([`policy::Policy`]);
//! 3. resolve the name **once** through the injected [`fetch::Resolver`] and classify **every** answer
//!    ([`addr::classify`]); one forbidden answer rejects the hop;
//! 4. connect to a vetted IP literal ([`fetch::VettedAddr`]) only, never the hostname (DNS-rebinding defence);
//!    SNI and `Host` come from the original name;
//! 5. redirects: at most `max_redirects`, each hop re-vetted from step 1, https→http refused, cross-origin only if
//!    the policy allows (credentials stripped);
//! 6. one deadline over the whole fetch, caps on response head and body.
//!
//! The rustls client handshake lives behind the `tls-client` feature (off by default) so the cmvp build compiles it
//! out (spikes/cmvp-client-policy). This crate builds no `ClientConfig`: the TLS profile is built by aegis-tls
//! (`aegis_tls::client_config`) and injected through [`TlsClient::from_config`].
#![forbid(unsafe_code)]

pub mod addr;
pub mod error;
pub mod fetch;
pub mod http1;
pub mod policy;
#[cfg(feature = "tls-client")]
pub mod tls;
pub mod url;

#[cfg(test)]
mod tests;

pub use addr::{AddrClass, Prefix, classify};
pub use error::EgressError;
pub use fetch::{
    BoxFuture, Connector, Egress, Exchanged, Hop, NetConnector, Request, Resolver, Response, SystemResolver,
    VettedAddr, check_addr, vet,
};
pub use http1::{Method, RawResponse};
pub use policy::{HostRule, Policy};
#[cfg(feature = "tls-client")]
pub use tls::TlsClient;
pub use url::{Host, Scheme, Url};
