//! Admin listener (loopback TCP or a unix socket; never public): `GET /metrics` (OpenMetrics, every golden family
//! from the aegis-metrics registry plus `aegis_proxy_*` counters) and `GET /healthz`. Always on: no feature flag.
//! One request per connection, bounded head (8 KiB) and deadline (5 s).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use aegis_metrics::{Family, FamilyDesc, MetricType, Sample, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::shared::Shared;
use crate::util::find_head_end;

const MAX_HEAD: usize = 8 * 1024;
const DEADLINE: Duration = Duration::from_secs(5);

const fn counter(name: &'static str, help: &'static str) -> FamilyDesc {
    FamilyDesc { name, kind: MetricType::Counter, unit: None, help, labels: &[] }
}

const REQUESTS: FamilyDesc = counter("aegis_proxy_requests", "Inbound requests that reached the proxy pipeline.");
const FORWARDED: FamilyDesc = counter("aegis_proxy_forwarded", "Requests forwarded upstream that got a response.");
const AUTHZ_DENIED: FamilyDesc = counter(
    "aegis_proxy_authz_denied",
    "Requests denied by the route authz requirement (INV-NONEMPTY / unknown policy).",
);
const CANON_REJECTS: FamilyDesc =
    counter("aegis_proxy_canon_rejects", "Requests refused by canonicalization or routing (308/400/404/421/501...).");
const UP_ERRORS: FamilyDesc = counter("aegis_proxy_upstream_errors", "Upstream exchanges that failed (502/504).");
const UP_CONNECTS: FamilyDesc = counter("aegis_proxy_upstream_connects", "New upstream connections opened.");
const RELOADS: FamilyDesc = counter("aegis_proxy_config_reloads", "Config reloads applied (SIGHUP).");

/// The full exposition.
pub fn metrics_text(shared: &Shared) -> Result<String, String> {
    let na = shared.cert_not_after.load(Ordering::Relaxed);
    if na != i64::MIN {
        let secs = aegis_ops::cert::seconds_to_expiry(na, crate::util::unix_s());
        shared.registry.cert_seconds_to_expiry.set(aegis_metrics::CertSlot::Serving, secs);
    }
    let st = &shared.stats;
    let extra = [
        (REQUESTS, &st.requests),
        (FORWARDED, &st.forwarded),
        (AUTHZ_DENIED, &st.authz_denied),
        (CANON_REJECTS, &st.canon_rejects),
        (UP_ERRORS, &st.upstream_errors),
        (UP_CONNECTS, &st.upstream_connects),
        (RELOADS, &st.config_reloads),
    ];
    let mut fams: Vec<Family<'static>> = shared.registry.families();
    for (desc, v) in extra {
        fams.push(Family {
            desc,
            samples: vec![Sample { labels: Vec::new(), value: Value::Unsigned(v.load(Ordering::Relaxed)) }],
        });
    }
    aegis_metrics::render(&fams).map_err(|e| format!("{e:?}"))
}

/// `/healthz`. `fips.module` is the linked FIPS module's own version string (PLAN-6 D2; `null` on the floor build);
/// `fips.cosign` is the audit checkpoint cosignature algorithm: `"mldsa87"` on the floor build (every checkpoint carries
/// an ML-DSA-87 cosignature), `"none"` on the cmvp build, where ML-DSA-87 is compiled out
/// (`fips.cosign_mldsa87 = "compiled-out"`, PLAN-6 D15).
fn healthz(shared: &Shared, fips: &aegis_tls::FipsStatus) -> String {
    let snap = shared.snapshot();
    // The module string comes from the C library; emit it only if it is plain printable ASCII without JSON
    // metacharacters, else report it as unreadable rather than splice it into the JSON.
    let module = match fips.module {
        None => "null".to_string(),
        Some(m) if m.bytes().all(|b| (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\') => format!("\"{m}\""),
        Some(_) => "\"unreadable\"".to_string(),
    };
    format!(
        "{{\"status\":\"{}\",\"generation\":{},\"config_hash\":\"{}\",\"fips\":{{\"config_fips\":{},\"module_fips_mode\":{},\"module\":{},\"cmvp_claim\":{},\"cosign\":\"{}\",\"cosign_mldsa87\":\"{}\"}}}}\n",
        if shared.is_draining() { "draining" } else { "ok" },
        snap.generation,
        aegis_config::hex(&snap.hash),
        fips.config_fips,
        fips.module_fips_mode,
        module,
        fips.cmvp_claim,
        if aegis_audit::MLDSA87_COSIGN { "mldsa87" } else { "none" },
        if aegis_audit::MLDSA87_COSIGN { "available" } else { "compiled-out" },
    )
}

/// Serve one admin connection.
pub async fn handle<IO: AsyncRead + AsyncWrite + Unpin>(
    shared: Arc<Shared>,
    fips: Arc<aegis_tls::FipsStatus>,
    mut io: IO,
) {
    let work = async {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 2048];
        let end = loop {
            if let Some(e) = find_head_end(&buf) {
                break e;
            }
            if buf.len() > MAX_HEAD {
                return Some((431u16, "text/plain", String::new()));
            }
            let n = io.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
        };
        let line = buf.get(..end).unwrap_or(&[]).split(|&b| b == b'\r').next().unwrap_or(&[]);
        let mut parts = line.split(|&b| b == b' ');
        let (method, target) = (parts.next().unwrap_or(&[]), parts.next().unwrap_or(&[]));
        let path = target.split(|&b| b == b'?').next().unwrap_or(&[]);
        Some(match (method, path) {
            (b"GET", b"/metrics") => match metrics_text(&shared) {
                Ok(t) => (200, aegis_metrics::CONTENT_TYPE, t),
                Err(e) => (500, "text/plain", format!("{e}\n")),
            },
            (b"GET", b"/healthz") => (200, "application/json", healthz(&shared, &fips)),
            (b"GET", _) => (404, "text/plain", "not found\n".to_string()),
            _ => (405, "text/plain", "method not allowed\n".to_string()),
        })
    };
    let Ok(Some((status, ct, body))) = timeout(DEADLINE, work).await else { return };
    let resp = format!(
        "HTTP/1.1 {status} {}\r\ncontent-type: {ct}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        crate::util::reason(status),
        body.len()
    );
    let _ = timeout(DEADLINE, io.write_all(resp.as_bytes())).await;
    let _ = timeout(DEADLINE, io.shutdown()).await;
}
