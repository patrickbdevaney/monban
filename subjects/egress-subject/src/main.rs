//! ssrf-corpus subject: one JSON case per stdin line, one JSON verdict per stdout line.
//!
//! Case: `{"id", "url", "dns": {host: [[addr..], ..]}, "allow_hosts": [..] ("*.x" = strict subdomains of x),
//! "allow_ports": [..], "allow_http": bool, "readmit": ["prefix", ..], "max_redirects": n, "cross_origin": bool,
//! "redirects": {url: [status, location]}, "live": bool, "deadline_ms": n, "max_bytes": n}`.
//! The i-th DNS query for a host is answered with the i-th answer set (the last repeats), so a fetcher that asks
//! twice sees the rebinding answer. Non-live cases never open a socket: the scripted connector records the vetted
//! address egress hands it and answers from `redirects` (else 200). Live cases use the real `NetConnector`
//! (plain HTTP to the harness's loopback server) and report every vetted address handed to it as a connect.
//!
//! Verdict: `{"id", "decision": "connect", "addr", "status", "connects": [..], "queries": {host: n}}` or
//! `{"id", "reject": code, "detail", "connects": [..], "queries": {..}}`.
#![forbid(unsafe_code)]

mod json;

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

use aegis_egress::{
    BoxFuture, Connector, Egress, EgressError, Exchanged, Hop, HostRule, NetConnector, Policy, Prefix, RawResponse,
    Request, Resolver, Url,
};
use json::Pj;

struct Dns {
    sets: BTreeMap<String, Vec<Vec<IpAddr>>>,
    queries: Mutex<BTreeMap<String, usize>>,
}

impl Resolver for &Dns {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>, EgressError>> {
        Box::pin(async move {
            let i = {
                let mut q = self.queries.lock().map_err(|_| EgressError::Resolve("lock".into()))?;
                let n = q.entry(host.to_string()).or_insert(0);
                let i = *n;
                *n = n.saturating_add(1);
                i
            };
            let sets = self.sets.get(host).ok_or_else(|| EgressError::Resolve("nxdomain".into()))?;
            Ok(sets.get(i).or(sets.last()).cloned().unwrap_or_default())
        })
    }
}

struct Sim {
    redirects: BTreeMap<String, (u16, String)>,
    connects: Mutex<Vec<SocketAddr>>,
}

impl Connector for &Sim {
    fn exchange<'a>(&'a self, hop: Hop<'a>) -> BoxFuture<'a, Result<Exchanged, EgressError>> {
        Box::pin(async move {
            let peer = hop.addrs.first().ok_or_else(|| EgressError::Connect("no address".into()))?.get();
            if let Ok(mut c) = self.connects.lock() {
                c.push(peer);
            }
            let response = match self.redirects.get(&hop.url.to_string()) {
                Some((s, l)) => {
                    RawResponse { status: *s, headers: vec![("location".into(), l.as_bytes().to_vec())], body: vec![] }
                }
                None => RawResponse { status: 200, headers: vec![], body: b"sim".to_vec() },
            };
            Ok(Exchanged { peer, response })
        })
    }
}

struct Live {
    net: NetConnector,
    connects: Mutex<Vec<SocketAddr>>,
}

impl Connector for &Live {
    fn exchange<'a>(&'a self, hop: Hop<'a>) -> BoxFuture<'a, Result<Exchanged, EgressError>> {
        Box::pin(async move {
            // Report every address NetConnector may dial for this hop, before dialling (over-reports in the safe
            // direction; a failed or timed-out exchange still shows its connect).
            if let Ok(mut c) = self.connects.lock() {
                c.extend(hop.addrs.iter().map(|a| a.get()));
            }
            self.net.exchange(hop).await
        })
    }
}

fn s(v: Option<&Pj>) -> Option<String> {
    match v {
        Some(Pj::Str(b)) => String::from_utf8(b.clone()).ok(),
        _ => None,
    }
}

fn num(v: Option<&Pj>) -> Option<u64> {
    match v {
        Some(Pj::Num(n)) => n.parse().ok(),
        _ => None,
    }
}

fn strs(v: Option<&Pj>) -> Vec<String> {
    match v {
        Some(Pj::Arr(a)) => a.iter().filter_map(|x| s(Some(x))).collect(),
        _ => Vec::new(),
    }
}

fn policy(c: &Pj) -> Result<Policy, String> {
    let mut p = Policy {
        allowed_hosts: strs(c.get("allow_hosts"))
            .into_iter()
            .map(|h| match h.strip_prefix("*.") {
                Some(sfx) => HostRule::Suffix(sfx.to_string()),
                None => HostRule::Exact(h),
            })
            .collect(),
        allow_plain_http: c.get("allow_http").is_none_or(Pj::truthy),
        cross_origin_redirects: c.get("cross_origin").is_some_and(Pj::truthy),
        ..Policy::default()
    };
    if let Some(Pj::Arr(a)) = c.get("allow_ports") {
        for x in a {
            p.allowed_ports.push(num(Some(x)).and_then(|n| u16::try_from(n).ok()).ok_or("bad allow_ports")?);
        }
    }
    for r in strs(c.get("readmit")) {
        p.readmit.push(Prefix::parse(&r).ok_or_else(|| format!("bad readmit {r}"))?);
    }
    if let Some(n) = num(c.get("max_redirects")) {
        p.max_redirects = u8::try_from(n).map_err(|_| "bad max_redirects")?;
    }
    if let Some(n) = num(c.get("deadline_ms")) {
        p.deadline = Duration::from_millis(n);
    }
    if let Some(n) = num(c.get("max_bytes")) {
        p.max_response_bytes = usize::try_from(n).map_err(|_| "bad max_bytes")?;
    }
    Ok(p)
}

fn dns(c: &Pj) -> Result<Dns, String> {
    let mut sets = BTreeMap::new();
    if let Some(Pj::Obj(m)) = c.get("dns") {
        for (host, v) in m {
            let host = String::from_utf8(host.clone()).map_err(|_| "bad dns host")?;
            let Pj::Arr(rounds) = v else { return Err("dns rounds must be arrays".into()) };
            let mut rs = Vec::new();
            for r in rounds {
                let mut set = Vec::new();
                for a in strs(Some(r)) {
                    set.push(a.parse::<IpAddr>().map_err(|_| format!("bad dns answer {a}"))?);
                }
                rs.push(set);
            }
            sets.insert(host, rs);
        }
    }
    Ok(Dns { sets, queries: Mutex::new(BTreeMap::new()) })
}

fn redirects(c: &Pj) -> Result<BTreeMap<String, (u16, String)>, String> {
    let mut out = BTreeMap::new();
    if let Some(Pj::Obj(m)) = c.get("redirects") {
        for (k, v) in m {
            let k = String::from_utf8(k.clone()).map_err(|_| "bad redirect key")?;
            let Pj::Arr(a) = v else { return Err("redirect must be [status, location]".into()) };
            let status = num(a.first()).and_then(|n| u16::try_from(n).ok()).ok_or("bad redirect status")?;
            out.insert(k, (status, s(a.get(1)).ok_or("bad redirect location")?));
        }
    }
    Ok(out)
}

fn push_list(out: &mut String, key: &str, items: &[SocketAddr]) {
    out.push_str(&format!(",\"{key}\":["));
    for (i, a) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        json::write_str(out, a.to_string().as_bytes());
    }
    out.push(']');
}

fn handle(rt: &tokio::runtime::Runtime, line: &[u8]) -> String {
    let mut out = String::from("{\"id\":");
    let Some(c) = json::parse(line) else {
        return "{\"error\":\"bad json\"}".into();
    };
    json::write_str(&mut out, s(c.get("id")).unwrap_or_default().as_bytes());
    let setup = (|| -> Result<_, String> { Ok((policy(&c)?, dns(&c)?, redirects(&c)?)) })();
    let (pol, dns, redirects) = match setup {
        Ok(x) => x,
        Err(e) => {
            out.push_str(",\"error\":");
            json::write_str(&mut out, e.as_bytes());
            out.push('}');
            return out;
        }
    };
    let url = s(c.get("url")).unwrap_or_default();
    let live = c.get("live").is_some_and(Pj::truthy);
    let sim = Sim { redirects, connects: Mutex::new(Vec::new()) };
    let net = Live { net: NetConnector::plain(), connects: Mutex::new(Vec::new()) };
    let result = rt.block_on(async {
        let req = Request::get(Url::parse(&url)?);
        if live {
            Egress::new(&dns, &net).fetch(&pol, req).await
        } else {
            Egress::new(&dns, &sim).fetch(&pol, req).await
        }
    });
    let connects = if live { &net.connects } else { &sim.connects };
    let connects: Vec<SocketAddr> = connects.lock().map(|g| g.clone()).unwrap_or_default();
    match &result {
        Ok(r) => {
            out.push_str(",\"decision\":\"connect\",\"addr\":");
            json::write_str(&mut out, r.peers.last().map(|p| p.to_string()).unwrap_or_default().as_bytes());
            out.push_str(&format!(",\"status\":{},\"body_len\":{}", r.status, r.body.len()));
        }
        Err(e) => {
            out.push_str(",\"reject\":");
            json::write_str(&mut out, e.code().as_bytes());
            out.push_str(",\"detail\":");
            json::write_str(&mut out, e.to_string().as_bytes());
        }
    }
    push_list(&mut out, "connects", &connects);
    out.push_str(",\"queries\":{");
    if let Ok(q) = dns.queries.lock() {
        for (i, (h, n)) in q.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            json::write_str(&mut out, h.as_bytes());
            out.push_str(&format!(":{n}"));
        }
    }
    out.push_str("}}");
    out
}

fn main() {
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("egress-subject: runtime: {e}");
            std::process::exit(2);
        }
    };
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().split(b'\n') {
        let Ok(line) = line else { break };
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let reply = handle(&rt, &line);
        if writeln!(stdout, "{reply}").and_then(|()| stdout.flush()).is_err() {
            break;
        }
    }
}
