//! q3-008: cost of discard-on-cancel (NC3) vs state-tracked reuse for a tokio-postgres client.
//!
//! Modes (one cycle each):
//!   connect          connect (TCP [+TLS] + auth + backend fork) + `SELECT 1`, then drop. Pure reconnect.
//!   discard          held conn: BEGIN; `SELECT pg_sleep(0.05)` cancelled by a 2 ms timeout (future dropped
//!                    mid-protocol); fire-and-forget CancelRequest so the orphan backend stops; drop the conn;
//!                    connect a replacement; `SELECT 1`. Timed from the drop to the replacement being ready.
//!   discard-nocancel same, without the CancelRequest (orphan backend runs the query out, then sees EOF).
//!   reuse            held conn: same cancelled query; await CancelRequest; `ROLLBACK`; `DISCARD ALL`;
//!                    `SELECT 1` sentinel on the SAME conn. Any error => counted + fall back to discard.
//! Output: one JSON line.
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_postgres::tls::MakeTlsConnect;
use tokio_postgres::{Client, Config, NoTls, Socket};

#[derive(Clone)]
struct Args {
    mode: String,
    tls: String,
    host: String,
    port: u16,
    user: String,
    password: String,
    ca: String,
    n: u64,
    secs: f64,
    warmup: u64,
    conc: usize,
    cgroup: String,
    label: String,
}

fn parse() -> Args {
    let mut a = Args {
        mode: "connect".into(),
        tls: "off".into(),
        host: "127.0.0.1".into(),
        port: 55432,
        user: "postgres".into(),
        password: "benchpw".into(),
        ca: String::new(),
        n: 0,
        secs: 0.0,
        warmup: 100,
        conc: 1,
        cgroup: String::new(),
        label: String::new(),
    };
    let v: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i + 1 < v.len() {
        let (k, val) = (v[i].as_str(), v[i + 1].clone());
        match k {
            "--mode" => a.mode = val,
            "--tls" => a.tls = val,
            "--host" => a.host = val,
            "--port" => a.port = val.parse().unwrap_or(55432),
            "--user" => a.user = val,
            "--password" => a.password = val,
            "--ca" => a.ca = val,
            "--n" => a.n = val.parse().unwrap_or(0),
            "--secs" => a.secs = val.parse().unwrap_or(0.0),
            "--warmup" => a.warmup = val.parse().unwrap_or(0),
            "--conc" => a.conc = val.parse().unwrap_or(1),
            "--cgroup" => a.cgroup = val,
            "--label" => a.label = val,
            _ => {
                eprintln!("unknown arg {k}");
                std::process::exit(2)
            }
        }
        i += 2;
    }
    a
}

fn cpu_self_us() -> u64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let t = |tv: libc::timeval| tv.tv_sec as u64 * 1_000_000 + tv.tv_usec as u64;
    t(ru.ru_utime) + t(ru.ru_stime)
}

fn cgroup_us(path: &str) -> u64 {
    if path.is_empty() {
        return 0;
    }
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("usage_usec"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        })
        .unwrap_or(0)
}

struct Stats {
    lat_us: Mutex<Vec<f64>>,
    done: AtomicU64,
    errors: AtomicU64,
    reuse_fail: AtomicU64,
    stop: AtomicBool,
}

async fn connect<T>(cfg: &Config, tls: T) -> Result<Client, tokio_postgres::Error>
where
    T: MakeTlsConnect<Socket> + Send + 'static,
    T::Stream: Send + 'static,
{
    let (client, conn) = cfg.connect(tls).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(client)
}

async fn ready<T>(cfg: &Config, tls: T) -> Result<Client, tokio_postgres::Error>
where
    T: MakeTlsConnect<Socket> + Send + 'static,
    T::Stream: Send + 'static,
{
    let c = connect(cfg, tls).await?;
    c.simple_query("SELECT 1").await?;
    Ok(c)
}

/// Put the held connection mid-protocol: open txn, then drop a query future after it was sent.
async fn cancel_midflight(c: &Client) -> Result<(), tokio_postgres::Error> {
    c.batch_execute("BEGIN").await?;
    let _ = tokio::time::timeout(Duration::from_millis(2), c.batch_execute("SELECT pg_sleep(0.05)")).await;
    Ok(())
}

async fn worker<T>(a: Arc<Args>, cfg: Arc<Config>, tls: T, st: Arc<Stats>, quota: u64, record: bool)
where
    T: MakeTlsConnect<Socket> + Clone + Send + Sync + 'static,
    T::Stream: Send + 'static,
    T::TlsConnect: Send,
    <T::TlsConnect as tokio_postgres::tls::TlsConnect<Socket>>::Future: Send,
{
    let mut held: Option<Client> = None;
    let mut i = 0u64;
    while (quota == 0 || i < quota) && !st.stop.load(Ordering::Relaxed) {
        i += 1;
        let r: Result<f64, tokio_postgres::Error> = async {
            match a.mode.as_str() {
                "connect" => {
                    let t0 = Instant::now();
                    let c = ready(&cfg, tls.clone()).await?;
                    let dt = t0.elapsed();
                    drop(c);
                    Ok(dt.as_secs_f64() * 1e6)
                }
                "discard" | "discard-nocancel" | "reuse" => {
                    if held.is_none() {
                        held = Some(ready(&cfg, tls.clone()).await?);
                    }
                    let c = held.take().unwrap();
                    cancel_midflight(&c).await?;
                    let t0 = Instant::now();
                    if a.mode == "reuse" {
                        let ok: Result<(), tokio_postgres::Error> = async {
                            c.cancel_token().cancel_query(tls.clone()).await?;
                            c.batch_execute("ROLLBACK").await?;
                            c.batch_execute("DISCARD ALL").await?;
                            c.clear_type_cache();
                            c.simple_query("SELECT 1").await?;
                            Ok(())
                        }
                        .await;
                        if ok.is_ok() {
                            held = Some(c);
                        } else {
                            st.reuse_fail.fetch_add(1, Ordering::Relaxed);
                            drop(c);
                            held = Some(ready(&cfg, tls.clone()).await?);
                        }
                    } else {
                        if a.mode == "discard" {
                            let tok = c.cancel_token();
                            let t2 = tls.clone();
                            tokio::spawn(async move {
                                let _ = tok.cancel_query(t2).await;
                            });
                        }
                        drop(c);
                        held = Some(ready(&cfg, tls.clone()).await?);
                    }
                    Ok(t0.elapsed().as_secs_f64() * 1e6)
                }
                m => panic!("bad mode {m}"),
            }
        }
        .await;
        match r {
            Ok(us) => {
                if record {
                    st.lat_us.lock().unwrap().push(us);
                    st.done.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(e) => {
                if st.errors.fetch_add(1, Ordering::Relaxed) < 3 {
                    eprintln!("error: {e:?}");
                }
                held = None;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }
}

async fn run<T>(a: Args, tls: T)
where
    T: MakeTlsConnect<Socket> + Clone + Send + Sync + 'static,
    T::Stream: Send + 'static,
    T::TlsConnect: Send,
    <T::TlsConnect as tokio_postgres::tls::TlsConnect<Socket>>::Future: Send,
{
    let mut cfg = Config::new();
    cfg.host(&a.host).port(a.port).user(&a.user).password(&a.password).dbname("postgres");
    cfg.ssl_mode(if a.tls == "off" {
        tokio_postgres::config::SslMode::Disable
    } else {
        tokio_postgres::config::SslMode::Require
    });
    let cfg = Arc::new(cfg);
    let a = Arc::new(a);
    let mk = || {
        Arc::new(Stats {
            lat_us: Mutex::new(Vec::new()),
            done: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            reuse_fail: AtomicU64::new(0),
            stop: AtomicBool::new(false),
        })
    };
    // warmup (not recorded)
    let wst = mk();
    let mut hs = vec![];
    for _ in 0..a.conc {
        hs.push(tokio::spawn(worker(a.clone(), cfg.clone(), tls.clone(), wst.clone(), (a.warmup / a.conc as u64).max(1), false)));
    }
    for h in hs {
        let _ = h.await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let st = mk();
    let (c0, s0, t0) = (cpu_self_us(), cgroup_us(&a.cgroup), Instant::now());
    let quota = if a.n > 0 { (a.n / a.conc as u64).max(1) } else { 0 };
    let mut hs = vec![];
    for _ in 0..a.conc {
        hs.push(tokio::spawn(worker(a.clone(), cfg.clone(), tls.clone(), st.clone(), quota, true)));
    }
    if a.n == 0 {
        tokio::time::sleep(Duration::from_secs_f64(a.secs)).await;
        st.stop.store(true, Ordering::Relaxed);
    }
    for h in hs {
        let _ = h.await;
    }
    let wall = t0.elapsed().as_secs_f64();
    let (c1, s1) = (cpu_self_us(), cgroup_us(&a.cgroup));
    let mut v = st.lat_us.lock().unwrap().clone();
    v.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let q = |p: f64| if v.is_empty() { 0.0 } else { v[(((v.len() as f64) * p) as usize).min(v.len() - 1)] };
    let n = v.len() as f64;
    let mean = if v.is_empty() { 0.0 } else { v.iter().sum::<f64>() / n };
    let cc = (c1 - c0) as f64;
    let sc = s1.saturating_sub(s0) as f64;
    println!(
        "{{\"label\":\"{}\",\"mode\":\"{}\",\"tls\":\"{}\",\"user\":\"{}\",\"conc\":{},\"cycles\":{},\"wall_s\":{:.3},\"rate_per_s\":{:.1},\"p50_us\":{:.0},\"p90_us\":{:.0},\"p99_us\":{:.0},\"p999_us\":{:.0},\"max_us\":{:.0},\"mean_us\":{:.0},\"client_cpu_us_per_cycle\":{:.0},\"client_cpu_util\":{:.3},\"server_cpu_us_per_cycle\":{:.0},\"server_cpu_util\":{:.3},\"errors\":{},\"reuse_fail\":{}}}",
        a.label, a.mode, a.tls, a.user, a.conc, v.len(), wall, n / wall, q(0.5), q(0.9), q(0.99), q(0.999),
        v.last().copied().unwrap_or(0.0), mean, cc / n.max(1.0), cc / 1e6 / wall,
        if a.cgroup.is_empty() { -1.0 } else { sc / n.max(1.0) }, sc / 1e6 / wall,
        st.errors.load(Ordering::Relaxed), st.reuse_fail.load(Ordering::Relaxed)
    );
}

fn main() {
    let a = parse();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    if a.tls == "off" {
        rt.block_on(run(a, NoTls));
    } else {
        use rustls::crypto::aws_lc_rs::{default_provider, kx_group};
        let mut p = default_provider();
        p.kx_groups = match a.tls.as_str() {
            "p256" => vec![kx_group::SECP256R1],
            "x25519" => vec![kx_group::X25519],
            "pq" => vec![kx_group::X25519MLKEM768],
            _ => p.kx_groups, // "default": rustls default order (HRR against PG17's single P-256 group)
        };
        let mut roots = rustls::RootCertStore::empty();
        let pem = std::fs::read(&a.ca).expect("--ca");
        for c in rustls_pemfile::certs(&mut &pem[..]) {
            roots.add(c.unwrap()).unwrap();
        }
        let cc = rustls::ClientConfig::builder_with_provider(Arc::new(p))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let tls = tokio_postgres_rustls::MakeRustlsConnect::new(cc);
        rt.block_on(run(a, tls));
    }
}
