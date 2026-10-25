# AEGIS explorer 02 progress (2026-10-25)
Raw artifacts: state/raw/round-002/w02/{out/*.log,run.sh,count.py,hello/,tools/,pingora/,cfg/}
Host: 32-core box load avg ~41 (siblings running) -> servers pinned via docker --cpuset-cpus=5 (1 core), --memory=512m, --network host; loadgen taskset 13,15,6. Throughput numbers = noisy; use cgroup cpu.stat usec as primary.
Built: hello = hyper 1.12.0+hyper-util 0.1.21+tokio+tokio-rustls 0.26.6+rustls 0.23.46 aws-lc-rs (aws-lc-sys 0.46.0), rustc 1.98.0, LTO fat, strip, panic=abort: 4.21 MB. pingora 0.9.0 (proxy+rustls feat) 7.24 MB.
FINDING: Pingora 0.9.0 + tokio 1.54.x panics at first accepted conn (BufStream::with_capacity(0,0), tokio PR #8494 merged 2026-09-22, shipped in 1.54.0 2026-10-19); cloudflare/pingora#1059 open 2026-10-20, maintainers: "will sync internal commit". Workaround cargo update -p tokio --precise 1.52.3. Reproduced independently.
Sizes: nginx 1.30.6 (alpine, OpenSSL 3.5.8) 1.33MB + libssl .84 + libcrypto 4.99 + pcre2 .78 + zlib .11; haproxy 3.4.7 stripped 5.97MB (+libs 7.5MB; unstripped image binary 32.4MB); caddy 2.11.7 go1.26.8 51.95MB, 147 go deps; envoy 1.40.1 106.9MB stripped static BoringSSL.
Rust deps (no-build,no-dev,no-proc-macro): hello 40 crates (39 deps), pingora 174.
FINAL: json written; nodes 11
