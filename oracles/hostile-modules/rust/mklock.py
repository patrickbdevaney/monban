"""One-off helper (kept for provenance): derive this workspace's Cargo.lock from oracles/isolation-fi/rust/Cargo.lock.
Same third-party set (wasmtime 50.0.1 + libc 0.2.191); only the root package differs (hostref instead of isofi,
no guest crate). Usage: python3 -I mklock.py <isolation-fi Cargo.lock> <out Cargo.lock>"""
import sys

src = open(sys.argv[1]).read()
head, rest = src.split("[[package]]", 1)
blocks = ["[[package]]" + b for b in ("[[package]]" + rest).split("[[package]]") if b.strip()]
out = []
for b in blocks:
    name = b.split('name = "', 1)[1].split('"', 1)[0]
    if name == "guest":
        continue
    if name == "isofi":
        b = b.replace('name = "isofi"', 'name = "hostref"')
    ver = b.split('version = "', 1)[1].split('"', 1)[0]
    key = [int(x) if x.isdigit() else x for x in ver.replace("-", ".").split(".")]
    out.append((name, key, b.rstrip("\n") + "\n"))
out.sort(key=lambda t: (t[0], t[1]))
open(sys.argv[2], "w").write(head + "\n".join(b for _, _, b in out))
