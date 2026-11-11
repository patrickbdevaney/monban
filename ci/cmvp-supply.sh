#!/usr/bin/env bash
# cmvp lock supply chain (PLAN-6 D12/D13, DEVIATIONS X-16). Part of the fips-lock gate.
#
#   ci/cmvp-supply.sh               vet + advisories + ledger premises over the cmvp overlay tree / profiles/cmvp/Cargo.lock
#   ci/cmvp-supply.sh --self-test   every check red on its mutants, clean fixtures green (no cargo, no network)
#
# 1. vet: `cargo vet --locked --output-format json` on the overlaid cmvp tree (profiles/cmvp/build.sh --metadata
#    prepares target/cmvp-src with the cmvp lock; the root supply-chain/ store is used unchanged). Every unvetted crate
#    must be in the frozen profiles/cmvp/vet-baseline.txt; the baseline may only shrink (ci/vet-baseline.py
#    --frozen-failures: no entry added after the freeze, stale entries must be removed).
# 2. advisories: `cargo audit --json --file profiles/cmvp/Cargo.lock`. Every reported advisory (vulnerability or
#    advisory warning) needs a live `advisory-accepted` entry in supply-chain/exceptions.toml for that crate, version
#    and advisory id, with `evidence` and `evidence_must` (whose freshness `cargo xtask ledger-check` judges). An
#    unlisted advisory, a non-advisory warning (yanked) or an empty advisory database is a FAIL.
#    CMVP_AUDIT_NO_FETCH=1 uses the local advisory DB as is (default: cargo audit fetches it, as the audit gate does).
# 3. premises of those ledger entries, each printed as one fixed `CMVP-PREMISE ...: PASS (...)` line that the entry
#    cites as `evidence_must` (log: gates/out/logs/phase6-fips-lock-cmd.log):
#    - 0042 (AWS-LC CRL scope check): no Rust source in the cmvp graph calls AWS-LC X509 verification / CRL checking;
#    - 0043 (AWS-LC AES-CCM tag timing): no Rust source in the cmvp graph calls EVP_aes_{128,192,256}_ccm;
#    - client-auth (0382 server half, 0285, 0348): no crate in the cmvp graph except rustls/rustls-webpki themselves
#      names a client-certificate verifier, so no listener verifies a WebPKI chain (D13);
#    - 0348 (Brotli certificate decompression): the cmvp rustls node is resolved without the `brotli` feature.
# Last line `CMVP-SUPPLY: PASS (...)`; exit 0 only on PASS.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

run_py() { python3 -I - "$@" <<'PY'
import json, os, re, sys, tempfile, datetime, tomllib

PREMISE = {
    "0042": "CMVP-PREMISE 0042: PASS (no Rust caller of AWS-LC X509 verification or CRL checking in the cmvp graph)",
    "0043": "CMVP-PREMISE 0043: PASS (no Rust caller of EVP_aes_*_ccm in the cmvp graph)",
    "client-auth": "CMVP-PREMISE client-auth: PASS (no client-certificate verifier in the cmvp graph)",
    "0348": "CMVP-PREMISE 0348: PASS (rustls 0.23.43 resolved without the brotli feature)",
}
# AWS-LC's chain verifier and the CRL switches that reach the 0042 code (X509_verify_cert with X509_V_FLAG_CRL_CHECK).
X509_RE = re.compile(r"\bX509_(verify_cert|STORE_CTX_init|STORE_set_flags|VERIFY_PARAM_set_flags|V_FLAG_CRL_CHECK\w*|"
                     r"STORE_add_crl)\b")
CCM_RE = re.compile(r"\bEVP_aes_(128|192|256)_ccm\b")
CLIENT_AUTH_RE = re.compile(r"\b(WebPkiClientVerifier|ClientCertVerifierBuilder|with_client_cert_verifier|"
                            r"AllowAnyAuthenticatedClient|AllowAnyAnonymousOrAuthenticatedClient|ClientCertVerifier)\b")
# Crates that define (not use) the scanned names: the scans are about callers.
DEFINERS_AWSLC = {"aws-lc-fips-sys", "aws-lc-sys"}
DEFINERS_VERIFIER = {"rustls", "rustls-webpki"}


# ------------------------------------------------------------------------------------------------ advisories
def ledger(text):
    return tomllib.loads(text).get("exception", [])


def reported(audit):
    """[(crate, version, advisory id or None, what)] from `cargo audit --json`."""
    out = []
    for v in audit.get("vulnerabilities", {}).get("list", []):
        out.append((v["package"]["name"], v["package"]["version"], v["advisory"]["id"], "vulnerability"))
    for kind, ws in (audit.get("warnings") or {}).items():
        for w in ws:
            adv = (w.get("advisory") or {}).get("id")
            out.append((w["package"]["name"], w["package"]["version"], adv, f"warning:{kind}"))
    return out


def check_advisories(audit, entries, today):
    bad = []
    if audit.get("database", {}).get("advisory-count", 0) <= 0:
        bad.append("advisory database is empty (vacuous scan)")
    if audit.get("lockfile", {}).get("dependency-count", 0) <= 0:
        bad.append("lockfile has no dependencies (vacuous scan)")
    rep = reported(audit)
    for crate, ver, adv, what in rep:
        if adv is None:
            bad.append(f"{crate}@{ver}: {what} without an advisory id (not ledgerable; fix the lock)")
            continue
        live = [e for e in entries if e.get("crate") == crate and e.get("version") == ver
                and adv in [a.strip() for a in e.get("advisory", "").split(",")]]
        if not live:
            bad.append(f"{crate}@{ver} {adv} ({what}): no ledger entry")
            continue
        ok = [e for e in live if e.get("kind") == "advisory-accepted" and e.get("evidence") and e.get("evidence_must")
              and e.get("expires", "") >= today]
        if not ok:
            bad.append(f"{crate}@{ver} {adv}: ledger entry is not a live advisory-accepted entry with evidence")
    return rep, bad


# ------------------------------------------------------------------------------------------------ premises
def graph(meta):
    """[(name, version, src dir, features)] for every package in the resolve graph."""
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    out = []
    for p in meta["packages"]:
        if p["id"] in nodes:
            out.append((p["name"], p["version"], os.path.dirname(p["manifest_path"]), nodes[p["id"]].get("features", [])))
    return out


def scan(pkgs, regex, skip):
    hits, files = [], 0
    for name, ver, d, _ in pkgs:
        if name in skip:
            continue
        for dp, dn, fn in os.walk(d):
            dn[:] = [x for x in dn if x not in ("target", ".git")]
            for f in fn:
                if not f.endswith(".rs"):
                    continue
                files += 1
                p = os.path.join(dp, f)
                try:
                    t = open(p, encoding="utf-8", errors="replace").read()
                except OSError as e:
                    hits.append(f"{name}@{ver}: unreadable {p}: {e}"); continue
                for m in regex.finditer(t):
                    line = t.count("\n", 0, m.start()) + 1
                    hits.append(f"{name}@{ver}: {os.path.relpath(p, d)}:{line}: {m.group(0)}")
    return files, hits


def check_premises(meta):
    pkgs = graph(meta)
    res, bad = {}, []
    for key, regex, skip in [("0042", X509_RE, DEFINERS_AWSLC), ("0043", CCM_RE, DEFINERS_AWSLC),
                             ("client-auth", CLIENT_AUTH_RE, DEFINERS_VERIFIER)]:
        files, hits = scan(pkgs, regex, skip)
        if files == 0:
            bad.append(f"{key}: scanned 0 Rust files (vacuous)")
        bad += [f"{key}: {h}" for h in hits]
        res[key] = (files, len(hits))
    rl = [p for p in pkgs if p[0] == "rustls"]
    if not rl:
        bad.append("0348: no rustls node in the cmvp graph")
    for name, ver, _, feats in rl:
        if "brotli" in feats:
            bad.append(f"0348: rustls@{ver} resolved with feature brotli")
    res["0348"] = (len(rl), 0)
    return res, bad


# ------------------------------------------------------------------------------------------------ self-test
def self_test():
    today = "2026-11-04"
    def entry(crate, ver, adv, kind="advisory-accepted", ev=True, exp="2027-05-04"):
        e = f'[[exception]]\ncrate = "{crate}"\nversion = "{ver}"\nkind = "{kind}"\nadvisory = "{adv}"\nreason = "r"\n' \
            f'approver = "a"\nexpires = "{exp}"\n'
        return e + ('evidence = "gates/out/logs/x.log"\nevidence_must = "X: PASS"\n' if ev else "")
    def vuln(crate, ver, adv):
        return {"advisory": {"id": adv}, "package": {"name": crate, "version": ver}}
    def audit(vulns, warnings=None, count=1403):
        return {"database": {"advisory-count": count}, "lockfile": {"dependency-count": 285},
                "vulnerabilities": {"list": vulns}, "warnings": warnings or {}}
    v0 = [vuln("rustls", "0.23.43", "RUSTSEC-2026-0349"), vuln("aws-lc-fips-sys", "0.13.11", "RUSTSEC-2026-0042")]
    led = entry("rustls", "0.23.43", "RUSTSEC-2026-0349") + entry("aws-lc-fips-sys", "0.13.11", "RUSTSEC-2026-0042")
    adv_cases = [
        ("clean", audit(v0), led, False),
        ("unlisted advisory", audit(v0 + [vuln("rustls", "0.23.43", "RUSTSEC-2099-0001")]), led, True),
        ("entry for another version", audit(v0), led.replace('"0.13.11"', '"0.13.12"'), True),
        ("entry kind cooldown-bypass", audit(v0), led.replace("advisory-accepted", "cooldown-bypass", 1), True),
        ("entry without evidence", audit(v0), entry("rustls", "0.23.43", "RUSTSEC-2026-0349", ev=False)
         + entry("aws-lc-fips-sys", "0.13.11", "RUSTSEC-2026-0042"), True),
        ("expired entry", audit(v0), led.replace("2027-05-04", "2026-11-03", 1), True),
        ("advisory only ledgered for another crate", audit(v0),
         entry("rustls", "0.23.43", "RUSTSEC-2026-0349,RUSTSEC-2026-0042"), True),
        ("unmaintained warning unlisted", audit(v0, {"unmaintained": [
            {"advisory": {"id": "RUSTSEC-2099-0002"}, "package": {"name": "nom", "version": "7.1.3"}}]}), led, True),
        ("yanked warning", audit(v0, {"yanked": [{"advisory": None, "package": {"name": "glob", "version": "0.3.4"}}]}),
         led, True),
        ("empty advisory database", audit([], count=0), led, True),
    ]
    wrong = [n for n, a, l, want in adv_cases if bool(check_advisories(a, ledger(l), today)[1]) != want]

    tmp = tempfile.mkdtemp(prefix="cmvp-supply-selftest-")
    def pkg(name, ver, src, feats=()):
        d = os.path.join(tmp, f"{name}-{ver}-{len(os.listdir(tmp))}")
        os.makedirs(os.path.join(d, "src"))
        open(os.path.join(d, "Cargo.toml"), "w").write("")
        open(os.path.join(d, "src", "lib.rs"), "w").write(src)
        pid = f"{name} {ver} ({d})"
        return {"id": pid, "name": name, "version": ver, "manifest_path": os.path.join(d, "Cargo.toml")}, \
               {"id": pid, "features": list(feats)}
    def meta(*ps):
        return {"packages": [p for p, _ in ps], "resolve": {"nodes": [n for _, n in ps]}}
    base = [
        pkg("rustls", "0.23.43", "pub struct WebPkiClientVerifier; // defines it", ["aws_lc_rs", "fips", "std"]),
        pkg("aws-lc-fips-sys", "0.13.11", "extern \"C\" { fn X509_verify_cert(); fn EVP_aes_128_ccm(); }"),
        pkg("aws-lc-rs", "1.15.3", "pub fn sign() {}"),
        pkg("monban-tls", "0.1.0", "fn f() { builder.with_no_client_auth(); }"),
    ]
    pre_cases = [
        ("clean", meta(*base), False),
        ("client-cert verifier in a workspace crate",
         meta(*base, pkg("monban-bin", "0.1.0", "let v = WebPkiClientVerifier::builder(roots);")), True),
        ("with_client_cert_verifier in a third-party crate",
         meta(*base, pkg("tokio-rustls", "0.26.6", "cfg.with_client_cert_verifier(v)")), True),
        ("X509 verification caller",
         meta(*base, pkg("aws-lc-rs", "1.15.3", "unsafe { aws_lc::X509_verify_cert(ctx) }")), True),
        ("CRL check flag", meta(*base, pkg("monban-ops", "0.1.0", "flags |= X509_V_FLAG_CRL_CHECK;")), True),
        ("AES-CCM caller", meta(*base, pkg("aws-lc-rs", "1.15.3", "aws_lc::EVP_aes_256_ccm()")), True),
        ("rustls with brotli", meta(pkg("rustls", "0.23.43", "", ["aws_lc_rs", "brotli"]), *base[1:]), True),
        ("no rustls node", meta(*base[1:]), True),
        ("nothing scanned", {"packages": [], "resolve": {"nodes": []}}, True),
    ]
    wrong += [f"premise: {n}" for n, m, want in pre_cases if bool(check_premises(m)[1]) != want]
    for dp, dn, fn in os.walk(tmp, topdown=False):
        for f in fn:
            os.remove(os.path.join(dp, f))
        os.rmdir(dp)
    n = len(adv_cases) + len(pre_cases)
    if wrong:
        print("CMVP-SUPPLY SELF-TEST: FAIL (wrong verdict on: " + "; ".join(wrong) + ")"); sys.exit(1)
    mut = n - 2
    print(f"CMVP-SUPPLY SELF-TEST: PASS ({mut}/{mut} mutants caught; clean advisory and premise fixtures pass)")


def main(argv):
    if argv[:1] == ["--self-test"]:
        return self_test()
    work, ledger_path = argv[0], argv[1]
    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    bad = []
    try:
        audit = json.load(open(os.path.join(work, "audit.json")))
        entries = ledger(open(ledger_path).read())
        meta = json.load(open(os.path.join(work, "metadata.json")))
    except (OSError, ValueError, tomllib.TOMLDecodeError) as e:
        print(f"CMVP-SUPPLY: FAIL (cannot read inputs: {e})"); sys.exit(1)
    rep, b = check_advisories(audit, entries, today)
    bad += [f"advisories: {x}" for x in b]
    for crate, ver, adv, what in rep:
        print(f"REPORTED {crate}@{ver} {adv} ({what})")
    res, b = check_premises(meta)
    bad += [f"premise {x}" for x in b]
    for key, (n, h) in res.items():
        print(f"  premise {key}: {n} {'rustls nodes' if key == '0348' else 'Rust files scanned'}, {h} hits")
    for key in PREMISE:
        if not any(x.startswith(f"premise {key}:") for x in bad):
            print(PREMISE[key])
    if bad:
        print("CMVP-SUPPLY: FAIL"); [print("  - " + x) for x in bad]; sys.exit(1)
    print(f"CMVP-SUPPLY ADVISORIES: PASS ({len(rep)} reported, each with a live advisory-accepted ledger entry)")


main(sys.argv[1:])
PY
}

if [ "${1:-}" = --self-test ]; then
  python3 -I ci/vet-baseline.py --self-test
  run_py --self-test
  exit 0
fi

export PATH="$HOME/.cache/aegis-tools/bin:$PATH"
W="$ROOT/target/cmvp-supply"
mkdir -p "$W"
profiles/cmvp/build.sh --metadata > "$W/metadata.json"

# 1. vet (exit 255 on vetting failures is expected; the JSON conclusion is judged by vet-baseline.py).
set +e
cargo vet --locked --output-format json --manifest-path "$ROOT/target/cmvp-src/Cargo.toml" > "$W/vet.json"
set -e
python3 -I ci/vet-baseline.py --frozen-failures "$W/vet.json" --baseline profiles/cmvp/vet-baseline.txt \
  ${CMVP_VET_AGAINST:+--against "$CMVP_VET_AGAINST"}

# 2 + 3. advisories and premises (cargo audit exits 1 when it reports anything; the JSON is judged below).
fetch=(); [ "${CMVP_AUDIT_NO_FETCH:-0}" = 1 ] && fetch=(--no-fetch)
set +e
cargo audit "${fetch[@]}" --json --file profiles/cmvp/Cargo.lock > "$W/audit.json"
rc=$?
set -e
[ "$rc" -le 1 ] || { echo "CMVP-SUPPLY: FAIL (cargo audit exit $rc)"; exit 1; }
run_py "$W" supply-chain/exceptions.toml
echo "CMVP-SUPPLY: PASS (vet frozen baseline, advisories ledgered, ledger premises hold)"
