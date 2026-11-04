#!/usr/bin/env bash
# Gate release-rebuild (P6-release-002; PLAN-6 D7; PREFLIGHT D-P5). Runs on the laptop and drives two machines:
#
#   ci/release/rebuild.sh --a kamrui --b quiet --profiles floor,cmvp
#   ci/release/rebuild.sh --self-test
#
# Build A: ci/release/pipeline.sh on kamrui through ci/remote.sh --host kamrui (the attested release: build, sbom,
#   attest, sign, tuf). Its output, including the `RELEASE-PIPELINE: PASS (<profile>, artifacts/aegis-<profile> sha256
#   <hex> ...` line that conformance/run reads from this gate's log, is streamed to stdout.
# Build B: the dedicated GCP VM aegis-quiet (ssh alias `quiet`), started by ci/release/vm.sh and ALWAYS stopped again
#   (EXIT trap; TERMINATED is checked with gcloud compute instances describe). B is provisioned independently of A:
#   - docker from the VM's own apt (first use only; the VM is a dedicated AEGIS box);
#   - the base image pulled by digest and the build image rebuilt from deploy/build/al2023.Containerfile
#     (deploy/build/image.sh, < 500 MB asserted);
#   - the Rust toolchain fetched on the VM from static.rust-lang.org (rustc, cargo, rust-std of the channel pinned in
#     rust-toolchain.toml): the channel manifest's published .sha256 is checked, every component's sha256 is checked
#     against that manifest AND against the hashes in kamrui's rustup manifest for the same channel;
#   - Go and cargo-auditable fetched on the VM from their ci/tools.lock URLs, sha256 checked against ci/tools.lock;
#   - a fresh CARGO_HOME filled by `cargo fetch --locked` from crates.io (cargo checks every crate against Cargo.lock);
#   - the source is `git archive <commit>` from the laptop (cmvp: the same overlay as the pipeline), and its tree
#     sha256 must equal the tree sha256 in A's provenance;
#   - then only the build job (ci/release/jobs/build.sh from that source) runs, with builder id
#     urn:aegis:ci:gcp-aegis-quiet:release-rebuild:v1 (A's is urn:aegis:ci:kamrui:release-pipeline:v1).
# Gate, per profile (both must pass):
#   sha256(A) = sha256(B) = the subject digest in A's provenance, whose DSSE signature verifies with A's attest key;
#   B's build record matches the attested recipe (source commit and tree sha256, SOURCE_DATE_EPOCH, command,
#   RUSTFLAGS, base image digest, Containerfile sha256, rustc -vV, cargo -V, Go and gcc versions, Cargo.lock and
#   cargo-auditable sha256); the builder ids differ; and ci/release/verify.py on A's release on kamrui passes with
#   --expect-sha256 <B's digest> (REL-1..5 plus the rebuild digest).
# The binary does not depend on SOURCE_DATE_EPOCH (ci/repro.sh requires that), so a B built with another epoch is
# caught by the recipe comparison, not by its digest.
# Final line: RELEASE-REBUILD: PASS (...) or RELEASE-REBUILD: FAIL (...). Records stay in target/release-rebuild/.
#
# --self-test needs neither kamrui nor the VM: the gate's decision is a pure function of (A's provenance and attest
# key, sha256(A), B's build record, sha256(B)), implemented once in check() below and fed here with real-format
# provenance made by ci/release/jobs/attest.py with a throwaway key. It requires: the clean case passes; B with another
# SOURCE_DATE_EPOCH fails; an attestation (validly signed) naming another digest fails; an envelope whose payload was
# edited to name another digest fails its signature; B's digest differing fails; B reusing A's builder id fails. When
# records of a real run exist in target/release-rebuild/<profile>/ they are replayed too (clean must pass, the epoch
# and digest mutants must fail).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REL="$ROOT/ci/release"
OUTROOT="$ROOT/target/release-rebuild"
B_BUILDER="urn:aegis:ci:gcp-aegis-quiet:release-rebuild:v1"
CHECK_PY="$(mktemp)"; trap 'rm -f "$CHECK_PY"' EXIT

# ------------------------------------------------------------------ the gate's check (laptop, python3 -I, stdlib)
cat > "$CHECK_PY" << 'PYEOF'
"""check.py --profile P --a DIR --b DIR: A = provenance.intoto.json, attest.pub.pem, aegis-P; B = aegis-P,
build-info.json, b-record.json. Last line REBUILD-CHECK: PASS (...) / FAIL (...)."""
import base64, hashlib, json, os, subprocess, sys, tempfile

DSSE = "application/vnd.in-toto+json"


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main(argv):
    a = dict(zip(argv[::2], argv[1::2]))
    prof, A, B = a["--profile"], a["--a"], a["--b"]
    art = f"artifacts/aegis-{prof}"
    errs = []
    env = json.load(open(os.path.join(A, "provenance.intoto.json")))
    if env.get("payloadType") != DSSE or len(env.get("signatures", [])) != 1:
        return f"FAIL ({prof}: provenance is not a single-signature DSSE in-toto envelope)"
    payload = base64.b64decode(env["payload"], validate=True)
    sig = base64.b64decode(env["signatures"][0]["sig"], validate=True)
    t = DSSE.encode()
    pae = b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "m"), "wb").write(pae)
        open(os.path.join(d, "s"), "wb").write(sig)
        v = subprocess.run([os.environ.get("AEGIS_OPENSSL", "/usr/bin/openssl"), "pkeyutl", "-verify", "-rawin", "-pubin",
                            "-inkey", os.path.join(A, "attest.pub.pem"), "-in", os.path.join(d, "m"),
                            "-sigfile", os.path.join(d, "s")], capture_output=True)
    if v.returncode != 0:
        return f"FAIL ({prof}: attestation signature does not verify with A's attest key)"
    st = json.loads(payload)
    if st.get("_type") != "https://in-toto.io/Statement/v1" or st.get("predicateType") != "https://slsa.dev/provenance/v1":
        return f"FAIL ({prof}: payload is not an in-toto v1 SLSA provenance v1 statement)"
    subj = st.get("subject") or []
    named = [s for s in subj if s.get("name") == art]
    if len(subj) != 1 or len(named) != 1:
        return f"FAIL ({prof}: provenance must have exactly one subject {art}, has {[s.get('name') for s in subj]})"
    d_att = named[0]["digest"]["sha256"]
    d_a = sha(os.path.join(A, f"aegis-{prof}"))
    d_b = sha(os.path.join(B, f"aegis-{prof}"))
    bi = json.load(open(os.path.join(B, "build-info.json")))
    br = json.load(open(os.path.join(B, "b-record.json")))
    if d_a != d_att:
        errs.append(f"sha256(A) {d_a} != attested {d_att}")
    if d_b != d_att:
        errs.append(f"sha256(B) {d_b} != attested {d_att}")
    if bi.get("sha256") != d_b or br.get("sha256") != d_b:
        errs.append("B's build record does not name sha256(B)")
    bd, rd = st["predicate"]["buildDefinition"], st["predicate"]["runDetails"]
    ep, ip = bd["externalParameters"], bd["internalParameters"]
    deps = {x.get("uri"): x for x in bd.get("resolvedDependencies", [])}
    recipe = [
        ("profile", ep.get("profile"), bi.get("profile")),
        ("source commit", ep["source"]["commit"], br.get("commit")),
        ("source tree sha256", ep["source"]["tree_sha256"], br.get("tree_sha256")),
        ("SOURCE_DATE_EPOCH", ep.get("source_date_epoch"), bi.get("source_date_epoch")),
        ("command", ep.get("command"), bi.get("command")),
        ("RUSTFLAGS", ip.get("rustflags"), bi.get("rustflags")),
        ("base image", ip["build_image"].get("base"), bi["image"].get("base")),
        ("Containerfile sha256", ip["build_image"].get("containerfile_sha256"), bi["image"].get("containerfile_sha256")),
        ("rustc -vV", ip.get("rustc_vV"), bi.get("rustc_vV")),
        ("cargo -V", ip.get("cargo_V"), bi.get("cargo_V")),
        ("go version", ip.get("go_version"), bi.get("go_version")),
        ("gcc version", ip.get("cc_version"), bi.get("cc_version")),
        ("in-container paths", ip.get("paths"), bi.get("paths")),
        ("Cargo.lock sha256", deps.get("file:Cargo.lock", {}).get("digest", {}).get("sha256"), bi.get("cargo_lock_sha256")),
        ("cargo-auditable sha256", deps.get("tool:cargo-auditable", {}).get("digest", {}).get("sha256"),
         bi.get("cargo_auditable_sha256")),
    ]
    for what, want, got in recipe:
        if want is None or want != got:
            errs.append(f"recipe {what}: attested {str(want)[:80]!r} != B {str(got)[:80]!r}")
    a_id, b_id = rd.get("builder", {}).get("id"), br.get("builder_id")
    if not a_id or not b_id or a_id == b_id:
        errs.append(f"builder ids must be distinct and non-empty (A {a_id!r}, B {b_id!r})")
    if errs:
        return f"FAIL ({prof}: " + "; ".join(errs) + ")"
    img = "same" if ip["build_image"].get("id") == bi["image"].get("id") else "rebuilt, different id"
    return (f"PASS ({prof} sha256 {d_att}: A = B = attested; recipe matches ({len(recipe)} fields); "
            f"builders {a_id} / {b_id}; image {img})")


if __name__ == "__main__":
    r = main(sys.argv[1:])
    print(f"REBUILD-CHECK: {r}")
    sys.exit(0 if r.startswith("PASS") else 1)
PYEOF
check() { python3 -I "$CHECK_PY" --profile "$1" --a "$2" --b "$3"; }

# ------------------------------------------------------------------ self-test
self_test() {
  local fails=0 out n=0
  T="$(mktemp -d)"; trap 'rm -rf "$T" "$CHECK_PY"' EXIT  # global: the EXIT trap runs after this function returns
  expect() {  # $1 = PASS|FAIL, $2 = case name, $3 = needle that must be in the FAIL line, rest = check args
    local want="$1" name="$2" needle="$3"; shift 3
    n=$((n + 1))
    out=$(python3 -I "$CHECK_PY" "$@" 2>&1 | tail -1) || true
    if [ "$want" = PASS ] && [[ "$out" == "REBUILD-CHECK: PASS"* ]]; then echo "  ok   $name: PASS"; return; fi
    if [ "$want" = FAIL ] && [[ "$out" == "REBUILD-CHECK: FAIL"* ]] && [[ "$out" == *"$needle"* ]]; then
      echo "  ok   $name: FAIL as required (${out:21:150})"; return
    fi
    echo "  BAD  $name: wanted $want ($needle), got: $out"; fails=$((fails + 1))
  }
  jset() {  # $1 file, $2 python expression on d (the loaded JSON), rewritten in place
    python3 -I -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); exec(sys.argv[2]); json.dump(d,open(p,"w"),indent=1,sort_keys=True)' "$1" "$2"
  }
  mkfix() {  # $1 dir, $2 artifact bytes, $3 attested digest override (empty = real) -> A/ and B/ in $1
    local d="$1" bytes="$2" att="$3" s
    mkdir -p "$d/A" "$d/B" "$d/w/key" "$d/w/out"; chmod 700 "$d/w/key"
    printf '%s' "$bytes" > "$d/A/aegis-floor"; cp "$d/A/aegis-floor" "$d/B/aegis-floor"
    s=$(sha256sum "$d/A/aegis-floor" | cut -d' ' -f1)
    cat > "$d/B/build-info.json" << EOF
{"profile": "floor", "artifact": "artifacts/aegis-floor", "sha256": "$s",
 "command": ["cargo", "auditable", "build", "--release", "--locked", "--offline", "-p", "aegis-bin"],
 "source_date_epoch": 1793800658, "rustflags": "--remap-path-prefix=/src=/src -Cforce-frame-pointers=yes",
 "image": {"name": "aegis-al2023-build:1f326d0afbea", "id": "sha256:$(printf b | sha256sum | cut -c1-64)",
           "base": "amazonlinux@sha256:bb1c85fe00170acd8a653de5f68cf77c7ec67234a130b18fad7ca1de1f61e3d3",
           "containerfile_sha256": "$(printf c | sha256sum | cut -c1-64)"},
 "rustc_vV": "rustc 1.99.1", "cargo_V": "cargo 1.99.1", "go_version": "go version go1.27.3 linux/amd64",
 "cc_version": "gcc (GCC) 11.5.0", "cargo_auditable_sha256": "$(printf d | sha256sum | cut -c1-64)",
 "cargo_lock_sha256": "$(printf e | sha256sum | cut -c1-64)",
 "paths": {"src": "/src", "target": "/job/target", "cargo_home": "/job/cargo-home", "rust": "/opt/rust", "go": "/opt/go"}}
EOF
    printf '{"commit": "%040d", "kind": "git", "source_date_epoch": 1793800658, "tree_sha256": "%s", "profile": "floor"}\n' \
      7 "$(printf f | sha256sum | cut -c1-64)" > "$d/w/source.json"
    printf '{"commit": "%040d", "tree_sha256": "%s", "sha256": "%s", "builder_id": "%s"}\n' \
      7 "$(printf f | sha256sum | cut -c1-64)" "$s" "$B_BUILDER" > "$d/B/b-record.json"
    printf '{"bomFormat": "CycloneDX", "specVersion": "1.5"}\n' > "$d/w/sbom.cdx.json"
    cp "$d/B/build-info.json" "$d/w/bi.json"
    if [ -n "$att" ]; then jset "$d/w/bi.json" "d['sha256']='$att'"; s="$att"; fi
    # The real attest job, with its own fresh throwaway key (shredded by the job), writes the provenance.
    python3 -I "$REL/jobs/attest.py" --subject "artifacts/aegis-floor=$s" --sbom "$d/w/sbom.cdx.json" \
      --build-info "$d/w/bi.json" --source "$d/w/source.json" --keydir "$d/w/key" --out "$d/w/out" > /dev/null
    cp "$d/w/out/provenance.intoto.json" "$d/A/"; cp "$d/w/out/attest/attest.pub.pem" "$d/A/"
  }
  echo "release-rebuild self-test (check() on real-format provenance from jobs/attest.py, throwaway keys)"
  mkfix "$T/clean" "aegis floor binary" ""
  expect PASS clean x --profile floor --a "$T/clean/A" --b "$T/clean/B"
  cp -r "$T/clean" "$T/epoch"; jset "$T/epoch/B/build-info.json" "d['source_date_epoch'] += 1"
  expect FAIL "mutant B SOURCE_DATE_EPOCH+1" "recipe SOURCE_DATE_EPOCH" --profile floor --a "$T/epoch/A" --b "$T/epoch/B"
  mkfix "$T/other" "aegis floor binary" "$(printf other | sha256sum | cut -c1-64)"
  expect FAIL "attestation (validly signed) naming another digest" "!= attested" --profile floor --a "$T/other/A" --b "$T/other/B"
  cp -r "$T/clean" "$T/edit"
  python3 -I -c '
import base64, json, sys
p = sys.argv[1]; e = json.load(open(p)); s = json.loads(base64.b64decode(e["payload"]))
s["subject"][0]["digest"]["sha256"] = "0" * 64
e["payload"] = base64.b64encode(json.dumps(s, sort_keys=True, separators=(",", ":")).encode()).decode()
json.dump(e, open(p, "w"))' "$T/edit/A/provenance.intoto.json"
  expect FAIL "attestation payload edited to another digest" "signature does not verify" --profile floor --a "$T/edit/A" --b "$T/edit/B"
  cp -r "$T/clean" "$T/bdig"; printf 'different' > "$T/bdig/B/aegis-floor"
  expect FAIL "B binary differs" "sha256(B)" --profile floor --a "$T/bdig/A" --b "$T/bdig/B"
  cp -r "$T/clean" "$T/bid"; jset "$T/bid/B/b-record.json" "d['builder_id']='urn:aegis:ci:kamrui:release-pipeline:v1'"
  expect FAIL "B reuses A's builder id" "builder ids" --profile floor --a "$T/bid/A" --b "$T/bid/B"
  cp -r "$T/clean" "$T/tree"; jset "$T/tree/B/b-record.json" "d['tree_sha256']='1'*64"
  expect FAIL "B built another source tree" "source tree" --profile floor --a "$T/tree/A" --b "$T/tree/B"
  local p replayed=""
  for p in floor cmvp; do
    [ -f "$OUTROOT/$p/PASS" ] || continue
    echo "replaying the recorded real run for $p (target/release-rebuild/$p)"
    cp -r "$OUTROOT/$p" "$T/rec-$p"
    expect PASS "recorded $p" x --profile "$p" --a "$T/rec-$p/A" --b "$T/rec-$p/B"
    cp -r "$OUTROOT/$p" "$T/rec-$p-e"; jset "$T/rec-$p-e/B/build-info.json" "d['source_date_epoch'] += 1"
    expect FAIL "recorded $p, B SOURCE_DATE_EPOCH+1" "recipe SOURCE_DATE_EPOCH" --profile "$p" --a "$T/rec-$p-e/A" --b "$T/rec-$p-e/B"
    cp -r "$OUTROOT/$p" "$T/rec-$p-s"
    python3 -I -c '
import base64, json, sys
p = sys.argv[1]; e = json.load(open(p)); s = json.loads(base64.b64decode(e["payload"]))
s["subject"][0]["digest"]["sha256"] = "0" * 64
e["payload"] = base64.b64encode(json.dumps(s, sort_keys=True, separators=(",", ":")).encode()).decode()
json.dump(e, open(p, "w"))' "$T/rec-$p-s/A/provenance.intoto.json"
    expect FAIL "recorded $p, attestation naming another digest" "signature does not verify" --profile "$p" --a "$T/rec-$p-s/A" --b "$T/rec-$p-s/B"
    replayed+=" $p"
  done
  if [ "$fails" = 0 ]; then
    echo "RELEASE-REBUILD SELF-TEST: PASS ($n cases; recorded runs replayed:${replayed:- none})"
  else
    echo "RELEASE-REBUILD SELF-TEST: FAIL ($fails of $n cases wrong)"; exit 1
  fi
}

# ------------------------------------------------------------------ build B (runs on the VM)
B_SCRIPT=$(cat << 'BEOF'
# args: W RUN COMMIT EPOCH EPOCH_OFFSET "rustc=H cargo=H rust-std=H" PROFILES...
set -euo pipefail
W="$1" RUN="$2" COMMIT="$3" EPOCH="$4" OFF="$5" KHASH="$6"; shift 6
UA="User-Agent: aegis-ci"
say() { echo "B: $*"; }
die() { echo "B: FAIL $*" >&2; exit 1; }
mkdir -p "$W/dl" "$RUN"
df -BG --output=avail "$HOME" | tail -1 | awk '{ if ($1+0 < 25) { print "B: FAIL less than 25 GB free on the VM"; exit 1 } else print "B: disk " $1 " free" }'
command -v docker > /dev/null || die "docker missing (provisioning step failed)"
docker info > /dev/null 2>&1 || die "docker not usable by $USER"
fetch() {  # $1 url, $2 sha256 -> path in $W/dl (re-verified on every run)
  local f="$W/dl/$(basename "$1")"
  if [ ! -f "$f" ] || ! echo "$2  $f" | sha256sum -c --quiet 2> /dev/null; then
    curl -sfL --retry 3 -H "$UA" -o "$f.part" "$1" || die "download failed: $1"; mv "$f.part" "$f"
  fi
  echo "$2  $f" | sha256sum -c --quiet || { rm -f "$f"; die "sha256 mismatch: $1"; }
  printf '%s' "$f"
}
mkdir -p "$RUN/src0"; tar -xf "$RUN/src.tar" -C "$RUN/src0"
LOCK="$RUN/src0/ci/tools.lock"
CHAN=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$RUN/src0/rust-toolchain.toml")
# Rust: manifest from static.rust-lang.org, its published sha256, then each component against the manifest and kamrui.
M="$W/dl/channel-rust-$CHAN.toml"
curl -sfL --retry 3 -H "$UA" -o "$M" "https://static.rust-lang.org/dist/channel-rust-$CHAN.toml" || die "manifest download"
msha=$(curl -sfL --retry 3 -H "$UA" "https://static.rust-lang.org/dist/channel-rust-$CHAN.toml.sha256" | cut -c1-64)
[ "$(sha256sum "$M" | cut -c1-64)" = "$msha" ] || die "channel manifest sha256 != published .sha256"
TC="$RUN/rust"; mkdir -p "$TC"
for pkg in rustc cargo rust-std; do
  read -r url h < <(python3 -I -c '
import sys, tomllib
m = tomllib.load(open(sys.argv[1], "rb"))
t = m["pkg"][sys.argv[2]]["target"]["x86_64-unknown-linux-gnu"]
assert t["available"], "not available"
print(t["xz_url"], t["xz_hash"])' "$M" "$pkg")
  kh=$(printf '%s\n' $KHASH | sed -n "s/^$pkg=//p")
  [ "$h" = "$kh" ] || die "$pkg: static.rust-lang.org manifest hash $h != kamrui's rustup manifest hash $kh"
  f=$(fetch "$url" "$h")
  x="$RUN/x-$pkg"; mkdir -p "$x"; tar -xJf "$f" -C "$x"
  (cd "$x"/*/ && ./install.sh --prefix="$TC" --disable-ldconfig > /dev/null) || die "$pkg install.sh failed"
  rm -rf "$x"
  say "rust $pkg $h (manifest + kamrui agree)"
done
row() { awk -F'\t' -v n="$1" '$1 == n { print $4, $5 }' "$LOCK"; }
read -r gsha gurl < <(row '#go:go'); [ -n "$gsha" ] || die "no #go:go row in ci/tools.lock"
f=$(fetch "$gurl" "$gsha"); mkdir -p "$RUN/goroot"; tar -xzf "$f" -C "$RUN/goroot"; GO="$RUN/goroot/go"
say "go $gsha"
read -r asha aurl < <(row cargo-auditable); [ -n "$asha" ] || die "no cargo-auditable row in ci/tools.lock"
f=$(fetch "$aurl" "$asha"); x="$RUN/x-aud"; mkdir -p "$x" "$RUN/tools"; tar -xf "$f" -C "$x"
bin=$(find "$x" -type f -name cargo-auditable -perm -u+x | head -1); [ -n "$bin" ] || die "no cargo-auditable in archive"
install -m 0755 "$bin" "$RUN/tools/cargo-auditable"; rm -rf "$x"; AUD="$RUN/tools/cargo-auditable"
say "cargo-auditable $asha"
base=$(sed -n 's/^FROM \(.*\)$/\1/p' "$RUN/src0/deploy/build/al2023.Containerfile")
docker pull -q "$base" > /dev/null || die "docker pull $base"
[ "$(docker image inspect -f '{{index .RepoDigests 0}}' "$base")" = "$base" ] || die "pulled base digest differs"
IMG=$("$RUN/src0/deploy/build/image.sh" | sed -n 's/^IMAGE \([^ ]*\) .*/\1/p'); [ -n "$IMG" ] || die "image.sh failed"
say "image $IMG $(docker image inspect -f '{{.Id}}' "$IMG") from base $base"
export CARGO_HOME="$RUN/cargo-home" PATH="$TC/bin:/usr/bin:/bin"
for P in "$@"; do
  SRC="$RUN/src-$P"; mkdir -p "$SRC"; tar -xf "$RUN/src.tar" -C "$SRC"
  if [ "$P" = cmvp ]; then
    python3 -I "$SRC/profiles/cmvp/overlay.py" "$SRC/profiles/cmvp/overlay.toml" "$SRC/Cargo.toml" "$SRC/Cargo.toml.cmvp" \
      || die "cmvp overlay failed"
    mv "$SRC/Cargo.toml.cmvp" "$SRC/Cargo.toml"; cp "$SRC/profiles/cmvp/Cargo.lock" "$SRC/Cargo.lock"
  fi
  TREE=$(cd "$SRC" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)
  (cd "$SRC" && cargo fetch --locked -q) || die "$P: cargo fetch --locked failed"
  E=$((EPOCH + OFF))
  [ "$OFF" = 0 ] || say "MUTANT: building $P with SOURCE_DATE_EPOCH $E (attested $EPOCH)"
  mkdir -p "$RUN/job-$P/home"
  if ! (cd "$RUN/job-$P" && env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC HOME="$RUN/job-$P/home" TMPDIR="$RUN/job-$P" \
      CARGO_BUILD_JOBS="$(nproc)" "$SRC/ci/release/jobs/build.sh" --profile "$P" --src "$SRC" \
      --registry "$CARGO_HOME/registry" --toolchain "$TC" --go "$GO" --auditable "$AUD" --image "$IMG" --epoch "$E" \
      --scratch "$RUN/job-$P" --out "$RUN/out-$P"); then
    echo "B-RESULT: $P FAIL build"; continue
  fi
  s=$(sha256sum "$RUN/out-$P/aegis-$P" | cut -d' ' -f1)
  printf '{"commit": "%s", "tree_sha256": "%s", "sha256": "%s", "builder_id": "%s", "host": "aegis-quiet"}\n' \
    "$COMMIT" "$TREE" "$s" "urn:aegis:ci:gcp-aegis-quiet:release-rebuild:v1" > "$RUN/out-$P/b-record.json"
  rm -rf "$RUN/job-$P" "$SRC"
  echo "B-RESULT: $P PASS sha256 $s tree $TREE"
done
BEOF
)

# ------------------------------------------------------------------ gate
gate() {
  local A_HOST="$1" B_HOST="$2" PROFILES="$3" OFF="$4"
  [ "$A_HOST" = kamrui ] || { echo "RELEASE-REBUILD: FAIL (--a must be kamrui, the attested release host)"; exit 1; }
  [ "$B_HOST" = quiet ] || { echo "RELEASE-REBUILD: FAIL (--b must be quiet, the aegis-quiet VM)"; exit 1; }
  local p P=()
  IFS=, read -r -a P <<< "$PROFILES"
  for p in "${P[@]}"; do case "$p" in floor | cmvp) ;; *) echo "RELEASE-REBUILD: FAIL (unknown profile $p)"; exit 1 ;; esac; done
  local COMMIT EPOCH REPO
  COMMIT=$(git -C "$ROOT" rev-parse HEAD); EPOCH=$(git -C "$ROOT" log -1 --format=%ct HEAD)
  [ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ] \
    || echo "rebuild: note: uncommitted changes; both builds use commit $COMMIT (A in tree mode would differ: checked)"
  REPO=repo; [ "$(basename "$ROOT")" = aegis ] || REPO="repo-$(printf %s "$ROOT" | sha256sum | cut -c1-12)"
  mkdir -p "$OUTROOT"
  declare -A RES
  local okA=()
  # ---- A: the attested release on kamrui
  for p in "${P[@]}"; do
    rm -rf "${OUTROOT:?}/$p"; mkdir -p "$OUTROOT/$p/A" "$OUTROOT/$p/B"
    echo "== A ($A_HOST): ci/release/pipeline.sh --profile $p"
    local alog="$OUTROOT/$p/A/pipeline.log"
    "$ROOT/ci/remote.sh" --host kamrui bash -c "export AEGIS_RELEASE_COMMIT=$COMMIT AEGIS_RELEASE_EPOCH=$EPOCH; \
ci/release/pipeline.sh --profile $p --out target/release-rebuild/A-$p" 2>&1 | tee "$alog" || true
    local line; line=$(grep "^RELEASE-PIPELINE: PASS ($p, artifacts/aegis-$p sha256 " "$alog" | tail -1 || true)
    if [ -z "$line" ]; then RES[$p]="A: release pipeline failed ($(grep '^RELEASE-PIPELINE:' "$alog" | tail -1 || echo 'no result line'))"; continue; fi
    ssh -o BatchMode=yes kamrui "tar -C aegis-ci/$REPO/target/release-rebuild/A-$p -cf - provenance.intoto.json \
attest/attest.pub.pem SHA256SUMS artifacts/aegis-$p" | tar -x -C "$OUTROOT/$p/A" \
      || { RES[$p]="A: could not fetch the release from kamrui"; continue; }
    mv "$OUTROOT/$p/A/attest/attest.pub.pem" "$OUTROOT/$p/A/"; mv "$OUTROOT/$p/A/artifacts/aegis-$p" "$OUTROOT/$p/A/"
    rmdir "$OUTROOT/$p/A/attest" "$OUTROOT/$p/A/artifacts"
    local la; la=$(sha256sum "$OUTROOT/$p/A/aegis-$p" | cut -d' ' -f1)
    [[ "$line" == *"sha256 $la,"* ]] || { RES[$p]="A: fetched artifact sha256 $la differs from the pipeline's line"; continue; }
    okA+=("$p")
  done
  # kamrui's rustup manifest hashes for the channel (B's toolchain must be the same bytes)
  local chan khash=""
  chan=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml")
  if [ ${#okA[@]} -gt 0 ]; then
    khash=$(ssh -o BatchMode=yes kamrui "cat aegis-ci/rustup/toolchains/$chan-x86_64-unknown-linux-gnu/lib/rustlib/multirust-channel-manifest.toml" \
      | python3 -I -c 'import sys, tomllib; m = tomllib.loads(sys.stdin.read()); print(" ".join(p + "=" + m["pkg"][p]["target"]["x86_64-unknown-linux-gnu"]["xz_hash"] for p in ("rustc", "cargo", "rust-std")))') \
      || { for p in "${okA[@]}"; do RES[$p]="could not read kamrui's rustup manifest"; done; okA=(); }
  fi
  # ---- B: the VM
  local vm_t0 vm_t1 vm_s=0 vm_line="VM not started (no profile reached B)"
  if [ ${#okA[@]} -gt 0 ]; then
    vm_t0=$(date +%s)
    trap 'rm -f "$CHECK_PY"; "$REL/vm.sh" stop || true' EXIT
    trap 'exit 130' INT TERM
    if ! "$REL/vm.sh" start; then
      for p in "${okA[@]}"; do RES[$p]="B: VM did not start"; done
    else
      local VMSSH=("$REL/vm.sh" ssh) W='$HOME/aegis-ci/rebuild' RUN id
      id=$(date +%Y%m%d%H%M%S); RUN="aegis-ci/rebuild/run-$id"
      # first use: docker from the VM's apt (dedicated AEGIS VM; never on operator boxes)
      "${VMSSH[@]}" 'command -v docker > /dev/null || { echo "B: installing docker.io (first use)";
        sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io > /dev/null; };
        id -nG | grep -qw docker || sudo usermod -aG docker "$USER"; df -h / | tail -1 | sed "s/^/B: disk /"'
      "${VMSSH[@]}" "find aegis-ci/rebuild -maxdepth 1 -name 'run-*' -mtime +1 -exec rm -rf {} + 2>/dev/null; mkdir -p $RUN"
      git -C "$ROOT" archive --format=tar "$COMMIT" | "${VMSSH[@]}" "cat > $RUN/src.tar"
      printf '%s\n' "$B_SCRIPT" | "${VMSSH[@]}" "cat > $RUN/b.sh"
      # detached on the VM (a dropped laptop connection does not kill the build); followed by short polls
      "${VMSSH[@]}" "cd $RUN && setsid bash -c 'nice -n 5 bash b.sh \"\$@\" > b.log 2>&1; echo \$? > b.rc' _ \
        $W \$HOME/$RUN $COMMIT $EPOCH $OFF '$khash' ${okA[*]} < /dev/null > /dev/null 2>&1 &"
      local off=0 out body rc down=0
      while :; do
        if out=$("${VMSSH[@]}" "rc=\$(cat $RUN/b.rc 2>/dev/null); tail -c +$((off + 1)) $RUN/b.log; printf '\\n@@RC@@%s' \"\$rc\"" 2> /dev/null); then
          down=0; body=${out%$'\n'@@RC@@*}; rc=${out##*@@RC@@}
          printf '%s' "$body" | tee -a "$OUTROOT/b.log"; off=$((off + $(printf '%s' "$body" | wc -c)))
          [ -n "$rc" ] && break
        else
          down=$((down + 1)); [ $down -lt 120 ] || { rc=255; echo "rebuild: VM unreachable for 20 min"; break; }
        fi
        sleep 10
      done
      echo
      for p in "${okA[@]}"; do
        if grep -q "^B-RESULT: $p PASS" "$OUTROOT/b.log"; then
          "${VMSSH[@]}" "tar -C $RUN/out-$p -cf - aegis-$p build-info.json b-record.json" | tar -x -C "$OUTROOT/$p/B" \
            || RES[$p]="B: could not fetch B's output"
        else
          RES[$p]="B: build on aegis-quiet failed (rc $rc; see B: lines above)"
        fi
      done
      "${VMSSH[@]}" "rm -rf $RUN/rust $RUN/goroot $RUN/cargo-home $RUN/src0" || true
    fi
    "$REL/vm.sh" stop && vm_line=$("$REL/vm.sh" status) || vm_line="NOT STOPPED"
    vm_t1=$(date +%s); vm_s=$((vm_t1 - vm_t0))
    trap 'rm -f "$CHECK_PY"' EXIT
    [ "$vm_line" = TERMINATED ] || { for p in "${P[@]}"; do RES[$p]="${RES[$p]:-}; VM not TERMINATED"; done; }
    vm_line="VM aegis-quiet $vm_line after ${vm_s} s (~$(( (vm_s + 59) / 60 )) min)"
    echo "rebuild: $vm_line"
  fi
  # ---- compare
  local passes=() fails=()
  for p in "${P[@]}"; do
    if [ -z "${RES[$p]:-}" ]; then
      local c; c=$(check "$p" "$OUTROOT/$p/A" "$OUTROOT/$p/B" | tail -1) || true
      echo "$c"
      if [[ "$c" == "REBUILD-CHECK: PASS"* ]]; then
        local db; db=$(sha256sum "$OUTROOT/$p/B/aegis-$p" | cut -d' ' -f1)
        echo "== kamrui: ci/release/verify.py --allow-test-keys --expect-sha256 artifacts/aegis-$p=<sha256(B)>"
        local v; v=$("$ROOT/ci/remote.sh" --host kamrui ci/release/verify.py --allow-test-keys \
          --expect-sha256 "artifacts/aegis-$p=$db" "target/release-rebuild/A-$p" 2>&1 | tail -3) || true
        echo "$v"
        if [[ "$(echo "$v" | tail -1)" == "RELEASE-VERIFY: PASS" ]]; then
          touch "$OUTROOT/$p/PASS"; passes+=("$p sha256 $db"); continue
        fi
        RES[$p]="verify.py on A's release with B's digest: $(echo "$v" | tail -1)"
      else
        RES[$p]="${c#REBUILD-CHECK: }"
      fi
    fi
    fails+=("$p: ${RES[$p]}")
  done
  if [ ${#fails[@]} -eq 0 ]; then
    echo "RELEASE-REBUILD: PASS ($(IFS=';'; echo "${passes[*]}"); A kamrui = B aegis-quiet = attested subject; $vm_line)"
  else
    echo "RELEASE-REBUILD: FAIL ($(IFS='|'; echo "${fails[*]}"); passed: ${passes[*]:-none}; $vm_line)"
    exit 1
  fi
}

A= Bh= PROFILES= OFF=0
case "${1:-}" in
  --self-test) self_test; exit 0 ;;
esac
while [ $# -gt 0 ]; do
  case "$1" in
    --a) A="${2:-}"; shift 2 ;;
    --b) Bh="${2:-}"; shift 2 ;;
    --profiles) PROFILES="${2:-}"; shift 2 ;;
    --mutant-b-epoch-offset) OFF="${2:-}"; [[ "$OFF" =~ ^[0-9]+$ ]] || exit 2
      echo "rebuild: MUTANT RUN: B builds with SOURCE_DATE_EPOCH + $OFF; this run must FAIL"; shift 2 ;;
    *) echo "usage: ci/release/rebuild.sh --a kamrui --b quiet --profiles floor,cmvp | --self-test" >&2; exit 2 ;;
  esac
done
[ -n "$A" ] && [ -n "$Bh" ] && [ -n "$PROFILES" ] || { echo "usage: ci/release/rebuild.sh --a kamrui --b quiet --profiles floor,cmvp | --self-test" >&2; exit 2; }
gate "$A" "$Bh" "$PROFILES" "$OFF"
