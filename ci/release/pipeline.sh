#!/usr/bin/env bash
# AEGIS release pipeline (P6-release-001; PLAN-6 D6/D7; PREFLIGHT D-P2/D-P5). Runs on kamrui inside ~/aegis-ci/repo
# with the ci/remote.sh environment (gate release-verify, remote = "kamrui"):
#
#   ci/release/pipeline.sh --profile floor|cmvp --out DIR
#
# Writes DIR in the release layout contract v1 (docstring of ci/release/verify.py), checked afterwards by
#   ci/release/verify.py --allow-test-keys DIR
#
# Stage 0 (this script): export the source of HEAD with `git archive` (SOURCE_DATE_EPOCH = the commit time). A tree
#   without git metadata (an rsynced worktree) needs AEGIS_RELEASE_COMMIT=<40 hex> and AEGIS_RELEASE_EPOCH=<unix time>
#   and is copied as is (source kind "tree"). cmvp applies profiles/cmvp/overlay.toml and profiles/cmvp/Cargo.lock
#   (PLAN-6 D1). `cargo fetch --locked` fills the registry (the only networked step besides a first image build), and
#   deploy/build/image.sh builds or reuses the pinned AL2023 image (< 500 MB asserted).
# Five jobs, each its own process started with `env -i`, its own scratch dir and, for the keyed jobs, its own key dir
# on tmpfs (/dev/shm); keys are fresh per run (D-P2) and shredded by the job, and this script refuses to finish while
# a key dir is not empty:
#   1 build   jobs/build.sh   cargo auditable build --release --locked in the AL2023 image (no network, ro mounts)
#   2 sbom    jobs/sbom.sh    CycloneDX via cargo-cyclonedx
#   3 attest  jobs/attest.py  separate Ed25519 key; reads only the artifact digest, the build record and the SBOM;
#                             in-toto Statement v1 / SLSA provenance v1 in a DSSE envelope
#   4 sign    jobs/sign.sh    Ed25519 + SLH-DSA-SHA2-128s + ML-DSA-87 over sha256(SHA256SUMS), OpenSSL >= 3.5
#   5 tuf     jobs/tuf.py     root 3 of 5 Ed25519, targets/snapshot/timestamp, test_keys true (py-tuf venv)
# Then: jobs/leakcheck.py over the release (no private key material, D-P2), and DIR is replaced atomically. On any
# failure DIR is left absent, so a stale release cannot pass the verifier after a failed run.
# Final line: RELEASE-PIPELINE: PASS (...) or RELEASE-PIPELINE: FAIL (<reason>).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
J="$ROOT/ci/release/jobs"
fail() { echo "RELEASE-PIPELINE: FAIL ($*)"; exit 1; }
PROFILE= OUT=
while [ $# -gt 0 ]; do
  case "$1" in
    --profile) PROFILE="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    *) echo "usage: ci/release/pipeline.sh --profile floor|cmvp --out DIR" >&2; exit 2 ;;
  esac
done
case "$PROFILE" in floor | cmvp) ;; *) echo "usage: ci/release/pipeline.sh --profile floor|cmvp --out DIR" >&2; exit 2 ;; esac
[ -n "$OUT" ] || { echo "usage: ci/release/pipeline.sh --profile floor|cmvp --out DIR" >&2; exit 2; }
case "$OUT" in /*) ;; *) OUT="$PWD/$OUT" ;; esac
rm -rf "$OUT"

# ------------------------------------------------------------------ environment
OPENSSL="${AEGIS_OPENSSL:-/usr/bin/openssl}"
PY_TUF="${AEGIS_PY_TUF_PYTHON:-$HOME/aegis-ci/py-tuf/bin/python}"
TOOLS="${AEGIS_TOOLS:-$HOME/aegis-ci/tools}"
GO="$(realpath "${AEGIS_GO:-$HOME/aegis-ci/go1.27.3}")"
: "${RUSTUP_HOME:?RUSTUP_HOME unset (run through ci/remote.sh --host kamrui)}"
: "${CARGO_HOME:?CARGO_HOME unset (run through ci/remote.sh --host kamrui)}"
command -v docker > /dev/null || fail "docker not found"
[[ "$("$OPENSSL" version 2> /dev/null)" =~ ^OpenSSL\ 3\.([5-9]|[1-9][0-9])\. ]] || fail "need OpenSSL >= 3.5 at $OPENSSL"
[ -x "$PY_TUF" ] || fail "python-tuf venv python not found at $PY_TUF"
[ -x "$GO/bin/go" ] || fail "Go not found at $GO"
chan=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml")
TC="$(realpath "$RUSTUP_HOME")/toolchains/$chan-x86_64-unknown-linux-gnu"
[ -x "$TC/bin/cargo" ] || fail "toolchain $chan not installed under $RUSTUP_HOME"
tool_ok() {  # $1 = tool name: installed, and its stamp is the sha256 pinned in ci/tools.lock
  local sha; sha=$(awk -F'\t' -v n="$1" '$1 == n { print $4 }' "$ROOT/ci/tools.lock")
  [ -n "$sha" ] && [ -x "$TOOLS/bin/$1" ] && [ -f "$TOOLS/bin/.$1.$sha" ]
}
if ! tool_ok cargo-auditable || ! tool_ok cargo-cyclonedx; then
  AEGIS_TOOLS="$TOOLS" "$ROOT/ci/install-tools.sh" > /dev/null || fail "ci/install-tools.sh failed"
fi
tool_ok cargo-auditable && tool_ok cargo-cyclonedx || fail "cargo-auditable / cargo-cyclonedx not at their ci/tools.lock pins"

mkdir -p "$ROOT/target"
WORK="$(mktemp -d "$(realpath "$ROOT/target")/release-work.XXXXXX")"
KEYROOT=/dev/shm; [ -d /dev/shm ] && [ -w /dev/shm ] || KEYROOT="$WORK"
KEYDIRS=()
newkeydir() {  # own key dir per keyed job, mode 0700, on tmpfs
  local d; d="$(mktemp -d "$KEYROOT/aegis-release-keys.$1.XXXXXX")"; chmod 700 "$d"; KEYDIRS+=("$d"); KD="$d"
}
cleanup() {
  local d
  for d in "${KEYDIRS[@]}"; do
    [ -d "$d" ] || continue
    find "$d" -type f -exec shred -u -z {} + 2> /dev/null || true
    rm -rf "$d"
  done
  rm -rf "$WORK"
}
trap cleanup EXIT
JOBENV=(env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC AEGIS_OPENSSL="$OPENSSL" CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}")
job() {  # $1 = job name, rest = command; its own process with an empty environment and its own HOME/scratch
  local name="$1"; shift
  mkdir -p "$WORK/jobs/$name/home"
  echo "== job $name"
  if ! (cd "$WORK/jobs/$name" && "${JOBENV[@]}" HOME="$WORK/jobs/$name/home" TMPDIR="$WORK/jobs/$name" "$@"); then
    fail "job $name failed"
  fi
}

# ------------------------------------------------------------------ stage 0: source
SRC="$WORK/src"; mkdir -p "$SRC"
if git -C "$ROOT" rev-parse --verify -q HEAD > /dev/null 2>&1; then
  COMMIT=$(git -C "$ROOT" rev-parse HEAD)
  EPOCH=$(git -C "$ROOT" log -1 --format=%ct HEAD)
  KIND=git
  [ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ] \
    || echo "pipeline: note: working tree has uncommitted changes; building the commit $COMMIT only"
  git -C "$ROOT" archive --format=tar HEAD | tar -x -C "$SRC"
else
  COMMIT="${AEGIS_RELEASE_COMMIT:-}" EPOCH="${AEGIS_RELEASE_EPOCH:-}" KIND=tree
  [[ "$COMMIT" =~ ^[0-9a-f]{40}$ && "$EPOCH" =~ ^[0-9]+$ ]] \
    || fail "no git metadata at $ROOT: set AEGIS_RELEASE_COMMIT=<40 hex> and AEGIS_RELEASE_EPOCH=<commit time>"
  echo "pipeline: note: no git metadata; building the working tree as commit $COMMIT (source kind tree)"
  rsync -a --exclude /target/ --exclude /.git --exclude /.claude/ --exclude '**/target/' --exclude '**/.lake/' \
    --exclude /research/state/raw/ --exclude '**/__pycache__/' --exclude /gates/out/ "$ROOT/" "$SRC/"
fi
if [ "$PROFILE" = cmvp ]; then
  python3 -I "$SRC/profiles/cmvp/overlay.py" "$SRC/profiles/cmvp/overlay.toml" "$SRC/Cargo.toml" "$SRC/Cargo.toml.cmvp" \
    || fail "cmvp overlay failed"
  mv "$SRC/Cargo.toml.cmvp" "$SRC/Cargo.toml"
  cp "$SRC/profiles/cmvp/Cargo.lock" "$SRC/Cargo.lock"
fi
# Content digest of the exported tree (paths and bytes; the tree an independent rebuild must reproduce).
TREE_SHA=$(cd "$SRC" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)
SRCJSON="$WORK/source.json"
printf '{"commit": "%s", "kind": "%s", "source_date_epoch": %s, "tree_sha256": "%s", "profile": "%s"}\n' \
  "$COMMIT" "$KIND" "$EPOCH" "$TREE_SHA" "$PROFILE" > "$SRCJSON"
echo "pipeline: $PROFILE from $KIND $COMMIT (SOURCE_DATE_EPOCH $EPOCH, tree sha256 $TREE_SHA)"
(cd "$SRC" && cargo fetch --locked --manifest-path "$SRC/Cargo.toml" -q) || fail "cargo fetch --locked failed"
REG="$(realpath "$CARGO_HOME")/registry"
IMG=$("$ROOT/deploy/build/image.sh" | sed -n 's/^IMAGE \([^ ]*\) .*/\1/p')
[ -n "$IMG" ] || fail "deploy/build/image.sh failed"

# ------------------------------------------------------------------ jobs
B="$WORK/out-build" S="$WORK/out-sbom" A="$WORK/out-attest" G="$WORK/out-sign" R="$WORK/stage"
job build "$J/build.sh" --profile "$PROFILE" --src "$SRC" --registry "$REG" --toolchain "$TC" --go "$GO" \
  --auditable "$TOOLS/bin/cargo-auditable" --image "$IMG" --epoch "$EPOCH" --scratch "$WORK/jobs/build" --out "$B"
job sbom "$J/sbom.sh" --profile "$PROFILE" --src "$SRC" --registry "$REG" --toolchain "$TC" \
  --cyclonedx "$TOOLS/bin/cargo-cyclonedx" --image "$IMG" --epoch "$EPOCH" --scratch "$WORK/jobs/sbom" --out "$S"

ART="artifacts/aegis-$PROFILE"
mkdir -p "$R/artifacts"
cp "$B/aegis-$PROFILE" "$R/$ART"
cp "$S/sbom.cdx.json" "$R/sbom.cdx.json"
(cd "$R" && sha256sum "$ART" sbom.cdx.json | LC_ALL=C sort -k2 > SHA256SUMS)
ART_SHA=$(sha256sum "$R/$ART" | cut -d' ' -f1)
[ "$ART_SHA" = "$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha256"])' "$B/build-info.json")" ] \
  || fail "artifact digest differs from the build record"

newkeydir attest
job attest python3 -I "$J/attest.py" --subject "$ART=$ART_SHA" --sbom "$R/sbom.cdx.json" \
  --build-info "$B/build-info.json" --source "$SRCJSON" --keydir "$KD" --out "$A"
cp -r "$A/provenance.intoto.json" "$A/attest" "$R/"

newkeydir sign
job sign "$J/sign.sh" --sums "$R/SHA256SUMS" --keydir "$KD" --out "$G"
cp -r "$G/sigs" "$R/"
printf 'test_keys: true\n' > "$R/TEST_KEYS"

newkeydir tuf
job tuf "$PY_TUF" -I "$J/tuf.py" --release "$R" --keydir "$KD"

# ------------------------------------------------------------------ checks and hand-over
for d in "${KEYDIRS[@]}"; do
  [ -z "$(ls -A "$d")" ] || fail "key dir $d not empty after its job"
  rmdir "$d"
done
python3 -I "$J/leakcheck.py" "$R" || fail "private key material in the release (D-P2)"
leftover=$(find "$KEYROOT" -maxdepth 1 -name 'aegis-release-keys.*' -user "$(id -u)" -mmin +120 2> /dev/null | head -1)
[ -z "$leftover" ] || echo "pipeline: note: stale key dir from an earlier run: $leftover (shredding)"
for d in $(find "$KEYROOT" -maxdepth 1 -name 'aegis-release-keys.*' -user "$(id -u)" -mmin +120 2> /dev/null); do
  find "$d" -type f -exec shred -u -z {} + 2> /dev/null || true; rm -rf "$d"
done
mkdir -p "$(dirname "$OUT")"
mv "$R" "$OUT"
n=$(find "$OUT" -type f | wc -l)
echo "RELEASE-PIPELINE: PASS ($PROFILE, $ART sha256 $ART_SHA, $n files, commit $COMMIT, 3 key dirs (12 keys) destroyed)"
