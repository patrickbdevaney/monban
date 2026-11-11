#!/usr/bin/env bash
# The keyed half of the release pipeline (jobs 3-5 and the leak check), split out of ci/release/pipeline.sh so the
# production signing path can be exercised end to end without a cargo build (ci/release/keys/ceremony.sh --self-test).
#
#   sign-release.sh --stage DIR --artifact artifacts/<name> --build-info FILE --source FILE --work DIR
#                   [--keys DIR --pubdir DIR (--passfile FILE | --passphrase-fd N)]
#
# --stage holds artifacts/<name>, sbom.cdx.json and SHA256SUMS (ci/release/pipeline.sh writes them); on success it is
# the finished release (layout contract v1, ci/release/verify.py). --work is scratch (job dirs).
#
# Test-key mode (no --keys; what the release-verify gate runs): fresh per-run keys in each job (PREFLIGHT D-P2) and a
# TEST_KEYS file. Production mode (--keys DIR = the encrypted online keys from ci/release/keys/ceremony.sh, --pubdir =
# the committed release-keys/): each keyed job decrypts only its own keys into its own tmpfs key dir and shreds it; no
# TEST_KEYS file, no test_keys marker; tuf/ carries the committed root chain. The passphrase comes from --passfile (a
# 0600 file on tmpfs that the caller shreds; pipeline.sh) or one line on --passphrase-fd N (copied to a tmpfs file
# shredded on exit). It is never put on a command line or in the environment.
# Both modes: each job is its own process under `env -i` with its own key dir (mode 0700, /dev/shm), and this script
# refuses to finish while a key dir is not empty.
# Final line: SIGN-RELEASE: PASS (...) or SIGN-RELEASE: FAIL (<reason>); exit status 0 / 1.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
J="$ROOT/ci/release/jobs"
# shellcheck source=ci/release/keys/lib.sh
. "$ROOT/ci/release/keys/lib.sh"
fail() { echo "SIGN-RELEASE: FAIL ($*)"; exit 1; }
R= ART= BI= SRCJSON= WORK= KEYS= PUBDIR= PASSFILE= PASSFD=
while [ $# -gt 0 ]; do
  case "$1" in
    --stage) R="${2:-}" ;; --artifact) ART="${2:-}" ;; --build-info) BI="${2:-}" ;; --source) SRCJSON="${2:-}" ;;
    --work) WORK="${2:-}" ;; --keys) KEYS="${2:-}" ;; --pubdir) PUBDIR="${2:-}" ;; --passfile) PASSFILE="${2:-}" ;;
    --passphrase-fd) PASSFD="${2:-}" ;;
    *) echo "sign-release.sh: unknown argument $1" >&2; exit 2 ;;
  esac
  shift 2
done
for v in R ART BI SRCJSON WORK; do [ -n "${!v}" ] || { echo "sign-release.sh: missing argument for $v" >&2; exit 2; }; done
PY_TUF="${AEGIS_PY_TUF_PYTHON:-$HOME/aegis-ci/py-tuf/bin/python}"
keylib_openssl || fail "need OpenSSL >= 3.5"
[ -x "$PY_TUF" ] || fail "python-tuf venv python not found at $PY_TUF"

KEYROOT=/dev/shm; [ -d /dev/shm ] && [ -w /dev/shm ] || KEYROOT="$WORK"
KEYDIRS=()
PASSDIR=
newkeydir() {  # own key dir per keyed job, mode 0700, on tmpfs
  local d; d="$(mktemp -d "$KEYROOT/monban-release-keys.$1.XXXXXX")"; chmod 700 "$d"; KEYDIRS+=("$d"); KD="$d"
}
cleanup() {
  local d
  for d in "${KEYDIRS[@]}"; do
    [ -d "$d" ] || continue
    find "$d" -type f -exec shred -u -z {} + 2> /dev/null || true
    rm -rf "$d"
  done
  keylib_shred_dir "$PASSDIR"
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

PROD=0
if [ -n "$KEYS$PUBDIR$PASSFILE$PASSFD" ]; then
  PROD=1
  [ -n "$KEYS" ] && [ -n "$PUBDIR" ] || fail "production mode needs --keys DIR and --pubdir DIR"
  if [ -n "$PASSFD" ]; then
    [ -z "$PASSFILE" ] || fail "give --passfile or --passphrase-fd, not both"
    PASSDIR="$(keylib_tmpfs release-pass)" || fail "no tmpfs for the passphrase"
    PASSFILE="$PASSDIR/pass"
    keylib_read_pass "$PASSFILE" "release key passphrase" "$PASSFD" 0 1 || fail "no passphrase"
  fi
  [ -n "$PASSFILE" ] && [ -f "$PASSFILE" ] || fail "production mode needs --passfile FILE or --passphrase-fd N"
  case "$(realpath "$KEYS")/" in "$ROOT"/*) fail "--keys $KEYS is inside the repository tree" ;; esac
  KEYS="$(realpath "$KEYS")" PUBDIR="$(realpath "$PUBDIR")"
  python3 -I "$ROOT/ci/release/keys/keycheck.py" online "$KEYS" | sed 's/^/keys: /' || fail "the --keys dir did not pass keycheck online"
  python3 -I "$ROOT/ci/release/keys/keycheck.py" public "$PUBDIR" | sed 's/^/keys: /' || fail "the --pubdir did not pass keycheck public"
  "$PY_TUF" -I "$ROOT/ci/release/keys/root.py" check --pubdir "$PUBDIR" | sed 's/^/keys: /' || fail "the committed root chain in $PUBDIR is refused"
  for k in "$KEYS"/*.key.enc.pem; do
    keylib_pass_ok "$k" "$PASSFILE" || fail "the passphrase does not open $(basename "$k")"
  done
  [ ! -e "$R/TEST_KEYS" ] || fail "production mode: the stage carries a TEST_KEYS file"
fi

ART_SHA=$(sha256sum "$R/$ART" | cut -d' ' -f1)
A="$WORK/out-attest" G="$WORK/out-sign"
newkeydir attest
if [ "$PROD" = 1 ]; then
  job attest python3 -I "$J/attest.py" --subject "$ART=$ART_SHA" --sbom "$R/sbom.cdx.json" \
    --build-info "$BI" --source "$SRCJSON" --keydir "$KD" --out "$A" \
    --enc-key "$KEYS/attest.key.enc.pem" --passfile "$PASSFILE" --expect-pub "$PUBDIR/attest.pub.pem"
else
  job attest python3 -I "$J/attest.py" --subject "$ART=$ART_SHA" --sbom "$R/sbom.cdx.json" \
    --build-info "$BI" --source "$SRCJSON" --keydir "$KD" --out "$A"
fi
cp -r "$A/provenance.intoto.json" "$A/attest" "$R/"

newkeydir sign
if [ "$PROD" = 1 ]; then
  job sign "$J/sign.sh" --sums "$R/SHA256SUMS" --keydir "$KD" --out "$G" \
    --enc-keys "$KEYS" --passfile "$PASSFILE" --pubdir "$PUBDIR"
  cp -r "$G/sigs" "$R/"
else
  job sign "$J/sign.sh" --sums "$R/SHA256SUMS" --keydir "$KD" --out "$G"
  cp -r "$G/sigs" "$R/"
  printf 'test_keys: true\n' > "$R/TEST_KEYS"
fi

newkeydir tuf
if [ "$PROD" = 1 ]; then
  job tuf "$PY_TUF" -I "$J/tuf.py" --release "$R" --keydir "$KD" \
    --enc-keys "$KEYS" --passfile "$PASSFILE" --roots "$PUBDIR"
else
  job tuf "$PY_TUF" -I "$J/tuf.py" --release "$R" --keydir "$KD"
fi

for d in "${KEYDIRS[@]}"; do
  [ -z "$(ls -A "$d")" ] || fail "key dir $d not empty after its job"
  rmdir "$d"
done
python3 -I "$J/leakcheck.py" "$R" || fail "private key material in the release (D-P2)"
if [ "$PROD" = 1 ]; then
  [ ! -e "$R/TEST_KEYS" ] || fail "production release has a TEST_KEYS file"
  python3 -I -c '
import base64, glob, json, os, sys
r = sys.argv[1]
def mark(o):
    return isinstance(o, dict) and ("test_keys" in o or any(mark(v) for v in o.values())) or \
        isinstance(o, list) and any(mark(v) for v in o)
docs = [json.load(open(p))["signed"] for p in glob.glob(os.path.join(r, "tuf", "*.json"))]
docs.append(json.loads(base64.b64decode(json.load(open(os.path.join(r, "provenance.intoto.json")))["payload"])))
sys.exit(1 if any(mark(d) for d in docs) else 0)' "$R" || fail "production release carries a test_keys marker"
  echo "SIGN-RELEASE: PASS (production keys from $KEYS; 3 key dirs (7 decrypted online keys) destroyed)"
else
  echo "SIGN-RELEASE: PASS (test keys; 3 key dirs (12 keys) destroyed)"
fi
