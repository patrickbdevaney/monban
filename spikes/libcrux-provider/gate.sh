#!/usr/bin/env bash
# Gate `libcrux-spike` (gates/phase-7.toml, remote = "kamrui"; unit P7-libcrux-001, PREFLIGHT D-P7.5).
#
#   spikes/libcrux-provider/gate.sh [--only STEP[,STEP...]]   STEPS: supply build lint kat interop bench
#   spikes/libcrux-provider/gate.sh --self-test
#
# Run it as `ci/remote.sh --host kamrui spikes/libcrux-provider/gate.sh` (kamrui has /usr/bin/openssl 3.5.3 and
# ~/aegis-ci/go1.27.3). Run anywhere else, it re-runs itself there through ci/remote.sh. Everything cargo builds goes
# to $CARGO_TARGET_DIR/libcrux-spike/ (remote.sh sets a per-worktree CARGO_TARGET_DIR); measurements go to results/.
#
# Steps (all must pass):
#   supply   the spike lock is its own (not the root or cmvp lock, no spike crate in either), is current (--locked),
#            every crates.io package >= 7 days old and not yanked, cargo-deny with the root deny.toml, OSV clean over
#            EVERY package in the lock, no acceptance list (the one open advisory: INFEASIBLE_REPORT.md)
#   build    release builds of the libcrux server (lcx-provider) and of the same server on aws-lc-rs (lcx-baseline),
#            each from an empty target dir with $CC/$CXX = tools/cc-log, counting the C/C++/asm files compiled.
#            Pass: the aws-lc-rs build compiled > 0 files (the counter works) and the libcrux build compiled fewer.
#   lint     clippy on the whole spike workspace, all targets, warnings denied (unwrap/expect/panic/indexing denied)
#   kat      lcx-kat over kat/ (RFC 7748, NIST CAVP GCM, RFC 8439, RFC 5869, RFC 4231, RFC 8032, RFC 5903, ACVP
#            ML-KEM-768) plus negative tests, group round trips and record-layer round trips
#   interop  interop/interop.py: 24 cells, server <- OpenSSL 3.5.3 s_client and Go 1.27.3, every kx x AEAD (ECDSA-P256
#            leaf) and every kx with an Ed25519 leaf
#   bench    lcx-bench: in-memory handshake cost, libcrux server vs aws-lc-rs server (recorded, provisional; passes when
#            every handshake completed)
# Every selected step runs even if an earlier one failed. Self-test mutants (each must turn its check red):
#   gcm-notag  provider built with --features mutant-gcm-notag (GCM tag never checked): the KAT fails, on GCM checks only
#              (NIST CAVP GCM vectors and the AES-GCM record-layer tamper checks)
#   kx-swap    provider built with --features mutant-kx-swap (X25519 share sent as X25519MLKEM768): every
#              X25519MLKEM768 interop cell fails (OpenSSL and Go), every other cell still passes
#   c-fixture  provider built with --features c-fixture (one extra cc::Build): the C-surface count is larger and names
#              cfixture/src/fixture.c
#   (plus)     OSV names a known-vulnerable package planted into a copy of the lock; lock-age evaluated as of
#              2026-10-08 (libcrux 1 day old) is red
# Last line: LIBCRUX-SPIKE: PASS|FAIL (...) or LIBCRUX-SPIKE SELF-TEST: PASS|FAIL (...). Exit 0 only on PASS.
set -u -o pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
self_test=0; only=""; pass=()
while [ $# -gt 0 ]; do
  case "$1" in
    --self-test) self_test=1; pass+=("$1") ;;
    --only) only="${2:-}"; pass+=("$1" "${2:-}"); shift ;;
    *) echo "usage: gate.sh [--only STEPS] | --self-test"; exit 2 ;;
  esac
  shift
done
NAME="LIBCRUX-SPIKE"; [ $self_test = 1 ] && NAME="LIBCRUX-SPIKE SELF-TEST"
die() { echo "$NAME: FAIL ($1)"; exit 1; }

OPENSSL=/usr/bin/openssl
GO="${LCX_GO:-$HOME/aegis-ci/go1.27.3/bin/go}"
have_peers() {
  [ -x "$GO" ] && "$GO" version 2>/dev/null | grep -q ' go1\.27\.3 ' \
    && "$OPENSSL" version 2>/dev/null | grep -q '^OpenSSL 3\.5\.3 '
}
if ! have_peers; then
  if [ -z "${LCX_DELEGATED:-}" ] && ssh -o BatchMode=yes -o ConnectTimeout=5 kamrui true 2>/dev/null; then
    echo "libcrux-spike: peers not on this host; running on kamrui" >&2
    exec "$repo/ci/remote.sh" --host kamrui env LCX_DELEGATED=1 spikes/libcrux-provider/gate.sh "${pass[@]}"
  fi
  die "this host lacks the peers (need $OPENSSL = OpenSSL 3.5.3, $GO = go1.27.3); run on kamrui"
fi
command -v cargo-deny >/dev/null || die "cargo-deny not on PATH"

HEAVY=(); [ "${AEGIS_HEAVY_HELD:-0}" = 1 ] || HEAVY=("$repo/ci/heavy.sh")
T="${CARGO_TARGET_DIR:-$here/target}/libcrux-spike"
RES="$here/results"
mkdir -p "$T" "$RES"
TRIPLE=x86_64_unknown_linux_gnu

want() { [ -z "$only" ] || [[ ",$only," == *",$1,"* ]]; }
cargo_t() { local tdir="$1"; shift; (cd "$here" && CARGO_TARGET_DIR="$tdir" "${HEAVY[@]}" cargo "$@"); }

# build_counted LABEL TARGETDIR CARGO-BUILD-ARGS... : empty target dir, C compiler = counter, summary to results/.
build_counted() {
  local label="$1" tdir="$2"; shift 2
  local log="$RES/cc-$label.log"
  rm -rf "$tdir"; : > "$log"
  (cd "$here" && env CARGO_TARGET_DIR="$tdir" LCX_CC_LOG="$log" \
     CC="$here/tools/cc-log" CXX="$here/tools/cc-log-cxx" "CC_$TRIPLE=$here/tools/cc-log" "CXX_$TRIPLE=$here/tools/cc-log-cxx" \
     HOST_CC="$here/tools/cc-log" HOST_CXX="$here/tools/cc-log-cxx" \
     "${HEAVY[@]}" cargo build --release --locked -q "$@") >&2 || return 1
  python3 -I "$here/tools/c_surface.py" "$label" "$log" "$tdir" "$RES/c-surface-$label.json"
}
files_of() { python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["files"])' "$1"; }

gopeer() {
  (cd "$here/interop/go" && GOTOOLCHAIN=local GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off CGO_ENABLED=0 \
    GOCACHE="$T/gocache" GOPATH="$T/gopath" "$GO" build -trimpath -o "$T/lcx-gopeer" .) >&2
}

interop() {  # interop SERVER-BIN WORKDIR [interop.py args...]
  local bin="$1" work="$2"; shift 2
  rm -rf "$work"; mkdir -p "$work"
  python3 -I "$here/interop/interop.py" --server "$bin" --openssl "$OPENSSL" --gopeer "$T/lcx-gopeer" --work "$work" "$@"
}

# ------------------------------------------------------------------------------------------------ self-test
if [ $self_test = 1 ]; then
  summary=()
  # M1 gcm-notag: the KAT must go red, and only on GCM checks.
  cargo_t "$T/mut-gcm" build --release --locked -q -p lcx-provider --bin lcx-kat --features mutant-gcm-notag >&2 \
    || die "gcm-notag mutant build failed"
  out=$("$T/mut-gcm/release/lcx-kat" "$here/kat")
  echo "$out" | tail -3
  echo "$out" | grep -q '^LCX-KAT: FAIL' || die "gcm-notag: KAT stayed green with the GCM tag check disabled"
  nfail=$(echo "$out" | grep -c '^  FAIL ')
  nother=$(echo "$out" | grep '^  FAIL ' | grep -Evc '^  FAIL (gcm-|record-aes(128|256)gcm-)')
  [ "$nother" = 0 ] || die "gcm-notag: $nother non-GCM checks failed too (mutant not isolated)"
  summary+=("gcm-notag: KAT red, $nfail GCM checks failed")

  # M2 kx-swap: every X25519MLKEM768 interop cell must fail; every other cell must pass.
  cargo_t "$T/mut-kx" build --release --locked -q -p lcx-provider --bin lcx-server --features mutant-kx-swap >&2 \
    || die "kx-swap mutant build failed"
  gopeer || die "Go peer build failed"
  out=$(interop "$T/mut-kx/release/lcx-server" "$T/mut-kx-work" --expect-fail 'x25519mlkem768')
  echo "$out" | grep -E 'x25519mlkem768.*(openssl|go):' | head -4
  echo "$out" | tail -1
  echo "$out" | tail -1 | grep -q '^LCX-INTEROP: PASS' || die "kx-swap: $(echo "$out" | tail -1)"
  nred=$(echo "$out" | grep -c '^cell x25519mlkem768.*: fail (expected fail) -> ok')
  ngreen=$(echo "$out" | grep -c '^cell .*: pass -> ok')
  [ "$nred" -ge 8 ] || die "kx-swap: only $nred X25519MLKEM768 cells red"
  summary+=("kx-swap: $nred/$nred X25519MLKEM768 cells red (OpenSSL+Go), $ngreen other cells green")

  # M3 c-fixture: one extra cc::Build must be counted.
  build_counted lcx-st "$T/st-lcx" -p lcx-provider --bins >/dev/null || die "lcx build failed"
  build_counted lcx-fixture "$T/st-fix" -p lcx-provider --bins --features c-fixture || die "c-fixture build failed"
  a=$(files_of "$RES/c-surface-lcx-st.json"); b=$(files_of "$RES/c-surface-lcx-fixture.json")
  [ "$b" -gt "$a" ] || die "c-fixture: count did not grow ($a -> $b)"
  grep -q 'cfixture/src/fixture.c' "$RES/c-surface-lcx-fixture.json" || die "c-fixture: fixture.c not named"
  summary+=("c-fixture: C files $a -> $b (cfixture/src/fixture.c counted)")

  # Supply checks can go red: OSV names a known-vulnerable package (h2 0.3.0, RUSTSEC-2024-0003 et al.) planted into
  # a copy of the lock; lock-age evaluated as of 2026-10-08 (the day after the libcrux release train) names libcrux.
  mkdir -p "$T/osv-mut"
  { cat "$here/Cargo.lock"
    printf '\n[[package]]\nname = "h2"\nversion = "0.3.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
  } > "$T/osv-mut/Cargo.lock"
  out=$(python3 -I "$here/tools/supply.py" osv "$T/osv-mut/Cargo.lock" "$here/Cargo.toml" "$repo/deny.toml")
  [ $? != 0 ] && echo "$out" | grep -q '^  h2@0.3.0: ' || die "osv: a planted h2 0.3.0 was not reported"
  out=$(python3 -I "$here/tools/supply.py" lockage "$here/Cargo.lock" --min 7 --today 2026-10-08)
  [ $? != 0 ] && echo "$out" | grep -q 'libcrux-ml-kem@0.0.11' || die "lock-age: stayed green with a 1-day-old libcrux"
  summary+=("supply: OSV names a planted h2 0.3.0, lock-age red as of 2026-10-08")
  # The acceptance ledger cannot hide a vulnerability or an expired entry (accepted-advisories.toml rules).
  AEGIS_SPIKE_INFO_OVERRIDE=vulnerability python3 -I "$here/tools/supply.py" osv "$here/Cargo.lock" "$here/Cargo.toml" "$repo/deny.toml" >/dev/null \
    && die "osv ledger: an accepted id re-classed as a vulnerability stayed green"
  AEGIS_SPIKE_TODAY=2027-02-07 python3 -I "$here/tools/supply.py" osv "$here/Cargo.lock" "$here/Cargo.toml" "$repo/deny.toml" >/dev/null \
    && die "osv ledger: an expired acceptance stayed green"
  summary+=("osv ledger: vulnerability-class and expired acceptances red")
  rm -rf "$T/mut-gcm" "$T/mut-kx" "$T/st-lcx" "$T/st-fix" "$T/mut-kx-work" "$T/osv-mut"
  rm -f "$RES/c-surface-lcx-st.json" "$RES/cc-lcx-st.log" "$RES/cc-lcx-fixture.log"
  echo "$NAME: PASS ($(IFS=';'; echo "${summary[*]}" | sed 's/;/; /g'))"
  exit 0
fi

# ------------------------------------------------------------------------------------------------ gate
# Every selected step runs even after an earlier one failed, so one red check never hides the others.
summary=(); failed=(); err=""; msg=""
bad() { err="$1"; return 1; }

step_supply() {
  local sub=() rc rootmeta=""
  python3 -I "$here/tools/supply.py" isolation "$here/Cargo.lock" "$repo/Cargo.lock" "$repo/profiles/cmvp/Cargo.lock" \
    || sub+=("spike crates leaked into a shipped lock")
  rootmeta=$(cd "$repo" && cargo metadata --locked --format-version 1 --no-deps 2>/dev/null) || sub+=("root cargo metadata failed")
  case "$rootmeta" in *'"lcx-provider'*|*'"lcx-baseline'*) sub+=("root workspace sees the spike packages") ;; esac
  (cd "$here" && cargo metadata --locked --format-version 1 >/dev/null) || sub+=("spike Cargo.lock is not current (--locked)")
  python3 -I "$here/tools/supply.py" lockage "$here/Cargo.lock" --min 7 || sub+=("lock-age: crate younger than 7 days")
  (cd "$here" && cargo deny --manifest-path "$here/Cargo.toml" --config "$repo/deny.toml" check 2>&1) > "$RES/deny.txt"
  rc=$?; tail -1 "$RES/deny.txt"
  [ $rc = 0 ] || sub+=("cargo-deny failed (results/deny.txt)")
  python3 -I "$here/tools/supply.py" osv "$here/Cargo.lock" "$here/Cargo.toml" "$repo/deny.toml" > "$RES/osv.txt"
  rc=$?; cat "$RES/osv.txt"
  [ $rc = 0 ] || sub+=("OSV: $(sed -n 2p "$RES/osv.txt" | sed 's/^ *//')")
  if [ ${#sub[@]} -gt 0 ]; then bad "$(IFS='|'; echo "${sub[*]}" | sed 's/|/; /g')"; return 1; fi
  msg="supply ok (isolation, --locked, lock-age, cargo-deny, OSV)"
}

step_build() {
  local lcx awslc
  build_counted lcx "$T/lcx" -p lcx-provider --bins | tee "$RES/c-surface.txt" || { bad "libcrux build failed"; return 1; }
  build_counted awslc "$T/awslc" -p lcx-baseline | tee -a "$RES/c-surface.txt" || { bad "aws-lc-rs build failed"; return 1; }
  lcx=$(files_of "$RES/c-surface-lcx.json"); awslc=$(files_of "$RES/c-surface-awslc.json")
  ls -l "$T/lcx/release/lcx-server" "$T/awslc/release/awslc-server" | awk '{print "binary", $9, $5}' | tee -a "$RES/c-surface.txt"
  [ "$awslc" -gt 0 ] || { bad "C-surface counter saw nothing in the aws-lc-rs build (counter broken)"; return 1; }
  [ "$lcx" -lt "$awslc" ] || { bad "libcrux build compiled $lcx C files, not fewer than aws-lc-rs ($awslc)"; return 1; }
  msg="C files: libcrux $lcx vs aws-lc-rs $awslc"
}

step_lint() {
  cargo_t "$T/lint" clippy --locked -q --workspace --all-targets -- -D warnings >&2 || { bad "clippy"; return 1; }
  msg="clippy clean"
}

step_kat() {
  local rc
  cargo_t "$T/lcx" build --release --locked -q -p lcx-provider --bins >&2 || { bad "build"; return 1; }
  "$T/lcx/release/lcx-kat" "$here/kat" > "$RES/kat.txt"; rc=$?
  grep -v '^  ' "$RES/kat.txt"
  if [ $rc != 0 ] || ! tail -1 "$RES/kat.txt" | grep -q '^LCX-KAT: PASS'; then bad "KAT: $(tail -1 "$RES/kat.txt")"; return 1; fi
  msg="$(tail -1 "$RES/kat.txt" | sed 's/^LCX-KAT: PASS (\(.*\))/KAT \1/')"
}

step_interop() {
  local rc
  cargo_t "$T/lcx" build --release --locked -q -p lcx-provider --bins >&2 || { bad "build"; return 1; }
  gopeer || { bad "Go peer build failed"; return 1; }
  interop "$T/lcx/release/lcx-server" "$T/interop-work" > "$RES/interop.txt"; rc=$?
  cat "$RES/interop.txt"
  [ $rc = 0 ] || { bad "interop: $(tail -1 "$RES/interop.txt")"; return 1; }
  msg="$(tail -1 "$RES/interop.txt" | sed 's/^LCX-INTEROP: PASS (\(.*\))/interop \1/')"
}

q() { "$@" >/dev/null 2>&1; }
step_bench() {
  local w="$T/bench-work" rc
  cargo_t "$T/bench" build --release --locked -q -p lcx-bench >&2 || { bad "bench build failed"; return 1; }
  rm -rf "$w"; mkdir -p "$w"
  q "$OPENSSL" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$w/ca.key" -out "$w/ca.pem" \
      -days 2 -subj "/CN=lcx bench CA" -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign \
    && q "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$w/leaf.key" \
    && q "$OPENSSL" req -new -key "$w/leaf.key" -out "$w/leaf.csr" -subj /CN=monban.test \
    && printf 'subjectAltName=DNS:monban.test\n' > "$w/ext" \
    && q "$OPENSSL" x509 -req -in "$w/leaf.csr" -CA "$w/ca.pem" -CAkey "$w/ca.key" -out "$w/leaf.pem" -days 2 -extfile "$w/ext" \
    && cat "$w/leaf.pem" "$w/ca.pem" > "$w/chain.pem" || { bad "bench credentials"; return 1; }
  { echo "# $(date -u +%FT%TZ) host=$(hostname -s) cpu=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //')"
    echo "# rustls 0.23.46 in-memory TLS 1.3 handshakes, ECDSA-P256 leaf, AES-128-GCM, aws-lc-rs 1.18.2 client"
    "${HEAVY[@]}" "$T/bench/release/lcx-bench" --ca "$w/ca.pem" --cert "$w/chain.pem" --key "$w/leaf.key" --n 400 --warmup 40
  } > "$RES/bench.txt"; rc=$?
  rm -rf "$w"
  cat "$RES/bench.txt"
  [ $rc = 0 ] || { bad "bench: a handshake failed"; return 1; }
  msg="bench recorded (results/bench.txt)"
}

ran=0
for s in supply build lint kat interop bench; do
  want "$s" || continue
  ran=1; msg=""; err=""
  echo "== $s" >&2
  if "step_$s"; then summary+=("$msg"); else failed+=("$s: $err"); fi
done
[ $ran = 1 ] || die "no step selected"
join_by() { local sep="$1" out="" x; shift; for x in "$@"; do out="${out:+$out$sep}$x"; done; echo "$out"; }
if [ ${#failed[@]} -gt 0 ]; then
  echo "$NAME: FAIL ($(join_by ' | ' "${failed[@]}")) [passed: $(join_by '; ' "${summary[@]}")]"
  exit 1
fi
echo "$NAME: PASS ($(join_by '; ' "${summary[@]}"))"
