#!/usr/bin/env bash
# Self-test of the production key path (ci/release/keys/ceremony.sh --self-test). No real keys: every key is a
# throwaway made by the ceremony itself into a tmpfs dir (/dev/shm) with random throwaway passphrases, and the whole
# dir is shredded on exit. Runs where OpenSSL >= 3.5 and the python-tuf venv are (kamrui):
#   ci/remote.sh --host kamrui ci/release/keys/ceremony.sh --self-test
#
# Clean runs that must PASS:
#   ceremony new; ceremony check; the production signing path (ci/release/sign-release.sh --keys: the real attest,
#   sign and tuf jobs in production mode) on a small fake release; ci/release/verify.py --trusted-root 1.root.json
#   (no --allow-test-keys); ceremony next-root (renew, then replace root-2 and all online keys) and a release under
#   each new root, verified against the original 1.root.json (root chain walk).
# Mutants that must FAIL, each with its own reason:
#   private dir inside the repo; non-empty private dir; non-empty public dir; same root and online passphrase;
#   wrong passphrase (pipeline-level and job-level); root signed by only 2 of 5 (verifier, tuf job, root.py make,
#   next-root); test_keys marker in production mode (TEST_KEYS in the stage, marked committed root, tuf job, a
#   release re-signed with a TEST_KEYS file); a plaintext private key left in the private, online or public dir;
#   a committed public key that is not the encrypted key's; old online keys after rotation; release verified
#   without a trust anchor.
# Final line: CEREMONY: PASS (self-test: ...) or CEREMONY: FAIL (self-test: <first bad case>).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
REL="$ROOT/ci/release"
# shellcheck source=ci/release/keys/lib.sh
. "$HERE/lib.sh"
keylib_openssl || { echo "CEREMONY: FAIL (self-test: need OpenSSL >= 3.5)"; exit 1; }
PY_TUF="${AEGIS_PY_TUF_PYTHON:-$HOME/aegis-ci/py-tuf/bin/python}"
[ -x "$PY_TUF" ] || { echo "CEREMONY: FAIL (self-test: no python-tuf venv at $PY_TUF)"; exit 1; }
export AEGIS_OPENSSL="$OPENSSL" AEGIS_PY_TUF_PYTHON="$PY_TUF"

T="$(keylib_tmpfs keys-selftest)"
trap 'keylib_shred_dir "$T"' EXIT
touch "$T/.start"
RP="selftest-root-$("$OPENSSL" rand -hex 12)"
OP="selftest-online-$("$OPENSSL" rand -hex 12)"
NP="selftest-online2-$("$OPENSSL" rand -hex 12)"
BAD=() NOK=0 NMUT=0
LOG="$T/log"

# run NAME EXPECT(PASS|FAIL) PATTERN cmd...: run cmd (stdin closed), keep its output in $LOG; PASS needs exit 0 and
# a final line matching PATTERN; FAIL needs a non-zero exit and PATTERN somewhere in the output.
run() {
  local name="$1" want="$2" pat="$3" rc=0 last
  shift 3
  "$@" > "$LOG" 2>&1 < /dev/null || rc=$?
  last="$(tail -n 1 "$LOG")"
  if [ "$want" = PASS ]; then
    if [ "$rc" = 0 ] && grep -qE "$pat" <<< "$last"; then
      echo "SELF-TEST clean $name: ok ($last)"; NOK=$((NOK + 1)); return 0
    fi
  else
    if [ "$rc" != 0 ] && grep -qE "$pat" "$LOG"; then
      echo "SELF-TEST mutant $name: refused ($(grep -E "$pat" "$LOG" | head -1 | cut -c1-150))"; NMUT=$((NMUT + 1))
      return 0
    fi
  fi
  echo "SELF-TEST $name: BAD (want $want /$pat/, exit $rc)"; sed 's/^/    | /' "$LOG" | tail -n 25
  BAD+=("$name")
}

# fd 3 root passphrase, 4 online passphrase, 5 the new online passphrase (rotation), 7 the root passphrase again
cer() {
  bash "$HERE/ceremony.sh" "$@" 3< <(printf '%s\n' "$RP") 4< <(printf '%s\n' "$OP") 5< <(printf '%s\n' "$NP") \
    7< <(printf '%s\n' "$RP")
}
verify() { python3 -I "$REL/verify.py" "$@"; }
mkstage() {  # $1 = dir: a small fake release before the keyed jobs (artifact, SBOM, SHA256SUMS, build record, source)
  local d="$1" s
  mkdir -p "$d/stage/artifacts" "$d/w"
  head -c 4096 /dev/urandom > "$d/stage/artifacts/aegis-floor"
  printf '{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}\n' > "$d/stage/sbom.cdx.json"
  (cd "$d/stage" && sha256sum artifacts/aegis-floor sbom.cdx.json | LC_ALL=C sort -k2 > SHA256SUMS)
  s=$(sha256sum "$d/stage/artifacts/aegis-floor" | cut -d' ' -f1)
  h() { printf '%s' "$1" | sha256sum | cut -c1-64; }
  cat > "$d/bi.json" << EOF
{"profile": "floor", "artifact": "artifacts/aegis-floor", "sha256": "$s",
 "command": ["cargo", "auditable", "build", "--release", "--locked", "--offline", "-p", "aegis-bin"],
 "source_date_epoch": 1793800658, "rustflags": "--remap-path-prefix=/src=/src",
 "image": {"name": "aegis-al2023-build:selftest", "id": "sha256:$(h b)", "base": "amazonlinux@sha256:$(h a)",
           "containerfile_sha256": "$(h c)"},
 "rustc_vV": "rustc selftest", "cargo_V": "cargo selftest", "go_version": "go selftest", "cc_version": "gcc selftest",
 "cargo_auditable_sha256": "$(h d)", "cargo_lock_sha256": "$(h e)",
 "paths": {"src": "/src", "target": "/job/target", "cargo_home": "/job/cargo-home", "rust": "/opt/rust", "go": "/opt/go"}}
EOF
  printf '{"commit": "%040d", "kind": "git", "source_date_epoch": 1793800658, "tree_sha256": "%s", "profile": "floor"}\n' \
    7 "$(h f)" > "$d/source.json"
}
# signrel DIR KEYS PUBDIR FD-of-passphrase: the production signing path on DIR's stage
signrel() {
  local d="$1" keys="$2" pub="$3" fd="$4"
  bash "$REL/sign-release.sh" --stage "$d/stage" --artifact artifacts/aegis-floor --build-info "$d/bi.json" \
    --source "$d/source.json" --work "$d/w" --keys "$keys" --pubdir "$pub" --passphrase-fd "$fd" \
    3< <(printf '%s\n' "$RP") 4< <(printf '%s\n' "$OP") 5< <(printf '%s\n' "$NP") 6< <(printf 'wrong-passphrase\n')
}
decrypt_to() {  # $1 encrypted key, $2 passphrase, $3 plaintext out (on tmpfs)
  printf '%s' "$2" > "$T/pp"; keylib_decrypt "$1" "$T/pp" "$3"; shred -u "$T/pp"
}

echo "== ceremony refusals"
run "private dir inside the repo" FAIL "inside the repository tree" \
  cer new --private "$ROOT/ci/release/keys/must-not-exist" --public "$T/pubX" --root-pass-fd 3 --online-pass-fd 4
[ ! -e "$ROOT/ci/release/keys/must-not-exist" ] || BAD+=("private dir in repo was created")
mkdir -p "$T/full" "$T/fullpub"; touch "$T/full/x" "$T/fullpub/x"
run "non-empty private dir" FAIL "is not empty" cer new --private "$T/full" --public "$T/pubX" --root-pass-fd 3 --online-pass-fd 4
run "non-empty public dir" FAIL "is not empty" cer new --private "$T/privX" --public "$T/fullpub" --root-pass-fd 3 --online-pass-fd 4
run "same root and online passphrase" FAIL "must differ" \
  cer new --private "$T/privX" --public "$T/pubX" --root-pass-fd 3 --online-pass-fd 7
[ ! -e "$T/privX" ] || BAD+=("a refused ceremony left $T/privX behind")

echo "== ceremony new"
run "ceremony new" PASS "^CEREMONY: PASS \(new" cer new --private "$T/priv" --public "$T/pub" --root-pass-fd 3 --online-pass-fd 4
run "ceremony check" PASS "^CEREMONY: PASS \(check" cer check --private "$T/priv" --public "$T/pub"
if grep -q test_keys "$T/pub/1.root.json"; then BAD+=("1.root.json carries test_keys"); fi
run "1.root.json signatures" PASS "^5$" python3 -I -c \
  'import json,sys; print(len(json.load(open(sys.argv[1]))["signatures"]))' "$T/pub/1.root.json"

echo "== production signing path"
mkstage "$T/r1"
run "sign-release --keys (production)" PASS "^SIGN-RELEASE: PASS \(production" signrel "$T/r1" "$T/priv/online" "$T/pub" 4
run "verify --trusted-root 1.root.json" PASS "^RELEASE-VERIFY: PASS$" verify --trusted-root "$T/pub/1.root.json" "$T/r1/stage"
[ ! -e "$T/r1/stage/TEST_KEYS" ] || BAD+=("production release has TEST_KEYS")
run "production release without a trust anchor" FAIL "REL-2 no-trust-anchor" verify "$T/r1/stage"

echo "== wrong passphrase"
mkstage "$T/m-pass"
run "wrong passphrase (sign-release)" FAIL "passphrase does not open" signrel "$T/m-pass" "$T/priv/online" "$T/pub" 6
mkdir -m 700 "$T/kd-pass" "$T/pp-dir"; printf 'wrong-passphrase' > "$T/pp-dir/p"
run "wrong passphrase (sign job)" FAIL "cannot decrypt" bash "$REL/jobs/sign.sh" --sums "$T/m-pass/stage/SHA256SUMS" \
  --keydir "$T/kd-pass" --out "$T/m-pass/sigout" --enc-keys "$T/priv/online" --passfile "$T/pp-dir/p" --pubdir "$T/pub"
[ -z "$(ls -A "$T/kd-pass")" ] || BAD+=("sign job left keys after a wrong passphrase")

echo "== root signed by only 2 of 5"
run "strip root to 2 signatures" PASS "" "$PY_TUF" -I "$HERE/selftest_mut.py" strip-root "$T/pub/1.root.json" "$T/root-2of5.json" 2
run "verify with a 2-of-5 trusted root" FAIL "REL-2 root-threshold" verify --trusted-root "$T/root-2of5.json" "$T/r1/stage"
cp -r "$T/pub" "$T/pub-2of5"; cp "$T/root-2of5.json" "$T/pub-2of5/1.root.json"
mkstage "$T/m-2of5"
run "2-of-5 committed root (tuf job / sign-release)" FAIL "2/5 valid signatures" signrel "$T/m-2of5" "$T/priv/online" "$T/pub-2of5" 4
mkdir -m 700 "$T/two"; mkdir "$T/pub-empty"
for i in 1 2; do decrypt_to "$T/priv/root-$i.key.enc.pem" "$RP" "$T/two/root-$i.key.pem"; done
cp "$T/pub"/*.pub.pem "$T/pub-empty/"
run "root.py make with 2 root keys" FAIL "2/5 valid signatures" "$PY_TUF" -I "$HERE/root.py" make --pubdir "$T/pub-empty" \
  --signdir "$T/two" --days 365 --out "$T/pub-empty/1.root.json"
[ ! -e "$T/pub-empty/1.root.json" ] || BAD+=("root.py make wrote a 2-of-5 root")
cp -r "$T/pub" "$T/pub-n2"
run "next-root with 2 root keys" FAIL "at least 3 --root-key" cer next-root --public "$T/pub-n2" \
  --root-key "$T/priv/root-1.key.enc.pem" --root-key "$T/priv/root-2.key.enc.pem" --root-pass-fd 3

echo "== test_keys markers in production mode"
mkstage "$T/m-tk"; printf 'test_keys: true\n' > "$T/m-tk/stage/TEST_KEYS"
run "TEST_KEYS in the stage (sign-release)" FAIL "TEST_KEYS" signrel "$T/m-tk" "$T/priv/online" "$T/pub" 4
mkdir -m 700 "$T/kd-tk" "$T/five"
run "TEST_KEYS in the stage (tuf job)" FAIL "carries a TEST_KEYS file" "$PY_TUF" -I "$REL/jobs/tuf.py" --release "$T/m-tk/stage" \
  --keydir "$T/kd-tk" --enc-keys "$T/priv/online" --passfile "$T/pp-dir/p" --roots "$T/pub"
for i in 1 2 3 4 5; do decrypt_to "$T/priv/root-$i.key.enc.pem" "$RP" "$T/five/root-$i.key.pem"; done
cp -r "$T/pub" "$T/pub-marked"
run "mark root" PASS "" "$PY_TUF" -I "$HERE/selftest_mut.py" mark-root "$T/pub/1.root.json" "$T/five" "$T/pub-marked/1.root.json"
mkstage "$T/m-mark"
run "committed root with test_keys (sign-release)" FAIL "test_keys marker" signrel "$T/m-mark" "$T/priv/online" "$T/pub-marked" 4
run "committed root with test_keys (ceremony check)" FAIL "test_keys marker" cer check --public "$T/pub-marked"
cp -r "$T/r1/stage" "$T/m-tkrel"; mkdir -m 700 "$T/onl"
for n in targets snapshot timestamp; do decrypt_to "$T/priv/online/$n.key.enc.pem" "$OP" "$T/onl/$n.key.pem"; done
run "re-sign release with TEST_KEYS" PASS "" "$PY_TUF" -I "$HERE/selftest_mut.py" mark-release "$T/m-tkrel" "$T/onl"
run "production verify of a TEST_KEYS release" FAIL "REL-4 test-keys" verify --trusted-root "$T/pub/1.root.json" "$T/m-tkrel"

echo "== plaintext private key left behind"
cp -a "$T/priv" "$T/priv-leak"
decrypt_to "$T/priv/online/attest.key.enc.pem" "$OP" "$T/priv-leak/online/attest.key.pem"
run "plaintext key in the private dir (check)" FAIL "attest.key.pem" cer check --private "$T/priv-leak"
mkstage "$T/m-leak"
run "plaintext key in the online dir (sign-release)" FAIL "plaintext private key|unexpected file" \
  signrel "$T/m-leak" "$T/priv-leak/online" "$T/pub" 4
cp -a "$T/priv" "$T/priv-leak2"
decrypt_to "$T/priv/root-3.key.enc.pem" "$RP" "$T/priv-leak2/root-3.key.enc.pem"
run "root copy stored unencrypted (check)" FAIL "root-3.key.enc.pem: (plaintext|not a single)" cer check --private "$T/priv-leak2"
cp -r "$T/pub" "$T/pub-leak"; cp "$T/five/root-1.key.pem" "$T/pub-leak/1.root.json.bak"
run "plaintext key in the public dir (check)" FAIL "PRIVATE KEY|private key|unexpected file" cer check --public "$T/pub-leak"

echo "== committed public key differs"
cp -r "$T/pub" "$T/pub-other"
"$OPENSSL" genpkey -algorithm ED25519 -out "$T/five/other.key.pem"
"$OPENSSL" pkey -in "$T/five/other.key.pem" -pubout -out "$T/pub-other/ed25519.pub.pem"
mkstage "$T/m-other"
run "release key is not the committed one (sign job)" FAIL "is not the committed" signrel "$T/m-other" "$T/priv/online" "$T/pub-other" 4

echo "== next-root: renew, then replace root-2 and the online keys"
cp -r "$T/pub" "$T/pubR"
run "next-root renew (root-1,2,3)" PASS "^CEREMONY: PASS \(next-root: v2" cer next-root --public "$T/pubR" \
  --root-key "$T/priv/root-1.key.enc.pem" --root-key "$T/priv/root-2.key.enc.pem" \
  --root-key "$T/priv/root-3.key.enc.pem" --root-pass-fd 3
mkstage "$T/r2"
run "sign-release under root v2" PASS "^SIGN-RELEASE: PASS \(production" signrel "$T/r2" "$T/priv/online" "$T/pubR" 4
run "verify v2 release against 1.root.json" PASS "^RELEASE-VERIFY: PASS$" verify --trusted-root "$T/pub/1.root.json" "$T/r2/stage"
run "next-root replace root-2 + online (root-1,3,4)" PASS "^CEREMONY: PASS \(next-root: v3" cer next-root --public "$T/pubR" \
  --root-key "$T/priv/root-1.key.enc.pem" --root-key "$T/priv/root-3.key.enc.pem" \
  --root-key "$T/priv/root-4.key.enc.pem" --replace-root 2 --replace-online --new-private "$T/new" \
  --root-pass-fd 3 --online-pass-fd 5
mkstage "$T/r3"
run "sign-release with the new online keys" PASS "^SIGN-RELEASE: PASS \(production" signrel "$T/r3" "$T/new/online" "$T/pubR" 5
run "verify v3 release against 1.root.json" PASS "^RELEASE-VERIFY: PASS$" verify --trusted-root "$T/pub/1.root.json" "$T/r3/stage"
mkstage "$T/m-old"
run "old online keys after rotation" FAIL "is not the (key of the )?committed|not the .* key named" \
  signrel "$T/m-old" "$T/priv/online" "$T/pubR" 4
run "next-root signed with the replaced root-2" FAIL "is not one of the current root keys" cer next-root --public "$T/pubR" \
  --root-key "$T/priv/root-1.key.enc.pem" --root-key "$T/priv/root-2.key.enc.pem" \
  --root-key "$T/priv/root-3.key.enc.pem" --root-pass-fd 3

echo "== leftovers"
left=$(find /dev/shm -maxdepth 1 \( -name 'aegis-release-keys.*' -o -name 'aegis-release-pass.*' -o -name 'aegis-ceremony.*' \) \
  -user "$(id -u)" -newer "$T/.start" 2> /dev/null | head -3)
[ -z "$left" ] || BAD+=("decrypted key / passphrase dirs left on tmpfs: $left")
keylib_shred_dir "$T"
[ ! -e "$T" ] || BAD+=("self-test dir $T not removed")
if [ "${#BAD[@]}" -gt 0 ]; then
  echo "CEREMONY: FAIL (self-test: ${BAD[0]}; ${#BAD[@]} bad case(s))"
  exit 1
fi
echo "CEREMONY: PASS (self-test: $NOK clean steps passed, $NMUT mutants refused, each with its own reason; throwaway keys shredded)"
