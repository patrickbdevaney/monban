#!/usr/bin/env bash
# AEGIS release key ceremony (solo maintainer; runbook: ci/release/keys/README.md).
#
#   ceremony.sh new --private DIR --public DIR [--root-days N] [--root-pass-fd N] [--online-pass-fd N]
#       Makes every production key once: 5 TUF root keys (Ed25519), the TUF targets/snapshot/timestamp keys (Ed25519),
#       the release signing keys (Ed25519, SLH-DSA-SHA2-128s, ML-DSA-87) and a separate attest key (Ed25519).
#       --private (outside the repo, empty or absent) gets every private key, each its own passphrase-encrypted
#       PKCS#8 file (PBES2, PBKDF2-HMAC-SHA256 600,000 iterations, AES-256-CBC):
#         root-1.key.enc.pem .. root-5.key.enc.pem     the 5 root copies: store each in a different place
#         online/*.key.enc.pem                         the 7 keys a release uses (ci/release/pipeline.sh --keys)
#         WHERE-TO-STORE.txt
#       --public (empty or absent; normally release-keys/ in the repo) gets the 12 public keys, KEYS.txt and
#       1.root.json: 5 root keys, threshold 3, signed by all 5 root keys, no test_keys marker.
#       Two passphrases, each asked twice on the terminal (or one line from the given fd): one for the 5 root files,
#       one (different) for the online keys. Minimum 12 characters.
#   ceremony.sh next-root --public DIR --root-key FILE --root-key FILE --root-key FILE [...]
#                         [--replace-root N ...] [--replace-online] [--new-private DIR] [--root-days N]
#                         [--root-pass-fd N] [--online-pass-fd N]
#       Writes DIR/(N+1).root.json signed by >= 3 of the current root keys (the files given). With no replacement it
#       just renews the expiry. --replace-root N makes a new root-N key; --replace-online makes 7 new online keys (new
#       online passphrase); both go to --new-private (outside the repo, empty or absent) and their public keys
#       replace the old ones in DIR.
#   ceremony.sh check [--private DIR] [--public DIR]
#       Audits a private dir (every key encrypted, nothing else in it) and/or a public dir (public keys only, root
#       chain 3 of 5 Ed25519, no test_keys).
#   ceremony.sh --self-test
#       Runs ci/release/keys/selftest.sh (throwaway keys on tmpfs; never real keys).
#
# Plaintext keys exist only in a 0700 dir on tmpfs (/dev/shm) that is shredded on exit, as are the passphrase files.
# Needs OpenSSL >= 3.5 ($AEGIS_OPENSSL or /usr/bin/openssl) and the hash-locked python-tuf venv
# ($AEGIS_PY_TUF_PYTHON or ~/aegis-ci/py-tuf/bin/python) for the TUF root.
# Final line: CEREMONY: PASS (...) or CEREMONY: FAIL (<reason>).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
# shellcheck source=ci/release/keys/lib.sh
. "$HERE/lib.sh"
fail() { echo "CEREMONY: FAIL ($*)"; exit 1; }
usage() { sed -n '2,/^# Plaintext/p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
PY_TUF="${AEGIS_PY_TUF_PYTHON:-$HOME/aegis-ci/py-tuf/bin/python}"
ONLINE=(ed25519 slh-dsa-sha2-128s ml-dsa-87 attest targets snapshot timestamp)
declare -A ALG=([ed25519]=ED25519 [slh-dsa-sha2-128s]=SLH-DSA-SHA2-128s [ml-dsa-87]=ML-DSA-87 [attest]=ED25519
  [targets]=ED25519 [snapshot]=ED25519 [timestamp]=ED25519)

[ $# -gt 0 ] || usage
CMD="$1"; shift
if [ "$CMD" = --self-test ]; then exec bash "$HERE/selftest.sh" "$@"; fi

W=
CREATED=
on_exit() {
  local rc=$?
  keylib_shred_dir "$W"
  # a failed `new` leaves no half-made private dir behind
  if [ "$rc" != 0 ] && [ -n "$CREATED" ] && [ -d "$CREATED" ]; then keylib_shred_dir "$CREATED"; fi
}
trap on_exit EXIT

need_tools() {
  keylib_openssl || fail "need OpenSSL >= 3.5"
  [ -x "$PY_TUF" ] || fail "python-tuf venv python not found at $PY_TUF (set AEGIS_PY_TUF_PYTHON)"
}

abspath() {  # absolute path of a possibly missing path (its parent must exist)
  local p="$1" d
  d="$(cd "$(dirname "$p")" 2> /dev/null && pwd -P)" || fail "parent of $p does not exist"
  printf '%s/%s\n' "$d" "$(basename "$p")"
}

outside_repo() {  # $1 = absolute path: refuse anything inside this repo or any git work tree
  local p="$1" q
  case "$p/" in "$ROOT"/*) fail "$p is inside the repository tree ($ROOT); private keys never go there" ;; esac
  q="$p"; while [ ! -d "$q" ]; do q="$(dirname "$q")"; done
  if git -C "$q" rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    fail "$p is inside a git work tree ($(git -C "$q" rev-parse --show-toplevel)); private keys never go there"
  fi
}

empty_dir() {  # $1 = path: absent (then created 0700) or an empty directory
  if [ -e "$1" ]; then
    [ -d "$1" ] || fail "$1 exists and is not a directory"
    [ -z "$(ls -A "$1")" ] || fail "$1 is not empty (refusing to mix or overwrite keys)"
  else
    mkdir -p "$1"
  fi
  chmod 700 "$1"
}

spki_sha256() { "$OPENSSL" pkey -pubin -in "$1" -outform DER | sha256sum | cut -d' ' -f1; }

genkey() {  # $1 name, $2 algorithm, $3 passfile, $4 encrypted output; plaintext in $W/plain, public in $W/pub
  (umask 077 && "$OPENSSL" genpkey -algorithm "$2" -out "$W/plain/$1.key.pem") || fail "genpkey $2 failed"
  "$OPENSSL" pkey -in "$W/plain/$1.key.pem" -pubout -out "$W/pub/$1.pub.pem"
  keylib_encrypt "$W/plain/$1.key.pem" "$3" "$4" || fail "encrypting $1 failed"
  # round trip: the encrypted file opens with the passphrase and holds the same key
  keylib_decrypt "$4" "$3" "$W/check.key.pem" || fail "$4 does not decrypt"
  cmp -s <("$OPENSSL" pkey -in "$W/check.key.pem" -pubout) "$W/pub/$1.pub.pem" || fail "$4 round trip differs"
  shred -u -z "$W/check.key.pem"
}

write_keys_txt() {  # $1 = public dir
  {
    echo "AEGIS release public keys (ci/release/keys/README.md). sha256 = sha256 of the SPKI DER public key."
    echo "Written by ci/release/keys/ceremony.sh $CMD on $(date -u +%Y-%m-%dT%H:%M:%SZ)."
    echo
    local n
    for n in root-1 root-2 root-3 root-4 root-5 "${ONLINE[@]}"; do
      printf '%-18s %-18s %s\n' "$n" "$( [[ $n == root-* ]] && echo ED25519 || echo "${ALG[$n]}")" \
        "$(spki_sha256 "$1/$n.pub.pem")"
    done
    echo
    echo "Root metadata: $(cd "$1" && ls ./*.root.json | sed 's|^\./||' | sort -n | tr '\n' ' ')"
  } > "$1/KEYS.txt"
}

storage_text() {  # $1 = private dir
  cat << EOF
AEGIS release keys: where each encrypted file goes (ci/release/keys/README.md has the full runbook).
Every file here is passphrase-encrypted. A copy alone is useless without its passphrase; a passphrase alone is
useless without the file. Keep the two apart.

ROOT KEYS (any 3 of the 5 sign a new root; losing or leaking up to 2 is survivable). One copy per place,
never two on the same device, never all on this computer:
  root-1.key.enc.pem   external drive A (at home)
  root-2.key.enc.pem   USB stick B (at home, a different drawer from A)
  root-3.key.enc.pem   USB stick C (another building: office, family, safe deposit box)
  root-4.key.enc.pem   encrypted cloud backup / password manager file attachment
  root-5.key.enc.pem   USB stick D (a second other building)
  Root passphrase: in your password manager, plus a paper copy in a sealed envelope that is NOT stored
  with any of the USB sticks.
  Then delete the root files from this computer:  shred -u $1/root-*.key.enc.pem

ONLINE KEYS (online/, used for every release; one passphrase for all 7):
  online/  -> the build box that runs ci/release/pipeline.sh (kamrui: ~/aegis-release-keys/online, mode 0700)
           -> plus one backup copy on external drive A (next to root-1 is fine: they have different passphrases)
  Online passphrase: password manager. If online keys leak, replace them (ceremony.sh next-root --replace-online).
EOF
}

# ------------------------------------------------------------------ new
cmd_new() {
  local PRIV= PUB= DAYS=365 RFD= OFD=
  while [ $# -gt 0 ]; do
    case "$1" in
      --private) PRIV="${2:-}" ;; --public) PUB="${2:-}" ;; --root-days) DAYS="${2:-}" ;;
      --root-pass-fd) RFD="${2:-}" ;; --online-pass-fd) OFD="${2:-}" ;; *) usage ;;
    esac
    shift 2
  done
  [ -n "$PRIV" ] && [ -n "$PUB" ] || usage
  [[ "$DAYS" =~ ^[0-9]+$ ]] && [ "$DAYS" -ge 30 ] && [ "$DAYS" -le 3650 ] || fail "--root-days must be 30..3650"
  need_tools
  PRIV="$(abspath "$PRIV")" PUB="$(abspath "$PUB")"
  outside_repo "$PRIV"
  case "$PUB/" in "$PRIV"/*) fail "--public must not be inside --private" ;; esac
  case "$PRIV/" in "$PUB"/*) fail "--private must not be inside --public" ;; esac
  [ ! -e "$PRIV" ] || [ -z "$(ls -A "$PRIV" 2> /dev/null)" ] || fail "$PRIV is not empty (refusing to mix or overwrite keys)"
  [ ! -e "$PUB" ] || [ -z "$(ls -A "$PUB" 2> /dev/null)" ] || fail "$PUB is not empty (refusing to mix or overwrite keys)"
  W="$(keylib_tmpfs ceremony)" || fail "no tmpfs"
  mkdir -m 700 "$W/plain" "$W/pub"
  keylib_read_pass "$W/rootpass" "root key passphrase (for the 5 root copies)" "$RFD" 1 12 || fail "root passphrase"
  keylib_read_pass "$W/onlinepass" "online key passphrase (for releases; different from the root one)" "$OFD" 1 12 \
    || fail "online passphrase"
  ! cmp -s "$W/rootpass" "$W/onlinepass" || fail "the root and online passphrases must differ"
  [ -e "$PRIV" ] || CREATED="$PRIV"
  empty_dir "$PRIV"
  [ -n "$CREATED" ] || CREATED="$PRIV"  # it was empty: on failure empty it again
  mkdir -m 700 "$PRIV/online"
  local i n
  for i in 1 2 3 4 5; do
    genkey "root-$i" ED25519 "$W/rootpass" "$PRIV/root-$i.key.enc.pem"
    echo "ceremony: root-$i (Ed25519) made and encrypted"
  done
  for n in "${ONLINE[@]}"; do
    genkey "$n" "${ALG[$n]}" "$W/onlinepass" "$PRIV/online/$n.key.enc.pem"
    echo "ceremony: online $n (${ALG[$n]}) made and encrypted"
  done
  "$PY_TUF" -I "$HERE/root.py" make --pubdir "$W/pub" --signdir "$W/plain" --days "$DAYS" \
    --out "$W/pub/1.root.json" | sed 's/^/ceremony: /' || fail "root.py make failed"
  write_keys_txt "$W/pub"
  storage_text "$PRIV" > "$PRIV/WHERE-TO-STORE.txt"
  chmod 600 "$PRIV/WHERE-TO-STORE.txt"
  "$PY_TUF" -I "$HERE/root.py" check --pubdir "$W/pub" | sed 's/^/ceremony: /' || fail "root.py check failed"
  python3 -I "$HERE/keycheck.py" private "$PRIV" | sed 's/^/ceremony: /' || fail "keycheck private failed"
  python3 -I "$HERE/keycheck.py" public "$W/pub" | sed 's/^/ceremony: /' || fail "keycheck public failed"
  empty_dir "$PUB"
  cp "$W/pub"/* "$PUB/"
  chmod 644 "$PUB"/*
  chmod 755 "$PUB"
  CREATED=
  echo
  storage_text "$PRIV"
  echo
  echo "Public keys and root: $PUB (commit this directory)."
  case "$PRIV" in /dev/shm/* | /run/*) echo "NOTE: $PRIV is on tmpfs and vanishes on reboot: copy the files out now." ;; esac
  echo "CEREMONY: PASS (new: 12 keys encrypted in $PRIV, root v1 3 of 5 signed by 5, expires in $DAYS days; plaintext shredded)"
}

# ------------------------------------------------------------------ next-root
cmd_next_root() {
  local PUB= NEWPRIV= DAYS=365 RFD= OFD= ONL=0 RK=() REP=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --public) PUB="${2:-}"; shift 2 ;; --root-key) RK+=("${2:-}"); shift 2 ;;
      --replace-root) REP+=("${2:-}"); shift 2 ;; --replace-online) ONL=1; shift ;;
      --new-private) NEWPRIV="${2:-}"; shift 2 ;; --root-days) DAYS="${2:-}"; shift 2 ;;
      --root-pass-fd) RFD="${2:-}"; shift 2 ;; --online-pass-fd) OFD="${2:-}"; shift 2 ;; *) usage ;;
    esac
  done
  [ -n "$PUB" ] || usage
  [ "${#RK[@]}" -ge 3 ] || fail "need at least 3 --root-key files (3 of the 5 current root keys sign a new root)"
  [[ "$DAYS" =~ ^[0-9]+$ ]] && [ "$DAYS" -ge 30 ] && [ "$DAYS" -le 3650 ] || fail "--root-days must be 30..3650"
  local r
  for r in "${REP[@]}"; do [[ "$r" =~ ^[1-5]$ ]] || fail "--replace-root takes 1..5, got $r"; done
  if [ "${#REP[@]}" -gt 0 ] || [ "$ONL" = 1 ]; then
    [ -n "$NEWPRIV" ] || fail "replacing keys needs --new-private DIR (outside the repo) for the new encrypted keys"
  fi
  need_tools
  PUB="$(cd "$PUB" && pwd -P)" || fail "no public dir $PUB"
  python3 -I "$HERE/keycheck.py" public "$PUB" > /dev/null || fail "keycheck public $PUB refused"
  "$PY_TUF" -I "$HERE/root.py" check --pubdir "$PUB" --ignore-expiry | sed 's/^/ceremony: current: /' \
    || fail "the current root chain in $PUB is refused"
  W="$(keylib_tmpfs ceremony)" || fail "no tmpfs"
  mkdir -m 700 "$W/plain" "$W/pub" "$W/sign"
  cp "$PUB"/* "$W/pub/"
  keylib_read_pass "$W/rootpass" "root key passphrase" "$RFD" 0 1 || fail "root passphrase"
  local f i slot used=" "
  for f in "${RK[@]}"; do
    keylib_decrypt "$f" "$W/rootpass" "$W/one.key.pem" || fail "cannot decrypt $f (wrong passphrase?)"
    slot=
    for i in 1 2 3 4 5; do
      cmp -s <("$OPENSSL" pkey -in "$W/one.key.pem" -pubout) "$PUB/root-$i.pub.pem" && slot=$i
    done
    [ -n "$slot" ] || fail "$f is not one of the current root keys in $PUB"
    [[ "$used" != *" $slot "* ]] || fail "$f is root-$slot again (give 3 different root keys)"
    used+="$slot "
    mv "$W/one.key.pem" "$W/sign/root-$slot.key.pem"
    echo "ceremony: $f opens as current root-$slot"
  done
  if [ -n "$NEWPRIV" ]; then
    NEWPRIV="$(abspath "$NEWPRIV")"
    outside_repo "$NEWPRIV"
    [ ! -e "$NEWPRIV" ] || [ -z "$(ls -A "$NEWPRIV" 2> /dev/null)" ] || fail "$NEWPRIV is not empty"
    [ -e "$NEWPRIV" ] || CREATED="$NEWPRIV"
    empty_dir "$NEWPRIV"
    [ -n "$CREATED" ] || CREATED="$NEWPRIV"
  fi
  for r in "${REP[@]}"; do
    genkey "root-$r" ED25519 "$W/rootpass" "$NEWPRIV/root-$r.key.enc.pem"
    cp "$W/plain/root-$r.key.pem" "$W/sign/root-$r.new.key.pem"
    echo "ceremony: new root-$r made and encrypted"
  done
  if [ "$ONL" = 1 ]; then
    keylib_read_pass "$W/onlinepass" "NEW online key passphrase" "$OFD" 1 12 || fail "online passphrase"
    ! cmp -s "$W/rootpass" "$W/onlinepass" || fail "the root and online passphrases must differ"
    mkdir -m 700 "$NEWPRIV/online"
    local n
    for n in "${ONLINE[@]}"; do
      genkey "$n" "${ALG[$n]}" "$W/onlinepass" "$NEWPRIV/online/$n.key.enc.pem"
      echo "ceremony: new online $n made and encrypted"
    done
  fi
  local v
  v=$(( $(cd "$W/pub" && ls ./*.root.json | wc -l) + 1 ))
  "$PY_TUF" -I "$HERE/root.py" make --pubdir "$W/pub" --signdir "$W/sign" --days "$DAYS" \
    --out "$W/new.root.json" | sed 's/^/ceremony: /' || fail "root.py make refused the new root"
  mv "$W/new.root.json" "$W/pub/$v.root.json"
  write_keys_txt "$W/pub"
  "$PY_TUF" -I "$HERE/root.py" check --pubdir "$W/pub" | sed 's/^/ceremony: /' || fail "root.py check failed"
  python3 -I "$HERE/keycheck.py" public "$W/pub" | sed 's/^/ceremony: /' || fail "keycheck public failed"
  if [ -n "$NEWPRIV" ]; then
    python3 -I "$HERE/keycheck.py" partial "$NEWPRIV" | sed 's/^/ceremony: /' || fail "keycheck of $NEWPRIV failed"
  fi
  cp "$W/pub"/* "$PUB/"
  chmod 644 "$PUB"/*
  CREATED=
  echo
  echo "Commit $PUB ($v.root.json and the changed public keys)."
  for r in "${REP[@]}"; do
    echo "Store $NEWPRIV/root-$r.key.enc.pem where the old root-$r copy lived; destroy the old copy if you still have it."
  done
  [ "$ONL" = 0 ] || echo "Replace the online/ dir on the build box (and its backup) with $NEWPRIV/online; destroy the old one."
  local who; who="$(echo $used)"
  echo "CEREMONY: PASS (next-root: v$v signed by root keys ${who// /,}; ${#REP[@]} root key(s) and $([ "$ONL" = 1 ] && echo 7 || echo 0) online keys replaced; expires in $DAYS days)"
}

# ------------------------------------------------------------------ check
cmd_check() {
  local PRIV= PUB=
  while [ $# -gt 0 ]; do
    case "$1" in --private) PRIV="${2:-}" ;; --public) PUB="${2:-}" ;; *) usage ;; esac
    shift 2
  done
  [ -n "$PRIV$PUB" ] || usage
  if [ -n "$PRIV" ]; then
    python3 -I "$HERE/keycheck.py" private "$PRIV" || fail "private dir $PRIV refused"
  fi
  if [ -n "$PUB" ]; then
    [ -x "$PY_TUF" ] || fail "python-tuf venv python not found at $PY_TUF"
    python3 -I "$HERE/keycheck.py" public "$PUB" || fail "public dir $PUB refused"
    "$PY_TUF" -I "$HERE/root.py" check --pubdir "$PUB" || fail "root chain in $PUB refused"
  fi
  echo "CEREMONY: PASS (check${PRIV:+ private $PRIV}${PUB:+ public $PUB})"
}

case "$CMD" in
  new) cmd_new "$@" ;;
  next-root) cmd_next_root "$@" ;;
  check) cmd_check "$@" ;;
  *) usage ;;
esac
