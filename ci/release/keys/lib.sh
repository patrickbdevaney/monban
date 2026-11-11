# Shared helpers for the release key tools (sourced by ci/release/keys/ceremony.sh, ci/release/sign-release.sh and
# ci/release/pipeline.sh). Bash only; nothing here prints or logs a passphrase.
#
# Encrypted key format: PKCS#8 EncryptedPrivateKeyInfo PEM ("BEGIN ENCRYPTED PRIVATE KEY"), PBES2 with
# PBKDF2-HMAC-SHA256 (600,000 iterations, 16-byte salt) and AES-256-CBC, written by `openssl pkcs8 -topk8`.
# A passphrase only ever lives in a bash variable for the moment it is read and in a 0600 file on tmpfs that the
# caller shreds; OpenSSL reads it with `-passin file:` / `-passout file:` (never argv, never the environment).

KEYLIB_ITER=600000

keylib_openssl() {  # sets OPENSSL, or returns 1
  OPENSSL="${AEGIS_OPENSSL:-/usr/bin/openssl}"
  [[ "$("$OPENSSL" version 2> /dev/null)" =~ ^OpenSSL\ 3\.([5-9]|[1-9][0-9])\. ]] || {
    echo "need OpenSSL >= 3.5 at $OPENSSL (set AEGIS_OPENSSL)" >&2
    return 1
  }
}

keylib_tmpfs() {  # $1 = name tag -> prints a fresh 0700 dir on tmpfs (/dev/shm), or fails
  [ -d /dev/shm ] && [ -w /dev/shm ] || { echo "no writable /dev/shm (tmpfs) for decrypted keys" >&2; return 1; }
  local d
  d="$(mktemp -d "/dev/shm/monban-$1.XXXXXX")" || return 1
  chmod 700 "$d"
  printf '%s\n' "$d"
}

keylib_shred_dir() {  # $1 = dir: shred every file in it, then remove it
  [ -n "${1:-}" ] && [ -d "$1" ] || return 0
  find "$1" -type f -exec shred -u -z {} + 2> /dev/null || true
  rm -rf "$1"
}

# keylib_read_pass FILE PROMPT FD CONFIRM MINLEN
#   FD non-empty: read one line from that file descriptor (automation, the self-test).
#   FD empty: prompt on /dev/tty without echo; CONFIRM=1 asks twice.
#   Writes the passphrase (no newline) to FILE with mode 0600. Refuses an empty or too short passphrase.
keylib_read_pass() {
  local file="$1" prompt="$2" fd="$3" confirm="$4" min="${5:-1}" p="" q=""
  if [ -n "$fd" ]; then
    [[ "$fd" =~ ^[0-9]+$ ]] || { echo "bad passphrase fd $fd" >&2; return 1; }
    IFS= read -r -u "$fd" p || [ -n "$p" ] || { echo "no passphrase on fd $fd" >&2; return 1; }
  else
    [ -r /dev/tty ] || { echo "no terminal for the passphrase prompt; use the --*pass-fd option" >&2; return 1; }
    IFS= read -r -s -p "$prompt: " p < /dev/tty || true
    echo > /dev/tty
    if [ "$confirm" = 1 ]; then
      IFS= read -r -s -p "$prompt (again): " q < /dev/tty || true
      echo > /dev/tty
      [ "$p" = "$q" ] || { p="" q=""; echo "passphrases differ" >&2; return 1; }
    fi
  fi
  q=""
  [ "${#p}" -ge "$min" ] || { p=""; echo "passphrase shorter than $min characters" >&2; return 1; }
  (umask 077 && printf '%s' "$p" > "$file")
  p=""
}

keylib_encrypt() {  # $1 plaintext key PEM, $2 passphrase file, $3 output (encrypted PKCS#8 PEM, mode 0600)
  (umask 077 && "$OPENSSL" pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter "$KEYLIB_ITER" \
    -in "$1" -passout "file:$2" -out "$3")
}

keylib_decrypt() {  # $1 encrypted key, $2 passphrase file, $3 plaintext output (mode 0600; put it on tmpfs)
  (umask 077 && "$OPENSSL" pkey -in "$1" -passin "file:$2" -out "$3" 2> /dev/null)
}

keylib_pass_ok() {  # $1 encrypted key, $2 passphrase file: the passphrase opens the key (nothing written)
  "$OPENSSL" pkey -in "$1" -passin "file:$2" -noout > /dev/null 2>&1
}
