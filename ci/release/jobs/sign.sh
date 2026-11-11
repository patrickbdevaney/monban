#!/usr/bin/env bash
# Release job 4: sign (PLAN-6 D6, F1 REL-1). Ed25519, SLH-DSA-SHA2-128s and ML-DSA-87 over the same digest with the
# OpenSSL 3.5.3 CLI. Fresh per-run test keys (D-P2) in this job's own key directory, shredded before it exits.
#
#   sign.sh --sums SHA256SUMS --keydir DIR --out DIR
#   sign.sh --sums SHA256SUMS --keydir DIR --out DIR --enc-keys DIR --passfile FILE --pubdir DIR   (production)
#
# Production mode (ci/release/keys/README.md): no key is generated; each <alg>.key.enc.pem in --enc-keys is decrypted
# into this job's key directory (openssl pkey -passin file:PASSFILE) and must match the committed --pubdir/<alg>.pub.pem
# byte for byte. The key directory is shredded the same way in both modes.
#
# The signed message (layout contract v1, ci/release/verify.py) is
#   b"aegis-release-v1 sha256:" + hex(sha256(SHA256SUMS)) + b"\n"
# and SHA256SUMS lists every artifact and the SBOM, so the three signatures cover both. Writes OUT/sigs/<alg>.sig,
# .subject and .pub.pem; each signature is verified with the shipped public key before the job succeeds.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
die() { echo "sign: $*" >&2; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --sums) SUMS="$2" ;; --keydir) KD="$2" ;; --out) OUT="$2" ;;
    --enc-keys) ENC="$2" ;; --passfile) PASSFILE="$2" ;; --pubdir) PUBDIR="$2" ;;
    *) die "unknown argument $1" ;;
  esac
  shift 2
done
for v in SUMS KD OUT; do [ -n "${!v:-}" ] || die "missing --${v,,}"; done
PROD=0
if [ -n "${ENC:-}${PASSFILE:-}${PUBDIR:-}" ]; then
  [ -n "${ENC:-}" ] && [ -n "${PASSFILE:-}" ] && [ -n "${PUBDIR:-}" ] \
    || die "production mode needs --enc-keys, --passfile and --pubdir together"
  PROD=1
fi
OPENSSL="${AEGIS_OPENSSL:-/usr/bin/openssl}"
ver=$("$OPENSSL" version)
[[ "$ver" =~ ^OpenSSL\ 3\.([5-9]|[1-9][0-9])\. ]] || die "need OpenSSL >= 3.5, got $ver"
[ -d "$KD" ] && [ -z "$(ls -A "$KD")" ] || die "key directory must exist and be empty"
shred_keys() { find "$KD" -type f -exec shred -u -z {} + 2> /dev/null || true; }
trap shred_keys EXIT
mkdir -p "$OUT/sigs"
digest=$(sha256sum "$SUMS" | cut -d' ' -f1)
declare -A ALG=([ed25519]=ED25519 [slh-dsa-sha2-128s]=SLH-DSA-SHA2-128s [ml-dsa-87]=ML-DSA-87)
for a in ed25519 slh-dsa-sha2-128s ml-dsa-87; do
  k="$KD/$a.key.pem"
  if [ "$PROD" = 1 ]; then
    (umask 077 && "$OPENSSL" pkey -in "$ENC/$a.key.enc.pem" -passin "file:$PASSFILE" -out "$k" 2> /dev/null) \
      || die "cannot decrypt $ENC/$a.key.enc.pem (wrong passphrase or not an encrypted key)"
    "$OPENSSL" pkey -in "$k" -pubout -out "$OUT/sigs/$a.pub.pem"
    cmp -s "$OUT/sigs/$a.pub.pem" "$PUBDIR/$a.pub.pem" || die "$a key is not the committed $PUBDIR/$a.pub.pem"
  else
    (umask 077 && "$OPENSSL" genpkey -algorithm "${ALG[$a]}" -out "$k")
    "$OPENSSL" pkey -in "$k" -pubout -out "$OUT/sigs/$a.pub.pem"
  fi
  printf 'aegis-release-v1 sha256:%s\n' "$digest" > "$OUT/sigs/$a.subject"
  "$OPENSSL" pkeyutl -sign -rawin -inkey "$k" -in "$OUT/sigs/$a.subject" -out "$OUT/sigs/$a.sig"
  "$OPENSSL" pkeyutl -verify -rawin -pubin -inkey "$OUT/sigs/$a.pub.pem" -in "$OUT/sigs/$a.subject" \
    -sigfile "$OUT/sigs/$a.sig" > /dev/null || die "$a signature does not verify"
  echo "sign: $a $(stat -c %s "$OUT/sigs/$a.sig") B over sha256:$digest"
done
python3 -I "$HERE/leakcheck.py" --keys "$KD" "$OUT" > /dev/null || {
  python3 -I "$HERE/leakcheck.py" --keys "$KD" "$OUT" >&2 || true
  die "private key material in the sign output"
}
shred_keys
[ -z "$(ls -A "$KD")" ] || die "key directory not empty after shred"
if [ "$PROD" = 1 ]; then echo "sign: 3 signatures over one digest (production keys); decrypted copies destroyed"; else echo "sign: 3 signatures over one digest; keys destroyed"; fi
