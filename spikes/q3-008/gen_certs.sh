#!/usr/bin/env bash
# Throwaway P-256 CA + localhost leaf for the TLS runs (not committed). Uses system openssl.
set -euo pipefail; cd "$(dirname "$0")/certs"; O=${OPENSSL:-/usr/bin/openssl}
$O req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj /CN=q3008-ca -keyout ca.key -out ca.crt
$O req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=localhost -keyout server.key -out server.csr
$O x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 -extfile ext.cnf -out server.crt
rm -f ca.key server.csr ca.srl
