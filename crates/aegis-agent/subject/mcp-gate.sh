#!/usr/bin/env bash
# Subject wiring for oracles/mcp-corpus against the SHIPPED binary (P3-agent-001; gate `mcp-gateway`).
#
#   crates/aegis-agent/subject/mcp-gate.sh run        [--flood-n N]   # full corpus incl. needs-* cases -> exit 0 on PASS
#   crates/aegis-agent/subject/mcp-gate.sh self-test                  # negative control: deny-all PDP policy must FAIL
#
# Binaries: $AEGIS_BIN (default target/release/aegis) and $AEGIS_PDP_BIN (default target/release/aegis-pdp); build them
# first (cargo build --release --locked -p aegis-bin -p aegis-pdp, through ci/heavy.sh or ci/remote.sh).
# Starts: aegis-pdp (Cedar, out of process) on a SOCK_SEQPACKET socket, then `aegis agent` with the corpus.json
# gateway profile (routes /mcp, /mcp2, /mcp-redir, /mcp-multi -> the oracle's mock upstream on --upstream-port),
# then the oracle with every subject URL and --subject-pid. Processes it started are stopped by PID only.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HERE="$ROOT/crates/aegis-agent/subject"
mode="${1:-run}"; shift || true
FLOOD=3000
while [ $# -gt 0 ]; do
  case "$1" in
    --flood-n) FLOOD="$2"; shift 2 ;;
    *) echo "usage: $0 run|self-test [--flood-n N]" >&2; exit 2 ;;
  esac
done
AEGIS="${AEGIS_BIN:-$ROOT/target/release/aegis}"
PDP="${AEGIS_PDP_BIN:-$ROOT/target/release/aegis-pdp}"
for b in "$AEGIS" "$PDP"; do [ -x "$b" ] || { echo "MCP-GATE: missing binary $b (build it first)" >&2; exit 2; }; done

work=$(mktemp -d "${TMPDIR:-/tmp}/aegis-mcp-gate.XXXXXX")
pids=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done
  rm -rf "$work"
}
trap cleanup EXIT

read -r P U < <(python3 -I -c '
import socket
s=[socket.socket() for _ in range(2)]
[x.bind(("127.0.0.1",0)) for x in s]
print(*[x.getsockname()[1] for x in s])
[x.close() for x in s]')

secret=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["profile"]["auth"]["secret"])' "$ROOT/oracles/mcp-corpus/corpus.json")
iss=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["profile"]["auth"]["iss"])' "$ROOT/oracles/mcp-corpus/corpus.json")
printf '%s' "$secret" > "$work/jwt.key"
printf '%s' "gw-upstream-credential" > "$work/upstream.key"
chmod 600 "$work/jwt.key" "$work/upstream.key"

policy="$HERE/mcp.cedar"; [ "$mode" = self-test ] && policy="$HERE/deny-all.cedar"
"$PDP" serve --policies "$policy" --schema "$HERE/mcp.cedarschema" --listen "$work/pdp.sock" 2>"$work/pdp.log" &
pids+=($!)

B="http://127.0.0.1:$P"
cat > "$work/agent.json" <<EOF
{"v": 1, "listen": "127.0.0.1:$P",
 "hosts": ["127.0.0.1:$P", "localhost:$P"],
 "origins": ["http://127.0.0.1:$P", "http://localhost:$P"],
 "auth": {"issuer": "$iss", "hs256_secret_file": "$work/jwt.key"},
 "pdp": {"socket": "$work/pdp.sock", "deadline_ms": 500},
 "upstream_credential_file": "$work/upstream.key",
 "egress_readmit": ["127.0.0.1/32"],
 "sessions": {"max": 10000, "per_principal": 256, "idle_ttl_s": 1800},
 "routes": [
  {"path": "/mcp", "resource": "$B/mcp", "upstreams": [{"prefix": "", "url": "http://127.0.0.1:$U/"}]},
  {"path": "/mcp2", "resource": "$B/mcp2", "upstreams": [{"prefix": "", "url": "http://127.0.0.1:$U/"}]},
  {"path": "/mcp-redir", "resource": "$B/mcp-redir", "upstreams": [{"prefix": "", "url": "http://127.0.0.1:$U/redir"}]},
  {"path": "/mcp-multi", "resource": "$B/mcp-multi",
   "upstreams": [{"prefix": "a__", "url": "http://127.0.0.1:$U/a"}, {"prefix": "b__", "url": "http://127.0.0.1:$U/b"}]}]}
EOF

for _ in $(seq 100); do [ -S "$work/pdp.sock" ] && break; sleep 0.05; done
[ -S "$work/pdp.sock" ] || { echo "MCP-GATE: aegis-pdp did not start"; cat "$work/pdp.log"; exit 1; }
"$AEGIS" agent --config "$work/agent.json" >"$work/agent.out" 2>"$work/agent.log" &
apid=$!
pids+=($apid)
for _ in $(seq 100); do grep -q LISTENING "$work/agent.out" 2>/dev/null && break; sleep 0.05; done
grep -q LISTENING "$work/agent.out" || { echo "MCP-GATE: aegis agent did not start"; cat "$work/agent.log"; exit 1; }

set +e
out=$("$ROOT/oracles/mcp-corpus/run" --subject "$B/mcp" --upstream-port "$U" \
  --subject-url2 "$B/mcp2" --subject-redir-url "$B/mcp-redir" --subject-multi-url "$B/mcp-multi" \
  --subject-pid "$apid" --flood-n "$FLOOD" --json-out "$work/results.json" 2>&1)
rc=$?
set -e
echo "$out"
if [ "$mode" = self-test ]; then
  # The deny-all PDP must turn the run red, through the baselines (a gateway that rejects everything).
  if [ $rc -ne 0 ] && echo "$out" | tail -1 | grep -q 'baseline=FAIL'; then
    echo "MCP-GATE SELF-TEST: PASS (deny-all PDP policy -> corpus FAIL with baseline=FAIL)"; exit 0
  fi
  echo "MCP-GATE SELF-TEST: FAIL (deny-all PDP policy did not turn the corpus red)"; exit 1
fi
kill -0 "$apid" 2>/dev/null || { echo "MCP-GATE: aegis agent died during the run"; tail -20 "$work/agent.log"; exit 1; }
exit $rc
