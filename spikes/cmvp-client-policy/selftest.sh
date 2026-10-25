#!/usr/bin/env bash
# Light: run probes and the gate on every binary + mutants; compare to expected verdicts. Needs ./build.sh output.
# Usage (from this dir): ./selftest.sh   -> results/selftest.txt, results/gate-*.json, results/probe-*.json
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd); o="$here/out"; r="$here/results"; mkdir -p "$r"
for x in pq_client bad_client bad_resume; do "$o/$x" --probe > "$r/probe-$x.json"; done
G() { python3 -I "$here/fips_client_policy.py" --manifest "$here/tlsbins" --src "$here/tlsbins/src" "$@"; }
fails=0
check() { # name expected-verdict expected-mode args...
  local n=$1 ev=$2 em=$3; shift 3
  G "$@" > "$r/gate-$n.json"; local code=$?
  local v m; v=$(python3 -c "import json;print(json.load(open('$r/gate-$n.json'))['verdict'])")
  m=$(python3 -c "import json;print(json.load(open('$r/gate-$n.json')).get('mode','-'))")
  local ok=ok; { [ "$v" = "$ev" ] && [ "$m" = "$em" ]; } || { ok=MISMATCH; fails=$((fails+1)); }
  printf '%-28s expect %-5s %-13s got %-5s %-13s exit %s  %s\n' "$n" "$ev" "$em" "$v" "$m" "$code" "$ok"
}
{
check srv_only            PASS compiled-out --features "" --bin "$o/srv_only" --map "$o/srv_only.stripped.map" --clippy-log "$o/clippy-srv_only.log"
check pq_client           PASS pq-only      --features tls-client --bin "$o/pq_client" --map "$o/pq_client.stripped.map" --clippy-log "$o/clippy-pq_client.log" --probe "$r/probe-pq_client.json"
check bad_client          FAIL -            --features tls-client --bin "$o/bad_client" --map "$o/bad_client.map" --clippy-log "$o/clippy-bad_client.log" --probe "$r/probe-bad_client.json"
check bad_resume          FAIL -            --features tls-client --bin "$o/bad_resume" --map "$o/bad_resume.map" --clippy-log "$o/clippy-bad_resume.log" --probe "$r/probe-bad_resume.json"
check dead_client         FAIL -            --features tls-client --bin "$o/dead_client" --map "$o/dead_client.map" --clippy-log "$o/clippy-dead_client.log"
# Mutants of the passing inputs
check mut_srv_feature_on  FAIL -            --features tls-client --bin "$o/srv_only" --map "$o/srv_only.stripped.map" --clippy-log "$o/clippy-srv_only.log"
check mut_srv_stripped    ERROR -           --features "" --bin "$o/srv_only.stripped"
check mut_srv_client_bin  FAIL -            --features "" --bin "$o/bad_client" --clippy-log "$o/clippy-srv_only.log"
check mut_pq_no_probe     FAIL -            --features tls-client --bin "$o/pq_client" --clippy-log "$o/clippy-pq_client.log"
check mut_pq_bad_probe    FAIL -            --features tls-client --bin "$o/pq_client" --clippy-log "$o/clippy-pq_client.log" --probe "$r/probe-bad_resume.json"
check mut_pq_clippy_dirty FAIL -            --features tls-client --bin "$o/pq_client" --clippy-log "$o/clippy-bad_client.log" --probe "$r/probe-pq_client.json"
rm -rf "$r/mut-src"; cp -r "$here/tlsbins/src" "$r/mut-src"
sed -i 's|^fn main|#[allow(clippy::disallowed_methods)]\nfn main|' "$r/mut-src/bin/bad_client.rs"
n=mut_pq_second_suppression; G --features tls-client --bin "$o/pq_client" --clippy-log "$o/clippy-pq_client.log" --probe "$r/probe-pq_client.json" --src "$r/mut-src" > "$r/gate-$n.json"
v=$(python3 -c "import json;print(json.load(open('$r/gate-$n.json'))['verdict'])"); [ "$v" = FAIL ] && ok=ok || { ok=MISMATCH; fails=$((fails+1)); }
printf '%-28s expect %-5s %-13s got %-5s %-13s %s\n' "$n" FAIL - "$v" - "$ok"; rm -rf "$r/mut-src"
echo "self-test mismatches: $fails"
} | tee "$r/selftest.txt"
exit $fails
