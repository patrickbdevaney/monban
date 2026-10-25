#!/bin/bash
# usage: run.sh <name>   ; server pinned to 1 core (cpuset), mem 512m, host net
set -u
W=/home/patrickd/aegis/research/state/raw/round-002/w02
N=$1; SC=${SC:-5}; LG=${LG:-13,15,6}
OHA=$W/oha-root/bin/oha; T=$W/target/release/tools
docker rm -f srv >/dev/null 2>&1
V="-v $W:/w:ro"
case $N in
 nginx) sed "s/WP/${WP:-1}/" $W/cfg/nginx.conf > $W/cfg/nginx.run.conf; CMD="docker run -d --name srv --cpuset-cpus=$SC --memory=512m --network host $V --entrypoint nginx nginx:stable-alpine-slim -g 'daemon off;' -c /w/cfg/nginx.run.conf";;
 caddy) CMD="docker run -d --name srv --cpuset-cpus=$SC --memory=512m --network host $V caddy:2-alpine caddy run --config /w/cfg/Caddyfile --adapter caddyfile";;
 envoy) CMD="docker run -d --name srv --cpuset-cpus=$SC --memory=512m --network host $V envoyproxy/envoy:distroless-v1.40.1 -c /w/cfg/envoy.yaml --concurrency 1 --disable-hot-restart";;
 haproxy) CMD="docker run -d --name srv --cpuset-cpus=$SC --memory=512m --network host $V haproxy:lts-alpine haproxy -f /w/cfg/haproxy.cfg";;
 hello) CMD="docker run -d --name srv --cpuset-cpus=$SC --memory=512m --network host $V ubuntu:24.04 /w/bins/hello 0.0.0.0:18080 plain 1";;
 hellotls) CMD="docker run -d --name srv --cpuset-cpus=$SC --memory=512m --network host $V ubuntu:24.04 /w/bins/hello 0.0.0.0:18443 tls 1";;
 pingora) CMD="docker run -d --name srv --cpuset-cpus=$SC --memory=512m --network host $V ubuntu:24.04 /w/bins/pgr 1";;
esac
eval $CMD >/dev/null; sleep 4
ID=$(docker inspect -f '{{.Id}}' srv); CG=/sys/fs/cgroup/system.slice/docker-$ID.scope
docker ps --filter name=srv --format '{{.Status}}' ; 
rss(){ docker run --rm --pid=container:srv --cap-add SYS_PTRACE ubuntu:24.04 sh -c 'r=0;p=0;n=0;for f in /proc/[0-9]*/smaps_rollup; do a=$(awk "/^Rss:/{print \$2}" $f 2>/dev/null);b=$(awk "/^Pss:/{print \$2}" $f 2>/dev/null);r=$((r+${a:-0}));p=$((p+${b:-0}));n=$((n+1));done;echo "RSS_kB=$r PSS_kB=$p nproc=$((n-1))"' | tr '\n' ' '; echo "cg_anon_kB=$(awk '/^anon /{print int($2/1024)}' $CG/memory.stat) cg_file_kB=$(awk '/^file /{print int($2/1024)}' $CG/memory.stat) cg_current_kB=$(( $(cat $CG/memory.current)/1024 ))"; }
echo "[$N] idle: $(rss)"
cpu(){ awk '/usage_usec/{print $2}' $CG/cpu.stat; }
PORT=18080; [ $N = hellotls ] && PORT=18443
if [ $N != hellotls ]; then
 taskset -c $LG $T hold 127.0.0.1:$PORT 1000 >/dev/null & HP=$!; sleep 6; echo "[$N] 1k-idle-conns: $(rss)"; kill $HP 2>/dev/null; wait $HP 2>/dev/null; sleep 3
 echo "[$N] after-close: $(rss)"
fi
if [ $N != pingora ] && [ $N != hello ]; then
 PT=18443
 taskset -c $LG $T hold 127.0.0.1:$PT 1000 tls >/dev/null 2>&1 & HP=$!; sleep 8; echo "[$N] 1k-idle-TLS-conns: $(rss)"; kill $HP 2>/dev/null; wait $HP 2>/dev/null; sleep 3
fi
# static throughput plain h1, keepalive, c=64, 10s
if [ $N != hellotls ]; then
 c0=$(cpu); taskset -c $LG $OHA -z 10s -c 64 --no-tui http://127.0.0.1:$PORT/ > $W/out/$N.oha.h1.txt 2>&1; c1=$(cpu)
 req=$(grep -m1 'Requests/sec' $W/out/$N.oha.h1.txt | awk '{print $2}'); ok=$(grep -A3 'Status code' $W/out/$N.oha.h1.txt | head -3 | tr '\n' ' ')
 echo "[$N] h1 plain c64: req/s=$req p99=$(grep '99.00%' $W/out/$N.oha.h1.txt | head -1 | awk '{print $3,$4}') server_cpu_us=$((c1-c0)) $ok"
fi
# tls h2 static
if [ $N != pingora ] && [ $N != hello ]; then
 P2=18443
 c0=$(cpu); taskset -c $LG $OHA -z 10s -c 64 --no-tui --insecure --http2 https://127.0.0.1:$P2/ > $W/out/$N.oha.h2tls.txt 2>&1; c1=$(cpu)
 echo "[$N] h2+tls c64: req/s=$(grep -m1 'Requests/sec' $W/out/$N.oha.h2tls.txt | awk '{print $2}') p99=$(grep '99.00%' $W/out/$N.oha.h2tls.txt | head -1| awk '{print $3,$4}') server_cpu_us=$((c1-c0))"
 for g in x25519 mlkem; do
  c0=$(cpu); out=$(taskset -c $LG $T hs 127.0.0.1:$P2 $g 8 16 2>&1 | head -c 700 | tr '\n' ' '); c1=$(cpu)
  n=$(echo "$out" | sed -E 's/.*handshakes=([0-9]+).*/\1/')
  echo "[$N] hs $g: $out server_cpu_us_per_hs=$(( (c1-c0)*1000/${n:-1} ))e-3"
 done
fi
echo "[$N] final: $(rss)"
docker rm -f srv >/dev/null
