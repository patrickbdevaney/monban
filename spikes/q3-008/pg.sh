#!/usr/bin/env bash
# Throwaway loopback-only PostgreSQL for q3-008.  usage: pg.sh start <image> <cpuset> [extra -c args...] | pg.sh stop
# Host network + listen_addresses=127.0.0.1 => reachable on loopback only, no docker-proxy/NAT in the path.
set -euo pipefail
D=$(cd "$(dirname "$0")" && pwd); NAME=q3008-pg; PORT=55432
case "$1" in
start)
  IMG=$2; CPUS=$3; shift 3
  docker run -d --name $NAME --network host --cpuset-cpus "$CPUS" \
    -e POSTGRES_PASSWORD=benchpw -v "$D/certs:/certs:ro" -v "$D/certs/init.sql:/docker-entrypoint-initdb.d/init.sql:ro" \
    --entrypoint bash "$IMG" -c "mkdir -p /etc/pgc && cp /certs/server.* /certs/pg_hba.conf /etc/pgc/ && chown -R postgres /etc/pgc && chmod 600 /etc/pgc/server.key && exec docker-entrypoint.sh postgres -c port=$PORT -c listen_addresses=127.0.0.1 -c max_connections=400 -c ssl=on -c ssl_cert_file=/etc/pgc/server.crt -c ssl_key_file=/etc/pgc/server.key -c hba_file=/etc/pgc/pg_hba.conf $*" >/dev/null
  for i in $(seq 60); do docker exec $NAME pg_isready -h 127.0.0.1 -p $PORT -q 2>/dev/null && docker logs $NAME 2>&1 | grep -q "PostgreSQL init process complete" && break; sleep 1; done
  sleep 2; id=$(docker inspect -f '{{.Id}}' $NAME)
  ls /sys/fs/cgroup/system.slice/docker-$id.scope/cpu.stat ;;
stop) docker rm -f $NAME >/dev/null 2>&1 || true ;;
esac
