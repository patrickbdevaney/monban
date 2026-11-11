#!/usr/bin/env bash
# Start, stop and reach the dedicated Monban GCP VM aegis-quiet (PLAN-6 D7, PREFLIGHT D-P5), from the laptop.
#
#   ci/release/vm.sh start      start the VM (idempotent), wait for RUNNING and for ssh; prints `VM: ... RUNNING <ip>`
#   ci/release/vm.sh stop       stop the VM and wait until `gcloud compute instances describe` says TERMINATED;
#                               prints `VM: aegis-quiet TERMINATED (...)`, exit 1 if it never gets there
#   ci/release/vm.sh status     prints the describe status (RUNNING, TERMINATED, ...)
#   ci/release/vm.sh ssh <cmd>  runs <cmd> on the VM (ssh options below)
#   ci/release/vm.sh scp-opts   prints the ssh options, one per line (for rsync -e / scp)
#
# The VM has no reserved address, so its external IP changes on every start. The ssh alias `quiet` (user, key) is
# used with the current IP as HostName. The host key is not trusted on first use: it is pinned to the keys already in
# ~/.ssh/known_hosts for the alias's configured HostName (read only), copied into a private known_hosts under
# target/release-rebuild/vm/ with HostKeyAlias aegis-quiet and StrictHostKeyChecking=yes. A VM whose host key changed
# is refused.
# Cost: the VM (c2-standard-8) is billed per second only while RUNNING; ci/release/rebuild.sh starts it and always
# stops it (EXIT trap) and checks TERMINATED.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VM="${AEGIS_VM_NAME:-aegis-quiet}" ZONE="${AEGIS_VM_ZONE:-us-central1-a}" ALIAS="${AEGIS_VM_ALIAS:-quiet}"
STATE="$ROOT/target/release-rebuild/vm"
KH="$STATE/known_hosts"
die() { echo "vm.sh: $*" >&2; exit 1; }
gc() {  # gcloud without the snap deprecation banner; real errors still reach stderr
  local err rc=0 out
  err=$(mktemp); out=$(gcloud "$@" 2> "$err") || rc=$?
  grep -v -e '=====' -e "superseded by 'google-cloud-cli'" -e 'migration instructions' -e '^\s*$' "$err" >&2 || true
  rm -f "$err"; printf '%s' "$out"; return $rc
}
status() { gc compute instances describe "$VM" --zone "$ZONE" --format='value(status)'; }
ip() { gc compute instances describe "$VM" --zone "$ZONE" --format='value(networkInterfaces[0].accessConfigs[0].natIP)'; }
pin_hostkey() {
  mkdir -p "$STATE"; chmod 700 "$STATE"
  local cfg_host keys
  cfg_host=$(ssh -G "$ALIAS" 2> /dev/null | awk '$1 == "hostname" { print $2 }')
  keys=$(ssh-keygen -F "$cfg_host" 2> /dev/null | grep -v '^#' | awk '{ print $2, $3 }' || true)
  if [ -z "$keys" ] && [ -s "$KH" ]; then return 0; fi  # pinned earlier
  [ -n "$keys" ] || die "no known host key for $ALIAS ($cfg_host) in ~/.ssh/known_hosts; refusing to trust on first use"
  printf '%s\n' "$keys" | sed 's/^/aegis-quiet /' > "$KH"
}
SSHOPTS=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=8
  -o HostKeyAlias=aegis-quiet -o UserKnownHostsFile="$KH" -o GlobalKnownHostsFile=/dev/null
  -o StrictHostKeyChecking=yes -o LogLevel=ERROR)
cur_ip() { [ -s "$STATE/ip" ] || die "VM address unknown: run ci/release/vm.sh start"; cat "$STATE/ip"; }

case "${1:-}" in
  start)
    # Real-money tripwire (operator 2026-11-06): no VM start once spend net of the credit is above zero.
    python3 -I "$ROOT/ci/release/spend-guard.py" check || die "spend guard tripped or unreadable; not starting $VM"
    pin_hostkey
    s=$(status)
    if [ "$s" != RUNNING ]; then
      [ "$s" = TERMINATED ] || [ "$s" = STOPPING ] || die "VM $VM is $s; refusing to start it"
      [ "$s" = STOPPING ] && for _ in $(seq 60); do [ "$(status)" = TERMINATED ] && break; sleep 5; done
      gc compute instances start "$VM" --zone "$ZONE" --quiet > /dev/null
    fi
    for _ in $(seq 60); do [ "$(status)" = RUNNING ] && break; sleep 5; done
    [ "$(status)" = RUNNING ] || die "VM $VM did not reach RUNNING"
    a=$(ip); [[ "$a" =~ ^[0-9.]+$ ]] || die "VM $VM has no external IP"
    printf '%s\n' "$a" > "$STATE/ip"
    for _ in $(seq 40); do
      ssh "${SSHOPTS[@]}" -o HostName="$a" "$ALIAS" true 2> /dev/null && { echo "VM: $VM RUNNING $a"; exit 0; }
      sleep 5
    done
    die "VM $VM is RUNNING at $a but ssh does not answer (or its host key changed)"
    ;;
  stop)
    s=$(status) || die "gcloud describe failed"
    if [ "$s" != TERMINATED ]; then
      gc compute instances stop "$VM" --zone "$ZONE" --quiet > /dev/null || true
      for _ in $(seq 60); do s=$(status) || true; [ "$s" = TERMINATED ] && break; sleep 5; done
    fi
    rm -f "$STATE/ip"
    [ "$s" = TERMINATED ] || { echo "VM: $VM NOT STOPPED (status $s)"; exit 1; }
    echo "VM: $VM TERMINATED (gcloud compute instances describe $VM --zone $ZONE: status=$s)"
    ;;
  status) status; echo ;;
  ssh)
    shift; a=$(cur_ip)
    exec ssh "${SSHOPTS[@]}" -o HostName="$a" "$ALIAS" "$@"
    ;;
  scp-opts) a=$(cur_ip); printf '%s\n' "${SSHOPTS[@]}" -o HostName="$a" ;;
  *) echo "usage: ci/release/vm.sh start|stop|status|ssh <cmd...>|scp-opts" >&2; exit 2 ;;
esac
