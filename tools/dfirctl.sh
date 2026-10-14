#!/usr/bin/env bash
# dfirctl.sh — single-entry driver for the C01 Linux web-server compromise emulation.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVID=/mnt/dfir-evidence
CASE="${CASE:-C01}"
SNAP="${SNAP:-snapshot3}"
VM="${VM:-SRV-WEB-01}"
GUEST="srv-web-01@10.10.10.30"
HEALTH_PORT=8888
GT="${EVID}/case/ground-truth-sealed.jsonl"
LOG="${EVID}/logs/dfirctl-$(date -u +%Y%m%dT%H%M%SZ).log"
GTAPPEND="${REPO}/tools/gt-append.sh"

mkdir -p "${EVID}/logs"
exec > >(tee -a "$LOG") 2>&1
echo "[dfirctl] log: $LOG"

die()  { echo "[dfirctl] FATAL: $*" >&2; exit 1; }
info() { echo "[dfirctl] $*"; }

require_guest_clean() {
  info "preflight: checking guest ${GUEST}"
  local route rules
  route=$(ssh -o BatchMode=yes "$GUEST" 'ip route') || die "cannot ssh guest"
  echo "$route" | grep -q '^10\.10\.10\.0/24 ' || die "guest has no 10.10.10.0/24 route"
  echo "$route" | grep -q 'default' && die "guest has a default route — isolation broken"
  rules=$(ssh -o BatchMode=yes "$GUEST" 'sudo -n auditctl -l 2>/dev/null | wc -l') || rules=0
  [ "$rules" = "6" ] || info "WARN: auditctl count=$rules (expected 6)"
  ssh -o BatchMode=yes "$GUEST" 'sudo -n /usr/local/sbin/dfir-collect-logs | wc -c' >/dev/null \
    || die "guest collector failed"
  info "preflight: guest OK"
}

cmd_preflight() {
  info "preflight: checking host"
  virsh net-list --all | grep -q 'lab-isolated.*active' || die "lab-isolated network not active"
  virsh snapshot-list "$VM" | grep -q "$SNAP" || die "snapshot $SNAP missing on $VM"
  command -v tcpdump >/dev/null || die "tcpdump missing"
  command -v jq      >/dev/null || die "jq missing"
  command -v zeek    >/dev/null || info "WARN: zeek missing"
  require_guest_clean
  info "preflight: host OK"
}

run_step() {
  local id="$1" label="$2" attack="$3" status="$4" cmd="$5" notes="$6"
  local s e
  s=$(date -u +%FT%TZ); info "[$id] start $s"
  bash -c "$cmd" >&2 || die "$id command failed"
  e=$(date -u +%FT%TZ); info "[$id] end $e"
  "$GTAPPEND" "$id" "$label" "$attack" "$status" "$s" "$e" "$notes"
}

step_s08() {
  local s e
  s=$(date -u +%FT%TZ); info "[S08] start $s"
  ssh "$GUEST" bash -s >&2 <<'S08_EOF'
LOG=/tmp/dfir-lab-cron.log
if ! rm -f "$LOG" 2>/dev/null; then LOG=/tmp/dfir-lab-cron-$(date -u +%s).log; fi
( crontab -l 2>/dev/null; echo "* * * * * echo DFIR-LAB-S08 \$(date -u +\%FT\%TZ) >> $LOG" ) | crontab -
sleep 70
cat "$LOG"
crontab -r
S08_EOF
  e=$(date -u +%FT%TZ); info "[S08] end $e"
  "$GTAPPEND" S08 "temporary cron persistence" "T1053.003" "executed_with_cleanup" \
    "$s" "$e" "cron added, fired, removed"
}

cmd_run() {
  local run
  run="C01-$(date -u +%Y%m%dT%H%M%SZ)"
  echo "$run" | tee "${EVID}/case/current-run-id.txt" >/dev/null
  mkdir -p "${EVID}/evidence/incoming/$run"
  info "run id: $run"

  [ -f "$GT" ] && chmod 600 "$GT" 2>/dev/null || true
  : > "$GT"; chmod 600 "$GT"

  info "starting health server"
  python3 "$REPO/tools/lab_health_server.py" \
    --bind 10.10.10.1 --port "$HEALTH_PORT" \
    --log "${EVID}/logs/lab-health.log" &
  local health_pid=$!
  sleep 2

  info "starting tcpdump"
  sudo tcpdump -i virbr-lab -nn -s 0 -Z "$(id -u -n)" \
    -w "${EVID}/evidence/incoming/$run/lab.pcap" \
    'net 10.10.10.0/24' &
  local tcpdump_pid=$!
  sleep 2

  trap 'kill '"$health_pid"' '"$tcpdump_pid"' 2>/dev/null || true' EXIT

  run_step S01 "inbound web activity marker" "T1190" "emulated_marker_only" \
    "curl -sS -o /dev/null -w 'HTTP %{http_code}\n' http://10.10.10.30/" \
    "host GET to guest nginx"

  run_step S02 "benign shell execution marker" "T1059.004" "executed_benign_behavior" \
    "ssh $GUEST 'echo \"DFIR-LAB-S02 \$(date -u +%FT%TZ) \$(uname -a) \$(hostname)\" | sudo tee -a /tmp/dfir-lab-s02.log >/dev/null'" \
    "tee to /tmp/dfir-lab-s02.log"

  run_step S03 "HTTP callback-like traffic" "T1071.001" "emulated_network_behavior" \
    "ssh $GUEST 'for i in 1 2 3 4 5; do curl -sS -o /dev/null \"http://10.10.10.1:8888/health?seq=\$i\"; sleep 2; done'" \
    "5 GETs to health endpoint"

  run_step S04 "system discovery" "T1082" "executed_benign_behavior" \
    "ssh $GUEST 'uname -a >/dev/null; hostname >/dev/null; head -5 /etc/os-release >/dev/null; id >/dev/null; uptime >/dev/null'" \
    "uname/hostname/os-release/id/uptime"

  run_step S05 "account discovery" "T1033,T1087.001" "executed_benign_behavior" \
    "ssh $GUEST 'cut -d: -f1 /etc/passwd >/dev/null; whoami >/dev/null; w >/dev/null; last | head -5 >/dev/null'" \
    "passwd/whoami/w/last"

  run_step S06 "synthetic credential-file access" "T1552.001" "emulated_with_canary" \
    "ssh $GUEST 'sudo -n cat /opt/dfir-demo/markers/credential-canary.txt >/dev/null'" \
    "read canary; no real credential"

  run_step S07 "private-key discovery marker" "T1552.004" "emulated_with_dummy_artifact" \
    "ssh $GUEST 'sudo -n cat /opt/dfir-demo/markers/dummy-key.pem >/dev/null 2>&1 || true'" \
    "read planted dummy key (or skipped)"

  step_s08

  run_step S09 "collection and archive" "T1560.001" "executed_benign_behavior" \
    "ssh $GUEST 'mkdir -p /tmp/dfir-lab-staging && cp /opt/dfir-demo/finance-demo.db /tmp/dfir-lab-staging/ && cd /tmp/dfir-lab-staging && tar czf finance-demo.tar.gz finance-demo.db'" \
    "finance-demo.db copied and tarred"

  run_step S10 "data staging" "T1074.001" "executed_benign_behavior" \
    "ssh $GUEST 'mkdir -p /tmp/dfir-lab-exfil-staging && mv /tmp/dfir-lab-staging/finance-demo.tar.gz /tmp/dfir-lab-exfil-staging/'" \
    "archive moved to exfil staging"

  run_step S11 "exfiltration behavior marker" "T1041" "emulated_marker_only" \
    "ssh $GUEST 'echo \"DFIR-LAB-S11 \$(date -u +%FT%TZ) simulated\" | sudo tee -a /var/log/dfir-lab-markers.log >/dev/null'" \
    "no data left the lab"

  run_step S12 "defense-evasion marker" "T1070.003" "emulated_marker_only" \
    "ssh $GUEST 'echo \"DFIR-LAB-S12 \$(date -u +%FT%TZ) simulated\" | sudo tee -a /var/log/dfir-lab-markers.log >/dev/null'" \
    "marker only; logs not cleared"

  info "stopping tcpdump and health server"
  kill "$tcpdump_pid" 2>/dev/null || true
  kill "$health_pid"  2>/dev/null || true
  sleep 1

  local n
  n=$(wc -l < "$GT")
  [ "$n" -eq 12 ] || die "expected 12 GT lines, got $n"
  grep -q 'REPLACE\|<START>\|<END>' "$GT" && die "placeholder in ground truth"
  sha256sum "$GT" > "${GT}.sha256"
  chmod 400 "$GT"
  info "ground truth sealed: $(cat ${GT}.sha256)"
}

cmd_collect() {
  local run; run=$(cat "${EVID}/case/current-run-id.txt")
  info "collecting guest logs for $run"
  "$REPO/tools/collect-guest-logs.sh" "$run"
  info "shutting down guest"
  ssh "$GUEST" 'sudo -n poweroff' || true
  sleep 10
  virsh list --all | grep "$VM" | grep -q 'shut off' || virsh destroy "$VM" || true
}

cmd_ingest() {
  local run; run=$(cat "${EVID}/case/current-run-id.txt")
  python3 "$REPO/tools/ingest.py" --root "$EVID" --case "$CASE" --type PCAP \
    "${EVID}/evidence/incoming/$run/lab.pcap"
  python3 "$REPO/tools/ingest.py" --root "$EVID" --case "$CASE" --type TRIAGE \
    "${EVID}/evidence/incoming/$run/guest-logs/guest-logs.tar.gz"
}

cmd_process() {
  local pcap tri
  pcap=$(ls "${EVID}"/evidence/originals/"$CASE"/C01-E001-PCAP/*.pcap 2>/dev/null | head -1)
  tri=$(ls  "${EVID}"/evidence/originals/"$CASE"/C01-E002-TRIAGE/*.tar.gz 2>/dev/null | head -1)
  [ -n "$pcap" ] || die "pcap original missing"
  [ -n "$tri" ]  || die "triage original missing"

  local zjob zdir
  zjob="zeek-$(date -u +%Y%m%dT%H%M%SZ)"; zdir="${EVID}/work/$zjob"
  mkdir -p "$zdir"; cp "$pcap" "$zdir/lab.pcap"
  ( cd "$zdir" && mkdir -p zeek-out && cd zeek-out && zeek -C -r ../lab.pcap )
  mkdir -p "${EVID}/results/C01-E001-PCAP/zeek"
  cp "$zdir"/zeek-out/*.log "${EVID}/results/C01-E001-PCAP/zeek/"

  local yjob ydir
  yjob="yara-$(date -u +%Y%m%dT%H%M%SZ)"; ydir="${EVID}/work/$yjob"
  mkdir -p "$ydir"; cp "$tri" "$ydir/"; ( cd "$ydir" && tar xzf guest-logs.tar.gz )
  mkdir -p "${EVID}/results/C01-E002-TRIAGE/yara"
  ( cd "$ydir" && yara -r -s "$REPO/rules/dfir_demo.yar" . ; \
    yara -r -s "$REPO/rules/lab_beacon.yar" . ) \
    > "${EVID}/results/C01-E002-TRIAGE/yara/matches.txt" 2>&1 || true

  local pjob pdir
  pjob="plaso-$(date -u +%Y%m%dT%H%M%SZ)"; pdir="${EVID}/work/$pjob"
  mkdir -p "$pdir/input" "$pdir/output"
  cp "$tri" "$pdir/input/"
  ( cd "$pdir/input" && tar xzf guest-logs.tar.gz && rm -f guest-logs.tar.gz )
  docker run --rm -v "$pdir/input:/input:ro" -v "$pdir/output:/output" \
    log2timeline/plaso:latest log2timeline.py --storage-file /output/timeline.plaso /input
  docker run --rm -v "$pdir/output:/output" \
    log2timeline/plaso:latest psort.py -o json_line -w /output/timeline.jsonl /output/timeline.plaso
  mkdir -p "${EVID}/results/C01-E002-TRIAGE/plaso"
  cp "$pdir/output/timeline.plaso" "$pdir/output/timeline.jsonl" \
     "${EVID}/results/C01-E002-TRIAGE/plaso/"
}

cmd_timeline() { python3 "$REPO/tools/build-timeline.py"; }
cmd_verify()   { python3 "$REPO/tools/verify.py" --root "$EVID"; }

cmd_portal() {
  local py="$HOME/venvs/portal/bin/python3"
  [ -x "$py" ] || die "portal venv missing: python3 -m venv ~/venvs/portal && ~/venvs/portal/bin/pip install jinja2"
  "$py" "$REPO/tools/build-portal.py" --root "$EVID" --case "$CASE"
  info "portal: file://$EVID/results/$CASE/portal/index.html"
}

cmd_report() {
  local md="$REPO/report/02-analysis.md"
  [ -f "$md" ] || die "report source missing: $md"
  pandoc "$md" -o "$REPO/report/C01-report.pdf" \
    --pdf-engine=xelatex --toc --number-sections
  info "report: $REPO/report/C01-report.pdf"
}

cmd_all() {
  cmd_preflight
  cmd_run
  cmd_collect
  cmd_ingest
  cmd_verify
  cmd_process
  cmd_timeline
  cmd_verify
  cmd_portal
}

case "${1:-}" in
  preflight) cmd_preflight ;;
  run)       cmd_run ;;
  collect)   cmd_collect ;;
  ingest)    cmd_ingest ;;
  process)   cmd_process ;;
  timeline)  cmd_timeline ;;
  verify)    cmd_verify ;;
  report)    cmd_report ;;
  portal)    cmd_portal ;;
  all)       cmd_all ;;
  *) sed -n '/^# Subcommands:/,/^# Every/p' "$0"; exit 1 ;;
esac
