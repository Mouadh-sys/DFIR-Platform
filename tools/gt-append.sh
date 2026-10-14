#!/usr/bin/env bash
set -euo pipefail
GT="${GT:-/mnt/dfir-evidence/case/ground-truth-sealed.jsonl}"
if [ $# -ne 7 ]; then
  echo "usage: $0 <step> <label> <attack> <status> <start> <end> <notes>" >&2
  exit 2
fi
for v in "$5" "$6"; do
  case "$v" in
    *"<"*|*">"*|*REPLACE*|*PLACEHOLDER*|"") echo "REFUSED: bad timestamp: $v" >&2; exit 3;;
  esac
  if ! [[ "$v" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
    echo "REFUSED: not ISO8601 UTC: $v" >&2; exit 3
  fi
done
printf '{"step_id":"%s","label":"%s","attack":"%s","status":"%s","start_utc":"%s","end_utc":"%s","exit_code":0,"notes":"%s"}\n' \
  "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$GT"
echo "[gt] appended $1 — total lines: $(wc -l < "$GT")"
