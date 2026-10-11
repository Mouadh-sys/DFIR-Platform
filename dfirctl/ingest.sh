#!/usr/bin/env bash
# dfirctl/ingest.sh - Ingest an evidence file into immutable custody storage
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
EVIDENCE_DIR="${DFIR_EVIDENCE_PATH:-${REPO_DIR}/evidence}"

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <path_to_evidence_file> <type: mem|disk|pcap|triage|log> [case_id: default C01] [notes]"
  echo "Example: $0 /tmp/WS-FIN-01-mem.raw mem C01 'Acquired via hypervisor dump'"
  exit 1
fi

FILE_PATH="$1"
EV_TYPE="$2"
CASE_ID="${3:-C01}"
NOTES="${4:-Acquired during incident phase 1}"

python3 "${SCRIPT_DIR}/custody.py" ingest "$FILE_PATH" \
  --type "$EV_TYPE" \
  --case "$CASE_ID" \
  --evidence-dir "$EVIDENCE_DIR" \
  --notes "$NOTES"
