#!/usr/bin/env bash
set -euo pipefail
RUN_ID="${1:?usage: $0 <run-id>}"
DEST="/mnt/dfir-evidence/evidence/incoming/${RUN_ID}/guest-logs"
mkdir -p "$DEST"

# tar may exit 1 on benign warnings (file-changed); ignore the exit but verify size.
ssh srv-web-01@10.10.10.30 'sudo /usr/local/sbin/dfir-collect-logs' \
  > "${DEST}/guest-logs.tar.gz" || true

size=$(stat -c%s "${DEST}/guest-logs.tar.gz")
if [ "$size" -lt 4096 ]; then
  echo "ERROR: tarball is suspiciously small (${size} bytes); collection failed" >&2
  exit 1
fi
sha256sum "${DEST}/guest-logs.tar.gz"
echo "OK: ${size} bytes"
