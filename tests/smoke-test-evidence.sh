#!/usr/bin/env bash
set -euo pipefail
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/evidence/incoming/C01-run" "$ROOT/evidence/originals" "$ROOT/case"
printf 'DFIR_LAB_CANARY_C01\n' > "$ROOT/evidence/incoming/C01-run/canary.txt"
python3 "$(dirname "$0")/../tools/ingest.py" --root "$ROOT" --case C01 --type TEST "$ROOT/evidence/incoming/C01-run/canary.txt"
python3 "$(dirname "$0")/../tools/verify.py" --root "$ROOT"
# Prove the verifier catches a changed ORIGINAL, using only this disposable test fixture.
ORIGINAL="$(find "$ROOT/evidence/originals" -type f -name canary.txt -print -quit)"
chmod u+w "$ORIGINAL"
printf 'tampered\n' >> "$ORIGINAL"
if python3 "$(dirname "$0")/../tools/verify.py" --root "$ROOT"; then
  echo 'ERROR: verifier failed to catch changed test original' >&2
  exit 1
fi
echo 'PASS smoke test: clean original accepted; changed test original detected'
