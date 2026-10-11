#!/usr/bin/env bash
# dfirctl/verify.sh - Verify cryptographic integrity and custody hash chain
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
EVIDENCE_DIR="${DFIR_EVIDENCE_PATH:-${REPO_DIR}/evidence}"

python3 "${SCRIPT_DIR}/custody.py" verify --evidence-dir "$EVIDENCE_DIR"
