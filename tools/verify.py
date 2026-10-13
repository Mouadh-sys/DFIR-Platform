#!/usr/bin/env python3
"""Verify registered original evidence hashes and the custody hash chain."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def canonical_json(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def hashes(path: Path) -> tuple[str, str, int]:
    sha = hashlib.sha256()
    md5 = hashlib.md5()  # nosec - MD5 retained only for legacy forensic-tool compatibility
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(4 * 1024 * 1024):
            size += len(chunk)
            sha.update(chunk)
            md5.update(chunk)
    return sha.hexdigest(), md5.hexdigest(), size


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at {path}:{line_no}: {exc}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"Expected JSON object at {path}:{line_no}")
            records.append(record)
    return records


def verify_chain(path: Path) -> tuple[bool, str, str]:
    try:
        entries = read_jsonl(path)
    except ValueError as exc:
        return False, "", str(exc)
    previous = ""
    for index, record in enumerate(entries, start=1):
        if record.get("prev_entry_hash", "") != previous:
            return False, previous, f"Previous hash mismatch at custody record {index}"
        supplied = record.get("entry_hash")
        body = {key: value for key, value in record.items() if key != "entry_hash"}
        computed = hashlib.sha256(canonical_json(body)).hexdigest()
        if not isinstance(supplied, str) or supplied != computed:
            return False, previous, f"Entry hash mismatch at custody record {index}"
        previous = supplied
    return True, previous, f"Custody chain valid ({len(entries)} records)"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="Evidence root, e.g. /mnt/dfir-evidence")
    args = parser.parse_args()
    root = args.root.expanduser().resolve()
    manifest_path = root / "case" / "manifest.jsonl"
    custody_path = root / "case" / "custody.jsonl"
    failures = 0

    try:
        manifest = read_jsonl(manifest_path)
    except ValueError as exc:
        print(f"FAIL manifest: {exc}")
        return 2

    if not manifest:
        print(f"WARN: no manifest records found at {manifest_path}")

    for record in manifest:
        evidence_id = str(record.get("evidence_id", "<missing-id>"))
        relative_path = record.get("relative_path")
        if not isinstance(relative_path, str):
            print(f"FAIL {evidence_id}: missing relative_path")
            failures += 1
            continue
        path = (root / relative_path).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            print(f"FAIL {evidence_id}: original missing or path escapes root: {path}")
            failures += 1
            continue
        try:
            sha, md5, size = hashes(path)
        except OSError as exc:
            print(f"FAIL {evidence_id}: cannot hash: {exc}")
            failures += 1
            continue
        expected = (record.get("sha256"), record.get("md5"), record.get("size_bytes"))
        actual = (sha, md5, size)
        if actual != expected:
            print(f"FAIL {evidence_id}: expected {expected}, got {actual}")
            failures += 1
        else:
            print(f"PASS {evidence_id}: SHA-256 {sha}")

    chain_ok, last_hash, chain_message = verify_chain(custody_path)
    print(("PASS" if chain_ok else "FAIL") + f" custody: {chain_message}")
    if chain_ok:
        print(f"Custody-chain tip (anchor this separately): {last_hash or '(empty)'}")
    else:
        failures += 1

    if failures:
        print(f"VERIFICATION FAILED: {failures} issue(s)")
        return 1
    print(f"VERIFICATION PASSED: {len(manifest)} manifest item(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
