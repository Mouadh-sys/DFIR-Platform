#!/usr/bin/env python3
"""Register one acquired file as an original, recording hashes and custody events."""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
TYPE_RE = re.compile(r"^[A-Z0-9]{2,12}$")
EVIDENCE_ID_RE = re.compile(r"^(?P<case>[A-Z0-9]+)-E(?P<num>\d{3})-(?P<type>[A-Z0-9]{2,12})$")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def canonical_json(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def hashes(path: Path) -> tuple[str, str, int]:
    sha = hashlib.sha256()
    md5 = hashlib.md5()  # nosec - MD5 retained only for compatibility with legacy forensic tooling
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(4 * 1024 * 1024):
            size += len(chunk)
            sha.update(chunk)
            md5.update(chunk)
    return sha.hexdigest(), md5.hexdigest(), size


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    result: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_no}: {exc}") from exc
            if not isinstance(item, dict):
                raise ValueError(f"Expected JSON object at {path}:{line_no}")
            result.append(item)
    return result


def verify_custody_chain(path: Path) -> tuple[bool, str, str]:
    """Return (valid, last_hash, message). Empty chain is valid with empty last hash."""
    try:
        entries = read_jsonl(path)
    except ValueError as exc:
        return False, "", str(exc)
    previous = ""
    for index, record in enumerate(entries, start=1):
        supplied_hash = record.get("entry_hash")
        supplied_prev = record.get("prev_entry_hash", "")
        if supplied_prev != previous:
            return False, previous, f"Chain link mismatch at entry {index}"
        body = {key: value for key, value in record.items() if key != "entry_hash"}
        computed = hashlib.sha256(canonical_json(body)).hexdigest()
        if not isinstance(supplied_hash, str) or supplied_hash != computed:
            return False, previous, f"Entry hash mismatch at entry {index}"
        previous = supplied_hash
    return True, previous, f"Chain valid ({len(entries)} entries)"


def append_custody(path: Path, *, evidence_id: str, action: str, sha256: str,
                   md5: str, note: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    ok, previous, message = verify_custody_chain(path)
    if not ok:
        raise RuntimeError(f"Refusing to append: existing custody chain is invalid: {message}")
    body: dict[str, Any] = {
        "timestamp_utc": utc_now(),
        "evidence_id": evidence_id,
        "action": action,
        "actor": getpass.getuser(),
        "host": socket.gethostname(),
        "tool": f"dfir-ingest/{TOOL_VERSION}",
        "sha256": sha256,
        "md5": md5,
        "note": note,
        "prev_entry_hash": previous,
    }
    entry_hash = hashlib.sha256(canonical_json(body)).hexdigest()
    record = dict(body, entry_hash=entry_hash)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return entry_hash


def next_evidence_id(originals_case_dir: Path, case: str, evidence_type: str) -> str:
    max_number = 0
    if originals_case_dir.exists():
        for item in originals_case_dir.iterdir():
            if not item.is_dir():
                continue
            match = EVIDENCE_ID_RE.match(item.name)
            if match and match.group("case") == case:
                max_number = max(max_number, int(match.group("num")))
    return f"{case}-E{max_number + 1:03d}-{evidence_type}"


def immutable_flag(path: Path) -> None:
    if shutil.which("chattr") is None:
        raise RuntimeError("--immutable requested, but chattr is not installed")
    completed = subprocess.run(["chattr", "+i", str(path)], capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"chattr +i failed: {(completed.stderr or completed.stdout).strip()}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Acquired file inside evidence/incoming")
    parser.add_argument("--root", type=Path, required=True, help="Evidence root, e.g. /mnt/dfir-evidence")
    parser.add_argument("--case", required=True, help="Case ID such as C01")
    parser.add_argument("--type", dest="evidence_type", required=True, help="Short type code such as PCAP, MEM, TRIAGE, LOG")
    parser.add_argument("--note", default="Registered from evidence/incoming", help="Custody note")
    parser.add_argument("--immutable", action="store_true", help="Set Linux immutable flag (requires supported filesystem and privilege)")
    args = parser.parse_args()

    case = args.case.upper()
    evidence_type = args.evidence_type.upper()
    if not re.fullmatch(r"[A-Z0-9]{2,12}", case):
        parser.error("--case must contain only letters/numbers and be 2-12 characters")
    if not TYPE_RE.fullmatch(evidence_type):
        parser.error("--type must contain only letters/numbers and be 2-12 characters")

    root = args.root.expanduser().resolve()
    incoming = (root / "evidence" / "incoming").resolve()
    source = args.source.expanduser().resolve()
    if not source.is_file():
        parser.error(f"source is not a file: {source}")
    if not source.is_relative_to(incoming):
        parser.error(f"source must be under {incoming}; refusing to ingest arbitrary paths")
    if source.name in {".", ".."}:
        parser.error("invalid source filename")

    originals_case = root / "evidence" / "originals" / case
    evidence_id = next_evidence_id(originals_case, case, evidence_type)
    destination_dir = originals_case / evidence_id
    destination = destination_dir / source.name
    manifest = root / "case" / "manifest.jsonl"
    custody = root / "case" / "custody.jsonl"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    destination_dir.mkdir(parents=True, exist_ok=False)

    source_sha, source_md5, source_size = hashes(source)
    try:
        shutil.move(str(source), str(destination))
        os.chmod(destination, 0o444)
        dest_sha, dest_md5, dest_size = hashes(destination)
        if (source_sha, source_md5, source_size) != (dest_sha, dest_md5, dest_size):
            raise RuntimeError("Hash/size mismatch after moving file; preserve both paths and investigate")
        if args.immutable:
            immutable_flag(destination)

        relative_path = destination.relative_to(root).as_posix()
        manifest_record = {
            "evidence_id": evidence_id,
            "case_id": case,
            "relative_path": relative_path,
            "original_filename": destination.name,
            "registered_utc": utc_now(),
            "sha256": dest_sha,
            "md5": dest_md5,
            "size_bytes": dest_size,
            "tool": f"dfir-ingest/{TOOL_VERSION}",
        }
        with manifest.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(manifest_record, sort_keys=True, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

        append_custody(custody, evidence_id=evidence_id, action="registered", sha256=dest_sha,
                       md5=dest_md5, note=args.note)
        append_custody(custody, evidence_id=evidence_id, action="frozen", sha256=dest_sha,
                       md5=dest_md5, note="Original moved to originals/ and chmod 0444" + ("; chattr +i set" if args.immutable else ""))
    except Exception as exc:  # leave the acquired bytes in place for recovery; never silently delete them
        print(f"ERROR: ingest incomplete for {evidence_id}: {exc}", file=sys.stderr)
        print(f"Inspect source/destination and manifests manually: {source} ; {destination}", file=sys.stderr)
        return 2

    print(f"Evidence ID: {evidence_id}")
    print(f"Original:    {destination}")
    print(f"SHA-256:     {dest_sha}")
    print(f"MD5:         {dest_md5}")
    print(f"Size:        {dest_size} bytes")
    print(f"Manifest:    {manifest}")
    print(f"Custody:     {custody}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
