#!/usr/bin/env python3
"""
Chain of Custody and Evidence Integrity Tool
Handles evidence ingestion, SHA-256 / MD5 hashing, immutable storage,
and cryptographically hash-chained custody logging.
"""

import argparse
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

GENESIS_HASH = "0" * 64

def compute_hashes(file_path: Path) -> tuple[str, str, int]:
    """Compute SHA-256 and MD5 hashes in streaming 64KiB chunks."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    total_bytes = 0

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
            md5.update(chunk)
            total_bytes += len(chunk)

    return sha256.hexdigest(), md5.hexdigest(), total_bytes

def get_last_custody_hash(custody_log_path: Path) -> str:
    """Return the entry_hash of the last record in custody.jsonl, or genesis hash if empty."""
    if not custody_log_path.exists() or custody_log_path.stat().st_size == 0:
        return GENESIS_HASH

    last_line = ""
    with open(custody_log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                last_line = line

    if not last_line:
        return GENESIS_HASH

    try:
        record = json.loads(last_line)
        return record.get("entry_hash", GENESIS_HASH)
    except json.JSONDecodeError:
        return GENESIS_HASH

def get_next_evidence_index(originals_case_dir: Path) -> int:
    """Scan existing evidence IDs to find the next available sequential number."""
    if not originals_case_dir.exists():
        return 1

    max_idx = 0
    for entry in originals_case_dir.iterdir():
        if entry.is_dir() and "-E" in entry.name:
            parts = entry.name.split("-")
            for part in parts:
                if part.startswith("E") and part[1:].isdigit():
                    max_idx = max(max_idx, int(part[1:]))
    return max_idx + 1

def ingest_evidence(
    source_file: Path,
    evidence_type: str,
    case_id: str,
    base_evidence_dir: Path,
    operator: str,
    notes: str,
) -> str:
    """Ingest a file into immutable evidence storage and update custody.jsonl."""
    if not source_file.exists() or not source_file.is_file():
        raise FileNotFoundError(f"Source file does not exist: {source_file}")

    case_dir = base_evidence_dir / "originals" / case_id
    case_dir.mkdir(parents=True, exist_ok=True)

    next_idx = get_next_evidence_index(case_dir)
    evidence_id = f"{case_id}-E{next_idx:03d}-{evidence_type.lower()}"
    target_dir = case_dir / evidence_id
    target_dir.mkdir(parents=True, exist_ok=False)

    dest_file = target_dir / source_file.name

    print(f"[*] Hashing original: {source_file} ...")
    sha256_hash, md5_hash, size_bytes = compute_hashes(source_file)
    print(f"    SHA-256 : {sha256_hash}")
    print(f"    MD5     : {md5_hash}")
    print(f"    Size    : {size_bytes} bytes")

    print(f"[*] Moving evidence to: {dest_file}")
    shutil.move(str(source_file), str(dest_file))

    # Set file read-only
    os.chmod(dest_file, 0o444)
    # Attempt chattr +i (requires root or CAP_LINUX_IMMUTABLE)
    try:
        subprocess.run(["chattr", "+i", str(dest_file)], check=True, stderr=subprocess.DEVNULL)
        print("    [+] Immutable flag (+i) set successfully.")
    except Exception:
        print("    [!] Notice: chattr +i skipped (run with sudo or chattr +i manually for hardware-level immutability).")

    # Hash chain custody log entry
    custody_file = base_evidence_dir / "custody.jsonl"
    prev_hash = get_last_custody_hash(custody_file)

    record = {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "action": "INGEST",
        "case_id": case_id,
        "evidence_id": evidence_id,
        "evidence_type": evidence_type,
        "filename": dest_file.name,
        "stored_path": str(dest_file.relative_to(base_evidence_dir.parent)),
        "size_bytes": size_bytes,
        "sha256": sha256_hash,
        "md5": md5_hash,
        "operator": operator,
        "notes": notes,
        "prev_entry_hash": prev_hash,
    }

    # Canonical entry serialization for deterministic entry_hash
    canonical_bytes = json.dumps(record, sort_keys=True).encode("utf-8")
    record["entry_hash"] = hashlib.sha256(canonical_bytes).hexdigest()

    with open(custody_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    print(f"[✓] Evidence registered: {evidence_id}")
    print(f"    Chain Hash: {record['entry_hash'][:16]}... (linked to prev: {prev_hash[:16]}...)")
    return evidence_id

def verify_custody(base_evidence_dir: Path) -> bool:
    """Verify chain-of-custody hash chain and re-check all stored files against SHA-256 & MD5."""
    custody_file = base_evidence_dir / "custody.jsonl"
    if not custody_file.exists():
        print(f"[!] No custody log found at {custody_file}")
        return False

    all_passed = True
    prev_hash = GENESIS_HASH
    line_num = 0

    print("================================================================================")
    print("                 CHAIN OF CUSTODY INTEGRITY VERIFICATION                        ")
    print("================================================================================")
    print(f"Custody Log: {custody_file}\n")

    with open(custody_file, "r", encoding="utf-8") as f:
        for raw_line in f:
            line_num += 1
            raw_line = raw_line.strip()
            if not raw_line:
                continue

            try:
                record = json.loads(raw_line)
            except json.JSONDecodeError as e:
                print(f"[FAIL] Line {line_num}: Invalid JSON format: {e}")
                all_passed = False
                continue

            stored_entry_hash = record.get("entry_hash")
            stored_prev_hash = record.get("prev_entry_hash")

            # 1. Verify previous hash chain linkage
            if stored_prev_hash != prev_hash:
                print(f"[FAIL] Line {line_num} ({record.get('evidence_id')}): Hash chain broken!")
                print(f"       Expected prev: {prev_hash}")
                print(f"       Found prev:    {stored_prev_hash}")
                all_passed = False

            # 2. Verify record signature
            record_copy = dict(record)
            record_copy.pop("entry_hash", None)
            expected_entry_hash = hashlib.sha256(
                json.dumps(record_copy, sort_keys=True).encode("utf-8")
            ).hexdigest()

            if stored_entry_hash != expected_entry_hash:
                print(f"[FAIL] Line {line_num} ({record.get('evidence_id')}): Tampered log entry payload!")
                all_passed = False

            prev_hash = stored_entry_hash

            # 3. Verify file on disk if INGEST action
            if record.get("action") == "INGEST":
                stored_path_rel = record.get("stored_path")
                full_path = base_evidence_dir.parent / stored_path_rel
                ev_id = record.get("evidence_id", "UNKNOWN")

                if not full_path.exists():
                    print(f"[FAIL] {ev_id}: Missing evidence file on disk: {full_path}")
                    all_passed = False
                    continue

                actual_sha256, actual_md5, actual_size = compute_hashes(full_path)
                expected_sha256 = record.get("sha256")
                expected_md5 = record.get("md5")

                if actual_sha256 == expected_sha256 and actual_md5 == expected_md5:
                    print(f"[PASS] {ev_id:<18} | Size: {actual_size:>10} B | SHA-256: {actual_sha256[:16]}... [VERIFIED]")
                else:
                    print(f"[FAIL] {ev_id:<18} | HASH MISMATCH!")
                    print(f"       Expected SHA-256: {expected_sha256}")
                    print(f"       Actual   SHA-256: {actual_sha256}")
                    print(f"       Expected MD5:    {expected_md5}")
                    print(f"       Actual   MD5:    {actual_md5}")
                    all_passed = False

    print("\n--------------------------------------------------------------------------------")
    if all_passed:
        print("[✓] ALL EVIDENCE INTEGRITY CHECKS PASSED. CHAIN OF CUSTODY INTACT.")
    else:
        print("[✗] INTEGRITY COMPROMISED. TAMPERING OR CORRUPTION DETECTED.")
    print("================================================================================")
    return all_passed

def main():
    parser = argparse.ArgumentParser(description="Chain of Custody and Evidence Integrity Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Ingest parser
    ingest_p = subparsers.add_parser("ingest", help="Ingest and hash evidence file")
    ingest_p.add_argument("file", type=Path, help="Path to evidence file to ingest")
    ingest_p.add_argument("--type", required=True, help="Evidence type: mem, disk, pcap, triage, log")
    ingest_p.add_argument("--case", default="C01", help="Case identifier (default: C01)")
    ingest_p.add_argument("--evidence-dir", type=Path, default=Path(__file__).resolve().parent.parent / "evidence",
                          help="Path to evidence directory")
    ingest_p.add_argument("--operator", default=os.getenv("USER", "analyst"), help="Analyst name")
    ingest_p.add_argument("--notes", default="Acquired during lab incident run", help="Acquisition notes")

    # Verify parser
    verify_p = subparsers.add_parser("verify", help="Verify hash chain and evidence integrity")
    verify_p.add_argument("--evidence-dir", type=Path, default=Path(__file__).resolve().parent.parent / "evidence",
                          help="Path to evidence directory")

    args = parser.parse_args()

    if args.command == "ingest":
        ingest_evidence(
            source_file=args.file,
            evidence_type=args.type,
            case_id=args.case,
            base_evidence_dir=args.evidence_dir,
            operator=args.operator,
            notes=args.notes,
        )
    elif args.command == "verify":
        success = verify_custody(base_evidence_dir=args.evidence_dir)
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
