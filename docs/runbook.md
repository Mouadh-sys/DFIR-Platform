# DFIR Platform Runbook

## Evidence Ingestion

### Standard ingest (without --immutable)
```bash
python3 tools/ingest.py --root /mnt/dfir-evidence --case C01 --type PCAP \
  /mnt/dfir-evidence/evidence/incoming/<run-id>/lab.pcap
```

### Immutable ingest (after tool validation)
```bash
python3 tools/ingest.py --root /mnt/dfir-evidence --case C01 --type MEM \
  --immutable /mnt/dfir-evidence/evidence/incoming/<run-id>/memory.lime
```

### Verify after ingest
```bash
python3 tools/verify.py --root /mnt/dfir-evidence
```

---

## If ingest partially fails

**Symptom**: `chattr +i` succeeded but manifest/custody write failed. The original file is now immutable with no custody record.

**Recovery**:
1. `sudo chattr -i /mnt/dfir-evidence/evidence/originals/C01/<evidence-id>/<filename>`
2. Investigate the failure (disk full, permission, etc.)
3. Re-run `ingest.py` (it will re-hash and register; the source file is still in `evidence/incoming/`)

**Prevention**: Run first ingest without `--immutable` to validate the full pipeline works on your filesystem.