#!/usr/bin/env python3
import csv, json, re
from datetime import datetime, timezone
from pathlib import Path

EVID = Path("/mnt/dfir-evidence")
GT   = EVID/"case/ground-truth-sealed.jsonl"
TL   = EVID/"results/C01/timeline-merged.csv"

# Marker strings to look for in the timeline, per step
MARKERS = {
    "S01": ["GET /"],                       # Zeek http
    "S02": ["dfir-lab-s02"],
    "S03": ["health?seq"],
    "S04": ["uname", "hostname"],
    "S05": ["whoami", "/etc/passwd", "/usr/bin/w"],
    "S06": ["credential-canary"],
    "S07": ["dummy-key"],
    "S08": ["DFIR-LAB-S08", "dfir-lab-cron"],
    "S09": ["finance-demo"],
    "S10": ["dfir-lab-exfil"],
    "S11": ["DFIR-LAB-S11", "dfir-lab-markers"],
    "S12": ["DFIR-LAB-S12"],
}

def parse_ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))

gt = [json.loads(l) for l in GT.read_text().splitlines() if l.strip()]
rows = list(csv.DictReader(TL.open()))

hits = 0
print(f"{'step':<5} {'gt_start':<22} {'closest_evidence':<22} {'delta_s':>8}  found")
print("-" * 75)

for step in gt:
    sid = step["step_id"]
    t0 = parse_ts(step["start_utc"])
    best = None; best_delta = None; best_row = None

    for row in rows:
        rowtext = (row.get("event","") + " " + row.get("detail","")).lower()
        for m in MARKERS.get(sid, []):
            if m.lower() in rowtext:
                # try to parse row utc
                utc = row.get("utc","")
                if utc.startswith("@"):  # zeek epoch
                    continue
                if not utc:
                    # epoch_us in plaso
                    try:
                        epoch = int(row.get("epoch_us","")) / 1_000_000
                        t = datetime.fromtimestamp(epoch, tz=timezone.utc)
                    except Exception:
                        continue
                else:
                    try:
                        t = parse_ts(utc)
                    except Exception:
                        continue
                delta = abs((t - t0).total_seconds())
                if best_delta is None or delta < best_delta:
                    best_delta = delta; best = t; best_row = m

    if best is not None and best_delta is not None and best_delta < 600:
        hits += 1
        print(f"{sid:<5} {step['start_utc']:<22} {best.isoformat():<22} {best_delta:>8.0f}  {best_row}")
    else:
        print(f"{sid:<5} {step['start_utc']:<22} {'(no match)':<22} {'-':>8}")

print(f"\nAT-07 detection coverage: {hits}/{len(gt)} steps with evidence within 600s of ground truth")
