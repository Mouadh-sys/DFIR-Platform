#!/usr/bin/env python3
import csv, json, sys
from pathlib import Path

root = Path("/mnt/dfir-evidence")
out = root / "results/C01/timeline-merged.csv"
out.parent.mkdir(parents=True, exist_ok=True)

with out.open("w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["utc", "epoch_us", "source", "event", "detail"])

    # Zeek http
    for line in (root/"results/C01-E001-PCAP/zeek/http.log").read_text().splitlines():
        if not line or line.startswith("#"): continue
        parts = line.split("\t")
        if len(parts) < 15: continue
        ts = parts[0]
        w.writerow([f"@zeek-http", ts, "zeek-http",
                    f"{parts[2]}:{parts[3]} GET {parts[9]}",
                    f"host={parts[8]} status={parts[14]}"])

    # Zeek conn
    for line in (root/"results/C01-E001-PCAP/zeek/conn.log").read_text().splitlines():
        if not line or line.startswith("#"): continue
        parts = line.split("\t")
        if len(parts) < 10: continue
        ts = parts[0]
        w.writerow([f"@zeek-conn", ts, "zeek-conn",
                    f"{parts[2]}:{parts[3]} -> {parts[4]}:{parts[5]}",
                    f"proto={parts[6]} dur={parts[8]}"])

    # Health log
    for line in (root/"logs/lab-health.log").read_text().splitlines():
        if "method=GET" in line and "src=" in line:
            fields = dict(kv.split("=", 1) for kv in line.split() if "=" in kv)
            w.writerow([fields.get("time", ""), "", "health-log",
                        f"src={fields.get('src', '?')}",
                        f"path={fields.get('path', '?')}"])

    # Plaso — use date_time, NOT timestamp
    for line in (root/"results/C01-E002-TRIAGE/plaso/timeline.jsonl").read_text().splitlines():
        if not line.strip(): continue
        e = json.loads(line)
        msg = str(e.get("message", ""))[:160]
        w.writerow([
            e.get("date_time", ""),
            e.get("timestamp", ""),
            "plaso",
            e.get("timestamp_desc", ""),
            msg,
        ])

print(f"wrote {out}")
