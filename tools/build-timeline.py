#!/usr/bin/env python3
import csv, json
from pathlib import Path

root = Path("/mnt/dfir-evidence")
out = root / "results/C01/timeline-merged.csv"
out.parent.mkdir(parents=True, exist_ok=True)

def zeek_rows(path):
    """Yield dicts keyed by Zeek's #fields header."""
    fields = None
    with path.open() as f:
        for line in f:
            if line.startswith("#fields"):
                fields = line.strip().split("\t")[1:]
                continue
            if line.startswith("#") or not line.strip():
                continue
            if not fields: continue
            yield dict(zip(fields, line.rstrip("\n").split("\t")))

with out.open("w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["utc", "epoch_us", "source", "event", "detail"])

    for r in zeek_rows(root/"results/C01-E001-PCAP/zeek/http.log"):
        w.writerow([
            r.get("ts", ""), "",
            "zeek-http",
            f"{r.get('id.orig_h')}:{r.get('id.orig_p')} {r.get('method')} {r.get('uri')}",
            f"host={r.get('host')} status={r.get('status_code')}",
        ])

    for r in zeek_rows(root/"results/C01-E001-PCAP/zeek/conn.log"):
        w.writerow([
            r.get("ts", ""), "",
            "zeek-conn",
            f"{r.get('id.orig_h')}:{r.get('id.orig_p')} -> {r.get('id.resp_h')}:{r.get('id.resp_p')}",
            f"proto={r.get('proto')} dur={r.get('duration')}",
        ])

    for line in (root/"logs/lab-health.log").read_text().splitlines():
        if "method=GET" in line and "src=" in line:
            fields = dict(kv.split("=", 1) for kv in line.split() if "=" in kv)
            w.writerow([fields.get("time", ""), "", "health-log",
                        f"src={fields.get('src', '?')}",
                        f"path={fields.get('path', '?')}"])

    for line in (root/"results/C01-E002-TRIAGE/plaso/timeline.jsonl").read_text().splitlines():
        if not line.strip(): continue
        e = json.loads(line)
        w.writerow([
            e.get("date_time", ""), e.get("timestamp", ""),
            "plaso", e.get("timestamp_desc", ""),
            str(e.get("message", ""))[:160],
        ])

print(f"wrote {out}")
