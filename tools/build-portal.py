#!/usr/bin/env python3
"""build-portal.py — render a static HTML DFIR portal from case artifacts."""
from __future__ import annotations
import argparse, csv, json
from datetime import datetime, timezone
from pathlib import Path

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
except ImportError:
    raise SystemExit("jinja2 required: ~/venvs/portal/bin/pip install jinja2")


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def load_timeline(path: Path, limit: int) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    with path.open() as f:
        for i, row in enumerate(csv.DictReader(f)):
            if i >= limit:
                break
            rows.append(row)
    return rows


def derive_iocs(case: str, manifest: list[dict]) -> list[dict]:
    """Lab-generated indicators only. Not threat intel."""
    iocs: list[dict] = []

    for m in manifest:
        if m.get("sha256"):
            iocs.append({
                "type": "SHA-256",
                "value": m["sha256"],
                "note": f"{m.get('evidence_id','')} — {m.get('original_filename','')}",
            })

    iocs += [
        {"type": "IPv4",     "value": "10.10.10.30", "note": "guest SRV-WEB-01 (lab-only)"},
        {"type": "IPv4",     "value": "10.10.10.1",  "note": "host bridge / health endpoint (lab-only)"},
        {"type": "TCP port", "value": "8888",        "note": "lab health endpoint"},
        {"type": "URL path", "value": "/health?seq=1..5", "note": "S03 emulated callback"},
        {"type": "Marker",   "value": "DFIR_LAB_CANARY_C01",  "note": "health endpoint response marker"},
        {"type": "Marker",   "value": "DFIR-LAB-CANARY-ONLY", "note": "canary file header"},
        {"type": "Marker",   "value": "DFIR-LAB-S02",  "note": "S02 shell execution marker"},
        {"type": "Marker",   "value": "DFIR-LAB-S08",  "note": "S08 cron persistence marker"},
        {"type": "Marker",   "value": "DFIR-LAB-S11",  "note": "S11 exfil marker (no exfil performed)"},
        {"type": "Marker",   "value": "DFIR-LAB-S12",  "note": "S12 evasion marker (no log cleared)"},
        {"type": "Path",     "value": "/opt/dfir-demo/finance-demo.db", "note": "synthetic dataset"},
        {"type": "Path",     "value": "/opt/dfir-demo/markers/credential-canary.txt", "note": "synthetic canary"},
        {"type": "Path",     "value": "/opt/dfir-demo/markers/dummy-key.pem", "note": "fake PEM (not a real key)"},
        {"type": "Path",     "value": "/tmp/dfir-lab-s02.log", "note": "S02 marker file"},
        {"type": "Path",     "value": "/tmp/dfir-lab-cron.log", "note": "S08 cron output"},
        {"type": "Path",     "value": "/tmp/dfir-lab-exfil-staging/finance-demo.tar.gz", "note": "S10 staging"},
        {"type": "Path",     "value": "/var/log/dfir-lab-markers.log", "note": "S11/S12 markers"},
    ]

    return iocs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--case", default="C01")
    ap.add_argument("--template-dir", type=Path, default=None)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--timeline-limit", type=int, default=5000)
    args = ap.parse_args()

    repo = Path(__file__).resolve().parent.parent
    tpl_dir = args.template_dir or repo / "portal" / "templates"
    out = args.out or args.root / "results" / args.case / "portal"
    out.mkdir(parents=True, exist_ok=True)

    manifest = load_jsonl(args.root / "case" / "manifest.jsonl")
    custody = load_jsonl(args.root / "case" / "custody.jsonl")
    gt = load_jsonl(args.root / "case" / "ground-truth-sealed.jsonl")
    timeline = load_timeline(args.root / "results" / args.case / "timeline-merged.csv",
                             args.timeline_limit)

    custody_tip = custody[-1].get("entry_hash", "") if custody else ""

    gt_seal = ""
    seal_path = args.root / "case" / "ground-truth-sealed.jsonl.sha256"
    if seal_path.exists():
        gt_seal = seal_path.read_text().split()[0] if seal_path.read_text().split() else ""

    yara_path = args.root / "results" / f"{args.case}-E002-TRIAGE" / "yara" / "matches.txt"
    yara_text = yara_path.read_text() if yara_path.exists() else ""

    zeek_dir = args.root / "results" / f"{args.case}-E001-PCAP" / "zeek"
    zeek_files = sorted(p.name for p in zeek_dir.glob("*.log")) if zeek_dir.exists() else []

    plaso_dir = args.root / "results" / f"{args.case}-E002-TRIAGE" / "plaso"
    plaso_files = sorted(p.name for p in plaso_dir.iterdir()) if plaso_dir.exists() else []

    log_dir = args.root / "logs"
    run_logs = sorted(log_dir.glob("dfirctl-*.log"))
    run_log = run_logs[-1].read_text() if run_logs else ""

    iocs = derive_iocs(args.case, manifest)

    env = Environment(
        loader=FileSystemLoader(str(tpl_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.filters["toshort"] = lambda s, n=16: (str(s)[:n] + "…") if s and len(str(s)) > n else s

    html = env.get_template("index.html.j2").render(
        case=args.case,
        generated_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        manifest=manifest,
        custody=custody,
        custody_tip=custody_tip,
        ground_truth=gt,
        gt_seal=gt_seal,
        timeline=timeline,
        timeline_total=len(timeline),
        zeek_files=zeek_files,
        plaso_files=plaso_files,
        yara_text=yara_text,
        iocs=iocs,
        run_log=run_log,
    )
    (out / "index.html").write_text(html)

    # Copy CSS
    css_src = tpl_dir / "style.css"
    if css_src.exists():
        (out / "style.css").write_text(css_src.read_text())

    print(f"portal: file://{out}/index.html")
    print(f"        {len(manifest)} evidence items, {len(custody)} custody events, {len(timeline)} timeline rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())