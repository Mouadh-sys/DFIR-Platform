# DFIR Lab Platform

A self-hosted, lightweight Digital Forensics and Incident Response (DFIR) simulation and investigation platform designed for repeatable, evidence-grade academic and laboratory investigations.

Built for standard workstation hardware (16 GB RAM, Pop!_OS / Ubuntu Linux), this platform provides end-to-end attack simulation, volatile and persistent evidence collection, cryptographic chain-of-custody tracking, unified timeline reconstruction, and automated report generation.

---

## 🏗️ Architecture & Core Principles

```
  ┌────────────────────────────────────────────────────────────────────────┐
  │ PHASE 1: Attack Simulation & Acquisition (Victims: ON | Tools: OFF)   │
  │                                                                        │
  │  [WS-FIN-01] 10.10.10.20 ──(HTTP C2 Beacon)──> [Host] 10.10.10.1:8888  │
  │        │                                                               │
  │        └──(SSH Lateral Movement)──> [SRV-WEB-01] 10.10.10.30           │
  │                                                                        │
  │  Isolated Bridge: virbr-lab (10.10.10.0/24) | host-side tcpdump capture│
  └────────────────────────────────────────────────────────────────────────┘
                                     │
                        virsh dump + triage pull
                                     ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │ EVIDENCE STORE (Immutable originals, SHA-256 + MD5, hash-chained log)  │
  └────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │ PHASE 2: Offline Analysis & Reporting (Victims: OFF | Tools: ON)       │
  │                                                                        │
  │  • OpenSearch + Timesketch (Heap capped at 1.5 GB, bound to 127.0.0.1) │
  │  • Super-timeline analysis (Plaso, Zeek, Sysmon, auditd)               │
  │  • Custody verification (dfirctl/verify.sh)                            │
  │  • Pandoc Markdown → PDF Incident Report                              │
  └────────────────────────────────────────────────────────────────────────┘
```

1. **Strict Network Isolation**: The lab runs on a dedicated libvirt network (`10.10.10.0/24`) with no NAT or uplink forwarding. Victim VMs can never reach the physical LAN or the Internet.
2. **Two-Phase Memory Model**: To operate comfortably within 16 GB RAM:
   - **Phase 1 (Simulation & Acquisition)**: Windows and Linux VMs are running; heavy analytical tools are stopped.
   - **Phase 2 (Analysis & Reporting)**: VMs are powered off; Timesketch and forensic engines are started.
3. **Cryptographic Chain of Custody**: Evidence is hashed (SHA-256 and MD5) upon arrival, stored read-only (`0444` + `chattr +i`), and recorded in a hash-chained audit log (`custody.jsonl`).
4. **Offline & Open Source**: Zero commercial or cloud dependencies; fully self-contained using KVM/libvirt, Docker, and standard Linux utilities.

---

## 🌐 Network & Host Topology

| Host / Node | Role | IP Address | MAC Address | Notes |
|---|---|---|---|---|
| **Host Bridge** | Gateway / Capture / C2 listener | `10.10.10.1` | Host managed (`virbr-lab`) | Host side `tcpdump`, no internet routing |
| **WS-FIN-01** | Victim Workstation (Win 11) | `10.10.10.20` | `52:54:00:10:10:20` | Sysmon enabled, initial compromise target |
| **SRV-WEB-01** | Internal Server (Ubuntu 24.04) | `10.10.10.30` | `52:54:00:10:10:30` | Nginx, SSH, `auditd`, lateral movement target |

---

## 📁 Repository Structure

```text
dfir-platform/
├── ansible/                  # Playbooks for VM baselines and provisioning
├── compose/
│   └── timesketch/           # Timesketch + OpenSearch stack (1.5 GB heap limit)
├── dfirctl/                  # Lean CLI helper scripts
│   ├── custody.py            # Hashing, immutable storage & hash-chain validation
│   ├── ingest.sh             # Evidence ingestion wrapper
│   └── verify.sh             # Integrity check and tamper-verification wrapper
├── docs/                     # Documentation & runbooks
│   ├── architecture.md       # Complete system specification
│   ├── PLAN.md               # Milestones & host inspection findings
│   └── runbook.md            # Step-by-step host setup and execution guide
├── libvirt/
│   └── lab-isolated.xml      # Isolated libvirt network definition (no NAT)
├── rules/                    # Detection rules (YARA, Sigma)
├── scenarios/
│   └── beacon.py             # Lightweight HTTP C2 beacon (Caldera stand-in)
├── templates/
│   └── report.md             # Pandoc-ready incident report template
└── tests/                    # Integrity and test scripts
```

---

## 🚀 Quick Start Guide

For full prerequisites and environment preparation, refer to [docs/runbook.md](file:///home/mouadhboukari/Projects/dfir-platform/docs/runbook.md).

### 1. Initialize Isolated Network

```bash
# Define, autostart, and launch the isolated lab network
virsh net-define libvirt/lab-isolated.xml
virsh net-autostart lab-isolated
virsh net-start lab-isolated

# Verify status
virsh net-info lab-isolated
```

### 2. Evidence Acquisition & Ingestion (Phase 1)

Collect evidence during the incident scenario and register it immediately into the tamper-evident custody store:

```bash
# Set evidence directory (defaults to ./evidence)
export DFIR_EVIDENCE_PATH="$(pwd)/evidence"

# Example: Ingest hypervisor memory dump
./dfirctl/ingest.sh /tmp/WS-FIN-01-mem.raw mem C01 "Hypervisor RAM dump"

# Example: Ingest network PCAP
./dfirctl/ingest.sh /tmp/virbr-lab.pcap pcap C01 "Host-side bridge traffic capture"
```

### 3. Verify Chain of Custody Integrity

Run the verification check at any time to validate the cryptographic hash chain and verify that no evidence file has been modified:

```bash
./dfirctl/verify.sh
```

### 4. Start Analysis Stack (Phase 2)

Once VMs are powered off, start the Timesketch timeline analysis stack:

```bash
# Launch Timesketch (OpenSearch heap capped at 1.5 GB, UI on 127.0.0.1:5000)
docker compose -f compose/timesketch/docker-compose.yml up -d

# Check service logs
docker compose -f compose/timesketch/docker-compose.yml logs -f
```

Access the Timesketch web interface locally at: `http://127.0.0.1:5000`

### 5. Generate Incident Report

Compile the final markdown investigation report into a professional PDF using Pandoc:

```bash
pandoc templates/report.md -o docs/incident_report.pdf --pdf-engine=xelatex
```

---

## 🔒 Chain of Custody Specification

Every ingested evidence item is logged in `evidence/custody.jsonl` with an SHA-256 hash chain:

```json
{
  "timestamp_utc": "2026-10-11T14:49:50.000Z",
  "action": "INGEST",
  "case_id": "C01",
  "evidence_id": "C01-E001-mem",
  "evidence_type": "mem",
  "filename": "WS-FIN-01-mem.raw",
  "stored_path": "evidence/originals/C01/C01-E001-mem/WS-FIN-01-mem.raw",
  "size_bytes": 4294967296,
  "sha256": "355c357708e4840d12b0d4284d9fe1a911c79c013953874f03068b81127f3363",
  "md5": "f6dbc2fdeb4c5d86dc0008fa2c677746",
  "operator": "analyst",
  "notes": "Hypervisor RAM dump",
  "prev_entry_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "entry_hash": "28d1dfafef3e198ce431fae33b66479e0839e0eb38c92694db0995171fc45f27"
}
```

Any modification to a past line breaks all subsequent entry hashes, providing verifiable proof of integrity for investigation reports.

---

## 📖 Further Documentation

* [docs/runbook.md](file:///home/mouadhboukari/Projects/dfir-platform/docs/runbook.md): Detailed host configuration, package installations, and operation procedures.
* [docs/architecture.md](file:///home/mouadhboukari/Projects/dfir-platform/docs/architecture.md): Complete platform architecture and requirement specification.
* [docs/PLAN.md](file:///home/mouadhboukari/Projects/dfir-platform/docs/PLAN.md): Delivery plan, hardware baseline, and milestone checklist.
