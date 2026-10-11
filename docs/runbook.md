# DFIR Lab Platform: Host Setup & Operator Runbook

This runbook documents the exact host-level setup commands to prepare a fresh Pop!_OS (Ubuntu 24.04 LTS Noble) host for the 2-day lean DFIR lab.

---

## 1. System Packages & Toolchain

Update apt repositories and install hypervisor, container, forensic capture, and reporting prerequisites:

```bash
# Update repositories
sudo apt update && sudo apt upgrade -y

# Virtualization (KVM/libvirt) & network tools
sudo apt install -y qemu-system-x86 libvirt-daemon-system libvirt-clients bridge-utils virt-manager tcpdump tshark nftables

# Python environment and document compiler
sudo apt install -y python3-venv python3-pip pandoc texlive-latex-base texlive-latex-extra

# Docker & Docker Compose plugin (if not already installed)
sudo apt install -y docker.io docker-compose-v2
```

---

## 2. User Permissions & Group Membership

Grant your regular user account non-root access to libvirt, KVM virtualization, and the Docker daemon:

```bash
sudo usermod -aG libvirt,kvm,docker "$USER"

# Apply group changes to current session (or log out and back in)
newgrp docker
newgrp libvirt
```

---

## 3. Clock Synchronization (Forensic UTC Standard)

Digital forensics timelines require all timestamps to be in UTC without daylight savings drift:

```bash
# Set timezone to UTC
sudo timedatectl set-timezone UTC

# Ensure hardware clock runs in UTC (not local time)
sudo timedatectl set-local-rtc 0

# Verify clock status
timedatectl status
```

---

## 4. Evidence Store Directory Hierarchy

Initialize the evidence store structure (using `/home/mouadhboukari/Projects/dfir-platform/evidence`):

```bash
# Set environment variable
export DFIR_EVIDENCE_PATH="$(pwd)/evidence"

# Create directories
mkdir -p "${DFIR_EVIDENCE_PATH}/originals"
mkdir -p "${DFIR_EVIDENCE_PATH}/work"
mkdir -p "${DFIR_EVIDENCE_PATH}/results"

# Touch initial chain of custody file if not present
touch "${DFIR_EVIDENCE_PATH}/custody.jsonl"
```

---

## 5. Libvirt Isolated Network Setup

Define and launch the isolated network `lab-isolated` (`10.10.10.0/24` on bridge `virbr-lab`):

```bash
# Define the network from XML
virsh net-define libvirt/lab-isolated.xml

# Set to start automatically on host boot
virsh net-autostart lab-isolated

# Start the network immediately
virsh net-start lab-isolated

# Verify network state (mode isolated, active, autostart)
virsh net-info lab-isolated
virsh net-dumpxml lab-isolated
```

### Proving Network Isolation
Ensure the bridge cannot route to the host's WAN/LAN:
```bash
# Confirm virbr-lab exists and is bound to 10.10.10.1
ip addr show virbr-lab

# Verify iptables/nftables has zero FORWARD rules allowing virbr-lab egress
sudo iptables -S FORWARD | grep virbr-lab || echo "[OK] No forward NAT rule"
```

---

## 6. Two-Phase Operational Lifecycle

To protect host memory (16 GB total), the platform enforces strict two-phase execution:

### Phase 1: Attack Simulation & Evidence Acquisition
* **State**: Windows victim (`WS-FIN-01`, 10.10.10.20) and Linux server (`SRV-WEB-01`, 10.10.10.30) are **RUNNING**.
* **Analysis containers**: Timesketch and OpenSearch are **STOPPED**.
* **Host duties**:
  ```bash
  # 1. Start traffic capture on isolated bridge
  sudo tcpdump -i virbr-lab -w evidence/work/scenario_capture.pcap &
  TCPDUMP_PID=$!

  # 2. Start Caldera stand-in listener on host (10.10.10.1:8888)
  python3 -m http.server 8888 --bind 10.10.10.1 &
  C2_PID=$!

  # 3. Trigger scenario/beacon.py on victim

  # 4. Acquire hypervisor memory dump
  virsh dump WS-FIN-01 evidence/work/WS-FIN-01-mem.raw --memory-only

  # 5. Ingest evidence into custody store
  ./dfirctl/ingest.sh evidence/work/WS-FIN-01-mem.raw mem C01 "Hypervisor RAM dump"
  ./dfirctl/ingest.sh evidence/work/scenario_capture.pcap pcap C01 "virbr-lab bridge traffic"
  ```

### Phase 2: Analysis & Report Generation
* **State**: Victims are **SHUT DOWN** (`virsh shutdown WS-FIN-01 && virsh shutdown SRV-WEB-01`).
* **Analysis tools**: Timesketch and OpenSearch are **STARTED**.
* **Host duties**:
  ```bash
  # 1. Start Timesketch stack (capped at 1.5 GB heap)
  docker compose -f compose/timesketch/docker-compose.yml up -d

  # 2. Access Timesketch UI locally
  # Open browser: http://127.0.0.1:5000

  # 3. Run custody verification before writing report
  ./dfirctl/verify.sh

  # 4. Compile Pandoc report to PDF
  pandoc templates/report.md -o docs/incident_report.pdf --pdf-engine=xelatex
  ```
