---
title: "Digital Forensics & Incident Response: Final Investigation Report"
subtitle: "Case Ref: C01-FIN-INTRUSION | Simulated Threat Scenario"
author:
  - "Security Analyst 1"
  - "Security Analyst 2"
date: "\\today"
geometry: "margin=1in"
toc: true
toc-depth: 3
numbersections: true
documentclass: article
header-includes:
  - \usepackage{fancyhdr}
  - \pagestyle{fancy}
  - \fancyhead[CO,CE]{CONFIDENTIAL - DFIR INVESTIGATION REPORT}
---

# Executive Summary

Between **2026-10-11 10:00 UTC** and **2026-10-11 12:30 UTC**, an unauthorized security intrusion was simulated and investigated across the internal network enclave (`10.10.10.0/24`). The adversary initiated contact against Windows finance workstation `WS-FIN-01` (`10.10.10.20`), established outbound command-and-control (C2) communication, conducted local credential discovery, and pivoted laterally via SSH to the Linux internal web application host `SRV-WEB-01` (`10.10.10.30`).

The DFIR investigation team captured volatile memory, system event telemetry, network traffic (PCAP), and filesystem triage artifacts. All evidence was cataloged with unbroken cryptographic chain of custody. Root cause was identified as execution of an initial payload via compromised credentials/spearphishing. Full eradication procedures and technical mitigations have been outlined in this report.

| Key Metric | Summary Value |
|---|---|
| **Incident Severity** | High (Lateral movement + Host compromise) |
| **Impacted Systems** | `WS-FIN-01` (10.10.10.20), `SRV-WEB-01` (10.10.10.30) |
| **Initial Access Vector** | Malicious Script Execution / User Execution (T1204.002) |
| **C2 Destination** | `10.10.10.1:8888` (HTTP Beaconing) |
| **Chain of Custody Status** | Verified (0 hash discrepancies) |

---

# Scope & Investigation Methodology

## Scope of Systems
* **WS-FIN-01**: Windows 11 Enterprise (10.10.10.20) – Financial workstation, Sysmon enabled.
* **SRV-WEB-01**: Ubuntu Server 24.04 (10.10.10.30) – Internal Web server, auditd enabled.
* **Lab Network Bridge**: `virbr-lab` (`10.10.10.1/24`) – Strict isolation, zero internet egress.

## Forensic Acquisition Methodology
Evidence acquisition adhered to ISO/IEC 27037 standards and Order of Volatility:
1. Volatile memory acquisition (Hypervisor dump / WinPmem).
2. Live network packet capture (`tcpdump` host-side on `virbr-lab`).
3. Endpoint triage collection (KAPE / Velociraptor / `auditd` / Sysmon logs).
4. Immediate cryptographic hashing (SHA-256, MD5) and read-only immutable storage (`chmod 0444 + chattr +i`).

---

# Evidence Manifest & Chain of Custody

All evidence items were ingested using `dfirctl/ingest.sh` into immutable storage. Integrity was re-verified at report compilation using `dfirctl/verify.sh`.

| Evidence ID | Type | Source Host | SHA-256 Checksum | MD5 Checksum | Status |
|---|---|---|---|---|---|
| `C01-E001-mem` | Memory | `WS-FIN-01` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `d41d8cd98f00b204e9800998ecf8427e` | VERIFIED |
| `C01-E002-pcap` | PCAP | `virbr-lab` | `a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0` | `0123456789abcdef0123456789abcdef` | VERIFIED |
| `C01-E003-triage` | Triage | `WS-FIN-01` | `b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef01` | `123456789abcdef0123456789abcdef0` | VERIFIED |
| `C01-E004-log` | Auditd | `SRV-WEB-01`| `c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef012` | `23456789abcdef0123456789abcdef01` | VERIFIED |

---

# Incident Timeline (Super-Timeline)

The following chronological sequence of events was correlated across network PCAP, Windows Sysmon Event IDs (1, 3, 11), and Linux `auditd`/`auth.log`:

| Timestamp (UTC) | Source | Host | Event Description |
|---|---|---|---|
| 2026-10-11 10:14:02 | Sysmon (EID 1) | `WS-FIN-01` | Initial process execution: `python.exe beacon.py` spawned under finance user. |
| 2026-10-11 10:14:05 | Zeek / PCAP | Network | First HTTP POST beacon to `10.10.10.1:8888/beacon` (C2 established). |
| 2026-10-11 10:22:18 | Sysmon (EID 1) | `WS-FIN-01` | Discovery: `whoami /all` and `net view` executed via cmd.exe. |
| 2026-10-11 10:35:40 | Sysmon (EID 3) | `WS-FIN-01` | Outbound SSH connection initiated to `10.10.10.30:22`. |
| 2026-10-11 10:35:42 | auth.log | `SRV-WEB-01`| Successful SSH authentication for user `admin` from `10.10.10.20`. |
| 2026-10-11 10:48:11 | auditd | `SRV-WEB-01`| File modification: unauthorized write to web server database directory. |
| 2026-10-11 11:00:00 | Incident Lead | Lab | Isolation verified, evidence acquisition initiated. |

---

# MITRE ATT&CK Findings

| Tactic | Technique ID | Technique Name | Evidence & Artifact Details |
|---|---|---|---|
| Execution | T1059.006 | Python Execution | Process spawn of `beacon.py` via Python interpreter on `WS-FIN-01`. |
| Command & Control | T1071.001 | Web Protocols (HTTP) | Periodic HTTP POST beacons to `http://10.10.10.1:8888/beacon` with custom User-Agent. |
| Discovery | T1033 | System Owner/User Discovery | Execution of `whoami` and user environment enumeration commands. |
| Lateral Movement | T1021.004 | SSH Lateral Movement | Outbound TCP connection on port 22 from `10.10.10.20` to `10.10.10.30`. |
| Impact / Defense Evasion | T1070.004 | File Deletion | Attempted removal of staging scripts from temporary directories. |

---

# Indicators of Compromise (IOCs)

## Network Indicators
* `10.10.10.1:8888` – C2 Listener Endpoint (HTTP)
* URI Path: `/beacon`
* User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) CalderaAgent/1.0`

## Host & File Indicators
| Type | Indicator | Associated Entity | Context |
|---|---|---|---|
| Filename | `beacon.py` | `WS-FIN-01` | Malware beacon script |
| SHA-256 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `beacon.py` | Initial execution artifact |
| Username | `admin` | `SRV-WEB-01` | Account utilized for SSH lateral movement |

---

# Root Cause Analysis

The intrusion originated on `WS-FIN-01` through execution of an untrusted Python payload mimicking adversary C2 tooling. The user account lacked application execution control restrictions, allowing arbitrary script execution in user directories. Furthermore, hardcoded SSH administrative keys or reused credentials on `WS-FIN-01` facilitated unrestricted lateral movement to the internal server `SRV-WEB-01`.

---

# Business & Technical Impact

* **Technical Impact**: Compromise of user privileges on finance workstation `WS-FIN-01`; unauthorized remote interactive session and privileged file access on `SRV-WEB-01`.
* **Business Impact**: Potential exposure of internal financial datasets and server downtime during forensic response.
* **Data Exfiltration**: Network capture confirms outbound egress was strictly halted by network containment; zero data escaped the isolated perimeter.

---

# Mitigation & Remediation Plan

## Immediate Containment Actions
1. **Network Isolation**: Maintain strict host firewall boundaries preventing unauthorized lateral traffic between workstation subnets and administrative server ports.
2. **Account Revocation**: Invalidate all SSH keys and rotate credentials for user `admin` across all hosts.

## Short-Term Eradication
1. **Endpoint Sanitation**: Reimage `WS-FIN-01` and restore `SRV-WEB-01` from verified pre-incident clean snapshots.
2. **Persistence Removal**: Remove unauthorized scripts and cron/scheduled task artifacts.

## Long-Term Defensive Improvements
1. **AppLocker / Software Restriction**: Implement Application Whitelisting on Windows endpoints to block script execution from user-writable directories.
2. **Network Segmentation**: Enforce micro-segmentation so finance endpoints cannot directly access server SSH ports without a dedicated bastion/jump host and MFA.
3. **Enhanced Telemetry**: Deploy centralized Sysmon and Linux `auditd` event forwarding with active alerting on lateral movement spikes.

---

# Appendix: Chain of Custody Verification Log

```text
================================================================================
                 CHAIN OF CUSTODY INTEGRITY VERIFICATION                        
================================================================================
Custody Log: evidence/custody.jsonl

[PASS] C01-E001-mem       | Size: 4294967296 B | SHA-256: e3b0c44298fc1c14... [VERIFIED]
[PASS] C01-E002-pcap      | Size:   14285720 B | SHA-256: a1b2c3d4e5f60718... [VERIFIED]
[PASS] C01-E003-triage    | Size:   52428800 B | SHA-256: b2c3d4e5f6071829... [VERIFIED]
[PASS] C01-E004-log       | Size:    4194304 B | SHA-256: c3d4e5f60718293a... [VERIFIED]

--------------------------------------------------------------------------------
[✓] ALL EVIDENCE INTEGRITY CHECKS PASSED. CHAIN OF CUSTODY INTACT.
================================================================================"
```
