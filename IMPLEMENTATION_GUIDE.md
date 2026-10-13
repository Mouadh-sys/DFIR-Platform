# DFIR Platform: Linux-only implementation guide

**Target host:** Pop!_OS, 16 GB RAM, KVM/libvirt, roughly 250 GB evidence storage.  
**Lab target:** one Ubuntu Server 24.04 guest, `SRV-WEB-01` at `10.10.10.30`.  
**Host lab interface:** `10.10.10.1` on `virbr-lab`.  
**Case:** `C01`. **Clock:** UTC.

## 0. What changes when Windows is removed

This is a scope reduction, not a drop-in replacement for the original two-OS scenario. The project becomes a **Linux web-server compromise emulation and DFIR investigation**. It will still demonstrate isolated lab design, attack-activity emulation, network capture, Linux log collection, optional memory capture, evidence hashing/custody, timeline generation, IOC extraction, reporting, and repeatability.

Removed claims and components: Windows victim, Sysmon, PowerShell logging, Windows Event Logs, registry/MFT analysis, WinPmem, Windows Volatility plugins, Windows-to-Linux pivot, and cross-platform memory comparison. Do not leave these in the report or demo as if they were implemented.

Use the Pop!_OS host as the controlled activity driver and DFIR collection/analysis host. This is less realistic than a separate attacker VM, but it avoids the extra guest memory. Do not run real malware, use real secrets, disable host protections, or send traffic outside the lab. The incident is a controlled emulation, not a claim that a real exploit or real exfiltration occurred.

### Scope priority

**Must finish:** isolated libvirt network; one Linux guest with auditd + journald + SSH/nginx logs; reviewed Linux Atomic tests and harmless manual markers; PCAP; triage and (if feasible) memory; SHA-256 manifest and custody log; normalized timeline; findings/IOCs; final report and demo.

**Optional, only after the pipeline works:** Timesketch UI, DFIR-IRIS, full Ansible rebuild, advanced `dfirctl`, and a hypervisor memory dump if the format cannot be analyzed. Timesketch/OpenSearch can use several GB even by itself; run it only in the analysis phase, after the guest is shut down. If resource usage is still high, use Plaso CSV plus a spreadsheet/timeline viewer and document the fallback.

## 1. Create the working directories and install host tools

Install the host packages:

```bash
sudo apt update
sudo apt install -y qemu-kvm libvirt-daemon-system libvirt-clients virt-manager \
  bridge-utils docker.io docker-compose-v2 git python3 python3-venv python3-pip \
  tcpdump tshark nftables jq sqlite3 yara pandoc curl wget unzip rsync
sudo usermod -aG libvirt,kvm,docker "$USER"
```

Log out and back in. The Docker group grants root-equivalent control over the host, so keep host access restricted. Verify:

```bash
virsh --version
qemu-system-x86_64 --version
docker --version
docker compose version
python3 --version
free -h
```

Create the repository and external/dedicated evidence area:

```bash
mkdir -p ~/projects/dfir-platform
cd ~/projects/dfir-platform
# Copy the starter-kit files here, then:
git init
sudo mkdir -p /mnt/dfir-evidence/{evidence/incoming,evidence/originals,work,results,case,logs,backups}
sudo chown -R "$USER":"$USER" /mnt/dfir-evidence
findmnt /mnt/dfir-evidence
df -h /mnt/dfir-evidence
```

Use a dedicated ext4 partition or external SSD where possible. Do not proceed until `findmnt` confirms the evidence filesystem is really mounted. Keep evidence, working copies, memory images, PCAPs, `.env`, credentials, and keys outside Git; the included `.gitignore` should enforce this.

Set host time to UTC and record the baseline:

```bash
sudo timedatectl set-timezone UTC
timedatectl status
free -h
df -h
```

## 2. Create the isolated libvirt network

The included `libvirt/lab-isolated.xml` defines `virbr-lab` with host address `10.10.10.1/24` and deliberately has no `<forward>` element. Define/start it:

```bash
sudo virsh net-define ~/projects/dfir-platform/libvirt/lab-isolated.xml
sudo virsh net-start lab-isolated
sudo virsh net-autostart lab-isolated
virsh net-list --all
virsh net-dumpxml lab-isolated
ip -br addr show virbr-lab
```

If the file is elsewhere, adjust the path. Inspect the resulting XML and confirm no forwarding/NAT is configured.

## 3. Build the single Linux guest

Create one VM using `virt-manager`:

- Name: `SRV-WEB-01`.
- OS: Ubuntu Server 24.04 LTS.
- Start with **2 vCPUs, 2 GB RAM, 25–40 GB qcow2 disk**. Raise RAM only if measurements show it is necessary.
- During package installation only, you may temporarily attach a NAT NIC or use a controlled transfer ISO. **Remove the NAT NIC before testing**. The final VM must have exactly one NIC attached to `lab-isolated`.
- Static guest address: `10.10.10.30/24`; no default gateway and no public DNS.
- Enable UTC and set hostname `SRV-WEB-01`.

Configure Netplan with your guest interface name (get it from `ip -br link`). Example:

```yaml
network:
  version: 2
  ethernets:
    enp1s0:
      dhcp4: false
      addresses: [10.10.10.30/24]
```

Apply it from the VM console and verify:

```bash
sudo netplan try
ip -br addr
ip route
hostnamectl
sudo timedatectl set-timezone UTC
```

There should be no default route. Replace `enp1s0` with the actual interface. Take a `base` snapshot after basic OS configuration. Install the tooling and telemetry in the next step; after verifying them, take a `clean` snapshot.

Verify the VM is on the right network:

```bash
virsh list --all
virsh domiflist SRV-WEB-01
```

## 4. Isolation gate: mandatory before simulation

Before every scenario run:

1. `SRV-WEB-01` has exactly one NIC, attached to `lab-isolated`.
2. Its IP is `10.10.10.30/24`, and it has no default route.
3. The libvirt network has no forwarding element.
4. An external IP such as `1.1.1.1` and the home-router address are unreachable from the guest. Confirm with route inspection as well as a connection test; one failed ping alone proves very little.
5. Only explicitly approved host services are reachable on `10.10.10.1`.
6. Save `virsh net-dumpxml`, `virsh domiflist SRV-WEB-01`, `ip route`, host bridge/firewall status, and failed external connection checks as proof.

If the guest has an unexpected NIC or route, stop. Do not run Atomic tests until this gate passes. The isolated libvirt network is not a malware-proof boundary by itself; keep guest integration, shared folders, clipboard, USB passthrough, and host filesystem mounts disabled unless required.

## 5. Configure Linux telemetry and synthetic data

Inside the guest, install only the required services, preferably through a controlled package-install phase before disconnecting the temporary NAT path:

```bash
sudo apt update
sudo apt install -y nginx openssh-server auditd audispd-plugins sqlite3 \
  python3 curl jq cron
sudo systemctl enable --now nginx ssh auditd cron
sudo timedatectl set-timezone UTC
```

Check the exact SSH unit name for the Ubuntu release (`ssh` is common):

```bash
systemctl --no-pager --full status nginx ssh auditd cron
```

### 5.1 Configure auditd

Create `/etc/audit/rules.d/dfir-lab.rules` after creating the paths that will be watched:

```text
-a always,exit -F arch=b64 -S execve -k dfir_exec
-w /etc/crontab -p wa -k dfir_cron
-w /etc/cron.d -p wa -k dfir_cron
-w /var/spool/cron -p wa -k dfir_cron
-w /etc/ssh/sshd_config -p wa -k dfir_ssh_config
-w /opt/dfir-demo -p rwa -k dfir_demo_data
```

Rules vary with kernel/audit version and architecture. Validate instead of assuming:

```bash
sudo augenrules --check
sudo augenrules --load
sudo auditctl -l
sudo ausearch -k dfir_exec --start recent
```

If a watched path does not exist or a rule is unsupported, fix it and record the final output in `docs/commands.md`. Configure journald/system logs, SSH auth logs, nginx access/error logs and cron logs for later collection.

### 5.2 Create synthetic records and canary files

Everything must be fictitious:

```bash
sudo install -d -o root -g root -m 0755 /opt/dfir-demo
sudo sqlite3 /opt/dfir-demo/finance-demo.db <<'SQL'
CREATE TABLE payments (
  payment_id INTEGER PRIMARY KEY,
  client_code TEXT NOT NULL,
  amount REAL NOT NULL,
  status TEXT NOT NULL,
  created_utc TEXT NOT NULL
);
INSERT INTO payments VALUES
 (1001,'DEMO-ALPHA',1250.00,'PENDING','2026-10-01T09:10:00Z'),
 (1002,'DEMO-BRAVO',840.50,'APPROVED','2026-10-02T10:20:00Z'),
 (1003,'DEMO-CHARLIE',99.99,'PENDING','2026-10-03T11:30:00Z');
SQL
sudo chmod 0644 /opt/dfir-demo/finance-demo.db
sudo install -d -m 0750 -o root -g root /opt/dfir-demo/markers
printf 'DFIR-LAB-CANARY-ONLY\nuser=demo\nsecret=not-a-real-secret\n' \
  | sudo tee /opt/dfir-demo/markers/credential-canary.txt >/dev/null
```

Create a generated, non-authorized SSH private-key-shaped artifact only if you need to demonstrate file access. Prefer a dummy text file if the report only needs file-access telemetry. Never copy a personal key or authorize this artifact for any account. Do not use real credentials.

### 5.3 Baseline snapshot

Verify service logs and audit rules, confirm network isolation, reboot once, then shut down and take a `clean` snapshot. Everything created before `clean` is baseline and should be described in the report.

## 6. Atomic Red Team on Linux

Atomic Red Team contains tests organized by MITRE ATT&CK technique. The execution framework `Invoke-AtomicRedTeam` supports Linux when PowerShell Core is installed; that does **not** mean every test is Linux-compatible. Review the test definition and `supported_platforms` field before using it. Official references: https://www.atomicredteam.io/docs/atomic-red-team and https://www.atomicredteam.io/docs/invoke-atomicredteam/getting-started

Install PowerShell Core using the current Microsoft instructions for Ubuntu, then open `pwsh`:

```bash
pwsh --version
git --version
```

Inside `pwsh`:

```powershell
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name Invoke-AtomicRedTeam, powershell-yaml -Scope CurrentUser
Import-Module Invoke-AtomicRedTeam
```

Clone the test library in a controlled staging phase:

```powershell
git clone https://github.com/redcanaryco/atomic-red-team.git "$HOME/AtomicRedTeam"
$Atomics = "$HOME/AtomicRedTeam/atomics"
```

For each chosen technique, use this sequence, replacing `T1082` and the test number with one you have reviewed and confirmed supports Linux:

```powershell
Invoke-AtomicTest T1082 -PathToAtomicsFolder $Atomics -ShowDetailsBrief
Invoke-AtomicTest T1082 -PathToAtomicsFolder $Atomics -CheckPrereqs
# Read the test's YAML/Markdown, exact commands, dependencies and cleanup first.
Invoke-AtomicTest T1082 -PathToAtomicsFolder $Atomics -TestNumbers 1
Invoke-AtomicTest T1082 -PathToAtomicsFolder $Atomics -TestNumbers 1 -Cleanup
```

Test number `1` is only an example: do not assume that it is suitable. Pick a test whose definition shows Linux support and harmless effects. Run one test at a time. Record technique, GUID/test number, repository version/commit, UTC start/end, exit code, output, and cleanup result. Avoid tests that modify authentication, disable controls, establish remote callbacks, delete logs, or make external connections.

## 7. Host-side collection services

### 7.1 Velociraptor

Follow the current official quickstart and generate server/client configurations from the same pinned release: https://docs.velociraptor.app/docs/deployment/quickstart/

- Store generated server keys/configuration outside Git with restrictive permissions.
- Bind the client frontend only to `10.10.10.1:8000` for lab clients.
- Bind the administrative GUI to `127.0.0.1` on a separate port, such as `8889` (use the port in your actual generated config).
- Generate and install only the Linux client on `SRV-WEB-01`.
- Confirm the client checks in and test one harmless log/file collection before the incident.
- Collect journald/auth, auditd, nginx, cron, relevant configuration metadata, and selected filesystem artifacts with a documented artifact specification. Verify the returned bundle before ingesting it.

Do not paste a config from another Velociraptor version; generated configuration fields can change.

### 7.2 Packet capture and fixed health endpoint

The included `tools/lab_health_server.py` serves only `GET /health`, records request metadata, accepts no commands or uploads, and must bind to the lab bridge address only:

```bash
python3 tools/lab_health_server.py \
  --bind 10.10.10.1 --port 8888 \
  --log /mnt/dfir-evidence/logs/lab-health.log
```

Confirm `10.10.10.1` is assigned to `virbr-lab`. Do not change the bind address to `0.0.0.0`. Allow access to port 8888 only from the lab guest address/subnet using host firewall rules, and stop the service after the scenario.

## 8. Linux-only incident scenario

Rename the case narrative to **“Linux web-server compromise emulation”**. There is no Windows workstation and no genuine lateral-movement step. The Pop!_OS host is the controlled activity driver/collector; this limitation must be stated in the report.

Use `scenarios/linux-web-server-compromise.yaml`. Keep the ground-truth log separate from analysis outputs; record UTC start/end times and each action's result. Use the following 12 steps, but distinguish real benign actions from simulation markers:

1. **Inbound web activity marker (T1190 emulation only):** send a finite GET to the guest's nginx landing page from the host. No exploit or vulnerable service is used; do not report successful exploitation.
2. **Shell execution (T1059.004):** as a disposable lab user in the guest, run a reviewed benign diagnostic that writes `DFIR-LAB-S02` and basic OS information to a log file.
3. **HTTP callback-like traffic (T1071.001 emulation):** issue a few finite GET requests from the guest to `http://10.10.10.1:8888/health`. No commands or data uploads are possible.
4. **System discovery (T1082):** run an approved Linux Atomic test or harmless `uname`/`hostname` commands; preserve audit/process evidence.
5. **Account discovery (T1033/T1087.001):** inspect the lab user/account list with a reviewed low-impact test; do not scan outside the lab.
6. **Synthetic credential-file access (T1552.001 emulation):** read the canary at `/opt/dfir-demo/markers/credential-canary.txt`; it contains no real credential.
7. **Private-key discovery marker (T1552.004 emulation):** read only a planted, non-authorized dummy file if the scenario requires it. Never use any key from a real account.
8. **Cron persistence behavior (T1053.003):** add a temporary cron entry that only writes a timestamp to `/tmp/dfir-lab-cron.log`; verify the artifact and remove the entry immediately during cleanup.
9. **Collection/archive (T1560.001):** copy only `/opt/dfir-demo/finance-demo.db` into a case staging directory and archive it. Do not collect any real user data.
10. **Data staging (T1074.001):** create a separate staging directory and record hashes for the synthetic archive. Do not stage anything else.
11. **Exfiltration behavior marker (T1041 emulated only):** log an explicit marker that an exfiltration attempt was simulated. Do not claim data was exfiltrated; the health endpoint cannot accept uploads.
12. **Defense-evasion marker (T1070.003 emulated only):** write a marker for attempted history/log clearing and verify prior independently collected logs remain available. Do not actually clear logs or erase history.

Run the steps manually or through reviewed Linux-compatible Atomic tests. Do not automate any dangerous action just to make the timeline more dramatic. For each step, write its label in `case/ground-truth-sealed.jsonl` and record exact UTC times. Keep the file sealed/unopened by the analyst until the timeline is reconstructed.

## 9. Capture traffic and acquire evidence

Create a run folder and capture the lab network on the host:

```bash
RUN="C01-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "/mnt/dfir-evidence/evidence/incoming/$RUN"
sudo tcpdump -i virbr-lab -nn -s 0 \
  -w "/mnt/dfir-evidence/evidence/incoming/$RUN/lab.pcap" \
  'net 10.10.10.0/24'
```

Pilot the capture first: request nginx from the host and issue one health check from the guest. Confirm both are visible. Bridge/tap visibility can vary; if traffic is missing, test the guest tap interface or `-i any` and document the actual capture point. Stop tcpdump with Ctrl-C when the run ends.

Minimum collection set:

- Velociraptor Linux triage bundle: journald/system logs, auth/SSH logs, auditd, nginx access/error, cron, selected file metadata and configuration.
- Host-side PCAP and the health endpoint request log.
- Scenario run metadata and sealed ground-truth timeline.
- Linux in-guest memory image using a trusted AVML release, **only if supported and tested**. Collect/store it through the controlled evidence workflow; it may be large.
- Optional libvirt hypervisor memory dump while the VM is running. Check `virsh help dump` and available disk space first; some dump formats are not directly consumable by Volatility.
- Optional powered-off qcow2 copy only if disk analysis is required and storage allows it. Never analyze the live disk in place.
- Screenshots/config outputs proving the isolation gate.

For AVML, use its official upstream release and read its current usage/requirements before running it. Capture one memory source first and verify it exists and is non-zero before starting another large acquisition. If the machine becomes unstable or disk space is low, stop and prioritize logs, PCAP, and chain of custody. Do not claim memory analysis passed if no image was acquired or the format could not be parsed.

After evidence acquisition, stop the capture, record the end timestamp, shut down `SRV-WEB-01`, and do not boot it again until restoring `clean` for a new run. This frees host RAM for processing.

## 10. Evidence ingestion and chain of custody

Never analyze originals. The included tools are starter helpers, not certified forensic evidence-management software.

1. Put acquired files in `evidence/incoming/`.
2. Run `tools/ingest.py` to calculate SHA-256/MD5, assign an evidence ID, copy/move into `evidence/originals/`, and append custody events.
3. Run `tools/verify.py` immediately.
4. Copy each original to `work/<job-id>/`, hash the working copy, and compare with its original before processing.
5. Write output under `results/<evidence-id>/<tool>/` and capture tool version/command/output.
6. Re-run verification before reporting.

Example:

```bash
python3 tools/ingest.py --root /mnt/dfir-evidence --case C01 \
  --type PCAP /mnt/dfir-evidence/evidence/incoming/<run-id>/lab.pcap
python3 tools/verify.py --root /mnt/dfir-evidence
```

Use `--immutable` only on the correct evidence filesystem, typically ext4, and only after validating the tool and restore process. Immutable flags are not a substitute for hashes and backups. Hash the custody log at each session boundary and anchor that hash in a separate read-only location. Demonstrate tamper detection on a copied manifest/log, never by corrupting authoritative evidence.

## 11. Analyze evidence one heavy job at a time

Keep the victim shut down while processing. Check available RAM before each job (`free -h`, `vmstat`, `docker stats`). Do not start Volatility, Plaso, Zeek, and Timesketch all at once.

### 11.1 Volatility 3 (Linux memory, optional)

Install in a host-side Python virtual environment:

```bash
python3 -m venv ~/venvs/volatility3
source ~/venvs/volatility3/bin/activate
python -m pip install --upgrade pip
python -m pip install volatility3
vol -h
```

Test the working copy against the installed version. Linux analysis may require a matching kernel banner/symbol table; do not assume every image works out of the box. Check available Linux plugin names and help for your exact version (examples may include `linux.pslist`, `linux.pstree`, `linux.bash`, `linux.lsof` or network-related plugins). Keep the exact working commands and failures in `docs/commands.md`. Treat `virsh` ELF dumps and AVML output as different acquisition formats; successful capture does not guarantee parser support.

### 11.2 Plaso timeline

Use the official Plaso Docker instructions and pin the tested image/version: https://plaso.readthedocs.io/en/latest/sources/user/Installing-with-docker.html

Dry-run on a sample before the case. Process the Linux triage bundle, selected logs, and filesystem artifacts from a verified working copy. Use `log2timeline` and `psort` as appropriate to the pinned version; exact container paths/options can vary. Export a CSV/JSONL timeline normalized to UTC and save the exact command in `docs/commands.md`.

### 11.3 Zeek

Run Zeek on the PCAP from a fresh output directory:

```bash
mkdir -p /mnt/dfir-evidence/results/C01/zeek
cd /mnt/dfir-evidence/results/C01/zeek
zeek -r /mnt/dfir-evidence/work/<job-id>/lab.pcap
ls -l *.log
```

Expected outputs depend on the captured traffic: commonly `conn.log`, `http.log`, `ssh.log` and `dns.log` where such protocols appear. If the PCAP only includes HTTP and SSH, do not expect DNS or file-transfer logs automatically. Official guide: https://docs.zeek.org/en/current/quickstart.html

### 11.4 YARA

Use the included harmless marker rule against the synthetic sample first. A YARA hit is a lead, not proof of malware. Save the rule version, target hash, command, and output.

### 11.5 Timesketch or CSV fallback

Run Timesketch only after the guest is powered off and the heavy parsers have finished. Cap OpenSearch's heap conservatively and monitor total RAM. The exact environment variables and defaults depend on the pinned Timesketch deployment. If the stack thrashes, OOM-kills services, or exceeds the host budget, stop it and use the normalized Plaso CSV in a spreadsheet/timeline viewer. A defensible timeline is more important than a web UI.

Import/merge Plaso output, Zeek logs, auditd/journald, SSH, nginx and Velociraptor event timestamps where useful. Keep all timezones explicit. Mark known baseline events and attach evidence IDs to findings.

## 12. Findings, IOCs, report and hardening

For each finding, record: ID; plain-language behavior; ATT&CK ID plus a clear label of whether it was executed or only emulated; reconstructed time and uncertainty; original evidence IDs; at least two sources where actually available; relevant IOC(s); confidence/caveats; containment/eradication/recovery recommendations.

Use lab-only indicators: hashes of generated files, `10.10.10.30`, `10.10.10.1`, fake paths, dummy key fingerprint if present, and the health endpoint. Mark every IP/hash as lab-generated so it cannot be mistaken for real threat intelligence.

Only open the sealed ground-truth log after timeline reconstruction. Compare each observed step to the ground-truth time and record misses honestly. Suggested target: detect at least 10 of 12 steps, with detected times within two minutes when timestamps are sufficiently precise. A marker-only step must be marked emulated, not a successful intrusion technique.

The report template should contain:

1. Executive summary and scope.
2. One-guest architecture and network-isolation proof.
3. Scenario steps, tool versions, ATT&CK mapping and emulation limitations.
4. Evidence inventory, SHA-256/MD5, custody, verify output.
5. Unified timeline with evidence references.
6. Findings and IOC register.
7. Synthetic root cause/impact (no claims about a real organization).
8. Detection gaps and memory/parser limitations.
9. Containment, eradication and recovery mapped to findings.
10. Reproducibility, exact commands, snapshots and acceptance tests.
11. Screenshots/log excerpts and appendix.

Before delivery:

```bash
python3 tools/verify.py --root /mnt/dfir-evidence
sudo lynis audit system
git status --short
```

Run gitleaks using the installed version and save the result. Ensure that no `.env`, keys, tokens, PCAP, memory image, evidence bundle or results directory is staged in Git.

## 13. Revised acceptance tests

- **AT-01 Rebuild:** written runbook recreates the one-guest lab; automate Linux setup if time allows.
- **AT-02 Isolation:** guest cannot reach external IP/home LAN; no NAT NIC or forwarding; save XML/route/connection-test proof.
- **AT-03 RAM:** host peak remains under 14 GB; log `free -h`, `vmstat` or Docker stats during incident and analysis phases.
- **AT-04 Evidence integrity:** verification passes; modifying a working copy is detected; originals remain unchanged.
- **AT-05 Custody:** editing a *copied* custody entry breaks verification/hash-chain validation.
- **AT-06 Unit tests:** run included evidence smoke test plus hash/ID/custody checks.
- **AT-07 Detection coverage:** at least 10 of 12 scenario steps have supporting timeline evidence; prefer two sources where available.
- **AT-08 Timing:** reconstructed times are within two minutes of sealed ground truth where the source precision permits it.
- **AT-09 Log-resilience simulation:** the non-destructive evasion marker is detected and independently collected logs remain available; do not claim real log clearing was tested.
- **AT-10 Memory:** if AVML and a hypervisor dump are acquired and supported, compare their relevant artifacts; otherwise document precisely which acquisition/format/plugin was unavailable. Do not carry over the old Windows cross-check criterion.
- **AT-11 Report:** timeline, evidence hashes/custody, IOCs, ATT&CK labels, root cause/impact and mitigation are present.
- **AT-12 Demo:** run the one-guest collection-to-report flow or play a recorded run; include the isolation and integrity proofs.

## 14. Six-week milestones

- **Week 1 — One-guest lab:** isolated network, Linux guest, auditd/journald/SSH/nginx, synthetic data, Velociraptor client, clean snapshot.
- **Week 2 — Acquisition and custody:** PCAP pilot, Velociraptor triage, optional AVML test, evidence ingest/verify and restore/backup test.
- **Week 3 — Scenario dry run:** twelve safe/emulated steps, ground truth, cleanup, expected artifacts and acceptance checks.
- **Week 4 — Analysis:** Plaso, Zeek, YARA, optional Volatility; export normalized CSV; Timesketch only if memory allows.
- **Week 5 — Findings/report:** IOC register, findings, timeline correlation, mitigation and PDF render.
- **Week 6 — Hardening/demo:** full clean-snapshot run, RAM measurements, Lynis/gitleaks, integrity/custody tamper tests, recorded demo and final submission.

If behind, defer in this order: DFIR-IRIS, full Ansible/`dfirctl` automation, Timesketch UI (use CSV), then advanced memory analysis. Do not cut isolation proof, evidence hashing/custody, ground truth, timeline, report, or an end-to-end demo.

## 15. Official documentation

- Libvirt network XML: https://libvirt.org/formatnetwork.html
- Atomic Red Team tests: https://www.atomicredteam.io/docs/atomic-red-team
- Invoke-AtomicRedTeam Linux setup: https://www.atomicredteam.io/docs/invoke-atomicredteam/getting-started
- Velociraptor quickstart: https://docs.velociraptor.app/docs/deployment/quickstart/
- Timesketch installation: https://timesketch.org/guides/admin/install/
- Volatility 3: https://github.com/volatilityfoundation/volatility3
- Plaso Docker: https://plaso.readthedocs.io/en/latest/sources/user/Installing-with-docker.html
- Zeek quickstart: https://docs.zeek.org/en/current/quickstart.html
- YARA CLI: https://yara.readthedocs.io/en/stable/commandline.html
- AVML: https://github.com/microsoft/avml
- libvirt virsh reference: https://www.libvirt.org/manpages/virsh.html
