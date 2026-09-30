# DFIR Platform Delivery Plan

## M0 — host and repository baseline

**Inspection date:** 2026-09-30

### Host findings

| Area | Observed |
| --- | --- |
| OS | Pop!_OS 24.04 LTS (Ubuntu Noble), x86_64 |
| Kernel | 7.1.5-76070105-generic |
| CPU | Intel Core i5-11300H, 4 cores / 8 threads, VT-x (`vmx`) available |
| Memory | 15 GiB physical; 8.9 GiB used and 6.5 GiB available during inspection |
| Swap | 14.6 GiB encrypted swap plus 15.4 GiB zram |
| Root filesystem | 233 GiB ext4, 183 GiB used, 39 GiB available |
| Evidence mount | `/srv/dfir` does not exist and no dedicated evidence filesystem is mounted |
| Existing libvirt guests | `kali`, `rhel10.1`, `ubuntu24.04`, `win10`, all powered off |
| Existing libvirt networks | `default` is active and autostarted |
| libvirt | 10.0.0; `qemu:///system` is reachable |
| virt-manager | 4.1.0 |
| Docker Engine | 29.1.3 |
| Docker Compose | 2.40.3 |
| Ansible | Not installed; Noble candidate is 9.2.0+dfsg-0ubuntu5 |
| Python | 3.12.3 (meets the Python 3.11+ requirement) |
| nftables | 1.0.9 |
| Pandoc | Not installed; Noble candidate is 3.1.3+ds-2 |

No `sudo` command, package installation, network change, VM change, or evidence-path
change was performed during M0.

### Intended pins

Pins are recorded here before implementation. Container image digests will be recorded
alongside these tags when the images are first pulled; mutable `latest` tags are forbidden.

| Component | Intended pin | Installation/runtime |
| --- | --- | --- |
| Host OS baseline | Pop!_OS 24.04 LTS / Ubuntu Noble | Existing host |
| libvirt | 10.0.0-2ubuntu8.19 | Existing apt package |
| virt-manager | 4.1.0-3ubuntu0.1 | Existing apt package |
| Docker Engine | 29.1.3-0ubuntu3~24.04.2 | Existing apt package |
| Docker Compose | 2.40.3+ds1-0ubuntu1~24.04.1 | Existing Compose v2 plugin |
| Ansible | 9.2.0 / ansible-core 2.16 series | apt package, after approval |
| Python | 3.12.3 | Host venv |
| Typer | 0.27.2 | `dfirctl` venv |
| libvirt-python | 12.7.0 | `dfirctl` venv |
| Volatility 3 | 2.28.2 | Host venv |
| Plaso | 20260720 | One-shot container |
| Zeek | 9.0.0 | One-shot container |
| YARA Python bindings | 4.5.4 | Host venv |
| Jinja2 | 3.1.6 | `dfirctl` venv |
| Velociraptor | 0.77.2 | Pinned container/binary release |
| Timesketch | 20260630 | Pinned Compose image/release |
| DFIR-IRIS | 2.4.29 | Pinned Compose image/release |
| Caldera | 5.3.0 | Optional pinned Compose image |
| nftables | 1.0.9-1ubuntu0.1 | Existing apt package |
| Pandoc | 3.1.3+ds-2 | apt package, after approval |
| Linux guest | Ubuntu Server 24.04.3 LTS | Official ISO, checksum recorded before use |
| Windows guest | Windows 11 Enterprise Evaluation 24H2 | Official evaluation ISO, checksum recorded after manual download |

The release pins above were checked against the projects' official GitHub release
metadata and PyPI project metadata on the inspection date. Before deployment, image
digests and the official ISO checksums are mandatory additions to this file.

### Conflicts and blockers

1. `/srv/dfir` is absent, while the root filesystem has only about 39 GiB free. The
   required dedicated partition or external SSD path must be supplied and mounted before
   provisioning or evidence acquisition.
2. Ansible and Pandoc are absent and require an approved `sudo` installation.
3. The apt `qemu-kvm` and `docker-compose-plugin` package names have no candidate on
   this host, although QEMU and Compose v2 are already available through other packages.
   We will use the existing binaries and pin their observed package versions rather than
   install alternate repositories without approval.
4. Existing libvirt guests and the autostarted `default` network must not be changed
   implicitly. M1 will define only the new `lab-isolated` network and will require
   explicit approval before host firewall or libvirt changes.
5. The existing `docs/architecture.md` is a large lowercase specification. The required
   milestone records use `docs/ARCHITECTURE.md`; both will be kept consistent until the
   documentation naming is normalized deliberately.

### Milestone gates

| Milestone | Deliverable | Gate |
| --- | --- | --- |
| M0 | This plan and host baseline | Approval of pins, blockers, and evidence path |
| M1 | Host role, isolated network, nftables, evidence filesystem | Show `virsh net-info`, nftables ruleset, disk layout |
| M2 | Both VMs, provisioning, and clean snapshots | Reachability limited to the stated rules |
| M3 | Compose services and measured phase memory | `free -h` output for both phases |
| M4 | `dfirctl` core and evidence tests | Hash and custody tamper tests pass |
| M5 | Dry-run scenario and collection | User approval before any real scenario |
| M6 | Processing, IOC extraction, and case integrations | Timeline and case records populated |
| M7 | Report and runbook | Acceptance suite and final report inputs |

M0 stops here pending approval. No host mutation is authorized by this document.
