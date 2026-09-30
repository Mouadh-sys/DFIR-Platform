# DFIR Platform Architecture Record

This file is the milestone record for the implementation. The detailed system
specification remains in [`architecture.md`](architecture.md); this record tracks
changes made at each approved checkpoint.

## M0 — 2026-09-30

- Confirmed the five-layer, one-way pipeline, two-phase runtime model, and `dfirctl`
  ownership described in `architecture.md`.
- Confirmed host prerequisites and release pins in [`PLAN.md`](PLAN.md).
- Recorded `/srv/dfir` as an unresolved storage prerequisite; evidence must never use
  the repository or the nearly-full root filesystem.
- Recorded that all service images, guest ISOs, and processing tools require immutable
  version/checksum records before deployment.

## Required invariants

- The lab uses a libvirt isolated network only; no NAT, Internet route, or home-LAN route.
- Originals are immutable and processed only through verified working copies.
- Incident and analysis services are separated with Compose profiles to stay within the
  16 GiB host budget.
- `dfirctl` performs forensic orchestration and logging; Ansible performs provisioning
  only.
