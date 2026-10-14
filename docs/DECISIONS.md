# Architecture Decisions

## 2026-10-13 — Consolidated evidence ingestion on tools/ingest.py

Two evidence-ingest tools existed: `tools/ingest.py` and `dfirctl/custody.py`. They implemented the same chain-of-custody concept with different CLI interfaces and different custody log paths (`tools/ingest.py` writes to `<root>/case/custody.jsonl`; `dfirctl/custody.py` wrote to `<root>/evidence/custody.jsonl`).

Consolidated on `tools/ingest.py` because:
- It matches the implementation guide's command shape (§10)
- Writes a separate `manifest.jsonl` for evidence inventory
- Refuses to extend a broken custody chain (validates before appending)
- Gates `chattr +i` behind `--immutable` flag (per guide guidance)
- `tools/verify.py` already reads the paths `ingest.py` writes (`<root>/case/manifest.jsonl` and `<root>/case/custody.jsonl`)

The alternative is preserved at `dfirctl/_deprecated/custody.py` for reference.

## 2026-10-13 — --immutable flag usage

Per the implementation guide: "Use `--immutable` only on the correct evidence filesystem, typically ext4, and only after validating the tool and restore process."

- First ingest (Block 6): run **without** `--immutable`. Verify. Then manually `chattr +i` if desired, or redo with the flag.
- All subsequent ingests: use `--immutable`.

This keeps the tamper-test path (AT-04) simple — you can modify a working copy without needing `chattr -i` on the original.

**Edge case**: If `chattr +i` succeeds but the subsequent manifest/custody write fails, the original is stuck immutable with no rollback.

Recovery: `sudo chattr -i <file>`, then investigate, then re-run.

Added to docs/runbook.md under "if ingest partially fails.

## 2026-10-13 — Velociraptor deferred

Velociraptor deployment was scoped out to preserve time budget for the
evidence pipeline. Fallback: `tools/collect-guest-logs.sh` performs
a tar+scp of journald, auditd, nginx, cron, and syslog from
SRV-WEB-01 to the evidence store. This covers the expected_sources
listed for S04 (auditd-execve, journald) and S08 (auditd-cron-watch,
cron-log, file-metadata, Velociraptor-triage) in case_id C01.
Velociraptor-triage is marked unavailable in the report.

## 2026-10-13 — Collector pipeline and baseline snapshot rev2

Silent failure: initial guest-log collection used `ssh ... sudo tar` without
a TTY. sudo could not prompt, stdout was empty, and `2>/dev/null` masked the
cause. Fix: dedicated script `/usr/local/sbin/dfir-collect-logs`, passwordless
sudo scoped to that exact command, SSH key auth (host key at
`~/.ssh/dfir_lab_key`). Host-side wrapper `tools/collect-guest-logs.sh` uses
the guest IP directly and rejects tarballs under 4 KiB.

Also fixed: `/var/log/cron.log` does not exist on Ubuntu Server 24.04 (cron
logs go to syslog/journald). Removed from the collection path list. tar now
uses `--warning=no-file-changed --ignore-failed-read` because auditd writes
while tar reads.

Baseline snapshot `avant_attaque` retaken after these fixes. The previous
snapshot predated them and would have required a manual re-setup after every
restore.


## 2026-10-14 — S02 ground truth reconstructed

During the first complete scenario run, S02 (benign shell execution marker)
was executed in the guest but its ground-truth append was missed on the
host. The artifact /tmp/dfir-lab-s02.log was confirmed to exist inside the
guest and contains the timestamp the command wrote into it at execution
time. S02's start/end in ground-truth-sealed.jsonl were reconstructed from
that artifact. This is documented as a ground-truth recording method, not
as ground truth recorded live. Method: read the timestamp from the guest
file, append via gt-append.sh with an explicit note, re-sort the JSONL by
step_id, re-hash and seal.

## 2026-10-14 — S02 ground truth reconstructed from auditd

S02 (benign shell execution marker) was executed in the guest during the
first complete scenario run, but its ground-truth append was missed on the
host. Reconstruction source: auditd EXECVE record `1791932549.775:1723`
(`sudo tee -a /tmp/dfir-lab-s02.log`), extracted from the guest-logs triage
bundle. S02 start/end in ground-truth-sealed.jsonl were set to the
converted UTC time from that audit record. AT-08 timing comparison for S02
is marked as reconstructed rather than observed. Detection coverage:
11 of 12 steps observed live, 1 reconstructed from an independent source.

## 2026-10-14 — S03 health endpoint returned 404, not 200

S03 sends GET requests to `http://10.10.10.1:8888/health?seq=N`. The lab
health server matches on exact path `/health` and does not strip query
strings, so all 5 requests were answered 404 ("Only /health is available").
Evidence is unaffected: PCAP captured all 5 TCP sessions, the host health
log recorded all 5 with source 10.10.10.30 and UTC timestamps, and Zeek
will produce conn/http entries for each. The emulated network behavior
(S03 = T1071.001) is demonstrated by the traffic, not the response code.
Root cause: query string was added to the scenario command to disambiguate
each request in logs, without accounting for the server's strict path
match. This is documented as-is; no re-run is performed because the
evidence chain is complete.