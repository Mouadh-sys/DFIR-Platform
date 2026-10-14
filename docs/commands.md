# Commands used in the actual run

Copy commands that have been tested in this exact environment here. Record UTC timestamp, user/operator, tool version, exit code, and output reference. Never put passwords, access tokens, private keys, or sensitive evidence in this file.

| Step | UTC | Command | Tool/version | Exit status | Output/evidence ID |
|---|---|---|---|---|---|
| TODO | TODO | TODO | TODO | TODO | TODO |


# Guest log collection
ssh srv-web-01@10.10.10.30 'sudo /usr/local/sbin/dfir-collect-logs' > dest.tar.gz
# or via wrapper (preferred, includes size check):
cd ~/Projects/dfir-platform
./tools/collect-guest-logs.sh <run-id>

# Restore baseline
virsh snapshot-revert SRV-WEB-01 avant_attaque

# Reconstruct a missed ground truth entry from an auditd EXECVE record
sudo grep -a "dfir-lab-s02" /tmp/dfir-extract/var/log/audit/audit.log
# Extract the audit(<epoch>.<ms>:<id>) value, then:
date -u -d @<epoch> +%FT%TZ

# Plaso — actual working commands (2026-10-14)
docker run --rm \
  -v "$(pwd)/input:/input:ro" \
  -v "$(pwd)/output:/output" \
  log2timeline/plaso:latest \
  log2timeline.py --storage-file /output/timeline.plaso /input

docker run --rm \
  -v "$(pwd)/output:/output" \
  log2timeline/plaso:latest \
  psort.py -o json_line -w /output/timeline.jsonl /output/timeline.plaso

# Zeek on virbr-lab captures (2026-10-14)
# NOTE: -C is required. virbr-lab captures contain packets whose TCP checksums
# appear invalid because the capturing bridge sees packets before the guest's
# virtio NIC computes checksums. Without -C, Zeek discards most application
# payloads and http.log/ssh.log are not produced.
zeek -C -r lab.pcap