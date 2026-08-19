# CVE-2026-32252 live PoC

Run this from `bobo5090` while the isolated `poccase040` compose runtime is up:

```bash
cd /mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/10-case_040-chartbrew__chartbrew-CVE-2026-32252-csf_1011bb63c96314324bb32853
./reproduce.sh
```

The program creates two unrelated users and teams, puts a secret-bearing data request in the victim team, and uses the attacker token together with the attacker's team ID in the data-request route. It verifies: (1) the correctly scoped dataset endpoint returns `404`, (2) the unscoped data-request endpoint returns the victim's `Authorization` secret with `200`, and (3) the attacker can update the victim request, which the victim read then confirms. Each run creates a timestamped directory below `runs/` containing raw HTTP response bodies, status codes, and `summary.json`.
