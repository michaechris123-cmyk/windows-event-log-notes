# 7045 — Service Installed

## Why 7045 matters
Service installation is the #1 persistence mechanism on Windows.
Every installed service generates a 7045 event in the **System** log
(not Security — common beginner mistake).

Malware, PsExec, and C2 frameworks all use this to survive reboots
and run with SYSTEM privileges.

## Sample event decoded

| Field | Value | Interpretation |
|---|---|---|
| Event ID | 7045 | Service installed |
| Log Name | System | Not Security — important distinction |
| Source | Service Control Manager | SCM installed it |
| User | SYSTEM | Installed by a SYSTEM-level process |
| Service Name | Wazuh | Internal service name |
| Service File Name | "C:\Program Files (x86)\ossec-agent\wazuh-agent.exe" | Binary path |
| Service Type | user mode service | Runs in user space |
| Service Start Type | auto start | Persists across reboot |
| Service Account | LocalSystem | Highest privilege |

## Verdict
Benign. Wazuh is a known open-source HIDS agent installed in its
standard location (`Program Files (x86)\ossec-agent\`). Path, service
name, and binary all match the legitimate product.

## Why this is still a useful example
The event has all the characteristics a malicious service would use:
- `auto start` (persistence)
- `LocalSystem` (highest privilege)
- SYSTEM-level installation

Detection value comes from the **Service File Name** — the same event
pointing at `C:\Users\Public\svc.exe` or `\\attacker\share\payload.exe`
would be a confirmed compromise.

## Suspicious service path patterns

| Path pattern | Why suspicious |
|---|---|
| C:\Users\* | User profiles — services shouldn't live here |
| %TEMP%, C:\Windows\Temp | Staging directories for malware |
| C:\Users\Public | Public writable — common malware location |
| C:\ProgramData\* | Often writable, used for staging |
| \\server\share\* | UNC path — PsExec / lateral movement |
| C:\Windows\System32\cmd.exe /c ... | Service running a shell |
| powershell.exe -enc ... | Service running encoded payload |
| Unquoted path with spaces | Service path hijacking vector |
| svchost / lsass / winlogon typos | Masquerading |

## Known malicious service names
- `PSEXESVC` — PsExec execution (lateral movement)
- `PAExec` — PsExec clone
- Random strings with `Svc` / `Service` suffix in user directories

## Detection strategy
- Baseline installed services per machine
- Alert on any 7045 with Service File Name outside `C:\Windows\` and `C:\Program Files\`
- Alert on UNC paths (`\\*`)
- Alert on service names matching known offensive tools
- Correlate 7045 with a preceding suspicious 4688 (sc.exe / installutil)

## Reusable command
See [`powershell/7045-service-install-summary.ps1`](../powershell/7045-service-install-summary.ps1)
