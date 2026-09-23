# 4624 — Successful Logon & Logon Types

## Scenario
Enumerated all Event ID 4624 events in the Security log on a standalone
Windows 11 workstation using PowerShell + XML parsing, then grouped by
LogonType to establish a baseline.

## Baseline (this machine)

| Logon Type | Meaning | Count | Verdict |
|---|---|---|---|
| 5 | Service | 1064 | Normal — services.exe starting services as SYSTEM |
| 2 | Interactive | 89 | Normal — local keyboard logons + UAC |
| 7 | Unlock | 8 | Normal — workstation screen unlocks |
| 3 | Network | 0 | Expected — no SMB shares in use |
| 10 | RemoteInteractive | 0 | Expected — no RDP |

## Representative event decoded (Type 5)

| Field | Value | Interpretation |
|---|---|---|
| Event ID | 4624 | Successful logon |
| Logon Type | 5 | Service — not a human |
| Account Name | SYSTEM | Built-in highest-privilege account |
| Account Domain | NT AUTHORITY | Local system authority |
| Impersonation Level | Impersonation | Acting on behalf of SYSTEM |
| Elevated Token | Yes | Running with full privileges |
| Process Name | C:\Windows\System32\services.exe | Service Control Manager |
| Source Network Address | - | Local only, no network |

## Verdict
Benign. Type 5 with services.exe + SYSTEM is standard Windows behavior
and dominates the count. The absence of Type 3/10 is expected on a
standalone workstation — if either appeared, it would warrant review.

## Logon Type reference

| Type | Meaning | Typical source | Suspicious when |
|---|---|---|---|
| 2 | Interactive | Physical keyboard | Rarely |
| 3 | Network | SMB, PSExec, share access | External IP, off-hours, unexpected |
| 4 | Batch | Scheduled task | Unexpected scheduled tasks |
| 5 | Service | Windows services (services.exe) | SYSTEM over network |
| 7 | Unlock | Workstation unlock | Never — normal |
| 10 | RemoteInteractive | RDP | External IP, off-hours, brute force pattern |

## Reusable command
See [`powershell/4624-logon-type-summary.ps1`](../powershell/4624-logon-type-summary.ps1)
