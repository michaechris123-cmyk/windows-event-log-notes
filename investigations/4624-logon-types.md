# 4624 — Successful Logon & Logon Types

## Scenario
Filtered Security log to Event ID 4624 on a local Windows 11 workstation.
Reviewed a representative Type 5 (service) logon in detail.

## Sample event decoded

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
| Computer | DESKTOP-QGA4BCO | Local workstation |

## Verdict
Benign. `services.exe` starting a Windows service as SYSTEM with Logon Type 5 is normal OS behavior and appears dozens of times per day.

## Logon Type reference

| Type | Meaning | Typical source | Suspicious indicator |
|---|---|---|---|
| 2 | Interactive | Physical keyboard | Rarely — trusted baseline |
| 3 | Network | SMB, PSExec, share access | External IP, odd account, lateral movement |
| 4 | Batch | Scheduled task | Rare — unexpected tasks |
| 5 | Service | Windows services (services.exe) | Almost never — normal OS |
| 10 | RemoteInteractive | RDP | External IP, off-hours, repeated attempts |

## Why this matters
A Type 5 logon by SYSTEM might look alarming without context, but it is the standard signature of Windows starting a service. Recognizing this prevents false positives.

## What WOULD be suspicious
- Type 3 or 10 with a **remote source IP**
- `SYSTEM` or a service account authenticating **over the network**
- Logon Process = `NtLmSsp` / `Kerberos` on an account that should only run locally
- Many Type 10 logons to a single machine in a short window
