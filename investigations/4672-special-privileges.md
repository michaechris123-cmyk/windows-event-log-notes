# 4672 — Special Privileges Assigned to New Logon

## Why 4672 matters
Fires whenever an account logs on with admin-level privileges.
Primary detection for privilege escalation, credential dumping prep,
and token theft — but noisy on SYSTEM, so filter by account

## Baseline (this machine, 500-event window)

| Account | Count | Interpretation |
|---|---|---|
| SYSTEM | 472 | Normal — OS lifecycle, services, boot |
| oriso | 10 | Local user — elevated PowerShell/admin actions |
| DWM-1 | 6 | Desktop Window Manager virtual account (Session 1) |
| DWM-2 | 4 | DWM (Session 2) |
| NETWORK SERVICE | 3 | Standard Windows service account |
| LOCAL SERVICE | 3 | Standard Windows service account |
| DWM-3 | 2 | DWM (Session 3) |

## Sample event decoded (SYSTEM)

| Field | Value | Meaning |
|---|---|---|
| Event ID | 4672 | Special privileges assigned |
| Account Name | SYSTEM | Highest privilege built-in account |
| Account Domain | NT AUTHORITY | Local system authority |
| Logon ID | 0x3E7 | Canonical SYSTEM session identifier |
| Computer | my pc | Local workstation |

## Privileges observed (SYSTEM default set)

SeAssignPrimaryTokenPrivilege, SeTcbPrivilege, SeSecurityPrivilege,
SeTakeOwnershipPrivilege, SeLoadDriverPrivilege, SeBackupPrivilege,
SeRestorePrivilege, SeDebugPrivilege, SeAuditPrivilege,
SeSystemEnvironmentPrivilege, SeImpersonatePrivilege,
SeDelegateSessionUserImpersonatePrivilege

## Verdict
Benign. Baseline matches a clean Windows 11 workstation — SYSTEM
dominant, DWM virtual accounts present (expected), local user has
10 elevated events matching lab admin activity.

## DWM virtual accounts 
`DWM-1`, `DWM-2`, `DWM-N` are per-session virtual accounts used by
the Desktop Window Manager (dwm.exe). They are auto-created, have no
password, and appear in 4672 normally.

**Detection value:** legitimate DWM is `dwm.exe` in `C:\Windows\System32`.
Malware masquerading as DWM (e.g. `DWM-1.exe` from `%TEMP%`) or DWM
making network connections / spawning shells = high-confidence compromise.

## Privilege reference

| Privilege | Meaning | Suspicious when |
|---|---|---|
| SeDebugPrivilege | Read/write any process memory | Non-admin or unexpected user (Mimikatz, LSASS dump) |
| SeTcbPrivilege | Act as part of OS | Any non-SYSTEM account |
| SeImpersonatePrivilege | Impersonate another user | Non-service user (Potato privesc) |
| SeAssignPrimaryTokenPrivilege | Assign tokens to processes | Non-SYSTEM |
| SeBackupPrivilege | Bypass ACLs for backup | Non-backup account (SAM/SYSTEM hive read) |
| SeRestorePrivilege | Bypass ACLs for restore | Non-SYSTEM |
| SeLoadDriverPrivilege | Load kernel drivers | Non-SYSTEM (rootkit install) |
| SeTakeOwnershipPrivilege | Take ownership of any object | Non-admin user |
| SeSecurityPrivilege | Manage audit logs | Any unexpected account |
| SeSystemEnvironmentPrivilege | Modify firmware env | Non-SYSTEM |
| SeDelegateSessionUserImpersonatePrivilege | Delegate impersonation | Non-service account |
| SeAuditPrivilege | Generate security audits | Non-SYSTEM |

## Detection strategy
- Baseline SYSTEM counts (should dominate)
- Alert on non-SYSTEM, non-service, non-DWM accounts receiving
  SeDebugPrivilege or SeImpersonatePrivilege
- Alert on SeTcbPrivilege outside of boot window
- Correlate with 4624 — 4672 immediately after a suspicious 4624 is high signal
- Alert on DWM-* spawning child processes or making network connections

## Reusable command
See [`powershell/4672-special-privileges-summary.ps1`](../powershell/4672-special-privileges-summary.ps1)
