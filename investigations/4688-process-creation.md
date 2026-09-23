# 4688 — Process Creation

## Sample event (Event Viewer)

![4688 process creation](screenshots/4688-process-creation.png)

*`whoami.exe` spawned by `powershell.exe` from an elevated session — normal recon.*

## Why 4688 matters
Every executable launched on Windows generates a 4688 event.
It is the primary native source for detecting malicious execution —
if you can read 4688, you can catch LOLBins, encoded PowerShell,
macro execution, and living-off-the-land attacks.

## Prerequisite — command-line auditing
By default, 4688 logs the process name but NOT the command line.
Enabled with:

    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
      /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

Verified with `auditpol /get /subcategory:"Process Creation"`
→ Setting: Success and Failure

## Sample event decoded

| Field | Value | Meaning |
|---|---|---|
| Event ID | 4688 | Process creation |
| Creator Subject → Account Name | oriso | Local user who launched the process |
| Creator Subject → Account Domain | my desktop | Local machine |
| Creator Subject → Logon ID | 0x1EB2D | Session identifier |
| New Process Name | C:\Windows\System32\whoami.exe | The process that launched |
| Creator Process Name | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | Parent process |
| Process Command Line | "C:\Windows\System32\whoami.exe" | Full command executed |
| Token Elevation Type | %%1937 | Limited token with admin approval |
| Mandatory Label | High Mandatory Level | Elevated execution |
| Target Subject → Account Name | NULL SID | Normal for process creation |

## Verdict
Benign. User ran `whoami` from an elevated PowerShell session.
Parent-child relationship (powershell.exe → whoami.exe) is expected.

## Parent-child relationships — the detection gold

| Parent | Child | Verdict |
|---|---|---|
| explorer.exe | cmd.exe | Normal — user opened terminal |
| explorer.exe | chrome.exe | Normal — user launched browser |
| powershell.exe | whoami.exe | Normal — recon from shell |
| **winword.exe** | **cmd.exe** | SUSPICIOUS — macro execution |
| **outlook.exe** | **powershell.exe** | SUSPICIOUS — phishing payload |
| **services.exe** | **cmd.exe /c ...** | SUSPICIOUS — service-based persistence |
| **w3wp.exe (IIS)** | **powershell.exe** | SUSPICIOUS — web shell |
| **excel.exe** | **rundll32.exe** | SUSPICIOUS — macro spawns DLL |

## Suspicious command-line patterns

| Pattern | Why suspicious |
|---|---|
| `powershell.exe -enc <base64>` | Encoded payload |
| `powershell.exe -nop -w hidden -c ...` | Hidden window, no profile |
| `cmd.exe /c certutil -urlcache -f http://...` | Download via LOLBin |
| `net user /add attacker P@ssw0rd` | Persistence via new local user |
| `net localgroup administrators attacker /add` | Privilege escalation |
| `schtasks /create /sc onlogon ...` | Scheduled task persistence |
| `reg add HKCU\...\Run` | Registry Run key persistence |
| `rundll32.exe javascript:...` | JavaScript via DLL host |
| `mshta.exe http://...` | HTA execution from remote |
| `wmic process call create ...` | Remote process execution |

## Token Elevation Type reference

| Value | Meaning |
|---|---|
| %%1936 | Full token (UAC disabled or SYSTEM) |
| %%1937 | Limited token with admin approval (UAC elevated) |
| %%1938 | Default token (standard user) |

## Reusable command
See [`powershell/4688-process-creation-summary.ps1`](../powershell/4688-process-creation-summary.ps1)
