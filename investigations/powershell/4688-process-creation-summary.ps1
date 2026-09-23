# 4688-process-creation-summary.ps1
# Summarise Windows Security Event 4688 (Process Creation) with command lines.
# Requires command-line auditing enabled:
#   reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
#     /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
#   auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
#
# Usage: run in elevated PowerShell

Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 50 |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
      Time        = $_.TimeCreated
      User        = ($xml.Event.EventData.Data | Where-Object Name -eq 'SubjectUserName').'#text'
      NewProcess  = Split-Path ($xml.Event.EventData.Data | Where-Object Name -eq 'NewProcessName').'#text' -Leaf
      ParentProc  = Split-Path ($xml.Event.EventData.Data | Where-Object Name -eq 'ParentProcessName').'#text' -Leaf
      CommandLine = ($xml.Event.EventData.Data | Where-Object Name -eq 'CommandLine').'#text'
    }
  } | Format-Table -AutoSize -Wrap
