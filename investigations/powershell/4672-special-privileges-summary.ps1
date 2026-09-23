# 4672-special-privileges-summary.ps1
# Summarise Event 4672 (Special Privileges Assigned) by account.
# Requires elevated PowerShell.
# Output: count of 4672 events grouped by SubjectUserName.

Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672} -MaxEvents 500 |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
      Account = ($xml.Event.EventData.Data | Where-Object Name -eq 'SubjectUserName').'#text'
      Domain  = ($xml.Event.EventData.Data | Where-Object Name -eq 'SubjectDomainName').'#text'
      LogonID = ($xml.Event.EventData.Data | Where-Object Name -eq 'SubjectLogonId').'#text'
    }
  } |
  Group-Object Account |
  Select-Object Name, Count |
  Sort-Object Count -Descending
