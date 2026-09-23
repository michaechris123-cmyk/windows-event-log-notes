# Summarise Windows Security Event 4624 by LogonType
# Usage: run in elevated PowerShell
# Output: count of logon events grouped by Logon Type

Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
      Time      = $_.TimeCreated
      LogonType = ($xml.Event.EventData.Data | Where-Object Name -eq 'LogonType').'#text'
      Account   = ($xml.Event.EventData.Data | Where-Object Name -eq 'TargetUserName').'#text'
      SourceIP  = ($xml.Event.EventData.Data | Where-Object Name -eq 'IpAddress').'#text'
    }
  } |
  Group-Object LogonType |
  Select-Object Name, Count |
  Sort-Object Count -Descending
