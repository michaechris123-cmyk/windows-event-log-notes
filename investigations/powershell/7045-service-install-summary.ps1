# 7045-service-install-summary.ps1
# Summarise Event 7045 (Service Installed) from the System log.
# Requires elevated PowerShell.
# Output: service name, binary path, start type, account.

Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} -MaxEvents 50 |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
      Time        = $_.TimeCreated
      ServiceName = ($xml.Event.EventData.Data | Where-Object Name -eq 'ServiceName').'#text'
      ImagePath   = ($xml.Event.EventData.Data | Where-Object Name -eq 'ImagePath').'#text'
      StartType   = ($xml.Event.EventData.Data | Where-Object Name -eq 'StartType').'#text'
      Account     = ($xml.Event.EventData.Data | Where-Object Name -eq 'AccountName').'#text'
    }
  } | Format-Table -AutoSize -Wrap
