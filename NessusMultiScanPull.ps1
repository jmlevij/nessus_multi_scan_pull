<#
ScriptName: NessusMultiScanPull.ps1
Purpose:    PowerShell script that uses REST methods to obtain and export Nessus scan reports in html, csv, and .nessus formats.
Created:    Updated in October 2024.
Comments:   Portions of this script are derived from the works of Pwd9000-ML under the GPL license.
Author:     James Levija
GitHub:     https://github.com/jmlevij
Attribution: Portions of this code are based on:
             - [Pwd9000-ML/NessusV7-Report-Export-PowerShell](https://github.com/Pwd9000-ML/NessusV7-Report-Export-PowerShell), licensed under [GNU General Public License (GPL)](https://www.gnu.org/licenses/gpl-3.0.html).
             The original code has been modified and integrated to create this version.
#>

param (
    # Enter Nessus Server URL
  [string]$Server = "https://localhost:8834"
)

# Prompt user for Nessus API keys if not set in environment variables
$AccessKey = [System.Environment]::GetEnvironmentVariable("NESSUS_ACCESS_KEY")
$secretKey = [System.Environment]::GetEnvironmentVariable("NESSUS_SECRET_KEY")

if (-not $AccessKey) {
    $AccessKey = Read-Host "Enter Nessus Access Key"
    if (-not $AccessKey) {
      Write-Host -Fore Red "Nessus Access Key is required. Exiting..."
      exit 1
    }
  }
  
  if (-not $secretKey) {
    $secretKey = Read-Host "Enter Nessus Secret Key"
    if (-not $secretKey) {
      Write-Host -Fore Red "Nessus Secret Key is required. Exiting..."
      exit 1
    }
  }

  function Get-ApiHeaders {
    param (
      [string]$ContentType = "application/json"
    )
    $headers = @{
      "accept" = "application/json"
      "X-ApiKeys" = "accessKey=$AccessKey;secretKey=$secretKey"
    }
    if ($ContentType) {
      $headers["content-type"] = $ContentType
    }
    return $headers
  }

  # Retrieving the list of scans
  function Fetch-ScanDetails {
    Write-Host -Fore Cyan "[!] Fetching Scan Details..."
    $ScanURI = "$Server/scans"
    try {
      $response = Invoke-WebRequest -Uri $ScanURI -SkipCertificateCheck -Method GET -Headers (Get-ApiHeaders)
      return ConvertFrom-Json $response.Content | Select-Object -expand "scans"
    }
    catch {
      Write-Host -Fore Red "Error fetching scan details: $($_.Exception.Message)"
      return $null
    }
  }

  # Displays the list of scans
  function Display-ScanInfo {
    param (
      [psobject]$result
    )
    $ScanName = $result | Select-Object -expand "name"
    Write-Host "[!] Scan Name is:" -NoNewline; Write-Host -Fore DarkCyan "$ScanName"

    $ID = $result | Select-Object -expand "id"
    Write-Host "[!] Scan ID is:" -NoNewline; Write-Host -Fore DarkCyan "$ID"

    $ScanStatus = $result | Select-Object -expand "status"
    Write-Host "[!] Scan Status is:" -NoNewline; Write-Host -Fore DarkCyan "$ScanStatus"

    $ScanStartDate = $result | Select-Object -expand "creation_date"
    $readableDate = [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($ScanStartDate))
    Write-Host "[!] Scan Start Date is:" -NoNewline; Write-Host -Fore DarkCyan "$readableDate"

    $ScanModDate = $result | Select-Object -expand "last_modification_date"
    $readableModDate = [System.TimeZoneInfo]::ConvertTimeFromUtc(([datetime]'1970-01-01').AddSeconds($ScanModDate), [System.TimeZoneInfo]::Local)
    Write-Host "[!] Scan Last Modified Date is:" -NoNewline; Write-Host -Fore DarkCyan "$readableModDate"

    $ScanOwner = $result | Select-Object -expand "owner"
    Write-Host "[!] Scan Owner is:" -NoNewline; Write-Host -Fore DarkCyan "$ScanOwner"

    Write-Host ""
    Write-Host ""
  }

  # Scan Export Function
  function Export-Scan {
    param (
      [string]$ID,
      [string]$Format
    )
    Write-Host -Fore Cyan "[!] Exporting Scan..."
    $ExportURI = "$Server/scans/$ID/export"
    $ExportBody = @"
{
  "format": "$Format",
  "chapters": "vuln_hosts_summary"
}
"@
    $response = Invoke-WebRequest -Uri $ExportURI -SkipCertificateCheck -Method POST -Headers (Get-ApiHeaders "application/json") -ContentType 'application/json' -Body $ExportBody
    if ($response.statuscode -eq '200') {
      return ConvertFrom-Json $response.Content | Select-Object -expand "file"
    }
    else {
      Write-Host -Fore DarkCyan "[!] Export Not Successful Check Credentials"
      exit 1
    }
  }

  # Check Export Status
  function Check-ExportStatus {
    param (
      [string]$ID,
      [string]$fileID
    )
    $StatusURI = "$Server/scans/$ID/export/$fileID/status"
    while ($true) {
      try {
        Write-Host -Fore Cyan "[!] Checking Export Status..."
        $response = Invoke-WebRequest -Uri $StatusURI -SkipCertificateCheck -Method GET -Headers (Get-ApiHeaders)
        if ($response.statuscode -eq '200') {
          $keyValueStatus = ConvertFrom-Json $response.Content | Select-Object -expand "status"
          Write-Host -Fore DarkCyan "[*] Export Status is: $keyValueStatus"
          if ($keyValueStatus -eq 'ready') {
            return
          }
          else {
            Write-Host -Fore Cyan "[!] Waiting for export to be ready..."
          }
        }
      }
      catch {
        Write-Host "Error: $($_.Exception.Message). Retrying in 60 seconds..."
      }
      Start-Sleep -Seconds 60
    }
  }

  function Download-ScanExport {
    param (
      [string]$ID,
      [string]$fileID,
      [string]$SaveFile
    )
    Write-Host -Fore DarkCyan "[*] Starting Download!"
    $DownloadURI = "$Server/scans/$ID/export/$fileID/download"
    Invoke-WebRequest -Uri $DownloadURI -Method GET -SkipCertificateCheck -Headers (Get-ApiHeaders "application/octet-stream") -OutFile $SaveFile
    Write-Host -Fore DarkCyan "[!] Download Completed!"
  }

  # Main Logic
  $keyValueScan = Fetch-ScanDetails
if (-not $keyValueScan) {
  Write-Host -Fore Red "Failed to fetch scan details. Exiting..."
  exit 1
}
  $completedScans = $keyValueScan | Where-Object { $_.status -eq 'completed' }
  $notCompletedScans = $keyValueScan | Where-Object { $_.status -ne 'completed' }

  # Show the completed and not completed scans
  Write-Host "-------------------------------------------------------" -ForegroundColor Green
  Write-Host "-The following scans are Completed and can be exported-" -ForegroundColor Green
  Write-Host "-------------------------------------------------------" -ForegroundColor Green
  $completedScans | Format-Table -Property name, status, id -AutoSize

  Write-Host "---------------------------------------------------------------------" -ForegroundColor Red
  Write-Host "-The following scans have issues and cannot be exported-" -ForegroundColor Red
  Write-Host "---------------------------------------------------------------------" -ForegroundColor Red
  $notCompletedScans | Format-Table -Property name, status, id -AutoSize

  # Prompt user to export completed scans
  do {
    $answerexport = Read-Host "Do you want to export the completed scans? (Y/N)"
  } while ($answerexport -ne "Y" -and $answerexport -ne "N")
  
  If ($answerexport -eq "Y") {
    foreach ($result in $completedScans) {
      Display-ScanInfo -result $result

      $ScanName = $result | Select-Object -expand "name"
      $ID = $result | Select-Object -expand "id"
      $scanFolderPath = Join-Path -Path ".\Nessus Reports" -ChildPath "$ScanName"
      if (-not (Test-Path $scanFolderPath)) {
        New-Item -ItemType Directory -Path $scanFolderPath | Out-Null
      }

      # Export and download for each format
      foreach ($Format in @("html", "csv", "nessus")) {
        $ExportFileName = "$ScanName`_$(Get-Date -format 'yyyyMMdd_HHmmss').$Format"
        $SaveFile = Join-Path -Path $scanFolderPath -ChildPath $ExportFileName
        $fileID = Export-Scan -ID $ID -Format $Format
        Check-ExportStatus -ID $ID -fileID $fileID
        Download-ScanExport -ID $ID -fileID $fileID -SaveFile $SaveFile
      }
    }
  }
  else {
    Write-Host "You selected not to export completed Scans. The script will now terminate."
  }
