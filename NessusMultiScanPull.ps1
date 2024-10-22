<#
ScriptName: NessusMultiScanPull.ps1
Purpose:    PowerShell script that uses REST methods to obtain and export Nessus scan reports in html, csv, and .nessus formats, with an option to convert HTML to PDF.
Created:    Updated in October 2024.
Comments:   Portions of this script are derived from the works of Pwd9000-ML under the GPL license. This script requires PowerShell 7 or later.
Author:     James Levija
GitHub:     https://github.com/jmlevij
Attribution: Portions of this code are based on:
             - [Pwd9000-ML/NessusV7-Report-Export-PowerShell](https://github.com/Pwd9000-ML/NessusV7-Report-Export-PowerShell), licensed under [GNU General Public License (GPL)](https://www.gnu.org/licenses/gpl-3.0.html).
             The original code has been modified and integrated to create this version.
#>

param (
    # Enter Nessus Server URL
  [string]$Server = "https://localhost:8834",
  # Directory for storing reports
  [string]$ReportPath = ".\Nessus Reports"
)

# Disable SSL certificate validation to avoid trust issues
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

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

# Store API headers to avoid repeated calls
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

$ApiHeaders = Get-ApiHeaders

# Logging Mechanism
function Write-Log {
    param (
        [string]$Message
    )
    $LogFilePath = Join-Path -Path $ReportPath -ChildPath "NessusMultiScanPull.log"
    Add-Content -Path $LogFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') : $Message"
}

# Log the start of the script
$UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$ScriptStartTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Write-Log "Script started by user: $UserName at $ScriptStartTime"

# Retrieving the list of scans
function Fetch-ScanDetails {
    Write-Host -Fore Cyan "[!] Fetching Scan Details..."
    $ScanURI = "$Server/scans"
    try {
      $response = Invoke-WebRequest -Uri $ScanURI  -Method GET -Headers $ApiHeaders
      if ($response.StatusCode -eq 200) {
        return (ConvertFrom-Json $response.Content).scans
      } else {
        Write-Host -Fore Red "Error fetching scan details: Status Code $($response.StatusCode)"
      }
    }
    catch {
      if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Host -Fore Red "Error 401: Unauthorized. Please check your API keys."
      } else {
        Write-Host -Fore Red "Error fetching scan details: $($_.Exception.Message)"
      }
    }
    return $null
}

# Displays the list of scans
function Display-ScanInfo {
    param (
      [psobject]$result
    )
    $ScanName = $result.name
    $ID = $result.id
    $ScanStatus = $result.status
    $ScanStartDate = [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($result.creation_date))
    $ScanModDate = [System.TimeZoneInfo]::ConvertTimeFromUtc(([datetime]'1970-01-01').AddSeconds($result.last_modification_date), [System.TimeZoneInfo]::Local)
    $ScanOwner = $result.owner

    Write-Host "[!] Scan Name is:" -NoNewline; Write-Host -Fore DarkCyan "$ScanName"
    Write-Host "[!] Scan ID is:" -NoNewline; Write-Host -Fore DarkCyan "$ID"
    Write-Host "[!] Scan Status is:" -NoNewline; Write-Host -Fore DarkCyan "$ScanStatus"
    Write-Host "[!] Scan Start Date is:" -NoNewline; Write-Host -Fore DarkCyan "$ScanStartDate"
    Write-Host "[!] Scan Last Modified Date is:" -NoNewline; Write-Host -Fore DarkCyan "$ScanModDate"
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
    try {
      $response = Invoke-WebRequest -Uri $ExportURI  -Method POST -Headers $ApiHeaders -ContentType 'application/json' -Body $ExportBody
      if ($response.StatusCode -eq 200) {
        return (ConvertFrom-Json $response.Content).file
      } else {
        Write-Host -Fore DarkCyan "[!] Export Not Successful. Status Code: $($response.StatusCode)"
      }
    } catch {
      Write-Host -Fore Red "Error exporting scan: $($_.Exception.Message)"
    }
    return $null
}

# Check Export Status
function Check-ExportStatus {
    param (
      [string]$ID,
      [string]$fileID
    )
    $StatusURI = "$Server/scans/$ID/export/$fileID/status"
    $maxRetries = 30  # Maximum number of retries
    $retryCount = 0

    while ($retryCount -lt $maxRetries) {
      try {
        Write-Host -Fore Cyan "[!] Checking Export Status... (Attempt $($retryCount + 1) of $maxRetries)"
        $response = Invoke-WebRequest -Uri $StatusURI  -Method GET -Headers $ApiHeaders
        if ($response.StatusCode -eq 200) {
          $keyValueStatus = (ConvertFrom-Json $response.Content).status
          Write-Host -Fore DarkCyan "[*] Export Status is: $keyValueStatus"
          if ($keyValueStatus -eq 'ready') {
            return
          } else {
            Write-Host -Fore Cyan "[!] Waiting for export to be ready..."
          }
        }
      } catch {
        Write-Host "Error: $($_.Exception.Message). Retrying in 10 seconds..."
      }
      Start-Sleep -Seconds 10
      $retryCount++
    }

    Write-Host -Fore Red "[!] Maximum retries reached. Export did not complete."
    Write-Log "Maximum retries reached while waiting for export to be ready."
}

function Download-ScanExport {
    param (
      [string]$ID,
      [string]$fileID,
      [string]$SaveFile
    )
    Write-Host -Fore DarkCyan "[*] Starting Download!"
    $DownloadURI = "$Server/scans/$ID/export/$fileID/download"
    try {
      Invoke-WebRequest -Uri $DownloadURI -Method GET -Headers $ApiHeaders -OutFile $SaveFile
      Write-Host -Fore DarkCyan "[*] Download completed: $SaveFile"
    } catch {
      Write-Host -Fore Red "Error downloading scan export: $($_.Exception.Message)"
      Write-Log "Error downloading scan export with ID $ID: $($_.Exception.Message)"
    }
}

# Convert HTML to PDF using Microsoft Edge
function Convert-HtmlToPdf {
    param (
        [string]$HtmlFilePath,
        [string]$PdfFilePath
    )
    # Put the correct path for msedge.exe
    Write-Host -Fore Cyan "[!] Converting HTML to PDF using Microsoft Edge..."
    try {
        $edgePath = "C:\Program Files (x86)\Microsoft\EdgeCore\129.0.2792.79\msedge.exe"
        if (-not (Test-Path $edgePath)) {
            Write-Host -Fore Red "[!] Microsoft Edge not found. Please ensure Edge is installed or update the path."
            return
        }
        $arguments = "--headless --disable-gpu --print-to-pdf=$PdfFilePath $HtmlFilePath"
        Start-Process -FilePath $edgePath -ArgumentList $arguments -NoNewWindow -Wait
        if (Test-Path $PdfFilePath) {
            Write-Host -Fore DarkCyan "[!] PDF conversion completed: $PdfFilePath"
        } else {
            Write-Host -Fore Red "[!] PDF conversion failed. PDF file not found."
        }
    } catch {
        Write-Host -Fore Red "Error converting HTML to PDF: $($_.Exception.Message)"
    }
}

# Main Logic
$keyValueScan = Fetch-ScanDetails
if (-not $keyValueScan) {
  Write-Host -Fore Red "Failed to fetch scan details. Exiting..."
  Write-Log "Failed to fetch scan details."
  exit 1
}
$completedScans = $keyValueScan | Where-Object { $_.status -eq 'completed' -and [System.DateTime]::UtcNow.AddDays(-1) -lt ([System.DateTime]'1970-01-01').AddSeconds($_.last_modification_date) }
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
    $completedScans | ForEach-Object {
        $ScanName = $_.name
        $ID = $_.id
        $scanFolderPath = Join-Path -Path $ReportPath -ChildPath "$ScanName"
        if (-not (Test-Path $scanFolderPath)) {
            New-Item -ItemType Directory -Path $scanFolderPath | Out-Null
        }

        # Export and download for each format
        $jobs = @()
        foreach ($Format in @("html", "csv", "nessus")) {
            $ExportFileName = "$ScanName`_$(Get-Date -format 'yyyyMMdd_HHmmss').$Format"
            $SaveFile = Join-Path -Path $scanFolderPath -ChildPath $ExportFileName
            $fileID = Export-Scan -ID $ID -Format $Format
            if (-not $fileID) {
                Write-Host -Fore Red "[!] Failed to export scan with ID $ID. Skipping to next format."
                Write-Log "Failed to export scan with ID $ID for format $Format."
                continue
            }
            Check-ExportStatus -ID $ID -fileID $fileID
            $jobs += Start-Job -ScriptBlock {
                param($ID, $fileID, $SaveFile, $ApiHeaders, $Server)
                $DownloadURI = "$Server/scans/$ID/export/$fileID/download"
                Invoke-WebRequest -Uri $DownloadURI -Method GET -Headers $ApiHeaders -OutFile $SaveFile
            } -ArgumentList $ID, $fileID, $SaveFile, $ApiHeaders, $Server
        }

        # Wait for all download jobs to complete in batches
        $batchSize = 5
        while ($jobs.Count -gt 0) {
            $currentBatch = $jobs[0..([math]::Min($batchSize, $jobs.Count) - 1)]
            $currentBatch | ForEach-Object { $_ | Wait-Job }
            $currentBatch | ForEach-Object { Receive-Job -Job $_ | Out-Null }
            $jobs = $jobs[$batchSize..($jobs.Count - 1)]
        }
    }

    # Convert all HTML files to PDF after downloads are complete
    Get-ChildItem -Path $ReportPath -Recurse -Filter "*.html" | ForEach-Object {
        $HtmlFilePath = $_.FullName
        $PdfFilePath = [System.IO.Path]::ChangeExtension($HtmlFilePath, ".pdf")
        Convert-HtmlToPdf -HtmlFilePath $HtmlFilePath -PdfFilePath $PdfFilePath
    }
}
else {
    Write-Host "You selected not to export completed Scans. The script will now terminate."
    Write-Log "User chose not to export completed scans."
}
