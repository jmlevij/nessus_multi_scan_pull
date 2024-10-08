<#
ScriptName: NessusMultiScanPull.ps1
Purpose:    PowerShell script that uses REST methods to obtain and export Nessus scan reports in html, csv, and .nessus formats, with an option to convert HTML to PDF.
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
  [string]$Server = "https://localhost:8834",
  # Directory for storing reports
  [string]$ReportPath = ".\Nessus Reports"
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

# Store API headers to avoid repeated calls
$ApiHeaders = Get-ApiHeaders

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
      $response = Invoke-WebRequest -Uri $ScanURI -SkipCertificateCheck -Method GET -Headers $ApiHeaders
      return ConvertFrom-Json $response.Content | Select-Object -expand "scans"
    }
    catch {
      if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Host -Fore Red "Error 401: Unauthorized. Please check your API keys."
      } else {
        Write-Host -Fore Red "Error fetching scan details: $($_.Exception.Message)"
      }
      return $null
    }
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
      $response = Invoke-WebRequest -Uri $ExportURI -SkipCertificateCheck -Method POST -Headers $ApiHeaders -ContentType 'application/json' -Body $ExportBody
      if ($response.statuscode -eq '200') {
        return ConvertFrom-Json $response.Content | Select-Object -expand "file"
      } else {
        Write-Host -Fore DarkCyan "[!] Export Not Successful. Status Code: $($response.StatusCode)"
      }
    } catch {
      Write-Host -Fore Red "Error exporting scan: $($_.Exception.Message)"
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
        $response = Invoke-WebRequest -Uri $StatusURI -SkipCertificateCheck -Method GET -Headers $ApiHeaders
        if ($response.statuscode -eq '200') {
          $keyValueStatus = (ConvertFrom-Json $response.Content).status
          Write-Host -Fore DarkCyan "[*] Export Status is: $keyValueStatus"
          if ($keyValueStatus -eq 'ready') {
            return
          } else {
            Write-Host -Fore Cyan "[!] Waiting for export to be ready..."
          }
        }
      } catch {
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
    Invoke-WebRequest -Uri $DownloadURI -Method GET -SkipCertificateCheck -Headers $ApiHeaders -OutFile $SaveFile
    if (Test-Path $SaveFile) {
      Write-Host -Fore DarkCyan "[!] Download Completed! File saved as: $SaveFile"
    } else {
      Write-Host -Fore Red "[!] Download Failed. File not found."
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

# Logging Mechanism
function Write-Log {
    param (
        [string]$Message
    )
    $LogFilePath = Join-Path -Path $ReportPath -ChildPath "NessusMultiScanPull.log"
    Add-Content -Path $LogFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') : $Message"
}

# Main Logic
$keyValueScan = Fetch-ScanDetails
if (-not $keyValueScan) {
  Write-Host -Fore Red "Failed to fetch scan details. Exiting..."
  Write-Log "Failed to fetch scan details."
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
    $completedScans | ForEach-Object -Parallel {
        param ($result, $Server, $ApiHeaders, $ReportPath)

        $ScanName = $result.name
        $ID = $result.id
        $scanFolderPath = Join-Path -Path $ReportPath -ChildPath "$ScanName"
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

            # Convert HTML to PDF if format is HTML
            if ($Format -eq "html") {
                $PdfFilePath = [System.IO.Path]::ChangeExtension($SaveFile, ".pdf")
                Convert-HtmlToPdf -HtmlFilePath $SaveFile -PdfFilePath $PdfFilePath
            }
        }
    } -ArgumentList $_, $Server, $ApiHeaders, $ReportPath
} else {
    Write-Host "You selected not to export completed Scans. The script will now terminate."
    Write-Log "User chose not to export completed scans."
}
