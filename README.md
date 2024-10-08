Nessus Multi-Scan Exporter Tool

This PowerShell script automates the process of exporting Nessus scan reports in multiple formats, including .html, .csv, and .nessus. It uses REST API methods to interact with Nessus Professional, fetching scan details, exporting completed scans, and saving them in structured directories. The tool is ideal for those seeking a straightforward way to automate Nessus scan report exports for multiple scans.

Features

Fetches all scans from the Nessus server.

Lists completed and in-progress scans for easy visibility.

Exports completed scans in .html, .csv, and .nessus formats.

Saves each set of files in a folder named after the scan under a "Nessus Reports" directory.

Includes error handling for API interactions, directory creation, and file downloads.

Requirements

PowerShell Version: 5.1 or later.

Nessus Scanner URL: URL and port of the Nessus server (e.g., https://your-nessus-server:8834).

Nessus API Access Key and Secret Key: These can be set as environment variables (NESSUS_ACCESS_KEY and NESSUS_SECRET_KEY) or entered manually when prompted.

Installation

Clone the repository from GitHub:

https://github.com/jmlevij/nessus_multi_scan_pull.git

Ensure the PowerShell execution policy allows the script to run. Run PowerShell as an Administrator and execute:

Set-ExecutionPolicy Bypass

Usage

Run the Script

Open PowerShell and navigate to the directory where the script is located.

Execute the script:

.\NessusMultiScanPull.ps1

Enter the Nessus Server URL

Enter the URL of your Nessus scanner, including the port (e.g., https://your-nessus-server:8834).

Provide API Keys

If the NESSUS_ACCESS_KEY and NESSUS_SECRET_KEY environment variables are not set, the script will prompt you to enter the Nessus Access Key and Secret Key.

Select Scans to Export

The script will display all scans and allow you to export completed scans.

You will be prompted to confirm if you want to export completed scans.

Export Formats

Completed scans will be exported in .html, .csv, and .nessus formats, with each format saved in a folder named after the scan in a "Nessus Reports" directory.

Error Handling

API Errors: The script provides meaningful error messages for API failures (e.g., fetching scan details, export errors, etc.).

Directory Creation: Errors related to creating directories for saving reports are captured and logged.

User Inputs: Input validation is included for essential prompts, such as confirming scan exports.

Attribution

This script is based on and adapted from the following works:

Pwd9000-ML/NessusV7-Report-Export-PowerShell, licensed under the GNU General Public License (GPL).

License

This script is licensed under the GNU General Public License (GPL), version 3. Portions of the original script have been modified and integrated to create this version.

Author

James Levija

GitHub: jmlevij
