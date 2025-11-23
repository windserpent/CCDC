#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$SplunkServer = "splunk.ccdcteam.com",
    [string]$InstallPath = "C:\Program Files\SplunkUniversalForwarder",
    [string]$SourceDirectory = "splunk_forwarder"
)

Write-Host "Splunk Universal Forwarder Deployment - CCDC Edition" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# Function to refresh environment variables
function Get-RefreshedEnvironment {
    Write-Host "Refreshing environment variables..." -ForegroundColor Yellow
    
    $machinePath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
    $userPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
    $env:PATH = "$machinePath;$userPath"
    
    foreach ($level in @("Machine", "User")) {
        [System.Environment]::GetEnvironmentVariables($level).GetEnumerator() | ForEach-Object {
            if ($_.Name -ne "PATH") {
                [System.Environment]::SetEnvironmentVariable($_.Name, $_.Value, "Process")
            }
        }
    }
    
    Write-Host "Environment refreshed" -ForegroundColor Green
}

# Check if source directory exists
if (!(Test-Path $SourceDirectory)) {
    Write-Error "Source directory '$SourceDirectory' not found!"
    Write-Host "Expected structure:" -ForegroundColor Yellow
    Write-Host "  .\Deploy-SplunkForwarder.ps1" -ForegroundColor Gray
    Write-Host "  .\splunk_forwarder\" -ForegroundColor Gray
    Write-Host "    ├── splunkforwarder.msi" -ForegroundColor Gray
    Write-Host "    ├── splunkforwarder.inputs.conf" -ForegroundColor Gray
    Write-Host "    └── splunkforwarder.outputs.conf" -ForegroundColor Gray
    exit 1
}

# Define file paths
$msiFile = Join-Path $SourceDirectory "splunkforwarder.msi"
$inputsFile = Join-Path $SourceDirectory "splunkforwarder.inputs.conf" 
$outputsFile = Join-Path $SourceDirectory "splunkforwarder.outputs.conf"

# Check if all required files exist
$requiredFiles = @{
    "MSI Installer" = $msiFile
    "Inputs Configuration" = $inputsFile
    "Outputs Configuration" = $outputsFile
}

$missingFiles = @()
foreach ($file in $requiredFiles.GetEnumerator()) {
    if (!(Test-Path $file.Value)) {
        $missingFiles += $file.Key
        Write-Host "✗ Missing: $($file.Value)" -ForegroundColor Red
    } else {
        Write-Host "Found: $($file.Value)" -ForegroundColor Green
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Error "Missing required files: $($missingFiles -join ', ')"
    exit 1
}

# Install Splunk Universal Forwarder
Write-Host ""
Write-Host "Installing Splunk Universal Forwarder..." -ForegroundColor Yellow
try {
    $arguments = @(
        "/i", "`"$msiFile`""
        "AGREETOLICENSE=yes"
        "SERVICESTARTTYPE=auto"
        "LAUNCHSPLUNK=0"  # Don't start until configs are deployed
        "/quiet"
        "/l*v", "C:\temp\splunk_install.log"
    )
    
    # Create temp directory for logs
    if (!(Test-Path "C:\temp")) {
        New-Item -Path "C:\temp" -ItemType Directory -Force | Out-Null
    }
    
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -NoNewWindow -PassThru
    
    if ($process.ExitCode -eq 0) {
        Write-Host "Installation completed successfully" -ForegroundColor Green
    } else {
        throw "Installation failed with exit code: $($process.ExitCode)"
    }
}
catch {
    Write-Error "Installation failed: $($_.Exception.Message)"
    Write-Host "Check installation log: C:\temp\splunk_install.log" -ForegroundColor Red
    exit 1
}


# Setup configuration directories
Write-Host "Setting up configuration directories..." -ForegroundColor Yellow
$configDir = "$InstallPath\etc\system\local"
$authDir = "$InstallPath\etc\auth"

foreach ($dir in @($configDir, $authDir)) {
    if (!(Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        Write-Host "Created directory: $dir" -ForegroundColor Green
    }
}

# Deploy configuration files
Write-Host "Deploying configuration files..." -ForegroundColor Yellow

# Copy inputs.conf
$targetInputs = Join-Path $configDir "inputs.conf"
Copy-Item $inputsFile -Destination $targetInputs -Force
Write-Host "Deployed inputs.conf" -ForegroundColor Green

# Copy outputs.conf  
$targetOutputs = Join-Path $configDir "outputs.conf"
Copy-Item $outputsFile -Destination $targetOutputs -Force
Write-Host "Deployed outputs.conf" -ForegroundColor Green

# Change service account to LocalSystem for Security log access
Write-Host "Configuring service account for Security log access..." -ForegroundColor Yellow
try {
    sc.exe config SplunkForwarder obj= LocalSystem
    Write-Host "Service account changed to LocalSystem" -ForegroundColor Green
}
catch {
    Write-Error "Failed to change service account: $($_.Exception.Message)"
}

# Display configuration summary
Write-Host ""
Write-Host "Configuration Summary:" -ForegroundColor Cyan
Write-Host "=====================" -ForegroundColor Cyan
Write-Host "Windows Event Logs: Security, System, Application, PowerShell" -ForegroundColor White
Write-Host "Enhanced Monitoring: Sysmon, RDP, Task Scheduler, DNS" -ForegroundColor White
Write-Host "Network Logs: Windows Firewall" -ForegroundColor White
Write-Host "Web Logs: IIS (if applicable)" -ForegroundColor White
Write-Host "Forwarding Target: $SplunkServer" -ForegroundColor White
Write-Host "Default Mode: Non-SSL (port 9997)" -ForegroundColor White
Write-Host "SSL Available: Port 9998 (requires certificate)" -ForegroundColor White

# Certificate setup instructions
Write-Host ""
Write-Host "SSL CERTIFICATE SETUP" -ForegroundColor Yellow -BackgroundColor DarkRed
Write-Host "=====================" -ForegroundColor Yellow
Write-Host "To enable encrypted forwarding (port 9998):" -ForegroundColor White
Write-Host ""
Write-Host "1. Harden your Splunk server and extract certificate:" -ForegroundColor Cyan
Write-Host "   sudo openssl x509 -in /opt/splunk/etc/auth/server.pem -out /opt/splunk/etc/auth/cacert.pem" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Copy certificate to this system:" -ForegroundColor Cyan  
Write-Host "   scp user@$SplunkServer`:/opt/splunk/etc/auth/cacert.pem ." -ForegroundColor Gray
Write-Host "   Copy-Item cacert.pem `"$authDir\cacert.pem`"" -ForegroundColor Gray
Write-Host ""
Write-Host "3. Switch to SSL mode in outputs.conf:" -ForegroundColor Cyan
Write-Host "   Edit: $targetOutputs" -ForegroundColor Gray
Write-Host "   Change: defaultGroup = primary_indexer" -ForegroundColor Gray
Write-Host "   To:     defaultGroup = ssl_indexer" -ForegroundColor Gray
Write-Host ""
Write-Host "4. Restart the forwarder:" -ForegroundColor Cyan
Write-Host "   Restart-Service SplunkForwarder" -ForegroundColor Gray

# Start the service
Write-Host ""
Write-Host "Starting Splunk Universal Forwarder service..." -ForegroundColor Yellow
try {
    Start-Service -Name "SplunkForwarder" -ErrorAction Stop
    Write-Host "Service started successfully" -ForegroundColor Green
    
    # Brief status check
    Start-Sleep -Seconds 3
    $service = Get-Service -Name "SplunkForwarder"
    Write-Host "Service Status: $($service.Status)" -ForegroundColor $(if($service.Status -eq 'Running'){'Green'}else{'Red'})
    
    # Check for connections after startup delay
    Write-Host ""
    Write-Host "Checking forwarder connections..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    
    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
        $_.RemoteAddress -like "*$($SplunkServer.Split('.')[0])*" -or 
        $_.RemotePort -in @(9997, 9998)
    }
    
    if ($connections) {
        Write-Host "Network connections to Splunk server detected" -ForegroundColor Green
    } else {
        Write-Host "No immediate connections visible (connections may take time to establish)" -ForegroundColor Yellow
    }
}
catch {
    Write-Error "Failed to start service: $($_.Exception.Message)"
    Write-Host "Check Windows Event Viewer → Applications and Services → Splunk" -ForegroundColor Red
}

# Final deployment summary
Write-Host ""
Write-Host "DEPLOYMENT COMPLETE" -ForegroundColor Green -BackgroundColor DarkGreen
Write-Host "===================" -ForegroundColor Green
Write-Host "Splunk Universal Forwarder installed and running" -ForegroundColor Green
Write-Host ""
Write-Host "Verification Steps:" -ForegroundColor White
Write-Host "- Check Splunk web interface for incoming data" -ForegroundColor White
Write-Host "- Search: index=main host=$env:COMPUTERNAME" -ForegroundColor White
Write-Host "- Install Sysmon for enhanced process monitoring" -ForegroundColor White
Write-Host "- Configure SSL forwarding when Splunk server is ready" -ForegroundColor White

# Keep window open for review
Read-Host "Press Enter to exit"