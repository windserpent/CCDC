#Requires -RunAsAdministrator

[CmdletBinding()]
param()

Write-Host "WinGet Setup & Git Installation Script" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

# Function to refresh environment variables
function Get-RefreshedEnvironment {
    Write-Host "Refreshing environment variables..." -ForegroundColor Yellow
    
    # Refresh PATH specifically
    $machinePath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
    $userPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
    $env:PATH = "$machinePath;$userPath"
    
    # Refresh all other environment variables
    foreach ($level in @("Machine", "User")) {
        [System.Environment]::GetEnvironmentVariables($level).GetEnumerator() | ForEach-Object {
            if ($_.Name -ne "PATH") {
                [System.Environment]::SetEnvironmentVariable($_.Name, $_.Value, "Process")
            }
        }
    }
    
    Write-Host "Environment refreshed" -ForegroundColor Green
}

# Function to check and install WinGet
function Get-WinGet {
    Write-Host "Checking for WinGet..." -ForegroundColor Yellow
    
    # Check if winget command is available
    try {
        $wingetVersion = winget --version 2>$null
        if ($wingetVersion) {
            Write-Host "WinGet already installed: $wingetVersion" -ForegroundColor Green
            return $true
        }
    }
    catch {
        # Continue to installation
    }
    
    Write-Host "WinGet not found - installing..." -ForegroundColor Yellow
    
    try {
        # Step 1: Install PowerShell WinGet module
        Write-Host "Installing WinGet PowerShell module..." -ForegroundColor Yellow
        Install-Module -Name Microsoft.WinGet.Client -Force -Repository PSGallery -Scope AllUsers -ErrorAction Stop
        Write-Host "WinGet PowerShell module installed" -ForegroundColor Green
        
        # Step 2: Repair WinGet installation
        Write-Host "Repairing WinGet installation..." -ForegroundColor Yellow
        Import-Module Microsoft.WinGet.Client -Force
        Repair-WinGetPackageManager -AllUsers -ErrorAction Stop
        Write-Host "WinGet repaired for all users" -ForegroundColor Green
        
        # Step 3: Refresh environment
        Get-RefreshedEnvironment
        
        # Step 4: Verify installation
        Start-Sleep -Seconds 3
        $wingetVersion = winget --version 2>$null
        if ($wingetVersion) {
            Write-Host "WinGet installation verified: $wingetVersion" -ForegroundColor Green
            return $true
        } else {
            throw "WinGet command still not available after installation"
        }
    }
    catch {
        Write-Error "Failed to install WinGet: $($_.Exception.Message)"
        Write-Host "Manual installation may be required" -ForegroundColor Red
        return $false
    }
}

# Function to install Git via WinGet
function Install-Git {
    Write-Host "Installing Git via WinGet..." -ForegroundColor Yellow
    
    try {
        # Check if Git is already installed
        try {
            $gitVersion = git --version 2>$null
            if ($gitVersion) {
                Write-Host "Git already installed: $gitVersion" -ForegroundColor Green
                return $true
            }
        }
        catch {
            # Git not found, proceed with installation
        }
        
        # Install Git using WinGet
        Write-Host "Downloading and installing Git..." -ForegroundColor Yellow
        winget install --id Git.Git -e --source winget --silent --accept-package-agreements --accept-source-agreements
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Git installation completed" -ForegroundColor Green
            
            # Refresh environment to pick up Git
            Get-RefreshedEnvironment
            
            # Verify Git installation
            Start-Sleep -Seconds 3
            try {
                $gitVersion = git --version
                Write-Host "Git installation verified: $gitVersion" -ForegroundColor Green
                return $true
            }
            catch {
                Write-Warning "Git installed but not yet available in PATH. May require restart."
                return $true
            }
        } else {
            throw "WinGet install command failed with exit code: $LASTEXITCODE"
        }
    }
    catch {
        Write-Error "Failed to install Git: $($_.Exception.Message)"
        return $false
    }
}

# Main script execution
try {
    # Step 1: Ensure WinGet is installed and working
    if (!(Get-WinGet)) {
        Write-Error "Cannot proceed without WinGet. Exiting."
        exit 1
    }
    
    # Step 2: Install Git
    if (!(Install-Git)) {
        Write-Error "Git installation failed."
        exit 1
    }
    
    # Final status
    Write-Host ""
    Write-Host "INSTALLATION COMPLETE" -ForegroundColor Green -BackgroundColor DarkGreen
    Write-Host "=====================" -ForegroundColor Green
    Write-Host "WinGet is installed and functional" -ForegroundColor Green
    Write-Host "Git is installed and ready to use" -ForegroundColor Green
    Write-Host ""
    Write-Host "You can now use Git commands and WinGet for further software management." -ForegroundColor White
    Write-Host "If Git commands don't work immediately, try restarting PowerShell." -ForegroundColor Yellow
    
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    exit 1
}

# Keep window open
Read-Host "Press Enter to exit"