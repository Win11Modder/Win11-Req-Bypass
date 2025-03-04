<#
.SYNOPSIS
Bypasses Windows 11 installation and update restrictions and optionally performs a Windows Update reset.

.DESCRIPTION
This PowerShell script modifies the registry so that Windows 11 can be installed and updated even if the hardware does not meet Microsoft's official requirements.
The script adds registry entries that bypass:
- Compatibility checks used by Windows Update (to allow the update to work directly through Windows Update)
- Disables Windows telemetry to try to ensure that restrictions do not come into effect in the future

.PARAMETERS
-r : (switch) Optional parameter. If provided, a Windows Update reset is performed first.

.EXAMPLE
Execute only the bypasses and telemetry minimization:
    .\Win11_Bypass.ps1

Execute the Update reset first and then apply registry modifications:
    .\Win11_Bypass.ps1 -r

OR run it directly from the web:
    iwr -useb "https://raw.githubusercontent.com/Win11Modder/Win11-Req-Bypass/main/Win11_Bypass.ps1" | iex

.NOTES
- Enables the installation or update of Windows 11 on devices that are not officially supported by Microsoft.
- Use at your own risk.
- Run the script as an administrator!
#>

param(
    [switch]$r
)

# Check for administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "The script is not running as an administrator. Attempting to elevate privileges..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# --- Windows Update Reset (if -r switch is provided) ---
if ($r) {
    Write-Host "`n*** Executing Windows Update reset and network settings reset... ***" -ForegroundColor Cyan
    Write-Host "1. Stopping Windows Update services..."
    Stop-Service -Name BITS -Force -ErrorAction SilentlyContinue
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Stop-Service -Name appidsvc -Force -ErrorAction SilentlyContinue
    Stop-Service -Name cryptsvc -Force -ErrorAction SilentlyContinue

    Write-Host "2. Deleting QMGR files..."
    Remove-Item "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -ErrorAction SilentlyContinue

    Write-Host "3. Renaming folders: SoftwareDistribution and Catroot2..."
    Rename-Item "$env:systemroot\SoftwareDistribution" "SoftwareDistribution.bak" -ErrorAction SilentlyContinue
    Rename-Item "$env:systemroot\System32\Catroot2" "catroot2.bak" -ErrorAction SilentlyContinue

    Write-Host "4. Deleting WindowsUpdate.log file..."
    Remove-Item "$env:systemroot\WindowsUpdate.log" -ErrorAction SilentlyContinue

    Set-Location $env:systemroot\system32

    Write-Host "5. Registering DLL files..."
    regsvr32.exe /s atl.dll
    regsvr32.exe /s urlmon.dll
    regsvr32.exe /s mshtml.dll
    regsvr32.exe /s shdocvw.dll
    regsvr32.exe /s browseui.dll
    regsvr32.exe /s jscript.dll
    regsvr32.exe /s vbscript.dll
    regsvr32.exe /s scrrun.dll
    regsvr32.exe /s msxml.dll
    regsvr32.exe /s msxml3.dll
    regsvr32.exe /s msxml6.dll
    regsvr32.exe /s actxprxy.dll
    regsvr32.exe /s softpub.dll
    regsvr32.exe /s wintrust.dll
    regsvr32.exe /s dssenh.dll
    regsvr32.exe /s rsaenh.dll
    regsvr32.exe /s gpkcsp.dll
    regsvr32.exe /s sccbase.dll
    regsvr32.exe /s slbcsp.dll
    regsvr32.exe /s cryptdlg.dll
    regsvr32.exe /s oleaut32.dll
    regsvr32.exe /s ole32.dll
    regsvr32.exe /s shell32.dll
    regsvr32.exe /s initpki.dll
    regsvr32.exe /s wuapi.dll
    regsvr32.exe /s wuaueng.dll
    regsvr32.exe /s wuaueng1.dll
    regsvr32.exe /s wucltui.dll
    regsvr32.exe /s wups.dll
    regsvr32.exe /s wups2.dll
    regsvr32.exe /s wuweb.dll
    regsvr32.exe /s qmgr.dll
    regsvr32.exe /s qmgrprxy.dll
    regsvr32.exe /s wucltux.dll
    regsvr32.exe /s muweb.dll
    regsvr32.exe /s wuwebv.dll    

    Write-Host "6. Executing network reset commands..."
    arp -d *
    nbtstat -R
    nbtstat -RR
    ipconfig /flushdns
    ipconfig /registerdns
    netsh winsock reset
    netsh int ip reset c:\resetlog.txt

    Write-Host "7. Restarting Windows Update services..."
    Start-Service -Name BITS -ErrorAction SilentlyContinue
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    Start-Service -Name appidsvc -ErrorAction SilentlyContinue
    Start-Service -Name cryptsvc -ErrorAction SilentlyContinue

    Write-Host "*** Windows Update reset and network settings reset completed. ***" -ForegroundColor Green
    Write-Host "It is recommended to restart your computer before continuing." -ForegroundColor Yellow
    Read-Host "Press Enter to continue"
}

# --- Configure Windows Update Target Release Version ---
Write-Host "`n*** Configure Windows Update Target Release Version ***" -ForegroundColor Cyan
Write-Host "1 (or press Enter) - Set default target release version to 24H2"
Write-Host "2 - Set a custom target release version"
Write-Host "3 - Remove target release version from registry"

$choice = Read-Host "Select an option (1-3)"

if ($choice -eq "" -or $choice -eq "1") {
    $targetRelease = "24H2"
    Write-Host "Setting Windows Update target release to $targetRelease..." -ForegroundColor Cyan
    $WinUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    if (!(Test-Path $WinUpdatePath)) {
        New-Item -Path $WinUpdatePath -Force | Out-Null
    }
    New-ItemProperty -Path $WinUpdatePath -Name "ProductVersion" -Value "Windows 11" -PropertyType String -Force
    New-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersion" -Value 1 -PropertyType DWord -Force
    New-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersionInfo" -Value $targetRelease -PropertyType String -Force
    Write-Host "Target release version set to $targetRelease. Continuing with bypass modifications..."
}
elseif ($choice -eq "2") {
    $targetRelease = Read-Host "Enter the Windows 11 target release version (e.g., 23H2, 24H2)"
    Write-Host "Setting Windows Update target release to $targetRelease..." -ForegroundColor Cyan
    $WinUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    if (!(Test-Path $WinUpdatePath)) {
        New-Item -Path $WinUpdatePath -Force | Out-Null
    }
    New-ItemProperty -Path $WinUpdatePath -Name "ProductVersion" -Value "Windows 11" -PropertyType String -Force
    New-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersion" -Value 1 -PropertyType DWord -Force
    New-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersionInfo" -Value $targetRelease -PropertyType String -Force
    Write-Host "Target release version set to $targetRelease. Continuing with bypass modifications..."
}
elseif ($choice -eq "3") {
    Write-Host "Removing Windows Update target release settings..." -ForegroundColor Cyan
    $WinUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    Remove-ItemProperty -Path $WinUpdatePath -Name "ProductVersion" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersion" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersionInfo" -ErrorAction SilentlyContinue
    Write-Host "Target release settings removed. Exiting..."
    exit
}
else {
    Write-Host "Invalid option selected. Exiting..." -ForegroundColor Red
    exit
}

# --- Bypassing Windows 11 Installation and Update Restrictions ---
Write-Host "`n*** Bypassing Windows 11 installation and update restrictions ***" -ForegroundColor Cyan
Write-Host "*** Modifying the registry, make sure you know what you are doing! ***`n" -ForegroundColor Yellow

# Define registry paths
$moSetupPath = "HKLM:\SYSTEM\Setup\MoSetup"
$appCompatFlagsPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags"
$hwReqChkPath = "$appCompatFlagsPath\HwReqChk"

# Create registry keys if they do not exist
@($moSetupPath, $hwReqChkPath) | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -Path $_ -Force | Out-Null
    }
}

# Add registry entries (bypass hardware requirements)
@(
    @{ Path = $moSetupPath; Name = "AllowUpgradesWithUnsupportedTPMOrCPU"; Value = 1 }
) | ForEach-Object {
    New-ItemProperty -Path $_.Path -Name $_.Name -Value $_.Value -PropertyType DWord -Force
}

# Clear previous Windows Update compatibility checks
Write-Host "`n*** Removing previous Windows Update compatibility checks... ***" -ForegroundColor Cyan
@(
    "$appCompatFlagsPath\CompatMarkers",
    "$appCompatFlagsPath\Shared",
    "$appCompatFlagsPath\TargetVersionUpgradeExperienceIndicators"
) | ForEach-Object {
    Remove-Item -Path $_ -Force -Recurse -ErrorAction SilentlyContinue
}

# Add spoof settings for Windows Update
Write-Host "*** Adding new spoof settings for Windows Update... ***" -ForegroundColor Cyan
New-ItemProperty -Path "$appCompatFlagsPath\HwReqChk" -Name "HwReqChkVars" -PropertyType MultiString -Value @(
    "SQ_SecureBootCapable=TRUE",
    "SQ_SecureBootEnabled=TRUE",
    "SQ_TpmVersion=2",
    "SQ_RamMB=8192"
) -Force

# Remove the "System Requirements Not Met" watermark at the system level (HKLM)
$systemPolicyKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $systemPolicyKey)) {
    New-Item -Path $systemPolicyKey -Force | Out-Null
}
New-ItemProperty -Path $systemPolicyKey -Name "HideUnsupportedHardwareNotifications" -PropertyType DWord -Value 1 -Force | Out-Null
Write-Host "Watermark warning removed" -ForegroundColor Green

# Remove the "System Requirements Not Met" watermark on a per-user basis (HKCU)
$uhncKey = "HKCU:\Control Panel\UnsupportedHardwareNotificationCache"
if (-not (Test-Path $uhncKey)) {
    New-Item -Path $uhncKey -Force | Out-Null
}
New-ItemProperty -Path $uhncKey -Name "SV2" -Value 0 -PropertyType DWord -Force | Out-Null

# Set the registry key AllowTelemetry to 0
Write-Host "Setting the AllowTelemetry registry key to 0..." -ForegroundColor Cyan
try {
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -Force
    Write-Host "Registry key updated successfully." -ForegroundColor Green
} catch {
    Write-Host "Error updating registry key: $_" -ForegroundColor Red
}

# Disable scheduled tasks related to telemetry
$telemetryTasks = @(
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "\Microsoft\Windows\Application Experience\PcaPatchDbTask",
    "\Microsoft\Windows\Application Experience\StartupAppTask"
)

foreach ($task in $telemetryTasks) {
    schtasks /query /tn "$task" 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Disabling task: $task..." -ForegroundColor Cyan
        schtasks /change /disable /tn "$task" | Out-Null
        Write-Host "Task disabled: $task" -ForegroundColor Green
    } else {
        Write-Host "Task $task not found. It is either already removed or does not exist in this Windows version." -ForegroundColor Yellow
    }
}

Write-Host "*** Windows Update is now targeting the Windows 11 $targetRelease update! ***" -ForegroundColor Green
Write-Host "`n*** Done! ***" -ForegroundColor Green
Write-Host "*** Please restart your computer for the changes to take effect. ***" -ForegroundColor Yellow

# --- Installation Option Menu Section ---
Write-Host ""
Write-Host "-------------------------------------"
Write-Host "Installation Options:"
Write-Host "1 - Exit the script"
Write-Host "2 - Download the latest ISO and start update using /setup server (via Fido)"
Write-Host "3 - Run Windows Update via PowerShell (using PSWindowsUpdate)"
$installChoice = Read-Host "Select an option (1-3):"

switch ($installChoice) {
    "1" {
        Write-Host "Exiting the script." -ForegroundColor Yellow
        exit
    }
    "2" {
        Write-Host "Downloading the latest ISO using Fido..." -ForegroundColor Cyan
        
        # Detect current system language for ISO download
        $currentLang = (Get-Culture).Name
        
        # Download Fido script if not already present
        $fidoPath = Join-Path $env:TEMP "Fido.ps1"
        if (-not (Test-Path $fidoPath)) {
            Write-Host "Downloading Fido script from GitHub..."
            Invoke-WebRequest "https://raw.githubusercontent.com/pbatard/Fido/master/Fido.ps1" -OutFile $fidoPath
        }
        # Use Fido to retrieve the ISO download link. Adjust parameters as needed.
        Write-Host "Retrieving ISO download link via Fido..."
        $isoUrl = powershell -ExecutionPolicy Bypass -File $fidoPath -Win "Windows 11" -Rel "Latest" -Ed "Windows 11 Home/Pro/Edu" -Lang $currentLang -Arch "x64" -GetUrl
        if (-not $isoUrl) {
            Write-Host "Failed to retrieve ISO download link from Fido." -ForegroundColor Red
            exit
        }
        Write-Host "ISO download link obtained: $isoUrl" -ForegroundColor Green
        $isoPath = "C:\Windows11.iso"
        Write-Host "Downloading ISO to $isoPath ..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $isoUrl -OutFile $isoPath
        if (-not (Test-Path $isoPath -PathType Leaf)) {
            Write-Host "ISO download failed." -ForegroundColor Red
            exit
        }
        Write-Host "ISO downloaded successfully: $isoPath" -ForegroundColor Green
        Write-Host "Mounting ISO..." -ForegroundColor Cyan
        $mountOutput = Mount-DiskImage -ImagePath $isoPath -PassThru
        Start-Sleep -Seconds 5  # Allow time for mounting
        $volume = Get-Volume -DiskImage $mountOutput
        if ($volume) {
            $driveLetter = $volume.DriveLetter
            Write-Host ("ISO mounted to drive {0}:" -f $driveLetter) -ForegroundColor Green
            Write-Host "Starting setup.exe with /setup server parameter..." -ForegroundColor Cyan
            Start-Process -FilePath "$($driveLetter):\setup.exe" -ArgumentList "/setup server /auto upgrade" -Wait
        }
        else {
            Write-Host "Failed to determine drive letter from mounted ISO." -ForegroundColor Red
        }
    }
"3" {
    Write-Host "Running Windows Update via PowerShell..." -ForegroundColor Cyan
    # Ensure PSWindowsUpdate module is installed and imported
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
    }
    Import-Module PSWindowsUpdate
    Write-Host "Searching for and installing available Windows updates..." -ForegroundColor Cyan
    try {
        Install-WindowsUpdate -AcceptAll -AutoReboot -Verbose
    }
    catch {
        Write-Host "Error occurred during targeted update installation. Attempting to install all available updates..." -ForegroundColor Yellow
        Get-WindowsUpdate -MicrosoftUpdate -Verbose | Install-WindowsUpdate -AcceptAll -AutoReboot -Verbose
    }
}
default {
    Write-Host "Invalid selection. Exiting the script." -ForegroundColor Red
    exit
}
}
