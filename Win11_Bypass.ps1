<# 
.SYNOPSIS
    Windows 11 Bypass & Update Tool

.DESCRIPTION
    This tool applies registry tweaks to bypass Windows 11 installation and update restrictions,
    performs Windows Update reset, upgrades Windows via an ISO (downloaded using FIDO),
    runs Windows Update via the PSWindowsUpdate module, or removes a configured Windows Update target release.
    
    The script is structured in four sections:
      1. Title, Main Menu & Execution
      2. Registry Bypass Functions
      3. Windows Update / ISO Upgrade Functions
      4. Windows Update Reset Functions

.NOTES
    Use at your own risk.
    Run as an administrator!
#>

#region Section 1: Title, Main Menu & Main Execution
function Show-MainMenu {
    Clear-Host

    $menu = @'
 __   __  ___   __    _____  ___        ____     ____        _______  ___  ___  _______     __        ________  ________  
|"  |/  \|  "| |" \  (\"   \|"  \      /  " \   /  " \      |   _  "\|"  \/"  ||   __ "\   /""\      /"       )/"       ) 
|'  /    \:  | ||  | |.\\   \    |    /__|| |  /__|| |      (. |_)  :)\   \  / (. |__) :) /    \    (:   \___/(:   \___/  
|: /'        | |:  | |: \\   \\  |       |: |     |: |      |:     \/  \\  \/  |:  ____/ /' /\  \    \___  \   \___  \    
 \//  /'    | |.  | |.  \    \\ |      _\  |    _\  |      (|  _  \\  /   /   (|  /    //  __'  \    __/  \\   __/  \\   
 /   /  \\   | /\  |\|    \    \ |     /" \_|\  /" \_|\     |: |_)  :)/   /   /|__/ \  /   /  \\  \  /" \   :) /" \   :)  
|___/    \___|(__\_|_)\___|\____\)    (_______)(_______)    (_______/|___/   (_______)(___/    \___)(_______/ (_______/   
-------------------------------------------------------------------------------------
                    Windows 11 Bypass & Update Tool
----------------------------------------------------------------------------------------
0 - Reset Windows Update and network settings
1 - Apply registry tweaks (bypass Windows 11 restrictions)
2 - Apply registry tweaks & upgrade via the latest ISO (fully automatic)
3 - Apply registry tweaks & run Windows Update (PowerShell)
4 - Remove Windows Update target release setting
5 - Exit
'@

Write-Host $menu -ForegroundColor Cyan
}




# Main Execution
# Check for administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "The script is not running as an administrator. Attempting to elevate privileges..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Show-MainMenu
$installChoice = Read-Host "Select an option (0-5):"
#endregion

#region Section 2: Registry Bypass Functions

function Set-WUTargetRelease {
    Write-Host "`n*** Configure Windows Update Target Release Version ***" -ForegroundColor Cyan
    Write-Host "1 (or press Enter) - Set default target release version to 24H2" -ForegroundColor Yellow
    Write-Host "2 - Set a custom target release version" -ForegroundColor Yellow
    Write-Host "3 - Remove target release version from registry" -ForegroundColor Yellow
    $choice = Read-Host "Select an option (1-3)"
    if ($choice -eq "" -or $choice -eq "1") {
        $global:targetRelease = "24H2"
        Write-Host "Setting Windows Update target release to $targetRelease..." -ForegroundColor Cyan
        $WinUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        if (!(Test-Path $WinUpdatePath)) { New-Item -Path $WinUpdatePath -Force | Out-Null }
        New-ItemProperty -Path $WinUpdatePath -Name "ProductVersion" -Value "Windows 11" -PropertyType String -Force
        New-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersion" -Value 1 -PropertyType DWord -Force
        New-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersionInfo" -Value $targetRelease -PropertyType String -Force
    }
    elseif ($choice -eq "2") {
        $targetRelease = Read-Host "Enter the Windows 11 target release version (e.g., 23H2, 24H2)"
        Write-Host "Setting Windows Update target release to $targetRelease..." -ForegroundColor Cyan
        $WinUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        if (!(Test-Path $WinUpdatePath)) { New-Item -Path $WinUpdatePath -Force | Out-Null }
        New-ItemProperty -Path $WinUpdatePath -Name "ProductVersion" -Value "Windows 11" -PropertyType String -Force
        New-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersion" -Value 1 -PropertyType DWord -Force
        New-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersionInfo" -Value $targetRelease -PropertyType String -Force
    }
    elseif ($choice -eq "3") {
        Write-Host "Removing Windows Update target release settings..." -ForegroundColor Cyan
        $WinUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        Remove-ItemProperty -Path $WinUpdatePath -Name "ProductVersion" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersion" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersionInfo" -ErrorAction SilentlyContinue
        Write-Host "Target release settings removed." -ForegroundColor Green
        exit
    }
    else {
        Write-Host "Invalid option selected. Exiting..." -ForegroundColor Red
        exit
    }
}

function Set-BypassRegistryTweaks {
    Write-Host "`n*** Bypassing Windows 11 installation and update restrictions ***" -ForegroundColor Cyan
    Write-Host "*** Modifying the registry, make sure you know what you are doing! ***" -ForegroundColor Yellow

    # Define registry paths
    $moSetupPath = "HKLM:\SYSTEM\Setup\MoSetup"
    $appCompatFlagsPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags"
    $hwReqChkPath = "$appCompatFlagsPath\HwReqChk"
    @($moSetupPath, $hwReqChkPath) | ForEach-Object {
        if (-not (Test-Path $_)) { New-Item -Path $_ -Force | Out-Null }
    }

    # Add registry entry to allow upgrades with unsupported TPM/CPU
    @{ Path = $moSetupPath; Name = "AllowUpgradesWithUnsupportedTPMOrCPU"; Value = 1 } | ForEach-Object {
        New-ItemProperty -Path $_.Path -Name $_.Name -Value $_.Value -PropertyType DWord -Force
    }

    Write-Host "`n*** Disabling Windows Update safeguards... ***" -ForegroundColor Cyan
    $wuUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    if (-not (Test-Path $wuUpdatePath)) { New-Item -Path $wuUpdatePath -Force | Out-Null }
    New-ItemProperty -Path $wuUpdatePath -Name "DisableWUfBSafeguards" -Value 1 -PropertyType DWord -Force | Out-Null

    Write-Host "`n*** Removing previous Windows Update compatibility checks... ***" -ForegroundColor Cyan
    @(
        "$appCompatFlagsPath\CompatMarkers",
        "$appCompatFlagsPath\Shared",
        "$appCompatFlagsPath\TargetVersionUpgradeExperienceIndicators"
    ) | ForEach-Object {
        Remove-Item -Path $_ -Force -Recurse -ErrorAction SilentlyContinue
    }

    Write-Host "*** Adding new spoof settings for Windows Update... ***" -ForegroundColor Cyan
    New-ItemProperty -Path "$appCompatFlagsPath\HwReqChk" -Name "HwReqChkVars" -PropertyType MultiString -Value @(
        "SQ_SecureBootCapable=TRUE",
        "SQ_SecureBootEnabled=TRUE",
        "SQ_TpmVersion=2",
        "SQ_RamMB=8192"
    ) -Force

    # Remove the "System Requirements Not Met" watermark at system level
    $systemPolicyKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    if (-not (Test-Path $systemPolicyKey)) { New-Item -Path $systemPolicyKey -Force | Out-Null }
    New-ItemProperty -Path $systemPolicyKey -Name "HideUnsupportedHardwareNotifications" -PropertyType DWord -Value 1 -Force | Out-Null
    Write-Host "Watermark warning removed" -ForegroundColor Green

    # Remove the watermark on a per-user basis
    $uhncKey = "HKCU:\Control Panel\UnsupportedHardwareNotificationCache"
    if (-not (Test-Path $uhncKey)) { New-Item -Path $uhncKey -Force | Out-Null }
    New-ItemProperty -Path $uhncKey -Name "SV2" -Value 0 -PropertyType DWord -Force | Out-Null

    # Set AllowTelemetry to 0
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
            Write-Host "Task $task not found or already removed." -ForegroundColor Yellow
        }
    }

    Write-Host "*** Windows Update is now targeting the Windows 11 $targetRelease update! ***" -ForegroundColor Green
    Write-Host "`n*** Registry modifications complete. ***" -ForegroundColor Green
}

#endregion

#region Section 3: Windows Update / ISO Upgrade Functions

function Invoke-ISOUpgrade {
    Write-Host "Downloading the latest ISO using Fido..." -ForegroundColor Cyan

    # Get current system language
    $currentLang = (Get-Culture).Name
    Write-Host "Detected system language: $currentLang" -ForegroundColor Cyan

    # Define fallback language that is known to work
    $fallbackLang = "English International"
    
    # Download Fido script if not already present
    $fidoPath = "$env:TEMP\Fido.ps1"
    if (-not (Test-Path $fidoPath)) {
        Write-Host "Downloading Fido.ps1 from GitHub..."
        try {
            Invoke-WebRequest "https://raw.githubusercontent.com/pbatard/Fido/master/Fido.ps1" -OutFile $fidoPath -ErrorAction Stop
            Write-Host "Fido.ps1 downloaded successfully." -ForegroundColor Green
        } catch {
            Write-Host "Error downloading Fido script: $_" -ForegroundColor Red
            exit 1
        }
    }
    
    # Function to retrieve ISO URL using a given language parameter
    function Get-IsoUrl($lang) {
        Write-Host "Attempting to retrieve ISO link with language: $lang" -ForegroundColor Cyan
        try {
            $isoUrl = & powershell -ExecutionPolicy Bypass -File $fidoPath `
                        -Win "Windows 11" -Rel "Latest" `
                        -Ed "Windows 11 Home/Pro/Edu" -Arch "x64" `
                        -Lang $lang -GetUrl
            return $isoUrl
        } catch {
            Write-Host "FIDO request failed for language $($lang): $_" -ForegroundColor Yellow
            return $null
        }
    }
    
    # Try with system language first
    $isoUrl = Get-IsoUrl $currentLang

    # If the output contains the invalid language error message, treat it as failure
    if ($isoUrl -match "Invalid Windows language provided") {
        Write-Host "ISO link error detected. Retrying with fallback language: $fallbackLang" -ForegroundColor Yellow
        $isoUrl = $null
    }
    
    # If the first attempt fails, try with the fallback language
    if (-not $isoUrl) {
        $isoUrl = Get-IsoUrl $fallbackLang
    }
    
    # Ensure a valid ISO URL was obtained
    if (-not $isoUrl) {
        Write-Host "Failed to retrieve ISO download link from Fido after multiple attempts." -ForegroundColor Red
        exit 1
    }
    
    Write-Host "ISO download link obtained: $isoUrl" -ForegroundColor Green
    
    # If multiple URLs are returned, use the first one
    if ($isoUrl -is [System.Array]) {
        $isoUrl = $isoUrl[0]
    }
    
    Write-Host "Final ISO URL: $isoUrl" -ForegroundColor Cyan
    
    # Define ISO path and download ISO
    $isoPath = "C:\Windows11.iso"
    try {
        Write-Host "Downloading ISO from $isoUrl..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $isoUrl -OutFile $isoPath -ErrorAction Stop
        Write-Host "ISO downloaded successfully to: $isoPath" -ForegroundColor Green
    } catch {
        Write-Host "Error downloading ISO: $_" -ForegroundColor Red
        exit 1
    }
    
    # Mounting ISO
    Write-Host "Mounting ISO..." -ForegroundColor Cyan
    try {
        $mountOutput = Mount-DiskImage -ImagePath $isoPath -PassThru -ErrorAction Stop
        Start-Sleep -Seconds 5  # Wait for the mount to complete
        $volume = Get-Volume -DiskImage $mountOutput
        if (-not $volume) {
            Write-Host "Failed to determine drive letter from mounted ISO." -ForegroundColor Red
            exit 1
        }
        $driveLetter = $volume.DriveLetter
        Write-Host ("ISO mounted to drive {0}: " -f $driveLetter) -ForegroundColor Green
    } catch {
        Write-Host "Error mounting ISO: $_" -ForegroundColor Red
        exit 1
    }
    
   # Patch_hwreqchk
# ---------------------------------------------------------
# This PowerShell script directly patches hwreqchk.dll to
# force all hardware requirement checks to always return "true".
-----------------------------------------------------------
$driveLetter = (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match ":\\" }).Name
$dllPath = "$($driveLetter):\sources\hwreqchk.dll"
$backupPath = "$dllPath.bak"

Write-Host "Attempting to patch hwreqchk.dll for automatic hardware requirement pass..." -ForegroundColor Cyan

# Ensure the DLL file exists before proceeding
if (!(Test-Path $dllPath)) {
    Write-Host "Error: DLL file not found at $dllPath" -ForegroundColor Red
    return
}

try {
    # Read the DLL file as a byte array
    $content = [System.IO.File]::ReadAllBytes($dllPath)

    # Hex patterns to modify (Converting checks to always pass)
    $patches = @(
        @{ Search = [byte[]](0x85, 0xC0, 0x74, 0x3D); Replace = [byte[]](0xB0, 0x01, 0x90, 0x90) } # JZ -> MOV AL, 1 (force pass)
        @{ Search = [byte[]](0x0F, 0x85); Replace = [byte[]](0x90, 0x90) } # JNZ -> NOP NOP
        @{ Search = [byte[]](0x0F, 0x84); Replace = [byte[]](0x90, 0x90) } # JZ -> NOP NOP
    )

    # Create a backup before modifying
    if (!(Test-Path $backupPath)) {
        Copy-Item $dllPath $backupPath -Force
        Write-Host "Backup created: $backupPath" -ForegroundColor Yellow
    }

    # Apply each patch
    foreach ($patch in $patches) {
        $searchBytes = $patch.Search
        $replaceBytes = $patch.Replace
        $index = -1

        # Search for the hex pattern in the file
        for ($i = 0; $i -le $content.Length - $searchBytes.Length; $i++) {
            $found = $true
            for ($j = 0; $j -lt $searchBytes.Length; $j++) {
                if ($content[$i + $j] -ne $searchBytes[$j]) {
                    $found = $false
                    break
                }
            }
            if ($found) {
                $index = $i
                break
            }
        }

        # If pattern found, patch the bytes
        if ($index -ge 0) {
            for ($k = 0; $k -lt $replaceBytes.Length; $k++) {
                $content[$index + $k] = $replaceBytes[$k]
            }
            Write-Host "Patched: " + ($searchBytes -join ' ') + " → " + ($replaceBytes -join ' ') -ForegroundColor Green
        }
        else {
            Write-Host "Pattern not found: " + ($searchBytes -join ' ') + ". Skipped." -ForegroundColor Yellow
        }
    }

    # Save the modified DLL file
    [System.IO.File]::WriteAllBytes($dllPath, $content)
    Write-Host "Successfully patched hwreqchk.dll! All hardware checks will now pass." -ForegroundColor Green

}
catch {
    Write-Host "Error: Something went wrong while modifying hwreqchk.dll - $_" -ForegroundColor Red
}

    
    # Launch Windows setup
    Write-Host "Starting setup.exe with /setup server parameter..." -ForegroundColor Cyan
    try {
        $setupPath = "$($driveLetter):\setup.exe"
        if (-not (Test-Path $setupPath)) {
            Write-Host "setup.exe not found at $setupPath" -ForegroundColor Red
            exit 1
        }
        Start-Process -FilePath $setupPath -ArgumentList "/auto upgrade" -Wait -ErrorAction Stop
    } catch {
        Write-Host "Error starting setup.exe: $_" -ForegroundColor Red
        exit 1
    }
}

function Invoke-WindowsUpdate {
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
#endregion

#region Section 4: Windows Update Reset Functions
function Reset-WindowsUpdate {
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
#endregion


function Remove-WUTargetRelease {
    Write-Host "Removing Windows Update target release settings..." -ForegroundColor Cyan
    $WinUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    Remove-ItemProperty -Path $WinUpdatePath -Name "ProductVersion" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersion" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersionInfo" -ErrorAction SilentlyContinue
    Write-Host "Target release settings removed." -ForegroundColor Green
}


#region Main Execution
switch ($installChoice) {
    "0" { Reset-WindowsUpdate }
    "1" { Set-WUTargetRelease; Set-BypassRegistryTweaks }
    "2" { Set-WUTargetRelease; Set-BypassRegistryTweaks; Invoke-ISOUpgrade }
    "3" { Set-WUTargetRelease; Set-BypassRegistryTweaks; Invoke-WindowsUpdate }
    "4" { Remove-WUTargetRelease }
    "5" { Write-Host "Exiting the script." -ForegroundColor Yellow; exit }
    default { Write-Host "Invalid selection. Exiting the script." -ForegroundColor Red; exit }
}



#endregion
