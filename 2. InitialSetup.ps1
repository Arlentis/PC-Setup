##############################################################
### SELF-ELEVATE TO ADMIN

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
    Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

##############################################################
### CHECK FOR WINDOWS UPDATES
wuauclt /detectnow /updatenow
usoclient /startdownload /startinstall

##############################################################
### FIND/REMOVE APPX PACKAGES AND UNINSTALL (EXCEPT PAINT, CALCULATOR, STORE, PHOTOS)

param (
  [switch]$Debloat, [switch]$SysPrep
)

Function Begin-SysPrep {

    param([switch]$SysPrep)
        Write-Verbose -Message ('Starting Sysprep Fixes')

 } 

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
Function Start-Debloat {
    
    param([switch]$Debloat)

    [regex]$WhitelistedApps = 'Microsoft.ScreenSketch|Microsoft.Paint3D|Microsoft.WindowsCalculator|Microsoft.WindowsStore|Microsoft.Windows.Photos|CanonicalGroupLimited.UbuntuonWindows|`
    Microsoft.MicrosoftStickyNotes|Microsoft.MSPaint|Microsoft.WindowsCamera|.NET|Framework|Microsoft.HEIFImageExtension|Microsoft.ScreenSketch|Microsoft.StorePurchaseApp|`
    Microsoft.VP9VideoExtensions|Microsoft.WebMediaExtensions|Microsoft.WebpImageExtension|Microsoft.DesktopAppInstaller'
    Get-AppxPackage -AllUsers | Where-Object {$_.Name -NotMatch $WhitelistedApps} | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers | Where-Object {$_.Name -NotMatch $WhitelistedApps} | Remove-AppxPackage -ErrorAction SilentlyContinue
    $AppxRemoval = Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -NotMatch $WhitelistedApps} 
    ForEach ( $App in $AppxRemoval) {
    
        Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName 
        
        }
}

Function Remove-Keys {
        
    Param([switch]$Debloat)    
    
        
    $Keys = @(
        
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    )
    
    ForEach ($Key in $Keys) {
        Write-Output "Removing $Key from registry"
        Remove-Item $Key -Recurse -ErrorAction SilentlyContinue
    }
}
        
Function Protect-Privacy {
    
    Param([switch]$Debloat)    

    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
        
    Write-Output "Disabling Windows Feedback Experience program"
    $Advertising = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
    If (Test-Path $Advertising) {
        Set-ItemProperty $Advertising -Name Enabled -Value 0 -Verbose
    }
        
    Write-Output "Stopping Cortana from being used as part of your Windows Search Function"
    $Search = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
    If (Test-Path $Search) {
        Set-ItemProperty $Search -Name AllowCortana -Value 0 -Verbose
    }
        
    Write-Output "Stopping the Windows Feedback Experience program"
    $Period1 = 'HKCU:\Software\Microsoft\Siuf'
    $Period2 = 'HKCU:\Software\Microsoft\Siuf\Rules'
    $Period3 = 'HKCU:\Software\Microsoft\Siuf\Rules\PeriodInNanoSeconds'
    If (!(Test-Path $Period3)) { 
        mkdir $Period1 -ErrorAction SilentlyContinue
        mkdir $Period2 -ErrorAction SilentlyContinue
        mkdir $Period3 -ErrorAction SilentlyContinue
        New-ItemProperty $Period3 -Name PeriodInNanoSeconds -Value 0 -Verbose -ErrorAction SilentlyContinue
    }
               
    Write-Output "Adding Registry key to prevent bloatware apps from returning"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    If (!(Test-Path $registryPath)) {
        Mkdir $registryPath -ErrorAction SilentlyContinue
        New-ItemProperty $registryPath -Name DisableWindowsConsumerFeatures -Value 1 -Verbose -ErrorAction SilentlyContinue
    }          
    
    Write-Output "Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings"
    $Holo = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic'    
    If (Test-Path $Holo) {
        Set-ItemProperty $Holo -Name FirstRunSucceeded -Value 0 -Verbose
    }
    
    Write-Output "Disabling live tiles"
    $Live = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'    
    If (!(Test-Path $Live)) {
        mkdir $Live -ErrorAction SilentlyContinue     
        New-ItemProperty $Live -Name NoTileApplicationNotification -Value 1 -Verbose
    }
    
    Write-Output "Turning off Data Collection"
    $DataCollection = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'    
    If (Test-Path $DataCollection) {
        Set-ItemProperty $DataCollection -Name AllowTelemetry -Value 0 -Verbose
    }
    
    Write-Output "Disabling People icon on Taskbar"
    $People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
    If (Test-Path $People) {
        Set-ItemProperty $People -Name PeopleBand -Value 0 -Verbose
    }

    Write-Output "Disabling suggestions on the Start Menu"
    $Suggestions = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'    
    If (Test-Path $Suggestions) {
        Set-ItemProperty $Suggestions -Name SystemPaneSuggestionsEnabled -Value 0 -Verbose
    }
    
    
     Write-Output "Removing CloudStore from registry if it exists"
     $CloudStore = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore'
     If (Test-Path $CloudStore) {
     Stop-Process Explorer.exe -Force
     Remove-Item $CloudStore -Recurse -Force
     Start-Process Explorer.exe -Wait
    }

    reg load HKU\Default_User C:\Users\Default\NTUSER.DAT
    Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SystemPaneSuggestionsEnabled -Value 0
    Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name PreInstalledAppsEnabled -Value 0
    Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name OemPreInstalledAppsEnabled -Value 0
    reg unload HKU\Default_User
    
    Write-Output "Disabling scheduled tasks"
    Get-ScheduledTask -TaskName XblGameSaveTask | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskName Consolidator | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskName UsbCeip | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskName DmClient | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskName DmClientOnScenarioDownload | Disable-ScheduledTask -ErrorAction SilentlyContinue
}

Function FixWhitelistedApps {
    
    Param([switch]$Debloat)
    
    If(!(Get-AppxPackage -AllUsers | Select Microsoft.Paint3D, Microsoft.MSPaint, Microsoft.WindowsCalculator, Microsoft.WindowsStore, Microsoft.MicrosoftStickyNotes, Microsoft.WindowsSoundRecorder, Microsoft.Windows.Photos)) {
    
    Get-AppxPackage -allusers Microsoft.Paint3D | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -allusers Microsoft.MSPaint | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -allusers Microsoft.WindowsCalculator | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -allusers Microsoft.WindowsStore | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -allusers Microsoft.MicrosoftStickyNotes | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -allusers Microsoft.WindowsSoundRecorder | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -allusers Microsoft.Windows.Photos | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"} }
}

Function CheckDMWService {

  Param([switch]$Debloat)
  
If (Get-Service -Name dmwappushservice | Where-Object {$_.StartType -eq "Disabled"}) {
    Set-Service -Name dmwappushservice -StartupType Automatic}

If(Get-Service -Name dmwappushservice | Where-Object {$_.Status -eq "Stopped"}) {
   Start-Service -Name dmwappushservice} 
  }

Function CheckInstallService {
  Param([switch]$Debloat)
          If (Get-Service -Name InstallService | Where-Object {$_.Status -eq "Stopped"}) {  
            Start-Service -Name InstallService
            Set-Service -Name InstallService -StartupType Automatic 
            }
        }

Write-Output "Initiating Sysprep"
Begin-SysPrep
Write-Output "Removing bloatware apps."
Start-Debloat
Write-Output "Removing leftover bloatware registry keys."
Remove-Keys
Write-Output "Checking to see if any Whitelisted Apps were removed, and if so re-adding them."
FixWhitelistedApps
Write-Output "Stopping telemetry, disabling unneccessary scheduled tasks, and preventing bloatware from returning."
Protect-Privacy
CheckDMWService
CheckInstallService
Write-Output "Finished all tasks."

REMOVE ALL BUILT IN WIN10 APPS, THEN RE-INSTALL ESSENTIALS
Get-AppxPackage * | Remove-AppPackage
Get-AppXPackage *WindowsStore* -AllUsers | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppXPackage *Calculator* -AllUsers | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}


#######################################################################
### SET TRAY TO SHOW ALL ICONS IN TASKBAR

$traypath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
$tray = "EnableAutoTray"
$trayno = "0"
IF(!(Test-Path $traypath))
  {
    New-Item -Path $traypath -Force | Out-Null
    New-ItemProperty -Path $traypath -Name $tray -Value $trayno `
    -PropertyType DWORD -Force | Out-Null}
 ELSE {
    New-ItemProperty -Path $traypath -Name $tray -Value $trayno `
    -PropertyType DWORD -Force | Out-Null}


#######################################################################
### HIDE THE SEARCH BAR IN TASKBAR

$searchpath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
$search = "SearchboxTaskbarMode"
$searchno = "0"
IF(!(Test-Path $searchpath))
  {
    New-Item -Path $searchpath -Force | Out-Null
    New-ItemProperty -Path $searchpath -Name $search -Value $searchno `
    -PropertyType DWORD -Force | Out-Null}
 ELSE {
    New-ItemProperty -Path $searchpath -Name $search -Value $searchno `
    -PropertyType DWORD -Force | Out-Null}

#######################################################################
### HIDE CORTANA ICON IN TASKBAR

$cortanapath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$cortana = "ShowCortanaButton"
$cortanano = "0"
IF(!(Test-Path $cortanapath))
  {
    New-Item -Path $cortanapath -Force | Out-Null
    New-ItemProperty -Path $cortanapath -Name $cortana -Value $cortanano `
    -PropertyType DWORD -Force | Out-Null}
 ELSE {
    New-ItemProperty -Path $cortanapath -Name $cortana -Value $cortanano `
    -PropertyType DWORD -Force | Out-Null}

#######################################################################
### USE SMALL TASKBAR ICONS INSTEAD OF LARGE

$smalliconpath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$smallicon = "TaskbarSmallIcons"
$smalliconno = "1"
IF(!(Test-Path $smalliconpath))
  {
    New-Item -Path $smalliconpath -Force | Out-Null
    New-ItemProperty -Path $smalliconpath -Name $smallicon -Value $smalliconno `
    -PropertyType DWORD -Force | Out-Null}
 ELSE {
    New-ItemProperty -Path $smalliconpath -Name $smallicon -Value $smalliconno `
    -PropertyType DWORD -Force | Out-Null}

#######################################################################
### USE DARK THEME INSTEAD OF LIGHT

New-Item –Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" –Name Personalize -ErrorAction SilentlyContinue
New-Item –Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" –Name Personalize -ErrorAction SilentlyContinue

$darkpath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
$dark = "AppsUseLightTheme"
$darkno = "0"
IF(!(Test-Path $darkpath))
  {
    New-Item -Path $darkpath -Force | Out-Null
    New-ItemProperty -Path $darkpath -Name $dark -Value $darkno `
    -PropertyType DWORD -Force | Out-Null}
 ELSE {
    New-ItemProperty -Path $darkpath -Name $dark -Value $darkno `
    -PropertyType DWORD -Force | Out-Null}

$darkpath2 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
$dark2 = "AppsUseLightTheme"
$darkno2 = "0"
IF(!(Test-Path $darkpath2))
  {
    New-Item -Path $darkpath2 -Force | Out-Null
    New-ItemProperty -Path $darkpath2 -Name $dark2 -Value $darkno2 `
    -PropertyType DWORD -Force | Out-Null}
 ELSE {
    New-ItemProperty -Path $darkpath2 -Name $dark2 -Value $darkno2 `
    -PropertyType DWORD -Force | Out-Null}

#######################################################################
### DISABLE USER ACCOUNT CONTROL (UAC)

$osversion = (Get-CimInstance Win32_OperatingSystem).Version 
$version = $osversion.split(".")[0] 
 
if ($version -eq 10) { 
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value "0" 
} ElseIf ($Version -eq 6) { 
    $sub = $version.split(".")[1] 
    if ($sub -eq 1 -or $sub -eq 0) { 
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value "0" 
    } Else { 
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value "0" 
    } 
} ElseIf ($Version -eq 5) { 
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value "0" 
} Else { 
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value "0" 
}

#######################################################################
### SHOW HIDDEN FLES AND FOLDERS

$hiddenpath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$hidden = "Hidden"
$hiddenno = "1"
IF(!(Test-Path $hiddenpath))
  {
    New-Item -Path $hiddenpath -Force | Out-Null
    New-ItemProperty -Path $hiddenpath -Name $hidden -Value $hiddenno `
    -PropertyType DWORD -Force | Out-Null}
 ELSE {
    New-ItemProperty -Path $hiddenpath -Name $hidden -Value $hiddenno `
    -PropertyType DWORD -Force | Out-Null}

#######################################################################
### SHOW ALL FILE EXTENSIONS

$extpath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$ext = "HideFileExt"
$extno = "0"
IF(!(Test-Path $extpath))
  {
    New-Item -Path $extpath -Force | Out-Null
    New-ItemProperty -Path $extpath -Name $ext -Value $extno `
    -PropertyType DWORD -Force | Out-Null}
 ELSE {
    New-ItemProperty -Path $extpath -Name $ext -Value $extno `
    -PropertyType DWORD -Force | Out-Null}


#######################################################################
### DISABLE MICROSOFT CONSUMER PROMOTIONS

$mspath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$ms = "DisableWindowsConsumerFeatures"
$msno = "1"
IF(!(Test-Path $mspath))
  {
    New-Item -Path $mspath -Force | Out-Null
    New-ItemProperty -Path $mspath -Name $ms -Value $msno `
    -PropertyType DWORD -Force | Out-Null}
 ELSE {
    New-ItemProperty -Path $mspath -Name $ms -Value $msno `
    -PropertyType DWORD -Force | Out-Null}

#######################################################################
### BITLOCKER ENHANCED PIN & STARTUP 

$BitlockerAdvancedPassPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
$BitlockerAdvancedPass = "UseAdvancedStartup"
$BitlockerAdvancedPassNo = "1"
IF(!(Test-Path $BitlockerAdvancedPassPath))
  {
    New-Item -Path $BitlockerAdvancedPassPath -Force | Out-Null
    New-ItemProperty -Path $BitlockerAdvancedPassPath -Name $BitlockerAdvancedPass -Value $BitlockerAdvancedPassNo `
    -PropertyType DWORD -Force | Out-Null}
 ELSE {
    New-ItemProperty -Path $BitlockerAdvancedPassPath -Name $BitlockerAdvancedPass -Value $BitlockerAdvancedPassNo `
    -PropertyType DWORD -Force | Out-Null}

###
$BitlockerEnhancedPinPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
$BitlockerEnhancedPin = "UseEnhancedPin"
$BitlockerEnhancedPinNo = "1"
IF(!(Test-Path $BitlockerEnhancedPinPath))
  {
    New-Item -Path $BitlockerEnhancedPinPath -Force | Out-Null
    New-ItemProperty -Path $BitlockerEnhancedPinPath -Name $BitlockerEnhancedPin -Value $BitlockerEnhancedPinNo `
    -PropertyType DWORD -Force | Out-Null}
 ELSE {
    New-ItemProperty -Path $BitlockerEnhancedPinPath -Name $BitlockerEnhancedPin -Value $BitlockerEnhancedPinNo `
    -PropertyType DWORD -Force | Out-Null}

###
$BitlockerBDEPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
$BitlockerBDE = "EnableBDEWithNoTPM"
$BitlockerBDENo = "1"
IF(!(Test-Path $BitlockerBDEPath))
  {
    New-Item -Path $BitlockerBDEPath -Force | Out-Null
    New-ItemProperty -Path $BitlockerBDEPath -Name $BitlockerBDE -Value $BitlockerBDENo `
    -PropertyType DWORD -Force | Out-Null}
 ELSE {
    New-ItemProperty -Path $BitlockerBDEPath -Name $BitlockerBDE -Value $BitlockerBDENo `
    -PropertyType DWORD -Force | Out-Null}

###
$BitlockerUseTPMPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
$BitlockerUseTPM = "UseTPM"
$BitlockerUseTPMNo = "2"
IF(!(Test-Path $BitlockerUseTPMPath))
  {
    New-Item -Path $BitlockerUseTPMPath -Force | Out-Null
    New-ItemProperty -Path $BitlockerUseTPMPath -Name $BitlockerUseTPM -Value $BitlockerUseTPMNo `
    -PropertyType DWORD -Force | Out-Null}
 ELSE {
    New-ItemProperty -Path $BitlockerUseTPMPath -Name $BitlockerUseTPM -Value $BitlockerUseTPMNo `
    -PropertyType DWORD -Force | Out-Null}

###
$BitlockerTPMKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
$BitlockerTPMKey = "UseTPMKey"
$BitlockerTPMKeyNo = "2"
IF(!(Test-Path $BitlockerTPMKeyPath))
  {
    New-Item -Path $BitlockerTPMKeyPath -Force | Out-Null
    New-ItemProperty -Path $BitlockerTPMKeyPath -Name $BitlockerTPMKey -Value $BitlockerTPMKeyNo `
    -PropertyType DWORD -Force | Out-Null}
 ELSE {
    New-ItemProperty -Path $BitlockerTPMKeyPath -Name $BitlockerTPMKey -Value $BitlockerTPMKeyNo `
    -PropertyType DWORD -Force | Out-Null}

###
$BitlockerTPMKeyPinPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
$BitlockerTPMKeyPin = "UseTPMKeyPin"
$BitlockerTPMKeyPinNo = "2"
IF(!(Test-Path $BitlockerTPMKeyPath))
  {
    New-Item -Path $BitlockerTPMKeyPinPath -Force | Out-Null
    New-ItemProperty -Path $BitlockerTPMKeyPinPath -Name $BitlockerTPMKeyPin -Value $BitlockerTPMKeyPinNo `
    -PropertyType DWORD -Force | Out-Null}
 ELSE {
    New-ItemProperty -Path $BitlockerTPMKeyPinPath -Name $BitlockerTPMKeyPin -Value $BitlockerTPMKeyPinNo `
    -PropertyType DWORD -Force | Out-Null}

###
$BitlockerTPMPINPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
$BitlockerTPMPIN = "UseTPMPIN"
$BitlockerTPMPINNo = "2"
IF(!(Test-Path $BitlockerTPMKeyPath))
  {
    New-Item -Path $BitlockerTPMPINPath -Force | Out-Null
    New-ItemProperty -Path $BitlockerTPMPINPath -Name $BitlockerTPMPIN -Value $BitlockerTPMPINNo `
    -PropertyType DWORD -Force | Out-Null}
 ELSE {
    New-ItemProperty -Path $BitlockerTPMPINPath -Name $BitlockerTPMPIN -Value $BitlockerTPMPINNo `
    -PropertyType DWORD -Force | Out-Null}

#######################################################################
### PROGRAMS INSTALL (CHOCO)

Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

choco feature enable -n allowGlobalConfirmation

choco install choco-upgrade-all-at-startup
choco install dogtail.dotnet3.5sp1
choco install dotnet1.1
choco install dotnet3.5
choco install dotnet4.0
choco install dotnet4.5
choco install dotnet4.5.1
choco install dotnet4.5.2
choco install dotnet4.6
choco install dotnet4.6.1
choco install dotnet4.7
choco install dotnet4.7.1
choco install dotnet4.7.2
choco install dotnetcore-runtime
choco install dotnetfx
choco install javaruntime
choco install jre8
choco install msvisualcplusplus2012-redist
choco install msvisualcplusplus2013-redist
choco install netfx-4.6.2
choco install netfx-4.6.2
choco install netfx-4.8
choco install powershell
choco install powershell4
choco install vcredist-all
choco install vcredist140
choco install vcredist2005
choco install vcredist2010
choco install vcredist2012
choco install vcredist2013
choco install vcredist2015
choco install vcredist2017
#choco install rsat

#choco install 7-taskbar-tweaker
choco install 7zip
#choco install adexplorer
choco install adobereader
#choco install anydesk
#choco install cpu-z
#choco install crystaldiskinfo
#choco install cutepdf
#choco install discord
choco install drawio
#choco install dropbox
#choco install eartrumpet
#choco install epicgameslauncher
#choco install firefox
#choco install firefoxesr
#choco install fluent-terminal
#choco install gimp
choco install googlechrome
#choco install googledrive
#choco install googleearth
#choco install handbrake
#choco install hwinfo
#choco install imageresizerapp
#choco install licecap
choco install lightshot
#choco install lively
#choco install microsoft-teams
#choco install modernflyouts
#choco install nmap
#choco install notepadplusplus
choco install obs-studio
#choco install opera
choco install pdf24
#choco install picard
#choco install powertoys
choco install procexp
#choco install qbittorrent
#choco install quicklook
#choco install rainmeter
#choco install rufus
#choco install safari
choco install silverlight
#choco install simplenote
choco install skype
#choco install spotify
#choco install steam
#choco install synctrayzor
#choco install teamspeak
#choco install teamviewer9
#choco install vivaldi
choco install vlc
#choco install vmware-workstation-player
#choco install vscode
#choco install waterfox
#choco install whatsapp
#choco install winaero-tweaker
#choco install windows10-media-creation-tool
#choco install winxcorners
#choco install wireguard
#choco install wireshark
choco install wiztree
#choco install zoom


#######################################################################
### INSTALL OPEN VPN

$OVPNDownload ="https://github.com/Arlentis/Work-Healix/raw/main/openvpn-connect-2.7.1.110_signed.msi"
$OpenVPNFilePath = "$env:USERPROFILE\Downloads\openvpn-connect-2.7.1.110_signed.msi"
Invoke-WebRequest $OVPNDownload -OutFile $OpenVPNFilePath -Verbose
Start-Sleep -Seconds 5

Start-Process C:\Users\Admin\Downloads\openvpn-connect-2.7.1.110_signed.msi

Start-Sleep -Seconds 20
Remove-Item $OpenVPNFilePath -Force -ErrorAction SilentlyContinue

#######################################################################
### UNPIN EVERYTHING FROM START MENU

(New-Object -Com Shell.Application).
    NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').
    Items() |
  %{ $_.Verbs() } |
  ?{$_.Name -match 'Un.*pin from Start'} |
  %{$_.DoIt()}


#######################################################################
### UNPIN EVERYTHING FROM TASKBAR

function Pin-App ([string]$appname, [switch]$unpin, [switch]$start, [switch]$taskbar, [string]$path) {
    if ($unpin.IsPresent) {
        $action = "Unpin"
    } else {
        $action = "Pin"
    }
    
    if (-not $taskbar.IsPresent -and -not $start.IsPresent) {
        Write-Error "Specify -taskbar and/or -start!"
    }
    
    if ($taskbar.IsPresent) {
        try {
            $exec = $false
            if ($action -eq "Unpin") {
                ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $appname}).Verbs() | ?{$_.Name.replace('&','') -match 'Unpin from taskbar'} | %{$_.DoIt(); $exec = $true}
                if ($exec) {
                    Write "App '$appname' unpinned from Taskbar"
                } else {
                    if (-not $path -eq "") {
                        Pin-App-by-Path $path -Action $action
                    } else {
                        Write "'$appname' not found or 'Unpin from taskbar' not found on item!"
                    }
                }
            } else {
                ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $appname}).Verbs() | ?{$_.Name.replace('&','') -match 'Pin to taskbar'} | %{$_.DoIt(); $exec = $true}
                
                if ($exec) {
                    Write "App '$appname' pinned to Taskbar"
                } else {
                    if (-not $path -eq "") {
                        Pin-App-by-Path $path -Action $action
                    } else {
                        Write "'$appname' not found or 'Pin to taskbar' not found on item!"
                    }
                }
            }
        } catch {
            Write-Error "Error Pinning/Unpinning $appname to/from taskbar!"
        }
    }
    
    if ($start.IsPresent) {
        try {
            $exec = $false
            if ($action -eq "Unpin") {
                ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $appname}).Verbs() | ?{$_.Name.replace('&','') -match 'Unpin from Start'} | %{$_.DoIt(); $exec = $true}
                
                if ($exec) {
                    Write "App '$appname' unpinned from Start"
                } else {
                    if (-not $path -eq "") {
                        Pin-App-by-Path $path -Action $action -start
                    } else {
                        Write "'$appname' not found or 'Unpin from Start' not found on item!"
                    }
                }
            } else {
                ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $appname}).Verbs() | ?{$_.Name.replace('&','') -match 'Pin to Start'} | %{$_.DoIt(); $exec = $true}
                
                if ($exec) {
                    Write "App '$appname' pinned to Start"
                } else {
                    if (-not $path -eq "") {
                        Pin-App-by-Path $path -Action $action -start
                    } else {
                        Write "'$appname' not found or 'Pin to Start' not found on item!"
                    }
                }
            }
        } catch {
            Write-Error "Error Pinning/Unpinning $appname to/from Start!"
        }
    }
}

function Pin-App-by-Path([string]$Path, [string]$Action, [switch]$start) {
    if ($Path -eq "") {
        Write-Error -Message "You need to specify a Path" -ErrorAction Stop
    }
    if ($Action -eq "") {
        Write-Error -Message "You need to specify an action: Pin or Unpin" -ErrorAction Stop
    }
    if ((Get-Item -Path $Path -ErrorAction SilentlyContinue) -eq $null){
        Write-Error -Message "$Path not found" -ErrorAction Stop
    }
    $Shell = New-Object -ComObject "Shell.Application"
    $ItemParent = Split-Path -Path $Path -Parent
    $ItemLeaf = Split-Path -Path $Path -Leaf
    $Folder = $Shell.NameSpace($ItemParent)
    $ItemObject = $Folder.ParseName($ItemLeaf)
    $Verbs = $ItemObject.Verbs()
    
    if ($start.IsPresent) {
        switch($Action){
            "Pin"   {$Verb = $Verbs | Where-Object -Property Name -EQ "&Pin to Start"}
            "Unpin" {$Verb = $Verbs | Where-Object -Property Name -EQ "Un&pin from Start"}
            default {Write-Error -Message "Invalid action, should be Pin or Unpin" -ErrorAction Stop}
        }
    } else {
        switch($Action){
            "Pin"   {$Verb = $Verbs | Where-Object -Property Name -EQ "Pin to Tas&kbar"}
            "Unpin" {$Verb = $Verbs | Where-Object -Property Name -EQ "Unpin from Tas&kbar"}
            default {Write-Error -Message "Invalid action, should be Pin or Unpin" -ErrorAction Stop}
        }
    }
    
    if($Verb -eq $null){
        Write-Error -Message "That action is not currently available on this Path" -ErrorAction Stop
    } else {
        $Result = $Verb.DoIt()
    }
}

Pin-App "Opera Browser" -unpin -taskbar
Pin-App "Microsoft Edge" -unpin -taskbar
Pin-App "Mail" -unpin -taskbar
Pin-App "Windows Store" -unpin -taskbar
Pin-App "Microsoft Store" -unpin -taskbar
Pin-App "Store" -unpin -taskbar

#######################################################################
### REMOVE ANY STOCK DESKTOP SHORTCUTS

Remove-Item -Path $env:ALLUSERSPROFILE\Desktop\*
Remove-Item -Path $env:USERPROFILE\Desktop\* 
Remove-Item -Path $env:HOMEDRIVE\Users\Public\Desktop\*


#######################################################################
### ENABLE POWERSHELL REMOTING

Enable-PSRemoting -SkipNetworkProfileCheck -Force 

Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Set-Service WinRM -StartMode Automatic
Set-Item WSMan:localhost\client\trustedhosts -value * -Force

#######################################################################
### CHANGE NETWORK PROFILE TO PRIVATE

Set-NetConnectionProfile -InterfaceAlias Ethernet0 -NetworkCategory Private -ErrorAction SilentlyContinue
Set-NetConnectionProfile -InterfaceAlias Ethernet1 -NetworkCategory Private -ErrorAction SilentlyContinue
Set-NetConnectionProfile -InterfaceAlias Ethernet -NetworkCategory Private -ErrorAction SilentlyContinue
Set-NetConnectionProfile -InterfaceAlias WiFi -NetworkCategory Private -ErrorAction SilentlyContinue
Set-NetConnectionProfile -InterfaceAlias Wireless -NetworkCategory Private -ErrorAction SilentlyContinue
Set-NetConnectionProfile -InterfaceAlias WiFi1 -NetworkCategory Private -ErrorAction SilentlyContinue

#######################################################################
###  ENABLE SMB1 TO ALLOW COMPUTER TO JOIN DOMAIN
Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Server -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Deprecation -NoRestart


#######################################################################
###  RESTART EXPLORER - APPLY ALL PREVIOUS CHANGES & DELETE LEFTOVER ACCOUNT
Stop-Process -ProcessName explorer
Remove-LocalUser -Name "ASPNET"

#######################################################################
### CLOSE PROGRAMS THAT OPEN AFTER INSTALL....
Stop-Process -ProcessName TeamViewer -Force
Stop-Process -ProcessName TeamViewer_Service -Force
Stop-Process -ProcessName Skype -Force
Stop-Process -ProcessName OneDrive -Force
Stop-Process -ProcessName RainMeter -Force


#######################################################################
### REMOVE ANY STOCK DESKTOP SHORTCUTS
Remove-Item -Path $env:ALLUSERSPROFILE\Desktop\*
Remove-Item -Path $env:USERPROFILE\Desktop\* 
Remove-Item -Path $env:HOMEDRIVE\Users\Public\Desktop\*

#######################################################################
### RENAME COMPUTER
[System.Reflection.ASsembly]::LoadWithPartialName("Microsoft.VisualBasic")

$HLXComputerName1 = [Microsoft.VisualBasic.Interaction]::InputBox("Enter Computer Name","PC Name","HLX-")
$HLXComputerName = $HLXComputerName1

Rename-Computer -ComputerName $env:COMPUTERNAME -NewName $HLXComputerName 


#######################################################################
### RESTART LAPTOP
Restart-Computer -Force
