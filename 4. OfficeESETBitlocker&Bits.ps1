##############################################################
### SELF-ELEVATE TO ADMIN

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
    Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

New-PSDrive -Name "X" -PSProvider FileSystem -Root "\\fons\sharedx" -Credential HLX\CallumL -Persist

$ESETSetup = '\\fons\sharedx\healix it\temp\ESMC_Installer_x64_en_US_DHURLTEST.exe'
$OfficeSetup = "\\fons\sharedx\\Healix IT\ComputerSetup\Microsoft Office\Office 2013 Standard 32bit\setup.exe"

Start-Process -FilePath $ESETSetup -Verbose
Start-Sleep -Seconds 480
Start-Process -FilePath $OfficeSetup -Verbose

Start-Sleep -Seconds 900

### OFFICE 2013 ACTIVATION
cd "C:\Program Files (x86)\Microsoft Office\Office15"
cscript ospp.vbs /inpkey:8VHYT-6N33V-JDWGK-PX6B3-B96YG
cscript ospp.vbs /act


### ENABLE BITLOCKER
$BLSecureString = ConvertTo-SecureString "Healix2016" -AsPlainText -Force
Enable-BitLocker -MountPoint $env:HOMEDRIVE -EncryptionMethod Aes256 -Pin $BLSecureString -TpmAndPinProtector -SkipHardwareTest
Start-Sleep 5
Add-BitLockerKeyProtector -MountPoint $env:HOMEDRIVE -RecoveryPasswordProtector

Start-Sleep -Seconds 10
### BACKUP RECOVERY KEY
$BLRecoveryFileName2 = (Get-BitLockerVolume -MountPoint $env:HOMEDRIVE).KeyProtector | Select-Object -Property "KeyProtectorId","RecoveryPassword" | Where-Object -Property "RecoveryPassword" -NE "" | ForEach {$_.KeyProtectorID}
$BLRecoveryFileName1 = "$BLRecoveryFileName2".Trim('{}')
$BLRecoveryFileName = "BitLocker Recovery Key $BLRecoveryFileName1"
(Get-BitLockerVolume -MountPoint $env:HOMEDRIVE).KeyProtector | Select-Object -Property "KeyProtectorId","RecoveryPassword" | Where-Object -Property "RecoveryPassword" -NE "" | FL | Out-File "\\fons\sharedx\Healix IT\Healix Network\BitLocker Recovery\$BLRecoveryFileName.txt"
(Get-BitLockerVolume -MountPoint $env:HOMEDRIVE).KeyProtector | Select-Object -Property "KeyProtectorId","RecoveryPassword" | Where-Object -Property "RecoveryPassword" -NE "" | FL | Out-File "$env:USERPROFILE\Desktop\$BLRecoveryFileName.txt"


### COPY REMAPV2.BAT TO PUBLIC DESKTOP
Copy-Item -Path "\\fons\sharedx\healix it\ReMapV2.bat" -Destination "$env:PUBLIC\Desktop\" -Force

### ADD DOMAIN USERS TO ADMINISTRATORS GROUP
Add-LocalGroupMember -Group "Administrators" -Member "HLX\Domain Users"

### TURN ON NETWORK DISCOVERY & FILE&PRINTER SHARING
netsh advfirewall firewall set rule group=”network discovery” new enable=yes
netsh firewall set service type=fileandprint mode=enable profile=all


