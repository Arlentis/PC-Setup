##############################################################
### SELF-ELEVATE TO ADMIN

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
    Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

New-PSDrive -Name "X" -PSProvider FileSystem -Root "\\fons\sharedx" -Credential HLX\CallumL -Persist

$ESETSetup = '\\fons\sharedx\Healix IT\ComputerSetup\ESET Antivirus Installer.exe'
$OfficeSetup = "\\fons\sharedx\\Healix IT\ComputerSetup\Microsoft Office\Office 2013 Standard 32bit\setup.exe"

### INSTALL ESET
Write-Host "Installing ESET..."
Start-Process -FilePath $ESETSetup -Verbose

### PROMPT FOR ESET INSTALLATION FINISHED 
Add-Type -AssemblyName PresentationCore,PresentationFramework
$ButtonType = [System.Windows.MessageBoxButton]::OKCancel
$MessageIcon = [System.Windows.MessageBoxImage]::Exclamation
$MessageBody = "Click OK when ESET has finished installing!"
$MessageTitle = "ESET Antivirus"
$Result = [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)

### INSTALL OFFICE
Write-Host "Installing Office..."
Start-Process -FilePath $OfficeSetup -Verbose

### PROMPT FOR OFFICE INSTALLATION FINISHED
$ButtonType2 = [System.Windows.MessageBoxButton]::OKCancel
$MessageIcon2 = [System.Windows.MessageBoxImage]::Exclamation
$MessageBody2 = "Click OK when Office has finished installing!"
$MessageTitle2 = "Microsoft Office"
$Result2 = [System.Windows.MessageBox]::Show($MessageBody2,$MessageTitle2,$ButtonType2,$MessageIcon2)

### OFFICE 2013 ACTIVATION
Write-Host "Activating Office..."
Set-Location "C:\Program Files (x86)\Microsoft Office\Office15"
cscript ospp.vbs /inpkey:8VHYT-6N33V-JDWGK-PX6B3-B96YG
cscript ospp.vbs /act


### ENABLE BITLOCKER
Write-Host "Enabling Bitlocker..."
$BLSecureString = ConvertTo-SecureString "Healix2016" -AsPlainText -Force
Enable-BitLocker -MountPoint $env:HOMEDRIVE -EncryptionMethod Aes256 -Pin $BLSecureString -TpmAndPinProtector -SkipHardwareTest
Start-Sleep 5
Add-BitLockerKeyProtector -MountPoint $env:HOMEDRIVE -RecoveryPasswordProtector

Write-Host "Backing Up Bitlocker Recovery Key..."
Start-Sleep -Seconds 10

### BACKUP RECOVERY KEY
$BLRecoveryFileName2 = (Get-BitLockerVolume -MountPoint $env:HOMEDRIVE).KeyProtector | Select-Object -Property "KeyProtectorId","RecoveryPassword" | Where-Object -Property "RecoveryPassword" -NE "" | ForEach-Object {$_.KeyProtectorID}
$BLRecoveryFileName1 = "$BLRecoveryFileName2".Trim('{}')
$BLRecoveryFileName = "BitLocker Recovery Key $BLRecoveryFileName1"
(Get-BitLockerVolume -MountPoint $env:HOMEDRIVE).KeyProtector | Select-Object -Property "KeyProtectorId","RecoveryPassword" | Where-Object -Property "RecoveryPassword" -NE "" | Format-List | Out-File "\\fons\sharedx\Healix IT\Healix Network\BitLocker Recovery\$BLRecoveryFileName.txt"
(Get-BitLockerVolume -MountPoint $env:HOMEDRIVE).KeyProtector | Select-Object -Property "KeyProtectorId","RecoveryPassword" | Where-Object -Property "RecoveryPassword" -NE "" | Format-List | Out-File "$env:USERPROFILE\Desktop\$BLRecoveryFileName.txt"


### COPY REMAPV2.BAT AND OPENVPN SHORTCUT TO PUBLIC DESKTOP
Write-Host "Copying ReMap to the Public Desktop..."
Copy-Item -Path "\\fons\sharedx\healix it\ReMapV2.bat" -Destination "$env:PUBLIC\Desktop\" -Force
Copy-Item -Path "$env:HOMEDRIVE\ProgramData\Microsoft\Windows\Start Menu\Programs\OpenVPN Connect.lnk" -Destination "$env:PUBLIC\Desktop" -Force



### ADD DOMAIN USERS TO ADMINISTRATORS GROUP
Write-Host "Adding Domain Users to the Administrators group..."
Add-LocalGroupMember -Group "Administrators" -Member "HLX\Domain Users"

### TURN ON NETWORK DISCOVERY & FILE&PRINTER SHARING
Write-Host "Turning on Network Discovery & File+Printer Sharing..."
netsh advfirewall firewall set rule group=”network discovery” new enable=yes
netsh firewall set service type=fileandprint mode=enable profile=all

### INSTALL MIMECAST SECURITY AGENT
Write-Host "Installing Mimecast Security Agent..."

$MimecastWebSecurity = "https://github.com/Arlentis/Installers/raw/main/Mimecast%20Security%20Agent%20(x64)%201.9.477.msi"
$MimecastDownloadPath = "$env:USERPROFILE\Downloads\MimecastWebSecurity.msi"
$MimecastCustomerKeyPath1 = "$env:USERPROFILE\Documents\CustomerKey"
$MimecastCustomerKeyPath2 = "$env:USERPROFILE\Downloads\CustomerKey"

New-Item $MimecastCustomerKeyPath1
Set-Content $MimecastCustomerKeyPath1 'LNkrwaJmExM_5F1Xvmw1z_j3lfulfkfTaLfkc5vp2mGOiFVRzfvBRP_qn3KENtPOu2ClN5FZlrB1D368Gfs19tBajd8Zih1oAdrfdnI7w9qRYwjuOZEYngbsmVIwNSQCE8-iL0ve2wqtGSQxV5Ec5nU4gQ9h9c4aHy1JMHBfL5Y'
New-Item $MimecastCustomerKeyPath2
Set-Content $MimecastCustomerKeyPath2 'LNkrwaJmExM_5F1Xvmw1z_j3lfulfkfTaLfkc5vp2mGOiFVRzfvBRP_qn3KENtPOu2ClN5FZlrB1D368Gfs19tBajd8Zih1oAdrfdnI7w9qRYwjuOZEYngbsmVIwNSQCE8-iL0ve2wqtGSQxV5Ec5nU4gQ9h9c4aHy1JMHBfL5Y'


Invoke-WebRequest $MimecastWebSecurity -OutFile $MimecastDownloadPath -Verbose

Start-Sleep -Seconds 5
Start-Process $MimecastDownloadPath

Start-Sleep -Seconds 15

$wshell = New-Object -ComObject wscript.shell;
Start-Sleep 2
$wshell.SendKeys("{ENTER}")
Start-Sleep 5
$wshell.SendKeys("{ENTER}")
Start-Sleep 5
$wshell.SendKeys("{ENTER}")
Start-Sleep 5
$wshell.SendKeys('CustomerKey')
Start-Sleep 5
$wshell.SendKeys("{ENTER}")
Start-Sleep 5
$wshell.SendKeys("{TAB}")
Start-Sleep 5
$wshell.SendKeys("{ENTER}")
Start-Sleep 5
$wshell.SendKeys("{ENTER}")
Start-Sleep 5
$wshell.SendKeys("{ENTER}")
Start-Sleep 120
$wshell.SendKeys("{ENTER}")


Remove-Item $MimecastWebSecurity -Force -ErrorAction SilentlyContinue
Remove-Item $MimecastCustomerKeyPath1
Remove-Item $MimecastCustomerKeyPath2

### INSTALL LANSWEEPER AGENT

$LSAgent ="https://github.com/Arlentis/Work-Healix/raw/main/LsAgent-windows.msi"
$LSAgentPath = "$env:USERPROFILE\Downloads\LsAgent-windows.msi"
Invoke-WebRequest $LSAgent -OutFile $LSAgentPath -Verbose
Start-Sleep -Seconds 5

Start-Process $LSAgentPath

Start-Sleep -Seconds 20
Remove-Item $LSAgentPath -Force -ErrorAction SilentlyContinue

### CHANGE COMPUTER LOCATION AND DESCRIPTION

#[System.Reflection.ASsembly]::LoadWithPartialName("Microsoft.VisualBasic")

#$ComputerLocation1 = [Microsoft.VisualBasic.Interaction]::InputBox("Enter Computer Location","PC Location","Who's using this computer?")
#$ComputerLocation = $ComputerLocation1

#$ComputerDescription1 = [Microsoft.VisualBasic.Interaction]::InputBox("Enter Computer Description","PC Description","Asset Sticker? What's this being used for? Service Desk Number?")
#$ComputerDescription = $ComputerDescription1

#$session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://iris.hlx.int/powershell/ -Credential HLX\CLAdmin -Authentication Kerberos
#Import-PSSession $session -AllowClobber -Verbose

#Set-ADComputer -Identity $env:COMPUTERNAME -Location $ComputerLocation -Verbose
#Set-ADComputer -Identity $env:COMPUTERNAME -Description $ComputerDescription -Verbose

#Remove-PSSession $session

