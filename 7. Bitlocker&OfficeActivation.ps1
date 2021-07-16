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