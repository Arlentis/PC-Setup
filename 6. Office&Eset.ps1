New-PSDrive -Name "X" -PSProvider FileSystem -Root "\\fons\sharedx" -Credential HLX\CallumL -Persist

$OfficeSetup = "\\fons\sharedx\healix it\callum\installs\Microsoft Office\Office 2013 Standard 32bit\setup.exe"
$ESETSetup = '\\fons\sharedx\healix it\temp\ESMC_Installer_x64_en_US_DHURLTEST.exe'

Start-Process -FilePath $OfficeSetup -Verbose
Start-Process -FilePath $ESETSetup -Verbose