[System.Reflection.ASsembly]::LoadWithPartialName("Microsoft.VisualBasic")

$ComputerName1 = [Microsoft.VisualBasic.Interaction]::InputBox("Enter Computer Name","PC Name","HLX-")
$ComputerName = $ComputerName1

Rename-Computer -ComputerName $env:COMPUTERNAME -NewName $ComputerName -LocalCredential "$env:COMPUTERNAME\$env:USERNAME" -Force

Add-Computer -DomainName hlx.int -Credential HLX\CLAdmin -Restart -Force