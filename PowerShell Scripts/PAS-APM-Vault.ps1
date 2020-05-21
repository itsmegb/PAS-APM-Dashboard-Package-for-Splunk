#Service Status Check for Vault Server
$HostName = "$env:computername"
$SYSLOGPORT = 51444
$SYSLOGSERVER="10.0.0.2"
$Version = "2.0.0000"
$Date = Get-Date
$DateTime = $DATE.ToString("yyyy-MM-ddTHH:mm:ssZ")
$IsHACluster = $false

function SendSyslogMessage {
    param (
        [Parameter(Mandatory=$true)] [String] $Message,
        [Parameter(Mandatory=$false)] [String] $Server = $SYSLOGSERVER,
        [Parameter(Mandatory=$false)] [String] $Port = $SYSLOGPORT
    )

    # Cleanup Syslog output to remove new lines and carriage returns
    $MessageClean = $Message -replace "`n|`r"
    
    # Outputs the final message, useful for debugging
    $MessageClean | ConvertTo-Json

    # Send Syslog message to SIEM
    $UDPCLient = New-Object System.Net.Sockets.UdpClient
    $UDPCLient.Connect($Server, $Port)
    $Encoding = [System.Text.Encoding]::ASCII
    $ByteSyslogMessage = $Encoding.GetBytes(''+$MessageClean+'')
    $UDPCLient.Send($ByteSyslogMessage, $ByteSyslogMessage.Length)
}

function CheckServiceStatus {
    param (
        [Parameter(Mandatory=$true)] [String] $Service
    )
    $ServiceStatus = Get-Service $Service | Format-Table -HideTableHeaders Status | Out-String
    $ServiceStartTime = (Get-EventLog -LogName "System" -Source "Service Control Manager" -EntryType "Information" -Message "*$Service*running*" -Newest 1).TimeGenerated.ToString("yyyy-MM-ddTHH:mm:ssZ");
    $ServiceStopTime = (Get-EventLog -LogName "System" -Source "Service Control Manager" -EntryType "Information" -Message "*$Service*stopped*" -Newest 1).TimeGenerated.ToString("yyyy-MM-ddTHH:mm:ssZ");
    If ($ServiceStatus -like "*Running*") { $ServiceStatusNumeric = 1 } else { $ServiceStatusNumeric = 0 }

    return @($ServiceStatus,$ServiceStatusNumeric,$ServiceStartTime,$ServiceStopTime)
}

#PrivateArk Server Service Check - Separate to provide version details
$MonitorType = "ApplicationMonitor"
$ServiceName = "PrivateArk Server"
$status = CheckServiceStatus -Service $ServiceName
$SoftwareName = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -like "*CyberArk Digital Vault*" | Select-Object DisplayName | Select-Object -first 1 | Format-Table -HideTableHeaders | Out-String
$SoftwareVersion = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -like "*CyberArk Digital Vault*" | Select-Object DisplayVersion | Select-Object -first 1 | Format-Table -HideTableHeaders | Out-String
SendSyslogMessage -Message "$DateTime CEF:0|CyberArk|$MonitorType|$Version|$HostName|$ServiceName|$($status[0])|$($status[1])|$SoftwareName|$SoftwareVersion|$($status[2])|$($status[3])"

$Services = @("PrivateArk Database","CyberArk Logic Container","PrivateArk Remote Control Agent","Cyber-Ark Event Notification Engine")

$MonitorType = "ApplicationMonitor"
foreach ($Service in $Services) {
    $status = CheckServiceStatus -Service $Service
    SendSyslogMessage -Message "$DateTime CEF:0|CyberArk|$MonitorType|$Version|$HostName|$Service|$($status[0])|$($status[1])|$($status[2])|$($status[3])"
}

$MonitorType = "ApplicationMonitor"
if ($IsHACluster) {
    $Service = "CyberArk Cluster Vault Manager"
    $status = CheckServiceStatus -Service "CyberArk Cluster Vault Manager"
    SendSyslogMessage -Message "$DateTime CEF:0|CyberArk|$MonitorType|$Version|$HostName|$Service|$($status[0])|$($status[1])|$($status[2])|$($status[3])"
}

#OS System Information
$MonitorType = "OSMonitor"
$OSName = (Get-WmiObject Win32_OperatingSystem).Caption | Out-String
$OSVersion = (Get-WmiObject Win32_OperatingSystem).Version | Out-String
$OSServPack = (Get-WmiObject Win32_OperatingSystem).ServicePackMajorVersion | Out-String
$OSArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture | Out-String
SendSyslogMessage -Message "$DateTime CEF:0|CyberArk|$MonitorType|$Version|$HostName|$OSName|$OSVersion|$OSServPack|$OSArchitecture"

#Admin Logon Information - Lists all Vault Local OS user logons
$MonitorType = "LogonMonitor"
$users = (Get-WMIObject -Class Win32_UserAccount -Filter {LocalAccount = "True" and Disabled = "False"} |Select-Object * |Format-Table -HideTableHeaders Name |Out-String).Trim().Split([Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries)
foreach ($user in $users) {
    $user = $user.Trim()
    # Ignore the LogicContainerUser
    if($user.Contains("LogicContainerUser")){break}
    $SID = (Get-WMIObject -Class Win32_UserAccount -Filter "Name = '$user'" | Select-Object * | Format-Table -HideTableHeaders SID | Out-String)
    $LastLogon = (net user $($user) | findstr /B /C:"Last logon")
    $LastLogon = $LastLogon -replace "Last logon"
    SendSyslogMessage -Message "$DateTime CEF:0|CyberArk|$MonitorType|$Version|$HostName|$user|$SID|$LastLogon"
}
