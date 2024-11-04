function Enable-SWGMaxDebug {
	<#
        .SYNOPSIS
        Enables max debug logging for Cisco AnyConnect/Secure Client Umbrella SWG module .
        .DESCRIPTION
		Copies the contents of the "orgConfig" object from the SWGConfig.json file to the "swg_org_config.flag" file.
        Adds "logLevel": "1" value to the "orgConfig" object.
		Saves file swg_org_config.flag in C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Umbrella\data or 
		C:\ProgramData\Cisco\Cisco Secure Client\Umbrella\data
        .EXAMPLE
        PS> Enable-SWGMaxDebug
		
		.LINK
		https://support.umbrella.com/hc/en-us/articles/360043386131-Cisco-AnyConnect-SWG-How-to-enable-the-max-debug-logging
		#>
	$clienttype = Detect-Client
	If ($clienttype -eq "NoClient"){
		return "No client detected"
	}
	Write-Output "+ Installed client is $clienttype" 
	$swgconfig = Get-Content "C:\ProgramData\Cisco\$clienttype\Umbrella\SWG\SWGConfig.json" -Raw | ConvertFrom-Json
	$swgconfig.orgConfig | Add-Member -Name 'logLevel' -MemberType NoteProperty -Value '1' -Force
	$swgconfig.orgConfig | ConvertTo-Json -depth 100 | Out-File "C:\ProgramData\Cisco\$clienttype\Umbrella\data\swg_org_config.flag" -Force
	Write-Output "+ SWG maximum debug logging enabled"
	Write-Output $swgconfig.orgConfig
	return 0
}

function Disable-SWGMaxDebug {
	<#
        .SYNOPSIS
        Disables max debug logging for Cisco AnyConnect/Secure Umbrella Client SWG module .
        .DESCRIPTION
		Removes file swg_org_config.flag in C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Umbrella\data or
		C:\ProgramData\Cisco\Cisco Secure Client\Umbrella\data
        .EXAMPLE
        PS> Disable-SWGMaxDebug
		
		.LINK
		https://support.umbrella.com/hc/en-us/articles/360043386131-Cisco-AnyConnect-SWG-How-to-enable-the-max-debug-logging
		#>
	$clienttype = Detect-Client
	If ($clienttype -eq "NoClient"){
		return "No client detected"
	}
	Write-Output "+ Installed client is $clienttype" 
	Try {
    Remove-Item -Path "C:\ProgramData\Cisco\$clienttype\Umbrella\data\swg_org_config.flag" -ErrorAction Stop
	Write-Output "- SWG maximum debug logging disabled"
}
	Catch {
    Write-Warning "Most probably SWG Max debug logging is not enabled: $($_.Exception.Message)"
}
	
}

function Enable-KDFDebug ($DebugFlags){
	<#
        .SYNOPSIS
        Enables KDF(Kernel Driver Framework) logs for Cisco AnyConnect.
        .DESCRIPTION
		Creates DebugFlags parameter in registry HKLM:\SYSTEM\CurrentControlSet\Services\acsock
		Restart of vpnagent and acsock services is required for changes to be applied by Cisco AnyConnect
        .EXAMPLE
        PS> Enable-KDFDebug 0xFFFFFFFF
		
		#>
	$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\acsock'
	$Name         = 'DebugFlags'
	If ($DebugFlags -eq $null) {$Value = '0xFFFFFFFF'} else {$Value = $DebugFlags}
	If (-NOT (Test-Path $RegistryPath)) {
		New-Item -Path $RegistryPath -Force | Out-Null
	}  
	New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force
	Write-Output "- KDF logging enabled"
}

function Disable-KDFDebug {
	<#
        .SYNOPSIS
        Disables KDF(Kernel Driver Framework) logs for Cisco AnyConnect.
        .DESCRIPTION
		Removes DebugFlags parameter in registry HKLM:\SYSTEM\CurrentControlSet\Services\acsock
		Restart of vpnagent and acsock services is required for changes to be applied by Cisco AnyConnect
        .EXAMPLE
        PS> Disable-KDFDebug
		
		#>
	Try {
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\acsock" -Name "DebugFlags" -ErrorAction Stop
	Write-Output "- KDF logging disabled"
}
	Catch {
    Write-Warning "Most probably KDF debug logging is not enabled: $($_.Exception.Message)"
}
	
}

function Restart-AC {
	<#
        .SYNOPSIS
        Restarts Anyconnect services
        .DESCRIPTION
		Restarts vpnagent and acsock services to apply changes after enabling/disabling logging
        .EXAMPLE
        PS> Restart-AC
		
		#>
	$clienttype = Detect-Client
	Write-Output "+ Installed client is $clienttype"
	If ($clienttype -eq "NoClient"){
		return "No client detected"
	}
	elseif ($clienttype -eq "Cisco Secure Client") {
		Stop-Service csc_vpnagent
		Stop-Service acsock
		Start-Service csc_vpnagent
		Write-Output "+ Secure Client csc_vpnagent service restarted"
		Start-Service acsock
		Write-Output "+ Secure Client acsock service restarted"
	}
	elseif ($clienttype -eq "Cisco AnyConnect Secure Mobility Client") {		
		Stop-Service vpnagent
		Stop-Service acsock
		Start-Service vpnagent
		Write-Output "+ Anyconnect vpnagent service restarted"
		Start-Service acsock
		Write-Output "+ Anyconnect acsock service restarted"
	}
}

function Verify-SWGMaxDebug {
	<#
        .SYNOPSIS
        Verifies if SWG maximum debug logging is enabled succesfully
        .DESCRIPTION
		Gets last 50 events from Cisco AnyConnect Umbrella Roaming Security Module events log
		Checks for certain patterns in events to confirm that logging is working
		Prints last 50 events
        .EXAMPLE
        PS> Verify-SWGMaxDebug
		
		#>
	
	$clienttype = Detect-Client
	Write-Output "+ Installed client is $clienttype"
	If ($clienttype -eq "NoClient"){
		return "No client detected"
	}
	elseif ($clienttype -eq "Cisco Secure Client") {
		$events = Get-EventLog -LogName "Cisco Secure Client - Umbrella" -Source csc_swgagent -Newest 50
	}
	elseif ($clienttype -eq "Cisco AnyConnect Secure Mobility Client") {		
		$events = Get-EventLog -LogName "Cisco AnyConnect Umbrella Roaming Security Module" -Source acswgagent -Newest 50
	}
	If ($events | Select-String -InputObject {$_.message} -Pattern 'Resolved IP from', 'Hostnames from KDF are', 'Connecting to 146.112') { 
		Write-Output "Looks like SWG Max debug logging enabled and we see web traffic redirection events"
		Write-Output "Here is last 50 events from event log"
		$events
	}
	else
	{
		Write-Output "There is still no debug events."
		Write-Output "Please give more time to service to start or try to open some websites in browser to generate events"
	
	}
}

function Enable-WPFLogging {
	<#
        .SYNOPSIS
        Enables Windows Filtering Platform Auditing for Success and Failure events
        .DESCRIPTION
		Enables Windows Filtering Platform Auditing for Success and Failure events
        .EXAMPLE
        PS> Enable-WPFLogging
		
		#>
	auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
	auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
	$ifWPFEnabled = auditpol /get /subcategory:"Filtering Platform Packet Drop"
	$ifWPFEnabled
	If ($ifWPFEnabled | Select-String -InputObject {$_} -Pattern 'Success and Failure') {
		Write-Output "WPF Logging enabled succesfully"
	}
	
}

function Disable-WPFLogging {
	<#
        .SYNOPSIS
        Disables Windows Filtering Platform Auditing for Success and Failure events
        .DESCRIPTION
		Disables Windows Filtering Platform Auditing for Success and Failure events
        .EXAMPLE
        PS> Disable-WPFLogging
		
		#>
	auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:disable /failure:disable
	auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:disable
	$ifWPFEnabled = auditpol /get /subcategory:"Filtering Platform Packet Drop"
	$ifWPFEnabled
	If ($ifWPFEnabled | Select-String -InputObject {$_} -Pattern 'No Auditing') {
		Write-Output "WPF Logging disabled"
	}
}

function Verify-WPFLogging {
	<#
        .SYNOPSIS
        Prints last 50 events from Security log with EventID 5157 and 5152 to verify if WPF Auditing enabled succesfully
        .DESCRIPTION
		Prints last 50 events from Security log with EventID 5157 and 5152
        .EXAMPLE
        PS> Verify-WPFLogging
		
		#>
$wpfevents = Get-EventLog -LogName "Security" -InstanceId 5157,5152 -Newest 50
$wpfevents | Select-Object -Property TimeGenerated,Message | Format-List
}

function Detect-Client {

	If (Test-Path -Path "C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Umbrella\SWG\SWGConfig.json") {
		return "Cisco AnyConnect Secure Mobility Client"
		}
	elseif (Test-Path -Path "C:\ProgramData\Cisco\Cisco Secure Client\Umbrella\SWG\SWGConfig.json") {
		return "Cisco Secure Client"
		}
	else {Write-Output "No SWG Config found"
	      return "NoClient"
	}
}

function Add-ExternalDomain ($domain) {
	<#
        .SYNOPSIS
        Add domain or ip address to exception list
        .DESCRIPTION
		Copies the contents of the "orgConfig" object from the SWGConfig.json file to the "swg_org_config.flag" file.
        Adds domain value to the "exceptionList" object.
		Saves file swg_org_config.flag in C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Umbrella\data or 
		C:\ProgramData\Cisco\Cisco Secure Client\Umbrella\data
        .EXAMPLE
        PS> Add-ExternalDomain test.com
		
		.LINK
		https://support.umbrella.com/hc/en-us/articles/360043386131-Cisco-AnyConnect-SWG-How-to-enable-the-max-debug-logging
		#>
	$clienttype = Detect-Client
	If ($clienttype -eq "NoClient"){
		return "No client detected"
	}
	Write-Output "+ Installed client is $clienttype" 
	$swgconfig = Get-Content "C:\ProgramData\Cisco\$clienttype\Umbrella\SWG\SWGConfig.json" -Raw | ConvertFrom-Json
	If ($domain -eq $null) { 
		return "No domain specified"
		} 
	else {	
		$exceptionList = $swgconfig.orgConfig.exceptionList += $domain
		$swgconfig.orgConfig.exceptionList = $exceptionlist
		#$swgconfig.orgConfig.exceptionList.Add("120.130.120.130")
		$swgconfig.orgConfig | ConvertTo-Json -depth 100 | Out-File "C:\ProgramData\Cisco\$clienttype\Umbrella\data\swg_org_config.flag" -Force
		Write-Output $swgconfig.orgConfig.exceptionList
		return $domain + " was added succesfully"
	}
}