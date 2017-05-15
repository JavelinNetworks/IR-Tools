Function Get-SessionsAnomaly
{
	<#
	.SYNOPSIS
	This script will determine the existence of Pass-The-Ticket and Pass-The-Hash attacks.
	Can be also used to analyze current cached kerberos tickets on remote or local machine.
	
	Function: Get-SessionsAnomaly
	Author: Eyal Neemany (@Zwiitzer). http://www.javelin-networks.com
	License:  https://opensource.org/licenses/BSD-3-Clause
	Required Dependencies: None
	Optional Dependencies: None
	Version: 1.2

	.PARAMETER PTT
	Specify if you want to detect PTT anomaly
	.PARAMETER PTH
	Specify if you want to detect PTH anomaly
	.PARAMETER ComputerName
	Specify the target endpoint to run this script on (Requires WinRM)
	.NOTES
	Run this script on endpoint you suspect to be infected, or involved in attack.
	Not specifying PTT or PTH flag will return both
	.Example
	Get-SessionAnomaly -PTT -PTH | ft -auto
	Get-SessionAnomaly -ComputerName "W10-WannaFry" | ft -auto
	#>
	Param(
	  [switch]$PTT,
	  [switch]$PTH,
	  [string]$ComputerName="localhost"
	)
	
	$asciiart = @"
 _____             _         _____                   _     
|   __|___ ___ ___|_|___ ___|  _  |___ ___ _____ ___| |_ _ 
|__   | -_|_ -|_ -| | . |   |     |   | . |     | .'| | | |
|_____|___|___|___|_|___|_|_|__|__|_|_|___|_|_|_|__,|_|_  | 
                                                      |___|                                                             
Eyal Neemany @Zwiitzer           V 1.2
http://jblog.javelin-networks.com/blog	
		  
"@

		if(!$PTT -and !$PTH)
		{
			$PTT = $true
			$PTH = $true
		}
		write-host $asciiart -ForegroundColor White
		if($ComputerName -ne "localhost")
		{
			Write-Host "Intiating Remote Connection with" $computerName -ForegroundColor White
			return ((Invoke-Command -ComputerName $ComputerName -ScriptBlock ${function:Invoke-Sessions} -ArgumentList $PTT,$PTH) | select SessionAccount,TicketClient,ServiceTicket,LogonIdHex,LogonIdDec,Injected)
		}
		else
		{
			return (Invoke-Sessions -PTT $PTT -PTH $PTH | select SessionAccount,TicketClient,ServiceTicket,LogonIdHex,LogonIdDec,Injected)
		}
}

Function Invoke-Sessions
{
	<#
	.SYNOPSIS
	This script will determine the existence of Pass-The-Ticket and Pass-The-Hash attacks.
	.PARAMETER PTT
	Specify if you want to detect PTT anomaly
	.PARAMETER PTH
	Specify if you want to detect PTH anomaly
	.NOTES
	Run this script on endpoint you suspect to be infected, or involved in attack.
	Not specifying PTT or PTH flag will return both
	.DESCRIPTION 
	Usage :
	Get-SessionAnomaly -PTT $true
	Get-SessionAnomaly -PTH $true -PTT $true
	#>
	Param(
	  [bool]$PTT=$false,
	  [bool]$PTH=$false
	)
	## Data Gathering
	$LOU = Get-WmiObject Win32_LoggedOnUser
	$LOS_B = Get-WmiObject Win32_LogonSession
	$PTH_S = $LOS_B | Where-Object {$_.AuthenticationPackage -eq 'Negotiate' -and $_.LogonType -eq '9'}
	$LOS = $LOS_B | Where-Object {$_.AuthenticationPackage -ne 'NTLM'}
	$LOS_S = $LOS | Select LogonId, AuthenticationPackage, LogonType, StartTime
	$KLIST = $LOS | ForEach-Object {klist.exe -li ([Convert]::ToString($_.LogonId, 16))}
	$klistcurrent = klist 

	## Object Creating
	$ResObj = @()
	$TckObj = @()
	$SusObj = @()
	$PTHObj = @()

	## Parsing
	$rgx1 = "Name=\\`"`([\w-_\d]+`)\\[\w\W]*LogonId=\\`"`(\d+)\\`""
	$rgx2 = "Targeted LogonId is 0:`(0x[\w\d]{1,9}`)"
	$rgx4 = "Current LogonId is 0:`(0x[\w\d]{1,9}`)"
	$rgx3 = "#[\d]{1,3}>\s+Client:\s`([\d\w-_`$]+`)"
	$rgxService = "\s+Server:\s`([.\w\d/-]+`)"
	foreach ($obj in $LOU) 
	{
		$data=$obj.__PATH
		$match1 = $data -match $rgx1
	$Object = New-Object PSObject                                       
				   $Object | add-member Noteproperty idDec         $Matches[2]                      
				   $Object | add-member Noteproperty Account       $Matches[1] 
		$ResObj += $Object
	}
	## Injected Tickets Detection
	for ($i=0; $i -lt $Klist.length;$i++)
	{
		$line=$Klist[$i]
		if ($line -match $rgx2)
		{
			$LogonIdDec = [convert]::toint32($Matches[1],16)
			$LogonIdHex = $Matches[1]
		}
		if ($line -match $rgx3)
		{
			$SessionAccount = ""
			$TicketClient = $Matches[1]
			$SessionAccount = ($ResObj | Where-Object {$_.idDec -like $LogonIdDec}).Account  | Select -First 1 
			$match4 = $klist[$i+1] -match $rgxService
			$ServiceTicket = $Matches[1]
		$ObjectB = New-Object PSObject                                       
				   $ObjectB | add-member Noteproperty SessionAccount     $SessionAccount                  
				   $ObjectB | add-member Noteproperty TicketClient       $TicketClient
				   $ObjectB | add-member Noteproperty ServiceTicket       $ServiceTicket
				   $ObjectB | add-member Noteproperty LogonIdHex      $LogonIdHex
				   $ObjectB | add-member Noteproperty LogonIdDec      $LogonIdDec
				   $ObjectB | add-member Noteproperty Injected      "No"
		$TckObj += $ObjectB
		}
	}

	## Current SessionInjected Tickets Detection
	for ($i=0; $i -lt $klistcurrent.length;$i++)
	{
		$line=$klistcurrent[$i]
		if ($line -match $rgx4)
		{
			$LogonIdDec = [convert]::toint32($Matches[1],16)
			$LogonIdHex = $Matches[1]
		}
		if ($line -match $rgx3)
		{
			$SessionAccount = ""
			$TicketClient = $Matches[1]
			$SessionAccount = ($ResObj | Where-Object {$_.idDec -like $LogonIdDec}).Account  | Select -First 1  
			$match4 = $klistcurrent[$i+1] -match $rgxService
			$ServiceTicket = $Matches[1]
		$ObjectB = New-Object PSObject                                       
				   $ObjectB | add-member Noteproperty SessionAccount     $SessionAccount                  
				   $ObjectB | add-member Noteproperty TicketClient       $TicketClient
				   $ObjectB | add-member Noteproperty ServiceTicket       $ServiceTicket
				   $ObjectB | add-member Noteproperty LogonIdHex      $LogonIdHex
				   $ObjectB | add-member Noteproperty LogonIdDec      $LogonIdDec
				   $ObjectB | add-member Noteproperty Injected      "No"
		$TckObj += $ObjectB
		}
	}

	## Colored Results
	$RedYes = Write-Output "Yes" -ForegroundColor Red
	
	## Suspicous Objects Corrolation Print
	foreach ($obj in $TckObj) 
	{
		if ($obj.SessionAccount -ne $null -and $obj.SessionAccount -ne $obj.TicketClient -and $obj.TicketClient -notlike "*$")
		{
			$obj.Injected = "Yes"
		}
		if ($obj.TicketClient -like "*$" -and $obj.SessionAccount -ne $null -and $obj.SessionAccount -notlike "SYSTEM" -and $obj.SessionAccount -notlike "LOCAL SERVICE" -and $obj.SessionAccount -notlike "NETWORK SERVICE" -and $obj.SessionAccount -notlike "ANONYMOUS LOGON")
		{
			$obj.Injected = "Yes"
		}
	}

	##PTH Object Creation
	if($PTH_S -ne $null)
	{
		foreach ($obj in $PTH_S) 
		{
		$SessionAccount = ($ResObj | Where-Object {$_.idDec -like $obj.LogonId}).Account
			$ObjectC = New-Object PSObject                                       
					   $ObjectC | add-member Noteproperty SessionAccount     $SessionAccount                  
					   $ObjectC | add-member Noteproperty LogonIdDec      $obj.LogonId
					   $ObjectC | add-member Noteproperty Injected      "PTH Attack"
			$PTHObj += $ObjectC
		}
	}
	if($PTT)
	{
		$TckObj
	}
	if($PTH)
	{
		$PTHObj
	}
}
