Function Get-SessionsAnomaly
{
<#
.SYNOPSIS
This script will determine the existence of Pass-The-Ticket and Pass-The-Hash attacks.
.PARAMETER PTT
Specify if you want to detect PTT anomaly by enetering $true value
.PARAMETER PTH
Specify if you want to detect PTH anomaly by enetering $true value
.NOTES
Run this script on endpoint you suspect to be infected, or involved in attack.
.DESCRIPTION 
Usage :
Get-SessionAnomaly.ps1 -PTT $true | ft -auto
Get-SessionAnomaly.ps1 -PTH $true | ft -auto
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
	foreach ($obj in $PTH_S) 
	{
	$SessionAccount = ($ResObj | Where-Object {$_.idDec -like $obj.LogonId}).Account
		$ObjectC = New-Object PSObject                                       
				   $ObjectC | add-member Noteproperty SessionAccount     $SessionAccount                  
				   $ObjectC | add-member Noteproperty LogonIdDec      $obj.LogonId
				   $ObjectC | add-member Noteproperty Injected      "PTH Attack"
		$PTHObj += $ObjectC
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