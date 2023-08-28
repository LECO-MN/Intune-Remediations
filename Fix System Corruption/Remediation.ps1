<#
.SYNOPSIS
  Uses SFC and DISM to repair windows corruption
.DESCRIPTION
  Utilizing SFC and DISM this script will attempt to repair corruption that was found with the detection script. It reads $TMP_Folder\SystemCorruptionStatus.txt
  which is written to by the detection script and tells the script what commands to run for corruption found previously during detection.
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Version:        1.0
  Author:         Mark Newton
  Creation Date:  06/10/2023
  Purpose/Change: Initial script development

  Version:        1.1
  Author:         Mark Newton
  Creation Date:  07/17/2023
  Purpose/Change: Disable analyze component store with DISM and fixed issues with SFC not outputting text correctly due to the utility's character encoding.
.EXAMPLE
  PowerShell.exe -ExecutionPolicy Bypass -File Remediation.ps1
#>

################################################################################################################################################################
#                                                                            Globals                                                                           #
################################################################################################################################################################
$Log = $True
$Log_Folder = [System.Environment]::GetEnvironmentVariable('TEMP','Machine')
$TMP_Folder = [System.Environment]::GetEnvironmentVariable('TEMP','Machine')

################################################################################################################################################################
#                                                                           Functions                                                                          #
################################################################################################################################################################
Function Write-Log {
    <#
    .DESCRIPTION
    Validates the path to the log file, creates one if it doesnt exist, and writes to the specified log file with a specified log level

    .EXAMPLE
    Write-Log "This writes an INFO level log"
    OR
    Write-Log -LogLvl "WARNING" -LogMsg "This writes a WARNING level log"
    OR
    Write-Log -LogFile "Error.log" -LogLvl "ERROR" -LogMsg "This writes a ERROR level log to a log file called Error.log"
    
    .PARAMETERS
    [String]$LogMsg - Message to write to the log
    [String]$LogLvl - Level to write into the log. Defaults to INFO if not specified.
    [String]$LogName - Name of the log file to write to. Defaults to Debug.log if not specified.

    .RETURNS
    None
    #>

	param(

        [Parameter(Mandatory = $True)][string]$LogMsg,
		[string]$LogLvl = "INFO",
		[string]$LogName = "Corruption_Remediation.log"
	)

    $LogSize = ((Get-Item -Path "$Log_Folder\$LogName").Length)/1MB
    If ($LogSize -gt 1) { Remove-Item "$Log_Folder\$LogName" -Force }

	$TimeStamp = Get-Date -Format "MM/dd/yy HH:mm:ss"

	if (!(Test-Path -Path "$Log_Folder")) {
		New-Item -ItemType "Directory" -Path "$Log_Folder" > Out-Null
	}

    If ($Log -eq $True) {
        If (!(Test-Path -Path "$Log_Folder\$LogName")) {
            Write-Output "[$TimeStamp][INFO] Logging started" | Out-File -FilePath "$Log_Folder\$LogName" -Append
        }

        Write-Output "[$TimeStamp][$LogLvl] $LogMsg" | Out-File -FilePath "$Log_Folder\$LogName" -Append
        If ($Debug) {
            Write-Host "[$TimeStamp][$LogLvl] $LogMsg"
        }
    }
}

Function Test-Registry {
    <#
    .DESCRIPTION
    Tests if a registry key or value exists. If the PassThry paramter is provided it will return the registry value.

    .EXAMPLE
    Test-Registry "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    OR
    Test-Registry -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    OR
    Test-Registry -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoLogonSID"
    OR
    $AutoLogonSID = (Test-Registry -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoLogonSID" -PassThru).AutoLogonSID
    
    .PARAMETERS
    [String]$Path - Path to the registry key
    [String]$Name - Name of the registry value under the $Path
    [Switch]$PassThru - Returns the registry value in the property with the same name as the registry value

    .RETURNS
    None
    #>
    param(
        [Alias("PSPath")]
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [String]$Path
        ,
        [Parameter(Position = 1, Mandatory = $false)]
        [String]$Name
        ,
        [Parameter(Position = 2, Mandatory = $false)]
        [Switch]$PassThru
    ) 

    process {
        if (Test-Path $Path) {
            $Key = Get-Item -LiteralPath $Path
			If ($Name) {
				if ($Key.GetValue($Name, $null) -ne $null) {
					if ($PassThru) {
						Get-ItemProperty $Path $Name
					} else {
						$true
					}
				} else {
					$false
				}
            } else {
				$true
			}
        } else {
            $false
        }
    }
}

Function Fix-Corruption {
    <#
    .DESCRIPTION
    Runs SFC and DISM utilities to detect any corruption of Windows file and writes the output to a text file for remediation if any corruption is found

    .EXAMPLE
    Get-CorruptionStatus
    
    .PARAMETERS
    None

    .RETURNS
    None

    .OUTPUTS
    $TMP_Folder\SystemCorruptionStatus.txt
    #>

    Try {
        # Check and if needed modify registry to set "Specify settings for optional component installation and component repair" to download from Microsoft directly
        If (!(Test-Registry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing\" -Name "RepairContentServerSource")) {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing\" -Name "RepairContentServerSource" -Value 2 -PropertyType DWord
        } ElseIf ((Test-Registry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing\" -Name "RepairContentServerSource" -PassThru).RepairContentServerSource -ne 2) {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing\" -Name "RepairContentServerSource" -Value 2
        } 
        

        # Status codes for remediation: 0 - Default State, 1 - Remediated Successfully, 2 - Remedation Failed
        $CheckHealthRemedation = 0
        # Skipping this since it gets triggered a lot by the detection script. Uncomment if you wish to use it.
        # $AnalyzeComponentsRemedation = 0
        $SFCRemedation = 0

        # Create dictionary to store properties read from SystemCorruptionStatus.txt that was written to by Detection script
        $RepairStatus = [hashtable]::new();

        # Fetch the data from the specified file and transform it to a Dictionary.
        Get-Content -Path "$TMP_Folder\SystemCorruptionStatus.txt" | Where-Object { $_ -and $_ -notmatch "null" } | ForEach-Object { $kvp = $_.Replace(" ", "").Split('=', 2); $RepairStatus.Add($kvp[0], $kvp[1]); };

        If ($RepairStatus.RepairHealth -eq 1) {

            # Component store corruption was detected. Exit 1 to initiate remediation script.
            Write-Log -LogLvl "WARNING" -LogMsg "REMEDIATION: Component store corruption was detected. Attempting to restore health with DISM."

            $RestoreHealth = (C:\Windows\System32\Dism.exe /Online /Cleanup-Image /RestoreHealth)

            If ($RestoreHealth -like "*The restore operation completed successfully*") {
                # Component store corruption is repaired. Script continues to run.
                Write-Log -LogLvl "INFO" -LogMsg "REMEDIATION: Component store corruption was repaired."
                $CheckHealthRemedation = 1
            } Else {
                # Component store corruption was not able to be repaired
                Write-Log -LogLvl "ERROR" -LogMsg "REMEDIATION: Component store was not able to be repaired"
                Write-Log -LogLvl "ERROR" -LogMsg "REMEDIATION: $RestoreHealth"
                $CheckHealthRemedation = 2
            }
        }

        # Skipping this since it gets triggered a lot by the detection script. Uncomment if you wish to use it.
        <#
        If ($RepairStatus.RepairComponents -eq 1) {

            $Regex = $AnalyzeComponents -Match ".*:.*"
            If ($Regex) {
                Write-Log -LogLvl "INFO" -LogMsg "REMEDIATION: Component store information:"
                ForEach ($Match in $Matches) {
                    Write-Log -LogLvl "INFO" -LogMsg "REMEDIATION: $Match"
                }
            }

            Write-Log -LogLvl "WARNING" -LogMsg "REMEDIATION: Component store cleanup recommended. Attemping to clean up the component store"

            $ComponentCleanup = DISM /Online /Cleanup-Image /StartComponentCleanup

            If ($ComponentCleanup -like "*The operation completed successfully*") {
                # Component store is cleaned up. Script continues to run.
                Write-Log -LogLvl "INFO" -LogMsg "REMEDIATION: Component store was cleaned up."
                $AnalyzeComponentsRemedation = 1
            } Else {
                Write-Log -LogLvl "ERROR" -LogMsg "REMEDIATION: Component store was unable to be cleaned up."
                Write-Log -LogLvl "ERROR" -LogMsg "REMEDIATION: $ComponentCleanup"
                $AnalyzeComponentsRemedation = 2
            }
        }
        #>

        If ($RepairStatus.RepairSFC -eq 1) {

            Write-Log -LogLvl "WARNING" -LogMsg "REMEDIATION: System file corruption was found. Running SFC /ScanNow to attempt to repair it."

            # Handle the improper character encoding used by SFC utility
            $prev = [console]::OutputEncoding
            [console]::OutputEncoding = [Text.Encoding]::Unicode
            $SFCScan = (C:\Windows\System32\SFC.exe /ScanNow) -join "`r`n" -replace "`r`n`r`n", "`r`n"
            [console]::OutputEncoding = $prev

            If ($SFCScan -like "*Windows Resource Protection found corrupt files and successfully repaired them*") {
                # System file corruption is repaired. Script continues to run.
                Write-Log -LogLvl "INFO" -LogMsg "REMEDIATION: SFC successfully repaired the corrupt system files."
                $SFCRemedation = 1
            } Else {
                # System file corruption was not able to be repaired
                Write-Log -LogLvl "ERROR" -LogMsg "REMEDIATION: SFC was not able to repair the corrupt system files."
                Write-Log -LogLvl "ERROR" -LogMsg "REMEDIATION: $SFCScan"
                $SFCRemedation = 2
            }
        } 

        #If ($CheckHealthRemedation -eq 2 -or $AnalyzeComponentsRemedation -eq 2 -or $SFCRemedation -eq 2) {
        If ($CheckHealthRemedation -eq 2 -or $SFCRemedation -eq 2) {
            # Something went wrong...
            Write-Output "Remediation failed. Check C:\ProgramData\LECO Intune\Corruption_Remediation.log on the workstation."
            Remove-Item "$TMP_Folder\SystemCorruptionStatus.txt" -Force
            Exit 1
        }

        # No issues were found, exit script gracefully
        Write-Output "Remediation successful"
        Remove-Item "$TMP_Folder\SystemCorruptionStatus.txt" -Force
        Exit 0

    } Catch {
        # Error was caught
        Write-Log -LogLvl "WARNING" -LogMsg $_.Error.Message
        Remove-Item "$TMP_Folder\SystemCorruptionStatus.txt" -Force
        Write-Output "An error occured - Err Line: $($_.InvocationInfo.ScriptLineNumber) Err Name: $($_.Exception.GetType().FullName) Err Msg: $($_.Exception.Message)"
        Exit 1
    }
}

################################################################################################################################################################
#                                                                              Main                                                                            #
################################################################################################################################################################

Fix-Corruption
