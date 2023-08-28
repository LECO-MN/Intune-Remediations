<#
.SYNOPSIS
  Uses SFC and DISM to detect windows corruption
.DESCRIPTION
  Utilizing SFC and DISM this script can check for system image corruption with DISM, system file corruption with SFC, and it can also do component cleanup
  with DISM. It saves the output to a text file that is then read by the remediation script to determine whether SFC or DISM needs to be run.
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
  PowerShell.exe -ExecutionPolicy Bypass -File Detection.ps1
#>

################################################################################################################################################################
#                                                                            Globals                                                                           #
################################################################################################################################################################
$HDDAware = $True
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

Function Get-CorruptionStatus {
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

    If ($HDDAware) {
    # Correlate the disk to the C: partition to know if the disk the OS parition is installed on is a SSD or HDD
        Try {
            $Disks = Get-WmiObject -Namespace "root\cimv2" -Class "Win32_DiskPartition"
            ForEach ($Disk in $Disks) { 
                $PartitionResult = Get-WmiObject -Namespace "root\cimv2" -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$($Disk.DeviceID)'} WHERE AssocClass = Win32_LogicalDiskToPartition" 
                If ($PartitionResult.Name -eq "C:") {
                    $CPartition = $Disk
                }
            }

            $Regex = $CPartition.Name -match "Disk #(\d)"
            If ($Regex) {
                If ((Get-PhysicalDisk | Where-Object {$_.DeviceId -eq $Matches[1]}).MediaType -ne "SSD") {
                    Write-Output "HDD Detected as OS Disk. Skipping this workstation."
                    Exit 0
                } 
            } Else {
                Write-Output "Physical disk for C: partition could not be determined"
                Exit 2
            }
        } Catch {
            Write-Error "An error occured - Err Line: $($_.InvocationInfo.ScriptLineNumber) Err Name: $($_.Exception.GetType().FullName) Err Msg: $($_.Exception.Message)"
            Exit 2
        }
    }

    # Initialize variables with a zero to track which may need to be remediated
    $RepairHealth = 0
    # Skipping this since it gets triggered a lot by the detection script. Uncomment if you wish to use it.
    # $RepairComponents = 0
    $RepairSFC = 0

    Try {
        $CheckHealth = (C:\Windows\System32\DISM.exe /Online /Cleanup-Image /CheckHealth)

        # Check if system image needs to be repaired
        If ($CheckHealth -like "*The component store is repairable*") {
            # Component store corruption was detected. Exit 1 to initiate remediation script.
            Write-Log -Message_Type "WARNING" -Message "DETECTION: Component store corruption was detected. Remediation script will run to attempt to repair it."
            $RepairHealth = 1
        } 

        # Check if component store cleanup is necessary. Skipping this since it gets triggered a lot by the detection script. Uncomment if you wish to use it.
        <#
        $AnalyzeComponents = DISM /Online /Cleanup-Image /AnalyzeComponentStore

        If ($AnalyzeComponents -like "*Component Store Cleanup Recommended : Yes*") {
            Write-Log -Message_Type "WARNING" -Message "DETECTION: Component store cleanup recommended. Remediation script will run to attempt to clean it."
            $RepairComponents = 1
        }
        #>

        # Run SFC with verifyonly switch so it only checks for corruption without fixing it. Handle the improper character encoding used by SFC utility
        $prev = [console]::OutputEncoding
        [console]::OutputEncoding = [Text.Encoding]::Unicode
        $SFCVerify = (C:\Windows\System32\sfc.exe /VerifyOnly) -join "`r`n" -replace "`r`n`r`n", "`r`n"
        [console]::OutputEncoding = $prev
        
        If ($SFCVerify -like "*Windows Resource Protection found integrity violations*") {
            Write-Log -LogLvl "WARNING" -LogMsg "DETECTION: System file corruption was found. Remediation script will run to attempt to repair it."
            $RepairSFC = 1
        } 
        

        # If any of these equal 1 then remediation is needed
        #If ($RepairHealth -eq 1 -or $RepairComponents -eq 1 -or $RepairSFC -eq 1) {
        If ($RepairHealth -eq 1 -or $RepairSFC -eq 1) {
"RepairHealth=$RepairHealth`nRepairSFC=$RepairSFC" | Out-File -FilePath "$TMP_Folder\SystemCorruptionStatus.txt"

            # Initialize string to generate output string based on results
            $RemedationString = "Corruption was detected: "

            If ($RepairHealth -eq 1) {
                $RemedationString += "System image corruption with DISM; "
            }

            # Skipping this since it gets triggered a lot by the detection script. Uncomment if you wish to use it.
            <#
            If ($RepairComponents -eq 1) {
                $RemedationString += "Component store cleanup with DISM; "
            }
            #>

            If ($RepairSFC -eq 1) {
                $RemedationString += "System file corruption with SFC; "
            }

            $RemedationString += "Remediating..."

            # Issues were found. Write output and exit to start remediation
            Write-Output $RemedationString
            Exit 1
        }

        # No issues were found, exit script gracefully
        Write-Output "No corruption detected."
        Exit 0

    } Catch {
        # Error was caught
        Write-Log -Message_Type "ERROR" -Message $_.Error.Message
        Write-Error "An error occured - Err Line: $($_.InvocationInfo.ScriptLineNumber) Err Name: $($_.Exception.GetType().FullName) Err Msg: $($_.Exception.Message)"
        Exit 2
    }
}

################################################################################################################################################################
#                                                                              Main                                                                            #
################################################################################################################################################################

Get-CorruptionStatus

