Try {
    $SystemPartition = ($Env:SystemRoot).Substring(0,2)

    # Get Bitlocker status for system drive
    $BLInfo = Get-Bitlockervolume -MountPoint $SystemPartition
    If ($BLInfo.ProtectionStatus -eq "On") {
        # Bitlocker is turned on
        If ($BLInfo.VolumeStatus -eq "FullyEncrypted") {
            # System drive is fully encrypted
            $RecoveryKey = ((Get-BitLockerVolume -MountPoint $SystemPartition).KeyProtector).RecoveryPassword
            If ($Null -ne $RecoveryKey) {
                Write-Output $RecoveryKey
                Exit 0
            } Else {
                Write-Output "Recovery key not found!"
                Exit 1
            }
        } ElseIf ($BLInfo.VolumeStatus -eq "Progress") {
                Write-Output "Bitlocker encryption at $($BLInfo.EncryptionPercentage)%. Key will be uploaded once complete."
                Exit 0
        } Else {
            Write-Output "Bitlocker On; Unknown Volume Status: $($BLInfo.VolumeStatus)"
            Exit 2
        }
    } Else {
        $TPM = Get-Tpm
        If ($TPM.TpmPresent) {
            If ($TPM.TpmActivated) {
                Write-Output "Bitlocker Off or TPM incompatible"
                Exit 1
            } Else {
                Write-Output "TPM module not activated!"
                Exit 2
            }
        } Else {
            Write-Output "No TPM module found!"
            Exit 2
        }
    }
} Catch {
    Write-Error "An error occured - Err Line: $($_.InvocationInfo.ScriptLineNumber) Err Name: $($_.Exception.GetType().FullName) Err Msg: $($_.Exception.Message)"
    Exit 2
}
