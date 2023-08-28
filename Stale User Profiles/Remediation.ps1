# Profiles that havent been logged into after these amounts of days will be deleted
$Days = 60

# Get list of all profiles older than the $Days variable. Profiles should also not be loaded. 
$Profiles = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {$_.LastUseTime -lt (get-date).adddays(-$Days)} | Where-Object {$_.Loaded -eq $false}

If ($Profiles.Count -gt 0) {
    Try {
        # Initialize string variable for outputting to Post-Remediation Output in Intune
        $RemovedUsers = ""

        # Iterate through matching profiles and append to string variable
        ForEach ($Profile in $Profiles) {
            $User = ($Profile.LocalPath -Split "\\")[-1]
            $RemoveUsers += "$User; "
        }
        # Download DelProf2
        Invoke-WebRequest -URI "https://raw.githubusercontent.com/LECO-MN/Intune-Remediations/main/Stale%20User%20Profiles/DelProf2_1.6.0.exe" -OutFile "$env:TEMP\delprof2.exe"

        # Run DelProf2 to remove profiles that havent been used in $Days
        Start-Process -FilePath "$env:TEMP\delprof2.exe" -ArgumentList /q /d:$days -Wait

        # Remove DelProf2 after successfully running
        Remove-Item "$env:TEMP\delprof2.exe"

        # Append end to string
        $RemovedUsers += " user profiles were removed"

        # Output to Intune
        Write-Output $RemovedUsers
        Exit 0
    } Catch {
        Write-Output "An error occured - Err Line: $($_.InvocationInfo.ScriptLineNumber) Err Name: $($_.Exception.GetType().FullName) Err Msg: $($_.Exception.Message)"
        Exit 1
    }
} Else {
    Write-Output "No stale profiles detected..."
    Exit 0
}
