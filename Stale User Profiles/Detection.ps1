# Profiles that havent been logged into after these amounts of days will be deleted
$Days = 60

# Get list of all profiles older than the $Days variable. Profiles should also not be loaded. 
$Profiles = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {$_.LastUseTime -lt (get-date).adddays(-$Days)} | Where-Object {$_.Loaded -eq $false}

If ($Profiles.Count -gt 0) {
    Write-Output "Stale user profiles detected... remediating"
    Exit 1
} Else {
    Write-Output "No stale profiles detected..."
    Exit 0
}
