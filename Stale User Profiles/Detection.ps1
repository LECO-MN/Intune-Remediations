$Days = 60
Get-CimInstance -ClassName Win32_UserProfile | Where-Object {$_.LastUseTime -lt (get-date).adddays(-$Days)} | Where-Object {$_.Loaded -eq $false}
If ($Profiles.Count -gt 0) {
    Write-Output "Stale user profiles detected... remediating" -ForegroundColor Red
    Exit 1
} Else {
    Write-Output "No stale profiles detected..." -ForegroundColor Green
    Exit 0
}
