# This script will make the device sync to Intune every time it is run. You decide when setting the schedule in Intune how often this will occur.
Try {
    # Get last time PushLaunch scheduled task was executed
    $PushInfo = Get-ScheduledTask | Where-Object {$_.TaskName -eq 'PushLaunch'} | Get-ScheduledTaskInfo
    $LastPush = $PushInfo.LastRunTime

    # Get the current datetime
    $CurrentTime=(GET-DATE)

    $NoTimeDiff = 0

    Try {
        # Calculate the time difference between the current datetime and the date stored in the variable.
        $TimeDiff = New-TimeSpan -Start $LastPush -End $CurrentTime
    } Catch [System.Management.Automation.ParameterBindingException] {
        $NoTimeDiff = 1
    }

    # Run the scheduled task!
    Get-ScheduledTask | Where-Object {$_.TaskName -eq 'PushLaunch'} | Start-ScheduledTask

    If ($NoTimeDiff -eq 0) {
        Write-Output "Sync Started! Last sync was $($TimeDiff.Hours) hours and $($TimeDiff.Minutes) minutes ago"
    } Else {
        Write-Output "Sync Started! The last runtime of the PushLaunch task could not be calculated!"
    }
    Exit 0
} Catch {
    Write-Error "Err Line: $($_.InvocationInfo.ScriptLineNumber) Err Name: $($_.Exception.GetType().FullName) Err Msg: $($_.Exception.Message)"
    Exit 1
}
