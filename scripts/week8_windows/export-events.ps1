param([datetime]$Since,[string]$OutputDirectory,$Case,[int]$ControlPid)
$ErrorActionPreference = 'Stop'
$rows = [Collections.Generic.List[string]]::new()
# First select the real loader and its native children. Run labels are only used to scope the export.
$until = Get-Date
$all = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688,4663,4698,4699;StartTime=$Since;EndTime=$until} -Oldest)
foreach ($ev in $all) {
    $raw = $ev.ToXml()
    $data = @{}
    foreach ($f in ([xml]$raw).Event.EventData.Data) { $data[$f.Name] = $f.'#text' }
    $keep = $false
    switch ($ev.Id) {
        4688 {
            $newPid=[Convert]::ToInt64($data.NewProcessId,16)
            $parent=[Convert]::ToInt64($data.ProcessId,16)
            $keep = $newPid -in @($Case.pid,$ControlPid) -or $parent -eq $Case.pid -or
                $data.CommandLine -like '*C:\Week8Lab\loader.ps1*' -or $data.CommandLine -like '*C:\Week8Lab\update-marker.cmd*'
        }
        4663 { $keep = $data.ObjectName -like 'C:\Week8Lab\synthetic-profile*' -and [Convert]::ToInt64($data.ProcessId,16) -in @($Case.pid,$ControlPid) }
        4698 { $keep = $data.TaskName -eq "\$($Case.task)" }
        4699 { $keep = $data.TaskName -eq "\$($Case.task)" }
    }
    if ($keep) { $rows.Add($raw) }
}
foreach ($channel in @(@{log='Microsoft-Windows-PowerShell/Operational';id=4104},@{log='Windows PowerShell';id=400})) {
    $events=@(Get-WinEvent -FilterHashtable @{LogName=$channel.log;Id=$channel.id;StartTime=$Since;EndTime=$until} -Oldest -ErrorAction SilentlyContinue)
    foreach ($ev in $events) {
        $raw=$ev.ToXml()
        $xml = [xml]$raw
        if ([int]$xml.Event.System.Execution.ProcessID -ne [int]$Case.pid) { continue }
        if ($ev.Id -eq 4104) {
            $path = ($xml.Event.EventData.Data | Where-Object Name -eq 'Path').'#text'
            $scriptText = ($xml.Event.EventData.Data | Where-Object Name -eq 'ScriptBlockText').'#text'
            if ($path -ne 'C:\Week8Lab\loader.ps1' -and $scriptText.Trim() -cne "Write-Output 'WEEK8-LOADER'") { continue }
        }
        $rows.Add($raw)
    }
}
[IO.File]::WriteAllText("$OutputDirectory\events.xml","<Events>`n"+($rows -join "`n")+"`n</Events>")
