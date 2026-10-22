param([string]$OutputRoot=(Join-Path $PSScriptRoot '../evidence/assignment4'))
$ErrorActionPreference='Stop'
$runId=(Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')
$run=Join-Path $OutputRoot $runId
New-Item -ItemType Directory -Path $run -Force | Out-Null
$run=(Resolve-Path -LiteralPath $run).Path
$mock=Join-Path $run 'mock-browser.json'
@{origin='https://training.invalid';username='FAKE-STUDENT';password='NOT-A-REAL-PASSWORD';synthetic=$true} | ConvertTo-Json | Set-Content -LiteralPath $mock -Encoding utf8
$psExe=Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe'
$docs=@(); $labels=@(); $cases=@()
$start=Get-Date
function Quote-PS([string]$value) { return "'"+$value.Replace("'","''")+"'" }

foreach($case in @('automation_plain','simulation_encoded','control_cmd')) {
    $marker="TH_A4_${runId}_${case}"
    $outFile=Join-Path $run "$case.stdout.txt"
    $stderrFile=Join-Path $run "$case.stderr.txt"
    $command="Write-Output '$marker'; Start-Sleep -Seconds 8"
    if($case -eq 'simulation_encoded') {
        $staged=Join-Path $run 'staged-mock-browser.json'
        $command="Get-Content -LiteralPath $(Quote-PS $mock) | Out-Null; Copy-Item -LiteralPath $(Quote-PS $mock) -Destination $(Quote-PS $staged); $command"
    }
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $argsLine=if($case -eq 'simulation_encoded') { "-NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded" } else { "-NoLogo -NoProfile -NonInteractive -Command `"$command`"" }
    $begin=Get-Date
    $process=$null
        $info=[Diagnostics.ProcessStartInfo]::new()
        $info.FileName=if($case -eq 'control_cmd') { Join-Path $env:WINDIR 'System32/cmd.exe' } else { $psExe }
        $info.Arguments=if($case -eq 'control_cmd') { "/d /c `"echo $marker & ping -n 7 127.0.0.1 >nul`"" } else { $argsLine }
        $info.UseShellExecute=$false; $info.CreateNoWindow=$true
        $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
        $process=[Diagnostics.Process]::new(); $process.StartInfo=$info
        if(-not $process.Start()) { throw "Cannot start $case" }
        $snapshot=Get-CimInstance Win32_Process -Filter "ProcessId=$($process.Id)"
    if(-not $snapshot) { throw "No live process observation for $case" }
    $parent=Get-CimInstance Win32_Process -Filter "ProcessId=$($snapshot.ParentProcessId)"
    if(-not $parent.Name) { throw "Missing parent for $case" }
    $created=([datetime]$snapshot.CreationDate).ToUniversalTime().ToString('o')
    $observed=(Get-Date).ToUniversalTime().ToString('o')
    $raw=[ordered]@{ProcessId=$snapshot.ProcessId;ParentProcessId=$snapshot.ParentProcessId;Name=$snapshot.Name;ExecutablePath=$snapshot.ExecutablePath;CommandLine=$snapshot.CommandLine;CreationDate=$created;ObservedAt=$observed;ParentName=$parent.Name;ParentExecutablePath=$parent.ExecutablePath;ParentCreationDate=([datetime]$parent.CreationDate).ToUniversalTime().ToString('o')}
    $raw | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $run "$case.cim.json") -Encoding utf8
    if($process) {
        $stdout=$process.StandardOutput.ReadToEnd(); $stderr=$process.StandardError.ReadToEnd(); $process.WaitForExit()
        $exitCode=$process.ExitCode; $process.Dispose()
        $stdout | Set-Content -LiteralPath $outFile -Encoding utf8
        $stderr | Set-Content -LiteralPath $stderrFile -Encoding utf8
        if($exitCode -ne 0 -or $stdout.Trim() -ne $marker) { throw "Unexpected output/exit for $case" }
    }
    $eventIds=@()
    if($case -ne 'control_cmd') {
        $needle=if($case -eq 'simulation_encoded') { $encoded } else { $marker }
        $events=@(Get-WinEvent -FilterHashtable @{LogName='Windows PowerShell';Id=400;StartTime=$begin.AddSeconds(-1)} | Where-Object { $_.ToXml().Contains($needle) })
        if($events.Count -ne 1) { throw "Expected one native Event 400 for $case, got $($events.Count)" }
        $events[0].ToXml() | Set-Content -LiteralPath (Join-Path $run "$case.event400.xml") -Encoding utf8
        $eventIds=@($events | ForEach-Object {$_.RecordId})
    }
    $docs += [ordered]@{
        '@timestamp'=$observed
        event=@{kind='event';category=@('process');type=@('info');action='process_observed';dataset='lab.process_inventory';id="${runId}_${case}"}
        process=@{pid=[int]$snapshot.ProcessId;name=$snapshot.Name.ToLowerInvariant();executable=$snapshot.ExecutablePath;command_line=$snapshot.CommandLine;start=$created;parent=@{pid=[int]$parent.ProcessId;name=$parent.Name.ToLowerInvariant();executable=$parent.ExecutablePath}}
        lab=@{run_id=$runId;case=$case;marker=$marker;synthetic_payload=$true;source='Win32_Process live inventory; native Event 400 retained separately';event400_record_ids=$eventIds}
    }
    $labels += @{case=$case;expected_car_match=($case -in @('automation_plain','simulation_encoded'));reason=switch($case){automation_plain {'Legitimate automation also matches the broad CAR condition'} simulation_encoded {'Benign simulation: PowerShell reading and staging only the lab-created mock file'} control_cmd {'Process name is cmd.exe'}}}
    $cases += @{case=$case;process_id=$snapshot.ProcessId;parent_name=$parent.Name;exit_code=$exitCode;event400_record_ids=$eventIds}
}
if((Get-FileHash -LiteralPath $mock).Hash -ne (Get-FileHash -LiteralPath (Join-Path $run 'staged-mock-browser.json')).Hash) { throw 'Staging content mismatch' }
$docs | ForEach-Object { $_ | ConvertTo-Json -Depth 10 -Compress } | Set-Content -LiteralPath (Join-Path $run 'process-observations.jsonl') -Encoding utf8
$labels | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $run 'case-labels.json') -Encoding utf8
@{run_id=$runId;started_utc=$start.ToUniversalTime().ToString('o');completed_utc=(Get-Date).ToUniversalTime().ToString('o');cases=$cases;collector_sha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash;telemetry='Instrumented launches and live CIM inventory, not a native process-create stream';network='Only cmd control pinged 127.0.0.1; no external traffic or exfiltration';status='Collection complete; SIEM validation pending'} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $run 'collection-manifest.json') -Encoding utf8
Get-ChildItem -LiteralPath $run -File | ForEach-Object { @{file=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash} } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $run 'collection-sha256.json') -Encoding utf8
Write-Output "Collected: $run"
$cases | Format-Table -AutoSize
