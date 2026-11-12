#Requires -RunAsAdministrator
# Run with Windows PowerShell -STA in an interactive session on a disposable Windows VM.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = 'C:\Week8Lab'
$export = 'C:\Week8Evidence'
if ((Test-Path $root) -or (Test-Path $export)) { throw 'Revert the disposable VM to its clean snapshot first.' }
New-Item $root,$export -ItemType Directory | Out-Null
$run = [guid]::NewGuid().ToString('N').Substring(0,12)
$source = "$root\synthetic-profile"
$command = 'cmd.exe /d /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Week8Lab\loader.ps1'
$settings = @(
    @{key='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit';name='ProcessCreationIncludeCmdLine_Enabled'},
    @{key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging';name='EnableScriptBlockLogging'}
)
function Write-JsonFile($path,$value) { [IO.File]::WriteAllText($path,($value | ConvertTo-Json -Depth 8)) }
function Audit-Command([string[]]$Arguments) { & auditpol.exe @Arguments | Out-Null; if ($LASTEXITCODE) { throw "auditpol $Arguments failed" } }
function Test-LabTask([string]$name) {
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    try { $null = $service.GetFolder('\').GetTask($name); return $true }
    catch {
        if ($_.Exception.GetBaseException().HResult -eq -2147024894) { return $false }
        throw
    }
}
$receiver = $null
$auditSaved = $false
$oldSettings = @()
try {
    Audit-Command @('/backup',"/file:$root\audit-before.csv")
    $auditSaved = $true
    foreach ($id in @('922B','921D','9227')) {
        Audit-Command @('/set',"/subcategory:{0CCE$id-69AE-11D9-BED3-505054503030}",'/success:enable')
    }
    foreach ($s in $settings) {
        $keyExisted = Test-Path $s.key
        if (!$keyExisted) { New-Item -Path $s.key -Force | Out-Null }
        $key = Get-Item $s.key
        # Open an existing key without replacing its other values.
        $previous = $key.GetValue($s.name)
        $oldSettings += @{key=$s.key;name=$s.name;value=$previous;existed=$keyExisted}
        New-ItemProperty -Path $s.key -Name $s.name -Value 1 -PropertyType DWord -Force | Out-Null
    }
    New-Item $source,"$root\stage" -ItemType Directory | Out-Null
    $acl = Get-Acl -LiteralPath $source -Audit
    $rule = [Security.AccessControl.FileSystemAuditRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),'ReadData','ContainerInherit,ObjectInherit','None','Success')
    $acl.AddAuditRule($rule)
    Set-Acl -LiteralPath $source -AclObject $acl
    $fixtures = [ordered]@{'config.ini'='endpoint=https://training.invalid';'cookies.json'='{"token":"FAKE-SESSION-TRAINING"}';'mock-browser.json'='{"user":"FAKE-STUDENT","password":"NOT-A-REAL-PASSWORD"}';'wallet.txt'='SYNTHETIC-WALLET-NO-VALUE'}
    foreach ($name in $fixtures.Keys) { [IO.File]::WriteAllText("$source\$name",$fixtures[$name]) }
    [IO.File]::WriteAllText("$root\run.txt",$run)
    [IO.File]::WriteAllText("$root\update-marker.cmd","@echo off`r`n>$root\task.marker echo $run`r`n")
    Copy-Item "$PSScriptRoot\loader.ps1","$PSScriptRoot\receiver.ps1" -Destination $root
    $html = "<html><head><title>Training update</title></head><body><h1>Week 8 training update</h1><p>Synthetic lab only. Copy the command, open Run and paste it.</p><pre id='launch'>$command</pre><p>Run $run</p></body></html>"
    [IO.File]::WriteAllText("$root\update.html",$html)
    $since = Get-Date
    $receiver = Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File $root\receiver.ps1" -PassThru -WindowStyle Hidden
    for ($i=0;$i -lt 100 -and !(Test-Path "$root\ready.txt");$i++) { Start-Sleep -Milliseconds 150 }
    if (!(Test-Path "$root\ready.txt")) { throw 'Receiver failed to start' }
    # Two negative controls. A 404 must save zero bytes. Directory listing must not read the four fixture files.
    try { $null = Invoke-WebRequest -UseBasicParsing 'http://127.0.0.1:18768/rejected' -Method Post -Body 'TRAINING' } catch { if ([int]$_.Exception.Response.StatusCode -ne 404) { throw } }
    $ordinary = Start-Process cmd.exe -ArgumentList "/d /c dir /b $source" -RedirectStandardOutput "$root\control-files.txt" -PassThru -WindowStyle Hidden -Wait
    if ($ordinary.ExitCode) { throw 'Directory-list control failed' }

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $page = Invoke-WebRequest -UseBasicParsing 'http://127.0.0.1:18768/update'
    if ($page.StatusCode -ne 200 -or $page.Content -notmatch "<pre id='launch'>([^<]+)</pre>") { throw 'Training page did not load' }
    $shown = $matches[1]
    if ($shown -cne $command) { throw 'Unexpected command on training page' }
    $form = New-Object Windows.Forms.Form
    $form.Text = 'Week 8 | Local training update'; $form.Width=850; $form.Height=250; $form.StartPosition='CenterScreen'
    $message = New-Object Windows.Forms.Label
    $message.Text = "Synthetic lab $run   |   http://127.0.0.1:18768/update`r`nSelect the command (Ctrl+A, Ctrl+C), open Run (Win+R), paste, then press Enter."
    $message.SetBounds(15,15,800,55)
    $box = New-Object Windows.Forms.TextBox
    $box.ReadOnly=$true; $box.Text=$shown; $box.SetBounds(15,80,795,36)
    $form.Controls.AddRange(@($message,$box))
    $form.Add_Shown({$form.Activate(); $box.Focus(); $box.SelectAll()})
    $timer = New-Object Windows.Forms.Timer
    $timer.Interval=500; $timer.Add_Tick({if ((Test-Path "$root\completed.json") -or (Test-Path "$root\failure.txt")) { $form.Close() }})
    $timer.Start()
    [void]$form.ShowDialog()
    $timer.Stop(); $timer.Dispose(); $form.Dispose()
    if (!(Test-Path "$root\completed.json")) { throw 'The interactive training chain did not finish.' }
    $case = Get-Content "$root\completed.json" -Raw | ConvertFrom-Json
    $receiver.WaitForExit(5000) | Out-Null
    $clientHash = (Get-FileHash "$root\training.zip").Hash
    $receiverHash = (Get-FileHash "$root\received.zip").Hash
    if ($clientHash -ne $receiverHash -or $clientHash -ne $case.zip_hash) { throw 'Archive transfer hash mismatch' }
    Expand-Archive -LiteralPath "$root\received.zip" -DestinationPath "$root\verify"
    $members = @(Get-ChildItem "$root\verify" -File -Recurse | Sort-Object Name | ForEach-Object {
        $expected = $fixtures[$_.Name]
        if (!$expected -or [IO.File]::ReadAllText($_.FullName) -cne $expected) { throw 'Unexpected received archive content' }
        @{name=$_.Name;sha256=(Get-FileHash $_.FullName).Hash}
    })
    if (($members.name -join ',') -ne ($fixtures.Keys -join ',')) { throw 'ZIP membership mismatch' }
    $mru = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -ErrorAction SilentlyContinue
    $mruCommand = @($mru.PSObject.Properties | Where-Object { [string]$_.Value -like "$command*" } | ForEach-Object { $_.Value })
    Write-Host "Verified receiver ZIP and four extracted members"
    Copy-Item "$root\completed.json","$root\task.xml","$root\http.jsonl","$root\received.zip","$root\update.html" -Destination $export
    Write-JsonFile "$export\verification.json" ([ordered]@{run=$run;start_utc=$since.ToUniversalTime().ToString('o');host=$env:COMPUTERNAME;loader_pid=$case.pid;control_pid=$ordinary.Id;control_names=@(Get-Content "$root\control-files.txt");shown_command=$shown;run_mru=$mruCommand;sender_sha256=$clientHash;receiver_sha256=$receiverHash;members=$members;task_absent=!(Test-LabTask $case.task)})
    Write-Host 'Exporting native Windows events'
    Start-Sleep -Seconds 3
    & "$PSScriptRoot\export-events.ps1" -Since $since -OutputDirectory $export -Case $case -ControlPid $ordinary.Id
} catch {
    [IO.File]::WriteAllText("$export\error.txt",($_ | Out-String)+$_.ScriptStackTrace)
    if (Test-Path "$root\failure.txt") { Copy-Item "$root\failure.txt" $export }
    throw
} finally {
    Write-Host 'Cleaning up the lab'
    if ($receiver -and !$receiver.HasExited) { Stop-Process -Id $receiver.Id -Force }
    if (Test-LabTask "Week8-Training-$run") { & schtasks.exe /delete /tn "Week8-Training-$run" /f | Out-Null }
    if ($auditSaved) { Audit-Command @('/restore',"/file:$root\audit-before.csv") }
    foreach ($s in $oldSettings) {
        if ($null -ne $s.value) { Set-ItemProperty $s.key $s.name $s.value }
        else { Remove-ItemProperty $s.key $s.name -ErrorAction SilentlyContinue }
        if (!$s.existed -and (Get-Item $s.key).ValueCount -eq 0) { Remove-Item $s.key -ErrorAction SilentlyContinue }
    }
    Remove-Item $root -Recurse -Force
    Write-JsonFile "$export\cleanup.json" @{root_absent=!(Test-Path $root);task_absent=!(Test-LabTask "Week8-Training-$run");receiver_stopped=($null -eq $receiver -or $receiver.HasExited);utc=[datetime]::UtcNow.ToString('o')}
}
