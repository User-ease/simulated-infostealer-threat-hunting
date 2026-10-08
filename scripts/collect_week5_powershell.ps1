# Collect four benign Windows PowerShell cases and genuine engine-start events.
# This script changes neither audit settings nor registry settings.
[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string]$PrivateRoot,
    [switch]$OverwriteExistingRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)
$powerShellExe = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
}
$repoPath = [System.IO.Path]::GetFullPath($RepoRoot).TrimEnd('\', '/')
if (-not (Test-Path -LiteralPath $repoPath -PathType Container)) {
    throw "Repository does not exist: $repoPath"
}
if (-not (Test-Path -LiteralPath $powerShellExe -PathType Leaf)) {
    throw 'Windows PowerShell 5.1 executable is unavailable.'
}
if ([string]::IsNullOrWhiteSpace($PrivateRoot)) {
    $PrivateRoot = Join-Path (Split-Path -Parent $repoPath) 'tmp\week5'
}
$privatePath = [System.IO.Path]::GetFullPath($PrivateRoot).TrimEnd('\', '/')
if ($privatePath.Equals($repoPath, [System.StringComparison]::OrdinalIgnoreCase) -or
    $privatePath.StartsWith($repoPath + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'PrivateRoot must be outside the repository.'
}
$evidenceDir = Join-Path $repoPath 'evidence\week5'
$dataDir = Join-Path $repoPath 'data'
$xmlPath = Join-Path $evidenceDir 'windows-events.xml'
$jsonlPath = Join-Path $dataDir 'week5-powershell-events.jsonl'
$manifestPath = Join-Path $evidenceDir 'run-manifest.json'
foreach ($artifact in @($xmlPath, $jsonlPath, $manifestPath)) {
    if ((Test-Path -LiteralPath $artifact) -and -not $OverwriteExistingRun) {
        throw "Existing run is protected: $artifact. Use -OverwriteExistingRun explicitly to replace it."
    }
}

# Check log readability before creating the child processes. Do not configure it.
$null = Get-WinEvent -ListLog 'Windows PowerShell' -ErrorAction Stop
$runId = [guid]::NewGuid().ToString('N')
$runPrivateDir = Join-Path $privatePath $runId
$null = New-Item -ItemType Directory -Path $runPrivateDir -Force
$caseDefinitions = @(
    @{ case_id = 'baseline_plain'; encoded = $false; hidden_bypass = $false },
    @{ case_id = 'encoded_only'; encoded = $true; hidden_bypass = $false },
    @{ case_id = 'hidden_bypass'; encoded = $false; hidden_bypass = $true },
    @{ case_id = 'encoded_hidden_bypass'; encoded = $true; hidden_bypass = $true }
)
$runStartedUtc = [datetime]::UtcNow
$caseResults = New-Object 'System.Collections.Generic.List[object]'
foreach ($definition in $caseDefinitions) {
    $caseId = $definition.case_id
    $marker = "W5LAB-$runId-$caseId"
    $payload = "Write-Output '$marker'"
    $argumentString = '-NoProfile -NonInteractive'
    if ($definition.hidden_bypass) {
        $argumentString += ' -WindowStyle Hidden -ExecutionPolicy Bypass'
    }
    if ($definition.encoded) {
        $encodedPayload = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($payload))
        $argumentString += ' -EncodedCommand ' + $encodedPayload
    } else {
        $argumentString += ' -Command "' + $payload + '"'
    }
    $stdoutPath = Join-Path $runPrivateDir ($caseId + '.stdout.txt')
    $stderrPath = Join-Path $runPrivateDir ($caseId + '.stderr.txt')
    $caseStartedUtc = [datetime]::UtcNow
    $child = Start-Process -FilePath $powerShellExe -ArgumentList $argumentString `
        -WindowStyle Hidden -Wait -PassThru `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    $child.WaitForExit()
    $child.Refresh()
    $caseFinishedUtc = [datetime]::UtcNow
    $stdout = (Get-Content -LiteralPath $stdoutPath -Raw).TrimEnd([char[]]"`r`n")
    $stderr = Get-Content -LiteralPath $stderrPath -Raw
    if ($child.ExitCode -ne 0) {
        throw "Case $caseId failed with exit code $($child.ExitCode). Private output: $runPrivateDir"
    }
    if ($stdout -cne $marker) {
        throw "Case $caseId did not produce exactly its expected output. Private output: $runPrivateDir"
    }
    $stderrClassification = 'empty'
    if (-not [string]::IsNullOrWhiteSpace($stderr)) {
        # Windows PowerShell can serialize first-use module progress to stderr
        # for EncodedCommand. Accept progress alone, never an error stream.
        if (-not $stderr.StartsWith('#< CLIXML')) {
            throw "Case $caseId produced unexpected stderr. Private output: $runPrivateDir"
        }
        $stderrXml = New-Object System.Xml.XmlDocument
        $stderrXml.LoadXml(($stderr -replace '^#< CLIXML\s*', ''))
        $streamNodes = @($stderrXml.SelectNodes("/*[local-name()='Objs']/*"))
        if ($streamNodes.Count -eq 0 -or @($streamNodes | Where-Object {
            $_.LocalName -ne 'Obj' -or $_.GetAttribute('S') -ne 'progress'
        }).Count -gt 0) {
            throw "Case $caseId produced a non-progress stderr stream. Private output: $runPrivateDir"
        }
        $stderrClassification = 'powershell_clixml_progress_only'
    }
    $caseResults.Add([ordered]@{
        case_id = $caseId
        pid = [int]$child.Id
        exit_code = [int]$child.ExitCode
        stdout = $stdout
        stderr_classification = $stderrClassification
        private_stderr_sha256 = (Get-FileHash -LiteralPath $stderrPath -Algorithm SHA256).Hash
        payload = $payload
        started_utc = $caseStartedUtc.ToString('o')
        finished_utc = $caseFinishedUtc.ToString('o')
    })
}
$launchFinishedUtc = [datetime]::UtcNow

# Event 400 is selected by the real process ID and bounded launch interval.
# Poll only for delayed delivery; never substitute an event from an older run.
$selectedEvents = @{}
for ($attempt = 0; $attempt -lt 10; $attempt++) {
    $events = @(Get-WinEvent -FilterHashtable @{
        LogName = 'Windows PowerShell'
        Id = 400
        StartTime = $runStartedUtc.ToLocalTime()
        EndTime = $launchFinishedUtc.ToLocalTime()
    } -ErrorAction SilentlyContinue)
    $allPresent = $true
    foreach ($caseResult in $caseResults) {
        $matches = @($events | Where-Object { [int]$_.ProcessId -eq $caseResult.pid })
        if ($matches.Count -gt 1) {
            throw "Expected one Event 400 for PID $($caseResult.pid), got $($matches.Count)."
        }
        if ($matches.Count -eq 0) {
            $allPresent = $false
        } else {
            $selectedEvents[$caseResult.case_id] = $matches[0]
        }
    }
    if ($allPresent) { break }
    if ($attempt -lt 9) { Start-Sleep -Milliseconds 500 }
}
if ($selectedEvents.Count -ne 4) {
    throw "Not all four genuine Event 400 records were available. Private output: $runPrivateDir"
}

$publicXml = New-Object System.Xml.XmlDocument
$null = $publicXml.AppendChild($publicXml.CreateElement('Events'))
$jsonLines = New-Object 'System.Collections.Generic.List[string]'
$engineVersions = New-Object 'System.Collections.Generic.List[string]'
foreach ($caseResult in $caseResults) {
    $eventRecord = $selectedEvents[$caseResult.case_id]
    $originalXml = $eventRecord.ToXml()
    $originalPath = Join-Path $runPrivateDir ($caseResult.case_id + '.event400.original.xml')
    [System.IO.File]::WriteAllText($originalPath, $originalXml, $utf8)
    $eventXml = New-Object System.Xml.XmlDocument
    $eventXml.LoadXml($originalXml)
    $context = ($eventXml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']") |
        ForEach-Object { $_.InnerText }) -join "`n"
    $hostMatches = [regex]::Matches($context, '(?m)^[ \t]*HostApplication=([^\r\n]*)')
    $versionMatches = [regex]::Matches($context, '(?m)^[ \t]*EngineVersion=([^\r\n]*)')
    if ($hostMatches.Count -ne 1 -or $versionMatches.Count -ne 1) {
        throw "Missing or ambiguous event context for $($caseResult.case_id)."
    }
    $hostApplication = $hostMatches[0].Groups[1].Value
    $engineVersion = $versionMatches[0].Groups[1].Value
    if (-not $engineVersion.StartsWith('5.1.')) {
        throw "Unexpected engine version $engineVersion for $($caseResult.case_id)."
    }
    $engineVersions.Add($engineVersion)
    $caseResult.command_line = $hostApplication
    $caseResult.record_id = [long]$eventRecord.RecordId
    $caseResult.event_time = $eventRecord.TimeCreated.ToUniversalTime().ToString('o')
    $caseResult.original_xml_sha256 = (Get-FileHash -LiteralPath $originalPath -Algorithm SHA256).Hash

    $computer = $eventXml.SelectSingleNode("/*[local-name()='Event']/*[local-name()='System']/*[local-name()='Computer']")
    if ($null -eq $computer) { throw 'Event System/Computer is missing.' }
    $computer.InnerText = 'LAB-WINDOWS-HOST'
    $security = $eventXml.SelectSingleNode("/*[local-name()='Event']/*[local-name()='System']/*[local-name()='Security']")
    if ($null -ne $security -and $security.HasAttribute('UserID')) {
        $security.SetAttribute('UserID', 'S-1-0-0')
    }
    $null = $publicXml.DocumentElement.AppendChild($publicXml.ImportNode($eventXml.DocumentElement, $true))
    $record = [ordered]@{
        '@timestamp' = $caseResult.event_time
        event = [ordered]@{ code = '400'; provider = 'PowerShell'; action = 'engine-start' }
        winlog = [ordered]@{ channel = 'Windows PowerShell'; record_id = [long]$eventRecord.RecordId }
        host = [ordered]@{ name = 'LAB-WINDOWS-HOST' }
        process = [ordered]@{ name = 'powershell.exe'; pid = [int]$caseResult.pid; command_line = $hostApplication }
        lab = [ordered]@{ run_id = $runId; case_id = $caseResult.case_id }
    }
    $jsonLines.Add(($record | ConvertTo-Json -Depth 6 -Compress))
}
$uniqueVersions = @($engineVersions | Select-Object -Unique)
if ($uniqueVersions.Count -ne 1) { throw 'Cases reported different PowerShell engine versions.' }

# Publish only after all process and event checks have succeeded.
$null = New-Item -ItemType Directory -Path $evidenceDir -Force
$null = New-Item -ItemType Directory -Path $dataDir -Force
$xmlSettings = New-Object System.Xml.XmlWriterSettings
$xmlSettings.Encoding = $utf8
$xmlSettings.Indent = $true
$writer = [System.Xml.XmlWriter]::Create($xmlPath, $xmlSettings)
try { $publicXml.Save($writer) } finally { $writer.Dispose() }
[System.IO.File]::WriteAllText($jsonlPath, (($jsonLines -join "`n") + "`n"), $utf8)
$manifest = [ordered]@{
    run_id = $runId
    started_utc = $runStartedUtc.ToString('o')
    launch_finished_utc = $launchFinishedUtc.ToString('o')
    collected_utc = [datetime]::UtcNow.ToString('o')
    powershell_version = $uniqueVersions[0]
    collector_powershell_version = $PSVersionTable.PSVersion.ToString()
    collector_script_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
    executable = $powerShellExe
    event_count = 4
    cases = @($caseResults.ToArray())
    redactions = @(
        [ordered]@{ field = 'Event/System/Computer'; replacement = 'LAB-WINDOWS-HOST'; scope = 'published XML and derived host.name' },
        [ordered]@{ field = 'Event/System/Security/@UserID'; replacement = 'S-1-0-0'; scope = 'published XML, only when present' }
    )
    original_xml_location = 'PrivateRoot/<run_id>/*.event400.original.xml; outside repository'
    artifacts = @(
        [ordered]@{ path = 'evidence/week5/windows-events.xml'; sha256 = (Get-FileHash -LiteralPath $xmlPath -Algorithm SHA256).Hash },
        [ordered]@{ path = 'data/week5-powershell-events.jsonl'; sha256 = (Get-FileHash -LiteralPath $jsonlPath -Algorithm SHA256).Hash }
    )
}
[System.IO.File]::WriteAllText($manifestPath, (($manifest | ConvertTo-Json -Depth 8) + "`n"), $utf8)
[ordered]@{
    run_id = $runId
    case_count = $caseResults.Count
    event_count = $selectedEvents.Count
    published_artifacts = @($xmlPath, $jsonlPath, $manifestPath)
    private_originals_and_output = $runPrivateDir
} | ConvertTo-Json -Depth 4
