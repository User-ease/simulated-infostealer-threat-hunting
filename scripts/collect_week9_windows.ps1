#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:SystemDrive ("week9-lab-" + [guid]::NewGuid().ToString('N'))
$tar = Join-Path $env:SystemRoot 'System32\tar.exe'
$profileDir = Join-Path $root 'profile'
$ordinary = Join-Path $root 'documents'
$out = Join-Path $root 'out'
$reg = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$setting = 'ProcessCreationIncludeCmdLine_Enabled'
$processAudit = '{0CCE922B-69AE-11D9-BED3-505054503030}'
$fileAudit = '{0CCE921D-69AE-11D9-BED3-505054503030}'
$utf8 = [Text.UTF8Encoding]::new($false)
$cases = [Collections.Generic.List[object]]::new()
function Invoke-AuditPol([string[]]$Parameters) {
    $lines = & auditpol.exe @Parameters
    if ($LASTEXITCODE) { throw "auditpol $Parameters failed (exit $LASTEXITCODE)" }
    return $lines
}
function Invoke-Case($Name, [string[]]$Arguments, $ExpectedHit, $ExpectedSuccess, $CheckSource, $Archive) {
    # Fixture paths are generated without spaces. No shell interprets arguments.
    $start = [DateTime]::UtcNow
    $info = [Diagnostics.ProcessStartInfo]::new($tar, ($Arguments -join ' '))
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $proc = [Diagnostics.Process]::Start($info)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    $case = [ordered]@{ name=$Name; pid=$proc.Id; argv=$Arguments; start_utc=$start.ToString('o');
        end_utc=[DateTime]::UtcNow.ToString('o'); exit_code=$proc.ExitCode; expected_hit=$ExpectedHit;
        expected_success=$ExpectedSuccess; stdout=$stdout.Trim(); stderr=$stderr.Trim(); member_sha256=$null }
    if (($proc.ExitCode -eq 0) -ne $ExpectedSuccess) { throw "Unexpected exit for $Name : $($proc.ExitCode) $stderr" }
    $proc.Dispose()
    if ($CheckSource) {
        $verify = Join-Path $root "verify-$Name"
        [void][IO.Directory]::CreateDirectory($verify)
        & $tar -xf $Archive -C $verify
        if ($LASTEXITCODE) { throw "Verification extraction failed for $Name" }
        $original = (Get-FileHash (Join-Path $CheckSource 'cookies.json')).Hash
        $recovered = (Get-FileHash (Join-Path $verify 'cookies.json')).Hash
        if ($original -ne $recovered) { throw "Archive member mismatch for $Name" }
        $case.member_sha256 = $recovered.ToLowerInvariant()
    }
    $cases.Add($case)
}
if (Test-Path -LiteralPath $OutputDirectory) { throw "Use a new output directory" }
[void][IO.Directory]::CreateDirectory($OutputDirectory)
[void][IO.Directory]::CreateDirectory($root)
# The native flag is independent of the computer's auditpol display language.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class Week9AuditPolicy {
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool AuditQuerySystemPolicy(ref Guid subcategory, uint count, out IntPtr policy);
    [DllImport("advapi32.dll")]
    static extern void AuditFree(IntPtr pointer);
    public static bool SuccessEnabled(Guid subcategory) {
        IntPtr result;
        if (!AuditQuerySystemPolicy(ref subcategory, 1, out result))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        // AUDIT_POLICY_INFORMATION starts with the 16-byte subcategory GUID, then a DWORD.
        try { return (Marshal.ReadInt32(result, 16) & 1) != 0; }
        finally { AuditFree(result); }
    }
}
'@
$oldBits = @{}
$hadReg = Test-Path $reg
$oldValue = $null
$changedReg = $false
try {
    foreach ($subcategory in @($processAudit,$fileAudit)) {
        $oldBits[$subcategory] = [Week9AuditPolicy]::SuccessEnabled([guid]$subcategory)
        [void](Invoke-AuditPol @('/set',"/subcategory:$subcategory",'/success:enable'))
    }
    if (!$hadReg) { [void](New-Item $reg -Force) }
    $oldValue = (Get-Item $reg).GetValue($setting)
    [void](New-ItemProperty $reg $setting -PropertyType DWord -Value 1 -Force)
    $changedReg = $true
    $everyone = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
    $acl = Get-Acl -LiteralPath $root -Audit
    $rule = [Security.AccessControl.FileSystemAuditRule]::new($everyone, 'ReadData,WriteData', 'ContainerInherit,ObjectInherit', 'None', 'Success')
    $acl.AddAuditRule($rule)
    Set-Acl -LiteralPath $root -AclObject $acl
    foreach ($dir in @($profileDir,$ordinary,$out)) { [void][IO.Directory]::CreateDirectory($dir) }
    $profileFile = Join-Path $profileDir 'cookies.json'
    [IO.File]::WriteAllText($profileFile, '{"fixture":"synthetic profile","session":"training-only"}', $utf8)
    [IO.File]::WriteAllText((Join-Path $ordinary 'cookies.json'), '{"fixture":"ordinary documentation"}', $utf8)
    $a = Join-Path $out 'profile.tar'
    $b = Join-Path $out 'documents.tar'
    $c = Join-Path $out 'browser-profile-backup.tar'
    $d = Join-Path $out 'authorized-backup.tar'
    $classicArchive = Join-Path $out 'traditional.tar'
    $since = Get-Date
    Invoke-Case 'profile_create' @('-cf',$a,'-C',$profileDir,'.') $true $true $profileDir $a
    Invoke-Case 'ordinary_backup' @('-cf',$b,'-C',$ordinary,'.') $false $true $ordinary $b
    Invoke-Case 'destination_only' @('-cf',$c,'-C',$ordinary,'.') $false $true $ordinary $c
    Invoke-Case 'list_archive' @('-tf',$a) $false $true $null $null
    Invoke-Case 'authorized_profile_backup' @('--create',"--file=$d",'-C',$profileDir,'.') $true $true $profileDir $d
    Invoke-Case 'list_raw_profile' @('-tf',$profileFile) $false $false $null $null
    Invoke-Case 'classic_create' @('cf',$classicArchive,'-C',$profileDir,'cookies.json') $true $true $profileDir $classicArchive
    Invoke-Case 'classic_list_archive' @('tf',$classicArchive) $false $true $null $null
    Invoke-Case 'classic_list_raw_profile' @('tf',$profileFile) $false $false $null $null
    if (@($cases.pid | Sort-Object -Unique).Count -ne $cases.Count) { throw 'Case PID reused; rerun' }
    Start-Sleep -Seconds 3
    $selected = [Collections.Generic.List[string]]::new()
    $launches = @()
    $profileReaders = @()
    $events = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4663,4688;StartTime=$since.AddSeconds(-1)} -Oldest
    foreach ($ev in $events) {
        $raw = $ev.ToXml()
        $doc = [xml]$raw
        $fields = @{}
        foreach ($field in $doc.Event.EventData.Data) { $fields[$field.Name] = $field.'#text' }
        if ($ev.Id -eq 4688) {
            if ($fields.NewProcessName -ne $tar -or $fields.CommandLine -notlike "*$root*") { continue }
            $procId = [Convert]::ToInt64($fields.NewProcessId,16)
        } else {
            if ($fields.ProcessName -ne $tar -or !$fields.ObjectName.StartsWith("$root\",[StringComparison]::OrdinalIgnoreCase)) { continue }
            $procId = [Convert]::ToInt64($fields.ProcessId,16)
        }
        if ($cases.pid -notcontains $procId) { continue }
        $selected.Add($raw)
        if ($ev.Id -eq 4688) { $launches += $procId }
        elseif ($fields.ObjectName -eq $profileFile -and ([Convert]::ToInt64($fields.AccessMask,16) -band 1)) { $profileReaders += $procId }
    }
    if ($launches.Count -ne $cases.Count -or @($launches | Sort-Object -Unique).Count -ne $cases.Count) {
        throw "Expected one detailed 4688 per case, got $($launches.Count)"
    }
    foreach ($case in $cases) {
        if (($case.expected_hit -or $case.name -in @('list_raw_profile','classic_list_raw_profile')) -and $profileReaders -notcontains $case.pid) {
            throw "No profile ReadData 4663 for $($case.name)"
        }
    }
    $os = Get-CimInstance Win32_OperatingSystem
    $manifest = [ordered]@{ computer=$env:COMPUTERNAME; os=$os.Caption; build=$os.BuildNumber;
        collected_utc=[DateTime]::UtcNow.ToString('o'); tar_exe=$tar; tar_version=(& $tar --version);
        root=$root; profile_input=$profileFile; profile_sha256=(Get-FileHash $profileFile).Hash.ToLowerInvariant();
        actions_run_id=$env:GITHUB_RUN_ID; source_commit=$env:GITHUB_SHA; cases=$cases }
    [IO.File]::WriteAllText((Join-Path $OutputDirectory 'events.xml'), "<Events>" + [Environment]::NewLine + ($selected -join [Environment]::NewLine) + [Environment]::NewLine + "</Events>", $utf8)
    [IO.File]::WriteAllText((Join-Path $OutputDirectory 'manifest.json'), ($manifest | ConvertTo-Json -Depth 8), $utf8)
    Write-Host "Collected $($selected.Count) native records for $($cases.Count) cases"
} finally {
    if ($changedReg) {
        if ($null -eq $oldValue) { Remove-ItemProperty $reg $setting }
        else { Set-ItemProperty $reg $setting $oldValue }
        if (!$hadReg -and !(Get-Item $reg).Property) { Remove-Item $reg }
    }
    foreach ($subcategory in $oldBits.Keys) {
        $success = if ($oldBits[$subcategory]) { 'enable' } else { 'disable' }
        [void](Invoke-AuditPol @('/set',"/subcategory:$subcategory","/success:$success"))
    }
    Remove-Item -LiteralPath $root -Recurse -Force
}
