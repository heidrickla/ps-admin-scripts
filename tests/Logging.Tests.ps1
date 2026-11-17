$repo = Split-Path -Parent $PSScriptRoot   # run from any clone, USB or share
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$fail = 0
function Check($name, [scriptblock]$b) {
    try { if (& $b) { "  PASS  $name" } else { "  FAIL  $name"; $script:fail++ } }
    catch { "  FAIL  $name -- $($_.Exception.Message)"; $script:fail++ }
}

$work = Join-Path $env:TEMP ("admlog-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$env:ADADMIN_STORE   = Join-Path $work 'adadmin-store.json'
$env:ADADMIN_LOG_DIR = Join-Path $work 'logs'
$env:ADADMIN_PROVIDER = 'mock'

Import-Module (Join-Path $repo 'ADAdmin\ADAdmin.psd1') -Force

"== diagnosis catalog -- hardened-AD signatures =="
function Diag($text, $op = 'test', $target = 'corp.example.com') {
    $ex = New-Object System.Exception($text)
    $er = New-Object System.Management.Automation.ErrorRecord($ex, 'x', 'NotSpecified', $null)
    & (Get-Module ADAdmin) { param($e, $o, $t) Resolve-AdmDiagnosis -ErrorObject $e -Operation $o -Target $t } $er $op $target
}

Check 'LDAP signing required is recognised' {
    (Diag '80090322: LdapErr: DSID-0C09044E, comment: The server requires binds to turn on integrity checking').Code -eq 'LDAP-SIGNING-REQUIRED'
}
Check 'bad password -> data 52e, not a generic failure' {
    $d = Diag '8009030C: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 52e, v4563'
    $d.Code -eq 'LDAP-BIND-52E' -and $d.Title -match 'Wrong username or password'
}
Check 'locked out -> data 775 with an unlock instruction' {
    $d = Diag 'AcceptSecurityContext error, data 775, v4563'
    $d.Code -eq 'LDAP-BIND-775' -and (@($d.Fix) -join ' ') -match 'adm user unlock'
}
Check 'disabled account -> data 533' { (Diag 'error, data 533, v4563').Code -eq 'LDAP-BIND-533' }
Check 'logon hours -> data 530'      { (Diag 'error, data 530, v4563').Code -eq 'LDAP-BIND-530' }
Check 'expired password -> data 532' { (Diag 'error, data 532, v4563').Code -eq 'LDAP-BIND-532' }
Check 'clock skew is recognised' {
    (Diag 'The clocks on the client and server machines are skewed 80090324').Code -eq 'KERBEROS-CLOCK-SKEW'
}
Check 'untrusted LDAPS certificate is recognised' {
    (Diag '8009030E: the certificate chain was issued by an authority that is not trusted').Code -eq 'LDAPS-CERT-UNTRUSTED'
}
Check 'server unreachable is recognised' {
    (Diag 'The server is not operational').Code -eq 'SERVER-UNREACHABLE'
}
Check 'access denied suggests the write tier' {
    $d = Diag 'Access is denied' 'unlock account'
    $d.Code -eq 'ACCESS-DENIED' -and (@($d.Fix) -join ' ') -match '-Tier write'
}
Check 'password policy refusal recognised on a reset' {
    (Diag '80072035 unwilling to perform' 'reset password for jsmith').Code -eq 'PASSWORD-POLICY-REFUSED'
}
Check 'bind by IP is called out as an NTLM problem' {
    (Diag '8007052e logon failure' 'bind' '192.0.2.40').Code -eq 'BIND-BY-IP-NTLM-BLOCKED'
}
Check 'size limit is a WARNING, not an error' {
    $d = Diag 'The size limit was exceeded'
    $d.Code -eq 'SIZE-LIMIT-EXCEEDED' -and $d.Severity -eq 'warn'
}
Check 'an unknown error says so instead of guessing' {
    $d = Diag 'Something nobody has ever seen before, code 12345'
    $d.Code -eq 'UNRECOGNISED' -and $d.Recognised -eq $false -and $d.Technical.Raw -match 'nobody has ever seen'
}
Check 'every rule supplies a title, a why and at least one fix' {
    $bad = @()
    foreach ($t in @('80090322 integrity', 'data 52e', 'The server is not operational', 'Access is denied', 'unknown-xyz')) {
        $d = Diag $t
        if (-not $d.Title -or -not $d.Why -or -not @($d.Fix).Count) { $bad += $t }
    }
    $bad.Count -eq 0
}

"== the log =="
Check 'writing creates a dated file' {
    Write-AdmLog -Severity info -Message 'suite start' | Out-Null
    @(Get-ChildItem $env:ADADMIN_LOG_DIR -Filter 'adadmin-*.jsonl').Count -ge 1
}
Check 'file is named for today' {
    Test-Path (Join-Path $env:ADADMIN_LOG_DIR ('adadmin-{0:yyyy-MM-dd}.jsonl' -f (Get-Date)))
}
Check 'entries read back' { @(Get-AdmLog -Last 50 | Where-Object { $_.message -eq 'suite start' }).Count -eq 1 }
Check 'log file has no BOM' {
    $f = Join-Path $env:ADADMIN_LOG_DIR ('adadmin-{0:yyyy-MM-dd}.jsonl' -f (Get-Date))
    $b = [System.IO.File]::ReadAllBytes($f)
    -not ($b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
}
Check 'an error record is diagnosed automatically' {
    try { throw '8009030C AcceptSecurityContext error, data 52e, v4563' } catch { Write-AdmLog -ErrorRecord $_ -Operation 'suite' -Target corp.example.com | Out-Null }
    $e = @(Get-AdmLog -Last 50 | Where-Object { $_.code -eq 'LDAP-BIND-52E' })
    $e.Count -ge 1 -and $e[-1].why -and @($e[-1].fix).Count -ge 1
}
Check 'log info reports a writable directory' {
    $i = Get-AdmLogInfo
    $i.Writable -eq $true -and $i.RetentionDays -eq 7 -and $i.Directory -eq $env:ADADMIN_LOG_DIR
}

"== 7-day rolling cleanup =="
Check 'files older than 7 days are deleted, newer kept' {
    $old = Join-Path $env:ADADMIN_LOG_DIR ('adadmin-{0:yyyy-MM-dd}.jsonl' -f (Get-Date).AddDays(-9))
    $edge = Join-Path $env:ADADMIN_LOG_DIR ('adadmin-{0:yyyy-MM-dd}.jsonl' -f (Get-Date).AddDays(-3))
    '{"ts":"x","severity":"info","message":"ancient"}' | Set-Content -LiteralPath $old -Encoding UTF8
    '{"ts":"y","severity":"info","message":"recent"}'  | Set-Content -LiteralPath $edge -Encoding UTF8
    Clear-AdmLog -Confirm:$false | Out-Null          # prunes to the window
    (-not (Test-Path $old)) -and (Test-Path $edge)
}
Check 'pruning uses the FILENAME date, not the file mtime' {
    # A restored backup or a copied USB stick rewrites mtime; the day a log covers does not change.
    $old = Join-Path $env:ADADMIN_LOG_DIR ('adadmin-{0:yyyy-MM-dd}.jsonl' -f (Get-Date).AddDays(-30))
    '{"ts":"z"}' | Set-Content -LiteralPath $old -Encoding UTF8
    (Get-Item $old).LastWriteTime = Get-Date          # looks brand new on disk
    Clear-AdmLog -Confirm:$false | Out-Null
    -not (Test-Path $old)
}

"== logging must never throw =="
Check 'an unwritable log directory does not break the caller' {
    $saved = $env:ADADMIN_LOG_DIR
    $env:ADADMIN_LOG_DIR = 'Z:\definitely\not\a\real\path'
    Import-Module (Join-Path $repo 'ADAdmin\ADAdmin.psd1') -Force   # reset the cached dir
    $threw = $false
    try { Write-AdmLog -Severity error -Message 'nowhere to write this' | Out-Null } catch { $threw = $true }
    $inRing = @(Get-AdmLog -Last 10 | Where-Object { $_.message -eq 'nowhere to write this' }).Count -ge 1
    $env:ADADMIN_LOG_DIR = $saved
    Import-Module (Join-Path $repo 'ADAdmin\ADAdmin.psd1') -Force
    (-not $threw) -and $inRing     # the entry survives in memory even with no disk
}

"== failures are logged AND raised loudly =="
Check 'an unresolved target is logged with a diagnosis and still throws' {
    $pp = ConvertTo-SecureString 'log-unlock-aaa' -AsPlainText -Force
    Initialize-AdmStore -RecipientName t -Passphrase $pp -Iterations 100000 -Force -Confirm:$false | Out-Null
    Unlock-AdmStore -Passphrase $pp | Out-Null
    $threw = $false; $hadDiag = $false
    try { Get-AdmUser -Target nowhere.example.org | Out-Null }
    catch { $threw = $true; $hadDiag = [bool]$_.Exception.Data['AdmDiagnosis'] }
    $logged = @(Get-AdmLog -Last 50 | Where-Object { $_.code -eq 'UNRESOLVED-TARGET' }).Count -ge 1
    $threw -and $hadDiag -and $logged
}
Check 'the raised message leads with the plain-English title' {
    try { Get-AdmUser -Target nowhere.example.org | Out-Null; $false }
    catch { $_.Exception.Message -match 'does not belong to any registered domain' }
}
Check 'a successful change is recorded as an audit entry' {
    Register-AdmDomain -Name corp -DnsDomain corp.example.com -NetbiosName CORP -Confirm:$false | Out-Null
    $c = New-Object System.Management.Automation.PSCredential('CORP\svc', (ConvertTo-SecureString 'x' -AsPlainText -Force))
    Set-AdmDomainCredential -Domain corp -Credential $c -Tier read -SetDefault -Confirm:$false | Out-Null
    Set-AdmDomainCredential -Domain corp -Credential $c -Tier write -Confirm:$false | Out-Null
    Unlock-AdmUser -Target corp.example.com -Identity aokafor -Confirm:$false | Out-Null
    @(Get-AdmLog -Last 50 | Where-Object { $_.event -eq 'change' -and $_.message -match 'aokafor' }).Count -ge 1
}
Check 'a password reset never writes the password to the log' {
    Reset-AdmUserPassword -Target corp.example.com -Identity jsmith `
        -NewPassword (ConvertTo-SecureString 'Zz9!zzzzzzzz' -AsPlainText -Force) -Confirm:$false | Out-Null
    $raw = Get-Content (Join-Path $env:ADADMIN_LOG_DIR ('adadmin-{0:yyyy-MM-dd}.jsonl' -f (Get-Date))) -Raw
    ($raw -notmatch 'Zz9!') -and ($raw -match 'Password reset for')
}

"== the human-readable report =="
Check 'export produces a report with what/why/what-to-do' {
    $p = Join-Path $work 'report.txt'
    Export-AdmLog -Path $p -Days 7 | Out-Null
    $t = Get-Content $p -Raw
    ($t -match 'What happened') -and ($t -match 'Why') -and ($t -match 'What to do') -and ($t -match 'ADAdmin activity report')
}
Check 'report wraps long prose instead of one endless line' {
    $t = Get-Content (Join-Path $work 'report.txt')
    ($t | Measure-Object -Property Length -Maximum).Maximum -lt 100
}
Check 'problems-only filter drops the info noise' {
    $p = Join-Path $work 'problems.txt'
    Export-AdmLog -Path $p -Days 7 -ProblemsOnly | Out-Null
    (Get-Content $p -Raw) -notmatch 'suite start'
}

Remove-Item -LiteralPath $work -Recurse -Force -EA SilentlyContinue
if ($fail -gt 0) { "`nFAILURES: $fail"; exit 1 } else { "`nall logging checks passed"; exit 0 }
