$repo = Split-Path -Parent $PSScriptRoot   # run from any clone, USB or share
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$fail = 0
function Check($name, [scriptblock]$b) {
    try { if (& $b) { "  PASS  $name" } else { "  FAIL  $name"; $script:fail++ } }
    catch { "  FAIL  $name -- $($_.Exception.Message)"; $script:fail++ }
}

$work = Join-Path $env:TEMP ("admscan-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$env:ADADMIN_STORE    = Join-Path $work 'store.json'
$env:ADADMIN_LOG_DIR  = Join-Path $work 'logs'
$env:ADADMIN_PROVIDER = 'mock'

Import-Module (Join-Path $repo 'ADAdmin\ADAdmin.psd1') -Force

"== the error catalog =="
Check 'catalog returns many rows'   { @(Get-AdmErrorCatalog).Count -ge 20 }
Check 'docs\error-catalog.md has not drifted from the code' {
    # ⛔ THE DOC SAYS "Do not hand-edit: regenerate it, or the table and the code drift apart" --
    # and nothing checked that anyone had. A generated file with an instruction and no check is a
    # file that drifts the first time someone adds a rule in a hurry, and the drift is invisible:
    # both halves keep working, they just stop agreeing.
    #
    # ⚠ NEWLINES NORMALISED BEFORE COMPARING. The repo is BOM-less UTF-8 with LF in git and CRLF
    # on disk, and Out-String emits CRLF -- so a raw comparison fails on every line for a reason
    # that has nothing to do with drift.
    $fresh  = (Get-AdmErrorCatalog -AsMarkdown | Out-String).Replace("`r`n", "`n").TrimEnd()
    $onDisk = [System.IO.File]::ReadAllText((Join-Path $repo 'docs\error-catalog.md')).Replace("`r`n", "`n").TrimEnd()
    if ($fresh -ne $onDisk) {
        "     regenerate it:  adm catalog -Markdown -Path docs\error-catalog.md"
        "     generated $($fresh.Length) chars, on disk $($onDisk.Length)"
    }
    # A control that cannot legitimately be empty: an empty generator would match an empty file.
    $fresh.Length -gt 2000 -and $fresh -eq $onDisk
}
Check 'lookup by exact code'        { (Get-AdmErrorCatalog -Code 'LDAP-BIND-52E').Title -match 'Wrong username or password' }
Check 'wildcard lookup works'       { @(Get-AdmErrorCatalog -Code 'LDAP-BIND-*').Count -ge 8 }
Check 'severity filter works'       { @(Get-AdmErrorCatalog -Severity warn).Count -ge 1 -and
                                      @(Get-AdmErrorCatalog -Severity warn | Where-Object { $_.Severity -ne 'warn' }).Count -eq 0 }
Check 'every entry is actionable'   {
    $bad = @(Get-AdmErrorCatalog | Where-Object { -not $_.Title -or -not $_.Why -or -not @($_.Fix).Count -or -not $_.Signature })
    if ($bad.Count) { "     incomplete: $(($bad | ForEach-Object { $_.Code }) -join ', ')" }
    $bad.Count -eq 0
}
Check 'codes are unique'            {
    $all = @(Get-AdmErrorCatalog | ForEach-Object { $_.Code })
    $all.Count -eq (@($all | Select-Object -Unique).Count)
}
Check 'markdown renders a table and detail sections' {
    $md = Get-AdmErrorCatalog -AsMarkdown
    ($md -match '\| Code \| Severity \|') -and ($md -match '## `LDAP-BIND-52E`') -and ($md -match 'fires when:')
}

"== scanning =="
$pp = ConvertTo-SecureString 'scan-test-unlock' -AsPlainText -Force
Initialize-AdmStore -RecipientName t -Passphrase $pp -Iterations 100000 -Force -Confirm:$false | Out-Null
Unlock-AdmStore -Passphrase $pp | Out-Null

Check 'machine scan produces findings' { @(Invoke-AdmScan -Scope machine).Count -ge 4 }
Check 'every finding has the fields the UI and a script rely on' {
    $need = @('Id','Name','Scope','Target','Status','Detail','Problem','Impact','CanFix','FixDescription','Changes','NeedsAdmin')
    $bad = @()
    foreach ($f in @(Invoke-AdmScan -Scope machine)) {
        foreach ($n in $need) { if (-not $f.PSObject.Properties[$n]) { $bad += "$($f.Id).$n" } }
    }
    if ($bad.Count) { "     missing: $($bad -join ', ')" }
    $bad.Count -eq 0
}
Check 'ids are stable and prefixed' { @(Invoke-AdmScan -Scope machine | Where-Object { $_.Id -notmatch '^ADM-' }).Count -eq 0 }
Check 'status is always one of the four' {
    @(Invoke-AdmScan -Scope machine | Where-Object { $_.Status -notin @('pass','warn','fail','unknown') }).Count -eq 0
}
Check 'a passing finding carries no problem text' {
    @(Invoke-AdmScan -Scope machine | Where-Object { $_.Status -eq 'pass' -and $_.Problem }).Count -eq 0
}
Check 'a failing finding always explains itself' {
    @(Invoke-AdmScan -Scope machine | Where-Object { $_.Status -in @('fail','warn') -and (-not $_.Problem -or -not $_.Impact) }).Count -eq 0
}
Check 'scanning changes nothing (two runs agree)' {
    $a = @(Invoke-AdmScan -Scope machine | ForEach-Object { "$($_.Id)=$($_.Status)" }) -join ';'
    $b = @(Invoke-AdmScan -Scope machine | ForEach-Object { "$($_.Id)=$($_.Status)" }) -join ';'
    $a -eq $b
}
Check '-Problems hides the passing checks' {
    @(Invoke-AdmScan -Scope machine -Problems | Where-Object { $_.Status -eq 'pass' }).Count -eq 0
}
Check 'a locked store reports unknown, never pass' {
    Lock-AdmStore | Out-Null
    $f = @(Invoke-AdmScan -Scope domain)
    Unlock-AdmStore -Passphrase $pp | Out-Null
    @($f | Where-Object { $_.Status -eq 'unknown' }).Count -ge 1 -and @($f | Where-Object { $_.Status -eq 'pass' }).Count -eq 0
}

"== the repair loop =="
# A domain configured for an encrypted connection but pointed at an IP address: the single most
# common LDAPS mistake, and one the toolkit can fix without touching the network.
Register-AdmDomain -Name broken -DnsDomain broken.example.com -NetbiosName BROKEN `
    -DomainControllers '192.0.2.9' -UseSsl $true -Port 636 -Confirm:$false | Out-Null
$c = New-Object System.Management.Automation.PSCredential('BROKEN\svc', (ConvertTo-SecureString 'x' -AsPlainText -Force))
Set-AdmDomainCredential -Domain broken -Credential $c -Tier read -SetDefault -Confirm:$false | Out-Null

Check 'the SSL-by-IP mistake is detected' {
    $f = @(Invoke-AdmScan -Domain broken -Scope domain | Where-Object { $_.Id -eq 'ADM-DOM-008' })
    $f.Count -eq 1 -and $f[0].Status -eq 'fail' -and $f[0].CanFix -eq $true
}
Check 'the fix says what it will do BEFORE doing it' {
    $f = @(Invoke-AdmScan -Domain broken -Scope domain | Where-Object { $_.Id -eq 'ADM-DOM-008' })[0]
    $f.FixDescription -match 'port 389' -and $f.Changes -eq 'store' -and $f.NeedsAdmin -eq $false
}
Check '-WhatIf applies nothing' {
    $f = @(Invoke-AdmScan -Domain broken -Scope domain | Where-Object { $_.CanFix })
    $f | Invoke-AdmRepair -WhatIf | Out-Null
    (Get-AdmDomain -Name broken).UseSsl -eq $true      # unchanged
}
Check 'applying the fix actually changes the setting' {
    $f = @(Invoke-AdmScan -Domain broken -Scope domain | Where-Object { $_.Id -eq 'ADM-DOM-008' })
    $r = @($f | Invoke-AdmRepair -Yes)
    $r[0].Outcome -eq 'fixed' -and (Get-AdmDomain -Name broken).UseSsl -eq $false -and (Get-AdmDomain -Name broken).Port -eq 389
}
Check 'and the finding is gone on the next scan' {
    @(Invoke-AdmScan -Domain broken -Scope domain | Where-Object { $_.Id -eq 'ADM-DOM-008' -and $_.Status -eq 'fail' }).Count -eq 0
}
Check 'the repair is recorded in the log' {
    @(Get-AdmLog -Last 50 | Where-Object { $_.event -eq 'repair' }).Count -ge 1
}
Check 'a machine-changing fix is REFUSED without explicit consent' {
    # Synthesised rather than provoked: the real one is a clock resync, which needs a domain.
    $fake = [pscustomobject]@{
        Id = 'ADM-TEST-999'; Name = 'pretend machine fix'; Target = 'x'; Status = 'fail'
        Problem = 'p'; Impact = 'i'; CanFix = $true; FixDescription = 'd'
        Changes = 'machine'; NeedsAdmin = $false
        Apply = { param($ctx, $f) throw 'this must never run' }
        Context = $null; Data = $null; Scope = 'machine'; Detail = ''
    }
    $r = @($fake | Invoke-AdmRepair -Yes)
    $r[0].Outcome -eq 'skipped' -and $r[0].Detail -match 'AllowMachineChanges'
}
Check 'a fix that throws is reported, not swallowed' {
    $fake = [pscustomobject]@{
        Id = 'ADM-TEST-998'; Name = 'pretend broken fix'; Target = 'x'; Status = 'fail'
        Problem = 'p'; Impact = 'i'; CanFix = $true; FixDescription = 'd'
        Changes = 'store'; NeedsAdmin = $false
        Apply = { param($ctx, $f) throw 'the fix itself failed' }
        Context = $null; Data = $null; Scope = 'store'; Detail = ''
    }
    $r = @($fake | Invoke-AdmRepair -Yes)
    $r[0].Outcome -eq 'failed'
}
Check 'nothing that cannot be fixed is silently reported as fixed' {
    $r = @(Invoke-AdmScan -Scope machine | Invoke-AdmRepair -Yes)
    @($r | Where-Object { $_.Outcome -eq 'fixed' -and -not $_.Detail }).Count -eq 0
}

Remove-Item -LiteralPath $work -Recurse -Force -EA SilentlyContinue
if ($fail -gt 0) { "`nFAILURES: $fail"; exit 1 } else { "`nall scan checks passed"; exit 0 }
