$repo = Split-Path -Parent $PSScriptRoot   # run from any clone, USB or share
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$fail = 0
function Check($name, [scriptblock]$b) {
    try { if (& $b) { "  PASS  $name" } else { "  FAIL  $name"; $script:fail++ } }
    catch { "  FAIL  $name -- $($_.Exception.Message)"; $script:fail++ }
}

$work = Join-Path $env:TEMP ("admimp-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$env:ADADMIN_STORE      = Join-Path $work 'store.json'
$env:ADADMIN_LOG_DIR    = Join-Path $work 'logs'
$env:ADADMIN_SCRIPT_DIR = Join-Path $work 'scripts'
$env:ADADMIN_PROVIDER   = 'mock'

Import-Module (Join-Path $repo 'ADAdmin\ADAdmin.psd1') -Force

# A script that breaks most of the house rules on purpose. Single-quoted here-string so nothing
# is expanded while writing it.
$messy = @'
param(
    [string]$Root = "$PSScriptRoot\out",
    [string]$User
)
$server = "LDAP://dc01.corp.example.com"
$cred = ConvertTo-SecureString 'example-not-a-real-value' -AsPlainText -Force

$parent = Split-Path -LiteralPath $Root -Parent

gci $parent | ? { $_.Name -like '*.log' } | % { Write-Host $_.Name }

try {
    $u = Get-ADUser -Identity $User -Server "dc01.corp.example.com"
    Set-ADUser -Identity $User -Enabled $true
} catch {
}

if (-not $u) { throw "no such user" }
Write-Host "done"
'@
$messyPath = Join-Path $work 'Messy-Script.ps1'
[System.IO.File]::WriteAllText($messyPath, $messy, (New-Object System.Text.UTF8Encoding($false)))
$messyHashBefore = (Get-FileHash -LiteralPath $messyPath -Algorithm SHA256).Hash

"== the house rules find what is there =="
$f = @(Test-AdmScript -Path $messyPath)
function HasRule($id) { @($script:f | Where-Object { $_.Id -eq $id }).Count -ge 1 }

Check 'no [CmdletBinding()]        (IMP-001)' { HasRule 'ADM-IMP-001' }
Check 'empty catch block           (IMP-002)' { HasRule 'ADM-IMP-002' }
Check 'aliases gci / ? / %         (IMP-003)' { HasRule 'ADM-IMP-003' }
Check 'Split-Path -LiteralPath     (IMP-004)' { HasRule 'ADM-IMP-004' }
Check 'plaintext secret            (IMP-005)' { HasRule 'ADM-IMP-005' }
Check 'writes with no -WhatIf      (IMP-006)' { HasRule 'ADM-IMP-006' }
Check 'hard-coded domain           (IMP-007)' { HasRule 'ADM-IMP-007' }
Check 'RSAT AD cmdlets             (IMP-008)' { HasRule 'ADM-IMP-008' }
Check 'bare throw string           (IMP-009)' { HasRule 'ADM-IMP-009' }
Check 'Write-Host for data         (IMP-010)' { HasRule 'ADM-IMP-010' }
Check 'no strict mode              (IMP-011)' { HasRule 'ADM-IMP-011' }
Check '$PSScriptRoot in a default  (IMP-012)' { HasRule 'ADM-IMP-012' }
Check 'every finding explains itself' {
    @($f | Where-Object { -not $_.Problem -or -not $_.Impact -or -not $_.Fix }).Count -eq 0
}
Check 'findings carry a line number' { @($f | Where-Object { $_.Line -lt 1 }).Count -eq 0 }

"== an empty catch: oversight vs decision =="
# A rule that flags every empty catch is noise on real scripts, and a rule ignored three times
# gets ignored on the fourth. Two things mean "someone decided this".
$catches = @'
try { Get-Process -Name nothing-here } catch { }
try { Stop-Transcript | Out-Null } catch { }
try { Invoke-BpaModel -ModelId x } catch {
    # Continue with the other models.
}
'@
$catchPath = Join-Path $work 'Catches.ps1'
[System.IO.File]::WriteAllText($catchPath, $catches, (New-Object System.Text.UTF8Encoding($false)))
$cf = @(Test-AdmScript -Path $catchPath | Where-Object { $_.Id -eq 'ADM-IMP-002' })

Check 'a genuinely silent catch IS flagged'          { @($cf | Where-Object { $_.Line -eq 1 }).Count -eq 1 }
Check 'a cleanup-only catch is NOT flagged'          { @($cf | Where-Object { $_.Line -eq 2 }).Count -eq 0 }
Check 'a catch with an explaining comment is NOT flagged' { @($cf | Where-Object { $_.Line -eq 3 }).Count -eq 0 }
Check 'so exactly one of the three is reported'      { $cf.Count -eq 1 }

"== the toolkit's own cmdlets are not mistaken for RSAT or for writes =="
# `-AD[A-Z]` matches `-Adm` case-insensitively, so these rules used to flag every ADAdmin cmdlet
# -- claiming the toolkit that exists to avoid RSAT depended on RSAT.
$ownCmdlets = @'
[CmdletBinding()]
param([string]$Target)
$e = New-AdmDirectoryEntry -Domain $d -Credential $c
$u = Get-AdmUser -Target $Target
$p = Get-AdmRawProp $u 'samaccountname'
Close-AdmDirectoryEntry $e
'@
$ownPath = Join-Path $work 'OwnCmdlets.ps1'
[System.IO.File]::WriteAllText($ownPath, $ownCmdlets, (New-Object System.Text.UTF8Encoding($false)))
$of = @(Test-AdmScript -Path $ownPath)
Check 'Get-AdmUser is NOT reported as an RSAT dependency' { @($of | Where-Object { $_.Id -eq 'ADM-IMP-008' }).Count -eq 0 }
Check 'New-AdmDirectoryEntry is NOT reported as a write' { @($of | Where-Object { $_.Id -eq 'ADM-IMP-006' }).Count -eq 0 }
Check 'Set-StrictMode is NOT reported as a write' {
    $p3 = Join-Path $work 'StrictOnly.ps1'
    [System.IO.File]::WriteAllText($p3, "Set-StrictMode -Version 2.0`r`n`$x = New-Object psobject`r`n",
                                   (New-Object System.Text.UTF8Encoding($false)))
    @(Test-AdmScript -Path $p3 | Where-Object { $_.Id -eq 'ADM-IMP-006' }).Count -eq 0
}
Check 'but a REAL write still is' {
    $p4 = Join-Path $work 'RealWrite.ps1'
    [System.IO.File]::WriteAllText($p4, "Set-Service -Name spooler -Status Stopped`r`n",
                                   (New-Object System.Text.UTF8Encoding($false)))
    @(Test-AdmScript -Path $p4 | Where-Object { $_.Id -eq 'ADM-IMP-006' }).Count -ge 1
}
Check 'but a REAL RSAT cmdlet still is' {
    $p2 = Join-Path $work 'RealRsat.ps1'
    [System.IO.File]::WriteAllText($p2, "Get-ADUser -Identity bob`r`n", (New-Object System.Text.UTF8Encoding($false)))
    @(Test-AdmScript -Path $p2 | Where-Object { $_.Id -eq 'ADM-IMP-008' }).Count -ge 1
}

"== a clean script is left alone =="
$clean = @'
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][string]$Target)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
try {
    Get-AdmUser -Target $Target | Select-Object SamAccountName, Enabled
} catch {
    Write-AdmLog -ErrorRecord $_ -Operation 'list users'
    throw
}
'@
$cleanPath = Join-Path $work 'Clean-Script.ps1'
[System.IO.File]::WriteAllText($cleanPath, $clean, (New-Object System.Text.UTF8Encoding($false)))
Check 'a house-style script produces no errors' {
    @(Test-AdmScript -Path $cleanPath | Where-Object { $_.Severity -eq 'error' }).Count -eq 0
}

"== a script that does not parse is refused =="
$brokenPath = Join-Path $work 'Broken-Script.ps1'
[System.IO.File]::WriteAllText($brokenPath, "function {{{ oops", (New-Object System.Text.UTF8Encoding($false)))
Check 'a parse error is reported as one finding' {
    @(Test-AdmScript -Path $brokenPath | Where-Object { $_.Id -eq 'ADM-IMP-000' }).Count -ge 1
}
Check 'and nothing is installed for it' {
    $r = Import-AdmScript -Path $brokenPath -Name broken -Confirm:$false
    $r.Installed -eq $false -and -not (Test-Path (Join-Path $env:ADADMIN_SCRIPT_DIR 'broken.ps1'))
}

"== importing =="
$imp = Import-AdmScript -Path $messyPath -Name messy -Confirm:$false
Check 'reports installed'         { $imp.Installed -eq $true }
Check 'writes wrapper, body and manifest' {
    (Test-Path $imp.Path) -and (Test-Path $imp.BodyPath) -and (Test-Path $imp.MetaPath)
}
Check 'THE ORIGINAL IS NEVER MODIFIED' {
    (Get-FileHash -LiteralPath $messyPath -Algorithm SHA256).Hash -eq $messyHashBefore
}
Check 'automatic fixes were applied' { @($imp.Applied).Count -ge 3 }

$bodyText = [System.IO.File]::ReadAllText($imp.BodyPath)
Check 'aliases were expanded'     { ($bodyText -match 'Get-ChildItem') -and ($bodyText -match 'Where-Object') -and ($bodyText -match 'ForEach-Object') }
Check 'Split-Path was replaced'   { $bodyText -match 'GetDirectoryName' -and $bodyText -notmatch 'Split-Path -LiteralPath \$Root -Parent' }
Check 'the empty catch now logs'  { $bodyText -match 'Write-AdmLog -ErrorRecord' }
Check 'STRICT MODE IS NOT ADDED SILENTLY' {
    # It changes runtime behaviour, so it is reported and never applied. A script doing
    # `Where-Object { $_.DisplayName }` over sparse objects would start erroring on every one.
    ($bodyText -notmatch 'Set-StrictMode') -and
    (@(Test-AdmScript -Path $messyPath | Where-Object { $_.Id -eq 'ADM-IMP-011' }).Count -ge 1)
}
Check 'no file-level preamble is prepended' {
    # Edits are confined to the constructs a finding points at. IMP-001 legitimately inserts
    # [CmdletBinding()] immediately above the param block; nothing else may appear before the
    # author's first line of code.
    $firstReal = @($bodyText -split "\r?\n" | Where-Object { $_.Trim() -and $_ -notmatch '^\s*#' })[0]
    $firstReal -match '^\s*(\[CmdletBinding\(\)\]|param\()'
}
Check 'the body records where it came from' { $bodyText -match 'IMPORTED BY ADAdmin' -and $bodyText -match 'Hash   :' }

"== the rewrite must not break the script =="
Check 'THE CONVERTED BODY STILL PARSES' {
    $errs = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($imp.BodyPath, [ref]$null, [ref]$errs)
    if ($errs -and $errs.Count) { "     parse errors: $(($errs | ForEach-Object { $_.Message }) -join '; ')" }
    (-not $errs) -or $errs.Count -eq 0
}
Check 'the generated wrapper parses too' {
    $errs = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($imp.Path, [ref]$null, [ref]$errs)
    (-not $errs) -or $errs.Count -eq 0
}
Check 'the wrapper offers -Target and -WhatIf' {
    $w = [System.IO.File]::ReadAllText($imp.Path)
    ($w -match '\[string\]\$Target') -and ($w -match 'SupportsShouldProcess') -and ($w -match 'Invoke-AdmGuardedPublic')
}
Check 'the rewrite preserved the original logic' {
    # The imported body must still contain what the script actually did.
    ($bodyText -match 'Get-ADUser') -and ($bodyText -match 'Set-ADUser') -and ($bodyText -match '\$User')
}

"== listing and drift =="
Check 'the import is listed'      { @(Get-AdmScript -Name messy).Count -eq 1 }
Check 'counts are recorded'       { (Get-AdmScript -Name messy).Errors -ge 1 }
Check 'source reported as current'{ (Get-AdmScript -Name messy).SourceState -eq 'current' }
Check 'a changed source is NOTICED' {
    Add-Content -LiteralPath $messyPath -Value "`r`n# edited after import"
    (Get-AdmScript -Name messy).SourceState -eq 'SOURCE CHANGED'
}
Check 'a second import needs -Force' {
    $threw = $false
    try { Import-AdmScript -Path $messyPath -Name messy -Confirm:$false | Out-Null } catch { $threw = $true }
    $threw
}
Check 're-import with -Force succeeds and clears the drift' {
    Import-AdmScript -Path $messyPath -Name messy -Force -Confirm:$false | Out-Null
    (Get-AdmScript -Name messy).SourceState -eq 'current'
}

"== analyze-only writes nothing =="
Check '-AnalyzeOnly installs nothing' {
    $r = Import-AdmScript -Path $cleanPath -Name neverinstalled -AnalyzeOnly -Confirm:$false
    $r.Installed -eq $false -and -not (Test-Path (Join-Path $env:ADADMIN_SCRIPT_DIR 'neverinstalled.ps1'))
}

"== removal =="
Check 'remove takes all three files' {
    $r = Remove-AdmScript -Name messy -Confirm:$false
    $r.Files -eq 3 -and -not (Test-Path $imp.Path) -and -not (Test-Path $imp.BodyPath)
}
Check 'and leaves the original source alone' { Test-Path $messyPath }
Check 'removing something absent is a clear error' {
    $threw = $false
    try { Remove-AdmScript -Name nothere -Confirm:$false | Out-Null } catch { $threw = $true }
    $threw
}
Check 'the import was logged' { @(Get-AdmLog -Last 50 | Where-Object { $_.event -eq 'import' }).Count -ge 1 }

Remove-Item -LiteralPath $work -Recurse -Force -EA SilentlyContinue
if ($fail -gt 0) { "`nFAILURES: $fail"; exit 1 } else { "`nall import checks passed"; exit 0 }
