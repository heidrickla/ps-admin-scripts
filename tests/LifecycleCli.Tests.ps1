# LifecycleCli.Tests.ps1 -- the adm.ps1 verbs for object lifecycle, groups, help-desk retrieval
# and forest shape, driven end to end against the mock provider.
#
# Separate from Lifecycle.Tests.ps1 because that one is pure functions with no store and no
# subprocess; this one spawns adm.ps1 per check and is correspondingly slower. Separate from
# CliGui.Tests.ps1 to keep the two files small.
#
# ⭐ WHAT THIS CATCHES THAT A UNIT TEST CANNOT: the wiring. A verb whose parameter name does not
# match the cmdlet's, or a switch spelled differently in the dispatch than in the help, fails only
# when someone types it. Two such bugs were found this way on first run.

$repo = Split-Path -Parent $PSScriptRoot
$ErrorActionPreference = 'Continue'
Set-StrictMode -Version 2.0
$fail = 0
$adm = (Join-Path $repo 'adm.ps1')
$ps  = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

$work = Join-Path $env:TEMP ("admlc-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$env:ADADMIN_STORE      = Join-Path $work 'adadmin-store.json'
$env:ADADMIN_PASSPHRASE = 'lifecycle-cli-zzz'
$env:ADADMIN_PROVIDER   = 'mock'
$env:ADADMIN_LOG_DIR    = Join-Path $work 'logs'

function Run { param([string[]]$A)
    $out = & $ps -NoProfile -ExecutionPolicy Bypass -File $adm @A 2>&1 | Out-String
    [pscustomobject]@{ Out = $out.Trim(); Code = $LASTEXITCODE }
}
function Check($name, [scriptblock]$b) {
    try { if (& $b) { "  PASS  $name" } else { "  FAIL  $name"; $script:fail++ } }
    catch { "  FAIL  $name -- $($_.Exception.Message)"; $script:fail++ }
}
# Parse the JSON envelope, or fail loudly with what actually came back. A verb that errored prints
# a diagnosis rather than JSON, and "ConvertFrom-Json: invalid" hides which verb broke.
#
# ⚠ THE ENVELOPE IS THE LAST LINE, NOT THE WHOLE OF STDOUT. With -WhatIf, PowerShell writes its
# own "What if: Performing the operation ..." narration to stdout before we print anything, and
# that line is written DIRECTLY TO THE HOST -- measured 2026-08-28, none of 2> 4> 5> 6> nor
# $WhatIfPreference suppress or capture it. So a script has to take the last line beginning with
# '{', and so does this harness.
function Json { param([string[]]$A)
    $r = Run $A
    $line = @($r.Out -split "`r?`n" | Where-Object { $_.TrimStart().StartsWith('{') }) | Select-Object -Last 1
    if (-not $line) { throw "no JSON envelope (exit $($r.Code)): $($r.Out -replace '\s+', ' ')" }
    try { $line | ConvertFrom-Json }
    catch { throw "not JSON (exit $($r.Code)): $($line -replace '\s+', ' ')" }
}

"== setup =="
Check 'store init'    { (Run @('store', 'init', '-Name', 'tester', '-NonInteractive')).Code -eq 0 }
Check 'domain add'    { (Run @('domain', 'add', '-Name', 'corp', '-Dns', 'corp.example.com', '-Netbios', 'CORP', '-Dc', 'dc01.corp.example.com', '-NonInteractive')).Code -eq 0 }
Check 'set-cred'      {
    $env:ADADMIN_CRED_PASSWORD = 'not-a-real-one'
    (Run @('domain', 'set-cred', '-Name', 'corp', '-Tier', 'write', '-User', 'CORP\svc', '-Default', '-NonInteractive')).Code -eq 0
}

"== help mentions the new verbs =="
# The help is the discovery surface for both a human and a script; a verb missing from it is
# effectively undocumented even though it works.
$help = (Run @('help')).Out
foreach ($v in @('adm user set', 'adm group members', 'adm ou list', 'adm object move',
                 'adm laps get', 'adm bitlocker get', 'adm trust list', 'adm site list', 'adm gpo list')) {
    Check "help lists '$v'" { $help -match [regex]::Escape($v) }
}

"== ou =="
Check 'ou list returns the fixture OUs' {
    $j = Json @('ou', 'list', '-Target', 'corp.example.com', '-Json')
    $j.ok -eq $true -and @($j.data).Count -ge 5
}
Check 'ou list -Identity filters' {
    $j = Json @('ou', 'list', '-Target', 'corp.example.com', '-Identity', 'Staff', '-Json')
    @($j.data).Count -ge 1 -and (@($j.data)[0].Name -eq 'Staff')
}
# ⛔ A DN is the unambiguous key and every other cmdlet takes one. Matched as a substring of a
# NAME it can never hit, and the result is zero rows rather than an error -- which reads as "no
# such OU" and, for a protection lookup, as "not protected".
Check 'ou list -Identity accepts a full distinguished name' {
    $j = Json @('ou', 'list', '-Target', 'corp.example.com', '-Identity', 'OU=Staff,DC=corp,DC=example,DC=com', '-Json')
    @($j.data).Count -eq 1 -and (@($j.data)[0].Name -eq 'Staff')
}
Check 'ou list -Identity by DN and by name agree' {
    $byName = Json @('ou', 'list', '-Target', 'corp.example.com', '-Identity', 'Staff', '-Json')
    $byDn   = Json @('ou', 'list', '-Target', 'corp.example.com', '-Identity', 'OU=Staff,DC=corp,DC=example,DC=com', '-Json')
    (@($byName.data)[0].DistinguishedName) -eq (@($byDn.data)[0].DistinguishedName)
}
Check 'ou list carries ParentDn for the tree' {
    $j = Json @('ou', 'list', '-Target', 'corp.example.com', '-Json')
    $row = @($j.data)[0]
    ($row.PSObject.Properties.Name -contains 'ParentDn') -and ($row.PSObject.Properties.Name -contains 'DistinguishedName')
}
Check 'ou new -WhatIf changes nothing and exits 0' {
    (Run @('ou', 'new', '-Target', 'corp.example.com', '-Name', 'Temp1', '-WhatIf', '-Yes', '-NonInteractive')).Code -eq 0
}

"== groups =="
Check 'group members lists the fixture group' {
    $j = Json @('group', 'members', '-Target', 'corp.example.com', '-Identity', 'Helpdesk', '-Json')
    $j.ok -eq $true -and @($j.data).Count -eq 2
}
Check 'group members rows carry Via and Foreign' {
    $j = Json @('group', 'members', '-Target', 'corp.example.com', '-Identity', 'Helpdesk', '-Json')
    $row = @($j.data)[0]
    ($row.PSObject.Properties.Name -contains 'Via') -and ($row.PSObject.Properties.Name -contains 'Foreign')
}
Check 'group new -WhatIf exits 0' {
    (Run @('group', 'new', '-Target', 'corp.example.com', '-Name', 'Test-RW', '-Scope', 'DomainLocal', '-WhatIf', '-Yes', '-NonInteractive')).Code -eq 0
}
Check 'group new rejects a bad scope' {
    # ValidateSet lives on the cmdlet; the CLI must not swallow the refusal into a success.
    (Run @('group', 'new', '-Target', 'corp.example.com', '-Name', 'X', '-Scope', 'Nonsense', '-Yes', '-NonInteractive')).Code -ne 0
}

"== user set =="
Check 'user set writes an attribute' {
    $j = Json @('user', 'set', '-Target', 'corp.example.com', '-Identity', 'jsmith', '-Title', 'Engineer', '-Yes', '-NonInteractive', '-Json')
    $j.ok -eq $true -and (@($j.data.Changed) -contains 'title')
}
Check 'user set maps several attributes at once' {
    $j = Json @('user', 'set', '-Target', 'corp.example.com', '-Identity', 'jsmith', '-Title', 'Eng', '-Department', 'Platform', '-Yes', '-NonInteractive', '-Json')
    (@($j.data.Changed) -contains 'title') -and (@($j.data.Changed) -contains 'department')
}
Check 'a valueless option means CLEAR, not the string True' {
    # -office with no value is how the CLI spells "clear this attribute". If it bound as the
    # boolean $true it would write the literal text "True" into the directory.
    $j = Json @('user', 'set', '-Target', 'corp.example.com', '-Identity', 'jsmith', '-Office', '-Yes', '-NonInteractive', '-Json')
    @($j.data.Changed) -contains 'physicalDeliveryOfficeName'
}
Check 'user set with no attributes is refused' {
    (Run @('user', 'set', '-Target', 'corp.example.com', '-Identity', 'jsmith', '-Yes', '-NonInteractive')).Code -ne 0
}

"== help desk and forest shape (mock returns empty, but the verbs must WIRE) =="
Check 'laps get reaches the cmdlet' {
    $j = Json @('laps', 'get', '-Target', 'corp.example.com', '-Identity', 'WS1', '-Json')
    $j.ok -eq $true -and $j.data.Status -eq 'NotDeployed'
}
Check 'laps get on an unknown machine fails, not silently empty' {
    (Run @('laps', 'get', '-Target', 'corp.example.com', '-Identity', 'NOPE', '-Json')).Code -ne 0
}
Check 'bitlocker get reaches the cmdlet' { (Run @('bitlocker', 'get', '-Target', 'corp.example.com', '-Identity', 'WS1', '-Json')).Code -eq 0 }
Check 'trust list reaches the cmdlet'    { (Json @('trust', 'list', '-Target', 'corp.example.com', '-Json')).ok -eq $true }
Check 'site list reaches the cmdlet'     { (Json @('site',  'list', '-Target', 'corp.example.com', '-Json')).ok -eq $true }
Check 'subnet list reaches the cmdlet'   { (Json @('subnet', 'list', '-Target', 'corp.example.com', '-Json')).ok -eq $true }
Check 'subnet list -Orphaned reaches it' { (Json @('subnet', 'list', '-Target', 'corp.example.com', '-Orphaned', '-Json')).ok -eq $true }
Check 'gpo list reaches the cmdlet'      { (Json @('gpo',   'list', '-Target', 'corp.example.com', '-Json')).ok -eq $true }
Check 'gpo list -Unlinked reaches it'    { (Json @('gpo',   'list', '-Target', 'corp.example.com', '-Unlinked', '-Json')).ok -eq $true }

"== bulk CSV import =="
# A file with one good row, one duplicate, one over the 20-character sAMAccountName limit, and
# one that already exists in the fixture. Every one of those must be caught BEFORE anything is
# written, and reported against its own row.
$csv = Join-Path $work 'joiners.csv'
@(
    'SamAccountName,DisplayName,Title,Department'
    'newuser1,New User One,Engineer,Platform'
    'newuser2,New User Two,Analyst,Finance'
    'newuser1,Duplicate Row,Engineer,Platform'
    'this-name-is-far-too-long,Too Long,Engineer,Platform'
    'jsmith,Already Exists,Engineer,Platform'
) | Set-Content -LiteralPath $csv -Encoding ASCII

Check '-WhatIf returns a plan and writes nothing' {
    $j = Json @('user', 'import', '-Target', 'corp.example.com', '-Path', $csv, '-WhatIf', '-Yes', '-NonInteractive', '-Json')
    @($j.data).Count -eq 5 -and (@($j.data) | Where-Object { $_.Status -eq 'would-run' }).Count -eq 5
}
Check 'the duplicate row is caught' {
    $j = Json @('user', 'import', '-Target', 'corp.example.com', '-Path', $csv, '-WhatIf', '-Yes', '-NonInteractive', '-Json')
    @($j.data | Where-Object { $_.Row -eq 4 -and $_.Reason -match 'duplicate' }).Count -eq 1
}
Check 'the over-long SamAccountName is caught' {
    $j = Json @('user', 'import', '-Target', 'corp.example.com', '-Path', $csv, '-WhatIf', '-Yes', '-NonInteractive', '-Json')
    @($j.data | Where-Object { $_.Row -eq 5 -and $_.Reason -match 'limit is 20' }).Count -eq 1
}
Check 'an existing account is refused in Create mode' {
    $j = Json @('user', 'import', '-Target', 'corp.example.com', '-Path', $csv, '-WhatIf', '-Yes', '-NonInteractive', '-Json')
    @($j.data | Where-Object { $_.Row -eq 6 -and $_.Reason -match 'already exists' }).Count -eq 1
}
Check '-StopOnError refuses the whole run' {
    # Nothing may be written when any row is bad and the caller asked for all-or-nothing.
    (Run @('user', 'import', '-Target', 'corp.example.com', '-Path', $csv, '-StopOnError', '-Yes', '-NonInteractive')).Code -ne 0
}
Check 'applying reports every row, good and bad' {
    $j = Json @('user', 'import', '-Target', 'corp.example.com', '-Path', $csv, '-Yes', '-NonInteractive', '-Json')
    $d = @($j.data)
    # 2 created, 3 skipped -- and the skipped ones must NOT be reported as ok.
    $d.Count -eq 5 -and
    (@($d | Where-Object { $_.Status -eq 'ok' }).Count -eq 2) -and
    (@($d | Where-Object { $_.Status -eq 'skipped' }).Count -eq 3)
}
Check 'a generated password is returned exactly once, for created rows only' {
    $j = Json @('user', 'import', '-Target', 'corp.example.com', '-Path', $csv, '-Yes', '-NonInteractive', '-Json')
    $withPw = @($j.data | Where-Object { $_.Password })
    $withPw.Count -eq 2 -and (@($withPw | Where-Object { $_.Status -ne 'ok' }).Count -eq 0)
}
Check 'a misspelled column is reported, not silently dropped' {
    $bad = Join-Path $work 'typo.csv'
    @('SamAccountName,Titel', 'newuser9,Engineer') | Set-Content -LiteralPath $bad -Encoding ASCII
    $j = Json @('user', 'import', '-Target', 'corp.example.com', '-Path', $bad, '-WhatIf', '-Yes', '-NonInteractive', '-Json')
    @(@($j.data)[0].UnknownColumns) -contains 'Titel'
}
Check 'a file with no SamAccountName column is refused' {
    $bad = Join-Path $work 'nosam.csv'
    @('Name,Title', 'someone,Engineer') | Set-Content -LiteralPath $bad -Encoding ASCII
    (Run @('user', 'import', '-Target', 'corp.example.com', '-Path', $bad, '-Yes', '-NonInteractive')).Code -ne 0
}
Check 'a missing file is refused' {
    (Run @('user', 'import', '-Target', 'corp.example.com', '-Path', (Join-Path $work 'nope.csv'), '-Yes', '-NonInteractive')).Code -ne 0
}
Check 'help lists the import verb' { $help -match [regex]::Escape('adm user import') }
Check 'the plan carries a resolved TargetDn for every row' {
    $j = Json @('user', 'import', '-Target', 'corp.example.com', '-Path', $csv, '-WhatIf', '-Yes', '-NonInteractive', '-Json')
    @(@($j.data) | Where-Object { $_.TargetDn }).Count -eq 5
}
Check 'a create row resolves into the default container' {
    $j = Json @('user', 'import', '-Target', 'corp.example.com', '-Path', $csv, '-WhatIf', '-Yes', '-NonInteractive', '-Json')
    (@($j.data) | Where-Object { $_.Row -eq 2 }).TargetDn -match '^CN=newuser1,CN=Users,DC=corp'
}
Check '-DefaultPath moves where creates land, visibly, before applying' {
    $j = Json @('user', 'import', '-Target', 'corp.example.com', '-Path', $csv, '-DefaultPath', 'OU=Staff,DC=corp,DC=example,DC=com', '-WhatIf', '-Yes', '-NonInteractive', '-Json')
    (@($j.data) | Where-Object { $_.Row -eq 2 }).TargetDn -match 'OU=Staff'
}
Check 'the plan reports per-attribute changes for a create' {
    $j = Json @('user', 'import', '-Target', 'corp.example.com', '-Path', $csv, '-WhatIf', '-Yes', '-NonInteractive', '-Json')
    $row = @($j.data) | Where-Object { $_.Row -eq 2 }
    $row.ChangeCount -ge 2 -and (@($row.Changes | ForEach-Object { $_.Attribute }) -contains 'Title')
}
Check 'a row whose values already match is no-change, not update' {
    # Update mode against the fixture's jsmith, feeding back the value already set by an earlier
    # check in this suite. An "update" that changes nothing should say so.
    $same = Join-Path $work 'same.csv'
    @('SamAccountName,Title', 'jsmith,Eng') | Set-Content -LiteralPath $same -Encoding ASCII
    $j = Json @('user', 'import', '-Target', 'corp.example.com', '-Path', $same, '-Mode', 'Update', '-WhatIf', '-Yes', '-NonInteractive', '-Json')
    $a = (@($j.data)[0]).Action
    $a -eq 'no-change' -or $a -eq 'update'   # either is defensible; 'create' or 'skip' is not
}
Check '-RollbackPath writes a manifest of what was applied' {
    $roll = Join-Path $work 'undo.csv'
    $fresh = Join-Path $work 'fresh.csv'
    @('SamAccountName,Title', 'rollme1,Engineer', 'rollme2,Analyst') | Set-Content -LiteralPath $fresh -Encoding ASCII
    $null = Run @('user', 'import', '-Target', 'corp.example.com', '-Path', $fresh, '-RollbackPath', $roll, '-Yes', '-NonInteractive', '-Json')
    if (-not (Test-Path -LiteralPath $roll)) { return $false }
    $u = @(Import-Csv -LiteralPath $roll)
    # Two creates -> two delete rows, each carrying the DN needed to undo it.
    $u.Count -eq 2 -and (@($u | Where-Object { $_.Action -eq 'delete' -and $_.TargetDn }).Count -eq 2)
}
Check 'the manifest excludes rows that did not apply' {
    $roll = Join-Path $work 'undo2.csv'
    $null = Run @('user', 'import', '-Target', 'corp.example.com', '-Path', $csv, '-RollbackPath', $roll, '-Yes', '-NonInteractive', '-Json')
    $u = @(Import-Csv -LiteralPath $roll)
    # 5 rows in, only 2 applied. A manifest naming the skipped ones would send someone deleting
    # accounts that were never created.
    $u.Count -eq 2
}
# ⛔ THE -Json CONTRACT UNDER -WhatIf. PowerShell's WhatIf narration lands on STDOUT ahead of the
# envelope and cannot be redirected, so the guarantee this CLI can actually make is "the envelope
# is the last line". Assert that, or a script parsing the whole of stdout breaks silently the
# first time someone previews a change.
Check 'the JSON envelope is the LAST line under -WhatIf' {
    $r = Run @('user', 'import', '-Target', 'corp.example.com', '-Path', $csv, '-WhatIf', '-Yes', '-NonInteractive', '-Json')
    $lines = @($r.Out -split "`r?`n" | Where-Object { $_.Trim() })
    $last = $lines[-1].Trim()
    $last.StartsWith('{') -and $last.EndsWith('}') -and (($last | ConvertFrom-Json).ok -eq $true)
}
Check 'stdout under -WhatIf is NOT parseable as a whole (documents the limit)' {
    # Not a wish -- a measured fact, asserted so nobody "fixes" the help text back.
    $r = Run @('user', 'import', '-Target', 'corp.example.com', '-Path', $csv, '-WhatIf', '-Yes', '-NonInteractive', '-Json')
    $whole = $true
    try { $null = $r.Out | ConvertFrom-Json } catch { $whole = $false }
    -not $whole
}

"== object verbs =="
Check 'object move -WhatIf exits 0' {
    (Run @('object', 'move', '-Target', 'corp.example.com', '-Identity', 'jsmith', '-To', 'OU=Staff,DC=corp,DC=example,DC=com', '-WhatIf', '-Yes', '-NonInteractive')).Code -eq 0
}
Check 'object move without -To is a usage error' {
    (Run @('object', 'move', '-Target', 'corp.example.com', '-Identity', 'jsmith', '-Yes', '-NonInteractive')).Code -ne 0
}
Check 'object rename -WhatIf exits 0' {
    (Run @('object', 'rename', '-Target', 'corp.example.com', '-Identity', 'jsmith', '-NewName', 'Jo Brown', '-WhatIf', '-Yes', '-NonInteractive')).Code -eq 0
}
Check 'object set parses name=value pairs' {
    $j = Json @('object', 'set', '-Target', 'corp.example.com', '-Identity', 'jsmith', '-Attr', 'description=hello,title=Eng', '-Yes', '-NonInteractive', '-Json')
    (@($j.data.Changed) -contains 'description') -and (@($j.data.Changed) -contains 'title')
}
Check 'unknown sub-verb is exit 2' { (Run @('ou', 'bogus', '-Target', 'corp.example.com')).Code -eq 2 }

# Leave nothing behind; a store and a log directory per run would accumulate.
Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue

if ($fail -gt 0) { "`nFAILURES: $fail"; exit 1 } else { "`nall lifecycle CLI checks passed"; exit 0 }
