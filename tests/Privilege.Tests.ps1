$repo = Split-Path -Parent $PSScriptRoot   # run from any clone, USB or share
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# The logic behind Get-AdPrivilegedAccess, Find-StaleComputers and Invoke-AdmSweep, tested offline.
#
# ⛔ WHY NOT ALL AGAINST A REAL DOMAIN: the interesting cases are a hidden nesting chain, a
# duplicate SPN spanning two forests, and a forest that will not answer -- none of which a
# single healthy lab domain can produce on demand. The nesting walk WAS proven against a lab domain controller by
# building the chain and tearing it down (2026-08-27); what is pinned here is the scoring, which
# is what silently rots.

$fail = 0
function Check($name, [scriptblock]$b) {
    try { if (& $b) { "  PASS  $name" } else { "  FAIL  $name"; $script:fail++ } }
    catch { "  FAIL  $name -- $($_.Exception.Message)"; $script:fail++ }
}

$work = Join-Path $env:TEMP ("admpriv-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$env:ADADMIN_STORE    = Join-Path $work 'store.json'
$env:ADADMIN_LOG_DIR  = Join-Path $work 'logs'
$env:ADADMIN_PROVIDER = 'mock'

Import-Module (Join-Path $repo 'ADAdmin\ADAdmin.psd1') -Force

"== SID conversion, as a DIRECTORY actually returns it =="
# S-1-5-21-1-2-3-512, the domain's Domain Admins group.
$sidBytes = [byte[]]@(1,5,0,0,0,0,0,5,21,0,0,0,1,0,0,0,2,0,0,0,3,0,0,0,0,2,0,0)

Check 'a real byte[] converts' {
    (ConvertTo-AdmSidString -Raw $sidBytes) -eq 'S-1-5-21-1-2-3-512'
}
Check 'OBJECT[] OF BYTE converts -- the shape a search really returns' {
    # ⛔ THE REGRESSION THAT MATTERS. A DirectorySearcher property collection comes back as
    # System.Object[] whose elements are System.Byte, NOT as byte[]. Two call sites had written
    # `if ($Raw -is [byte[]])`, which is FALSE here, and fell through to [string]$Raw -- yielding
    # "1 5 0 0 0 ...". Find-AdDuplicates printed that where a SID belonged, and the privilege
    # audit built a filter from it, matched nothing, and reported Domain Admins as EMPTY.
    # A test that passes a real byte[] (the one above) passes while the live path is broken.
    $asObjectArray = [object[]]@($sidBytes | ForEach-Object { $_ })
    $asObjectArray.GetType().Name -eq 'Object[]' -and
    (ConvertTo-AdmSidString -Raw $asObjectArray) -eq 'S-1-5-21-1-2-3-512'
}
Check 'a string SID passes through' { (ConvertTo-AdmSidString -Raw 'S-1-5-32-544') -eq 'S-1-5-32-544' }
Check 'a non-SID string is rejected rather than echoed' { $null -eq (ConvertTo-AdmSidString -Raw 'not a sid') }
Check 'null is null, not an exception'                  { $null -eq (ConvertTo-AdmSidString -Raw $null) }
Check 'too few bytes is null, not a crash'              { $null -eq (ConvertTo-AdmSidString -Raw ([byte[]]@(1,2,3))) }

"== nesting severity: what hides privilege and what is just AD =="
# Mirrors the scoring in Get-AdPrivilegedAccess: a path is only a finding when an intermediate
# group is NOT itself Tier 0.
function Test-Hidden {
    param([string[]]$Intermediate, [hashtable]$Tier0Dns)
    @($Intermediate | Where-Object { -not $Tier0Dns.ContainsKey($_) }).Count -gt 0
}
$t0 = @{ 'CN=Domain Admins,DC=x' = 'Domain Admins'; 'CN=Enterprise Admins,DC=x' = 'Enterprise Admins' }

Check 'a DIRECT member is not nesting'      { -not (Test-Hidden @() $t0) }
Check "AD's own Administrators -> Domain Admins is NOT a finding" {
    # Every domain that has ever existed nests these. Scoring it critical buries the real ones.
    -not (Test-Hidden @('CN=Domain Admins,DC=x') $t0)
}
Check 'nesting through an ORDINARY group IS a finding' {
    Test-Hidden @('CN=Helpdesk,DC=x') $t0
}
Check 'a mixed chain is a finding if ANY link is ordinary' {
    Test-Hidden @('CN=Domain Admins,DC=x', 'CN=Tier0-Ops,DC=x') $t0
}

"== cycle safety =="
Check 'a membership cycle terminates' {
    # AD permits A -> B -> A. A naive walk never returns; the audit keeps a seen-set.
    $graph = @{ A = @('B'); B = @('C'); C = @('A') }
    # A hashtable, not an int: `$script:visited++` from inside a nested function reaches SCRIPT
    # scope, where a variable assigned inside this scriptblock does not exist. The hashtable is
    # mutated by reference, so the count survives the scope hop.
    $state = @{ Seen = @{}; Visited = 0 }
    function Walk($n) {
        if ($state.Seen.ContainsKey($n)) { return }
        $state.Seen[$n] = $true; $state.Visited++
        foreach ($m in $graph[$n]) { Walk $m }
    }
    Walk 'A'
    $state.Visited -eq 3
}

"== stale computers: selection =="
$now = [datetime]::UtcNow
function Test-Stale {
    param($Row, [int]$Threshold, [string]$By)
    if ($Row.NeverContacted) { return ($null -ne $Row.AgeDays -and $Row.AgeDays -ge $Threshold) }
    switch ($By) {
        'PasswordLastSet' { $null -ne $Row.PasswordAgeDays  -and $Row.PasswordAgeDays  -ge $Threshold }
        'LastLogon'       { $null -ne $Row.LastLogonAgeDays -and $Row.LastLogonAgeDays -ge $Threshold }
        'Either'          {
            $p = if ($null -ne $Row.PasswordAgeDays)  { $Row.PasswordAgeDays }  else { [double]::MaxValue }
            $l = if ($null -ne $Row.LastLogonAgeDays) { $Row.LastLogonAgeDays } else { [double]::MaxValue }
            [math]::Min($p, $l) -ge $Threshold
        }
    }
}
function Row { param($Pw, $Logon, $Age, [switch]$Never)
    [pscustomobject]@{ PasswordAgeDays = $Pw; LastLogonAgeDays = $Logon; AgeDays = $Age; NeverContacted = [bool]$Never } }

Check 'an old machine password selects the machine'      { Test-Stale (Row 200 200 400) 180 'PasswordLastSet' }
Check 'a fresh machine password does not'                { -not (Test-Stale (Row 12 200 400) 180 'PasswordLastSet') }
Check 'A FRESH PASSWORD BEATS A STALE LAST-LOGON' {
    # The whole reason PasswordLastSet is the default. lastLogonTimestamp replicates lazily and
    # can be ~14 days behind; the machine password rotates every 30 days and replicates normally.
    # This machine is alive, and judging it on last logon alone would disable it.
    -not (Test-Stale (Row 5 200 400) 180 'PasswordLastSet')
}
Check "'Either' needs BOTH signals stale"                { -not (Test-Stale (Row 5 900 900) 180 'Either') }
Check "'Either' selects when both are stale"             { Test-Stale (Row 900 900 900) 180 'Either' }
Check 'a never-contacted NEW object is not stale' {
    # Pre-staged this morning. Judging it on age is the only evidence there is, and it is young.
    -not (Test-Stale (Row $null $null 2 -Never) 180 'PasswordLastSet')
}
Check 'a never-contacted OLD object is stale'            { Test-Stale (Row $null $null 900 -Never) 180 'PasswordLastSet' }
Check 'a machine with no readable dates is never selected' {
    -not (Test-Stale (Row $null $null $null) 180 'PasswordLastSet')
}

"== domain controllers are excluded, unconditionally =="
$fleet = @(
    [pscustomobject]@{ Name = 'DC01';   IsDomainController = $true;  PasswordAgeDays = 900 }
    [pscustomobject]@{ Name = 'OLDPC';  IsDomainController = $false; PasswordAgeDays = 900 }
)
Check 'a DC is filtered out before anything else' {
    $kept = @($fleet | Where-Object { -not $_.IsDomainController })
    $kept.Count -eq 1 -and $kept[0].Name -eq 'OLDPC'
}
Check 'Set-AdmComputerEnabled REFUSES to disable a domain controller' {
    # The guard lives in the module, not in the calling script, so it holds for any caller.
    $pp = ConvertTo-SecureString 'priv-test-unlock' -AsPlainText -Force
    Initialize-AdmStore -RecipientName t -Passphrase $pp -Iterations 100000 -Force -Confirm:$false | Out-Null
    Unlock-AdmStore -Passphrase $pp | Out-Null
    Register-AdmDomain -Name corp -DnsDomain 'corp.example.com' -NetbiosName CORP -Confirm:$false | Out-Null
    $c = New-Object System.Management.Automation.PSCredential('CORP\svc', (ConvertTo-SecureString 'x' -AsPlainText -Force))
    Set-AdmDomainCredential -Domain corp -Credential $c -Tier read  -SetDefault -Confirm:$false | Out-Null
    Set-AdmDomainCredential -Domain corp -Credential $c -Tier write -Confirm:$false | Out-Null

    $refused = $false
    try { Set-AdmComputerEnabled -Target 'corp.example.com' -Identity 'DC01' -Enabled $false -Confirm:$false | Out-Null }
    catch { $refused = $_.Exception.Message -match 'DOMAIN CONTROLLER' }
    $refused
}
Check 'but a member server CAN be disabled and re-enabled' {
    $r = Set-AdmComputerEnabled -Target 'corp.example.com' -Identity 'WS1' -Enabled $false -Confirm:$false
    $ok = ($r.Enabled -eq $false)
    $r2 = Set-AdmComputerEnabled -Target 'corp.example.com' -Identity 'WS1' -Enabled $true -Confirm:$false
    $ok -and $r2.Enabled -eq $true
}
Check 'the refusal is a CATALOGUED failure, not a bare throw' {
    (Get-AdmErrorCatalog -Code 'DC-DISABLE-REFUSED').Title -match 'domain controller'
}
Check 'Get-AdmComputer -Identity works on the mock provider' {
    # Regression: this threw "The property 'samAccountName' cannot be found on this object",
    # because computer fixture entries have no samAccountName and StrictMode rejects the read.
    @(Get-AdmComputer -Target 'corp.example.com' -Identity 'WS1').Count -eq 1
}
Check 'the mock provider returns the SAME SHAPE as a real search' {
    # A narrower mock object fails only on the mock path, which is exactly backwards.
    $c = @(Get-AdmComputer -Target 'corp.example.com')[0]
    $need = @('IsDomainController', 'PasswordLastSet', 'LastLogonTimestamp', 'OperatingSystemVersion', 'WhenCreated')
    @($need | Where-Object { -not $c.PSObject.Properties[$_] }).Count -eq 0
}

"== sweep: a domain that could not answer is FAILED, not clean =="
# The house exit-code contract: 0 = clean, 10 = found something, anything else = did not complete.
function Test-SweepOutcome { param([int]$Code) if ($Code -ne 0 -and $Code -ne 10) { 'FAILED' } else { 'ok' } }

Check 'exit 0 is ok'                              { (Test-SweepOutcome 0)  -eq 'ok' }
Check 'exit 10 (found something) is ok'           { (Test-SweepOutcome 10) -eq 'ok' }
Check 'EXIT 30 IS FAILED, NOT CLEAN' {
    # ⛔ The bug this pins. The house scripts DIAGNOSE their own failures instead of throwing --
    # an unreachable DC is recorded as unchecked and the script exits 30 -- so nothing reaches
    # the sweep's catch block, and two dead forests were reported as healthy domains that simply
    # found nothing. Measured 2026-08-27 against a domain pointed at an address with no DC.
    (Test-SweepOutcome 30) -eq 'FAILED'
}
Check 'exit 20 is FAILED'                         { (Test-SweepOutcome 20) -eq 'FAILED' }
Check 'exit 1 is FAILED'                          { (Test-SweepOutcome 1)  -eq 'FAILED' }

"== sweep: cross-domain collisions =="
# Mirrors the global grouping in Invoke-AdmSweep -CrossDomain.
function Group-CrossDomain {
    param($Holders)   # hashtable: value -> @("domain\account", ...)
    $out = @()
    foreach ($k in $Holders.Keys) {
        $h = @($Holders[$k] | Select-Object -Unique)
        if ($h.Count -lt 2) { continue }
        $doms = @($h | ForEach-Object { ($_ -split '\\')[0] } | Select-Object -Unique)
        $out += [pscustomobject]@{ Value = $k; Domains = $doms; Holders = $h; CrossDomain = ($doms.Count -gt 1) }
    }
    $out
}

Check 'a collision spanning TWO forests is found' {
    # ⭐ The case no single-domain scan can reach: a DC enforces SPN uniqueness only within its
    # own domain, so neither of these could have refused it.
    $r = @(Group-CrossDomain @{ 'mssqlsvc/db1:1433' = @('corp\svc-a', 'plant\svc-b') })
    $r.Count -eq 1 -and $r[0].CrossDomain -and $r[0].Domains.Count -eq 2
}
Check 'a collision inside ONE domain is labelled differently' {
    $r = @(Group-CrossDomain @{ 'host/x' = @('corp\a', 'corp\b') })
    $r.Count -eq 1 -and -not $r[0].CrossDomain
}
Check 'one holder is not a collision'          { @(Group-CrossDomain @{ 'host/x' = @('corp\a') }).Count -eq 0 }
Check 'the SAME account counted twice is not a collision' {
    # Re-running a sweep, or an account appearing under two SPN reads, must not invent a finding.
    @(Group-CrossDomain @{ 'host/x' = @('corp\a', 'corp\a') }).Count -eq 0
}
Check 'nothing collides in a clean estate' {
    @(Group-CrossDomain @{ 'host/a' = @('corp\a'); 'host/b' = @('plant\b') }).Count -eq 0
}

"== the scripts are well-formed =="
foreach ($s in @('Get-AdPrivilegedAccess', 'Find-StaleComputers', 'Invoke-AdmSweep')) {
    Check "$s.ps1 parses" {
        $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $repo "scripts\$s.ps1"), [ref]$null, [ref]$errs)
        (-not $errs) -or $errs.Count -eq 0
    }
}
Check 'the privilege audit has NO write path' {
    # It is read-only by design: every finding is a decision about who should have access, and
    # that is not a decision a script gets to make. Guard against a future edit adding one.
    $src = Get-Content (Join-Path $repo 'scripts\Get-AdPrivilegedAccess.ps1') -Raw
    -not ($src -match '\bCommitChanges\b|\bSet-AdmUserEnabled\b|\bSet-AdmComputerEnabled\b|\bRemove-AdmGroupMember\b')
}

Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
if ($fail -gt 0) { "`nFAILURES: $fail"; exit 1 } else { "`nall privilege/sweep checks passed"; exit 0 }
