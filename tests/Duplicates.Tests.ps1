$repo = Split-Path -Parent $PSScriptRoot   # run from any clone, USB or share
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# The duplicate-detection LOGIC, tested offline.
#
# ⛔ WHY NOT AGAINST A REAL DOMAIN: a modern DC refuses to create a duplicate SPN at all
# ("A constraint violation occurred"), so the case this code exists to find CANNOT be staged in a
# healthy single domain. The real duplicates come from cross-domain collisions and replication,
# neither of which a one-DC lab can produce. So the grouping is exercised directly, against the
# same shapes a search returns.

$fail = 0
function Check($name, [scriptblock]$b) {
    try { if (& $b) { "  PASS  $name" } else { "  FAIL  $name"; $script:fail++ } }
    catch { "  FAIL  $name -- $($_.Exception.Message)"; $script:fail++ }
}

# Mirrors the grouping in Find-AdDuplicates.ps1: case-insensitive, one row per SPN with >1 holder.
function Group-Spn {
    param($Objects)
    $bySpn = @{}
    foreach ($o in $Objects) {
        foreach ($spn in @($o.spns)) {
            if (-not $spn) { continue }
            $k = ([string]$spn).ToLowerInvariant()
            if (-not $bySpn.ContainsKey($k)) { $bySpn[$k] = @() }
            $bySpn[$k] += $o.sam
        }
    }
    $out = @()
    foreach ($k in $bySpn.Keys) {
        $holders = @($bySpn[$k] | Select-Object -Unique)
        if ($holders.Count -ge 2) { $out += [pscustomobject]@{ Spn = $k; Holders = $holders } }
    }
    # Emit, do NOT comma-wrap. `,@($out)` makes @(Group-Spn ...) return 1 for an EMPTY result --
    # the fifth time this exact trap has bitten in this repo, and the first three tests here
    # failed on it. docs/powershell-51-traps.md has the rule: just emit the collection.
    $out
}

"== duplicate SPN detection =="
Check 'a clean forest produces no findings' {
    @(Group-Spn @(
        [pscustomobject]@{ sam = 'DC01$';  spns = @('HOST/dc01', 'ldap/dc01.corp.example.com') }
        [pscustomobject]@{ sam = 'svc-a';  spns = @('MSSQLSvc/db1.corp.example.com:1433') }
    )).Count -eq 0
}
Check 'a genuine duplicate across two accounts is found' {
    $r = @(Group-Spn @(
        [pscustomobject]@{ sam = 'DC01$'; spns = @('HOST/dc01', 'MSSQLSvc/db1.corp.example.com:1433') }
        [pscustomobject]@{ sam = 'svc-a'; spns = @('MSSQLSvc/db1.corp.example.com:1433') }
    ))
    $r.Count -eq 1 -and $r[0].Holders.Count -eq 2 -and ($r[0].Holders -contains 'svc-a')
}
Check 'a CASE-ONLY difference is still a duplicate' {
    # The KDC treats SPNs case-insensitively, so comparing case-sensitively would miss exactly
    # the duplicates that are hardest to spot by eye.
    @(Group-Spn @(
        [pscustomobject]@{ sam = 'a'; spns = @('MSSQLSvc/DB1.corp.example.com:1433') }
        [pscustomobject]@{ sam = 'b'; spns = @('mssqlsvc/db1.CORP.EXAMPLE.COM:1433') }
    )).Count -eq 1
}
Check 'the same SPN twice on ONE account is not a duplicate' {
    # One account legitimately holding a value twice is a data oddity, not a Kerberos failure --
    # reporting it would be noise, and noise is how the real finding gets ignored.
    @(Group-Spn @(
        [pscustomobject]@{ sam = 'a'; spns = @('HOST/x', 'HOST/x') }
    )).Count -eq 0
}
Check 'three holders are all reported' {
    $r = @(Group-Spn @(
        [pscustomobject]@{ sam = 'a'; spns = @('HOST/x') }
        [pscustomobject]@{ sam = 'b'; spns = @('HOST/x') }
        [pscustomobject]@{ sam = 'c'; spns = @('HOST/x') }
    ))
    $r.Count -eq 1 -and $r[0].Holders.Count -eq 3
}
Check 'an object with no SPNs is ignored safely' {
    @(Group-Spn @([pscustomobject]@{ sam = 'a'; spns = @() })).Count -eq 0
}

"== machine-identity comparison =="
# Mirrors the grouping in Get-MachineIdentity.ps1 -Compare.
function Group-Machine {
    param($Rows, [string]$Field)
    $out = @()
    foreach ($g in ($Rows | Where-Object { $_.$Field } | Group-Object -Property $Field | Where-Object { $_.Count -gt 1 })) {
        $machines = @($g.Group | ForEach-Object { $_.ComputerName } | Select-Object -Unique)
        if ($machines.Count -ge 2) { $out += [pscustomobject]@{ Value = $g.Name; Machines = $machines } }
    }
    $out
}

$fleet = @(
    [pscustomobject]@{ ComputerName = 'PC1'; MachineSid = 'S-1-5-21-1-2-3'; MachineGuid = 'g1'; SusClientId = 's1' }
    [pscustomobject]@{ ComputerName = 'PC2'; MachineSid = 'S-1-5-21-4-5-6'; MachineGuid = 'g2'; SusClientId = 's2' }
)
Check 'a properly generalised fleet is clean' {
    (@(Group-Machine $fleet 'MachineSid').Count -eq 0) -and (@(Group-Machine $fleet 'MachineGuid').Count -eq 0)
}
Check 'two clones of one image are caught on every field' {
    $clones = @(
        [pscustomobject]@{ ComputerName = 'PC1'; MachineSid = 'S-1-5-21-1-2-3'; MachineGuid = 'g1'; SusClientId = 's1' }
        [pscustomobject]@{ ComputerName = 'PC2'; MachineSid = 'S-1-5-21-1-2-3'; MachineGuid = 'g1'; SusClientId = 's1' }
    )
    (@(Group-Machine $clones 'MachineSid').Count -eq 1) -and
    (@(Group-Machine $clones 'MachineGuid').Count -eq 1) -and
    (@(Group-Machine $clones 'SusClientId').Count -eq 1)
}
Check 'THE SAME MACHINE COLLECTED TWICE IS NOT A DUPLICATE' {
    # Re-running a sweep must not manufacture findings against itself. This is why the comparison
    # counts distinct ComputerName values, not rows.
    $twice = @(
        [pscustomobject]@{ ComputerName = 'PC1'; MachineSid = 'S-1-5-21-1-2-3'; MachineGuid = 'g1'; SusClientId = 's1' }
        [pscustomobject]@{ ComputerName = 'PC1'; MachineSid = 'S-1-5-21-1-2-3'; MachineGuid = 'g1'; SusClientId = 's1' }
    )
    @(Group-Machine $twice 'MachineSid').Count -eq 0
}
Check 'a machine that could not be collected from is not a duplicate of another such' {
    # Two unreachable machines both have null everywhere. Grouping on null would pair them up and
    # report a duplicate that does not exist -- so empty values are excluded before grouping.
    $unknown = @(
        [pscustomobject]@{ ComputerName = 'PC1'; MachineSid = $null; MachineGuid = $null; SusClientId = $null }
        [pscustomobject]@{ ComputerName = 'PC2'; MachineSid = $null; MachineGuid = $null; SusClientId = $null }
    )
    @(Group-Machine $unknown 'MachineSid').Count -eq 0
}
Check 'three clones report all three machines' {
    $three = 1..3 | ForEach-Object {
        [pscustomobject]@{ ComputerName = "PC$_"; MachineSid = 'S-1-5-21-9-9-9'; MachineGuid = 'g'; SusClientId = 's' }
    }
    @(Group-Machine $three 'MachineSid')[0].Machines.Count -eq 3
}

"== SID conversion =="
Check 'a binary SID converts to its string form' {
    # S-1-5-21-1-2-3-1000, as the directory returns it.
    $bytes = [byte[]]@(1,5,0,0,0,0,0,5,21,0,0,0,1,0,0,0,2,0,0,0,3,0,0,0,232,3,0,0)
    (New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)).Value -eq 'S-1-5-21-1-2-3-1000'
}

"== the script is well-formed =="
Check 'Find-AdDuplicates.ps1 parses' {
    $errs = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $repo 'scripts\Find-AdDuplicates.ps1'), [ref]$null, [ref]$errs)
    (-not $errs) -or $errs.Count -eq 0
}
Check 'every script in scripts\ parses' {
    $bad = @()
    foreach ($f in (Get-ChildItem (Join-Path $repo 'scripts') -Filter '*.ps1')) {
        $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errs)
        if ($errs -and $errs.Count) { $bad += $f.Name }
    }
    if ($bad.Count) { "     do not parse: $($bad -join ', ')" }
    $bad.Count -eq 0
}

if ($fail -gt 0) { "`nFAILURES: $fail"; exit 1 } else { "`nall duplicate checks passed"; exit 0 }
