<#
.SYNOPSIS
  Checks that need a REAL domain controller, and cannot be proved by the mock provider.

.DESCRIPTION
  ⛔ THIS IS NOT PART OF Invoke-AdmTests AND MUST NOT BE. That runner has to work on a target PC
  with no directory in reach; a suite that needs a domain controller would turn "the toolkit is
  broken" and "you are not on the network" into the same red line.

  What lives here is the small set of claims the offline suites STRUCTURALLY cannot make. The
  truncation mechanism is the clearest case: every offline check proves the flag is wired
  correctly, and none of them can prove the assumption the whole thing rests on -- that a real
  DirectorySearcher, with PageSize set, actually returns SizeLimit+1 rows when more exist. If
  that interacted badly the flag would be silently dead against a live directory while every
  offline suite stayed green. That is precisely the class of bug the flag exists to catch, so it
  would be a poor joke to let the detector have it.

  ⭐ EVERY "the warning fired" CHECK HAS A HIGH-LIMIT COUNTERPART. Proving only that a detector
  fires cannot tell a working one from one wired to complain every time -- and an audit that
  cries incomplete on every run is ignored within a week.

  ⚠ READ-ONLY. Nothing here creates, changes or deletes a directory object. It forces truncation
  with -Limit 1 rather than by writing thousands of objects.

.PARAMETER Target
  A registered domain to test against. The store must already be unlocked, or ADADMIN_PASSPHRASE
  set, exactly as for any other use of the toolkit.

.EXAMPLE
  # With credentials supplied by your own secret tool:
  #   powershell -File tests\live\Invoke-AdmLiveTests.ps1 -Target corp.example.com
  tests\live\Invoke-AdmLiveTests.ps1 -Target corp.example.com

.NOTES
  EXIT CODES
    0   every live check passed
    1   at least one failed

  Needs at least 3 objects of each kind it reads, which every real domain has.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Target,
    # Skip the audit scripts and check only the module's search path. Faster, and the part that
    # matters most if you are short of time.
    [switch]$ModuleOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)   # tests\live\ -> tests\ -> repo
$fail = 0
$skipped = 0
function Check($name, [scriptblock]$b) {
    try { if (& $b) { "  PASS  $name" } else { "  FAIL  $name"; $script:fail++ } }
    catch { "  FAIL  $name -- $($_.Exception.Message.Split([char]10)[0])"; $script:fail++ }
}
# ⛔ A SKIP IS NOT A PASS AND MUST NOT READ LIKE ONE. Forcing truncation needs at least two
# objects of whatever kind the script under test reads, and a small domain may not have them --
# a single-DC lab cannot make the lockout script's DC enumeration overflow at any limit. Saying
# so is honest; quietly passing because the warning did not fire would be the same lie this
# whole mechanism exists to prevent, told by its own test.
function Skip($name, $why) { "  SKIP  $name -- $why"; $script:skipped++ }

# The limit that is guaranteed to truncate a read of $Count objects, or $null if nothing can.
function TruncLimit([int]$Count) { if ($Count -ge 2) { $Count - 1 } else { $null } }

# ⛔ NOT -Force, AND NOT IF ALREADY LOADED. Re-importing discards module state, and the unlocked
# store lives in module state -- so a -Force here locks the store out from under a caller that
# had just unlocked it, and every check below fails with "The credential store is locked" as
# though the credentials were wrong. The offline suites can use -Force because they set up their
# own store; this one runs INSIDE somebody's already-prepared session, which is the point of it.
if (-not (Get-Module ADAdmin)) { Import-Module (Join-Path $repo 'ADAdmin\ADAdmin.psd1') }

if ((Get-AdmStoreInfo).Provider -eq 'mock') {
    throw ('The mock provider is selected, so nothing here would test anything. These checks exist ' +
           'precisely because the mock cannot prove them. Clear ADADMIN_PROVIDER and try again.')
}

"== ground truth =="
$all = @(Get-AdmUser -Target $Target -Limit 100000)
$n = $all.Count
"  $Target holds $n user(s) -- every check below is expressed against that, never a typed number"
if ($n -lt 3) { throw "need at least 3 users to force and clear truncation; found $n" }

"== a REAL DirectorySearcher honours SizeLimit+1 with PageSize 500 =="
Check "limit $($n-1) returns $($n-1) rows and reports TRUNCATED" {
    Reset-AdmSearchTruncated
    $r = @(Get-AdmUser -Target $Target -Limit ($n - 1))
    $r.Count -eq ($n - 1) -and (Get-AdmSearchTruncated)
}
Check "limit $n returns $n rows and reports NOT truncated" {
    # ⛔ THE CHECK THAT JUSTIFIES OVER-FETCHING AT ALL. `$rows.Count -ge $limit` fails here: it
    # cannot tell "exactly $limit objects exist" from "stopped at $limit".
    Reset-AdmSearchTruncated
    $r = @(Get-AdmUser -Target $Target -Limit $n)
    $r.Count -eq $n -and -not (Get-AdmSearchTruncated)
}
Check 'a whole-directory read at a high limit reports NOT truncated' {
    Reset-AdmSearchTruncated
    $r = @(Get-AdmSearchResult -Target $Target -Limit 100000 -Filter '(objectClass=*)' -Properties @('distinguishedname'))
    $r.Count -gt 10 -and -not (Get-AdmSearchTruncated)
}
Check 'the rows returned under truncation are complete objects, not stubs' {
    # Breaking out of the enumeration mid-FindAll must not damage what was already emitted.
    Reset-AdmSearchTruncated
    $r = @(Get-AdmUser -Target $Target -Limit 2)
    $r.Count -eq 2 -and @($r | Where-Object { -not $_.SamAccountName }).Count -eq 0
}
Check 'the flag is sticky across a later untruncated read' {
    Reset-AdmSearchTruncated
    Get-AdmUser -Target $Target -Limit 1 | Out-Null
    Get-AdmUser -Target $Target -Limit 100000 | Out-Null
    Get-AdmSearchTruncated
}

"== the OU delete count, which is what somebody actually acts on =="
Check 'a truncated child count is reported as a floor, never as a number' {
    # Through the resolver, not by assuming Target is already an FQDN -- it may be a NetBIOS name
    # or a host, which is the whole point of the resolver existing.
    $name = (Resolve-AdmDomain -Target $Target).Domain
    $dn = ConvertTo-AdmDistinguishedName -DnsDomain (Get-AdmDomain -Name $name).DnsDomain
    Reset-AdmSearchTruncated
    $found = @(Get-AdmSearchResult -Target $Target -SearchBase $dn -Scope Subtree -Limit 3 `
                -Filter '(objectClass=*)' -Properties @('distinguishedname'))
    $kids = if (Get-AdmSearchTruncated) { "AT LEAST $($found.Count - 1)" } else { [string]($found.Count - 1) }
    "     the confirmation would read: contains $kids object(s)"
    $kids -like 'AT LEAST*'
}

"== Get-AdmGpo: the refusal that could not be fired until it took a parameter =="
# ⛔ THE PUREST INSTANCE OF THE CLASS. Get-AdmGpo REFUSES rather than answering when its gPLink
# scan is truncated, because every link it missed would make a LIVE policy report as Unlinked --
# the filter people use to decide what is safe to delete. But the limit was hardcoded at 50000
# and no reachable estate has 50000 linked containers, so the most important safety behaviour in
# that cmdlet had never run and COULD NOT BE MADE TO RUN by anyone. Worse than the privileged
# audit's `0 -ge 1500` guard: that one could never fire, this one could not even be asked to.
#
# ⚠ -LinkLimit exists FOR THIS. It is deliberately not surfaced on `adm gpo list`, because
# raising a limit past a real truncation is the wrong affordance for an operator.
$links = @(Get-AdmSearchResult -Target $Target -Limit 50000 -Filter '(gPLink=*)' -Properties @('distinguishedname'))
"  $($links.Count) container(s) with a gPLink"
$lim = TruncLimit $links.Count
if (-not $lim) {
    Skip 'the GPO link-scan refusal' "only $($links.Count) linked container(s); the limit cannot be set below the count, so the refusal cannot be forced here"
} else {
    Check "a link scan truncated at $lim REFUSES rather than reporting Unlinked" {
        try {
            $null = @(Get-AdmGpo -Target $Target -LinkLimit $lim)
            '     returned rows instead of refusing'
            $false
        } catch {
            if ($_.Exception.Message -notmatch 'truncated at the size limit') { "     wrong refusal: $($_.Exception.Message)" }
            $_.Exception.Message -match 'truncated at the size limit'
        }
    }
    Check 'and a complete scan does NOT refuse' {
        # ⭐ The half that separates a working refusal from a broken cmdlet. A guard that always
        # fires carries exactly as much information as one that never does.
        $g = @(Get-AdmGpo -Target $Target -LinkLimit 50000)
        "     $($g.Count) GPO(s)"
        $g.Count -ge 1
    }
}

"== the ranged read, where a three-state field must be a real boolean on a clean read =="
# ⛔ THE NEGATIVE CONTROL FOR null-MEANS-UNKNOWN. Get-AdmPasswordSettingsPolicy reads
# msDS-PSOAppliesTo through Get-AdmRangedProp and sets Unlinked to $null when that read was cut,
# because "applies to nobody" is the conclusion somebody deletes a policy on. That design is only
# worth anything if a COMPLETE read yields a real $true/$false -- a three-state field that came
# back null when everything was fine would make "unknown" stop meaning anything, and people would
# learn to ignore it within a week. The fixture cannot test this: it cannot truncate.
$psos = @(Get-AdmPasswordSettingsPolicy -Target $Target)
"  $($psos.Count) fine-grained password policy(ies)"
if (-not $psos.Count) {
    Skip 'the PSO three-state check' 'this domain has no fine-grained password policies, so there is no row to inspect'
} else {
    Check 'Unlinked and AppliesToTruncated are real booleans on a complete read' {
        $bad = @($psos | Where-Object { $null -eq (Get-AdmRawProp $_ 'Unlinked') -or
                                        $null -eq (Get-AdmRawProp $_ 'AppliesToTruncated') })
        if ($bad.Count) { $bad | ForEach-Object { "     null on $($_.Name)" } }
        $bad.Count -eq 0
    }
    Check 'and AppliesToCount agrees with the list it was derived from' {
        @($psos | Where-Object { [int](Get-AdmRawProp $_ 'AppliesToCount' -1) -ne @(Get-AdmRawProp $_ 'AppliesTo' @()).Count }).Count -eq 0
    }
}

if ($ModuleOnly) {
    if ($fail) { "FAILED: $fail"; exit 1 } else { "all live module checks passed"; exit 0 }
}

# ⛔ THE AUDIT SCRIPTS, WHERE THE FINDING IS THE ABSENCE. Each is run twice: once at -Limit 1 to
# force truncation, once at a limit far above the domain, so a detector that is simply always on
# fails just as loudly as one that never fires.
$scripts = Join-Path $repo 'scripts'
function Warnings([string]$Script, [hashtable]$Params) {
    $w = @()
    & (Join-Path $scripts $Script) @Params -WarningVariable +w -WarningAction SilentlyContinue | Out-Null
    @($w | ForEach-Object { "$_" })
}

# ⛔ THE TRIGGER LIMIT IS MEASURED, NEVER TYPED. `-Limit 1` only forces truncation if the script
# reads at least two objects, and which objects it reads differs per script -- a lab with one
# domain controller cannot make the lockout script's DC enumeration overflow at ANY limit. A
# hardcoded 1 therefore passes or fails according to how many objects the domain happens to hold
# on the day, which is a flaky test dressed up as a strict one.
$ouCount   = @(Get-AdmOrganizationalUnit -Target $Target -Limit 100000).Count
$compCount = @(Get-AdmComputer -Target $Target -Limit 100000).Count
$spnCount  = @(Get-AdmSearchResult -Target $Target -Limit 100000 -Filter '(servicePrincipalName=*)' -Properties @('distinguishedname')).Count
$dcCount   = @(Get-AdmSearchResult -Target $Target -Limit 100000 -Properties @('distinguishedname') `
                -Filter '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))').Count
"  $ouCount OU(s), $compCount computer(s), $spnCount SPN holder(s), $dcCount domain controller(s)"

"== Find-AdDuplicates: a truncated run must not exit 0 =="
$lim = TruncLimit $spnCount
if (-not $lim) {
    Skip 'the truncated-run checks' "this domain has $spnCount object(s) with an SPN; two are needed to force a short read"
} else {
    Check "a limit of $lim exits 10 or 30, NEVER a clean 0" {
        # exit 0 is a CLAIM. Invoke-AdmSweep maps anything but 0 or 10 to "did not complete", so a
        # 0 from a partial read records the whole domain as clean in a multi-forest sweep.
        $global:LASTEXITCODE = 0
        & (Join-Path $scripts 'Find-AdDuplicates.ps1') -Target $Target -Limit $lim 3>$null | Out-Null
        "     exit $LASTEXITCODE"
        $LASTEXITCODE -in @(10, 30)
    }
    Check 'and it says the SILENCE is not the finding' {
        @(Warnings 'Find-AdDuplicates.ps1' @{ Target = $Target; Limit = $lim } |
            Where-Object { $_ -match 'INCOMPLETE' -and $_ -match 'SILENCE is not' }).Count -ge 1
    }
}
Check 'a generous limit exits 0 or 10' {
    $global:LASTEXITCODE = 0
    & (Join-Path $scripts 'Find-AdDuplicates.ps1') -Target $Target -Limit 100000 3>$null | Out-Null
    $LASTEXITCODE -in @(0, 10)
}

"== Get-AdPrivilegedAccess: a cut read becomes unchecked coverage =="
# ⚠ LIMIT 1, NOT n-1. This script makes a dozen reads of different KINDS -- group members,
# delegation flags, roastable accounts, adminCount orphans -- and there is no single count to
# derive a trigger from. 1 is the only limit that overflows every read returning two or more
# rows, whatever they are. If even that produces nothing the domain is too small to force it, and
# that is reported as a SKIP: it would be exactly the wrong test to let "no warning appeared"
# count as a pass here.
$privWarn = @(Warnings 'Get-AdPrivilegedAccess.ps1' @{ Target = $Target; Limit = 1 } |
                Where-Object { $_ -match 'Could not check everything matching' -and $_ -match 'never examined' })
if ($privWarn.Count) { "  PASS  a limit of 1 records unchecked coverage" }
else { Skip 'the truncated-read check' 'no read this script made returned more than one object, so truncation could not be forced -- this proves NOTHING about the detector' }
Check 'a generous limit records NONE' {
    @(Warnings 'Get-AdPrivilegedAccess.ps1' @{ Target = $Target; Limit = 100000 } |
        Where-Object { $_ -match 'the read stopped at' }).Count -eq 0
}

"== Find-StaleComputers: the denominator stops being a lie =="
$lim = TruncLimit $compCount
if (-not $lim) {
    Skip 'the truncated-read check' "this domain has $compCount computer(s); two are needed"
} else {
    Check "a limit of $lim warns INCOMPLETE and calls the count a floor" {
        @(Warnings 'Find-StaleComputers.ps1' @{ Target = $Target; Limit = $lim; StaleDays = 90 } |
            Where-Object { $_ -match 'INCOMPLETE' -and $_ -match 'FLOOR' }).Count -ge 1
    }
}
Check 'a generous limit does not' {
    @(Warnings 'Find-StaleComputers.ps1' @{ Target = $Target; Limit = 100000; StaleDays = 90 } |
        Where-Object { $_ -match 'INCOMPLETE' }).Count -eq 0
}

"== Get-AdDelegation: an unswept OU is unchecked coverage, not a clean bill =="
$lim = TruncLimit $ouCount
if (-not $lim) {
    Skip 'the truncated-sweep check' "this domain has $ouCount OU(s); a default domain has only Domain Controllers, and two are needed"
} else {
    Check "a limit of $lim names the OU list as unchecked" {
        @(Warnings 'Get-AdDelegation.ps1' @{ Target = $Target; Limit = $lim; Section = 'Containers' } |
            Where-Object { $_ -match 'every organizational unit' -and $_ -match 'never examined' }).Count -ge 1
    }
}
Check 'a generous limit does not' {
    @(Warnings 'Get-AdDelegation.ps1' @{ Target = $Target; Limit = 100000; Section = 'Containers' } |
        Where-Object { $_ -match 'every organizational unit' }).Count -eq 0
}

"== Get-AdLockoutSource: 'nothing found' must not come from an unread account =="
# It enumerates domain controllers from computer objects at the caller's -Limit, so that read is
# the one a limit can cut. One DC and nothing here can be forced, at any limit.
$lim = TruncLimit $dcCount
if (-not $lim) {
    Skip 'the truncated-read checks' "this domain has $dcCount domain controller(s); no read in this script can be made to overflow with fewer than two"
} else {
    Check "a limit of $lim records unchecked coverage" {
        @(Warnings 'Get-AdLockoutSource.ps1' @{ Target = $Target; Limit = $lim } |
            Where-Object { $_ -match 'the read stopped at' -and $_ -match 'locked one among them' }).Count -ge 1
    }
    Check 'and does not exit 0' {
        $global:LASTEXITCODE = 0
        & (Join-Path $scripts 'Get-AdLockoutSource.ps1') -Target $Target -Limit $lim 3>$null | Out-Null
        "     exit $LASTEXITCODE"
        $LASTEXITCODE -ne 0
    }
}
Check 'a generous limit records NONE' {
    @(Warnings 'Get-AdLockoutSource.ps1' @{ Target = $Target; Limit = 100000 } |
        Where-Object { $_ -match 'the read stopped at' }).Count -eq 0
}

"== Invoke-AdmSweep: a partially-read domain is not a clean estate =="
# ⛔ THE SWEEP IS THE PARENT, so the child exit codes cannot save it -- it does its OWN reads for
# the cross-domain collision maps. And cross-domain makes a cut read WORSE than a single-domain
# one: a collision is found by comparing two holders, so one truncated domain silently removes
# every pair with a leg in it, including pairs whose other leg was read perfectly.
$lim = TruncLimit $spnCount
if (-not $lim) {
    Skip 'the partial-sweep check' "this domain has $spnCount object(s) with an SPN; two are needed to force a short read"
} else {
    Check "a cross-domain sweep at limit $lim exits 30, not a clean 0" {
        $global:LASTEXITCODE = 0
        & (Join-Path $scripts 'Invoke-AdmSweep.ps1') -CrossDomain -Limit $lim 3>$null | Out-Null
        "     exit $LASTEXITCODE"
        $LASTEXITCODE -in @(10, 30)
    }
    Check 'and it names the domain as PARTIAL rather than ok' {
        $w = @()
        & (Join-Path $scripts 'Invoke-AdmSweep.ps1') -CrossDomain -Limit $lim `
            -WarningVariable +w -WarningAction SilentlyContinue | Out-Null
        @($w | Where-Object { "$_" -match 'PARTIAL' -and "$_" -match 'read cut at' }).Count -ge 1
    }
}
Check 'a generous limit sweeps clean, so PARTIAL means something' {
    $global:LASTEXITCODE = 0
    $w = @()
    & (Join-Path $scripts 'Invoke-AdmSweep.ps1') -CrossDomain -Limit 100000 `
        -WarningVariable +w -WarningAction SilentlyContinue | Out-Null
    "     exit $LASTEXITCODE"
    $LASTEXITCODE -in @(0, 10) -and @($w | Where-Object { "$_" -match 'PARTIAL' }).Count -eq 0
}

# ⛔ MODE 1 IS A DIFFERENT CODE PATH AND NEEDS ITS OWN LIVE CHECK. The cross-domain mode does its
# own reads; this one runs a CHILD SCRIPT per domain and reads its exit code. Forcing the child to
# exit 30 is the only way to exercise the branch that decides whether "could not look" is reported
# as a hard failure -- and it is the branch most recently rewritten.
Check "a per-domain sweep whose child exits 30 reports PARTIAL, not FAILED" {
    $w = @()
    & (Join-Path $scripts 'Invoke-AdmSweep.ps1') -Script 'Find-AdDuplicates' -Arguments @{ Limit = $lim } `
        -WarningVariable +w -WarningAction SilentlyContinue | Out-Null
    $partial = @($w | Where-Object { "$_" -match 'script exited 30' -and "$_" -match 'not examined' })
    $failed  = @($w | Where-Object { "$_" -match 'UNKNOWN, not clean' })
    "     $($partial.Count) partial warning(s), $($failed.Count) failure warning(s)"
    $partial.Count -ge 1 -and $failed.Count -eq 0
}
Check 'and the same sweep at a generous limit reports neither' {
    $w = @()
    & (Join-Path $scripts 'Invoke-AdmSweep.ps1') -Script 'Find-AdDuplicates' -Arguments @{ Limit = 100000 } `
        -WarningVariable +w -WarningAction SilentlyContinue | Out-Null
    @($w | Where-Object { "$_" -match 'script exited 30' -or "$_" -match 'UNKNOWN, not clean' }).Count -eq 0
}

""
if ($fail) { "FAILED: $fail$(if ($skipped) { ", $skipped skipped" })"; exit 1 }
if ($skipped) { "all live checks passed -- but $skipped were SKIPPED for want of objects to force truncation with; read the SKIP lines above before treating this as full coverage"; exit 0 }
"all live checks passed"; exit 0
